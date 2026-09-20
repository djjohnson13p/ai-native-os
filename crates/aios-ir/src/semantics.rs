//! Registry-backed graph, type, effect, authority, egress, cache, and fallback analysis.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use aios_contracts::{
    AiosIr, CachePolicy, CapabilityContract, CapabilityRole, Diagnostic, EffectClass,
    EffectSummary, EgressMode, ExecutionClass, FailurePolicy, GeneratedBy, Locality, Node,
    NodeEffectSummary, OperationKind, ValidatorReasonCode, ValueRef,
};
use aios_registry::{SemanticRegistry, effect_for_authority_class};

use crate::diagnostics::{DiagnosticCollector, contextual};

pub(crate) fn analyze(
    program: &AiosIr,
    registry: &SemanticRegistry,
    diagnostics: &mut DiagnosticCollector,
) -> Option<EffectSummary> {
    let nodes = index_nodes(program, diagnostics)?;

    validate_references(program, &nodes, diagnostics);
    if diagnostics.has_errors() {
        return None;
    }

    validate_acyclic(program, &nodes, diagnostics);
    if diagnostics.has_errors() {
        return None;
    }

    let capabilities = validate_types_and_capabilities(program, registry, &nodes, diagnostics);
    if diagnostics.has_errors() {
        return None;
    }

    let node_effects = validate_effects(program, &capabilities, diagnostics);
    if diagnostics.has_errors() {
        return None;
    }

    validate_fallbacks(program, registry, &capabilities, &node_effects, diagnostics);
    if diagnostics.has_errors() {
        return None;
    }

    warn_unused_pure_nodes(program, &nodes, &node_effects, diagnostics);
    let summary = build_summary(program, registry.snapshot_id(), "", &node_effects);
    Some(summary)
}

fn index_nodes<'a>(
    program: &'a AiosIr,
    diagnostics: &mut DiagnosticCollector,
) -> Option<BTreeMap<&'a str, &'a Node>> {
    let mut nodes = BTreeMap::new();
    for (index, node) in program.nodes.iter().enumerate() {
        if nodes.insert(node.id.as_str(), node).is_some() {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrGraphDuplicateNodeId,
                format!("node ID '{}' occurs more than once", node.id),
                Some(&node.id),
                None,
                Some(&node.operation.capability),
                Some(format!("/nodes/{index}/id")),
            ));
        }
    }
    (!diagnostics.has_errors()).then_some(nodes)
}

fn validate_references(
    program: &AiosIr,
    nodes: &BTreeMap<&str, &Node>,
    diagnostics: &mut DiagnosticCollector,
) {
    for (node_index, node) in program.nodes.iter().enumerate() {
        for (port, value_ref) in &node.inputs {
            validate_value_ref(
                value_ref,
                program,
                nodes,
                diagnostics,
                Some(node),
                Some(port),
                format!("/nodes/{node_index}/inputs/{}", escape_pointer(port)),
            );
        }
        let consumed_program_inputs: BTreeSet<&str> = node
            .inputs
            .values()
            .filter_map(|value_ref| match value_ref {
                ValueRef::Input { name } => Some(name.as_str()),
                ValueRef::Node { .. } => None,
            })
            .collect();
        for (request_index, request) in node.authority_requests.iter().enumerate() {
            if let Some(input) = request.resource.strip_prefix("input:") {
                if !program.inputs.contains_key(input) || !consumed_program_inputs.contains(input) {
                    diagnostics.push(contextual(
                        ValidatorReasonCode::IrReferenceInputNotFound,
                        format!(
                            "authority selector '{}' does not name a program input consumed by this node",
                            request.resource
                        ),
                        Some(&node.id),
                        None,
                        Some(&node.operation.capability),
                        Some(format!(
                            "/nodes/{node_index}/authority_requests/{request_index}/resource"
                        )),
                    ));
                }
            }
        }
    }

    for (name, value_ref) in &program.outputs {
        if matches!(value_ref, ValueRef::Input { .. }) {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrOutputNotFound,
                format!("program output '{name}' must resolve to a node output"),
                None,
                Some(name),
                None,
                Some(format!("/outputs/{}", escape_pointer(name))),
            ));
            continue;
        }
        validate_value_ref(
            value_ref,
            program,
            nodes,
            diagnostics,
            None,
            Some(name),
            format!("/outputs/{}", escape_pointer(name)),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_value_ref(
    value_ref: &ValueRef,
    program: &AiosIr,
    nodes: &BTreeMap<&str, &Node>,
    diagnostics: &mut DiagnosticCollector,
    consumer: Option<&Node>,
    consumer_port: Option<&str>,
    pointer: String,
) {
    match value_ref {
        ValueRef::Input { name } => {
            if !program.inputs.contains_key(name) {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrReferenceInputNotFound,
                    format!("program input '{name}' does not exist"),
                    consumer.map(|node| node.id.as_str()),
                    consumer_port,
                    consumer.map(|node| node.operation.capability.as_str()),
                    Some(pointer),
                ));
            }
        }
        ValueRef::Node { node, port } => match nodes.get(node.as_str()) {
            None => diagnostics.push(contextual(
                ValidatorReasonCode::IrReferenceNodeNotFound,
                format!("referenced node '{node}' does not exist"),
                consumer.map(|value| value.id.as_str()),
                consumer_port,
                consumer.map(|value| value.operation.capability.as_str()),
                Some(pointer),
            )),
            Some(producer) if !producer.outputs.contains_key(port) => {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrReferencePortNotFound,
                    format!("node '{node}' has no declared output port '{port}'"),
                    consumer.map(|value| value.id.as_str()),
                    consumer_port,
                    consumer.map(|value| value.operation.capability.as_str()),
                    Some(pointer),
                ));
            }
            Some(_) => {}
        },
    }
}

fn validate_acyclic(
    program: &AiosIr,
    nodes: &BTreeMap<&str, &Node>,
    diagnostics: &mut DiagnosticCollector,
) {
    let mut indegree: BTreeMap<&str, usize> = nodes.keys().map(|id| (*id, 0_usize)).collect();
    let mut consumers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for node in &program.nodes {
        for value_ref in node.inputs.values() {
            if let ValueRef::Node { node: producer, .. } = value_ref {
                if consumers
                    .entry(producer.as_str())
                    .or_default()
                    .insert(node.id.as_str())
                {
                    *indegree.entry(node.id.as_str()).or_default() += 1;
                }
            }
        }
    }

    let mut ready: BTreeSet<&str> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop_first() {
        visited += 1;
        if let Some(next) = consumers.get(id) {
            for consumer in next {
                let degree = indegree
                    .get_mut(consumer)
                    .expect("consumer originates from indexed program node");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(consumer);
                }
            }
        }
    }

    if visited != nodes.len() {
        let cyclic = indegree
            .iter()
            .filter_map(|(id, degree)| (*degree > 0).then_some((*id).to_owned()))
            .collect::<Vec<_>>();
        let mut diagnostic = Diagnostic::new(
            ValidatorReasonCode::IrGraphCycle,
            "program data-flow graph contains a cycle",
        );
        diagnostic.related = cyclic;
        diagnostics.push(diagnostic);
    }
}

fn validate_types_and_capabilities<'a>(
    program: &AiosIr,
    registry: &'a SemanticRegistry,
    nodes: &BTreeMap<&str, &Node>,
    diagnostics: &mut DiagnosticCollector,
) -> BTreeMap<String, &'a CapabilityContract> {
    for (name, input) in &program.inputs {
        if registry
            .resolve_type(&input.type_ref)
            .ok()
            .flatten()
            .is_none()
        {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrTypeNotFound,
                format!(
                    "input '{name}' references unknown type '{}'",
                    input.type_ref
                ),
                None,
                Some(name),
                None,
                Some(format!("/inputs/{}/type", escape_pointer(name))),
            ));
        }
    }

    let mut capabilities = BTreeMap::new();
    for (node_index, node) in program.nodes.iter().enumerate() {
        for (port, type_ref) in &node.outputs {
            if registry.resolve_type(type_ref).ok().flatten().is_none() {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrTypeNotFound,
                    format!("output '{port}' references unknown type '{type_ref}'"),
                    Some(&node.id),
                    Some(port),
                    Some(&node.operation.capability),
                    Some(format!(
                        "/nodes/{node_index}/outputs/{}",
                        escape_pointer(port)
                    )),
                ));
            }
        }

        let Some(contract) = registry
            .resolve_capability(&node.operation.capability)
            .ok()
            .flatten()
        else {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrCapabilityNotFound,
                format!(
                    "capability '{}' is absent from the selected registry snapshot",
                    node.operation.capability
                ),
                Some(&node.id),
                None,
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}/operation/capability")),
            ));
            continue;
        };
        capabilities.insert(node.id.clone(), contract);

        let expected_role = match node.operation.kind {
            OperationKind::Invoke => CapabilityRole::Ordinary,
            OperationKind::Verify => CapabilityRole::Verifier,
        };
        if contract.role != expected_role {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrCapabilityRoleMismatch,
                format!(
                    "operation kind {:?} is incompatible with capability role {:?}",
                    node.operation.kind, contract.role
                ),
                Some(&node.id),
                None,
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}/operation/kind")),
            ));
        }

        if !contract
            .allowed_execution_classes
            .contains(&node.execution_class)
        {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrExecutionClassIncompatible,
                format!(
                    "execution class {:?} is outside the capability contract envelope",
                    node.execution_class
                ),
                Some(&node.id),
                None,
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}/execution_class")),
            ));
        }

        validate_port_shape(node, contract, node_index, diagnostics);
        validate_flow_types(program, nodes, node, contract, node_index, diagnostics);
    }
    capabilities
}

fn validate_port_shape(
    node: &Node,
    contract: &CapabilityContract,
    node_index: usize,
    diagnostics: &mut DiagnosticCollector,
) {
    for (port, specification) in &contract.inputs {
        if specification.required && !node.inputs.contains_key(port) {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrCapabilityPortMismatch,
                format!("required capability input port '{port}' is missing"),
                Some(&node.id),
                Some(port),
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}/inputs")),
            ));
        }
    }
    for port in node.inputs.keys() {
        if !contract.inputs.contains_key(port) {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrCapabilityPortMismatch,
                format!("input port '{port}' is not declared by the capability"),
                Some(&node.id),
                Some(port),
                Some(&node.operation.capability),
                Some(format!(
                    "/nodes/{node_index}/inputs/{}",
                    escape_pointer(port)
                )),
            ));
        }
    }
    for (port, specification) in &contract.outputs {
        if specification.required && !node.outputs.contains_key(port) {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrCapabilityPortMismatch,
                format!("required capability output port '{port}' is missing"),
                Some(&node.id),
                Some(port),
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}/outputs")),
            ));
        }
    }
    for (port, type_ref) in &node.outputs {
        match contract.outputs.get(port) {
            None => diagnostics.push(contextual(
                ValidatorReasonCode::IrCapabilityPortMismatch,
                format!("output port '{port}' is not declared by the capability"),
                Some(&node.id),
                Some(port),
                Some(&node.operation.capability),
                Some(format!(
                    "/nodes/{node_index}/outputs/{}",
                    escape_pointer(port)
                )),
            )),
            Some(specification) if specification.type_ref != *type_ref => {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrCapabilityPortMismatch,
                    format!(
                        "declared output type '{type_ref}' does not match capability type '{}'",
                        specification.type_ref
                    ),
                    Some(&node.id),
                    Some(port),
                    Some(&node.operation.capability),
                    Some(format!(
                        "/nodes/{node_index}/outputs/{}",
                        escape_pointer(port)
                    )),
                ));
            }
            Some(_) => {}
        }
    }
}

fn validate_flow_types(
    program: &AiosIr,
    nodes: &BTreeMap<&str, &Node>,
    node: &Node,
    contract: &CapabilityContract,
    node_index: usize,
    diagnostics: &mut DiagnosticCollector,
) {
    for (port, value_ref) in &node.inputs {
        let Some(expected) = contract.inputs.get(port) else {
            continue;
        };
        let (actual, optional_program_input) = match value_ref {
            ValueRef::Input { name } => {
                let input = program
                    .inputs
                    .get(name)
                    .expect("references were validated before type analysis");
                (input.type_ref.as_str(), !input.required)
            }
            ValueRef::Node {
                node: producer,
                port,
            } => {
                let producer = nodes
                    .get(producer.as_str())
                    .expect("references were validated before type analysis");
                (
                    producer
                        .outputs
                        .get(port)
                        .expect("ports were validated before type analysis")
                        .as_str(),
                    false,
                )
            }
        };
        if optional_program_input && expected.required {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrOptionalInputToRequiredPort,
                format!("optional program input cannot feed required port '{port}'"),
                Some(&node.id),
                Some(port),
                Some(&node.operation.capability),
                Some(format!(
                    "/nodes/{node_index}/inputs/{}",
                    escape_pointer(port)
                )),
            ));
        }
        if actual != expected.type_ref {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrTypeMismatch,
                format!(
                    "value type '{actual}' does not match required type '{}'",
                    expected.type_ref
                ),
                Some(&node.id),
                Some(port),
                Some(&node.operation.capability),
                Some(format!(
                    "/nodes/{node_index}/inputs/{}",
                    escape_pointer(port)
                )),
            ));
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_effects(
    program: &AiosIr,
    capabilities: &BTreeMap<String, &CapabilityContract>,
    diagnostics: &mut DiagnosticCollector,
) -> BTreeMap<String, BTreeSet<EffectClass>> {
    let mut all_effects = BTreeMap::new();
    for (node_index, node) in program.nodes.iter().enumerate() {
        let contract = capabilities
            .get(&node.id)
            .expect("capabilities were resolved before effect analysis");
        let mut request_pairs = BTreeSet::new();
        let mut requested_actions = BTreeSet::new();
        let mut effects: BTreeSet<EffectClass> = contract
            .required_effect_classes
            .iter()
            .copied()
            .filter(|effect| *effect != EffectClass::Pure)
            .collect();

        for (request_index, request) in node.authority_requests.iter().enumerate() {
            if !request_pairs.insert((request.action.as_str(), request.resource.as_str())) {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrAuthorityDuplicateRequest,
                    format!(
                        "authority request ('{}', '{}') is duplicated",
                        request.action, request.resource
                    ),
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!(
                        "/nodes/{node_index}/authority_requests/{request_index}"
                    )),
                ));
            }
            requested_actions.insert(request.action.as_str());
            if !contract.allowed_authority_classes.contains(&request.action) {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrAuthorityClassNotAllowed,
                    format!(
                        "authority class '{}' is outside the capability contract envelope",
                        request.action
                    ),
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!(
                        "/nodes/{node_index}/authority_requests/{request_index}/action"
                    )),
                ));
            }
            match effect_for_authority_class(&request.action) {
                Some(effect) => {
                    effects.insert(effect);
                }
                None => diagnostics.push(contextual(
                    ValidatorReasonCode::IrEffectClassNotAllowed,
                    format!(
                        "authority class '{}' has no closed-profile effect mapping",
                        request.action
                    ),
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!(
                        "/nodes/{node_index}/authority_requests/{request_index}/action"
                    )),
                )),
            }
        }

        for required in &contract.required_authority_classes {
            if !requested_actions.contains(required.as_str()) {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrRequiredAuthorityMissing,
                    format!("required authority class '{required}' was not requested"),
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!("/nodes/{node_index}/authority_requests")),
                ));
            }
        }

        // Selecting remote as the only permitted placement makes network use
        // intrinsic to this node, even when the capability can also run locally.
        // Bound inputs also cross that placement boundary and therefore require
        // explicit data-egress authority and policy.
        let remote_only = node.constraints.as_ref().is_some_and(|constraints| {
            !constraints.locality.is_empty()
                && constraints
                    .locality
                    .iter()
                    .all(|locality| *locality == Locality::Remote)
        });
        if remote_only {
            require_placement_authority(
                node,
                node_index,
                "network.connect",
                &requested_actions,
                diagnostics,
            );
            effects.insert(EffectClass::Network);

            if !node.inputs.is_empty() {
                require_placement_authority(
                    node,
                    node_index,
                    "data.egress",
                    &requested_actions,
                    diagnostics,
                );
                effects.insert(EffectClass::DataEgress);
            }
        }

        if effects.is_empty() {
            effects.insert(EffectClass::Pure);
        }
        for effect in &effects {
            if !contract.allowed_effect_classes.contains(effect) {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrEffectClassNotAllowed,
                    format!(
                        "derived effect {effect:?} is outside the capability contract envelope"
                    ),
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!("/nodes/{node_index}/authority_requests")),
                ));
            }
        }

        validate_egress(node, contract, &effects, node_index, diagnostics);
        if node.cache != CachePolicy::Never && node.execution_class != ExecutionClass::Deterministic
        {
            diagnostics.push(contextual(
                ValidatorReasonCode::IrCacheExecutionClassMismatch,
                "non-deterministic execution cannot use deterministic or content-addressed caching",
                Some(&node.id),
                None,
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}/cache")),
            ));
        }
        all_effects.insert(node.id.clone(), effects);
    }
    all_effects
}

fn require_placement_authority(
    node: &Node,
    node_index: usize,
    action: &str,
    requested_actions: &BTreeSet<&str>,
    diagnostics: &mut DiagnosticCollector,
) {
    if !requested_actions.contains(action) {
        diagnostics.push(contextual(
            ValidatorReasonCode::IrRequiredAuthorityMissing,
            format!("remote-only placement requires authority class '{action}'"),
            Some(&node.id),
            None,
            Some(&node.operation.capability),
            Some(format!("/nodes/{node_index}/authority_requests")),
        ));
    }
}

fn validate_egress(
    node: &Node,
    contract: &CapabilityContract,
    effects: &BTreeSet<EffectClass>,
    node_index: usize,
    diagnostics: &mut DiagnosticCollector,
) {
    if !contract.allowed_egress_modes.contains(&node.egress.mode) {
        diagnostics.push(contextual(
            ValidatorReasonCode::IrEgressNotAllowed,
            format!(
                "egress mode {:?} is outside the capability contract envelope",
                node.egress.mode
            ),
            Some(&node.id),
            None,
            Some(&node.operation.capability),
            Some(format!("/nodes/{node_index}/egress/mode")),
        ));
    }

    let data_egress_resources: BTreeSet<&str> = node
        .authority_requests
        .iter()
        .filter(|request| request.action == "data.egress")
        .map(|request| request.resource.as_str())
        .collect();
    match node.egress.mode {
        EgressMode::Deny => {
            if !node.egress.destination_classes.is_empty()
                || !data_egress_resources.is_empty()
                || effects.contains(&EffectClass::DataEgress)
            {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrEgressContradiction,
                    "deny egress cannot name destinations or request data.egress authority",
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!("/nodes/{node_index}/egress")),
                ));
            }
        }
        EgressMode::Policy => {
            let expected: BTreeSet<String> = node
                .egress
                .destination_classes
                .iter()
                .map(|destination| format!("destination:{destination}"))
                .collect();
            if expected.is_empty()
                || expected
                    .iter()
                    .any(|resource| !data_egress_resources.contains(resource.as_str()))
                || data_egress_resources
                    .iter()
                    .any(|resource| !expected.contains(*resource))
            {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrEgressAuthorityMismatch,
                    "policy egress destinations must exactly match data.egress authority selectors",
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(format!("/nodes/{node_index}/egress")),
                ));
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_fallbacks(
    program: &AiosIr,
    registry: &SemanticRegistry,
    capabilities: &BTreeMap<String, &CapabilityContract>,
    node_effects: &BTreeMap<String, BTreeSet<EffectClass>>,
    diagnostics: &mut DiagnosticCollector,
) {
    for (node_index, node) in program.nodes.iter().enumerate() {
        let FailurePolicy::Fallback {
            fallback_capabilities,
        } = &node.failure
        else {
            continue;
        };
        let primary = capabilities
            .get(&node.id)
            .expect("primary capability was resolved before fallback analysis");
        let actions: BTreeSet<&str> = node
            .authority_requests
            .iter()
            .map(|request| request.action.as_str())
            .collect();
        let effects = node_effects
            .get(&node.id)
            .expect("node effects were derived before fallback analysis");

        for (fallback_index, fallback_ref) in fallback_capabilities.iter().enumerate() {
            let pointer =
                format!("/nodes/{node_index}/failure/fallback_capabilities/{fallback_index}");
            if fallback_ref == &node.operation.capability {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrFailurePolicyRecursiveFallback,
                    "fallback chain contains its primary capability",
                    Some(&node.id),
                    None,
                    Some(&node.operation.capability),
                    Some(pointer),
                ));
                continue;
            }
            let Some(fallback) = registry.resolve_capability(fallback_ref).ok().flatten() else {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrCapabilityNotFound,
                    format!("fallback capability '{fallback_ref}' is not in the registry"),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer),
                ));
                continue;
            };

            if !fallback_ports_compatible(program, node, primary, fallback) {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrFallbackPortMismatch,
                    format!(
                        "fallback capability '{fallback_ref}' cannot satisfy the node's bound inputs or graph-consumed outputs"
                    ),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer.clone()),
                ));
            }
            if !fallback
                .allowed_execution_classes
                .contains(&node.execution_class)
            {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrExecutionClassIncompatible,
                    format!(
                        "fallback capability '{fallback_ref}' cannot run with the node execution class"
                    ),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer.clone()),
                ));
            }
            let expected_role = match node.operation.kind {
                OperationKind::Invoke => CapabilityRole::Ordinary,
                OperationKind::Verify => CapabilityRole::Verifier,
            };
            if fallback.role != expected_role {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrCapabilityRoleMismatch,
                    format!(
                        "fallback capability '{fallback_ref}' has role {:?}, expected {:?}",
                        fallback.role, expected_role
                    ),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer.clone()),
                ));
            }

            let fallback_nonpure = fallback
                .allowed_effect_classes
                .iter()
                .filter(|effect| **effect != EffectClass::Pure);
            if fallback_nonpure
                .clone()
                .any(|effect| !effects.contains(effect))
            {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrFallbackEffectBroadening,
                    format!("fallback capability '{fallback_ref}' broadens the effect envelope"),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer.clone()),
                ));
            }
            if fallback
                .allowed_authority_classes
                .iter()
                .any(|action| !actions.contains(action.as_str()))
            {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrFallbackAuthorityBroadening,
                    format!("fallback capability '{fallback_ref}' broadens the authority envelope"),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer.clone()),
                ));
            }
            if node.egress.mode == EgressMode::Deny
                && fallback
                    .allowed_egress_modes
                    .iter()
                    .any(|mode| *mode != EgressMode::Deny)
            {
                diagnostics.push(contextual(
                    ValidatorReasonCode::IrFallbackEgressBroadening,
                    format!("fallback capability '{fallback_ref}' broadens the egress envelope"),
                    Some(&node.id),
                    None,
                    Some(fallback_ref),
                    Some(pointer),
                ));
            }
        }
    }
}

fn fallback_ports_compatible(
    program: &AiosIr,
    node: &Node,
    primary: &CapabilityContract,
    fallback: &CapabilityContract,
) -> bool {
    let bound_inputs_match = node.inputs.iter().all(|(name, value_ref)| {
        let Some(primary_port) = primary.inputs.get(name) else {
            return false;
        };
        let Some(fallback_port) = fallback.inputs.get(name) else {
            return false;
        };
        if fallback_port.type_ref != primary_port.type_ref {
            return false;
        }

        !fallback_port.required
            || !matches!(
                value_ref,
                ValueRef::Input { name }
                    if program.inputs.get(name).is_some_and(|input| !input.required)
            )
    });
    let required_fallback_inputs_are_bound = fallback
        .inputs
        .iter()
        .all(|(name, port)| !port.required || node.inputs.contains_key(name));
    let consumed_outputs_match = program
        .nodes
        .iter()
        .flat_map(|consumer| consumer.inputs.values())
        .chain(program.outputs.values())
        .filter_map(|value_ref| match value_ref {
            ValueRef::Node {
                node: producer,
                port,
            } if producer == &node.id => Some(port),
            ValueRef::Input { .. } | ValueRef::Node { .. } => None,
        })
        .all(|port| {
            let expected_type = node
                .outputs
                .get(port)
                .expect("references were validated before fallback analysis");
            fallback
                .outputs
                .get(port)
                .is_some_and(|fallback_port| fallback_port.type_ref == *expected_type)
        });

    bound_inputs_match && required_fallback_inputs_are_bound && consumed_outputs_match
}

fn warn_unused_pure_nodes(
    program: &AiosIr,
    nodes: &BTreeMap<&str, &Node>,
    effects: &BTreeMap<String, BTreeSet<EffectClass>>,
    diagnostics: &mut DiagnosticCollector,
) {
    let output_nodes: BTreeSet<&str> = program
        .outputs
        .values()
        .filter_map(|reference| match reference {
            ValueRef::Node { node, .. } => Some(node.as_str()),
            ValueRef::Input { .. } => None,
        })
        .collect();
    let effectful: BTreeSet<&str> = effects
        .iter()
        .filter_map(|(id, node_effects)| {
            (node_effects.len() != 1 || !node_effects.contains(&EffectClass::Pure))
                .then_some(id.as_str())
        })
        .collect();
    let mut consumers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for node in &program.nodes {
        for reference in node.inputs.values() {
            if let ValueRef::Node { node: producer, .. } = reference {
                consumers
                    .entry(producer.as_str())
                    .or_default()
                    .insert(node.id.as_str());
            }
        }
    }

    for (node_index, node) in program.nodes.iter().enumerate() {
        let node_effects = &effects[&node.id];
        if node_effects.len() != 1 || !node_effects.contains(&EffectClass::Pure) {
            continue;
        }
        let mut pending = VecDeque::from([node.id.as_str()]);
        let mut seen = BTreeSet::new();
        let mut useful = false;
        while let Some(candidate) = pending.pop_front() {
            if !seen.insert(candidate) {
                continue;
            }
            if output_nodes.contains(candidate) || effectful.contains(candidate) {
                useful = true;
                break;
            }
            if let Some(next) = consumers.get(candidate) {
                pending.extend(next.iter().copied());
            }
        }
        if !useful {
            debug_assert!(nodes.contains_key(node.id.as_str()));
            diagnostics.push(contextual(
                ValidatorReasonCode::IrGraphUnusedPureNode,
                "pure node has no path to a program output or effectful node",
                Some(&node.id),
                None,
                Some(&node.operation.capability),
                Some(format!("/nodes/{node_index}")),
            ));
        }
    }
}

fn build_summary(
    program: &AiosIr,
    snapshot_id: &str,
    semantic_hash: &str,
    node_effects: &BTreeMap<String, BTreeSet<EffectClass>>,
) -> EffectSummary {
    let mut effects = BTreeSet::new();
    let mut authority_classes = BTreeSet::new();
    let mut egress_modes = BTreeSet::new();
    let mut nodes = Vec::with_capacity(program.nodes.len());
    let mut verification_barriers = Vec::new();

    let mut ordered_nodes: Vec<&Node> = program.nodes.iter().collect();
    ordered_nodes.sort_by_key(|node| node.id.as_str());
    for node in ordered_nodes {
        let derived = &node_effects[&node.id];
        effects.extend(derived.iter().copied());
        let node_authorities: BTreeSet<String> = node
            .authority_requests
            .iter()
            .map(|request| request.action.clone())
            .collect();
        authority_classes.extend(node_authorities.iter().cloned());
        egress_modes.insert(node.egress.mode);
        let verification_gate = node.operation.kind == OperationKind::Verify;
        if verification_gate {
            verification_barriers.push(node.id.clone());
        }
        nodes.push(NodeEffectSummary {
            node_id: node.id.clone(),
            capability: node.operation.capability.clone(),
            execution_class: node.execution_class,
            effects: derived.iter().copied().collect(),
            authority_classes: node_authorities.into_iter().collect(),
            egress_mode: node.egress.mode,
            verification_gate,
        });
    }
    if effects.len() > 1 {
        effects.remove(&EffectClass::Pure);
    }

    EffectSummary {
        schema_version: "0.1".to_owned(),
        semantic_program_hash: semantic_hash.to_owned(),
        registry_snapshot_id: snapshot_id.to_owned(),
        effects: effects.into_iter().collect(),
        authority_classes: authority_classes.into_iter().collect(),
        egress_modes: egress_modes.into_iter().collect(),
        contains_probabilistic: program
            .nodes
            .iter()
            .any(|node| node.execution_class == ExecutionClass::Probabilistic),
        contains_opaque_external: program
            .nodes
            .iter()
            .any(|node| node.execution_class == ExecutionClass::OpaqueExternal)
            || node_effects
                .values()
                .any(|effects| effects.contains(&EffectClass::LegacyOpaque)),
        nodes,
        verification_barriers,
        generated_by: Some(GeneratedBy {
            id: Some("org.ainative.aios-ir-validator".to_owned()),
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        }),
        generated_at: None,
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
