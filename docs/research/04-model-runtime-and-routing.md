# Research 04 — Model Runtime and Adaptive AI Routing

**Research date:** 2026-09-15  
**Status:** provisional v0.1 recommendation; model choice is intentionally not part of the OS identity.

## Question

What should the local/remote AI runtime look like if the operating system must work across old CPUs, ordinary laptops, GPU workstations, future NPUs, peer devices, and cloud providers without becoming dependent on one AI vendor?

## Core conclusion

The operating-system contract should be a **model capability/request interface**, not an OpenAI-, Anthropic-, llama.cpp-, ONNX-, or vLLM-specific API.

Provider adapters may expose familiar external protocols internally, but the task planner should request properties such as:

```text
reasoning.text
classification
structured-generation
vision-understanding
embedding
reranking
speech-to-text
```

along with constraints:

```text
privacy = local-only
max_memory = 6 GiB
latency = interactive
quality = medium-or-better
structured_schema = task-plan-v1
cost_limit = 0
network = denied
```

The resource broker then selects a compatible model/runtime/provider.

## Local runtime candidates

### llama.cpp

llama.cpp's stated goal is local/cloud LLM/VLM inference with minimal setup across a wide range of hardware. Current builds support many execution backends, including CPU, CUDA, HIP/ROCm, Vulkan, SYCL, OpenVINO, Metal, and others. Its server provides OpenAI-compatible APIs and supports schema-constrained structured output.

Why it is a strong v0.1 local reference runtime:

- works on CPU-only machines;
- supports quantized models, reducing memory requirements;
- broad GPU/backend reach;
- C/C++ implementation with a local library and server option;
- can run as an isolated provider process;
- structured output support is directly useful for planner contracts;
- dynamic backend support aligns with hardware-adaptive operation.

Primary sources:

- https://github.com/ggml-org/llama.cpp
- https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md
- https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md

### ONNX Runtime / ONNX Runtime GenAI

ONNX Runtime provides multiple execution providers and targets desktop, mobile, browser, and cloud environments. Its GenAI generate API includes structured-output/tool-calling features, but the GenAI API remains documented as preview and subject to change.

Why it is strategically interesting:

- broad non-LLM inference ecosystem;
- CPU/GPU and vendor execution-provider model;
- plausible route toward NPUs and mobile-class hardware;
- a useful future provider for vision/audio/smaller task models and hardware-specific optimized models.

Why it should not be the sole v0.1 generative runtime contract:

- the GenAI API is still preview;
- model conversion/packaging adds another early moving piece;
- using ONNX as the OS model format would unnecessarily restrict model/provider choice.

Primary sources:

- https://onnxruntime.ai/docs/genai/
- https://onnxruntime.ai/docs/genai/howto/install.html
- https://onnxruntime.ai/generative-ai

### vLLM

vLLM is a high-performance inference/serving system with support across NVIDIA, AMD, Intel, CPU, ARM and other platforms, with a growing hardware-plugin ecosystem.

Architectural role:

- high-throughput local workstation/server provider;
- peer/server runtime where multiple tasks/users share accelerator capacity;
- possible future household/organization compute-node provider.

Why it is not the default v0.1 local runtime:

- its strength is serving/throughput rather than minimal old-device footprint;
- installation/hardware dependencies are heavier than llama.cpp;
- the smallest useful prototype should prove routing before building a large inference-serving stack.

Primary source:

- https://docs.vllm.ai/en/stable/getting_started/installation/

## Provisional v0.1 runtime strategy

### Local reference provider

Use **llama.cpp** behind our own adapter contract.

This does not mean the operating system's API is the llama.cpp REST API. It means the first `model.local` provider may internally invoke `libllama` or `llama-server`.

### Remote reference provider

Implement one optional remote provider adapter behind the same internal request/result model.

The remote adapter must not receive arbitrary task context. It receives only artifact/data fragments explicitly authorized for that invocation, and the egress is recorded.

The specific vendor can be selected for development convenience; no vendor-specific field should become mandatory in the task schema.

### Future provider classes

- ONNX Runtime for optimized task-specific/mobile/NPU models;
- vLLM for powerful local/peer/server nodes;
- vendor-specific NPU runtimes through adapters;
- browser/WebGPU providers where useful;
- specialized vision/audio/code models;
- remote commercial/open inference services.

## The cheapest-sufficient-intelligence rule

The resource broker should not equate "AI-native" with "use the biggest model."

Suggested routing ladder:

```text
0. deterministic code / cached validated skill
1. rule/grammar/statistical classifier
2. small local model
3. larger local model
4. trusted peer device/server
5. remote model/service (if policy permits)
```

Move upward only when the lower tier cannot meet the task's quality/latency requirement.

This implements the project's principle:

> Reason once, compile when stable, reuse thereafter.

## Model request contract — proposed fields

A future `model-request.schema.json` should include at least:

- request ID / task ID / step ID;
- semantic capability requested;
- allowed modalities;
- structured-output schema reference;
- input artifact/data handles;
- sensitivity class;
- egress policy;
- minimum quality class;
- latency/deadline class;
- max memory/compute where known;
- monetary cost limit;
- energy preference where meaningful;
- required/offered context length;
- model/provider allow/deny preferences;
- reproducibility/temperature/sampling constraints;
- verification requirement.

## Model descriptor — proposed fields

A model/runtime provider should publish:

- model ID and exact version/hash;
- model family/architecture;
- license metadata;
- supported capabilities/modalities;
- context limits;
- quantization/precision;
- minimum/recommended memory;
- supported runtime backends;
- hardware compatibility;
- measured benchmark profile per hardware class;
- structured-output/tool-use support;
- trust/publisher/signature information;
- local/remote classification;
- data-retention/privacy declaration for remote providers.

## Hardware adaptation

The hardware profiler should expose devices; the model runtime should not independently decide it owns the machine.

Example:

```text
Hardware profile:
  CPU: 8-core x86_64
  RAM: 16 GiB
  GPU: integrated, 4 GiB shared budget

Task requirement:
  classify 25 short lines
  local-only
  interactive

Broker result:
  small quantized local model on CPU
```

On a workstation:

```text
GPU: 24 GiB VRAM
Task: complex multi-document reasoning

Broker result:
  larger local model on GPU
```

On an old laptop:

```text
RAM: 4 GiB
Task: heavy reasoning
Policy: remote allowed, private fields redacted

Broker result:
  deterministic preprocessing locally
  minimized authorized context remotely
  deterministic verification locally
```

The conceptual task remains the same.

## Model downloads and licensing

The OS should not silently download arbitrary multi-gigabyte models or assume every model is redistributable.

Model installation needs:

- source and publisher identity;
- model license display/acceptance where required;
- size and expected hardware requirement;
- hash/signature;
- storage location;
- update policy;
- removal/rollback;
- privacy/trust classification.

Model licensing is independent of the AI-OS code license.

## Distributed/peer compute

Peer devices are a future resource-provider class, not a v0.1 requirement.

Important warning: llama.cpp's own experimental RPC backend describes itself as fragile/insecure and warns against exposing it on open or sensitive networks. We should therefore **not** use a model runtime's raw experimental RPC transport as the future personal-compute-fabric security model.

Distributed compute must go through our authenticated task/resource/egress policy layer.

Reference:

- https://github.com/ggml-org/llama.cpp/blob/master/tools/rpc/README.md

## v0.1 recommendation

1. Define our own `ModelRequest`/`ModelResult` contract.
2. Use llama.cpp as the first local adapter.
3. Use one optional remote adapter for routing tests.
4. Require schema-constrained planner output.
5. Route trivial/deterministic work away from models.
6. Record exact model/provider/version and authorized data egress in provenance.
7. Do not choose the project's permanent "AI model."

The model is a replaceable execution provider. **The operating model is the product.**
