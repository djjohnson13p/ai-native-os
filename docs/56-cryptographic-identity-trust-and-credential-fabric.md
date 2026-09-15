# 56 — Cryptographic Identity, Trust, and Credential Fabric

## Purpose

AIOS needs stable identities for users, organizations, devices, services, workloads, providers, and publishers that survive changing IP addresses, storage locations, processes, and cloud vendors.

It also needs to keep authentication separate from authorization.

The core rules are:

> **Knowing who or what something is does not automatically grant it permission.**

and:

> **Network location is not identity; possession of a credential is not unlimited authority.**

## Identity classes

AIOS should distinguish at least:

```text
USER
ORGANIZATION
DEVICE
SERVICE
WORKLOAD
PROVIDER
PACKAGE_PUBLISHER
PEER_FABRIC
AUTOMATION_PRINCIPAL
```

These are security/principal identities, not semantic business objects.

For example:

```text
principal://user/alice
object://party/alice
```

may refer to the same human in different conceptual roles, but they are not interchangeable identifiers.

## Stable cryptographic identity

Where practical, infrastructure identities should be rooted in cryptographic key material or a trusted federation that can be mapped to stable AIOS principal identity.

Examples:

```text
principal://device/laptop-a
principal://device/home-workstation
service://personal/object-store
publisher://org/ainative-project
```

IP addresses, hostnames, process IDs, container IDs, OAuth session tokens, and cloud instance IDs are runtime attributes rather than canonical identity.

## Authentication vs authorization

Authentication answers:

> Who/what is presenting this request?

Authorization answers:

> Is this principal allowed to perform this action on this resource in this Task/context?

AIOS policy must always evaluate the latter independently.

A cryptographically authenticated peer device does not gain permission to read all files.

A valid publisher signature does not grant a package unrestricted runtime authority.

## Trust domains

Useful trust-domain classes include:

```text
LOCAL_DEVICE
PERSONAL_FABRIC
HOUSEHOLD_SHARED
ORGANIZATION_MANAGED
TRUSTED_PARTNER
PUBLIC_REMOTE
UNTRUSTED
```

A trust domain is policy input, not a blanket grant.

A personal workstation might be trusted for confidential rendering while still being denied access to unrelated secrets or protected directories.

## Device enrollment and pairing

Personal Compute Fabric pairing should establish:

- stable device identity;
- mutual authentication;
- key agreement/rotation strategy;
- user-visible device name/fingerprint;
- ownership or management state;
- allowed peer roles/capability categories;
- revocation path;
- recovery path if a device is lost.

Discovery on a LAN is never sufficient to become a trusted peer.

## Service identities

Services should have stable logical identities independent of endpoints.

Example:

```text
service://personal/home-workstation/resource-broker
```

may currently resolve to a local IPv6 address, a VPN route, a relay, or another authenticated path.

Endpoint resolution happens after service identity/policy, not before.

## Workload identity

A provider process/container/component receives an ephemeral workload identity tied to:

- provider registration;
- Task/Execution Binding;
- sandbox instance;
- active grants;
- expiration/revocation.

It should not impersonate the logged-in user simply because the user initiated the Task.

## Credential mediation

Long-lived secrets should not be copied into planner/model/provider prompts or configuration files unnecessarily.

Instead, the trusted credential broker exposes opaque handles.

Example:

```text
credential://user/mail/send/default
```

A capability grant can permit a workload to use that handle for a narrowly scoped operation without revealing the underlying refresh token/private key/password.

## Credential classes

Possible classes:

```text
PRIVATE_KEY
CERTIFICATE
OAUTH_TOKEN_SET
API_CREDENTIAL
PASSWORD_REFERENCE
DATABASE_CREDENTIAL
SSH_CREDENTIAL
DEVICE_KEY
ORGANIZATION_SERVICE_IDENTITY
SECRET_REFERENCE
```

The handle record stores metadata and policy-relevant scope, not necessarily secret material itself.

## Secret storage

Actual secret material should live behind platform-appropriate secure storage such as:

- kernel/keyring mechanisms;
- TPM/secure enclave/HSM where useful;
- encrypted local secret store;
- organization secret manager;
- remote secret broker when policy permits.

The architecture should support hardware-backed storage without making it mandatory on devices that lack it.

## Exportability

Credentials should declare whether they are:

```text
NON_EXPORTABLE
LOCAL_EXPORT_RESTRICTED
DELEGABLE_HANDLE_ONLY
EXPORTABLE_WITH_APPROVAL
```

A non-exportable device key must never be serialized merely because a remote provider requests it.

## Delegation

Delegation narrows authority.

If principal A delegates to workload B, the resulting grant cannot exceed A's current authority and should include:

- Task ID;
- allowed action/resource classes;
- credential handles permitted;
- expiration;
- delegation depth;
- revocation linkage.

Delegation chains are recorded in provenance.

## Key lifecycle

The fabric needs explicit states:

```text
PENDING
ACTIVE
ROTATING
REVOKED
EXPIRED
RECOVERY_ONLY
COMPROMISED
```

Key rotation should preserve principal identity while changing cryptographic material.

This is analogous to provider substitution: key material is implementation state, not the durable identity of the principal.

## Revocation

Revocation must propagate according to risk and connectivity:

- current device denies immediately;
- paired peers receive signed revocation when reachable;
- remote services reject at next validation;
- offline grants expire conservatively;
- cached authorization never outlives its validity window.

A lost device can be removed from the Personal Compute Fabric without changing every Object/Task identity it previously touched.

## Attestation

Hardware/software attestation can provide evidence such as:

- secure boot state;
- measured component version;
- TPM-backed device identity;
- confidential-compute environment claim.

Attestation is evidence used by policy.

It does not override ordinary authorization, data-egress, or user-consent rules.

## Publisher identity

Packages/providers/Domain Packs/Views/Skills may be signed by stable publisher identities.

A signature proves:

- which key signed the package;
- whether bytes changed after signing;
- possibly whether the key chains to a trusted publisher policy.

It does **not** prove the software is safe, correct, non-malicious, or appropriate for broad authority.

Conformance, review, sandboxing, policy, and reputation remain separate.

## Human approval identity

Consequential approvals should be bound to an authenticated human/system principal and trusted system UI.

Approval records include:

```text
principal
Task
operation/effect summary
object/resource references
semantic program revision
expiry/revalidation conditions
timestamp
```

An untrusted provider View cannot manufacture a system approval merely by drawing a similar-looking button.

## Federation

AIOS should adapt to existing identity systems rather than require one global account provider.

Possible adapters include:

- local OS credentials/passkeys;
- WebAuthn/FIDO-style authenticators;
- OIDC/OAuth identity providers;
- enterprise directory/federation;
- SSH/certificate identities;
- service-account systems.

Federated identity maps into stable AIOS principal identity under explicit trust policy.

## Recovery

Account/device recovery is security-sensitive and should not be delegated to unconstrained AI judgment.

Recovery policy may use:

- recovery keys;
- multiple trusted devices;
- organization administrators;
- hardware-backed recovery;
- time delays;
- explicit emergency modes.

Every recovery action is auditable and may invalidate previous credentials.

## Privacy

Identity metadata can itself be sensitive.

The system should minimize disclosure of:

- device inventory;
- organization membership;
- external account identifiers;
- credential scopes;
- user relationship graph.

Remote providers receive only the identity claims required for their task.

## v0.1 boundary

The first prototype needs only:

- local user/system-service principal identities;
- provider/workload identity;
- task-scoped capability grants;
- opaque secret/credential handle abstraction;
- a design compatible with future device/service identities.

Full distributed PKI/federation is later work.

## Principle

> **Stable identity enables trust decisions; deterministic policy grants authority; credentials are narrowly mediated tools, not ambient power.**
