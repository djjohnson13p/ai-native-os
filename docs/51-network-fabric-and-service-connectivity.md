# 51 — Network Fabric and Service Connectivity

## Purpose

AIOS needs networking that supports ordinary internet access, local services, peer devices, remote providers, cloud execution, device discovery, synchronization, streaming, and offline/partitioned operation without exposing every capability to an unrestricted socket API.

The network architecture should preserve the same principles as the rest of the system:

- semantic intent above implementation;
- explicit authority;
- identity above address;
- provenance for external transfer;
- graceful degradation;
- provider/network substitution;
- local-first operation where practical.

## Principle

> **Tasks address trusted services and semantic destinations; the Network Fabric resolves transport, path, endpoint, and session details under policy.**

Applications/providers should not need blanket network access merely because they communicate.

## Layers

```text
Task / capability request
        ↓
semantic destination + data/effect declaration
        ↓
network policy / egress gate
        ↓
Network Broker
        ↓
service identity + route/path selection
        ↓
transport/session
        ↓
Wi-Fi · Ethernet · cellular · VPN/overlay · local IPC · internet · peer link
```

## Service identity vs network address

AIOS should avoid binding semantics to IP addresses, DNS names, or one cloud endpoint when possible.

Conceptually:

```text
service://user-home/workstation-render
service://org/billing-provider
service://model/reasoning/default
service://storage/object-sync
```

A service identity may resolve to one or more current endpoints.

Address resolution is runtime state; it does not change the Task's semantic program.

## Network authority

Providers should request bounded network capabilities such as:

```text
connect(service://org/crm)
connect(api.example.test:443)
listen(task-local-port)
publish(service://user/device-preview)
peer-transfer(peer://home-workstation)
```

instead of receiving unrestricted outbound/inbound networking by default.

Policy can constrain:

- destination/service class;
- protocol/port;
- data sensitivity;
- bytes/rate;
- time window;
- network class;
- metered networks;
- geographic/data-residency constraints;
- trusted-peer-only routes;
- inbound exposure.

## Network classes

Suggested normalized classes:

```text
LOOPBACK
LOCAL_TRUSTED
LOCAL_UNTRUSTED
PERSONAL_PEER
ORG_MANAGED
PUBLIC_INTERNET
METERED_WAN
RESTRICTED_WAN
OFFLINE
```

Network class influences policy but does not itself imply trust.

A home LAN device is not automatically trusted because it shares a subnet.

## Device and service discovery

Discovery should be separate from authorization.

Potential discovery sources include:

- local link/service discovery;
- previously paired peer registry;
- organization directory;
- configured provider registry;
- cloud/service directory;
- manual endpoint.

Discovery answers:

> "What might be reachable?"

Policy/authentication answers:

> "What is this, do I trust it, and may this Task communicate with it?"

## Personal Compute Fabric networking

Paired user-owned devices need authenticated encrypted channels that survive ordinary address changes.

Each peer should have a stable cryptographic/device identity independent of current IP address.

Peer session establishment should verify:

- pairing/trust state;
- current credential/key validity;
- task/user authorization;
- device posture where required;
- requested capability/data class;
- session freshness/replay protection.

A paired peer does not automatically gain filesystem/object visibility.

## Path selection

A single service may be reachable through multiple paths:

```text
same-LAN direct
peer overlay
organization VPN
relay
public internet
cellular
```

The Network Broker can choose among eligible paths using:

- policy;
- latency;
- bandwidth;
- loss/jitter;
- metering;
- energy;
- privacy;
- reliability;
- current reachability.

Hard policy exclusions occur before optimization.

## Multipath and failover

Later phases should support controlled path failover/multipath for resumable operations.

Changing path must not silently duplicate irreversible effects.

The operation/task layer still owns idempotency/outcome semantics.

For example, retrying an upload stream may be safe; retrying a "send order" API request requires operation-level guarantees.

## Data transfer objects

Bulk data movement should use explicit transfer records rather than invisible provider socket traffic when practical.

A transfer can declare:

```text
source artifact/object
destination service/peer
content hash
size
sensitivity
encryption requirement
retention/cache policy
resumability
expected purpose
```

This improves placement estimation, provenance, cancellation, and recovery.

## Content-addressed transfer

The Personal Compute Fabric can benefit from content-addressed objects/artifacts:

- avoid resending data already present on peer;
- resume interrupted transfers;
- verify integrity;
- account for actual data movement in placement decisions.

Possession of a hash does not confer access. The receiver still needs authority to obtain the content.

## Local service fabric

Core AIOS services/providers should prefer authenticated local IPC or narrowly scoped local service interfaces instead of opening TCP listeners unnecessarily.

Local networking is not automatically safer than IPC; namespace/credential boundaries still apply.

## Inbound connectivity

Inbound exposure should default closed.

A provider wishing to receive external traffic must request a published service capability with:

- service identity;
- interface contract;
- authentication requirement;
- allowed callers;
- binding scope;
- duration;
- rate/resource limits;
- isolation profile.

The system can then choose direct bind, reverse tunnel, relay, or no exposure according to environment/policy.

## NAT/firewall/relay reality

AIOS should not assume public routability.

The fabric should tolerate:

- NAT;
- carrier-grade NAT;
- dynamic IPs;
- firewalls;
- sleeping mobile devices;
- intermittent networks;
- captive portals;
- IPv4/IPv6 differences.

Relays/overlays may improve reachability, but they remain explicit infrastructure providers and do not become hidden data authorities.

## Offline and partitioned operation

Network loss is normal.

AIOS should support:

```text
offline-capable tasks
queued outbound operations
sync-after-reconnect
conflict detection
resumable transfer
deferred remote placement
local peer operation without internet where possible
```

Irreversible queued actions require revalidation at dispatch time because authorization, destination state, or user intent may have changed while offline.

## Network provenance

Material external transfers should record:

- Task / semantic node;
- source artifact/object references;
- destination service/provider/peer identity;
- purpose;
- policy decision;
- bytes/content hashes where appropriate;
- transport/path class;
- start/completion/failure;
- encryption/authentication class;
- remote operation identifier when applicable.

Users should be able to answer:

> "What left my devices, where did it go, and why?"

## Network security baseline

The fabric should favor:

- authenticated encrypted transport;
- modern forward-secure sessions;
- certificate/key pinning or service identity where appropriate;
- short-lived credentials;
- explicit trust roots;
- key rotation/revocation;
- replay resistance;
- minimal inbound surface;
- DNS/name-resolution hardening;
- no plaintext secret transport.

Exact protocols can evolve and should be selected through ADRs/experiments rather than becoming semantic contracts.

## Cloud relationship

Cloud is one destination/provider class on this fabric, not a privileged architectural center.

The same Network Broker path can reach:

- a user's workstation;
- a NAS/home server;
- organization infrastructure;
- a managed edge node;
- a public cloud service;
- a model API;
- a legacy remote desktop/application host.

Policy and semantic capability requirements decide eligibility.

## v0.1 scope

The first implementation only needs a narrow proof:

1. no-network provider sandbox by default;
2. allowlisted outbound service capability;
3. local-only policy denial fixture;
4. one simulated trusted peer path;
5. one remote provider path;
6. network transfer provenance;
7. disconnect/retry without duplicate external effect.

## Principle

> **Networking is a policy-governed execution resource, not ambient permission inherited by software.**
