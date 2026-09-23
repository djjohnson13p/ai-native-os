"""Regenerate synthetic, deterministic portable projection fixture bundles.

The public fixture key below has no privacy value. Real exports use a fresh,
secret 32-byte key for each bundle.
"""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
KEY = bytes(range(32))
PROFILE = "aios-provenance-redacted-projection-v1"
BUNDLE_ID = "bundle:v1:" + hashlib.sha256(b"synthetic-portable-v1-fixture").hexdigest()
VERIFIED_AT = "2026-09-22T00:00:00Z"
ALIAS_DOMAIN = b"AIOS-PROVENANCE-PROJECTION-ALIAS\0v1\0"
RECORD_DOMAIN = b"AIOS-PROVENANCE-PROJECTION-RECORD\0v1\0"
DESCRIPTOR_DOMAIN = b"AIOS-PROVENANCE-PROJECTION-DESCRIPTOR\0v1\0"


def jcs(value):
    # All fixture numbers are integers; this is RFC 8785 serialization for
    # the fixture's JSON value subset.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def alias(namespace, value):
    return {
        "kind": "bundle-local-alias",
        "version": "v1",
        "namespace": namespace,
        "alias": digest(ALIAS_DOMAIN + KEY + namespace.encode() + b"\0" + value.encode()),
    }


def record(sequence, previous, event):
    value = {
        "schema_version": "0.1",
        "projection_hash_profile": PROFILE,
        "bundle_id": BUNDLE_ID,
        "sequence": sequence,
        "previous_projection_hash": previous,
        "projected_event": event,
    }
    value["projection_hash"] = digest(RECORD_DOMAIN + jcs(value))
    return value


def manifest(records):
    value = {
        "schema_version": "0.1",
        "export_profile": "privacy-redacted-projection-v1",
        "projection_hash_profile": PROFILE,
        "bundle_id": BUNDLE_ID,
        "record_count": len(records),
        "head_sequence": records[-1]["sequence"],
        "head_projection_hash": records[-1]["projection_hash"],
    }
    value["descriptor_hash"] = digest(DESCRIPTOR_DOMAIN + jcs(value))
    return value


def result(valid, code, message, sequence, head):
    return {
        "schema_version": "0.1",
        "scope": "exported-projection",
        "valid": valid,
        "original_chain_verified_offline": False,
        "original_chain_linkage_proven": False,
        "bundle_id": BUNDLE_ID,
        "from_sequence": 1,
        "to_sequence": sequence,
        "computed_projection_head_hash": head,
        "diagnostics": [] if valid else [{
            "severity": "error", "code": code, "message": message,
            "sequence": sequence,
        }],
        "verified_at": VERIFIED_AT,
    }


def write_case(name, bundle_manifest, records, expected):
    folder = ROOT / name
    folder.mkdir(exist_ok=True)
    (folder / "manifest.json").write_text(json.dumps(bundle_manifest, indent=2) + "\n", encoding="utf-8")
    (folder / "records.jsonl").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records), encoding="utf-8")
    (folder / "expected-result.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")


creation = {
    "schema_version": "0.1",
    "event_id": alias("event", "event:fixture-created"),
    "task_id": alias("task", "task:synthetic-portable-fixture"),
    "event_type": "task.created",
    "timestamp": "2026-09-22T00:00:00Z",
    "actor": {"kind": "system-service", "id": alias("principal", "service:fixture")},
    "status": "success",
    "details": {
        "revision": 1,
        "creation": {
            "principal": {"kind": "user", "id": alias("principal", "user:fixture")},
            "workspace_id": alias("workspace", "workspace:fixture"),
            "original_intent_ref": {
                "kind": "task-field-commitment", "version": "v1",
                "algorithm": "sha256-keyed-prefix", "field": "original_intent",
                "commitment": digest(b"synthetic private commitment fixture"),
            },
            "normalized_intent_ref": None,
            "constraints": None,
            "created_at": "2026-09-22T00:00:00Z",
        },
        "active_plan": None,
        "active_step_ids": [alias("step", "step:fixture")],
        "waiting_on": [],
        "failure": None,
        "recovery": None,
    },
}
completion = {
    "schema_version": "0.1",
    "event_id": alias("event", "event:fixture-completed"),
    "task_id": creation["task_id"],
    "event_type": "task.completed",
    "timestamp": "2026-09-22T00:00:01Z",
    "actor": {"kind": "system-service", "id": alias("principal", "service:fixture")},
    "output_artifacts": [alias("artifact", "artifact:fixture-output")],
    "status": "success",
    "details": {"revision": 2},
}

first = record(1, None, creation)
second = record(2, first["projection_hash"], completion)
positive = [first, second]
positive_manifest = manifest(positive)
write_case("positive", positive_manifest, positive, result(True, None, None, 2, second["projection_hash"]))

tampered = copy.deepcopy(positive)
tampered[1]["projected_event"]["actor"]["kind"] = "user"
tampered_hash = record(2, first["projection_hash"], tampered[1]["projected_event"])["projection_hash"]
write_case("tampered", positive_manifest, tampered, result(
    False, "PROJECTION_HASH_MISMATCH",
    "projected record hash does not match its contents", 2, tampered_hash,
))

wrong_namespace = copy.deepcopy(positive)
wrong_namespace[1]["projected_event"]["output_artifacts"][0]["namespace"] = "step"
wrong_namespace[1] = record(2, first["projection_hash"], wrong_namespace[1]["projected_event"])
wrong_manifest = manifest(wrong_namespace)
write_case("wrong-namespace", wrong_manifest, wrong_namespace, result(
    False, "PROJECTION_RECORD_INVALID",
    "projected record shape, order, or predecessor is invalid", 2, first["projection_hash"],
))
