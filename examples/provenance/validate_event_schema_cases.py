"""Check the standalone provenance payload schema cases and array boundaries."""

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "specs" / "provenance-event.schema.json"
CASES = Path(__file__).with_name("event-schema-cases.json")


def main():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    for case in cases:
        actual = validator.is_valid(case["event"])
        assert actual == case["valid"], case["name"]

    base = next(case["event"] for case in cases if case["name"] == "authorization-details-allowed")
    for field in ("input_artifacts", "output_artifacts"):
        event = copy.deepcopy(base)
        event[field] = [f"artifact:{index}" for index in range(512)]
        assert validator.is_valid(event), f"{field} 512"
        event[field].append("artifact:512")
        assert not validator.is_valid(event), f"{field} 513"

    event = copy.deepcopy(base)
    event["external_transfer"] = {
        "destination": "local",
        "data_refs": [f"artifact:{index}" for index in range(512)],
    }
    assert validator.is_valid(event), "data_refs 512"
    event["external_transfer"]["data_refs"].append("artifact:512")
    assert not validator.is_valid(event), "data_refs 513"

    for field in ("event_id", "task_id"):
        event = copy.deepcopy(base)
        event[field] = "x" * 256
        assert validator.is_valid(event), f"{field} 256"
        event[field] += "x"
        assert not validator.is_valid(event), f"{field} 257"
    event = copy.deepcopy(base)
    event["actor"]["id"] = "x" * 256
    assert validator.is_valid(event), "actor.id 256"
    event["actor"]["id"] += "x"
    assert not validator.is_valid(event), "actor.id 257"

    event = copy.deepcopy(base)
    event["input_artifacts"] = ["x" * 4096]
    assert validator.is_valid(event), "artifact reference 4096"
    event["input_artifacts"][0] += "x"
    assert not validator.is_valid(event), "artifact reference 4097"
    print(f"{len(cases)} event fixtures and array/string shape boundaries passed")


if __name__ == "__main__":
    main()
