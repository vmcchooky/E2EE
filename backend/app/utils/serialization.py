import json


def to_json(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"))


def from_json(value: str) -> dict:
    return json.loads(value)


