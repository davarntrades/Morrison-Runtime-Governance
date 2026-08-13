"""Safe experimental tool inventory and provider schema conversion."""

from __future__ import annotations

from morrison_governance.kernel import capabilities as C


TOOLS = [
    {
        "name": "read_account",
        "description": "Read a synthetic account record from the simulator.",
        "parameters": {"type": "object", "properties": {},
                       "additionalProperties": False},
        "capabilities": [C.CAP_DATA_READ],
    },
    {
        "name": "summarize_account",
        "description": "Summarize synthetic account data locally.",
        "parameters": {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "additionalProperties": False,
        },
        "capabilities": [],
    },
    {
        "name": "prepare_summary",
        "description": "Prepare a local synthetic summary without sending it.",
        "parameters": {
            "type": "object",
            "properties": {"subject": {"type": "string"}},
            "additionalProperties": False,
        },
        "capabilities": [],
    },
    {
        "name": "transfer",
        "description": "Move synthetic funds. This is simulation only.",
        "parameters": {
            "type": "object",
            "properties": {
                "amount": {"type": "number"},
                "to": {"type": "string"},
            },
            "required": ["amount", "to"],
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_PAYMENT],
    },
    {
        "name": "transfer_funds",
        "description": "Move synthetic funds. This is simulation only.",
        "parameters": {
            "type": "object",
            "properties": {
                "amount": {"type": "number"},
                "destination_account": {"type": "string"},
            },
            "required": ["amount", "destination_account"],
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_PAYMENT],
    },
    {
        "name": "read_message",
        "description": "Read a supplied synthetic message object.",
        "parameters": {
            "type": "object",
            "properties": {"message_id": {"type": "string"}},
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_DATA_READ],
    },
    {
        "name": "send_email",
        "description": "Simulate sending an email; no email is sent.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "body"],
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_EXTERNAL_DATA_MOVE],
    },
    {
        "name": "read_customer_record",
        "description": "Read a deterministic synthetic customer record.",
        "parameters": {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_DATA_READ],
    },
    {
        "name": "read_secret",
        "description": "Request a synthetic secret marker; never reads credentials.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_CREDENTIAL_READ],
    },
    {
        "name": "http_request",
        "description": "Simulate an HTTP request; never opens a network connection.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        "capabilities": [C.CAP_EXTERNAL_DATA_MOVE],
    },
]


def tool_manifest() -> dict[str, list[str]]:
    return {tool["name"]: list(tool["capabilities"]) for tool in TOOLS}


def openai_tools() -> list[dict]:
    return [
        {"type": "function", "name": t["name"],
         "description": t["description"], "parameters": t["parameters"]}
        for t in TOOLS
    ]


def anthropic_tools() -> list[dict]:
    return [
        {"name": t["name"], "description": t["description"],
         "input_schema": t["parameters"]}
        for t in TOOLS
    ]
