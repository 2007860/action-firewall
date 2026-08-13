from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict
from typing import Any, Literal
from urllib.parse import urlparse
from html.parser import HTMLParser
import re

app = FastAPI(title="Deterministic Action Firewall")

TENANT_ID = "tenant-3ap0h9j"
ALLOWED_EMAIL_DOMAIN = "notify-sloc0qo.example"
ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    args: dict[str, Any]


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provenance: Literal["trusted", "untrusted"]
    humanApproved: bool
    untrustedContent: str | None = None
    action: Action


class SafetyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t in {"script", "iframe"}:
            self.unsafe = True
            return

        for name, value in attrs:
            n = name.lower()
            v = value or ""
            if n.startswith("on"):
                self.unsafe = True
                return
            if re.match(r"^\s*javascript\s*:", v, re.I):
                self.unsafe = True
                return

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def is_safe_html(html: str) -> bool:
    parser = SafetyParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return False
    return not parser.unsafe


def valid_exact_args(args: dict[str, Any], expected: set[str]) -> bool:
    return set(args.keys()) == expected


def valid_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def valid_query(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 200


def valid_email(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    # Strict enough for this gate: exactly one @, non-empty local/domain,
    # and no whitespace.
    if any(c.isspace() for c in value) or value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    return bool(local) and domain == ALLOWED_EMAIL_DOMAIN


@app.post("/action-firewall")
def action_firewall(req: Request):
    # Pydantic performs the top-level and action object schema checks before
    # entering this function. Invalid JSON/types are handled by FastAPI as 422.
    action = req.action
    tool = action.tool
    args = action.args

    # 1. Tool allowlist
    if tool not in ALLOWED_TOOLS:
        return {"decision": "block", "reason": "TOOL_NOT_ALLOWED"}

    # 2. Selected tool's argument schema
    if tool == "search":
        if not valid_exact_args(args, {"query"}) or not valid_query(args.get("query")):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "lookup_record":
        if not valid_exact_args(args, {"tenantId", "recordId"}):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}
        if not valid_nonempty_string(args.get("tenantId")) or not valid_nonempty_string(args.get("recordId")):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "send_email":
        if not valid_exact_args(args, {"to", "subject", "body"}):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}
        if not valid_email(args.get("to")):
            # Recipient format/domain is an egress boundary; malformed addresses
            # are treated as denied egress rather than an approval problem.
            return {"decision": "block", "reason": "EGRESS_DENIED"}
        if not isinstance(args.get("subject"), str) or not isinstance(args.get("body"), str):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "render_html":
        if not valid_exact_args(args, {"html"}) or not isinstance(args.get("html"), str):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    # 3. Tenant scope
    if tool == "lookup_record" and args["tenantId"] != TENANT_ID:
        return {"decision": "block", "reason": "TENANT_SCOPE"}

    # 4. Exact email domain / approval
    if tool == "send_email":
        # valid_email already enforces the exact assigned domain.
        if not req.humanApproved:
            return {"decision": "block", "reason": "APPROVAL_REQUIRED"}

    # 5. HTML safety
    if tool == "render_html" and not is_safe_html(args["html"]):
        return {"decision": "block", "reason": "UNSAFE_OUTPUT"}

    return {"decision": "allow", "reason": "ALLOW"}
