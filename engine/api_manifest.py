#!/usr/bin/env python3
"""Normalize API descriptions and captured traffic into one operation manifest.

Supported inputs: OpenAPI/Swagger JSON, HAR, Postman collections, Burp XML,
GraphQL introspection JSON, and an existing CBH manifest. Parsing is offline.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

SCHEMA_VERSION = "2.0"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_FIELDS = {
    "role", "roles", "permission", "permissions", "owner", "ownerid", "owner_id",
    "tenant", "tenantid", "tenant_id", "organization", "organizationid", "org_id",
    "price", "amount", "balance", "status", "verified", "isadmin", "is_admin",
    "email", "phone", "msisdn", "passwordresettoken", "password_reset_token",
}
ID_FIELD_RE = re.compile(r"(?:^id$|_id$|id$|uuid$|owner|tenant|account|user|order|invoice)", re.I)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{20,}$", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    p = parsed.path or "/"
    parts = []
    for part in p.split("/"):
        if part.isdigit() or UUID_RE.match(part) or (part.startswith("{") and part.endswith("}")):
            parts.append("{id}")
        else:
            parts.append(part)
    return "/".join(parts) or "/"


def operation_id(method: str, host: str, path: str) -> str:
    canonical = f"{method.upper()} {host.lower()} {normalize_path(path)}"
    short = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return f"op_{short}"


def _resolve_ref(ref: str, root: dict):
    """Follow a local JSON pointer (`#/components/schemas/Order`). Local only.

    Remote and file refs are deliberately not followed: resolving them would mean
    fetching a URL during what is documented as offline parsing, and an OpenAPI doc
    is attacker-adjacent input on a bug-bounty target.
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _schema_fields(schema: dict, seen=None, root: dict | None = None,
                   depth: int = 0) -> List[str]:
    """Field names reachable from a schema, through $ref and nesting alike.

    Without $ref resolution almost every real OpenAPI document yielded zero fields:
    request bodies are `$ref: '#/components/schemas/X'` far more often than they are
    inline. No fields meant no `property-authorization` risk hint, so mass-assignment
    candidates — the highest-value thing a spec can point at — were invisible.
    """
    seen = seen or set()
    if not isinstance(schema, dict) or depth > 12:
        return []
    ref = schema.get("$ref")
    if ref:
        if ref in seen:                       # a recursive schema, not an error
            return []
        seen.add(ref)
        target = _resolve_ref(ref, root or {})
        return _schema_fields(target or {}, seen, root, depth + 1)
    key = id(schema)
    if key in seen:
        return []
    seen.add(key)
    out = list((schema.get("properties") or {}).keys())
    # Nested objects carry the interesting fields (order.owner_id, user.role), so the
    # walk goes through properties as well as the container keywords.
    for child in (schema.get("properties") or {}).values():
        if isinstance(child, dict):
            out += _schema_fields(child, seen, root, depth + 1)
    for name in ("items", "schema", "additionalProperties"):
        child = schema.get(name)
        if isinstance(child, dict) and child:
            out += _schema_fields(child, seen, root, depth + 1)
    for name in ("allOf", "oneOf", "anyOf"):
        for item in schema.get(name) or []:
            out += _schema_fields(item, seen, root, depth + 1)
    return sorted(set(str(x) for x in out))


def risk_hints(path: str, method: str, fields: Iterable[str], secured=None) -> List[str]:
    blob = " ".join([path, *fields]).lower()
    hints = []
    if "{" in path or any(ID_FIELD_RE.search(f) for f in fields):
        hints.append("object-authorization")
    if method.upper() in WRITE_METHODS:
        hints.append("state-change")
    if any(f.lower().replace("-", "_") in SENSITIVE_FIELDS for f in fields):
        hints.append("property-authorization")
    if any(x in blob for x in ("admin", "role", "permission", "worker", "internal")):
        hints.append("function-authorization")
    if any(x in blob for x in ("oauth", "authorize", "token", "oidc")):
        hints.append("oauth")
    if "graphql" in blob:
        hints.append("graphql")
    if any(x in blob for x in ("price", "amount", "balance", "coupon", "order", "invoice", "payment")):
        hints.append("business-flow")
    if secured is False:
        hints.append("declared-public")
    return list(dict.fromkeys(hints))


def make_operation(method: str, url: str, source: str, *, fields=None, parameters=None,
                   secured=None, operation_name="", metadata=None) -> dict:
    parsed = urllib.parse.urlsplit(url)
    path = normalize_path(parsed.path)
    fields = sorted(set(fields or []))
    parameters = sorted(set(parameters or []))
    return {
        "id": operation_id(method, parsed.netloc, path),
        "method": method.upper(), "url": url, "host": parsed.hostname or "",
        "path": path, "operation_name": operation_name or "",
        "parameters": parameters, "fields": fields, "secured": secured,
        "risk_hints": risk_hints(path, method, [*fields, *parameters], secured),
        "source": source, "metadata": metadata or {},
    }


def from_openapi(doc: dict, base_url: str = "") -> List[dict]:
    servers = doc.get("servers") or []
    base = base_url or (servers[0].get("url", "") if servers else "")
    if not base and doc.get("host"):
        base = f"{doc.get('schemes', ['https'])[0]}://{doc['host']}{doc.get('basePath', '')}"
    global_security = doc.get("security")
    out = []
    for path, item in (doc.get("paths") or {}).items():
        common_params = item.get("parameters") or [] if isinstance(item, dict) else []
        for method, op in (item.items() if isinstance(item, dict) else []):
            if method.lower() not in METHODS or not isinstance(op, dict):
                continue
            all_params = [*common_params, *(op.get("parameters") or [])]
            # A parameter can itself be a $ref into components/parameters.
            all_params = [(_resolve_ref(p["$ref"], doc) or {}) if isinstance(p, dict) and p.get("$ref")
                          else p for p in all_params]
            params = [p.get("name", "") for p in all_params if isinstance(p, dict)]
            fields = []
            request_body = op.get("requestBody") or {}
            if request_body.get("$ref"):
                request_body = _resolve_ref(request_body["$ref"], doc) or {}
            for media in (request_body.get("content") or {}).values():
                fields += _schema_fields(media.get("schema") or {}, root=doc)
            # Response schemas matter too: a field the server RETURNS but the client
            # never sends is exactly where excessive data exposure lives.
            for resp in (op.get("responses") or {}).values():
                if isinstance(resp, dict) and resp.get("$ref"):
                    resp = _resolve_ref(resp["$ref"], doc) or {}
                for media in ((resp or {}).get("content") or {}).values():
                    fields += _schema_fields(media.get("schema") or {}, root=doc)
            for p in all_params:
                if isinstance(p, dict):
                    fields += _schema_fields(p.get("schema") or {}, root=doc)
            security = op.get("security", global_security)
            secured = bool(security) if security is not None else None
            out.append(make_operation(method, urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/")),
                                      "openapi", fields=fields, parameters=params, secured=secured,
                                      operation_name=op.get("operationId", ""),
                                      metadata={"tags": op.get("tags") or []}))
    return out


def from_har(doc: dict) -> List[dict]:
    out = []
    for entry in ((doc.get("log") or {}).get("entries") or []):
        req = entry.get("request") or {}
        url, method = req.get("url", ""), req.get("method", "GET")
        if not url:
            continue
        params = [x.get("name", "") for x in req.get("queryString") or []]
        fields = []
        post = req.get("postData") or {}
        fields += [x.get("name", "") for x in post.get("params") or []]
        try:
            val = json.loads(post.get("text") or "{}")
            if isinstance(val, dict):
                fields += val.keys()
        except (ValueError, TypeError):
            pass
        out.append(make_operation(method, url, "har", fields=fields, parameters=params,
                                  metadata={"status": (entry.get("response") or {}).get("status")}))
    return out


# Postman variable names whose VALUES are never carried into the manifest. The name is
# kept (knowing an endpoint takes an api_key is signal); the value is somebody's
# credential and the manifest is a file that gets committed and shared.
_POSTMAN_SECRET_RE = re.compile(
    r"token|secret|passw|api[-_]?key|auth|bearer|cookie|session|credential|signature", re.I)


def postman_variables(doc: dict, environment: dict | None = None) -> Dict[str, str]:
    """Collection + environment variables, with secret-shaped values dropped.

    Only substitution-safe values survive: a `{{baseUrl}}` that resolves turns a
    collection full of `{{baseUrl}}/v1/orders` into real hosts and paths, which is the
    difference between a usable manifest and one host called `placeholder.invalid`.
    """
    out: Dict[str, str] = {}
    for source in (doc, environment or {}):
        for var in (source.get("variable") or source.get("values") or []):
            if not isinstance(var, dict):
                continue
            key = str(var.get("key") or var.get("name") or "")
            if not key or var.get("disabled") is True:
                continue
            value = var.get("value")
            if not isinstance(value, (str, int, float)):
                continue
            if _POSTMAN_SECRET_RE.search(key):
                continue
            out[key] = str(value)
    return out


def _expand_postman(text: str, variables: Dict[str, str]) -> str:
    for key, value in variables.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def from_postman(doc: dict, environment: dict | None = None) -> List[dict]:
    out = []
    variables = postman_variables(doc, environment)
    variables.setdefault("baseUrl", "https://placeholder.invalid")

    def walk(items, folder=""):
        for item in items or []:
            if item.get("item"):
                walk(item["item"], folder=item.get("name", folder))
                continue
            req = item.get("request") or {}
            url = req.get("url")
            raw = url.get("raw", "") if isinstance(url, dict) else (url or "")
            if not raw:
                continue
            raw = _expand_postman(raw, variables)
            if "{{" in raw:
                # Park an unresolved variable rather than letting it through: a bogus
                # hostname would be scope-checked against a domain nobody owns.
                # An unresolved variable in the HOST would produce a bogus operation and,
                # worse, a scope check against a hostname nobody owns. Park it explicitly.
                raw = re.sub(r"\{\{[^}]+\}\}", "placeholder.invalid", raw, count=1)
                raw = re.sub(r"\{\{[^}]+\}\}", "{id}", raw)
            if "://" not in raw:
                raw = "https://" + raw.lstrip("/")
            params = []
            if isinstance(url, dict):
                params = [q.get("key", "") for q in url.get("query") or []
                          if isinstance(q, dict) and not q.get("disabled")]
            fields = []
            body = req.get("body") or {}
            fields += [x.get("key", "") for x in body.get("urlencoded") or []
                       if isinstance(x, dict)]
            fields += [x.get("key", "") for x in body.get("formdata") or []
                       if isinstance(x, dict)]
            try:
                val = json.loads(_expand_postman(body.get("raw") or "{}", variables))
                if isinstance(val, dict):
                    fields += val.keys()
            except (ValueError, TypeError):
                pass
            headers = [h.get("key", "") for h in req.get("header") or []
                       if isinstance(h, dict) and not h.get("disabled")]
            secured = True if any(_POSTMAN_SECRET_RE.search(h) for h in headers) else None
            if req.get("auth"):
                secured = True
            out.append(make_operation(req.get("method", "GET"), raw, "postman",
                                      fields=fields, parameters=params, secured=secured,
                                      operation_name=item.get("name", ""),
                                      metadata={"folder": folder}))
    walk(doc.get("item") or [])
    return out


def _gql_type_name(type_ref: dict | None) -> str:
    """Unwrap NON_NULL/LIST wrappers down to the named type."""
    node = type_ref or {}
    for _ in range(12):
        if node.get("name"):
            return node["name"]
        node = node.get("ofType") or {}
        if not node:
            break
    return ""


def _gql_input_fields(type_name: str, types: Dict[str, dict], depth: int = 0,
                      seen: set | None = None) -> List[str]:
    """Field names inside an INPUT_OBJECT argument, recursively.

    A mutation's argument is usually a single `input:` of an input object; without
    walking into it the operation records one parameter called `input` and no fields,
    so the sensitive members (`role`, `ownerId`, `amount`) never reach `risk_hints`.
    """
    seen = seen or set()
    if not type_name or type_name in seen or depth > 6:
        return []
    seen.add(type_name)
    node = types.get(type_name) or {}
    out = []
    for field in (node.get("inputFields") or []) + (node.get("fields") or []):
        name = field.get("name", "")
        if not name:
            continue
        out.append(name)
        out += _gql_input_fields(_gql_type_name(field.get("type")), types, depth + 1, seen)
    return out


def from_graphql(doc: dict, endpoint: str) -> List[dict]:
    """GraphQL introspection -> one operation per root field.

    Beyond the field name this now carries: the argument's input-object members (where
    mass assignment lives), the return type's own fields (excessive data exposure), the
    resolver group, and a `node(id:)`-shaped argument, which is the relay global-ID IDOR
    primitive and the single highest-value thing an introspection response points at.
    """
    schema = ((doc.get("data") or {}).get("__schema") or doc.get("__schema") or {})
    types = {t.get("name"): t for t in schema.get("types") or [] if t.get("name")}
    out = []
    for kind, method in (("queryType", "POST"), ("mutationType", "POST"),
                         ("subscriptionType", "WS")):
        root = schema.get(kind) or {}
        root_type = types.get(root.get("name"), {})
        for field in (root_type.get("fields") or []):
            name = field.get("name", "")
            args = [a.get("name", "") for a in field.get("args") or []]
            fields: List[str] = []
            for arg in field.get("args") or []:
                fields += _gql_input_fields(_gql_type_name(arg.get("type")), types)
            return_type = _gql_type_name(field.get("type"))
            fields += _gql_input_fields(return_type, types)
            op = make_operation(method, endpoint, "graphql", parameters=args, fields=fields,
                                operation_name=name, secured=None,
                                metadata={"graphql_kind": kind.replace("Type", ""),
                                          "return_type": return_type,
                                          "resolver_group": return_type or "root",
                                          "deprecated": bool(field.get("isDeprecated"))})
            hints = op["risk_hints"] + ["resolver-authorization", "batching-cost"]
            # Every GraphQL operation travels as an HTTP POST, so make_operation's
            # method-based `state-change` hint fires on plain queries too. In GraphQL
            # the verb carries no meaning — the root type does. A query marked
            # state-changing seeds CSRF and replay vectors against a read.
            if kind != "mutationType":
                hints = [h for h in hints if h != "state-change"]
            else:
                hints.append("state-change")
            # An `id`/`ids` argument on a query IS the object reference — this is the
            # node(id:) IDOR primitive, and it is worth naming rather than inferring.
            if any(a.lower() in ("id", "ids", "nodeid", "node_id") for a in args):
                hints.append("object-authorization")
            if name in ("node", "nodes") or return_type == "Node":
                hints.append("relay-global-id")
            out.append(op)
            op["risk_hints"] = list(dict.fromkeys(hints))
    return out


def _decode_burp_node(node) -> str:
    """Burp exports request/response bodies base64-encoded when they are not ASCII."""
    if node is None:
        return ""
    text = node.text or ""
    if (node.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", "replace")
        except (ValueError, binascii.Error):
            return ""
    return text


def _fields_from_body(body: str, content_type: str = "") -> List[str]:
    """Field NAMES from a captured body. Values are never read — they are live data."""
    body = (body or "").strip()
    if not body:
        return []
    ct = content_type.lower()
    if body.startswith("{") or "json" in ct:
        try:
            val = json.loads(body)
            if isinstance(val, dict):
                return [str(k) for k in val]
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return [str(k) for k in val[0]]
        except (ValueError, TypeError):
            pass
    if "form-urlencoded" in ct or ("=" in body and "\n" not in body.strip()):
        return [k for k, _ in urllib.parse.parse_qsl(body, keep_blank_values=True)]
    if "multipart" in ct:
        return re.findall(r'name="([^"]+)"', body)
    return []


def _split_http_request(raw: str) -> tuple[str, Dict[str, str], str]:
    """(request-line path, headers, body) from a raw HTTP request blob."""
    head, _, body = raw.partition("\r\n\r\n")
    if not _:
        head, _, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    path = lines[0].split(" ")[1] if lines and " " in lines[0] else ""
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return path, headers, body


def from_burp_xml(path: Path) -> List[dict]:
    """Burp proxy/history export.

    Previously this recorded method, URL and status only, which made a Burp export the
    weakest input the manifest accepted: no parameters and no body fields means no
    `property-authorization` hint, so the captured traffic contributed nothing the URL
    did not already say. The raw request is right there in the export — it just has to
    be parsed, and parsed for NAMES only: the bodies hold live session data.
    """
    out = []
    root = ET.parse(path).getroot()
    for item in root.findall(".//item"):
        url = item.findtext("url") or ""
        method = item.findtext("method") or "GET"
        if not url:
            continue
        params = [k for k, _ in urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True)]
        fields, secured = [], None
        raw = _decode_burp_node(item.find("request"))
        if raw:
            _, headers, body = _split_http_request(raw)
            fields = _fields_from_body(body, headers.get("content-type", ""))
            secured = any(h in headers for h in ("authorization", "cookie", "x-api-key")) or None
        out.append(make_operation(method, url, "burp-xml", fields=fields, parameters=params,
                                  secured=secured,
                                  metadata={"status": item.findtext("status")}))
    return out


def detect_and_parse(path: Path, base_url: str = "", graphql_endpoint: str = "",
                     postman_env: dict | None = None) -> List[dict]:
    if path.suffix.lower() == ".xml":
        return from_burp_xml(path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    if "openapi" in doc or "swagger" in doc:
        return from_openapi(doc, base_url)
    if "log" in doc and isinstance(doc.get("log"), dict):
        return from_har(doc)
    if "item" in doc and "info" in doc:
        return from_postman(doc, postman_env)
    if "__schema" in doc or "__schema" in (doc.get("data") or {}):
        if not graphql_endpoint:
            raise ValueError("GraphQL introspection input requires --graphql-endpoint")
        return from_graphql(doc, graphql_endpoint)
    if "operations" in doc:
        return doc["operations"]
    raise ValueError(f"cannot identify input format: {path}")


def merge_operations(groups: Iterable[Iterable[dict]]) -> List[dict]:
    merged: Dict[str, dict] = {}
    for group in groups:
        for op in group:
            if op["id"] not in merged:
                merged[op["id"]] = dict(op)
                merged[op["id"]]["sources"] = [op.get("source", "unknown")]
                continue
            cur = merged[op["id"]]
            for key in ("parameters", "fields", "risk_hints"):
                cur[key] = sorted(set(cur.get(key) or []) | set(op.get(key) or []))
            cur["sources"] = sorted(set(cur.get("sources") or []) | {op.get("source", "unknown")})
            if cur.get("secured") is None and op.get("secured") is not None:
                cur["secured"] = op["secured"]
    return sorted(merged.values(), key=lambda x: (x["host"], x["path"], x["method"]))


def build(inputs: Iterable[Path], base_url="", graphql_endpoint="", postman_env=None) -> dict:
    operations = merge_operations(
        detect_and_parse(p, base_url, graphql_endpoint, postman_env) for p in inputs)
    return {"schema_version": SCHEMA_VERSION, "generated_at": _now(),
            "sources": [str(p) for p in inputs], "operations": operations,
            "counts": {"operations": len(operations),
                       "hosts": len({o["host"] for o in operations})}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("--base-url", default="")
    ap.add_argument("--graphql-endpoint", default="")
    ap.add_argument("--postman-env", type=Path, default=None,
                    help="Postman environment JSON; secret-shaped values are dropped, "
                         "never written to the manifest")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    env = json.loads(args.postman_env.read_text()) if args.postman_env else None
    manifest = build(args.inputs, args.base_url, args.graphql_endpoint, env)
    args.out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{args.out}: {manifest['counts']['operations']} operations on {manifest['counts']['hosts']} hosts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
