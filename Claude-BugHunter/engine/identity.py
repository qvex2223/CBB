#!/usr/bin/env python3
"""identity.py — self-provisioned test identities for authorized engagements.

The old failure mode was: an authenticated flow is needed, the agent asks the
operator for an account, work stalls. This module is the "no" to that: the tool
provisions its own throwaway email (and a temporary phone number when an SMS
provider is configured) and registers by itself, through the browser or HTTP.

Rules baked into the code, not the prompt:

* Scope-gated: the target host must resolve as in-scope for the detected
  engagement before an identity is minted AT ALL. Out-of-scope raises.
* Profile-gated: `self_registration: false` in `Targets/<name>/profile.json`
  disables it for that program. Programs that gate sign-up on real government
  identity (IIN/ЭЦП-class) are a block, not a task — the caller logs it under
  `blocked-tests/` and moves on.
* No bypass services: no CAPTCHA solvers, no third-party cookie/token reuse. A
  CAPTCHA wall stops registration; it is recorded as blocked, never worked
  around.
* Never asks a human: every failure returns a structured result with
  `status: "blocked"` and a reason. Blocking is an answer too.
* Hygiene: credentials live at `Targets/<name>/identity.json`, mode 0600. The
  audit/journal sees provider + address, never the password or tokens.

Email uses the free mail.tm API (no key). Phone numbers need a paid SMS
provider; configure it in profile.json:

    "sms_provider": {"kind": "sms-activate", "api_key_env": "SMS_ACTIVATE_KEY",
                     "service": "ot", "country": 0}

Without it `provision()` returns an email-only identity with `phone: null` —
that is a supported state, not an error; flows that require SMS decline with a
clear reason instead of asking the operator.

CLI:  cbh identity new <url> | show [project-dir] | inbox
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pacing import find_project_dir, Engagement  # noqa: E402

IDENTITY_FILE = "identity.json"
MAILTM_BASE = "https://api.mail.tm"
SMS_TIMEOUT = 20


class ProvisioningBlocked(RuntimeError):
    """A policy-level refusal (scope, profile, capability), not a network error."""


def _http_json(url: str, *, method: str = "GET", data: dict | None = None,
               headers: dict | None = None, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, method=method)
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, data=body, timeout=timeout) as resp:
        raw = resp.read(1 << 20)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {"raw": raw.decode("utf-8", "replace")}


def _random_local_part() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "cbh-" + "".join(secrets.choice(alphabet) for _ in range(10))


def provision_email() -> dict:
    """Create a throwaway mail.tm mailbox. Returns address/password/token."""
    domains = _http_json(f"{MAILTM_BASE}/domains")
    members = domains.get("hydra:member") or []
    if not members:
        raise ProvisioningBlocked("mail.tm returned no available domains")
    domain = members[0].get("domain")
    if not domain:
        raise ProvisioningBlocked("mail.tm domain list is malformed")
    address = f"{_random_local_part()}@{domain}"
    password = secrets.token_urlsafe(18)
    _http_json(f"{MAILTM_BASE}/accounts", method="POST",
               data={"address": address, "password": password})
    token_resp = _http_json(f"{MAILTM_BASE}/token", method="POST",
                            data={"address": address, "password": password})
    token = token_resp.get("token")
    if not token:
        raise ProvisioningBlocked("mail.tm account was created but login token failed")
    return {"provider": "mail.tm", "address": address, "password": password,
            "token": token}


def read_inbox(identity: dict) -> list[dict]:
    """List the newest messages of a mail.tm identity (id, subject, from, intro)."""
    if identity.get("provider") != "mail.tm" or not identity.get("token"):
        raise ProvisioningBlocked("inbox reading is implemented for mail.tm identities only")
    headers = {"Authorization": f"Bearer {identity['token']}"}
    listing = _http_json(f"{MAILTM_BASE}/messages", headers=headers)
    out = []
    for msg in (listing.get("hydra:member") or [])[:10]:
        out.append({"id": msg.get("id"), "subject": msg.get("subject"),
                    "from": (msg.get("from") or {}).get("address"),
                    "intro": msg.get("intro")})
    return out


def fetch_message(identity: dict, message_id: str) -> str:
    """Fetch one message body (used to pull verification links/codes)."""
    headers = {"Authorization": f"Bearer {identity['token']}"}
    msg = _http_json(f"{MAILTM_BASE}/messages/{message_id}", headers=headers)
    text = msg.get("text") or ""
    if not text:
        html = msg.get("html")
        text = html[0] if isinstance(html, list) and html else (html or "")
    return text


# ---------------------------------------------------------------------------
# temporary phone numbers — sms-activate-compatible providers only
#
# The SMS provider is a paid third party; nothing here fires unless the
# engagement profile names one AND its API key is in the environment. The
# adapter speaks the sms-activate HTTP dialect, which several providers mirror.
# ---------------------------------------------------------------------------

def _sms_is_configured(profile: dict) -> dict | None:
    cfg = profile.get("sms_provider")
    if not isinstance(cfg, dict) or cfg.get("kind") != "sms-activate":
        return None
    key_env = cfg.get("api_key_env")
    if not key_env or not os.environ.get(key_env):
        return None
    return cfg


def _sms_call(cfg: dict, **params) -> str:
    base = cfg.get("base", "https://api.sms-activate.ru/stubs/handler/api.php")
    query = {"api_key": os.environ[cfg["api_key_env"]], **params}
    url = base + "?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=SMS_TIMEOUT) as resp:
        return resp.read(1 << 16).decode("utf-8", "replace").strip()


def provision_phone(profile: dict) -> tuple[str | None, str | None, str]:
    """Returns (number, activation_id, reason). (None, None, reason) is a
    supported outcome — an email-only identity, not a crash."""
    cfg = _sms_is_configured(profile)
    if cfg is None:
        return None, None, "no sms_provider configured (or API-key env unset); email-only identity"
    try:
        resp = _sms_call(cfg, action="getNumber", service=cfg.get("service", "ot"),
                         country=cfg.get("country", 0))
    except (OSError, urllib.error.URLError) as e:
        return None, None, f"sms provider unreachable: {e}"
    if resp.startswith("ACCESS_NUMBER:"):
        _, activation_id, number = resp.split(":", 2)
        return number, activation_id, "ok"
    return None, None, f"sms provider refused: {resp}"


def phone_code(cfg: dict | None, activation_id: str) -> str | None:
    """Poll once for the SMS code of an activation. Returns the code or None."""
    if not cfg:
        return None
    resp = _sms_call(cfg, action="getStatus", id=activation_id)
    if resp.startswith("STATUS_OK:"):
        return resp.split(":", 1)[1]
    return None


# ---------------------------------------------------------------------------
# engagement policy + persistence
# ---------------------------------------------------------------------------

def _engagement(start: Path | None = None) -> Engagement:
    eng = Engagement.detect(start)
    if eng.project_dir is None:
        raise ProvisioningBlocked(
            "no engagement resolved (run inside Targets/<name>/ or set CBH_PROJECT) — "
            "identities are provisioned per program, never free-floating")
    return eng


def _check_scope(eng: Engagement, target_url: str) -> None:
    scope_md = eng.project_dir / "scope.md"
    if not scope_md.is_file():
        raise ProvisioningBlocked(f"{scope_md} is missing — no scope file, no provisioning")
    from scope import _scope_from_md  # noqa: PLC0415
    scope = _scope_from_md(scope_md)
    if not scope.in_scope_host(target_url):
        raise ProvisioningBlocked(
            f"{target_url} is outside the engagement scope — refusing to mint an "
            "identity for a host the program did not authorize")


def _identity_path(eng: Engagement) -> Path:
    return eng.project_dir / IDENTITY_FILE


def save_identity(eng: Engagement, identity: dict) -> Path:
    path = _identity_path(eng)
    path.write_text(json.dumps(identity, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    path.chmod(0o600)
    return path


def load_identity(eng: Engagement) -> dict | None:
    path = _identity_path(eng)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def redacted_copy(identity: dict) -> dict:
    """What may appear in logs/audit: provider, address, masked password, flags."""
    out = dict(identity)
    if out.get("password"):
        out["password"] = "<redacted>"
    if out.get("token"):
        out["token"] = "<redacted>"
    return out


def provision(target_url: str, start: Path | None = None) -> dict:
    """Mint a self-serve identity scoped to the detected engagement.

    Always returns a dict. On any policy refusal the result carries
    status=blocked and a reason — callers log that under blocked-tests/ and
    keep hunting the unauthenticated surface; asking a human is not an outcome.
    """
    try:
        eng = _engagement(start)
        profile = eng.profile
        if profile.get("self_registration") is False:
            return {"status": "blocked",
                    "reason": f"{eng.name}: self-registration is disabled in profile.json"}
        _check_scope(eng, target_url)
        email = provision_email()
        number, activation_id, phone_reason = provision_phone(profile)
        identity = {
            "status": "ready",
            "target": target_url,
            "project": eng.name,
            "email": email["address"],
            "password": email["password"],
            "provider": email["provider"],
            "token": email["token"],
            "phone": number,
            "phone_status": phone_reason,
            "sms_activation_id": activation_id,
        }
        save_identity(eng, identity)
        try:
            from memory import Memory  # noqa: PLC0415
            Memory().audit({"source": "identity", "project": eng.name,
                            "target": target_url, **redacted_copy(identity)})
        except Exception:  # noqa: BLE001 - audit must never break provisioning
            pass
        return identity
    except ProvisioningBlocked as e:
        return {"status": "blocked", "reason": str(e)}
    except (OSError, urllib.error.URLError) as e:
        return {"status": "blocked", "reason": f"provider error: {e}"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="identity", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p_new = sub.add_parser("new", help="mint a throwaway email (+ SMS if configured) for an in-scope host")
    p_new.add_argument("url")
    p_show = sub.add_parser("show", help="print the engagement's stored identity (redacted)")
    p_show.add_argument("path", nargs="?", default=None)
    sub.add_parser("inbox", help="list the newest messages of the stored mail.tm identity")
    args = ap.parse_args(argv)

    if args.command == "new":
        ident = provision(args.url)
        print(json.dumps(redacted_copy(ident), indent=2, ensure_ascii=False))
        if ident.get("status") == "blocked":
            print("\nBLOCKED — log this under blocked-tests/ and continue with the "
                  "unauthenticated surface. If the flow genuinely needs real data only "
                  "the operator owns (their phone/account/ID), ask them — once, naming "
                  "exactly what is needed and what was already tried.")
            return 2
        print("\nIdentity saved to the engagement's identity.json (0600). "
              "Register yourself via the Playwright MCP tools; pull verification "
              "mail with `cbh identity inbox`.")
        return 0
    if args.command == "show":
        start = Path(args.path).resolve() if args.path else None
        eng = _engagement(start)
        ident = load_identity(eng)
        print(json.dumps(redacted_copy(ident), indent=2, ensure_ascii=False)
              if ident else "no identity stored for this engagement")
        return 0 if ident else 1
    if args.command == "inbox":
        eng = _engagement(None)
        ident = load_identity(eng)
        if not ident:
            print("no identity stored — run `cbh identity new <url>` first")
            return 1
        try:
            for m in read_inbox(ident):
                print(f"{m['id']}  {m.get('from') or '?'}  {m.get('subject') or '(no subject)'}")
        except ProvisioningBlocked as e:
            print(f"BLOCKED: {e}")
            return 2
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
