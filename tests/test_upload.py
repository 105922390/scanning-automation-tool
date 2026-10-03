"""Engagement upload: safe-parse, schema validation, slug/traversal, overwrite, size,
confirm step. Writes only into a temp engagements dir. No network."""

import asyncio
import json
from pathlib import Path

import pytest

from reconpilot.engagement import list_engagements, load_engagement
from reconpilot.web import planner, service
from reconpilot.web.app import create_app

_VALID = """
engagement:
  name: "{name}"
  program_url: "https://hackerone.com/{name}"
  authorized_by: "me"
  authorized_date: "2026-10-01"
in_scope:
  domains: ["{name}.com", "*.{name}.com"]
allowed_tools: ["httpx"]
"""


@pytest.fixture
def engdir(tmp_path):
    d = tmp_path / "engagements"
    d.mkdir()
    return d


# --------------------------------------------------------------------------- #
# validation (service)
# --------------------------------------------------------------------------- #
def test_valid_yaml_validates(engdir):
    info = service.validate_engagement_yaml(engdir, _VALID.format(name="acme"))
    assert info == {"name": "acme", "slug": "acme", "exists": False}


def test_missing_authorization_fields_rejected(engdir):
    y = ("engagement:\n  name: x\n  program_url: https://h1/x\n"
         "in_scope:\n  domains: [x.com]\nallowed_tools: [httpx]\n")   # no authorized_by/date
    with pytest.raises(service.UploadError) as e:
        service.validate_engagement_yaml(engdir, y)
    assert "authorized_by" in str(e.value)


def test_no_in_scope_rejected(engdir):
    y = ("engagement:\n  name: x\n  program_url: https://h1/x\n"
         "  authorized_by: me\n  authorized_date: 2026-10-01\n"
         "in_scope:\n  domains: []\nallowed_tools: [httpx]\n")
    with pytest.raises(service.UploadError):
        service.validate_engagement_yaml(engdir, y)


def test_unsafe_yaml_constructs_rejected(engdir):
    # safe_load must refuse arbitrary object construction / code execution tags
    y = "engagement: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(service.UploadError) as e:
        service.validate_engagement_yaml(engdir, y)
    assert "invalid YAML" in str(e.value) or "mapping" in str(e.value)


def test_path_traversal_name_rejected_or_contained(engdir):
    # a traversal-y name slugifies to safe chars and can never escape the dir
    info = service.validate_engagement_yaml(engdir, _VALID.format(name="../../etc/passwd"))
    assert "/" not in info["slug"] and ".." not in info["slug"]
    service.save_engagement_yaml(engdir, _VALID.format(name="../../etc/passwd"))
    # nothing was written outside the engagements dir
    assert not (engdir.parent.parent / "etc").exists()
    assert all((engdir / f"{s}.yaml").exists() for s in list_engagements(engdir))


def test_name_with_no_safe_chars_rejected(engdir):
    with pytest.raises(service.UploadError):
        service.validate_engagement_yaml(engdir, _VALID.format(name="///"))


def test_oversize_rejected(engdir):
    big = _VALID.format(name="acme") + ("\n# " + "x" * (service.MAX_UPLOAD_BYTES))
    with pytest.raises(service.UploadError) as e:
        service.validate_engagement_yaml(engdir, big)
    assert "too large" in str(e.value)


# --------------------------------------------------------------------------- #
# save + overwrite protection
# --------------------------------------------------------------------------- #
def test_save_writes_and_lists(engdir):
    res = service.save_engagement_yaml(engdir, _VALID.format(name="acme"))
    assert res["slug"] == "acme" and res["overwritten"] is False
    assert "acme" in list_engagements(engdir)
    assert load_engagement("acme", engdir).engagement.authorized_by == "me"


def test_overwrite_protection(engdir):
    service.save_engagement_yaml(engdir, _VALID.format(name="acme"))
    with pytest.raises(service.EngagementExists):
        service.save_engagement_yaml(engdir, _VALID.format(name="acme"))
    # explicit overwrite succeeds
    res = service.save_engagement_yaml(engdir, _VALID.format(name="acme"), overwrite=True)
    assert res["overwritten"] is True


# --------------------------------------------------------------------------- #
# endpoints over raw ASGI (confirm step + host gate)
# --------------------------------------------------------------------------- #
async def _asgi(app, method, path, body_obj=None, host="127.0.0.1:8000"):
    raw = json.dumps(body_obj).encode() if body_obj is not None else b""
    headers = [(b"host", host.encode())]
    if body_obj is not None:
        headers += [(b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "path": path, "raw_path": path.encode(),
             "query_string": b"", "scheme": "http", "root_path": "",
             "headers": headers, "client": ("127.0.0.1", 5), "server": ("127.0.0.1", 8000)}
    out, body = {}, bytearray()

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            body.extend(msg.get("body", b""))

    await app(scope, receive, send)
    out["json"] = json.loads(bytes(body) or b"null")
    return out


def test_endpoint_validate_then_save(engdir):
    app = create_app(base_dir=engdir)
    y = _VALID.format(name="acme")
    v = asyncio.run(_asgi(app, "POST", "/api/engagements/validate", {"yaml": y}))
    assert v["status"] == 200 and v["json"]["ok"] and v["json"]["slug"] == "acme"
    token = v["json"]["confirm_token"]

    saved = asyncio.run(_asgi(app, "POST", "/api/engagements",
                              {"yaml": y, "confirm_token": token}))
    assert saved["status"] == 200 and "acme" in saved["json"]["engagements"]


def test_endpoint_save_without_confirm_rejected(engdir):
    app = create_app(base_dir=engdir)
    y = _VALID.format(name="acme")
    r = asyncio.run(_asgi(app, "POST", "/api/engagements",
                          {"yaml": y, "confirm_token": ""}))
    assert r["status"] == 403
    assert list_engagements(engdir) == []            # nothing written


def test_endpoint_validate_reports_errors(engdir):
    app = create_app(base_dir=engdir)
    bad = "engagement:\n  name: x\nin_scope:\n  domains: [x.com]\nallowed_tools: [httpx]\n"
    v = asyncio.run(_asgi(app, "POST", "/api/engagements/validate", {"yaml": bad}))
    assert v["status"] == 200 and v["json"]["ok"] is False and v["json"]["errors"]


def test_endpoint_overwrite_conflict(engdir):
    app = create_app(base_dir=engdir)
    y = _VALID.format(name="acme")
    tok = asyncio.run(_asgi(app, "POST", "/api/engagements/validate",
                            {"yaml": y}))["json"]["confirm_token"]
    asyncio.run(_asgi(app, "POST", "/api/engagements", {"yaml": y, "confirm_token": tok}))
    # second save without overwrite -> 409
    tok2 = asyncio.run(_asgi(app, "POST", "/api/engagements/validate",
                             {"yaml": y}))["json"]["confirm_token"]
    r = asyncio.run(_asgi(app, "POST", "/api/engagements",
                          {"yaml": y, "confirm_token": tok2}))
    assert r["status"] == 409


def test_endpoint_rejects_foreign_host(engdir):
    app = create_app(base_dir=engdir)
    r = asyncio.run(_asgi(app, "POST", "/api/engagements/validate",
                          {"yaml": _VALID.format(name="acme")}, host="attacker.com"))
    assert r["status"] == 403
