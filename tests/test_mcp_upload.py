import base64

import pytest

from apps.base.models import KeyValue
from apps.base.mcp import sanitize_html_preview


def test_html_preview_sanitizer_removes_active_content_and_event_handlers():
    output = sanitize_html_preview(
        '<h1 onclick="alert(1)">Hello</h1><script>alert(2)</script>'
        '<iframe src="https://attacker.invalid"></iframe><a href="javascript:alert(3)">link</a>'
    )
    assert "Hello" in output
    assert "<script" not in output.lower()
    assert "onclick" not in output.lower()
    assert "attacker.invalid" not in output
    assert "javascript:" not in output.lower()


@pytest.mark.asyncio
async def test_mcp_initialize_and_list_tools(initialized_client):
    init_response = await initialized_client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init_response.status_code == 200
    assert init_response.json()["result"]["capabilities"]["tools"]

    tools_response = await initialized_client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    )
    assert tools_response.status_code == 200
    assert {tool["name"] for tool in tools_response.json()["result"]["tools"]} == {
        "share_text",
        "share_file",
    }


@pytest.mark.asyncio
async def test_mcp_rejects_cross_origin_requests(initialized_client):
    response = await initialized_client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        headers={"origin": "https://attacker.invalid"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_mcp_token_can_be_required(initialized_client):
    from core.settings import settings

    record = await KeyValue.filter(key="settings").first()
    config = dict(record.value)
    config["mcp_require_token"] = 1
    record.value = config
    await record.save()
    settings.user_config = config

    response = await initialized_client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "share_text", "arguments": {"text": "private"}},
        },
    )
    assert response.status_code == 401
    from apps.admin.dependencies import create_token

    token = create_token({"is_admin": True})
    authorized = await initialized_client.post(
        "/mcp",
        headers={"authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "share_text", "arguments": {"text": "private"}},
        },
    )
    assert authorized.status_code == 200
    assert "/#/?code=" in authorized.json()["result"]["structuredContent"]["url"]


@pytest.mark.asyncio
async def test_mcp_html_share_has_sandboxed_safe_preview(initialized_client):
    dangerous_html = '<h1>Hello</h1><script>alert(1)</script><img src=x onerror="alert(2)">'
    response = await initialized_client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "share_file",
                "arguments": {
                    "filename": "preview.html",
                    "content_type": "text/html",
                    "content_base64": base64.b64encode(dangerous_html.encode()).decode(),
                },
            },
        },
    )
    assert response.status_code == 200
    code = response.json()["result"]["structuredContent"]["code"]

    preview = await initialized_client.get(f"/share/preview/html/{code}")
    assert preview.status_code == 200
    assert preview.headers["content-type"].startswith("text/html")
    assert "sandbox" in preview.headers["content-security-policy"]
    assert "Hello" in preview.text
    assert "<script" not in preview.text.lower()
    assert "onerror" not in preview.text.lower()
    assert "nosniff" in preview.headers["x-content-type-options"]
