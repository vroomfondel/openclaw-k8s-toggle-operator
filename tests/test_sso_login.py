"""Tests for :mod:`openclaw_k8s_toggle_operator.sso_login`."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from nio import LoginResponse

from openclaw_k8s_toggle_operator.sso_login import (
    SSOAuthError,
    SSOLoginError,
    SSOLoginHandler,
    SSONetworkError,
    _extract_login_token,
    parse_keycloak_form,
)

# ---------------------------------------------------------------------------
# Sample HTML fragments
# ---------------------------------------------------------------------------

_KEYCLOAK_LOGIN_FORM = """
<html>
<body>
<form id="kc-form-login" action="https://keycloak.example.com/realms/myrealm/login-actions/authenticate?session_code=abc&amp;client_id=synapse" method="post">
    <input type="hidden" name="credentialId" value="">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Sign In">
</form>
</body>
</html>
"""

_KEYCLOAK_LOGIN_FORM_REVERSED_ATTRS = """
<html>
<body>
<form action="https://keycloak.example.com/realms/myrealm/login-actions/authenticate?code=xyz" id="kc-form-login" method="post">
    <input type="hidden" value="hidden-val" name="session_code">
    <input type="text" name="username">
    <input type="password" name="password">
</form>
</body>
</html>
"""

_KEYCLOAK_ERROR_PAGE = """
<html>
<body>
<div class="alert alert-error">
    <span class="kc-feedback-text">Invalid username or password.</span>
</div>
</body>
</html>
"""

_KEYCLOAK_ACCESS_DENIED_PAGE = """
<html>
<body>
<div class="alert">
    <p>Access denied. You do not have the required role.</p>
</div>
</body>
</html>
"""

_NO_FORM_HTML = """
<html><body><h1>Not a login page</h1></body></html>
"""


# ---------------------------------------------------------------------------
# TestKeycloakFormParser
# ---------------------------------------------------------------------------


class TestKeycloakFormParser:
    """Tests for :func:`parse_keycloak_form`."""

    def test_extract_form_action(self) -> None:
        action, _ = parse_keycloak_form(_KEYCLOAK_LOGIN_FORM)
        assert action == (
            "https://keycloak.example.com/realms/myrealm/login-actions/authenticate"
            "?session_code=abc&client_id=synapse"
        )

    def test_html_entity_unescaping(self) -> None:
        action, _ = parse_keycloak_form(_KEYCLOAK_LOGIN_FORM)
        assert "&amp;" not in action
        assert "&" in action

    def test_hidden_fields(self) -> None:
        _, fields = parse_keycloak_form(_KEYCLOAK_LOGIN_FORM)
        assert "credentialId" in fields
        assert fields["credentialId"] == ""

    def test_reversed_attribute_order(self) -> None:
        action, fields = parse_keycloak_form(_KEYCLOAK_LOGIN_FORM_REVERSED_ATTRS)
        assert "keycloak.example.com" in action
        assert fields["session_code"] == "hidden-val"

    def test_missing_form_raises(self) -> None:
        with pytest.raises(SSOLoginError, match="Could not find Keycloak login form"):
            parse_keycloak_form(_NO_FORM_HTML)


class TestExtractLoginToken:
    """Tests for :func:`_extract_login_token`."""

    def test_extracts_token(self) -> None:
        url = "http://localhost:0?loginToken=abc123&other=val"
        assert _extract_login_token(url) == "abc123"

    def test_no_token_returns_none(self) -> None:
        url = "http://localhost:0?other=val"
        assert _extract_login_token(url) is None

    def test_empty_url(self) -> None:
        assert _extract_login_token("http://localhost:0") is None


# ---------------------------------------------------------------------------
# TestSSOLoginHandler
# ---------------------------------------------------------------------------


def _make_response(status: int, headers: dict[str, str] | None = None, text: str = "") -> AsyncMock:
    """Create a mock aiohttp response as an async context manager."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {}
    resp.text = AsyncMock(return_value=text)
    return resp


def _cm(mock_resp: Any) -> MagicMock:
    """Wrap a mock response so it works as an ``async with`` context manager."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_handler() -> SSOLoginHandler:
    return SSOLoginHandler(
        homeserver="https://matrix.example.com",
        idp_id="keycloak",
        username="botuser",
        password="secret",
    )


def _mock_session_ctx(mock_session_cls: MagicMock) -> AsyncMock:
    """Set up mock ClientSession as an async context manager and return the session."""
    session = AsyncMock()
    mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
    mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
    return session


class TestSSOLoginHandler:
    """Tests for :class:`SSOLoginHandler`."""

    def test_successful_flow(self) -> None:
        handler = _make_handler()

        step1_resp = _make_response(302, {"Location": "https://keycloak.example.com/auth?state=xyz"})
        step2_resp = _make_response(200, text=_KEYCLOAK_LOGIN_FORM)
        step4_resp = _make_response(
            302,
            {"Location": "https://matrix.example.com/_synapse/client/oidc/callback?code=authcode&state=xyz"},
        )
        step5_resp = _make_response(302, {"Location": "http://localhost:0?loginToken=mytoken123"})

        async def _run() -> str:
            with patch("openclaw_k8s_toggle_operator.sso_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.get = MagicMock(side_effect=[_cm(step1_resp), _cm(step2_resp), _cm(step5_resp)])
                session.post = MagicMock(return_value=_cm(step4_resp))
                return await handler.obtain_login_token()

        token = asyncio.run(_run())
        assert token == "mytoken123"

    def test_auth_failure_bad_credentials(self) -> None:
        handler = _make_handler()

        step1_resp = _make_response(302, {"Location": "https://keycloak.example.com/auth"})
        step2_resp = _make_response(200, text=_KEYCLOAK_LOGIN_FORM)
        step4_resp = _make_response(200, text=_KEYCLOAK_ERROR_PAGE)

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.sso_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.get = MagicMock(side_effect=[_cm(step1_resp), _cm(step2_resp)])
                session.post = MagicMock(return_value=_cm(step4_resp))
                await handler.obtain_login_token()

        with pytest.raises(SSOAuthError, match="Invalid username or password"):
            asyncio.run(_run())

    def test_access_denied_missing_role(self) -> None:
        handler = _make_handler()

        step1_resp = _make_response(302, {"Location": "https://keycloak.example.com/auth"})
        step2_resp = _make_response(200, text=_KEYCLOAK_LOGIN_FORM)
        step4_resp = _make_response(200, text=_KEYCLOAK_ACCESS_DENIED_PAGE)

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.sso_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.get = MagicMock(side_effect=[_cm(step1_resp), _cm(step2_resp)])
                session.post = MagicMock(return_value=_cm(step4_resp))
                await handler.obtain_login_token()

        with pytest.raises(SSOAuthError, match="Access denied"):
            asyncio.run(_run())

    def test_wrong_idp_404(self) -> None:
        handler = _make_handler()

        step1_resp = _make_response(404)

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.sso_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.get = MagicMock(return_value=_cm(step1_resp))
                await handler.obtain_login_token()

        with pytest.raises(SSOLoginError, match="IDP.*not found"):
            asyncio.run(_run())

    def test_network_error(self) -> None:
        handler = _make_handler()

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.sso_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.get = MagicMock(side_effect=aiohttp.ClientError("Connection refused"))
                await handler.obtain_login_token()

        with pytest.raises(SSONetworkError, match="Network error"):
            asyncio.run(_run())

    def test_max_redirects_exceeded(self) -> None:
        handler = _make_handler()

        step1_resp = _make_response(302, {"Location": "https://keycloak.example.com/auth"})
        step2_resp = _make_response(200, text=_KEYCLOAK_LOGIN_FORM)
        step4_resp = _make_response(302, {"Location": "https://matrix.example.com/callback1"})

        redirect_responses = [
            _make_response(302, {"Location": f"https://matrix.example.com/callback{i}"}) for i in range(2, 8)
        ]

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.sso_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.get = MagicMock(
                    side_effect=[_cm(step1_resp), _cm(step2_resp)] + [_cm(r) for r in redirect_responses]
                )
                session.post = MagicMock(return_value=_cm(step4_resp))
                await handler.obtain_login_token()

        with pytest.raises(SSOLoginError, match="Login token not found after"):
            asyncio.run(_run())

    def test_perform_login_success(self) -> None:
        handler = _make_handler()

        fake_resp = MagicMock(spec=LoginResponse)

        async def _run() -> Any:
            with patch.object(handler, "obtain_login_token", new_callable=AsyncMock, return_value="tok123"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=fake_resp)
                return await handler.perform_login(mock_client)

        result = asyncio.run(_run())

        assert result is fake_resp

    def test_perform_login_token_rejected(self) -> None:
        handler = _make_handler()

        async def _run() -> None:
            with patch.object(handler, "obtain_login_token", new_callable=AsyncMock, return_value="badtok"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=MagicMock(message="token invalid"))
                await handler.perform_login(mock_client)

        with pytest.raises(SSOLoginError, match="Matrix token login failed"):
            asyncio.run(_run())
