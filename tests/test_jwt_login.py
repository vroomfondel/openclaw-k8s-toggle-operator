"""Tests for :mod:`openclaw_k8s_toggle_operator.jwt_login`."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from nio import LoginResponse

from openclaw_k8s_toggle_operator.jwt_login import (
    JWTAuthError,
    JWTLoginError,
    JWTLoginHandler,
    JWTNetworkError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status: int, json_data: dict[str, Any] | None = None) -> AsyncMock:
    """Create a mock aiohttp response as an async context manager."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data or {})
    return resp


def _cm(mock_resp: Any) -> MagicMock:
    """Wrap a mock response so it works as an ``async with`` context manager."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_handler(
    client_secret: str = "my-secret", login_type: str = "com.famedly.login.token.oauth"
) -> JWTLoginHandler:
    return JWTLoginHandler(
        keycloak_url="https://keycloak.example.com",
        realm="master",
        client_id="clawdbot-operator",
        client_secret=client_secret,
        username="botuser",
        password="secret",
        login_type=login_type,
    )


def _mock_session_ctx(mock_session_cls: MagicMock) -> AsyncMock:
    """Set up mock ClientSession as an async context manager and return the session."""
    session = AsyncMock()
    mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=session)
    mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
    return session


# ---------------------------------------------------------------------------
# TestJWTLoginHandler — obtain_jwt_token
# ---------------------------------------------------------------------------


class TestJWTLoginHandlerObtainToken:
    """Tests for :meth:`JWTLoginHandler.obtain_jwt_token`."""

    def test_successful_flow(self) -> None:
        handler = _make_handler()

        token_resp = _make_response(200, {"access_token": "eyJhbG.payload.sig"})

        async def _run() -> str:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                return await handler.obtain_jwt_token()

        token = asyncio.run(_run())
        assert token == "eyJhbG.payload.sig"

    def test_confidential_client(self) -> None:
        handler = _make_handler(client_secret="my-secret")

        token_resp = _make_response(200, {"access_token": "tok"})
        captured_data: dict[str, str] = {}

        async def _run() -> str:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                result = await handler.obtain_jwt_token()
                # Capture the POST data argument
                call_kwargs = session.post.call_args
                captured_data.update(call_kwargs.kwargs.get("data", call_kwargs[1].get("data", {})))
                return result

        asyncio.run(_run())
        assert "client_secret" in captured_data
        assert captured_data["client_secret"] == "my-secret"

    def test_public_client(self) -> None:
        handler = _make_handler(client_secret="")

        token_resp = _make_response(200, {"access_token": "tok"})
        captured_data: dict[str, str] = {}

        async def _run() -> str:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                result = await handler.obtain_jwt_token()
                call_kwargs = session.post.call_args
                captured_data.update(call_kwargs.kwargs.get("data", call_kwargs[1].get("data", {})))
                return result

        asyncio.run(_run())
        assert "client_secret" not in captured_data

    def test_invalid_credentials_401(self) -> None:
        handler = _make_handler()

        token_resp = _make_response(401, {"error": "invalid_grant"})

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                await handler.obtain_jwt_token()

        with pytest.raises(JWTAuthError, match="invalid credentials"):
            asyncio.run(_run())

    def test_ropc_disabled_400(self) -> None:
        handler = _make_handler()

        token_resp = _make_response(
            400, {"error": "unauthorized_client", "error_description": "Client not allowed ROPC"}
        )

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                await handler.obtain_jwt_token()

        with pytest.raises(JWTAuthError, match="Client not allowed ROPC"):
            asyncio.run(_run())

    def test_network_error(self) -> None:
        handler = _make_handler()

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(side_effect=aiohttp.ClientError("Connection refused"))
                await handler.obtain_jwt_token()

        with pytest.raises(JWTNetworkError, match="Network error"):
            asyncio.run(_run())

    def test_missing_access_token(self) -> None:
        handler = _make_handler()

        token_resp = _make_response(200, {"token_type": "Bearer"})

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                await handler.obtain_jwt_token()

        with pytest.raises(JWTLoginError, match="missing access_token"):
            asyncio.run(_run())

    def test_unexpected_status(self) -> None:
        handler = _make_handler()

        token_resp = _make_response(500)

        async def _run() -> None:
            with patch("openclaw_k8s_toggle_operator.jwt_login.aiohttp.ClientSession") as mock_cls:
                session = _mock_session_ctx(mock_cls)
                session.post = MagicMock(return_value=_cm(token_resp))
                await handler.obtain_jwt_token()

        with pytest.raises(JWTLoginError, match="Unexpected Keycloak response: HTTP 500"):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# TestJWTLoginHandler — perform_login
# ---------------------------------------------------------------------------


class TestJWTLoginHandlerPerformLogin:
    """Tests for :meth:`JWTLoginHandler.perform_login`."""

    def test_perform_login_success(self) -> None:
        handler = _make_handler()
        fake_resp = MagicMock(spec=LoginResponse)

        async def _run() -> Any:
            with patch.object(handler, "obtain_jwt_token", new_callable=AsyncMock, return_value="jwt-tok"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=fake_resp)
                return await handler.perform_login(mock_client)

        result = asyncio.run(_run())
        assert result is fake_resp

    def test_perform_login_matrix_failure(self) -> None:
        handler = _make_handler()

        async def _run() -> None:
            with patch.object(handler, "obtain_jwt_token", new_callable=AsyncMock, return_value="jwt-tok"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=MagicMock(message="JWT not accepted"))
                await handler.perform_login(mock_client)

        with pytest.raises(JWTLoginError, match="Matrix JWT login failed"):
            asyncio.run(_run())

    def test_perform_login_calls_login_raw_correctly(self) -> None:
        handler = _make_handler()
        fake_resp = MagicMock(spec=LoginResponse)

        async def _run() -> dict[str, Any]:
            with patch.object(handler, "obtain_jwt_token", new_callable=AsyncMock, return_value="my-jwt"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=fake_resp)
                await handler.perform_login(mock_client)
                result: dict[str, Any] = mock_client.login_raw.call_args[0][0]
                return result

        login_body = asyncio.run(_run())
        assert login_body["type"] == "com.famedly.login.token.oauth"
        assert login_body["identifier"] == {"type": "m.id.user", "user": "botuser"}
        assert login_body["token"] == "my-jwt"
        assert login_body["initial_device_display_name"] == "openclaw-toggle-operator"

    def test_perform_login_famedly_token_type(self) -> None:
        """Verify com.famedly.login.token format includes identifier."""
        handler = _make_handler(login_type="com.famedly.login.token")
        fake_resp = MagicMock(spec=LoginResponse)

        async def _run() -> dict[str, Any]:
            with patch.object(handler, "obtain_jwt_token", new_callable=AsyncMock, return_value="jwt-tok"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=fake_resp)
                await handler.perform_login(mock_client)
                result: dict[str, Any] = mock_client.login_raw.call_args[0][0]
                return result

        login_body = asyncio.run(_run())
        assert login_body["type"] == "com.famedly.login.token"
        assert "identifier" in login_body
        assert login_body["identifier"] == {"type": "m.id.user", "user": "botuser"}
        assert login_body["token"] == "jwt-tok"

    def test_perform_login_native_jwt_type(self) -> None:
        """Verify org.matrix.login.jwt format does not include identifier."""
        handler = _make_handler(login_type="org.matrix.login.jwt")
        fake_resp = MagicMock(spec=LoginResponse)

        async def _run() -> dict[str, Any]:
            with patch.object(handler, "obtain_jwt_token", new_callable=AsyncMock, return_value="jwt-tok"):
                mock_client = AsyncMock()
                mock_client.login_raw = AsyncMock(return_value=fake_resp)
                await handler.perform_login(mock_client)
                result: dict[str, Any] = mock_client.login_raw.call_args[0][0]
                return result

        login_body = asyncio.run(_run())
        assert login_body["type"] == "org.matrix.login.jwt"
        assert "identifier" not in login_body
        assert login_body["token"] == "jwt-tok"
        assert login_body["initial_device_display_name"] == "openclaw-toggle-operator"
