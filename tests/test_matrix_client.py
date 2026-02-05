"""Tests for :mod:`openclaw_k8s_toggle_operator.matrix_client`."""

from __future__ import annotations

import asyncio
import tempfile
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from openclaw_k8s_toggle_operator.matrix_client import MatrixClientHandler


class TestMatrixClientHandlerInit:
    """Tests for MatrixClientHandler initialization."""

    def test_creates_crypto_store_directory(self) -> None:
        """Crypto store directory is created on initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            crypto_path = f"{tmpdir}/new_store"
            handler = MatrixClientHandler(
                homeserver="https://matrix.example.com",
                user="testuser",
                crypto_store_path=crypto_path,
            )
            import os

            assert os.path.isdir(crypto_path)
            assert handler._homeserver == "https://matrix.example.com"
            assert handler._user == "testuser"
            assert handler._crypto_store_path == crypto_path

    def test_client_property(self) -> None:
        """client property returns the underlying AsyncClient."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = MatrixClientHandler(
                homeserver="https://matrix.example.com",
                user="testuser",
                crypto_store_path=tmpdir,
            )
            assert handler.client is handler._client


class TestMatrixClientHandlerLogin:
    """Tests for MatrixClientHandler.login()."""

    def test_login_password_success(self) -> None:
        """Password login succeeds and uploads keys if needed."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_login_response = MagicMock()
                mock_login_response.user_id = "@testuser:example.com"
                mock_login_response.device_id = "DEVICE123"

                # Create mock client to replace the real one
                mock_client = MagicMock()
                mock_client.login = AsyncMock(return_value=mock_login_response)
                mock_client.should_upload_keys = True
                mock_client.keys_upload = AsyncMock()

                # Replace the client
                handler._client = mock_client

                # Patch isinstance to accept our mock
                with patch("openclaw_k8s_toggle_operator.matrix_client.LoginResponse", type(mock_login_response)):
                    await handler.login(auth_method="password", password="secret")

                mock_client.login.assert_called_once_with("secret", device_name="openclaw-toggle-operator")
                mock_client.keys_upload.assert_called_once()

        asyncio.run(_run())

    def test_login_sso_delegates_to_handler(self) -> None:
        """SSO login delegates to SSOLoginHandler."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_login_response = MagicMock()
                mock_login_response.user_id = "@testuser:example.com"
                mock_login_response.device_id = "DEVICE123"

                mock_client = MagicMock()
                mock_client.should_upload_keys = False
                handler._client = mock_client

                with (
                    patch("openclaw_k8s_toggle_operator.matrix_client.LoginResponse", type(mock_login_response)),
                    patch(
                        "openclaw_k8s_toggle_operator.sso_login.SSOLoginHandler.perform_login",
                        new_callable=AsyncMock,
                        return_value=mock_login_response,
                    ) as mock_sso,
                ):
                    await handler.login(auth_method="sso", password="secret", sso_idp_id="my-idp")

                mock_sso.assert_called_once()

        asyncio.run(_run())

    def test_login_jwt_delegates_to_handler(self) -> None:
        """JWT login delegates to JWTLoginHandler."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_login_response = MagicMock()
                mock_login_response.user_id = "@testuser:example.com"
                mock_login_response.device_id = "DEVICE123"

                mock_client = MagicMock()
                mock_client.should_upload_keys = False
                handler._client = mock_client

                with (
                    patch("openclaw_k8s_toggle_operator.matrix_client.LoginResponse", type(mock_login_response)),
                    patch(
                        "openclaw_k8s_toggle_operator.jwt_login.JWTLoginHandler.perform_login",
                        new_callable=AsyncMock,
                        return_value=mock_login_response,
                    ) as mock_jwt,
                ):
                    await handler.login(
                        auth_method="jwt",
                        password="secret",
                        keycloak_url="https://keycloak.example.com",
                        keycloak_realm="master",
                        keycloak_client_id="myapp",
                        keycloak_client_secret="clientsecret",
                        jwt_login_type="com.famedly.login.token.oauth",
                    )

                mock_jwt.assert_called_once()

        asyncio.run(_run())


class TestMatrixClientHandlerDeviceTrust:
    """Tests for device trust methods."""

    def test_trust_devices_for_user_with_devices(self) -> None:
        """trust_devices_for_user verifies unverified devices."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                # Create mock device
                mock_device = MagicMock()
                mock_device_store: dict[str, dict[str, Any]] = {"@alice:example.com": {"DEVICE1": mock_device}}

                # Create mock olm object
                mock_olm = MagicMock()
                mock_olm.users_for_key_query = set()

                # Create mock client
                mock_client = MagicMock()
                mock_client.olm = mock_olm
                mock_client.keys_query = AsyncMock()
                mock_client.device_store = mock_device_store
                mock_client.is_device_verified = MagicMock(return_value=False)
                mock_client.verify_device = MagicMock()

                handler._client = mock_client

                await handler.trust_devices_for_user("@alice:example.com")

                assert "@alice:example.com" in mock_olm.users_for_key_query
                mock_client.keys_query.assert_called_once()
                mock_client.verify_device.assert_called_once_with(mock_device)

        asyncio.run(_run())

    def test_trust_devices_for_user_already_verified(self) -> None:
        """trust_devices_for_user skips already verified devices."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_device = MagicMock()
                mock_device_store: dict[str, dict[str, Any]] = {"@alice:example.com": {"DEVICE1": mock_device}}

                mock_olm = MagicMock()
                mock_olm.users_for_key_query = set()

                mock_client = MagicMock()
                mock_client.olm = mock_olm
                mock_client.keys_query = AsyncMock()
                mock_client.device_store = mock_device_store
                mock_client.is_device_verified = MagicMock(return_value=True)
                mock_client.verify_device = MagicMock()

                handler._client = mock_client

                await handler.trust_devices_for_user("@alice:example.com")

                mock_client.verify_device.assert_not_called()

        asyncio.run(_run())

    def test_trust_all_allowed_devices(self) -> None:
        """trust_all_allowed_devices calls trust_devices_for_user for each user."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                handler.trust_devices_for_user = AsyncMock()  # type: ignore[method-assign]

                await handler.trust_all_allowed_devices(["@alice:example.com", "@bob:example.com"])

                assert handler.trust_devices_for_user.call_count == 2
                handler.trust_devices_for_user.assert_any_call("@alice:example.com")
                handler.trust_devices_for_user.assert_any_call("@bob:example.com")

        asyncio.run(_run())

    def test_trust_devices_in_room(self) -> None:
        """trust_devices_in_room trusts all users except self."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                # Mock room
                mock_room = MagicMock()
                mock_room.users = ["@testuser:example.com", "@alice:example.com", "@bob:example.com"]

                mock_client = MagicMock()
                mock_client.rooms = {"!room:example.com": mock_room}
                mock_client.user_id = "@testuser:example.com"

                handler._client = mock_client
                handler.trust_devices_for_user = AsyncMock()  # type: ignore[method-assign]

                await handler.trust_devices_in_room("!room:example.com")

                # Should trust alice and bob, but not self
                assert handler.trust_devices_for_user.call_count == 2
                handler.trust_devices_for_user.assert_any_call("@alice:example.com")
                handler.trust_devices_for_user.assert_any_call("@bob:example.com")

        asyncio.run(_run())


class TestMatrixClientHandlerMessaging:
    """Tests for messaging methods."""

    def test_send_message(self) -> None:
        """send_message calls room_send with correct parameters."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_client = MagicMock()
                mock_client.room_send = AsyncMock()
                handler._client = mock_client

                await handler.send_message("!room:example.com", "Hello, World!")

                mock_client.room_send.assert_called_once_with(
                    room_id="!room:example.com",
                    message_type="m.room.message",
                    content={"msgtype": "m.text", "body": "Hello, World!"},
                    ignore_unverified_devices=True,
                )

        asyncio.run(_run())

    def test_send_message_handles_error(self) -> None:
        """send_message logs error but doesn't raise."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_client = MagicMock()
                mock_client.room_send = AsyncMock(side_effect=Exception("Send failed"))
                handler._client = mock_client

                # Should not raise
                await handler.send_message("!room:example.com", "Hello")

        asyncio.run(_run())

    def test_join_room(self) -> None:
        """join_room delegates to client.join."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_client = MagicMock()
                mock_client.join = AsyncMock()
                handler._client = mock_client

                await handler.join_room("!room:example.com")

                mock_client.join.assert_called_once_with("!room:example.com")

        asyncio.run(_run())


class TestMatrixClientHandlerCallbacks:
    """Tests for callback registration."""

    def test_add_event_callback(self) -> None:
        """add_event_callback delegates to client."""
        with tempfile.TemporaryDirectory() as tmpdir:
            handler = MatrixClientHandler(
                homeserver="https://matrix.example.com",
                user="testuser",
                crypto_store_path=tmpdir,
            )

            mock_client = MagicMock()
            mock_client.add_event_callback = MagicMock()
            handler._client = mock_client

            callback = AsyncMock()
            event_type = MagicMock()

            handler.add_event_callback(callback, event_type)

            mock_client.add_event_callback.assert_called_once_with(callback, event_type)


class TestMatrixClientHandlerSync:
    """Tests for sync methods."""

    def test_initial_sync_success(self) -> None:
        """initial_sync returns next_batch on success."""

        async def _run() -> str | None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_sync_response = MagicMock()
                mock_sync_response.next_batch = "batch_token_123"

                mock_client = MagicMock()
                mock_client.sync = AsyncMock(return_value=mock_sync_response)
                handler._client = mock_client

                with patch("openclaw_k8s_toggle_operator.matrix_client.SyncResponse", type(mock_sync_response)):
                    result = await handler.initial_sync(timeout=5000)

                assert mock_client.next_batch == "batch_token_123"
                mock_client.sync.assert_called_once_with(timeout=5000)
                return result

        result = asyncio.run(_run())
        assert result == "batch_token_123"

    def test_sync_forever(self) -> None:
        """sync_forever delegates to client.sync_forever."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_client = MagicMock()
                mock_client.sync_forever = AsyncMock()
                handler._client = mock_client

                await handler.sync_forever(timeout=15000)

                mock_client.sync_forever.assert_called_once_with(timeout=15000)

        asyncio.run(_run())


class TestMatrixClientHandlerClose:
    """Tests for cleanup."""

    def test_close(self) -> None:
        """close delegates to client.close."""

        async def _run() -> None:
            with tempfile.TemporaryDirectory() as tmpdir:
                handler = MatrixClientHandler(
                    homeserver="https://matrix.example.com",
                    user="testuser",
                    crypto_store_path=tmpdir,
                )

                mock_client = MagicMock()
                mock_client.close = AsyncMock()
                handler._client = mock_client

                await handler.close()

                mock_client.close.assert_called_once()

        asyncio.run(_run())
