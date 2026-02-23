"""Tests for :mod:`openclaw_k8s_toggle_operator.config`."""

import dataclasses

import pytest

from openclaw_k8s_toggle_operator.config import OperatorConfig

# All env vars that from_env() reads — clear them for isolation.
_ALL_ENV_VARS = [
    "MATRIX_HOMESERVER",
    "MATRIX_USER",
    "MATRIX_PASSWORD",
    "ALLOWED_USERS",
    "DEPLOYMENT_NAME",
    "DEPLOYMENT_NAMESPACE",
    "CRYPTO_STORE_PATH",
    "ECHO_MODE",
    "AUTH_METHOD",
    "SSO_IDP_ID",
    "KEYCLOAK_URL",
    "KEYCLOAK_REALM",
    "KEYCLOAK_CLIENT_ID",
    "KEYCLOAK_CLIENT_SECRET",
    "JWT_LOGIN_TYPE",
]


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every config env var so tests start from a clean slate."""
    for var in _ALL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _set_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the minimum required env vars."""
    monkeypatch.setenv("MATRIX_USER", "botuser")
    monkeypatch.setenv("MATRIX_PASSWORD", "secret")
    monkeypatch.setenv("ALLOWED_USERS", "@alice:example.com")


class TestOperatorConfigFromEnv:
    """Tests for :meth:`OperatorConfig.from_env`."""

    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)

        cfg = OperatorConfig.from_env()

        assert cfg.matrix_homeserver == "http://synapse.matrix.svc.cluster.local:8008"
        assert cfg.matrix_user == "botuser"
        assert cfg.matrix_password == "secret"
        assert cfg.allowed_users == ["@alice:example.com"]
        assert cfg.deployment_name == "clawdbot"
        assert cfg.deployment_namespace == "clawdbot"
        assert cfg.crypto_store_path == "/data/crypto_store"
        assert cfg.echo_mode is True
        assert cfg.auth_method == "password"
        assert cfg.sso_idp_id == "keycloak"
        assert cfg.keycloak_url == ""
        assert cfg.keycloak_realm == ""
        assert cfg.keycloak_client_id == ""
        assert cfg.keycloak_client_secret == ""
        assert cfg.jwt_login_type == ""

    def test_custom_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_HOMESERVER", "  https://matrix.custom.io  ")
        monkeypatch.setenv("MATRIX_USER", "  mybot  ")
        monkeypatch.setenv("MATRIX_PASSWORD", "  p@ss  ")
        monkeypatch.setenv("ALLOWED_USERS", " @bob:custom.io , @carol:custom.io ")
        monkeypatch.setenv("DEPLOYMENT_NAME", "  my-deploy  ")
        monkeypatch.setenv("DEPLOYMENT_NAMESPACE", "  my-ns  ")
        monkeypatch.setenv("CRYPTO_STORE_PATH", "  /tmp/store  ")
        monkeypatch.setenv("ECHO_MODE", "false")

        cfg = OperatorConfig.from_env()

        assert cfg.matrix_homeserver == "https://matrix.custom.io"
        assert cfg.matrix_user == "mybot"
        assert cfg.matrix_password == "p@ss"
        assert cfg.allowed_users == ["@bob:custom.io", "@carol:custom.io"]
        assert cfg.deployment_name == "my-deploy"
        assert cfg.deployment_namespace == "my-ns"
        assert cfg.crypto_store_path == "/tmp/store"
        assert cfg.echo_mode is False

    def test_missing_matrix_user_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_PASSWORD", "secret")
        monkeypatch.setenv("ALLOWED_USERS", "@alice:example.com")

        with pytest.raises(ValueError, match="MATRIX_USER"):
            OperatorConfig.from_env()

    def test_missing_matrix_password_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_USER", "botuser")
        monkeypatch.setenv("ALLOWED_USERS", "@alice:example.com")

        with pytest.raises(ValueError, match="MATRIX_PASSWORD"):
            OperatorConfig.from_env()

    def test_missing_allowed_users_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_USER", "botuser")
        monkeypatch.setenv("MATRIX_PASSWORD", "secret")

        with pytest.raises(ValueError, match="ALLOWED_USERS"):
            OperatorConfig.from_env()

    def test_empty_allowed_users_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_USER", "botuser")
        monkeypatch.setenv("MATRIX_PASSWORD", "secret")
        monkeypatch.setenv("ALLOWED_USERS", "")

        with pytest.raises(ValueError, match="ALLOWED_USERS"):
            OperatorConfig.from_env()

    def test_whitespace_only_allowed_users_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_USER", "botuser")
        monkeypatch.setenv("MATRIX_PASSWORD", "secret")
        monkeypatch.setenv("ALLOWED_USERS", "  ,  ,  ")

        with pytest.raises(ValueError, match="ALLOWED_USERS"):
            OperatorConfig.from_env()

    def test_single_allowed_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("ALLOWED_USERS", "@only:example.com")

        cfg = OperatorConfig.from_env()

        assert cfg.allowed_users == ["@only:example.com"]

    def test_multiple_allowed_users(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("ALLOWED_USERS", "@a:x.com,@b:x.com,@c:x.com")

        cfg = OperatorConfig.from_env()

        assert cfg.allowed_users == ["@a:x.com", "@b:x.com", "@c:x.com"]

    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "yes", "YES", "1"])
    def test_echo_mode_true_variants(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("ECHO_MODE", value)

        cfg = OperatorConfig.from_env()

        assert cfg.echo_mode is True

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "nope", ""])
    def test_echo_mode_false_variants(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("ECHO_MODE", value)

        cfg = OperatorConfig.from_env()

        assert cfg.echo_mode is False

    def test_frozen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)

        cfg = OperatorConfig.from_env()

        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.matrix_user = "nope"  # type: ignore[misc]

    def test_auth_method_sso(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "sso")

        cfg = OperatorConfig.from_env()

        assert cfg.auth_method == "sso"
        assert cfg.sso_idp_id == "keycloak"

    def test_auth_method_invalid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "oauth2")

        with pytest.raises(ValueError, match="AUTH_METHOD"):
            OperatorConfig.from_env()

    def test_custom_sso_idp_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "sso")
        monkeypatch.setenv("SSO_IDP_ID", "  my-idp  ")

        cfg = OperatorConfig.from_env()

        assert cfg.sso_idp_id == "my-idp"

    def test_auth_method_case_insensitive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "  SSO  ")

        cfg = OperatorConfig.from_env()

        assert cfg.auth_method == "sso"

    def test_auth_method_jwt_with_required_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")
        monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "my-secret")

        cfg = OperatorConfig.from_env()

        assert cfg.auth_method == "jwt"
        assert cfg.keycloak_url == "https://keycloak.example.com"
        assert cfg.keycloak_realm == "master"
        assert cfg.keycloak_client_id == "clawdbot-operator"
        assert cfg.keycloak_client_secret == "my-secret"
        assert cfg.jwt_login_type == "com.famedly.login.token.oauth"

    def test_auth_method_jwt_public_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")

        cfg = OperatorConfig.from_env()

        assert cfg.keycloak_client_secret == ""

    def test_auth_method_jwt_missing_keycloak_url_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")

        with pytest.raises(ValueError, match="KEYCLOAK_URL"):
            OperatorConfig.from_env()

    def test_auth_method_jwt_missing_keycloak_realm_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")

        with pytest.raises(ValueError, match="KEYCLOAK_REALM"):
            OperatorConfig.from_env()

    def test_auth_method_jwt_missing_keycloak_client_id_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")

        with pytest.raises(ValueError, match="KEYCLOAK_CLIENT_ID"):
            OperatorConfig.from_env()

    def test_auth_method_password_ignores_keycloak_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "password")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")

        cfg = OperatorConfig.from_env()

        assert cfg.auth_method == "password"
        assert cfg.keycloak_url == ""
        assert cfg.keycloak_realm == ""
        assert cfg.keycloak_client_id == ""
        assert cfg.keycloak_client_secret == ""
        assert cfg.jwt_login_type == ""

    def test_jwt_login_type_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """JWT_LOGIN_TYPE defaults to com.famedly.login.token.oauth when AUTH_METHOD=jwt."""
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")

        cfg = OperatorConfig.from_env()

        assert cfg.jwt_login_type == "com.famedly.login.token.oauth"

    def test_jwt_login_type_native_jwt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """JWT_LOGIN_TYPE accepts org.matrix.login.jwt."""
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")
        monkeypatch.setenv("JWT_LOGIN_TYPE", "org.matrix.login.jwt")

        cfg = OperatorConfig.from_env()

        assert cfg.jwt_login_type == "org.matrix.login.jwt"

    def test_jwt_login_type_invalid_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """JWT_LOGIN_TYPE rejects invalid values."""
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("AUTH_METHOD", "jwt")
        monkeypatch.setenv("KEYCLOAK_URL", "https://keycloak.example.com")
        monkeypatch.setenv("KEYCLOAK_REALM", "master")
        monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "clawdbot-operator")
        monkeypatch.setenv("JWT_LOGIN_TYPE", "invalid_type")

        with pytest.raises(ValueError, match="JWT_LOGIN_TYPE"):
            OperatorConfig.from_env()
