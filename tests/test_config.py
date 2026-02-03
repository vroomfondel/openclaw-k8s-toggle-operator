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

    def test_missing_matrix_password_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_env(monkeypatch)
        monkeypatch.setenv("MATRIX_USER", "botuser")
        monkeypatch.setenv("ALLOWED_USERS", "@alice:example.com")

        with pytest.raises(ValueError, match="MATRIX_PASSWORD"):
            OperatorConfig.from_env()

    def test_missing_allowed_users_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
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

    def test_whitespace_only_allowed_users_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
    def test_echo_mode_true_variants(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        _clear_env(monkeypatch)
        _set_required(monkeypatch)
        monkeypatch.setenv("ECHO_MODE", value)

        cfg = OperatorConfig.from_env()

        assert cfg.echo_mode is True

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "nope", ""])
    def test_echo_mode_false_variants(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
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
