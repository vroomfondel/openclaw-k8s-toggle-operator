"""Operator configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _parse_bool(value: str) -> bool:
    """Parse a string into a boolean (truthy: ``"true"``, ``"1"``, ``"yes"``)."""
    return value.strip().lower() in ("true", "1", "yes")


@dataclass(frozen=True)
class OperatorConfig:
    """Immutable configuration for the Matrix-controlled K8s toggle operator.

    All values are sourced from environment variables via :meth:`from_env`.
    """

    matrix_homeserver: str
    matrix_user: str
    matrix_password: str
    allowed_users: list[str]
    deployment_name: str
    deployment_namespace: str
    crypto_store_path: str
    echo_mode: bool
    auth_method: str
    sso_idp_id: str
    keycloak_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: str
    jwt_login_type: str

    @classmethod
    def from_env(cls) -> OperatorConfig:
        """Build an :class:`OperatorConfig` from environment variables.

        Environment variables
        ---------------------
        MATRIX_HOMESERVER : str, optional
            Matrix homeserver URL
            (default ``"http://synapse.matrix.svc.cluster.local:8008"``).
        MATRIX_USER : str, **required**
            Bot username (localpart, e.g. ``"clawdbot-operator"``).
        MATRIX_PASSWORD : str, **required**
            Bot password.
        ALLOWED_USERS : str, **required**
            Comma-separated list of full Matrix user IDs allowed to send
            commands (e.g. ``@user:matrix.example.com``).
        DEPLOYMENT_NAME : str, optional
            K8s deployment to scale (default ``"clawdbot"``).
        DEPLOYMENT_NAMESPACE : str, optional
            K8s namespace (default ``"clawdbot"``).
        CRYPTO_STORE_PATH : str, optional
            Path for persistent E2E key storage (default ``"/data/crypto_store"``).
        ECHO_MODE : str, optional
            When enabled the bot echoes the user's message (prefixed with a
            lobster emoji) before processing the command.  Truthy values are
            ``"true"``, ``"1"``, and ``"yes"`` (case-insensitive).
            Default ``"true"``.

        Raises
        ------
        ValueError
            If ``MATRIX_USER``, ``MATRIX_PASSWORD``, or ``ALLOWED_USERS``
            is missing or empty.
        """
        matrix_user = os.environ.get("MATRIX_USER", "").strip()
        if not matrix_user:
            raise ValueError("MATRIX_USER environment variable is required")

        matrix_password = os.environ.get("MATRIX_PASSWORD", "").strip()
        if not matrix_password:
            raise ValueError("MATRIX_PASSWORD environment variable is required")

        raw_allowed = os.environ.get("ALLOWED_USERS", "")
        allowed_users = [u.strip() for u in raw_allowed.split(",") if u.strip()]
        if not allowed_users:
            raise ValueError("ALLOWED_USERS environment variable is required and must contain at least one user ID")

        auth_method = os.environ.get("AUTH_METHOD", "password").strip().lower()
        if auth_method not in ("password", "sso", "jwt"):
            raise ValueError(f"AUTH_METHOD must be 'password', 'sso', or 'jwt', got '{auth_method}'")

        keycloak_url = ""
        keycloak_realm = ""
        keycloak_client_id = ""
        keycloak_client_secret = ""
        jwt_login_type = ""
        if auth_method == "jwt":
            keycloak_url = os.environ.get("KEYCLOAK_URL", "").strip()
            if not keycloak_url:
                raise ValueError("KEYCLOAK_URL environment variable is required when AUTH_METHOD=jwt")
            keycloak_realm = os.environ.get("KEYCLOAK_REALM", "").strip()
            if not keycloak_realm:
                raise ValueError("KEYCLOAK_REALM environment variable is required when AUTH_METHOD=jwt")
            keycloak_client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "").strip()
            if not keycloak_client_id:
                raise ValueError("KEYCLOAK_CLIENT_ID environment variable is required when AUTH_METHOD=jwt")
            keycloak_client_secret = os.environ.get("KEYCLOAK_CLIENT_SECRET", "").strip()
            jwt_login_type = os.environ.get("JWT_LOGIN_TYPE", "com.famedly.login.token.oauth").strip()
            valid_login_types = ("com.famedly.login.token.oauth", "com.famedly.login.token", "org.matrix.login.jwt")
            if jwt_login_type not in valid_login_types:
                raise ValueError(f"JWT_LOGIN_TYPE must be one of {valid_login_types}, got '{jwt_login_type}'")

        return cls(
            matrix_homeserver=os.environ.get(
                "MATRIX_HOMESERVER", "http://synapse.matrix.svc.cluster.local:8008"
            ).strip(),
            matrix_user=matrix_user,
            matrix_password=matrix_password,
            allowed_users=allowed_users,
            deployment_name=os.environ.get("DEPLOYMENT_NAME", "clawdbot").strip(),
            deployment_namespace=os.environ.get("DEPLOYMENT_NAMESPACE", "clawdbot").strip(),
            crypto_store_path=os.environ.get("CRYPTO_STORE_PATH", "/data/crypto_store").strip(),
            echo_mode=_parse_bool(os.environ.get("ECHO_MODE", "true")),
            auth_method=auth_method,
            sso_idp_id=os.environ.get("SSO_IDP_ID", "keycloak").strip(),
            keycloak_url=keycloak_url,
            keycloak_realm=keycloak_realm,
            keycloak_client_id=keycloak_client_id,
            keycloak_client_secret=keycloak_client_secret,
            jwt_login_type=jwt_login_type,
        )
