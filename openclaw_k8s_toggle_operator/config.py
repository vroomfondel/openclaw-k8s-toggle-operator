"""Operator configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


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
        )
