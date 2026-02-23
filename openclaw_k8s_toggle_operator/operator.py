"""OperatorBot — Matrix-controlled Kubernetes deployment scaler.

Connects to a Matrix homeserver with E2E encryption support via matrix-nio
and listens for chat commands to scale a K8s deployment between 0 and 1
replicas.
"""

from __future__ import annotations

from typing import Any

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from loguru import logger as glogger
from nio import InviteMemberEvent, MegolmEvent, RoomMessageText

from openclaw_k8s_toggle_operator.config import OperatorConfig
from minimatrix.matrix_client import MatrixClientHandler

logger = glogger.bind(classname="OperatorBot")

# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

HELP_TEXT = "\n".join(
    [
        "Clawdbot Operator commands:",
        "  start / on  — Scale deployment to 1 replica",
        "  stop / off  — Scale deployment to 0 replicas",
        "  status      — Show deployment status",
        "  help        — Show this message",
    ]
)


class OperatorBot:
    """Matrix bot that controls a Kubernetes deployment via chat commands."""

    def __init__(self, config: OperatorConfig) -> None:
        self.config = config
        self.startup_sync_done = False

        # Kubernetes client
        k8s_config.load_incluster_config()
        self._apps_v1 = k8s_client.AppsV1Api()

        # Matrix client handler
        self._matrix = MatrixClientHandler(
            homeserver=config.matrix_homeserver,
            user=config.matrix_user,
            crypto_store_path=config.crypto_store_path,
        )

    # -- Kubernetes helpers --------------------------------------------------

    def scale_deployment(self, replicas: int) -> str:
        """Scale the target deployment to *replicas* (0 or 1)."""
        self._apps_v1.patch_namespaced_deployment_scale(
            name=self.config.deployment_name,
            namespace=self.config.deployment_namespace,
            body={"spec": {"replicas": replicas}},
        )
        state = "on" if replicas else "off"
        return f"Deployment is now {state}  (replicas: {replicas})"

    def get_deployment_status(self) -> str:
        """Return a human-readable status string for the target deployment."""
        dep = self._apps_v1.read_namespaced_deployment(
            name=self.config.deployment_name,
            namespace=self.config.deployment_namespace,
        )
        spec = dep.spec.replicas or 0
        ready = dep.status.ready_replicas or 0
        available = dep.status.available_replicas or 0
        state = (
            "running" if spec > 0 and ready > 0 else ("starting" if spec > 0 else "off")
        )
        return (
            f"Deployment is {state}\n"
            f"  Desired replicas : {spec}\n"
            f"  Ready            : {ready}\n"
            f"  Available        : {available}"
        )

    # -- Command handling ----------------------------------------------------

    def handle_command(self, text: str) -> str:
        """Parse and execute a chat command, returning the response text."""
        cmd = text.strip().lower()
        try:
            if cmd in ("start", "on"):
                return self.scale_deployment(1)
            if cmd in ("stop", "off"):
                return self.scale_deployment(0)
            if cmd == "status":
                return self.get_deployment_status()
            if cmd == "help":
                return HELP_TEXT
            return f"Unknown command: {text.strip()}\n\n{HELP_TEXT}"
        except Exception as exc:
            logger.error("Command error: {}", exc)
            return f"Error: {exc}"

    # -- Matrix event callbacks ----------------------------------------------

    async def on_invite(self, room: Any, event: Any) -> None:
        """Auto-accept room invitations from allowed users."""
        sender = event.sender
        if sender not in self.config.allowed_users:
            logger.warning("Ignoring invite from {} to {}", sender, room.room_id)
            return
        logger.info("Accepting invite from {} to {}", sender, room.room_id)
        await self._matrix.join_room(room.room_id)
        await self._matrix.trust_devices_for_user(sender)

    async def on_message(self, room: Any, event: Any) -> None:
        """Process text messages from allowed users as commands."""
        if event.sender == self._matrix.user_id:
            return
        if not self.startup_sync_done:
            return
        if event.sender not in self.config.allowed_users:
            return

        logger.info("Command from {} in {}: {}", event.sender, room.room_id, event.body)

        await self._matrix.trust_devices_in_room(room.room_id)

        if self.config.echo_mode:
            await self._matrix.send_message(room.room_id, f"\U0001f99e {event.body}")

        response = self.handle_command(event.body)
        logger.info("Response: {}", response)

        await self._matrix.send_message(room.room_id, response)

    async def on_megolm_event(self, room: Any, event: Any) -> None:
        """Handle encrypted messages we could not decrypt (missing session)."""
        if not self.startup_sync_done:
            return
        if event.sender == self._matrix.user_id:
            return

        logger.warning(
            "Could not decrypt message from {} in {} (session: {}). Requesting keys ...",
            event.sender,
            room.room_id,
            event.session_id,
        )
        await self._matrix.trust_devices_in_room(room.room_id)

        await self._matrix.send_message(
            room.room_id,
            "I could not decrypt your message. "
            "This may happen after a restart. "
            "Please send your command again.",
        )

    # -- Main loop -----------------------------------------------------------

    async def run(self) -> None:
        """Log in, register callbacks, and run the sync loop."""
        await self._matrix.login(
            auth_method=self.config.auth_method,
            password=self.config.matrix_password,
            sso_idp_id=self.config.sso_idp_id,
            keycloak_url=self.config.keycloak_url,
            keycloak_realm=self.config.keycloak_realm,
            keycloak_client_id=self.config.keycloak_client_id,
            keycloak_client_secret=self.config.keycloak_client_secret,
            jwt_login_type=self.config.jwt_login_type,
        )

        self._matrix.add_event_callback(self.on_message, RoomMessageText)
        self._matrix.add_event_callback(self.on_megolm_event, MegolmEvent)
        self._matrix.add_event_callback(self.on_invite, InviteMemberEvent)

        await self._matrix.initial_sync(auto_join=True)
        await self._matrix.trust_all_allowed_devices(self.config.allowed_users)

        self.startup_sync_done = True
        await self._matrix.sync_forever()

    async def close(self) -> None:
        """Close the Matrix client connection."""
        await self._matrix.close()
