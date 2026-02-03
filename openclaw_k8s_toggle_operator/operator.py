"""OperatorBot — Matrix-controlled Kubernetes deployment scaler.

Connects to a Matrix homeserver with E2E encryption support via matrix-nio
and listens for chat commands to scale a K8s deployment between 0 and 1
replicas.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from loguru import logger as glogger
from nio import (
    AsyncClient,
    AsyncClientConfig,
    InviteMemberEvent,
    LocalProtocolError,
    LoginResponse,
    MegolmEvent,
    RoomMessageText,
    SyncResponse,
)

from openclaw_k8s_toggle_operator.config import OperatorConfig

logger = glogger.bind(classname="OperatorBot")

# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

HELP_TEXT = "\n".join(
    [
        "Clawdbot Operator commands:",
        "  start / on  \u2014 Scale deployment to 1 replica",
        "  stop / off  \u2014 Scale deployment to 0 replicas",
        "  status      \u2014 Show deployment status",
        "  help        \u2014 Show this message",
    ]
)


class OperatorBot:
    """Matrix bot that controls a Kubernetes deployment via chat commands."""

    def __init__(self, config: OperatorConfig) -> None:
        self.config = config

        # Kubernetes client
        k8s_config.load_incluster_config()
        self._apps_v1 = k8s_client.AppsV1Api()

        # Matrix client with E2E encryption
        os.makedirs(config.crypto_store_path, exist_ok=True)
        nio_config = AsyncClientConfig(
            encryption_enabled=True,
            store_sync_tokens=True,
        )
        self.client = AsyncClient(
            config.matrix_homeserver,
            config.matrix_user,
            store_path=config.crypto_store_path,
            config=nio_config,
        )
        self.startup_sync_done = False

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
        state = "running" if spec > 0 and ready > 0 else ("starting" if spec > 0 else "off")
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

    # -- Matrix login & device trust -----------------------------------------

    async def login(self) -> None:
        """Log in to the Matrix homeserver and upload device keys."""
        logger.info("Logging in as {} on {}", self.config.matrix_user, self.config.matrix_homeserver)
        resp = await self.client.login(self.config.matrix_password, device_name="openclaw-toggle-operator")
        if isinstance(resp, LoginResponse):
            logger.info("Login OK  user_id={}  device_id={}", resp.user_id, resp.device_id)
        else:
            logger.error("Login failed: {}", resp)
            sys.exit(1)

        if self.client.should_upload_keys:
            logger.info("Uploading device keys ...")
            await self.client.keys_upload()

    async def trust_devices_for_user(self, user_id: str) -> None:
        """Auto-trust all devices of a given user (TOFU)."""
        try:
            await self.client.keys_query()
        except LocalProtocolError:
            logger.debug("No key query required for {} — using existing device store", user_id)
        device_store = self.client.device_store
        if user_id not in device_store:
            return
        for device_id, olm_device in device_store[user_id].items():
            if not self.client.is_device_verified(olm_device):
                logger.info("Trusting device {} of {}", device_id, user_id)
                self.client.verify_device(olm_device)

    async def trust_all_allowed_devices(self) -> None:
        """Trust devices of all allowed users."""
        for user_id in self.config.allowed_users:
            await self.trust_devices_for_user(user_id)

    async def trust_devices_in_room(self, room_id: str) -> None:
        """Trust all devices of all members in a room (TOFU)."""
        room = self.client.rooms.get(room_id)
        if not room:
            return
        for user_id in room.users:
            if user_id == self.client.user_id:
                continue
            await self.trust_devices_for_user(user_id)

    # -- Matrix event callbacks ----------------------------------------------

    async def on_invite(self, room: Any, event: Any) -> None:
        """Auto-accept room invitations from allowed users."""
        sender = event.sender
        if sender not in self.config.allowed_users:
            logger.warning("Ignoring invite from {} to {}", sender, room.room_id)
            return
        logger.info("Accepting invite from {} to {}", sender, room.room_id)
        await self.client.join(room.room_id)
        await self.trust_devices_for_user(sender)

    async def on_message(self, room: Any, event: Any) -> None:
        """Process text messages from allowed users as commands."""
        if event.sender == self.client.user_id:
            return
        if not self.startup_sync_done:
            return
        if event.sender not in self.config.allowed_users:
            return

        logger.info("Command from {} in {}: {}", event.sender, room.room_id, event.body)

        await self.trust_devices_in_room(room.room_id)

        if self.config.echo_mode:
            try:
                await self.client.room_send(
                    room_id=room.room_id,
                    message_type="m.room.message",
                    content={"msgtype": "m.text", "body": f"\U0001f99e {event.body}"},
                )
            except Exception as exc:
                logger.error("Failed to send echo ACK: {}", exc)

        response = self.handle_command(event.body)
        logger.info("Response: {}", response)

        try:
            await self.client.room_send(
                room_id=room.room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": response},
            )
        except Exception as exc:
            logger.error("Failed to send response: {}", exc)

    async def on_megolm_event(self, room: Any, event: Any) -> None:
        """Handle encrypted messages we could not decrypt (missing session)."""
        if not self.startup_sync_done:
            return
        if event.sender == self.client.user_id:
            return

        logger.warning(
            "Could not decrypt message from {} in {} (session: {}). Requesting keys ...",
            event.sender,
            room.room_id,
            event.session_id,
        )
        await self.trust_devices_in_room(room.room_id)

        try:
            await self.client.room_send(
                room_id=room.room_id,
                message_type="m.room.message",
                content={
                    "msgtype": "m.text",
                    "body": (
                        "I could not decrypt your message. "
                        "This may happen after a restart. "
                        "Please send your command again."
                    ),
                },
            )
        except Exception as exc:
            logger.warning("Failed to send decryption warning: {}", exc)

    # -- Main loop -----------------------------------------------------------

    async def run(self) -> None:
        """Log in, register callbacks, and run the sync loop."""
        await self.login()

        self.client.add_event_callback(self.on_message, RoomMessageText)
        self.client.add_event_callback(self.on_megolm_event, MegolmEvent)
        self.client.add_event_callback(self.on_invite, InviteMemberEvent)

        logger.info("Running initial sync ...")
        sync_resp = await self.client.sync(timeout=10000)
        if isinstance(sync_resp, SyncResponse):
            self.client.next_batch = sync_resp.next_batch

        await self.trust_all_allowed_devices()

        self.startup_sync_done = True
        logger.info("Initial sync complete.  Listening for commands ...")

        await self.client.sync_forever(timeout=30000)

    async def close(self) -> None:
        """Close the Matrix client connection."""
        await self.client.close()
