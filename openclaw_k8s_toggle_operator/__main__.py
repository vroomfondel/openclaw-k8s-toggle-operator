import asyncio
import signal
import sys
from dataclasses import fields

from loguru import logger as glogger
from tabulate import tabulate

from openclaw_k8s_toggle_operator import __version__, configure_logging
from openclaw_k8s_toggle_operator.config import OperatorConfig
from minimatrix.matrix_client import MatrixClientHandler
from openclaw_k8s_toggle_operator.operator import OperatorBot

configure_logging()
glogger.enable("openclaw_k8s_toggle_operator")
glogger.enable("minimatrix")


async def _async_main() -> None:
    startup_rows = [
        ["version", __version__],
        ["github", "https://github.com/vroomfondel/openclaw-k8s-toggle-operator"],
        ["pypi", "https://pypi.org/project/openclaw-k8s-toggle-operator"],
        ["Docker Hub", "https://hub.docker.com/r/xomoxcc/openclaw-k8s-toggle-operator"],
    ]
    table_str = tabulate(startup_rows, tablefmt="mixed_grid")
    lines = table_str.split("\n")
    table_width = len(lines[0])
    title = "openclaw-k8s-toggle-operator starting up"
    title_border = "┍" + "━" * (table_width - 2) + "┑"
    title_row = "│ " + title.center(table_width - 4) + " │"
    separator = lines[0].replace("┍", "┝").replace("┑", "┥").replace("┯", "┿")

    glogger.opt(raw=True).info(
        "\n{}\n",
        title_border
        + "\n"
        + title_row
        + "\n"
        + separator
        + "\n"
        + "\n".join(lines[1:]),
    )

    try:
        cfg = OperatorConfig.from_env()
        config_table = [
            [f.name, "***" if f.name == "matrix_password" else getattr(cfg, f.name)]
            for f in fields(cfg)
        ]
        cfg_table_str = tabulate(config_table, tablefmt="mixed_grid")
        cfg_lines = cfg_table_str.split("\n")
        cfg_width = len(cfg_lines[0])
        cfg_title = "configuration"
        cfg_title_border = "┍" + "━" * (cfg_width - 2) + "┑"
        cfg_title_row = "│ " + cfg_title.center(cfg_width - 4) + " │"
        cfg_separator = (
            cfg_lines[0].replace("┍", "┝").replace("┑", "┥").replace("┯", "┿")
        )

        glogger.opt(raw=True).info(
            "\n{}\n",
            cfg_title_border
            + "\n"
            + cfg_title_row
            + "\n"
            + cfg_separator
            + "\n"
            + "\n".join(cfg_lines[1:]),
        )
    except ValueError as exc:
        glogger.error("Configuration error: {}", exc)
        sys.exit(1)

    retry = 0
    max_retries = 20

    while True:
        bot = OperatorBot(cfg)
        try:
            await bot.run()
        except asyncio.CancelledError:
            break
        except KeyboardInterrupt:
            break
        except Exception as exc:
            retry += 1
            if retry > max_retries:
                glogger.error("Max retries ({}) exceeded. Exiting.", max_retries)
                sys.exit(1)
            wait = min(2**retry, 60)
            glogger.error(
                "Error (attempt {}/{}, retry in {}s): {}",
                retry,
                max_retries,
                wait,
                exc,
            )
            await asyncio.sleep(wait)
        else:
            retry = 0
        finally:
            await bot.close()

    glogger.info("Bye.")


def _handle_signal() -> None:
    glogger.info("Received shutdown signal")
    for task in asyncio.all_tasks():
        task.cancel()


async def _async_connectortest() -> int:
    """Test Matrix homeserver connectivity and credentials.

    Returns 0 on success, 1 on failure.
    """
    import tempfile

    try:
        cfg = OperatorConfig.from_env()
    except ValueError as exc:
        glogger.error("Configuration error: {}", exc)
        return 1

    # Use a temporary directory for crypto store in connector test
    with tempfile.TemporaryDirectory() as tmp_crypto_store:
        handler = MatrixClientHandler(
            homeserver=cfg.matrix_homeserver,
            user=cfg.matrix_user,
            crypto_store_path=tmp_crypto_store,
        )
        try:
            glogger.info(
                "Attempting login to {} as {} (method={})",
                cfg.matrix_homeserver,
                cfg.matrix_user,
                cfg.auth_method,
            )

            await handler.login(
                auth_method=cfg.auth_method,
                password=cfg.matrix_password,
                sso_idp_id=cfg.sso_idp_id,
                keycloak_url=cfg.keycloak_url,
                keycloak_realm=cfg.keycloak_realm,
                keycloak_client_id=cfg.keycloak_client_id,
                keycloak_client_secret=cfg.keycloak_client_secret,
                jwt_login_type=cfg.jwt_login_type,
            )
            glogger.info("Login successful (user_id={})", handler.user_id)
            return 0
        except SystemExit:
            # login() calls sys.exit(1) on failure
            return 1
        except Exception as exc:
            glogger.error("Connection error: {}", exc)
            return 1
        finally:
            await handler.close()


def connectortest() -> None:
    """CLI entry point: test Matrix homeserver connectivity and exit."""
    sys.exit(asyncio.run(_async_connectortest()))


def main() -> None:
    loop = asyncio.new_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal)
    try:
        loop.run_until_complete(_async_main())
    finally:
        loop.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "conntest":
        connectortest()
    else:
        main()
