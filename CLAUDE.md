# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

openclaw-k8s-toggle-operator — a Python Kubernetes operator for toggling (scaling) deployments via chat commands (Matrix). Extracted from the inline `clawdbot_operator.py` ConfigMap in the Ansible infrastructure repo (`roles/kubectlstuff/files/clawdbot_operator.py`).

- **PyPI name**: `openclaw-k8s-toggle-operator`
- **Import name**: `openclaw_k8s_toggle_operator`
- **License**: LGPLv3
- **GitHub**: `vroomfondel/openclaw-k8s-toggle-operator`
- **Reference project**: Follows patterns from `flickr-immich-k8s-sync-operator` (same author, same toolchain)

## Environment

- **Python**: 3.14 (virtualenv at `.venv/`)
- **Activate venv**: `source .venv/bin/activate`

## Common Commands

```bash
make venv          # Create/update virtualenv, install all deps
make tests         # Run pytest
make lint          # Format with black (line length 120)
make isort         # Sort imports with isort
make tcheck        # Static type checking with mypy
make commit-checks # Run pre-commit hooks on all files
make prepare       # tests + commit-checks
make pypibuild     # Build sdist + wheel with hatch
make pypipush      # Publish to PyPI
make docker        # Build Docker image
```

Run a single test file or test:
```bash
pytest tests/test_config.py
pytest tests/test_config.py::TestClassName::test_method_name
```

## Architecture

- **Origin**: Refactored from `clawdbot_operator.py` (an Ansible-managed ConfigMap), which is a Matrix-controlled K8s deployment scaler using matrix-nio with E2E encryption
- **Flat layout**: Package at `openclaw_k8s_toggle_operator/` (not src-layout)
- **Build backend**: Hatchling — version is single-sourced from `__init__.py` via `[tool.hatch.version]`
- **Entry point**: Console script `openclaw-k8s-toggle-operator` → `__main__:main()`
- **Logging**: loguru with `configure_logging()` in `__init__.py`; disabled by default, enabled in `__main__.py`
- **Signal handling**: SIGTERM/SIGINT for clean container shutdown
- **Dependencies**: `kubernetes` (K8s Python client), `matrix-nio[e2e]` (Matrix with E2E encryption), `loguru`, `tabulate` (startup printout)

### Modules

- **`__init__.py`** — Version, loguru `configure_logging()` helper
- **`config.py`** — Frozen `OperatorConfig` dataclass with `from_env()` classmethod; reads Matrix credentials, allowed users, deployment target, and crypto store path from environment variables
- **`operator.py`** — `OperatorBot` class handling Matrix login, E2E encryption (TOFU device trust), command parsing, and K8s deployment scaling via `AppsV1Api.patch_namespaced_deployment_scale()`
- **`__main__.py`** — Signal setup, loads config, initialises operator, runs the main async loop with auto-reconnect and exponential backoff

### Environment Variables

| Variable | Required | Default |
|----------|----------|---------|
| `MATRIX_HOMESERVER` | no | `http://synapse.matrix.svc.cluster.local:8008` |
| `MATRIX_USER` | **yes** | — |
| `MATRIX_PASSWORD` | **yes** | — |
| `ALLOWED_USERS` | **yes** | — (comma-separated full Matrix user IDs) |
| `DEPLOYMENT_NAME` | no | `clawdbot` |
| `DEPLOYMENT_NAMESPACE` | no | `clawdbot` |
| `CRYPTO_STORE_PATH` | no | `/data/crypto_store` |

### Bot Commands

| Command | Action |
|---------|--------|
| `start` / `on` | Scale deployment to 1 replica |
| `stop` / `off` | Scale deployment to 0 replicas |
| `status` | Show deployment replica counts |
| `help` | Show available commands |

### Key Patterns (inherited from reference projects)

- **Frozen dataclass config**: Immutable `OperatorConfig` with `from_env()` classmethod, validated at construction
- **In-cluster K8s access**: Uses pod service account via `kubernetes.config.load_incluster_config()`
- **E2E encryption**: matrix-nio `AsyncClient` with `AsyncClientConfig(encryption_enabled=True)`, persistent crypto store on PVC
- **TOFU device trust**: Auto-trusts devices of allowed users on invite/message
- **Graceful shutdown**: Signal handlers cancel asyncio tasks; auto-reconnect loop with exponential backoff (max 20 retries)

## Code Style

- **Formatter**: black, line length 120
- **Imports**: isort (`profile = "black"`, `line_length = 120` in `pyproject.toml`)
- **Type checking**: mypy with strict settings (`disallow_untyped_defs`, `check_untyped_defs`)
- **Tests**: pytest, test files in `tests/`
- All public functions must have type annotations

## Testing

```bash
make tests         # or: pytest .
```

Tests live in `tests/`. The `pytest.ini` config discovers test files via `python_files=tests/*.py`.

K8s API interactions require mocking (`unittest.mock` or `pytest-mock`). Matrix interactions require mocking the `nio.AsyncClient`.

## Docker

Single-stage build on `python:3.14-slim-trixie`. Non-root user (UID 1200). Entry point is the console script via tini. Requires `libolm-dev` system package for E2E encryption.

```bash
make docker        # Builds image tagged with version + latest
```

## CI

- `.github/workflows/checkblack.yml` — black --check on push to main + PRs
- `.github/workflows/mypynpytests.yml` — mypy + pytest on push to main + PRs
- `.github/workflows/buildmultiarchandpush.yml` — Docker multi-arch build + push
