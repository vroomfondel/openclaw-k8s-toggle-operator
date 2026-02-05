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
- **Entry points**: Console scripts `openclaw-k8s-toggle-operator` → `__main__:main()` and `openclaw-k8s-toggle-operator-conntest` → `__main__:connectortest()`
- **Logging**: loguru with `configure_logging()` in `__init__.py`; disabled by default, enabled in `__main__.py`
- **Signal handling**: SIGTERM/SIGINT for clean container shutdown
- **Dependencies**: `kubernetes` (K8s Python client), `matrix-nio[e2e]` (Matrix with E2E encryption), `loguru`, `tabulate` (startup printout)

### Modules

- **`__init__.py`** — Version, loguru `configure_logging()` helper
- **`config.py`** — Frozen `OperatorConfig` dataclass with `from_env()` classmethod; reads Matrix credentials, allowed users, deployment target, and crypto store path from environment variables
- **`matrix_client.py`** — `MatrixClientHandler` class encapsulating Matrix client operations with E2E encryption, TOFU device trust, and multiple authentication methods (password, SSO, JWT)
- **`operator.py`** — `OperatorBot` class handling command parsing and K8s deployment scaling via `AppsV1Api.patch_namespaced_deployment_scale()`; uses `MatrixClientHandler` for Matrix operations
- **`sso_login.py`** — `SSOLoginHandler` for SSO authentication via Keycloak OAuth flow (discouraged, prefer JWT)
- **`jwt_login.py`** — `JWTLoginHandler` for JWT authentication via Keycloak ROPC grant
- **`__main__.py`** — Signal setup, loads config, initialises operator, runs the main async loop with auto-reconnect and exponential backoff; also provides `connectortest()` CLI for Matrix connectivity checks

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
| `ECHO_MODE` | no | `true` (echo user messages with lobster emoji before processing) |

#### JWT Authentication Variables (for `AUTH_METHOD=jwt`)

| Variable | Required | Default |
|----------|----------|---------|
| `KEYCLOAK_URL` | **yes** | — |
| `KEYCLOAK_REALM` | **yes** | — |
| `KEYCLOAK_CLIENT_ID` | **yes** | — |
| `KEYCLOAK_CLIENT_SECRET` | no | `""` (empty for public clients) |
| `JWT_LOGIN_TYPE` | no | `com.famedly.login.token.oauth` (alt: `com.famedly.login.token`, `org.matrix.login.jwt`) |

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
- **TOFU device trust**: Auto-trusts devices of allowed users on invite/message (see E2E trust flow below)
- **Graceful shutdown**: Signal handlers cancel asyncio tasks; auto-reconnect loop with exponential backoff (max 20 retries)

### E2E Encryption & Device Trust Flow

matrix-nio requires all recipient devices to be verified before `room_send` will encrypt. The bot uses TOFU (Trust On First Use) via `client.verify_device()`.

**Trust hierarchy** (each level calls into the next):
- `trust_devices_in_room(room_id)` — iterates all room members (except self), calls `trust_devices_for_user` for each
- `trust_devices_for_user(user_id)` — forces `user_id` into `olm.users_for_key_query` then runs `keys_query()` (catches `LocalProtocolError` as fallback), then iterates `client.device_store[user_id]` and verifies any unverified devices
- `trust_all_allowed_devices()` — startup-only, trusts allowed users via `trust_devices_for_user`

**When trust runs:**
- **Startup**: `trust_all_allowed_devices()` after initial sync
- **On invite**: `trust_devices_for_user(sender)` after joining room
- **Before every send** (`on_message`, `on_megolm_event`): `trust_devices_in_room(room_id)` — this is critical because `sync_forever` continuously populates the device store with newly discovered devices that must be verified before the bot can encrypt outgoing messages for them

**Common pitfalls**:
- Trusting only at startup or only the sender is insufficient. Encrypted `room_send` must encrypt for *all* devices of *all* room members. New devices appear in the device store during ongoing syncs and must be verified before the next send, otherwise matrix-nio raises `"Device X for user Y is not verified or blacklisted"`.
- `keys_query()` only queries users in `olm.users_for_key_query`. When that set is empty (no pending queries from sync), it raises `LocalProtocolError` and the device store stays stale. Fix: always add the user to `olm.users_for_key_query` before calling `keys_query()`.
- All `room_send()` calls use `ignore_unverified_devices=True` as a safety net against race conditions where a device appears between the trust loop and the send. Ignored devices still receive encryption keys — they just aren't formally verified. Do not remove this flag.

### JWT Authentication

When `AUTH_METHOD=jwt` is set, the operator authenticates via Keycloak ROPC instead of password login. Three login types are supported:

| Login Type | Synapse Module | Key Management |
|------------|----------------|----------------|
| `com.famedly.login.token.oauth` (default) | synapse-token-authenticator oauth: | JWKS endpoint (automatic) |
| `com.famedly.login.token` | synapse-token-authenticator jwt: | Symmetric secret (HS512) |
| `org.matrix.login.jwt` | Built-in | Public key (manual) |

#### Authentication Flow

1. Bot sends username/password to Keycloak via ROPC (Resource Owner Password Credentials) grant
2. Keycloak returns a JWT access token
3. Bot sends JWT to Synapse via the configured login type
4. Synapse validates JWT and logs in the user

#### Keycloak Requirements

Create a **confidential client** with ROPC enabled:
- `publicClient: false` — confidential client requires client secret
- `directAccessGrantsEnabled: true` — enables ROPC grant type
- `clientAuthenticatorType: client-secret`
- `standardFlowEnabled: false` (optional, bot doesn't use browser flows)

Get the realm public key (for native JWT):
```bash
curl -s "https://keycloak.example.com/realms/<realm>" | jq -r '.public_key'
```

#### Native Synapse JWT Setup

For `JWT_LOGIN_TYPE=org.matrix.login.jwt`, configure `homeserver.yaml`:

```yaml
jwt_config:
  enabled: true
  secret: |
    -----BEGIN PUBLIC KEY-----
    <Keycloak realm public key>
    -----END PUBLIC KEY-----
  algorithm: "RS256"
  subject_claim: "preferred_username"
  issuer: "https://keycloak.example.com/realms/<realm>"
```

#### synapse-token-authenticator Setup

For `JWT_LOGIN_TYPE=com.famedly.login.token.oauth` (default), install synapse-token-authenticator and configure `homeserver.yaml`:

```yaml
modules:
  - module: synapse_token_authenticator.TokenAuthenticator
    config:
      oauth:
        jwt_validation:
          jwks_endpoint: "https://keycloak.example.com/realms/<realm>/protocol/openid-connect/certs"
          localpart_path: "preferred_username"
          require_expiry: true
          validator:
            type: exist
        username_type: "localpart"
```

#### Comparison

| Feature | Native JWT | synapse-token-authenticator |
|---------|------------|----------------------------|
| Key management | Manual (copy public key) | Automatic (JWKS endpoint) |
| Key rotation | Manual update required | Automatic |
| Token revocation | Not supported | Introspection mode available |
| Setup complexity | Simpler | Requires module installation |

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
