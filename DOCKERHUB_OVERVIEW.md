[![black-lint](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/checkblack.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/checkblack.yml)
[![mypy and pytests](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/mypynpytests.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/mypynpytests.yml)
[![BuildAndPushMultiarch](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/buildmultiarchandpush.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/buildmultiarchandpush.yml)
[![Cumulative Clones](https://img.shields.io/endpoint?logo=github&url=https://gist.githubusercontent.com/vroomfondel/9519842e68e2ce05e5e223cb502d9e3d/raw/openclaw-k8s-toggle-operator_clone_count.json)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/openclaw-k8s-toggle-operator?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPi+Downloads)](https://pepy.tech/projects/openclaw-k8s-toggle-operator)
[![PyPI](https://img.shields.io/pypi/v/openclaw-k8s-toggle-operator?logo=pypi&logoColor=white)](https://pypi.org/project/openclaw-k8s-toggle-operator/)

[![Gemini_Generated_Image_7vikwe7vikwe7vik_250x250.png](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/raw/main/Gemini_Generated_Image_7vikwe7vikwe7vik_250x250.png)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator)

# openclaw-k8s-toggle-operator

Matrix-controlled Kubernetes deployment toggle operator. Connects to a Matrix
homeserver with E2E encryption and listens for chat commands to scale a K8s
deployment between 0 and 1 replicas.

![Operator startup in K9s](https://raw.githubusercontent.com/vroomfondel/openclaw-k8s-toggle-operator/main/Bildschirmfoto_2026-02-09_11-39-25_blurred.png)

![Operator startup with JWT auth and crypto store migration](https://raw.githubusercontent.com/vroomfondel/openclaw-k8s-toggle-operator/main/Bildschirmfoto_2026-02-23_15-11-07_blurred.png)

![Old crypto store key import and device trust](https://raw.githubusercontent.com/vroomfondel/openclaw-k8s-toggle-operator/main/Bildschirmfoto_2026-02-23_15-11-22_blurred.png)


- **Source**: [GitHub](https://github.com/vroomfondel/openclaw-k8s-toggle-operator)
- **PyPI**: [openclaw-k8s-toggle-operator](https://pypi.org/project/openclaw-k8s-toggle-operator/)
- **License**: LGPLv3

## Features

- Scale a Kubernetes Deployment to 0 or 1 replicas via Matrix chat commands
- E2E encryption via **minimatrix** (matrix-nio wrapper) with persistent crypto store
- Session reuse — persists Matrix access token and device ID across restarts
- Auto-join pending room invites on startup
- TOFU device trust for allowed users
- Multiple auth methods: password, SSO, or JWT via Keycloak (ROPC + JWKS)
- Clean signal handling (SIGTERM/SIGINT) for graceful container shutdown
- Auto-reconnect with exponential backoff (max 20 retries)
- Structured logging via loguru

## Quick start

```bash
docker run --rm xomoxcc/openclaw-k8s-toggle-operator:latest
```

## Bot Commands

| Command | Action |
|---------|--------|
| `start` / `on` | Scale deployment to 1 replica |
| `stop` / `off` | Scale deployment to 0 replicas |
| `status` | Show deployment replica counts |
| `help` | Show available commands |

## Configuration

| Variable | Description | Default |
|---|---|---|
| `MATRIX_HOMESERVER` | Matrix homeserver URL | `http://synapse.matrix.svc.cluster.local:8008` |
| `MATRIX_USER` | Matrix bot username (**required**) | -- |
| `MATRIX_PASSWORD` | Matrix bot password (**required**) | -- |
| `ALLOWED_USERS` | Comma-separated full Matrix user IDs (**required**) | -- |
| `DEPLOYMENT_NAME` | K8s Deployment to toggle | `clawdbot` |
| `DEPLOYMENT_NAMESPACE` | Namespace of the target Deployment | `clawdbot` |
| `CRYPTO_STORE_PATH` | Path for E2E encryption crypto store | `/data/crypto_store` |
| `AUTH_METHOD` | Auth method (`password`, `sso`, or `jwt`) | `password` |
| `ECHO_MODE` | Echo user messages with lobster emoji before processing | `true` |
| `LOGURU_LEVEL` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, ...) | `DEBUG` |

### JWT Authentication (Keycloak)

Set `AUTH_METHOD=jwt` to authenticate via Keycloak ROPC grant instead of direct Matrix password login. The bot obtains a JWT from Keycloak and presents it to Synapse for validation via JWKS.

| Variable | Description | Default |
|---|---|---|
| `AUTH_METHOD` | Auth method (`password`, `sso`, or `jwt`) | `password` |
| `KEYCLOAK_URL` | Keycloak base URL (required if `jwt`) | -- |
| `KEYCLOAK_REALM` | Keycloak realm name (required if `jwt`) | -- |
| `KEYCLOAK_CLIENT_ID` | Keycloak client ID (required if `jwt`) | -- |
| `KEYCLOAK_CLIENT_SECRET` | Keycloak client secret | `""` |
| `JWT_LOGIN_TYPE` | Matrix login type for JWT auth | `com.famedly.login.token.oauth` |

Requires [synapse-token-authenticator](https://github.com/famedly/synapse-token-authenticator) on the Synapse side. See the [setup guide](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/blob/main/HOWTO_MATRIX_KEYCLOAK_OAUTH.md) for step-by-step instructions.

## Kubernetes Deployment

The operator runs as a single-replica Deployment with a namespace-scoped ServiceAccount.
The crypto store must be on a persistent volume or the bot loses decryption keys on restart.
See the [README](https://github.com/vroomfondel/openclaw-k8s-toggle-operator#kubernetes-deployment) for full RBAC and Deployment manifests.

## Image details

- Base: `python:3.14-slim-trixie`
- Non-root user (`pythonuser`)
- Entrypoint: `tini --` with `openclaw-k8s-toggle-operator` as default CMD
- Requires `libolm-dev` for E2E encryption
- Multi-arch: `linux/amd64`, `linux/arm64`

## Building the image

```bash
# Simple local build
docker build -t openclaw-k8s-toggle-operator .

# Multi-arch build & push
./build-container-multiarch.sh

# Local-only build (no push)
./build-container-multiarch.sh onlylocal

# Docker Hub login only
./build-container-multiarch.sh login
```

## License
This project is licensed under the LGPL where applicable/possible — see [LICENSE.md](LICENSE.md). Some files/parts may use other licenses: [MIT](LICENSEMIT.md) | [GPL](LICENSEGPL.md) | [LGPL](LICENSELGPL.md). Always check per‑file headers/comments.


## Authors
- Repo owner (primary author)
- Additional attributions are noted inline in code comments


## Acknowledgments
- Inspirations and snippets are referenced in code comments where appropriate.


## ⚠️ Note

This is a development/experimental project. For production use, review security settings, customize configurations, and test thoroughly in your environment. Provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. Use at your own risk.
