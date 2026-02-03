[![black-lint](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/checkblack.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/checkblack.yml)
[![mypy and pytests](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/mypynpytests.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/mypynpytests.yml)
![Cumulative Clones](https://img.shields.io/endpoint?logo=github&url=https://gist.githubusercontent.com/vroomfondel/9519842e68e2ce05e5e223cb502d9e3d/raw/openclaw-k8s-toggle-operator_clone_count.json)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/openclaw-k8s-toggle-operator?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPi+Downloads)](https://pepy.tech/projects/openclaw-k8s-toggle-operator)

# openclaw-k8s-toggle-operator

Matrix-controlled Kubernetes deployment toggle operator. Connects to a Matrix
homeserver with E2E encryption and listens for chat commands to scale a K8s
deployment between 0 and 1 replicas.

- **Source**: [GitHub](https://github.com/vroomfondel/openclaw-k8s-toggle-operator)
- **PyPI**: [openclaw-k8s-toggle-operator](https://pypi.org/project/openclaw-k8s-toggle-operator/)
- **License**: LGPLv3

## Features

- Scale a Kubernetes Deployment to 0 or 1 replicas via Matrix chat commands
- E2E encryption support via matrix-nio with persistent crypto store
- TOFU device trust for allowed users
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
| `LOGURU_LEVEL` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, ...) | `DEBUG` |

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