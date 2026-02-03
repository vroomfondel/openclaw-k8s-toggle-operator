# openclaw-k8s-toggle-operator

[![black-lint](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/checkblack.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/checkblack.yml)
[![mypy and pytests](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/mypynpytests.yml/badge.svg)](https://github.com/vroomfondel/openclaw-k8s-toggle-operator/actions/workflows/mypynpytests.yml)
![Cumulative Clones](https://img.shields.io/endpoint?logo=github&url=https://gist.githubusercontent.com/vroomfondel/9519842e68e2ce05e5e223cb502d9e3d/raw/openclaw-k8s-toggle-operator_clone_count.json)
[![Docker Pulls](https://img.shields.io/docker/pulls/xomoxcc/openclaw-k8s-toggle-operator?logo=docker)](https://hub.docker.com/r/xomoxcc/openclaw-k8s-toggle-operator/tags)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/openclaw-k8s-toggle-operator?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPi+Downloads)](https://pepy.tech/projects/openclaw-k8s-toggle-operator)

[![Gemini_Generated_Image_7vikwe7vikwe7vik_250x250.png](Gemini_Generated_Image_7vikwe7vikwe7vik_250x250.png)](https://hub.docker.com/r/xomoxcc/openclaw-k8s-toggle-operator)

Matrix-controlled Kubernetes deployment toggle operator. Connects to a Matrix
homeserver with E2E encryption and listens for chat commands to scale a K8s
deployment between 0 and 1 replicas.

Extracted from the inline `clawdbot_operator.py` ConfigMap in the
[Ansible infrastructure repo](https://github.com/vroomfondel/somestuff)
(`roles/kubectlstuff/files/clawdbot_operator.py`).

## Status

**Beta (v0.0.1)** — the core Matrix bot and K8s scaling loop is implemented.
The project scaffolding (packaging, Docker image, CI) is in place.

## Bot Commands

Send these as plain text messages in a Matrix room with the bot (encrypted or unencrypted):

| Command | Action |
|---------|--------|
| `start` / `on` | Scale deployment to 1 replica |
| `stop` / `off` | Scale deployment to 0 replicas |
| `status` | Show deployment replica counts |
| `help` | Show available commands |

Only users listed in `ALLOWED_USERS` can send commands. The bot auto-accepts
room invitations from allowed users.

## Architecture

- Runs as a single-replica **Deployment** in a dedicated namespace
- Uses the **Kubernetes Python client** with in-cluster config to patch deployment scale
- Connects to Matrix via **matrix-nio** with E2E encryption (`libolm`)
- **TOFU device trust** — automatically trusts all devices of allowed users
- Crypto store must be on a **persistent volume** or the bot loses decryption keys on restart
- Auto-reconnect loop with exponential backoff (max 20 retries)

## Configuration

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
| `LOGURU_LEVEL` | no | `DEBUG` |

## Kubernetes Deployment

### RBAC

The operator requires a ServiceAccount with a Role scoped to the target namespace:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openclaw-toggle-operator
  namespace: clawdbot
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openclaw-toggle-operator
  namespace: clawdbot
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "deployments/scale"]
    verbs: ["get", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: openclaw-toggle-operator
  namespace: clawdbot
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: openclaw-toggle-operator
subjects:
  - kind: ServiceAccount
    name: openclaw-toggle-operator
    namespace: clawdbot
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw-toggle-operator
  namespace: clawdbot
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openclaw-toggle-operator
  template:
    metadata:
      labels:
        app: openclaw-toggle-operator
    spec:
      serviceAccountName: openclaw-toggle-operator
      containers:
        - name: operator
          image: xomoxcc/openclaw-k8s-toggle-operator:latest
          env:
            - name: MATRIX_USER
              value: "clawdbot-operator"
            - name: MATRIX_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: openclaw-toggle-operator
                  key: matrix-password
            - name: ALLOWED_USERS
              value: "@henning:matrix.example.com,@openclaw:matrix.example.com"
            # - name: MATRIX_HOMESERVER
            #   value: "http://synapse.matrix.svc.cluster.local:8008"  # default
            # - name: DEPLOYMENT_NAME
            #   value: "clawdbot"                                      # default
            # - name: DEPLOYMENT_NAMESPACE
            #   value: "clawdbot"                                      # default
            # - name: CRYPTO_STORE_PATH
            #   value: "/data/crypto_store"                            # default
            # - name: ECHO_MODE
            #   value: "true"                                          # default
          volumeMounts:
            - name: crypto-store
              mountPath: /data/crypto_store
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 128Mi
      volumes:
        - name: crypto-store
          persistentVolumeClaim:
            claimName: openclaw-toggle-operator-crypto
```

## Installation

### From PyPI

```bash
pip install openclaw-k8s-toggle-operator
```

### From source

```bash
git clone https://github.com/vroomfondel/openclaw-k8s-toggle-operator.git
cd openclaw-k8s-toggle-operator
make venv
source .venv/bin/activate
pip install .
```

### Docker

```bash
docker build -t openclaw-k8s-toggle-operator .
```

Or via Makefile:

```bash
make docker
```

### Multi-arch build script

`build-container-multiarch.sh` builds and pushes multi-arch images (amd64 + arm64).

```bash
./build-container-multiarch.sh              # login + full multi-arch build & push
./build-container-multiarch.sh onlylocal    # login + local-only build (no push)
./build-container-multiarch.sh login        # Docker Hub login only
```

## Usage

```bash
# Run directly
openclaw-k8s-toggle-operator

# Or via Python module
python -m openclaw_k8s_toggle_operator
```

## Development

### Makefile targets

| Target          | Description                                  |
|-----------------|----------------------------------------------|
| `make venv`     | Create virtualenv and install all dependencies |
| `make tests`    | Run pytest                                   |
| `make lint`     | Format code with black (line length 120)     |
| `make isort`    | Sort imports with isort                      |
| `make tcheck`   | Static type checking with mypy               |
| `make commit-checks` | Run pre-commit hooks on all files      |
| `make prepare`  | Run tests + commit-checks                    |
| `make pypibuild`| Build sdist + wheel with hatch               |
| `make pypipush` | Publish to PyPI with hatch                   |
| `make docker`   | Build Docker image                           |

## License

[GNU Lesser General Public License v3](LICENSE.md)
