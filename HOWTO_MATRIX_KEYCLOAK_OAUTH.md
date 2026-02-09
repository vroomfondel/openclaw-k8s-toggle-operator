# HOWTO: Authenticate a Matrix Bot via Keycloak OAuth/JWT (ROPC + synapse-token-authenticator)

This guide explains how to authenticate a headless Matrix bot against Synapse using
**Keycloak** as the identity provider. The bot obtains a JWT from Keycloak via the
**Resource Owner Password Credentials (ROPC)** grant type and presents it to Synapse,
which validates the token against Keycloak's **JWKS endpoint** using
[synapse-token-authenticator](https://github.com/famedly/synapse-token-authenticator).

This approach avoids browser-based OAuth redirects, making it suitable for bots and
services running in Kubernetes.

## Prerequisites

- **Keycloak** deployed and reachable from both Synapse and the bot
- **Synapse** (Matrix homeserver) deployed with the `synapse-token-authenticator` module installed
- A dedicated **Keycloak realm** for Matrix (recommended — Matrix localparts can't contain `@`, so using `registrationEmailAsUsername` would break things)
- The bot user registered on **both** Synapse and Keycloak (same username)

---

## Step 1: Create a Keycloak Client for ROPC

Create a **confidential** client in your Keycloak realm with ROPC enabled. This client
is used by bots and services — it is separate from any browser-based OIDC client you
may already have for Element/Cinny.

| Setting | Value | Why |
|---------|-------|-----|
| `publicClient` | `false` | Confidential — requires client secret |
| `directAccessGrantsEnabled` | `true` | Enables the ROPC grant type |
| `standardFlowEnabled` | `false` | Bot doesn't use browser redirects |
| `clientAuthenticatorType` | `client-secret` | Secret-based client auth |

Via `kcadm.sh`:

```bash
kcadm.sh create clients -r <REALM> \
  -s clientId=<CLIENT_ID> \
  -s publicClient=false \
  -s directAccessGrantsEnabled=true \
  -s standardFlowEnabled=false \
  -s clientAuthenticatorType=client-secret
```

After creation, retrieve the client secret from the Keycloak Admin Console or via:

```bash
kcadm.sh get clients/<CLIENT_UUID>/client-secret -r <REALM> --fields value
```

---

## Step 2: Create the Bot User in Keycloak

The bot must exist as a user in the Keycloak realm — ROPC authenticates against
Keycloak's user database, not Synapse's. The username must match the Matrix localpart.

```bash
kcadm.sh create users -r <REALM> \
  -s username=<BOT_USERNAME> \
  -s enabled=true

kcadm.sh set-password -r <REALM> \
  --username <BOT_USERNAME> \
  --new-password "<BOT_PASSWORD>"
```

> **Important:** The bot user must also exist on Synapse (e.g. via
> `register_new_matrix_user`). Keycloak and Synapse maintain separate user databases —
> ROPC authenticates against Keycloak, but Synapse must recognise the localpart when
> the JWT is presented.

---

## Step 3: Install and Configure synapse-token-authenticator

[synapse-token-authenticator](https://github.com/famedly/synapse-token-authenticator)
adds JWT/OIDC login types to Synapse. It needs to be installed into the Synapse
Python environment.

### Installation

**Option A — pip install at container startup (no custom image):**

Override the container command to install the module before starting Synapse.
This adds a few seconds to startup but avoids maintaining a custom Docker image.

```yaml
# In the Synapse container spec:
containers:
  - name: synapse
    image: matrixdotorg/synapse:latest
    command: ["/bin/sh", "-c"]
    args:
      - |
        pip install --no-cache-dir synapse-token-authenticator && \
        exec /start.py
```

**Option B — custom Docker image (faster startup):**

```dockerfile
FROM matrixdotorg/synapse:latest
RUN pip install --no-cache-dir synapse-token-authenticator
```

### Configuration

Add the `oauth` block to `homeserver.yaml`:

```yaml
modules:
  - module: synapse_token_authenticator.TokenAuthenticator
    config:
      oauth:
        jwt_validation:
          jwks_endpoint: "https://<KEYCLOAK_HOST>/realms/<REALM>/protocol/openid-connect/certs"
          localpart_path: "preferred_username"
          require_expiry: true
          validator:
            type: exist
        username_type: "localpart"
```

Key settings:

| Setting | Purpose |
|---------|---------|
| `jwks_endpoint` | Synapse fetches Keycloak's public keys automatically (supports key rotation) |
| `localpart_path` | Maps the JWT's `preferred_username` claim to the Matrix localpart |
| `validator.type: exist` | Rejects login if the user doesn't already exist on Synapse |
| `require_expiry` | Reject tokens without an `exp` claim |

This enables the Matrix login type `com.famedly.login.token.oauth`.

---

## Step 4: Configure the Operator Deployment

Set the following environment variables on the bot's container:

```yaml
env:
  # --- Matrix connection ---
  - name: MATRIX_HOMESERVER
    value: "http://synapse.<NAMESPACE>.svc.cluster.local:8008"
  - name: MATRIX_USER
    value: "<BOT_USERNAME>"
  - name: MATRIX_PASSWORD          # still needed — used as Keycloak password for ROPC
    valueFrom:
      secretKeyRef:
        name: <SECRET_NAME>
        key: MATRIX_PASSWORD

  # --- JWT authentication via Keycloak ---
  - name: AUTH_METHOD
    value: "jwt"
  - name: KEYCLOAK_URL
    value: "http://keycloak.<NAMESPACE>.svc.cluster.local:8080"  # or external URL
  - name: KEYCLOAK_REALM
    value: "<REALM>"
  - name: KEYCLOAK_CLIENT_ID
    value: "<CLIENT_ID>"
  - name: KEYCLOAK_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: <SECRET_NAME>
        key: KEYCLOAK_CLIENT_SECRET
  - name: JWT_LOGIN_TYPE
    value: "com.famedly.login.token.oauth"
```

> **Why is `MATRIX_PASSWORD` still required?** The ROPC grant type sends
> `grant_type=password` to Keycloak — the bot authenticates to Keycloak with
> username + password, receives a JWT, and then presents the JWT to Synapse.
> The password is used for Keycloak authentication, not for Synapse login.

### Supported Login Types

| `JWT_LOGIN_TYPE` | Synapse validates via | Module |
|---|---|---|
| `com.famedly.login.token.oauth` | JWKS endpoint (automatic key rotation) | synapse-token-authenticator |
| `com.famedly.login.token` | Symmetric secret (HS512) | synapse-token-authenticator |
| `org.matrix.login.jwt` | Public key (RS256, manual) | Built-in Synapse `jwt_config` |

---

## Step 5: Make the Client Secret Available

The Keycloak client secret must be available to the bot pod as a K8s Secret. If
Keycloak and the bot run in different namespaces, you'll need to copy the secret.

**Option A** — Store it in the bot's own Secret (e.g. via Ansible, Helm, or manually):

```bash
kubectl -n <BOT_NAMESPACE> create secret generic <SECRET_NAME> \
  --from-literal=MATRIX_PASSWORD="<BOT_PASSWORD>" \
  --from-literal=KEYCLOAK_CLIENT_SECRET="<CLIENT_SECRET>" \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Option B** — Use a tool like [kubernetes-replicator](https://github.com/mittwald/kubernetes-replicator) or [ExternalSecrets](https://external-secrets.io/) to sync the secret across namespaces.

---

## Step 6: Verify the Flow

Test the complete chain manually before deploying the bot.

### 6a. Test Keycloak ROPC grant

```bash
curl -s -X POST \
  "https://<KEYCLOAK_HOST>/realms/<REALM>/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "username=<BOT_USERNAME>" \
  -d "password=<BOT_PASSWORD>" | jq .access_token
```

You should get a JWT back. Common errors:
- `401` — user doesn't exist in Keycloak or password is wrong
- `400 unauthorized_client` — ROPC not enabled on the client (`directAccessGrantsEnabled=false`)
- `400 invalid_client` — wrong client secret

### 6b. Test Matrix login with the JWT

```bash
curl -s -X POST \
  "https://<MATRIX_HOST>/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "com.famedly.login.token.oauth",
    "identifier": {"type": "m.id.user", "user": "<BOT_USERNAME>"},
    "token": "<JWT_FROM_STEP_6a>"
  }' | jq .
```

You should get `user_id`, `access_token`, and `device_id` back.

### 6c. Deploy and check operator logs

```bash
kubectl -n <BOT_NAMESPACE> logs -f deployment/<BOT_DEPLOYMENT>
```

Look for a log line like:
```
Logging in as <BOT_USERNAME> on <HOMESERVER> (method=jwt, login_type=com.famedly.login.token.oauth)
```

---

## Authentication Flow

```
Bot                         Keycloak                      Synapse
 |                             |                             |
 |-- ROPC grant -------------->|                             |
 |   (username + password      |                             |
 |    + client_id/secret)      |                             |
 |                             |                             |
 |<-- JWT access token --------|                             |
 |                             |                             |
 |-- Matrix login ------------------------------------------->|
 |   (type: com.famedly.       |                             |
 |    login.token.oauth,       |    +-- JWKS validation -->  |
 |    token: <JWT>)            |    |   (fetches public key  |
 |                             |    |    from Keycloak JWKS) |
 |                             |    +------------------------+
 |<-- Matrix access token + device_id -----------------------|
```

---

## Checklist

- [ ] Keycloak client exists with ROPC enabled (`directAccessGrantsEnabled=true`)
- [ ] Bot user exists **in Keycloak** (not just Synapse) with matching username
- [ ] Bot user exists **in Synapse** (via `register_new_matrix_user` or registration API)
- [ ] `synapse-token-authenticator` installed on Synapse with `oauth` config block pointing to Keycloak JWKS
- [ ] Client secret accessible to the bot pod as a K8s Secret
- [ ] Operator env vars set: `AUTH_METHOD=jwt`, `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `JWT_LOGIN_TYPE`
- [ ] ROPC grant tested manually (`curl` to Keycloak token endpoint)
- [ ] Matrix JWT login tested manually (`curl` to `/_matrix/client/v3/login`)
- [ ] Bot deployed and logs show successful JWT login

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 Invalid user credentials` from Keycloak | Bot user doesn't exist in Keycloak or password is wrong | Create user in Keycloak realm with `kcadm.sh` |
| `400 unauthorized_client` from Keycloak | ROPC not enabled on client | Set `directAccessGrantsEnabled=true` on the Keycloak client |
| `403 M_FORBIDDEN` from Synapse | User doesn't exist on Synapse, or `validator.type: exist` rejects it | Register the user on Synapse first |
| `403 M_UNKNOWN` / invalid token from Synapse | JWKS endpoint misconfigured or unreachable from Synapse | Verify Synapse can reach `https://<KEYCLOAK_HOST>/realms/<REALM>/protocol/openid-connect/certs` |
| `M_UNKNOWN` with "unknown login type" | `synapse-token-authenticator` not installed or `oauth` block missing | Check `pip list` on Synapse container and verify `homeserver.yaml` |