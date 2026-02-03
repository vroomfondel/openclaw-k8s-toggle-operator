#!/bin/bash

cd "$(dirname "$0")" || exit 2

source ./include.sh
# note: source include.local.sh if found (which it should -> otherwise makes no sense)

# Create public DockerHub repo via API
DHREPO_NS="${DHREPO%%/*}"
DHREPO_NAME="${DHREPO##*/}"

# Create repo + org access token via API if DOCKER_TOKEN is missing or not an OAT
if [[ -z "$DOCKER_TOKEN" || "$DOCKER_TOKEN" != dckr_oat* ]]; then
  # Export vars needed by dh_login.py (sourced shell vars aren't visible to child processes)
  export DOCKERHUB_ADMIN_USER DOCKERHUB_ADMIN_PASSWORD DOCKERHUB_TOTP_SECRET

  # Login to Docker Hub (handles MFA/TOTP if DOCKERHUB_TOTP_SECRET is set)
  DH_JWT=$(python3 ./dh_login.py)

  if [[ -z "$DH_JWT" ]]; then
    echo "ERROR: DockerHub login failed" >&2
    exit 123
  fi

  curl -s -f -X POST 'https://hub.docker.com/v2/repositories/' \
    -H "Authorization: Bearer $DH_JWT" \
    -H 'Content-Type: application/json' \
    -d "{\"namespace\":\"$DHREPO_NS\",\"name\":\"$DHREPO_NAME\",\"is_private\":false}"

  # Docs: https://docs.docker.com/reference/api/hub/latest/#tag/org-access-tokens
  OAT_DESC="CI/CD push token for $DHREPO, created $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  OAT_EXPIRES=$(date -u -d "+365 days" +%Y-%m-%dT%H:%M:%SZ)
  OAT_RESPONSE=$(curl -s -f -X POST "https://hub.docker.com/v2/orgs/$DHREPO_NS/access-tokens" \
    -H "Authorization: Bearer $DH_JWT" \
    -H 'Content-Type: application/json' \
    -d "{\"label\":\"$DHREPO\",\"description\":\"$OAT_DESC\",\"expires_at\":\"$OAT_EXPIRES\",\"resources\":[{\"type\":\"TYPE_REPO\",\"path\":\"*/*/public\",\"scopes\":[\"image-pull\"]},{\"type\":\"TYPE_REPO\",\"path\":\"$DHREPO\",\"scopes\":[\"image-pull\",\"image-push\"]}]}")

  # Extract token value (dckr_oat_...) — shown once, cannot be retrieved again
  echo "$OAT_RESPONSE" >&2
  DOCKER_TOKEN=$(echo "$OAT_RESPONSE" | jq -r '.token')
  if [[ -z "$DOCKER_TOKEN" ]]; then
    echo "ERROR: OAT token creation/extraction failed" >&2
    exit 124
  fi
  echo "OAT token: $DOCKER_TOKEN"

  # Persist to include.local.sh
  sed -i "s|^DOCKER_TOKEN=.*|DOCKER_TOKEN=\"$DOCKER_TOKEN\"|" include.local.sh
fi

# Create public gist with badge files if GIST_ID is not yet set
if [[ -z "$GIST_ID" || "$GIST_ID" != ghp_* ]]; then
  REPO_SHORT="${GHREPO##*/}"
  GIST_DESC="$REPO_SHORT clone tracking"

  # Check if a gist with this description already exists
  EXISTING_GIST_ID=$(GH_TOKEN="$GIST_TOKEN" gh gist list --public -L 100 | grep "$GIST_DESC" | head -1 | cut -f1)

  if [[ -n "$EXISTING_GIST_ID" ]]; then
    GIST_ID="$EXISTING_GIST_ID"
    echo "Found existing gist: $GIST_ID (description: $GIST_DESC)"
  else
    HIST_FILE="/tmp/${REPO_SHORT}_clone_history.json"
    BADGE_FILE="/tmp/${REPO_SHORT}_clone_count.json"
    echo '{}' > "$HIST_FILE"
    echo '{}' > "$BADGE_FILE"

    GIST_URL=$(GH_TOKEN="$GIST_TOKEN" gh gist create --public --desc "$GIST_DESC" "$HIST_FILE" "$BADGE_FILE")
    GIST_ID="${GIST_URL##*/}"
    echo "Created gist: $GIST_URL (ID: $GIST_ID)"

    rm "$HIST_FILE" "$BADGE_FILE"
  fi

  # Persist to include.local.sh
  sed -i "s|^GIST_ID=.*|GIST_ID=\"$GIST_ID\"|" include.local.sh
fi

# Replace GIST_ID default in update_badge.py if it doesn't match
CURRENT_GIST_DEFAULT=$(grep -oP 'os\.environ\.get\("GIST_ID",\s*"\K[^"]+' update_badge.py)
if [[ -n "$GIST_ID" && "$CURRENT_GIST_DEFAULT" != "$GIST_ID" ]]; then
  sed -i "s|$CURRENT_GIST_DEFAULT|$GIST_ID|" update_badge.py
  echo "Updated GIST_ID default in update_badge.py: $CURRENT_GIST_DEFAULT -> $GIST_ID"
fi

# Create GitHub repo if it doesn't exist yet
if ! gh repo view "$GHREPO" &>/dev/null; then
  gh repo create "$GHREPO" --public
  echo "Created GitHub repo: $GHREPO"
fi

gh secret set GIST_ID --body "$GIST_ID" --repo "$GHREPO"
gh secret set DOCKERHUB_TOKEN --body "$DOCKER_TOKEN" --repo "$GHREPO"
gh secret set DOCKERHUB_USERNAME --body "$DOCKER_TOKENUSER" --repo "$GHREPO"
gh secret set GIST_TOKEN --body "$GIST_TOKEN" --repo "$GHREPO"
gh secret set REPO_PRIV_TOKEN --body "$REPO_PRIV_TOKEN" --repo "$GHREPO"

# NOTE: REPO_TOKEN only needed locally