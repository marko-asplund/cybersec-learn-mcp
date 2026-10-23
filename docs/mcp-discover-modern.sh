#!/usr/bin/env bash
# MCP 2026-07-28: optional server/discover -> tools/resources/prompts discovery.
# Each HTTP request is independent; no initialize, initialized, or session ID.
set -euo pipefail

MCP_URL="${MCP_URL:-http://127.0.0.1:8000/mcp}"
PROTOCOL_VERSION='2026-07-28'
REQUEST_ID=0
WORK_DIR="$(mktemp -d)"
HEADERS="$WORK_DIR/headers"
BODY="$WORK_DIR/body"
trap 'rm -rf "$WORK_DIR"' EXIT

for cmd in curl jq; do
  command -v "$cmd" >/dev/null || { echo "Missing dependency: $cmd" >&2; exit 1; }
done

# Pretty-print either plain JSON or JSON-RPC messages carried as SSE data.
print_response() {
  if [[ ! -s "$BODY" ]]; then
    echo '(no response body)'
  elif grep -qi '^content-type:.*text/event-stream' "$HEADERS"; then
    sed -n 's/^data:[[:space:]]*//p' "$BODY" | while IFS= read -r line; do
      jq . <<<"$line" || printf '%s\n' "$line"
    done
  else
    jq . "$BODY" || cat "$BODY"
  fi
}

modern_request() {
  local method="$1"
  REQUEST_ID=$((REQUEST_ID + 1))
  local payload status

  # Modern MCP requires protocol version and client capabilities on EVERY call.
  payload="$(jq -nc --arg method "$method" --arg version "$PROTOCOL_VERSION" \
    --argjson id "$REQUEST_ID" '{
      jsonrpc:"2.0", id:$id, method:$method,
      params:{_meta:{
        "io.modelcontextprotocol/protocolVersion":$version,
        "io.modelcontextprotocol/clientInfo":{name:"curl-discovery-modern",version:"1.0"},
        "io.modelcontextprotocol/clientCapabilities":{}
      }}
    }')"

  echo
  echo "=== $method ==="
  status="$(curl -sS --max-time 30 -D "$HEADERS" -o "$BODY" -w '%{http_code}' \
    -X POST "$MCP_URL" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "MCP-Protocol-Version: $PROTOCOL_VERSION" \
    -H "Mcp-Method: $method" \
    --data-binary "$payload")"
  printf 'HTTP %s\n' "$status"
  print_response
  if [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
    echo "Request failed with HTTP $status" >&2
    exit 1
  fi
}

# Phase 1: Discover server versions/capabilities (optional in modern MCP).
modern_request 'server/discover'

# Phase 2: Discover tools and their input schemas.
modern_request 'tools/list'

# Phase 3: Discover concrete resources and URI templates.
modern_request 'resources/list'
modern_request 'resources/templates/list'

# Phase 4: Discover prompts and their arguments.
modern_request 'prompts/list'

# Phase 5: No session to close (stateless protocol).
echo
echo '=== 5. Done — no MCP session to close ==='

