Based on the MCP authorization specification, here are the steps for a client to construct an authorization URL from an MCP server URL:

## Step-by-Step Authorization URL Construction

### 1. Initial Request and Discovery

1. Make an MCP request to the server without a token
2. Server responds with `HTTP 401 Unauthorized` containing `WWW-Authenticate` header
3. Extract the resource metadata URL from the `WWW-Authenticate` header

### 2. Get Protected Resource Metadata

1. Request the protected resource metadata from the MCP server:
   ```
   GET /.well-known/oauth-protected-resource
   ```
2. Parse the response to extract `authorization_servers` array
3. Select an authorization server from the list

### 3. Authorization Server Metadata Discovery

For the selected authorization server URL, try these endpoints in priority order:

**For issuer URLs with path components** (e.g., `https://auth.example.com/tenant1`):

1. `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`
2. `https://auth.example.com/.well-known/openid-configuration/tenant1`

**For issuer URLs without path components** (e.g., `https://auth.example.com`):

1. `https://auth.example.com/.well-known/oauth-authorization-server`
2. `https://auth.example.com/.well-known/openid-configuration`

### 4. Parse Authorization Server Metadata

Extract from the metadata response:

- `authorization_endpoint` - for the authorization URL
- `token_endpoint` - for later token exchange
- `registration_endpoint` - for dynamic client registration (if supported)
- `code_challenge_methods_supported` - **MUST** be present and include `S256`

### 5. Dynamic Client Registration (if supported)

If `registration_endpoint` is present:

1. POST to the registration endpoint to get client credentials
2. Store the returned `client_id` (and `client_secret` if confidential client)

### 6. Construct Authorization URL

Build the authorization URL with these **required** parameters:

```text path="authorization-url-template.txt"
{authorization_endpoint}?
  response_type=code&
  client_id={client_id}&
  redirect_uri={redirect_uri}&
  resource={mcp_server_canonical_uri}&
  code_challenge={code_challenge}&
  code_challenge_method=S256&
  state={random_state}
```

**Key Requirements:**

- `resource` parameter **MUST** be the canonical URI of the MCP server
- `code_challenge_method` **MUST** be `S256`
- `code_challenge` **MUST** be base64url-encoded SHA256 hash of the code verifier
- `state` parameter **SHOULD** be included for security

### 7. Example Implementation Flow

```javascript path="mcp-auth-flow.js"
async function constructAuthorizationUrl(mcpServerUrl) {
  // Step 1: Try initial request to trigger 401
  const response = await fetch(mcpServerUrl);
  if (response.status !== 401) {
    throw new Error("Expected 401 response");
  }

  // Step 2: Get resource metadata (note: .well-known at path start)
  const resourceMetadataUrl = new URL(
    "/.well-known/oauth-protected-resource",
    mcpServerUrl
  );
  const resourceMetadata = await fetch(resourceMetadataUrl).then((r) =>
    r.json()
  );

  // Step 3: Select authorization server
  const authServerUrl = resourceMetadata.authorization_servers[0];

  // Step 4: Discover authorization server metadata
  const authMetadata = await discoverAuthServerMetadata(authServerUrl);

  // Verify PKCE support is required
  if (!authMetadata.code_challenge_methods_supported?.includes("S256")) {
    throw new Error("Authorization server must support PKCE with S256");
  }

  // Step 5: Dynamic client registration (if supported)
  let clientId;
  if (authMetadata.registration_endpoint) {
    const registration = await fetch(authMetadata.registration_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://localhost:8080/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
      }),
    }).then((r) => r.json());
    clientId = registration.client_id;
  }

  // Step 6: Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomState();

  // Step 7: Construct authorization URL
  const authUrl = new URL(authMetadata.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", "http://localhost:8080/callback");
  authUrl.searchParams.set("resource", mcpServerUrl); // Canonical URI of MCP server
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);

  return {
    authorizationUrl: authUrl.toString(),
    codeVerifier,
    state,
    tokenEndpoint: authMetadata.token_endpoint,
  };
}

async function discoverAuthServerMetadata(issuerUrl) {
  const url = new URL(issuerUrl);
  const basePath = url.pathname === "/" ? "" : url.pathname;

  // Try different discovery endpoints in priority order
  const endpoints = [
    `/.well-known/oauth-authorization-server${basePath}`,
    `/.well-known/openid-configuration${basePath}`,
  ];

  for (const endpoint of endpoints) {
    try {
      const metadataUrl = new URL(endpoint, url.origin);
      const response = await fetch(metadataUrl);
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      continue;
    }
  }

  throw new Error("Could not discover authorization server metadata");
}
```

**Critical Notes:**

- The `.well-known` path **MUST** be at the beginning of the pathname as specified
- PKCE with `S256` is **MANDATORY** - clients must refuse to proceed without it
- The `resource` parameter **MUST** be included in both authorization and token requests
- Dynamic client registration is **RECOMMENDED** but not required
