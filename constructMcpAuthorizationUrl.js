/**
 * Constructs an OAuth 2.0 authorization URL for MCP server access using dynamic client registration
 *
 * @param {string} mcpServerUrl - The canonical URI of the MCP server to authorize access to
 * @param {string} callbackUrl - The redirect URI where the authorization code will be sent
 * @returns {Promise<{authorizationUrl: string, registrationResponse: Object, codeVerifier: string, state: string, tokenEndpoint: string}>}
 *   Authorization URL, registration response, PKCE code verifier, state parameter, and token endpoint
 * @throws {Error} If the authorization flow cannot be established or server doesn't support required features
 *
 * @example
 * const result = await constructMcpAuthorizationUrl(
 *   'https://api.example.com/mcp',
 *   'http://localhost:8080/callback'
 * );
 * console.log('Visit:', result.authorizationUrl);
 * // Store result.codeVerifier and result.state for token exchange
 */
async function constructMcpAuthorizationUrl(mcpServerUrl, callbackUrl) {
  // Step 1: Discover protected resource metadata
  const resourceMetadataUrl = new URL(
    "/.well-known/oauth-protected-resource",
    mcpServerUrl
  );
  const resourceResponse = await fetch(resourceMetadataUrl);

  if (!resourceResponse.ok) {
    throw new Error(
      `Failed to fetch resource metadata: ${resourceResponse.status} ${resourceResponse.statusText}`
    );
  }

  const resourceMetadata = await resourceResponse.json();

  if (
    !resourceMetadata.authorization_servers ||
    !Array.isArray(resourceMetadata.authorization_servers) ||
    resourceMetadata.authorization_servers.length === 0
  ) {
    throw new Error("No authorization servers found in resource metadata");
  }

  // Step 2: Select first authorization server and discover its metadata
  const authServerUrl = resourceMetadata.authorization_servers[0];
  const authMetadata = await discoverAuthServerMetadata(authServerUrl);

  // Step 3: Verify PKCE support (mandatory)
  if (!authMetadata.code_challenge_methods_supported?.includes("S256")) {
    throw new Error("Authorization server must support PKCE with S256 method");
  }

  if (!authMetadata.authorization_endpoint || !authMetadata.token_endpoint) {
    throw new Error("Authorization server metadata missing required endpoints");
  }

  // Step 4: Dynamic client registration (if supported)
  let registrationResponse = null;
  let clientId = null;

  if (authMetadata.registration_endpoint) {
    const registrationRequest = {
      redirect_uris: [callbackUrl],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none", // PKCE public client
    };

    const regResponse = await fetch(authMetadata.registration_endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(registrationRequest),
    });

    if (!regResponse.ok) {
      throw new Error(
        `Dynamic client registration failed: ${regResponse.status} ${regResponse.statusText}`
      );
    }

    registrationResponse = await regResponse.json();
    clientId = registrationResponse.client_id;

    if (!clientId) {
      throw new Error("Registration response missing client_id");
    }
  } else {
    throw new Error(
      "Dynamic client registration not supported - client_id required but no registration endpoint available"
    );
  }

  // Step 5: Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomState();

  // Step 6: Construct authorization URL
  const authUrl = new URL(authMetadata.authorization_endpoint);
  const params = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: callbackUrl,
    resource: mcpServerUrl, // Canonical URI of MCP server
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: state,
  };

  Object.entries(params).forEach(([key, value]) => {
    authUrl.searchParams.set(key, value);
  });

  return {
    authorizationUrl: authUrl.toString(),
    registrationResponse,
    codeVerifier,
    state,
    tokenEndpoint: authMetadata.token_endpoint,
  };
}

/**
 * Discovers OAuth 2.0 authorization server metadata using standard discovery endpoints
 *
 * @private
 * @param {string} issuerUrl - The authorization server issuer URL
 * @returns {Promise<Object>} Authorization server metadata
 * @throws {Error} If metadata cannot be discovered
 */
async function discoverAuthServerMetadata(issuerUrl) {
  const url = new URL(issuerUrl);
  const basePath = url.pathname === "/" ? "" : url.pathname;

  // Try discovery endpoints in priority order per RFC 8414
  const endpoints = [
    `/.well-known/oauth-authorization-server${basePath}`,
    `/.well-known/openid-configuration${basePath}`,
  ];

  for (const endpoint of endpoints) {
    try {
      const metadataUrl = new URL(endpoint, url.origin);
      const response = await fetch(metadataUrl, {
        headers: { Accept: "application/json" },
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      // Continue to next endpoint
      continue;
    }
  }

  throw new Error(
    `Could not discover authorization server metadata for ${issuerUrl}`
  );
}

/**
 * Generates a cryptographically random code verifier for PKCE
 *
 * @private
 * @returns {string} Base64url-encoded code verifier
 */
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Generates a code challenge from a code verifier using SHA256
 *
 * @private
 * @param {string} codeVerifier - The code verifier
 * @returns {Promise<string>} Base64url-encoded code challenge
 */
async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(new Uint8Array(digest));
}

/**
 * Generates a cryptographically random state parameter
 *
 * @private
 * @returns {string} Random state string
 */
function generateRandomState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Encodes bytes as base64url (RFC 4648 Section 5)
 *
 * @private
 * @param {Uint8Array} bytes - Bytes to encode
 * @returns {string} Base64url-encoded string
 */
function base64urlEncode(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
