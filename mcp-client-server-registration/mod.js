/**
 * Generates a random code verifier for PKCE
 * @returns {string} Base64url-encoded code verifier
 */
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Generates a code challenge from a code verifier using SHA256
 * @param {string} codeVerifier - The code verifier string
 * @returns {Promise<string>} Base64url-encoded SHA256 hash of the code verifier
 */
async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Generates a random state parameter for OAuth2 security
 * @returns {string} Random state string
 */
function generateRandomState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Constructs an OAuth2 authorization URL for an MCP server following the MCP authorization specification.
 * This is a stateless function that performs all necessary discovery steps and returns
 * everything needed for the authorization flow.
 *
 * @param {string} mcpUrl - The URL of the MCP server to authorize against
 * @param {string} callbackUrl - The redirect URI for the OAuth2 callback
 * @returns {Promise<{
 *   authorizationUrl: string,
 *   codeVerifier: string,
 *   state: string,
 *   tokenEndpoint: string,
 *   clientId: string,
 *   clientSecret?: string,
 *   registrationResponse?: object,
 *   mcpServerUrl: string,
 *   authServerMetadata: object
 * }>} Authorization flow data needed for token exchange
 * @throws {Error} When authorization server doesn't support required features or discovery fails
 */
export async function constructMCPAuthorizationUrl(mcpUrl, callbackUrl) {
  // Step 1: Initial MCP request to trigger 401 or discover resource metadata
  let resourceMetadataUrl;

  try {
    // Try MCP initialize request first
    const initResponse = await fetch(mcpUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json,text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {
            roots: {
              listChanged: true,
            },
            sampling: {},
          },
          clientInfo: {
            name: "mcp-auth-client",
            title: "MCP Authorization Client",
            version: "1.0.0",
          },
        },
      }),
    });

    if (initResponse.status === 401) {
      // Extract resource metadata URL from WWW-Authenticate header
      const wwwAuth = initResponse.headers.get("WWW-Authenticate");
      if (wwwAuth) {
        const match = wwwAuth.match(/resource="([^"]+)"/);
        if (match) {
          resourceMetadataUrl = match[1];
        }
      }
    }
  } catch (error) {
    // Continue with fallback approach
  }

  // Step 2: Get protected resource metadata
  if (!resourceMetadataUrl) {
    // Fallback: use MCP server hostname as base for .well-known discovery
    const mcpUrlObj = new URL(mcpUrl);
    resourceMetadataUrl = new URL(
      "/.well-known/oauth-protected-resource",
      `${mcpUrlObj.protocol}//${mcpUrlObj.host}`
    ).toString();
  }

  let resourceMetadata;
  try {
    const resourceResponse = await fetch(resourceMetadataUrl);
    if (!resourceResponse.ok) {
      throw new Error(
        `Failed to fetch resource metadata: ${resourceResponse.status}`
      );
    }
    resourceMetadata = await resourceResponse.json();
  } catch (error) {
    throw new Error(
      `Could not discover protected resource metadata: ${error.message}`
    );
  }

  if (
    !resourceMetadata.authorization_servers ||
    !Array.isArray(resourceMetadata.authorization_servers) ||
    resourceMetadata.authorization_servers.length === 0
  ) {
    throw new Error("No authorization servers found in resource metadata");
  }

  // Step 3: Select first authorization server and discover metadata
  const authServerUrl = resourceMetadata.authorization_servers[0];
  const authMetadata = await discoverAuthServerMetadata(authServerUrl);

  // Step 4: Verify PKCE support (mandatory)
  if (
    !authMetadata.code_challenge_methods_supported ||
    !authMetadata.code_challenge_methods_supported.includes("S256")
  ) {
    throw new Error("Authorization server must support PKCE with S256");
  }

  if (!authMetadata.authorization_endpoint || !authMetadata.token_endpoint) {
    throw new Error("Authorization server metadata missing required endpoints");
  }

  // Step 5: Dynamic client registration (if supported)
  let clientId, clientSecret, registrationResponse;

  if (authMetadata.registration_endpoint) {
    try {
      const registrationRequest = {
        redirect_uris: [callbackUrl],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "MCP Authorization Client",
        application_type: "native",
      };

      const regResponse = await fetch(authMetadata.registration_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(registrationRequest),
      });

      if (!regResponse.ok) {
        throw new Error(`Client registration failed: ${regResponse.status}`);
      }

      registrationResponse = await regResponse.json();
      clientId = registrationResponse.client_id;
      clientSecret = registrationResponse.client_secret;
    } catch (error) {
      throw new Error(`Dynamic client registration failed: ${error.message}`);
    }
  } else {
    throw new Error(
      "Authorization server does not support dynamic client registration"
    );
  }

  // Step 6: Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomState();

  // Step 7: Construct authorization URL
  const authUrl = new URL(authMetadata.authorization_endpoint);
  const params = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: callbackUrl,
    resource: mcpUrl, // Canonical URI of MCP server
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: state,
  };

  Object.entries(params).forEach(([key, value]) => {
    authUrl.searchParams.set(key, value);
  });

  return {
    authorizationUrl: authUrl.toString(),
    codeVerifier,
    state,
    tokenEndpoint: authMetadata.token_endpoint,
    clientId,
    clientSecret,
    registrationResponse,
    mcpServerUrl: mcpUrl,
    authServerMetadata: authMetadata,
  };
}

/**
 * Discovers authorization server metadata using standard OAuth2/OIDC discovery endpoints
 * @param {string} issuerUrl - The authorization server issuer URL
 * @returns {Promise<object>} Authorization server metadata
 * @throws {Error} When metadata discovery fails
 */
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

  throw new Error(
    `Could not discover authorization server metadata for ${issuerUrl}`
  );
}
