/**
 * OAuth2 authorization flow data needed for token exchange
 */
export interface AuthorizationFlowData {
  authorizationUrl?: string;
  codeVerifier?: string;
  state?: string;
  tokenEndpoint?: string;
  clientId?: string;
  clientSecret?: string;
  registrationResponse?: Record<string, unknown>;
  mcpServerUrl: string;
  authServerMetadata?: AuthServerMetadata;
  noAuthRequired?: boolean;
  accessToken?: string;
}

/**
 * Client information for MCP authorization
 */
export interface ClientInfo {
  name: string;
  title: string;
  version: string;
}

/**
 * Authorization server metadata
 */
export interface AuthServerMetadata {
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  code_challenge_methods_supported?: string[];
  [key: string]: unknown;
}

/**
 * MCP server information
 */
export interface MCPServerInfo {
  serverName: string;
  tools: unknown[];
}

/**
 * Protected resource metadata
 */
interface ProtectedResourceMetadata {
  authorization_servers?: string[];
  [key: string]: unknown;
}

/**
 * Client registration request
 */
interface ClientRegistrationRequest {
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  client_name: string;
  application_type: string;
}

/**
 * Client registration response
 */
interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  [key: string]: unknown;
}

/**
 * MCP initialize request params
 */
interface InitializeParams {
  protocolVersion: string;
  capabilities: {
    roots: { listChanged: boolean };
    sampling: Record<string, unknown>;
  };
  clientInfo: ClientInfo;
}

/**
 * MCP JSON-RPC request
 */
interface JSONRPCRequest {
  jsonrpc: string;
  id?: number;
  method: string;
  params: Record<string, unknown>;
}

/**
 * MCP JSON-RPC response
 */
interface JSONRPCResponse {
  result?: {
    serverInfo?: { name: string };
    tools?: unknown[];
    [key: string]: unknown;
  };
  error?: {
    code: number;
    message: string;
  };
}

/**
 * Generates a random code verifier for PKCE
 * @returns Base64url-encoded code verifier
 */
function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Generates a code challenge from a code verifier using SHA256
 * @param codeVerifier - The code verifier string
 * @returns Base64url-encoded SHA256 hash of the code verifier
 */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Generates a random state parameter for OAuth2 security
 * @returns Random state string
 */
function generateRandomState(): string {
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
 * @param mcpUrl - The URL of the MCP server to authorize against
 * @param callbackUrl - The redirect URI for the OAuth2 callback
 * @param clientInfo - Client information
 * @returns Authorization flow data needed for token exchange, or immediate access if no auth required
 * @throws When authorization server doesn't support required features or discovery fails
 */
export async function constructMCPAuthorizationUrl(
  mcpUrl: string,
  callbackUrl: string,
  clientInfo: ClientInfo,
): Promise<AuthorizationFlowData> {
  // Step 1: Initial MCP request to check if auth is required
  let resourceMetadataUrl: string | undefined;
  let noAuthRequired = false;
  let accessToken: string | null = null;

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
          clientInfo,
        } as InitializeParams,
      } as JSONRPCRequest),
    });

    if (initResponse.status === 200) {
      // No authentication required - MCP server is public
      noAuthRequired = true;

      return {
        mcpServerUrl: mcpUrl,
        noAuthRequired: true,
        accessToken: null, // Public servers don't need tokens
      };
    } else if (initResponse.status === 401) {
      // Extract resource metadata URL from WWW-Authenticate header
      const wwwAuth = initResponse.headers.get("WWW-Authenticate");
      if (wwwAuth) {
        const match = wwwAuth.match(/resource_metadata="([^"]+)"/);
        if (match) {
          resourceMetadataUrl = match[1];
        }
      }
    } else {
      throw new Error(`Unexpected response status: ${initResponse.status}`);
    }
  } catch (error) {
    // Continue with fallback approach for auth discovery
  }

  // Step 2: Discover authorization servers
  let authorizationServers: string[] = [];

  // Try to get protected resource metadata first (if we have a resourceMetadataUrl)
  if (resourceMetadataUrl) {
    try {
      const resourceResponse = await fetch(resourceMetadataUrl);
      if (resourceResponse.ok) {
        const resourceMetadata =
          (await resourceResponse.json()) as ProtectedResourceMetadata;
        if (
          resourceMetadata.authorization_servers &&
          Array.isArray(resourceMetadata.authorization_servers) &&
          resourceMetadata.authorization_servers.length > 0
        ) {
          authorizationServers = resourceMetadata.authorization_servers;
        }
      }
    } catch (error) {
      // Continue to fallback methods
    }
  }

  // Fallback 1: Try .well-known/oauth-protected-resource on MCP server host (SEP-985)
  if (authorizationServers.length === 0) {
    try {
      const mcpUrlObj = new URL(mcpUrl);
      const fallbackResourceUrl = new URL(
        "/.well-known/oauth-protected-resource",
        `${mcpUrlObj.protocol}//${mcpUrlObj.host}`,
      ).toString();

      const resourceResponse = await fetch(fallbackResourceUrl);
      if (resourceResponse.ok) {
        const resourceMetadata =
          (await resourceResponse.json()) as ProtectedResourceMetadata;
        if (
          resourceMetadata.authorization_servers &&
          Array.isArray(resourceMetadata.authorization_servers) &&
          resourceMetadata.authorization_servers.length > 0
        ) {
          authorizationServers = resourceMetadata.authorization_servers;
        }
      }
    } catch (error) {
      // Continue to next fallback
    }
  }

  // Fallback 2: Assume authorization server is on same host as MCP server
  if (authorizationServers.length === 0) {
    const mcpUrlObj = new URL(mcpUrl);
    const assumedAuthServer = `${mcpUrlObj.protocol}//${mcpUrlObj.host}`;
    authorizationServers = [assumedAuthServer];
  }

  // Step 3: Try each authorization server until we find one that works
  let authMetadata: AuthServerMetadata | undefined;
  let selectedAuthServer: string | undefined;
  const discoveryErrors: string[] = [];

  for (const authServerUrl of authorizationServers) {
    try {
      authMetadata = await discoverAuthServerMetadata(authServerUrl);
      selectedAuthServer = authServerUrl;
      break;
    } catch (error) {
      discoveryErrors.push(`${authServerUrl}: ${(error as Error).message}`);
      continue;
    }
  }

  if (!authMetadata || !selectedAuthServer) {
    throw new Error(
      `Could not discover authorization server metadata. Tried: ${discoveryErrors.join(
        ", ",
      )}`,
    );
  }

  // Step 4: Verify PKCE support (mandatory per draft spec)
  if (
    !authMetadata.code_challenge_methods_supported ||
    !authMetadata.code_challenge_methods_supported.includes("S256")
  ) {
    throw new Error(
      "Authorization server must support PKCE with S256 - this is mandatory per MCP specification",
    );
  }

  if (!authMetadata.authorization_endpoint || !authMetadata.token_endpoint) {
    throw new Error("Authorization server metadata missing required endpoints");
  }

  // Step 5: Dynamic client registration (if supported)
  let clientId: string;
  let clientSecret: string | undefined;
  let registrationResponse: ClientRegistrationResponse | undefined;

  if (authMetadata.registration_endpoint) {
    try {
      const registrationRequest: ClientRegistrationRequest = {
        redirect_uris: [callbackUrl],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: clientInfo.name,
        application_type: "native",
      };

      const regResponse = await fetch(authMetadata.registration_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(registrationRequest),
      });

      if (!regResponse.ok) {
        const errorText = await regResponse.text().catch(() => "Unknown error");
        throw new Error(
          `Client registration failed: ${regResponse.status} - ${errorText}`,
        );
      }

      registrationResponse =
        (await regResponse.json()) as ClientRegistrationResponse;
      clientId = registrationResponse.client_id;
      clientSecret = registrationResponse.client_secret;
    } catch (error) {
      throw new Error(
        `Dynamic client registration failed: ${(error as Error).message}`,
      );
    }
  } else {
    throw new Error(
      "Authorization server does not support dynamic client registration",
    );
  }

  // Step 6: Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomState();

  // Step 7: Construct authorization URL
  const authUrl = new URL(authMetadata.authorization_endpoint);
  const params: Record<string, string> = {
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
    noAuthRequired: false,
  };
}

/**
 * Discovers authorization server metadata using enhanced discovery mechanism from draft spec
 * @param issuerUrl - The authorization server issuer URL
 * @returns Authorization server metadata
 * @throws When metadata discovery fails
 */
async function discoverAuthServerMetadata(
  issuerUrl: string,
): Promise<AuthServerMetadata> {
  const url = new URL(issuerUrl);
  const basePath = url.pathname === "/" ? "" : url.pathname;

  // Enhanced discovery endpoints per draft spec
  const endpoints: string[] = [];

  // For issuer URLs with path components
  if (basePath && basePath !== "") {
    endpoints.push(
      `/.well-known/oauth-authorization-server${basePath}`, // OAuth 2.0 with path insertion
      `/.well-known/openid-configuration${basePath}`, // OpenID Connect with path insertion
      `${basePath}/.well-known/openid-configuration`, // OpenID Connect path appending
    );
  }

  // Standard endpoints (for URLs without path or as fallbacks)
  endpoints.push(
    `/.well-known/oauth-authorization-server`, // OAuth 2.0 standard
    `/.well-known/openid-configuration`, // OpenID Connect standard
  );

  const discoveryErrors: string[] = [];

  for (const endpoint of endpoints) {
    try {
      const metadataUrl = new URL(endpoint, url.origin);
      const response = await fetch(metadataUrl);
      if (response.ok) {
        const metadata = (await response.json()) as AuthServerMetadata;

        // Basic validation of required fields
        if (metadata.authorization_endpoint && metadata.token_endpoint) {
          // Enhanced PKCE verification per draft spec
          if (!metadata.code_challenge_methods_supported) {
            discoveryErrors.push(
              `${endpoint}: Missing code_challenge_methods_supported`,
            );
            continue;
          }

          if (!metadata.code_challenge_methods_supported.includes("S256")) {
            discoveryErrors.push(
              `${endpoint}: S256 not supported in code_challenge_methods_supported`,
            );
            continue;
          }

          return metadata;
        }

        discoveryErrors.push(`${endpoint}: Missing required endpoints`);
      } else {
        discoveryErrors.push(`${endpoint}: ${response.status}`);
      }
    } catch (error) {
      discoveryErrors.push(`${endpoint}: ${(error as Error).message}`);
      continue;
    }
  }

  throw new Error(
    `Could not discover authorization server metadata for ${issuerUrl}. Tried: ${discoveryErrors.join(
      ", ",
    )}`,
  );
}

/**
 * Extracts server information and tools from an MCP server
 * @param clientInfo - Client information
 * @param mcpUrl - The MCP server URL
 * @param accessToken - Optional access token for authenticated requests
 * @returns Server name and available tools
 * @throws When server request fails or server name cannot be extracted
 */
export async function extractMCPServerInfo(
  clientInfo: ClientInfo,
  mcpUrl: string,
  accessToken?: string,
): Promise<MCPServerInfo> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json,text/event-stream",
    "MCP-Protocol-Version": "2025-06-18", // Add protocol version header
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  // First, initialize the connection
  const initResponse = await fetch(mcpUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {
          roots: { listChanged: true },
          sampling: {},
        },
        clientInfo,
      } as InitializeParams,
    }),
  });

  if (!initResponse.ok) {
    const errorText = await initResponse.text();
    throw new Error(
      `MCP server request to ${mcpUrl} failed (access token: ${
        accessToken || "None"
      }): ${initResponse.status} - ${errorText}`,
    );
  }

  // Extract session ID from the initialization response
  const sessionId = initResponse.headers.get("Mcp-Session-Id");

  const contentType = initResponse.headers.get("content-type") || "";
  let serverName: string;

  if (contentType.includes("text/event-stream")) {
    const initResult = await parseSSEResponse(initResponse);
    if (!initResult.result?.serverInfo?.name) {
      throw new Error("Could not extract server name from SSE response");
    }
    serverName = initResult.result.serverInfo.name;
  } else {
    const initData = (await initResponse.json()) as JSONRPCResponse;
    if (!initData.result?.serverInfo?.name) {
      throw new Error("Could not extract server name from JSON response");
    }
    serverName = initData.result.serverInfo.name;
  }

  // Send initialized notification with session ID if provided
  if (sessionId) {
    const initializedHeaders = { ...headers };
    initializedHeaders["Mcp-Session-Id"] = sessionId;

    await fetch(mcpUrl, {
      method: "POST",
      headers: initializedHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialized",
        params: {},
      } as JSONRPCRequest),
    });
  }

  // Now get the tools list with session ID
  const toolsHeaders = { ...headers };
  if (sessionId) {
    toolsHeaders["Mcp-Session-Id"] = sessionId;
  }

  const toolsResponse = await fetch(mcpUrl, {
    method: "POST",
    headers: toolsHeaders,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    } as JSONRPCRequest),
  });

  let tools: unknown[] = [];

  if (!toolsResponse.ok) {
    const errorText = await toolsResponse.text();
    console.error("Tools response not ok", toolsResponse.status, errorText);
  }

  if (toolsResponse.ok) {
    const toolsContentType = toolsResponse.headers.get("content-type") || "";

    if (toolsContentType.includes("text/event-stream")) {
      try {
        const toolsResult = await parseSSEResponse(toolsResponse);
        if (
          toolsResult.result?.tools &&
          Array.isArray(toolsResult.result.tools)
        ) {
          tools = toolsResult.result.tools;
        }
      } catch (e) {
        // Tools list failed, but that's OK - continue without tools
      }
    } else {
      try {
        const toolsData = (await toolsResponse.json()) as JSONRPCResponse;
        if (toolsData.result?.tools && Array.isArray(toolsData.result.tools)) {
          tools = toolsData.result.tools;
        }
      } catch (e) {
        // Tools list failed, but that's OK - continue without tools
      }
    }
  }

  return { serverName, tools };
}

/**
 * Parses Server-Sent Events (SSE) response from MCP server
 * @param response - The fetch Response object with SSE content
 * @returns Parsed JSON data from the SSE stream
 * @throws When response body is unavailable or parsing fails
 */
async function parseSSEResponse(response: Response): Promise<JSONRPCResponse> {
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("No response body");
  }

  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");

      // Keep the last incomplete line in the buffer
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("event: message")) {
          // Look for the next data line
          continue;
        }
        if (line.startsWith("data: ")) {
          const jsonStr = line.substring(6);
          try {
            const data = JSON.parse(jsonStr) as JSONRPCResponse;
            if (data.result) {
              return data;
            }
          } catch (e) {
            continue;
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  throw new Error("Could not parse SSE response");
}
