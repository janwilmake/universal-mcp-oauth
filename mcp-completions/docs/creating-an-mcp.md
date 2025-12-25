# Creating an MCP Server with OAuth

This guide explains how to create an MCP (Model Context Protocol) server that works with the `mcp-completions` library's OAuth flow.

For complete MCP specification and implementation details, see the official documentation at [modelcontextprotocol.io](https://modelcontextprotocol.io).

## MCP Overview

MCP servers expose tools that LLMs can call. The `mcp-completions` library:

1. Discovers available tools from your MCP server
2. Translates them into OpenAI-compatible function calls
3. Executes tool calls against your server
4. Handles OAuth authentication automatically

## Basic MCP Server Structure

### Required Endpoints

Your MCP server needs to handle these JSON-RPC methods over HTTP POST:

```
POST /mcp
Content-Type: application/json

Methods:
- initialize
- notifications/initialized
- tools/list
- tools/call
```

### Minimal Implementation

```ts
export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const body = await request.json();
    const { method, params, id } = body;

    switch (method) {
      case "initialize":
        return Response.json({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: "2025-06-18",
            serverInfo: {
              name: "My MCP Server",
              version: "1.0.0",
            },
            capabilities: {
              tools: {},
            },
          },
        });

      case "notifications/initialized":
        return new Response(null, { status: 204 });

      case "tools/list":
        return Response.json({
          jsonrpc: "2.0",
          id,
          result: {
            tools: [
              {
                name: "get_weather",
                description: "Get current weather for a location",
                inputSchema: {
                  type: "object",
                  properties: {
                    location: {
                      type: "string",
                      description: "City name",
                    },
                  },
                  required: ["location"],
                },
              },
            ],
          },
        });

      case "tools/call":
        const { name, arguments: args } = params;
        const result = await executeTool(name, args);
        return Response.json({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: JSON.stringify(result) }],
          },
        });

      default:
        return Response.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: "Method not found" },
        });
    }
  },
};

async function executeTool(name: string, args: any) {
  if (name === "get_weather") {
    // Your implementation
    return { temperature: 72, condition: "sunny" };
  }
  throw new Error(`Unknown tool: ${name}`);
}
```

## Adding OAuth Authentication

For MCP servers that need user authentication, implement OAuth 2.0 following RFC 9728 (OAuth Protected Resource Metadata).

### 1. OAuth Metadata Endpoints

```ts
// Protected Resource Metadata
// GET /.well-known/oauth-protected-resource
{
  "resource": "https://your-mcp-server.com/mcp",
  "authorization_servers": ["https://your-mcp-server.com"]
}

// Authorization Server Metadata
// GET /.well-known/oauth-authorization-server
{
  "issuer": "https://your-mcp-server.com",
  "authorization_endpoint": "https://your-mcp-server.com/authorize",
  "token_endpoint": "https://your-mcp-server.com/token",
  "registration_endpoint": "https://your-mcp-server.com/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "scopes_supported": ["tools:read", "tools:execute"]
}
```

### 2. Return 401 with WWW-Authenticate

When authentication is required:

```ts
if (!isValidToken(request)) {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate":
        'Bearer realm="your-mcp-server.com/mcp", ' +
        'resource_metadata="https://your-mcp-server.com/.well-known/oauth-protected-resource", ' +
        'scope="tools:read tools:execute"',
    },
  });
}
```

### 3. Dynamic Client Registration

```ts
// POST /register
async function handleRegistration(request: Request, env: Env) {
  const body = await request.json();

  const client = {
    client_id: crypto.randomUUID(),
    client_secret: crypto.randomUUID(),
    redirect_uris: body.redirect_uris,
    client_name: body.client_name,
    grant_types: body.grant_types || ["authorization_code"],
    response_types: body.response_types || ["code"],
  };

  await env.CLIENTS.put(client.client_id, JSON.stringify(client));

  return Response.json(client);
}
```

### 4. Authorization Endpoint

```ts
// GET /authorize
async function handleAuthorize(request: Request, env: Env) {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const codeChallenge = url.searchParams.get("code_challenge");
  const scope = url.searchParams.get("scope");

  // Validate client
  const client = await env.CLIENTS.get(clientId);
  if (!client) {
    return new Response("Invalid client", { status: 400 });
  }

  // Show login/consent page or redirect to your auth provider
  // After user authenticates, generate authorization code:

  const code = crypto.randomUUID();
  await env.AUTH_CODES.put(
    code,
    JSON.stringify({
      clientId,
      redirectUri,
      codeChallenge,
      scope,
      userId: authenticatedUser.id,
    }),
    { expirationTtl: 600 },
  );

  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", code);
  redirectUrl.searchParams.set("state", state);

  return Response.redirect(redirectUrl.toString());
}
```

### 5. Token Endpoint

```ts
// POST /token
async function handleToken(request: Request, env: Env) {
  const body = new URLSearchParams(await request.text());
  const grantType = body.get("grant_type");

  if (grantType === "authorization_code") {
    const code = body.get("code");
    const codeVerifier = body.get("code_verifier");
    const clientId = body.get("client_id");

    // Validate code and PKCE
    const authCode = JSON.parse(await env.AUTH_CODES.get(code));
    if (!authCode || authCode.clientId !== clientId) {
      return Response.json({ error: "invalid_grant" }, { status: 400 });
    }

    // Verify PKCE code_verifier
    const challenge = await generateCodeChallenge(codeVerifier);
    if (challenge !== authCode.codeChallenge) {
      return Response.json({ error: "invalid_grant" }, { status: 400 });
    }

    // Generate tokens
    const accessToken = await generateJWT(authCode.userId, authCode.scope, env);
    const refreshToken = crypto.randomUUID();

    await env.REFRESH_TOKENS.put(
      refreshToken,
      JSON.stringify({
        userId: authCode.userId,
        clientId,
        scope: authCode.scope,
      }),
    );

    await env.AUTH_CODES.delete(code);

    return Response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: authCode.scope,
    });
  }

  if (grantType === "refresh_token") {
    const refreshToken = body.get("refresh_token");
    const tokenData = JSON.parse(await env.REFRESH_TOKENS.get(refreshToken));

    if (!tokenData) {
      return Response.json({ error: "invalid_grant" }, { status: 400 });
    }

    const accessToken = await generateJWT(
      tokenData.userId,
      tokenData.scope,
      env,
    );

    return Response.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
  }

  return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
}
```

## Complete MCP Server with OAuth

```ts
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // OAuth metadata
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return Response.json({
        resource: `${url.origin}/mcp`,
        authorization_servers: [url.origin],
      });
    }

    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer: url.origin,
        authorization_endpoint: `${url.origin}/authorize`,
        token_endpoint: `${url.origin}/token`,
        registration_endpoint: `${url.origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
      });
    }

    // OAuth endpoints
    if (url.pathname === "/register") return handleRegistration(request, env);
    if (url.pathname === "/authorize") return handleAuthorize(request, env);
    if (url.pathname === "/token") return handleToken(request, env);

    // MCP endpoint
    if (url.pathname === "/mcp") {
      // Validate authentication
      const auth = request.headers.get("Authorization");
      const user = await validateToken(auth, env);

      if (!user) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer realm="${url.hostname}/mcp", resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`,
          },
        });
      }

      // Handle MCP request
      return handleMCP(request, user, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

async function handleMCP(request: Request, user: User, env: Env) {
  const body = await request.json();
  const { method, params, id } = body;

  const sessionId = request.headers.get("Mcp-Session-Id");

  const headers = new Headers({
    "Content-Type": "application/json",
  });

  // Generate session ID on initialize
  if (method === "initialize") {
    const newSessionId = crypto.randomUUID();
    headers.set("Mcp-Session-Id", newSessionId);

    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-06-18",
          serverInfo: { name: "My MCP Server", version: "1.0.0" },
          capabilities: { tools: {} },
        },
      }),
      { headers },
    );
  }

  // ... rest of MCP handling
}
```

## Using Your MCP Server

Once deployed, use it with `mcp-completions`:

```ts
const stream = await client.chat.completions.create({
  model: "gpt-4o",
  stream: true,
  messages: [{ role: "user", content: "What's the weather in London?" }],
  tools: [
    {
      type: "mcp",
      server_url: "https://your-mcp-server.com/mcp",
      require_approval: "never",
    },
  ],
});
```

The library will:

1. Check if user is authenticated
2. If not, return a login link in the stream
3. Once authenticated, discover and execute tools automatically

## Session Management

MCP supports stateful sessions via the `Mcp-Session-Id` header:

```ts
// Server generates session ID on initialize
response.headers.set("Mcp-Session-Id", sessionId);

// Client sends it on subsequent requests
request.headers.get("Mcp-Session-Id");

// Return 404 if session expired
if (!validSession) {
  return new Response("Session expired", { status: 404 });
}
```

## SSE Streaming Responses

For long-running tools, return Server-Sent Events:

```ts
if (method === "tools/call" && isLongRunning(params.name)) {
  const stream = new ReadableStream({
    async start(controller) {
      const encoder = new TextEncoder();

      // Send progress updates
      controller.enqueue(
        encoder.encode(
          `data: ${JSON.stringify({
            jsonrpc: "2.0",
            method: "notifications/progress",
            params: { progress: 50 },
          })}\n\n`,
        ),
      );

      // Send final result
      const result = await executeTool(params.name, params.arguments);
      controller.enqueue(
        encoder.encode(
          `data: ${JSON.stringify({
            jsonrpc: "2.0",
            id,
            result: { content: [{ type: "text", text: result }] },
          })}\n\n`,
        ),
      );

      controller.close();
    },
  });

  return new Response(stream, {
    headers: { "Content-Type": "text/event-stream" },
  });
}
```

## Further Reading

- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/html/rfc9728)
- [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414)
- [Proof Key for Code Exchange (RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636)