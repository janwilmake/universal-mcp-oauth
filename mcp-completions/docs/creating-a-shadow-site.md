# Creating a Shadow Site

A "shadow site" is an alternative endpoint that provides better programmatic access to content from sites that aren't easily consumable by LLMs. The `mcp-completions` library supports automatic URL replacement via the `shadowUrls` configuration.

## What is a Shadow Site?

When LLMs need to fetch content from URLs, many sites return HTML, require authentication, or have other barriers. A shadow site provides:

- **Clean text/markdown output** instead of HTML
- **API-friendly responses** with proper content types
- **Optional authentication** that integrates with OAuth flows
- **Structured data** extraction from complex pages

## Built-in Shadow URL Examples

```ts
const { fetchProxy } = chatCompletionsProxy(env, {
  // ... other config
  shadowUrls: {
    "github.com": "uithub.com", // GitHub repos as markdown
    "x.com": "xymake.com", // X/Twitter threads as text
    "twitter.com": "xymake.com",
  },
});
```

When a user message contains `https://github.com/owner/repo`, the URL context fetcher will automatically request `https://uithub.com/owner/repo` instead.

## Creating Your Own Shadow Site

### 1. Basic Requirements

Your shadow site should:

```
GET /{original-path}
Accept: text/markdown, text/plain

Response:
Content-Type: text/markdown (or text/plain)
Body: Extracted content in markdown format
```

### 2. Minimal Implementation

```ts
export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Get the original URL from the path
    const originalUrl = `https://original-site.com${url.pathname}${url.search}`;

    // Fetch and extract content
    const response = await fetch(originalUrl);
    const html = await response.text();

    // Extract meaningful content (use your preferred method)
    const markdown = extractMarkdown(html);

    return new Response(markdown, {
      headers: {
        "Content-Type": "text/markdown",
        "X-Original-URL": originalUrl,
      },
    });
  },
};
```

### 3. Adding OAuth Authentication

If your shadow site needs to access protected resources, implement OAuth 2.0 with the following endpoints:

#### Required OAuth Endpoints

```
/.well-known/oauth-protected-resource
/.well-known/oauth-authorization-server (or openid-configuration)
```

#### Protected Resource Metadata

```json
// GET /.well-known/oauth-protected-resource
{
  "resource": "https://your-shadow-site.com",
  "authorization_servers": ["https://your-auth-server.com"]
}
```

#### Authorization Server Metadata

```json
// GET /.well-known/oauth-authorization-server
{
  "issuer": "https://your-auth-server.com",
  "authorization_endpoint": "https://your-auth-server.com/authorize",
  "token_endpoint": "https://your-auth-server.com/token",
  "registration_endpoint": "https://your-auth-server.com/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["read", "write"]
}
```

#### WWW-Authenticate Header

When returning 401, include proper headers:

```ts
return new Response("Unauthorized", {
  status: 401,
  headers: {
    "WWW-Authenticate":
      'Bearer realm="your-shadow-site.com", ' +
      'resource_metadata="https://your-shadow-site.com/.well-known/oauth-protected-resource", ' +
      'scope="read"',
  },
});
```

### 4. Dynamic Client Registration

Implement the registration endpoint to allow automatic client registration:

```ts
// POST /register
export async function handleRegistration(request: Request) {
  const body = await request.json();

  // Validate required fields
  const { redirect_uris, client_name } = body;

  // Generate client credentials
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();

  // Store client
  await storeClient({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris,
    client_name,
  });

  return Response.json({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris,
    client_name,
  });
}
```

### 5. Complete Shadow Site Example

```ts
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // OAuth metadata endpoints
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return Response.json({
        resource: url.origin,
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
    if (url.pathname === "/register") {
      return handleRegistration(request, env);
    }
    if (url.pathname === "/authorize") {
      return handleAuthorize(request, env);
    }
    if (url.pathname === "/token") {
      return handleToken(request, env);
    }

    // Protected content endpoint
    const auth = request.headers.get("Authorization");
    if (!auth || !(await validateToken(auth, env))) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "WWW-Authenticate": `Bearer realm="${url.hostname}", resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`,
        },
      });
    }

    // Fetch and transform content
    const originalUrl = `https://original-site.com${url.pathname}`;
    const content = await fetchAndExtract(originalUrl, auth);

    return new Response(content, {
      headers: { "Content-Type": "text/markdown" },
    });
  },
};
```

## Using Your Shadow Site

Register your shadow site in the configuration:

```ts
const { fetchProxy } = chatCompletionsProxy(env, {
  baseUrl: "https://your-app.com",
  userId: "user-123",
  clientInfo: { name: "My App", title: "My App", version: "1.0.0" },
  shadowUrls: {
    "original-site.com": "your-shadow-site.com",
  },
});
```

When users paste URLs from `original-site.com`, they'll automatically be fetched from your shadow site with proper authentication.

## Best Practices

1. **Return proper content types**: Always use `text/markdown` or `text/plain`
2. **Include token estimates**: Add `X-Token-Count` header if possible
3. **Handle errors gracefully**: Return meaningful error messages
4. **Support caching**: Add appropriate cache headers
5. **Rate limiting**: Implement rate limits to prevent abuse
6. **Cost tracking**: Return `X-Price` header if there are usage costs