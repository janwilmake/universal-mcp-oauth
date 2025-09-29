# OpenRouter OAuth Provider

A minimal, MCP-compliant OAuth provider that proxies to OpenRouter's OAuth flow to provide API keys with budget control.

## Features

- **MCP Compliant**: Implements all required OAuth endpoints for Model Context Protocol
- **PKCE Security**: Uses Proof Key for Code Exchange for secure authorization
- **Direct Proxy**: Redirects directly to OpenRouter's OAuth flow
- **No Key Storage**: Doesn't store API keys, just facilitates the exchange
- **Budget Control**: Leverages OpenRouter's built-in budget management

## Endpoints

- `/.well-known/oauth-authorization-server` - OAuth server metadata
- `/.well-known/oauth-protected-resource` - Protected resource metadata
- `/register` - Dynamic client registration
- `/authorize` - Authorization endpoint (redirects to OpenRouter)
- `/token` - Token exchange endpoint
- `/me` - User info endpoint for token verification

## Usage

Deploy to Cloudflare Workers at `openrouter.simplerauth.com`:

```bash
npm install
wrangler deploy --env production
```

### Environment Variables

- `SECRET` - Secret key for state encryption
- `KV` - KV namespace binding for temporary state storage

### MCP Integration

Any MCP client can use this provider by setting:

```json
{
  "oauth": {
    "provider": "https://openrouter.simplerauth.com"
  }
}
```

## How It Works

1. **Authorization Request**: Client requests authorization with PKCE
2. **OpenRouter Redirect**: Provider redirects to OpenRouter's OAuth flow
3. **User Authorization**: User authorizes on OpenRouter and sets budget
4. **Code Exchange**: Client exchanges authorization code for API key
5. **Token Validation**: `/me` endpoint validates tokens with OpenRouter

The provider acts as a transparent proxy, ensuring MCP compliance while leveraging OpenRouter's native OAuth implementation.

## Security

- Uses PKCE (Proof Key for Code Exchange) for secure authorization
- Encrypts temporary state data in KV storage
- No long-term storage of API keys or sensitive data
- 10-minute expiration on temporary state storage

## Example Flow

```javascript
// 1. Register client (optional for MCP)
const registration = await fetch(
  "https://openrouter.simplerauth.com/register",
  {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      redirect_uris: ["https://yourapp.com/callback"],
    }),
  }
);

// 2. Generate PKCE and redirect to authorize
const { codeVerifier, codeChallenge } = await generatePKCE();
window.location = `https://openrouter.simplerauth.com/authorize?client_id=yourapp.com&redirect_uri=https://yourapp.com/callback&response_type=code&code_challenge=${codeChallenge}&code_challenge_method=S256`;

// 3. Exchange code for token
const token = await fetch("https://openrouter.simplerauth.com/token", {
  method: "POST",
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    code_verifier: codeVerifier,
    redirect_uri: "https://yourapp.com/callback",
  }),
});

// 4. Use token with OpenRouter API
const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
  headers: { Authorization: `Bearer ${accessToken}` },
  // ... rest of request
});
```
