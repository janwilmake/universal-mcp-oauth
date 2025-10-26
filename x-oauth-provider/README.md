# X OAuth Provider

[![](https://badge.forgithub.com/janwilmake/universal-oauth-provider/tree/main/x-oauth-provider/README.md)](https://uithub.com/janwilmake/universal-oauth-provider/tree/main/x-oauth-provider/README.md)

This X OAuth Provider uses the client's domain name as the client_id and automatically derives it from the `redirect_uri` (e.g., `https://example.com/callback` means `client_id` must equal `example.com`), eliminating the need for client registration while maintaining security through domain validation.

**Why**

- X Free or Basic just allows creating a single client
- A single client can have up to just 10 callback URLs, which limits you in how many apps you can create
- To bypass this problem, you can use the `simplerauth-client` to create unlimited X Authed Apps (even without a client)

**Key Features:**

- Makes your worker a oauth provider
- No client registration required - use any domain as client_id
- [MCP compatible Authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization) including dynamic client registraiton fully supported
- Uses [DORM](https://github.com/janwilmake/dorm) to expose admin panel with all users in aggregate (readonly) without compromising on performance (each user gets their own DO as source of truth)
- Users that are already logged in won't be redirected to X Again, even from other clients.

**Run locally**

`wrangler dev --env localhost` (needed in order to have localhost with correct port as hostname)

**3 ways to use it**

1. **Hosted** - Use directly from https://login.wilmake.com
2. **Internal** - Use directly in your cloudflare worker
3. **Central** - Host as a separate worker and use as a central "OAuth Hub" for all your x-oauthed apps

## Simplest Setup: Hosted

The Simple Hosted Setup is explained in the root [readme](../README.md)

## Setup: Internal and Central

1. Installation:

```bash
npm i x-oauth-provider
```

2. Set environment variables:

   - `X_CLIENT_ID`: Your X OAuth app client ID
   - `X_CLIENT_SECRET`: Your X OAuth app client secret
   - `ADMIN_X_USERNAME`: Your X Username that needs access to `/admin`

3. Add Durable Object binding to your `wrangler.toml`:

```toml
[[durable_objects.bindings]]
name = "UserDO"
class_name = "UserDO"

[[migrations]]
new_sqlite_classes = ["UserDO"]
tag = "v1"
```

## Usage Examples

### Simple Enforced Authentication

```typescript path="src/index.ts"
import { UserDO, withSimplerAuth } from "x-oauth-provider";
export { UserDO };

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      return new Response(
        `<html><body>
        <h1>X OAuth Demo</h1>
        <p>Welcome, ${ctx.user.name || ctx.user.username}!</p>
        <img src="${
          ctx.user.profile_image_url || "/default-avatar.png"
        }" alt="Avatar" width="400" height="400" style="border-radius:200px;">
        <p>Username: @${ctx.user.username}</p>
        <p>Verified: ${ctx.user.verified ? "✓" : "✗"}</p>
        <a href="/logout">Logout</a>
      </body></html>`,
        { headers: { "Content-Type": "text/html;charset=utf8" } }
      );
    },
    { isLoginRequired: true }
  ),
};
```

### Step-by-Step Integration

1. **Authorization Request**: Redirect users to your provider's authorize endpoint:

```
https://your-provider.com/authorize?client_id=CLIENT_DOMAIN&redirect_uri=REDIRECT_URI&response_type=code&state=RANDOM_STATE
```

Parameters:

- `client_id`: Your client's domain (e.g., `example.com`)
- `redirect_uri`: Where to redirect after auth (must be HTTPS and on same domain as client_id)
- `response_type`: Must be `code`
- `state`: Random string for CSRF protection

2. **Handle Authorization Callback**: After user authorizes, they'll be redirected to your `redirect_uri` with:

```
https://your-app.com/callback?code=AUTH_CODE&state=YOUR_STATE
```

3. **Exchange Code for Token**: Make a POST request to exchange the authorization code:

```javascript path="token-exchange.js"
const response = await fetch("https://your-provider.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: "AUTH_CODE_FROM_CALLBACK",
    client_id: "your-domain.com",
    redirect_uri: "https://your-domain.com/callback",
  }),
});

const { access_token } = await response.json();
```

4. **Get User Information**: Use the `/me` endpoint to get X user data:

```javascript path="get-user.js"
const userResponse = await fetch("https://your-provider.com/me", {
  headers: { Authorization: `Bearer ${access_token}` },
});

const userData = await userResponse.json();
console.log(userData.data); // X user object with id, name, username, etc.
```

### Available User Data

The `/me` endpoint returns X user information in this format:

```json path="user-response.json"
{
  "data": {
    "id": "123456789",
    "name": "John Doe",
    "username": "johndoe",
    "profile_image_url": "https://pbs.twimg.com/profile_images/.../photo.jpg",
    "verified": false
  }
}
```

## API Routes

Your OAuth provider exposes these endpoints:

- `GET /admin` - Readonly DB Access to admin aggregate DB
- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - OAuth token endpoint
- `GET /callback` - X OAuth callback handler
- `GET /me` - Get authenticated user information
- `GET /logout` - Logout and clear session
- `GET /.well-known/oauth-authorization-server` - OAuth server metadata (MCP required)
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata (MCP required)

## Security Features

- **Domain Validation**: Client domains are validated - `client_id` must be a valid domain
- **HTTPS Enforcement**: Redirect URIs must be HTTPS and on the same domain as `client_id`
- **CSRF Protection**: State parameter validation prevents cross-site request forgery
- **Token Expiration**: Authorization codes expire after 10 minutes
- **Secure Storage**: User data encrypted in Durable Objects
- **PKCE Support**: Proof Key for Code Exchange for enhanced security

## MCP Compliance

This implementation is fully compliant with the Model Context Protocol (MCP) OAuth 2.0 requirements, including:

- RFC 8414 OAuth 2.0 Authorization Server Metadata
- RFC 9728 OAuth 2.0 Protected Resource Metadata
- Proper WWW-Authenticate headers with login URLs
- Bearer token support in Authorization headers
- Resource parameter support for audience validation

## Notes

This provider is designed to be agent-friendly while maintaining security. When authentication is required, it provides multiple indicators for where to login:

```typescript
{
  status: isBrowser ? 302 : 401,
  headers: {
    Location: loginUrl,
    "X-Login-URL": loginUrl,
    "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
  },
}
```

Agents can either attempt automated login or direct users to the login URL for credential retrieval.
