This minimal OAuth provider:

1. **Stateless except for temporary KV storage** - Only stores the API key for 10 minutes in KV during the auth flow
2. **Uses cookie for repeat visits** - Saves the API key in a cookie for convenience on repeat visits
3. **Simple flow**:
   - `/authorize` shows a clean form asking for API key
   - User enters API key, it gets stored in KV with a temporary auth code
   - `/token` exchanges the auth code for the API key and deletes it from KV
4. **Proper OAuth compliance** - Includes all the required metadata endpoints

To use it on any server:

```
npm i parallel-oauth-provider
```

```js
import { parallelOauthProvider } from "parallel-oauth-provider";

export default {
  async fetch(request, env) {
    const oauthResponse = await parallelOauthProvider(
      request,
      // Must have {get,put,delete}
      env.KV,
      // Encryption Secret
      env.SECRET,
      // Optional config
      { pathPrefix: "/oauth", assetsPrefix: "/assets/oauth" }
    );
    if (oauthResponse) return oauthResponse;

    // Your other routes...
  },
};
```

It has been abstracted away fully from Cloudflare and can be used in any cloud provider that allows JavaScript. It uses the KV API equal to that of Cloudflare KV.

See [demo](demo.ts) in combination with [index.html](index.html)

The user just needs to get their API key from the Parallel dashboard and enter it once - it'll be remembered in a cookie for future use.

# How to test if this works

- in this folder, run `wrangler dev --env dev` (spawns localhost:3000)
- in `task-mcp`, run `wrangler dev --env dev` (spawns localhost:8787)
- Run `npx @modelcontextprotocol/inspector` and test `http://localhost:8787/mcp`. The oauth flow should work.

# How to create a client using Parallel.ai OAuth Provider

A simple OAuth 2.0 provider that lets users share their Parallel.ai API keys with trusted applications.

## 🔗 Provider URL

**https://oauth.parallel.ai**

## 🚀 Quick Start

### 1. Discover OAuth Endpoints

```bash
curl https://oauth.parallel.ai/.well-known/oauth-authorization-server
```

### 2. Register Your Client (Dynamic Registration)

```javascript
const response = await fetch("https://oauth.parallel.ai/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    redirect_uris: ["https://yourapp.com/callback"],
  }),
});

const { client_id } = await response.json();
// client_id will be your hostname (e.g., "yourapp.com")
```

### 3. Start Authorization Flow

```javascript
// Generate PKCE parameters
function generatePKCE() {
  const codeVerifier = btoa(crypto.getRandomValues(new Uint8Array(32))).replace(
    /[+/=]/g,
    (m) => ({ "+": "-", "/": "_", "=": "" }[m])
  );

  return crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(codeVerifier))
    .then((hash) => ({
      codeVerifier,
      codeChallenge: btoa(String.fromCharCode(...new Uint8Array(hash))).replace(
        /[+/=]/g,
        (m) => ({ "+": "-", "/": "_", "=": "" }[m])
      ),
    }));
}

// Redirect user to authorization
const { codeVerifier, codeChallenge } = await generatePKCE();
localStorage.setItem("code_verifier", codeVerifier);

const authUrl = new URL("https://oauth.parallel.ai/authorize");
authUrl.searchParams.set("client_id", "yourapp.com");
authUrl.searchParams.set("redirect_uri", "https://yourapp.com/callback");
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("scope", "api");
authUrl.searchParams.set("code_challenge", codeChallenge);
authUrl.searchParams.set("code_challenge_method", "S256");
authUrl.searchParams.set("state", "random-state-value");

window.location.href = authUrl.toString();
```

### 4. Handle Callback & Exchange Code

```javascript
// On your callback page
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get("code");
const codeVerifier = localStorage.getItem("code_verifier");

const response = await fetch("https://oauth.parallel.ai/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    client_id: "yourapp.com",
    redirect_uri: "https://yourapp.com/callback",
    code_verifier: codeVerifier,
  }),
});

const { access_token } = await response.json();
// access_token is the user's Parallel.ai API key
```

### 5. Use the API Key

```javascript
const response = await fetch("https://api.parallel.ai/v1/chat/completions", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${access_token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello!" }],
  }),
});
```

## 📝 Key Points

- **Public Client**: No client secret needed
- **PKCE Required**: Code challenge/verifier mandatory for security
- **Dynamic Registration**: Use your hostname as `client_id`
- **Secure**: Users manually enter their API key on oauth.parallel.ai
- **Simple**: The `access_token` IS the Parallel.ai API key

## 🎯 Working Demo

See the full implementation at: **https://oauth.parallel.ai**

```html path="demo.html"
<!DOCTYPE html>
<html>
  <head>
    <title>OAuth Demo</title>
  </head>
  <body>
    <button onclick="startOAuth()">Login with Parallel.ai</button>
    <script>
      async function startOAuth() {
        // Register client
        const reg = await fetch("https://oauth.parallel.ai/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ redirect_uris: [location.origin + "/"] }),
        });
        const { client_id } = await reg.json();

        // Generate PKCE
        const cv = btoa(crypto.getRandomValues(new Uint8Array(32))).replace(
          /[+/=]/g,
          (m) => ({ "+": "-", "/": "_", "=": "" }[m])
        );
        localStorage.setItem("cv", cv);
        const cc = btoa(
          String.fromCharCode(
            ...new Uint8Array(
              await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(cv)
              )
            )
          )
        ).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" }[m]));

        // Redirect
        const url = new URL("https://oauth.parallel.ai/authorize");
        Object.entries({
          client_id,
          redirect_uri: location.origin + "/",
          response_type: "code",
          scope: "api",
          code_challenge: cc,
          code_challenge_method: "S256",
        }).forEach(([k, v]) => url.searchParams.set(k, v));
        location.href = url;
      }

      // Handle callback
      const code = new URLSearchParams(location.search).get("code");
      if (code) {
        fetch("https://oauth.parallel.ai/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: location.hostname,
            redirect_uri: location.origin + "/",
            code_verifier: localStorage.getItem("cv"),
          }),
        })
          .then((r) => r.json())
          .then((data) => {
            alert("Got API key: " + data.access_token.substring(0, 20) + "...");
          });
      }
    </script>
  </body>
</html>
```

That's it! 🎉
