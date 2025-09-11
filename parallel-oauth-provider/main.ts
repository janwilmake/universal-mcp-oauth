/**
 * Super minimal OAuth provider for Parallel.ai API keys
 * @param {Request} request - The incoming request
 * @param {KVNamespace} kv - Cloudflare KV namespace for temporary storage
 * @returns {undefined|Promise<Response>} - Returns undefined if not an OAuth route, otherwise a Response
 */
export async function parallelOauthProvider(request, kv) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Helper function for CORS headers
  const getCorsHeaders = () => ({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });

  // Helper function for OPTIONS responses
  const handleOptionsRequest = (allowedMethods = ["GET", "OPTIONS"]) => {
    return new Response(null, {
      status: 204,
      headers: {
        ...getCorsHeaders(),
        "Access-Control-Allow-Methods": allowedMethods.join(", "),
      },
    });
  };

  // Handle OPTIONS requests
  if (request.method === "OPTIONS") {
    return handleOptionsRequest(["GET", "POST", "OPTIONS"]);
  }

  // OAuth Authorization Server Metadata (RFC8414)
  if (path === "/.well-known/oauth-authorization-server") {
    const metadata = {
      issuer: url.origin,
      authorization_endpoint: `${url.origin}/authorize`,
      token_endpoint: `${url.origin}/token`,
      token_endpoint_auth_methods_supported: ["none"],
      registration_endpoint: `${url.origin}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      scopes_supported: ["api"],
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
      },
    });
  }

  // Protected resource metadata
  if (path === "/.well-known/oauth-protected-resource") {
    const metadata = {
      resource: url.origin,
      authorization_servers: [url.origin],
      scopes_supported: ["api"],
      bearer_methods_supported: ["header"],
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
      },
    });
  }

  // Dynamic Client Registration endpoint
  if (path === "/register") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest(["POST", "OPTIONS"]);
    }

    const corsHeaders = getCorsHeaders();

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: corsHeaders,
      });
    }

    try {
      const body = await request.json();

      // Validate redirect_uris is present and is an array
      if (
        !body.redirect_uris ||
        !Array.isArray(body.redirect_uris) ||
        body.redirect_uris.length === 0
      ) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "redirect_uris must be a non-empty array",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      // Extract hosts from all redirect URIs
      const hostnames = new Set();
      for (const uri of body.redirect_uris) {
        try {
          const url = new URL(uri);
          hostnames.add(url.hostname);
        } catch (e) {
          return new Response(
            JSON.stringify({
              error: "invalid_redirect_uri",
              error_description: `Invalid redirect URI: ${uri}`,
            }),
            {
              status: 400,
              headers: {
                ...corsHeaders,
                "Content-Type": "application/json",
              },
            }
          );
        }
      }

      // Ensure all redirect URIs have the same host
      if (hostnames.size !== 1) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "All redirect URIs must have the same host",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      const clientHost = Array.from(hostnames)[0];

      // Response with client_id as the host
      const response = {
        client_id: clientHost,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: "none", // Public client, no secret needed
        grant_types: ["authorization_code"],
        response_types: ["code"],
      };

      return new Response(JSON.stringify(response, null, 2), {
        status: 201,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          Pragma: "no-cache",
        },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "invalid_client_metadata",
          error_description: "Invalid JSON in request body",
        }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
  }

  // Helper function to validate domain
  const isValidDomain = (domain) => {
    const domainRegex =
      /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return (
      (domainRegex.test(domain) &&
        domain.includes(".") &&
        domain.length <= 253) ||
      domain === "localhost"
    );
  };

  // Authorization endpoint - shows the API key input form
  if (path === "/authorize") {
    const clientId = url.searchParams.get("client_id");
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state");
    const responseType = url.searchParams.get("response_type") || "code";

    if (!clientId || !redirectUri || responseType !== "code") {
      return new Response("Invalid request parameters", {
        status: 400,
        headers: getCorsHeaders(),
      });
    }

    // Validate that client_id looks like a domain
    if (!isValidDomain(clientId)) {
      return new Response("Invalid client_id: must be a valid domain", {
        status: 400,
        headers: getCorsHeaders(),
      });
    }

    // Validate redirect_uri matches client_id hostname
    try {
      const redirectUrl = new URL(redirectUri);
      if (redirectUrl.hostname !== clientId) {
        return new Response(
          "Invalid redirect_uri: must be on same origin as client_id",
          {
            status: 400,
            headers: getCorsHeaders(),
          }
        );
      }

      if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
        return new Response("Invalid redirect_uri: must use HTTPS", {
          status: 400,
          headers: getCorsHeaders(),
        });
      }
    } catch {
      return new Response("Invalid redirect_uri format", {
        status: 400,
        headers: getCorsHeaders(),
      });
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parallel.ai API Access</title>
    <style>
        @font-face {
            font-family: 'FT System Mono';
            src: url('https://assets.p0web.com/FTSystemMono-Regular.woff2') format('woff2');
            font-weight: 400;
            font-style: normal;
        }
        @font-face {
            font-family: 'FT System Mono';
            src: url('https://assets.p0web.com/FTSystemMono-Medium.woff2') format('woff2');
            font-weight: 500;
            font-style: normal;
        }
        @font-face {
            font-family: 'Gerstner Programm';
            src: url('https://assets.p0web.com/Gerstner-ProgrammRegular.woff2') format('woff2');
            font-weight: 400;
            font-style: normal;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'FT System Mono', monospace;
            background-color: #fcfcfa;
            color: #1d1b16;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            max-width: 400px;
            width: 100%;
            text-align: center;
        }

        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 32px;
            background: url('https://assets.p0web.com/dark-parallel-symbol-270.svg') no-repeat center;
            background-size: contain;
        }

        h1 {
            font-family: 'Gerstner Programm', serif;
            font-size: 24px;
            font-weight: 400;
            margin-bottom: 8px;
            color: #1d1b16;
        }

        .subtitle {
            font-size: 14px;
            color: #d8d0bf;
            margin-bottom: 32px;
        }

        .trust-notice {
            background: rgba(251, 99, 27, 0.1);
            border: 2px solid #fb631b;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 14px;
            text-align: left;
        }

        .client-info {
            font-weight: 500;
            color: #fb631b;
            margin-bottom: 8px;
        }

        .form-group {
            margin-bottom: 24px;
            text-align: left;
        }

        label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
            color: #1d1b16;
        }

        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            font-family: 'FT System Mono', monospace;
            font-size: 14px;
            border: 2px solid #d8d0bf;
            border-radius: 8px;
            background: #fcfcfa;
            color: #1d1b16;
            transition: border-color 0.2s;
        }

        input[type="password"]:focus {
            outline: none;
            border-color: #fb631b;
        }

        input[type="password"]::placeholder {
            color: #d8d0bf;
        }

        .button {
            width: 100%;
            padding: 12px 24px;
            font-family: 'FT System Mono', monospace;
            font-size: 14px;
            font-weight: 500;
            background: #fb631b;
            color: #fcfcfa;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .button:hover {
            background: #e55a18;
        }

        .button:disabled {
            background: #d8d0bf;
            cursor: not-allowed;
        }

        .link {
            display: inline-block;
            margin-top: 16px;
            font-size: 14px;
            color: #fb631b;
            text-decoration: none;
            transition: color 0.2s;
        }

        .link:hover {
            color: #e55a18;
        }

        .error {
            color: #fb631b;
            font-size: 12px;
            margin-top: 8px;
            text-align: left;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo"></div>
        <h1>API Access Authorization</h1>
        <p class="subtitle">Grant access to your Parallel.ai API key</p>
        
        <div class="trust-notice">
            <div class="client-info">${clientId}</div>
            <div>Do you trust this application to access your Parallel.ai API key?</div>
        </div>
        
        <form id="authForm">
            <div class="form-group">
                <label for="apiKey">Your Parallel.ai API Key</label>
                <input 
                    type="password" 
                    id="apiKey" 
                    name="apiKey" 
                    placeholder="Enter your API key..."
                    required
                />
                <div id="error" class="error"></div>
            </div>
            
            <button type="submit" class="button" id="submitBtn">
                Authorize ${clientId}
            </button>
        </form>
        
        <a href="https://platform.parallel.ai/settings?tab=api-keys" class="link" target="_blank">
            Get your API key →
        </a>
    </div>

    <script>
        // Load previous API key from localStorage
        const apiKeyInput = document.getElementById('apiKey');
        const savedApiKey = localStorage.getItem('parallel_api_key');
        if (savedApiKey) {
            apiKeyInput.value = savedApiKey;
        }

        document.getElementById('authForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const apiKey = apiKeyInput.value.trim();
            const errorDiv = document.getElementById('error');
            const submitBtn = document.getElementById('submitBtn');
            
            if (!apiKey) {
                errorDiv.textContent = 'Please enter your API key';
                return;
            }
            
            submitBtn.disabled = true;
            submitBtn.textContent = 'Authorizing...';
            errorDiv.textContent = '';
            
            try {
                // Save to localStorage for next time
                localStorage.setItem('parallel_api_key', apiKey);
                
                // Generate auth code
                const authCode = 'auth_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
                
                // Store API key with auth code in KV (10 minutes expiration)
                const response = await fetch('/store-key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ authCode, apiKey })
                });
                
                if (!response.ok) {
                    throw new Error('Failed to store API key');
                }
                
                // Redirect back to client
                const redirectUrl = new URL('${redirectUri}');
                redirectUrl.searchParams.set('code', authCode);
                ${
                  state
                    ? `redirectUrl.searchParams.set('state', '${state}');`
                    : ""
                }
                
                window.location.href = redirectUrl.toString();
                
            } catch (error) {
                errorDiv.textContent = 'Authorization failed. Please try again.';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Authorize ${clientId}';
            }
        });
    </script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "text/html",
      },
    });
  }

  // Store API key endpoint (called by the authorization form)
  if (path === "/store-key" && request.method === "POST") {
    try {
      const { authCode, apiKey } = await request.json();

      if (!authCode || !apiKey) {
        return new Response("Invalid request", {
          status: 400,
          headers: getCorsHeaders(),
        });
      }

      // Store in KV with 10 minute expiration
      await kv.put(authCode, apiKey, { expirationTtl: 600 });

      return new Response("OK", {
        headers: getCorsHeaders(),
      });
    } catch (error) {
      return new Response("Invalid JSON", {
        status: 400,
        headers: getCorsHeaders(),
      });
    }
  }

  // Token endpoint - exchanges auth code for API key
  if (path === "/token" && request.method === "POST") {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest(["POST", "OPTIONS"]);
    }

    try {
      const formData = await request.formData();
      const grantType = formData.get("grant_type");
      const code = formData.get("code");
      const clientId = formData.get("client_id");

      if (grantType !== "authorization_code" || !code || !clientId) {
        return new Response(
          JSON.stringify({
            error: "invalid_request",
            error_description:
              "Invalid grant_type, missing code, or missing client_id",
          }),
          {
            status: 400,
            headers: {
              ...getCorsHeaders(),
              "Content-Type": "application/json",
            },
          }
        );
      }

      // Validate client_id is a valid domain
      if (!isValidDomain(clientId)) {
        return new Response(
          JSON.stringify({
            error: "invalid_client",
            error_description: "client_id must be a valid domain",
          }),
          {
            status: 400,
            headers: {
              ...getCorsHeaders(),
              "Content-Type": "application/json",
            },
          }
        );
      }

      // Get API key from KV
      const apiKey = await kv.get(code);

      if (!apiKey) {
        return new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description: "Authorization code not found or expired",
          }),
          {
            status: 400,
            headers: {
              ...getCorsHeaders(),
              "Content-Type": "application/json",
            },
          }
        );
      }

      // Delete the code from KV (one-time use)
      await kv.delete(code);

      // Return the API key as access token
      return new Response(
        JSON.stringify({
          access_token: apiKey,
          token_type: "bearer",
          scope: "api",
        }),
        {
          headers: {
            ...getCorsHeaders(),
            "Content-Type": "application/json",
          },
        }
      );
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "server_error",
          error_description: "Internal server error",
        }),
        {
          status: 500,
          headers: {
            ...getCorsHeaders(),
            "Content-Type": "application/json",
          },
        }
      );
    }
  }

  if (path === "/me") {
    const accessToken =
      request.headers.get("Authorization")?.slice("Bearer ".length) || "";
    const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;
    const loginUrl = `${url.origin}/authorize?redirect_to=${encodeURIComponent(
      request.url
    )}`;

    // Get access token from request
    if (!accessToken) {
      return new Response(
        JSON.stringify({
          error: "unauthorized",
          error_description: "Access token required",
        }),
        {
          status: 401,
          headers: {
            ...getCorsHeaders(),
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}`,
          },
        }
      );
    }
  }

  // Not an OAuth route
  return undefined;
}
