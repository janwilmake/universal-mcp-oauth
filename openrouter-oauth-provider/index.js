/**
 * OpenRouter OAuth Provider - MCP compliant proxy to OpenRouter's OAuth
 *
 * This provider acts as a proxy to OpenRouter's OAuth flow, making it MCP compliant.
 * It doesn't store any keys itself, just facilitates the PKCE flow with OpenRouter.
 *
 * @param {Request} request - The incoming request
 * @param {{put:(key:string,value:string,config:{expirationTtl?:number})=>Promise<any>,get:(key:string)=>Promise<string>,delete:(key:string)=>Promise<any>}} kv - KV storage for temporary PKCE state
 * @param {string} secret - secret for encryption (used for state encryption)
 * @param {{pathPrefix?:string}} config - optional prefix for paths (must not have trailing /)
 * @returns {undefined|Promise<Response>} - Returns undefined if not an OAuth route, otherwise a Response
 */
export async function openrouterOauthProvider(
  request,
  kv,
  secret,
  config = {}
) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Helper function for CORS headers
  const getCorsHeaders = () => ({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, MCP-Protocol-Version",
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

  // Generate PKCE parameters
  const generatePKCE = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = btoa(
      String.fromCharCode.apply(null, Array.from(array))
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    return crypto.subtle
      .digest("SHA-256", new TextEncoder().encode(codeVerifier))
      .then((hash) => ({
        codeVerifier,
        codeChallenge: btoa(String.fromCharCode(...new Uint8Array(hash)))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, ""),
      }));
  };

  // Create a deterministic key from redirect_uri and code_challenge
  const createSessionKey = async (redirectUri, codeChallenge) => {
    const data = `${redirectUri}:${codeChallenge}`;
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(data)
    );
    const hashArray = Array.from(new Uint8Array(hash));
    return hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .substring(0, 32);
  };

  // Handle OPTIONS requests
  if (request.method === "OPTIONS") {
    return handleOptionsRequest(["GET", "POST", "OPTIONS"]);
  }

  // OAuth Authorization Server Metadata (RFC8414)
  if (
    path === "/.well-known/oauth-authorization-server" ||
    path.startsWith("/.well-known/oauth-authorization-server/")
  ) {
    const metadata = {
      issuer: url.origin,
      authorization_endpoint: `${url.origin}${
        config.pathPrefix || ""
      }/authorize`,
      token_endpoint: `${url.origin}${config.pathPrefix || ""}/token`,
      token_endpoint_auth_methods_supported: ["none"],
      registration_endpoint: `${url.origin}${config.pathPrefix || ""}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      scopes_supported: ["api"],
      code_challenge_methods_supported: ["S256"],
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
      },
    });
  }

  // Protected resource metadata
  const protectedResourcePath = "/.well-known/oauth-protected-resource";
  if (
    path === protectedResourcePath ||
    path.startsWith(protectedResourcePath + "/")
  ) {
    const suffix = path.slice(protectedResourcePath.length);
    const metadata = {
      resource: url.origin + suffix,
      authorization_servers: [url.origin],
      scopes_supported: ["api"],
      bearer_methods_supported: ["header"],
    };

    return new Response(JSON.stringify(metadata, null, 2), {
      headers: {
        ...getCorsHeaders(),
        "Content-Type": "application/json",
      },
    });
  }

  // Dynamic Client Registration endpoint (MCP requirement)
  if (path === `${config.pathPrefix || ""}/register`) {
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

      // Extract hostnames from redirect URIs
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

      const clientHost = Array.from(hostnames)[0];

      const response = {
        client_id: clientHost,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: "none",
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

  // Authorization endpoint - redirects to OpenRouter with PKCE
  if (path === `${config.pathPrefix || ""}/authorize`) {
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state");
    const responseType = url.searchParams.get("response_type") || "code";
    const codeChallenge = url.searchParams.get("code_challenge");
    const codeChallengeMethod = url.searchParams.get("code_challenge_method");

    if (!redirectUri || responseType !== "code") {
      return new Response("Invalid request parameters", {
        status: 400,
        headers: getCorsHeaders(),
      });
    }

    // PKCE is required
    if (!codeChallenge || codeChallengeMethod !== "S256") {
      return new Response(
        "PKCE required: code_challenge and code_challenge_method=S256",
        { status: 400, headers: getCorsHeaders() }
      );
    }

    // Generate our own PKCE parameters for OpenRouter
    const pkce = await generatePKCE();

    // Create a deterministic session key based on the original request
    const sessionKey = await createSessionKey(redirectUri, codeChallenge);

    // Store session information in KV using the deterministic key
    const sessionData = {
      originalRedirectUri: redirectUri,
      originalState: state,
      originalCodeChallenge: codeChallenge,
      codeVerifier: pkce.codeVerifier,
      timestamp: Date.now(),
    };

    await kv.put(
      `session_${sessionKey}`,
      JSON.stringify(sessionData),
      { expirationTtl: 600 } // 10 minutes
    );

    // Build OpenRouter authorization URL - pass through the original state
    const openrouterAuthUrl = new URL("https://openrouter.ai/auth");
    openrouterAuthUrl.searchParams.set("callback_url", redirectUri);
    openrouterAuthUrl.searchParams.set("code_challenge", pkce.codeChallenge);
    openrouterAuthUrl.searchParams.set("code_challenge_method", "S256");

    // Pass through the original state if provided
    if (state) {
      openrouterAuthUrl.searchParams.set("state", state);
    }

    return new Response(null, {
      status: 302,
      headers: {
        ...getCorsHeaders(),
        Location: openrouterAuthUrl.toString(),
      },
    });
  }

  // Token endpoint - exchanges code for OpenRouter API key
  if (
    path === `${config.pathPrefix || ""}/token` &&
    request.method === "POST"
  ) {
    if (request.method === "OPTIONS") {
      return handleOptionsRequest(["POST", "OPTIONS"]);
    }

    try {
      const formData = await request.formData();
      const grantType = formData.get("grant_type");
      const code = formData.get("code");
      const codeVerifier = formData.get("code_verifier");
      const redirectUri = formData.get("redirect_uri");

      if (
        grantType !== "authorization_code" ||
        !code ||
        !codeVerifier ||
        !redirectUri
      ) {
        return new Response(
          JSON.stringify({
            error: "invalid_request",
            error_description:
              "Invalid grant_type, missing code, redirect_uri, or missing code_verifier",
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

      // Verify the PKCE challenge
      const hash = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(codeVerifier)
      );
      const computedChallenge = btoa(
        String.fromCharCode(...new Uint8Array(hash))
      )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

      // Create the same session key to look up our stored data
      const sessionKey = await createSessionKey(redirectUri, computedChallenge);
      const sessionDataStr = await kv.get(`session_${sessionKey}`);

      if (!sessionDataStr) {
        return new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description: "Invalid or expired authorization code",
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

      const sessionData = JSON.parse(sessionDataStr);

      // Verify the code_verifier matches what we stored
      if (computedChallenge !== sessionData.originalCodeChallenge) {
        return new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description: "Invalid code_verifier",
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

      // Clean up the session data
      await kv.delete(`session_${sessionKey}`);

      // Exchange the code with OpenRouter using our stored code_verifier
      const tokenResponse = await fetch(
        "https://openrouter.ai/api/v1/auth/keys",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            code: code,
            code_verifier: sessionData.codeVerifier,
            code_challenge_method: "S256",
          }),
        }
      );

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.text();
        console.error("OpenRouter token exchange failed:", errorData);
        return new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description: "Authorization code exchange failed",
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

      const tokenData = await tokenResponse.json();

      if (!tokenData.key) {
        return new Response(
          JSON.stringify({
            error: "server_error",
            error_description: "No API key received from OpenRouter",
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

      // Return the API key as access token in OAuth format
      return new Response(
        JSON.stringify({
          access_token: tokenData.key,
          token_type: "bearer",
          scope: "api",
        }),
        {
          headers: {
            ...getCorsHeaders(),
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        }
      );
    } catch (error) {
      console.error("Token endpoint error:", error);
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

  // /me endpoint for token verification (MCP requirement)
  if (path === `${config.pathPrefix || ""}/me`) {
    const accessToken =
      request.headers.get("Authorization")?.slice("Bearer ".length) || "";
    const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;
    const loginUrl = `${url.origin}${
      config.pathPrefix || ""
    }/authorize?redirect_to=${encodeURIComponent(request.url)}`;

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
            "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
          },
        }
      );
    }

    // Verify token with OpenRouter
    try {
      const keyResponse = await fetch("https://openrouter.ai/api/v1/key", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!keyResponse.ok) {
        return new Response(
          JSON.stringify({
            error: "invalid_token",
            error_description: "Token validation failed",
          }),
          {
            status: 401,
            headers: {
              ...getCorsHeaders(),
              "Content-Type": "application/json",
              "WWW-Authenticate": `Bearer realm="main", error="invalid_token", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
            },
          }
        );
      }

      const keyData = await keyResponse.json();

      // Return minimal user info (MCP requirement)
      return new Response(
        JSON.stringify({
          id: keyData.id || "openrouter_user",
          name: keyData.name || "OpenRouter User",
          username: keyData.name || "openrouter_user",
        }),
        {
          headers: {
            ...getCorsHeaders(),
            "Content-Type": "application/json",
          },
        }
      );
    } catch (error) {
      console.error("Token verification error:", error);
      return new Response(
        JSON.stringify({
          error: "server_error",
          error_description: "Token verification failed",
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

  // Not an OAuth route - return undefined to let other handlers process the request
  return undefined;
}
