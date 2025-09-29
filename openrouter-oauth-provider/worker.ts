import { openrouterOauthProvider } from "./index.js";

export interface Env {
  KV: KVNamespace;
  SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Try OAuth provider first
    const oauthResponse = await openrouterOauthProvider(
      request,
      env.KV,
      env.SECRET,
      { pathPrefix: undefined }
    );
    if (oauthResponse) return oauthResponse;

    return new Response("OpenRouter OAuth Provider - MCP Compliant", {
      headers: { "Content-Type": "text/plain" },
    });
  },
};
