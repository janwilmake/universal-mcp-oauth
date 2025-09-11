import { parallelOauthProvider } from "./main";

export interface Env {
  PKV: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Try OAuth provider first
    const oauthResponse = await parallelOauthProvider(request, env.PKV);
    if (oauthResponse) return oauthResponse;
    return new Response("Not found", { status: 404 });
  },
};
