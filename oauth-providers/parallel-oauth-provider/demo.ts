import { parallelOauthProvider } from "./index";

export interface Env {
  PKV: KVNamespace;
  SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Try OAuth provider first
    const oauthResponse = await parallelOauthProvider(
      request,
      env.PKV,
      env.SECRET,
      { assetsPrefix: undefined, pathPrefix: undefined }
    );
    if (oauthResponse) return oauthResponse;
    return new Response("Not found", { status: 404 });
  },
};
