/// <reference types="@cloudflare/workers-types" />
/// <reference lib="esnext" />

import { env } from "cloudflare:workers";
import { withSimplerAuth } from "simplerauth-client";
import { withMcp } from "with-mcp";

type Env = { PORT: string; OAUTH_PROVIDER_HOST: string };
const handler = withSimplerAuth(
  async (request, env, ctx) => {
    if (!ctx.authenticated || !ctx.user) {
      return new Response("Not authorized", { status: 401 });
    }
    const url = new URL(request.url);
    if (url.pathname === "/add") {
      const a = url.searchParams.get("a");
      const b = url.searchParams.get("b");
      if (a === null || b === null) {
        return new Response("Need a and b", { status: 400 });
      }
      const sum = Number(a) + Number(b);
      return new Response(
        `The sum is ${sum}, ${ctx.user.name || ctx.user.username}.`,
        { status: 200 }
      );
    }
    return new Response("Not found", { status: 404 });
  },
  {
    isLoginRequired: true,
    oauthProviderHost: (env as Env).OAUTH_PROVIDER_HOST,
    scope: "profile",
    sameSite: "Lax",
  }
);
export default {
  fetch: withMcp(
    handler,
    {
      paths: {
        "/add": {
          get: {
            operationId: "add",
            description: "Add 2 numbers",
            responses: {
              200: {
                description: "Sum",
                content: { "text/plain": { schema: { type: "string" } } },
              },
              400: {
                description: "Invalid input",
                content: { "text/plain": { schema: { type: "string" } } },
              },
            },
            parameters: [
              {
                in: "query",
                name: "a",
                required: true,
                schema: { type: "number" },
              },
              {
                in: "query",
                name: "b",
                required: true,
                schema: { type: "number" },
              },
            ],
          },
        },
      },
    },
    { authEndpoint: "/me", toolOperationIds: ["add"] }
  ),
};
