import { withSimplerAuth } from "./client";
export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      // Your handler logic here
      if (ctx.authenticated) {
        return new Response(`Hello ${ctx.user.name}! You are logged in.`);
      } else {
        return new Response("Hello, anonymous user!");
      }
    },
    {
      isLoginRequired: true, // Force login
      providerHostname: "localhost:8787", // Your OAuth provider
      scope: "profile",
      sameSite: "Lax",
    }
  ),
};
