import { UserDO, withSimplerAuth } from "./github-oauth-provider";

export { UserDO };

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      return new Response(
        `<html><head><meta charset="utf8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SimplerAuth GitHub Provider</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font:14px system-ui;background:#fcfcfa;color:#1d1b16;min-height:100vh;display:flex;align-items:center;justify-content:center;position:relative}@media(prefers-color-scheme:dark){body{background:#1d1b16;color:#fcfcfa}}.github-link{position:absolute;top:20px;left:20px;background:#1d1b16;color:#fcfcfa;padding:8px 16px;border-radius:8px;text-decoration:none;font-weight:600}@media(prefers-color-scheme:dark){.github-link{background:#fcfcfa;color:#1d1b16}}.github-link:hover{opacity:.8}.admin{position:absolute;top:20px;right:20px;background:#fb631b;color:#fcfcfa;padding:8px 16px;border-radius:8px;text-decoration:none;font-weight:600}@media(prefers-color-scheme:dark){.admin{background:#fb631b}}.admin:hover{background:#e55a17}.container{text-align:center;max-width:320px}.title{font-size:20px;margin-bottom:8px}.subtitle{color:#d8d0bf;margin-bottom:24px}.card{background:#fcfcfa;border:1px solid #d8d0bf;border-radius:12px;padding:24px;text-align:center;box-shadow:0 2px 8px rgba(29,27,22,.1)}@media(prefers-color-scheme:dark){.card{background:#1d1b16;border-color:#d8d0bf33}}.avatar{width:80px;height:80px;border-radius:50%;margin:0 auto 16px;display:block;border:2px solid #d8d0bf}.name{color:#1d1b16;font-weight:600;font-size:16px;margin-bottom:8px}@media(prefers-color-scheme:dark){.name{color:#fcfcfa}}.username{margin-bottom:8px;color:#d8d0bf}.logout{color:#fb631b;text-decoration:none;display:inline-block}.logout:hover{text-decoration:underline}</style></head><body><a href="https://github.com/janwilmake/simplerauth-provider" target="_blank" class="github-link">GitHub</a>${
          env.ADMIN_GITHUB_USERNAME === ctx.user.login
            ? '<a href="/admin" target="_blank" class="admin">Admin</a>'
            : ""
        }<div class="container"><h1 class="title">SimplerAuth GitHub Provider</h1><p class="subtitle">Any client will be able to retrieve your profile without further consent.</p><div class="card"><img src="${
          ctx.user.avatar_url || "/default-avatar.png"
        }" alt="Avatar" class="avatar"><p class="name">${
          ctx.user.name || ctx.user.login
        }</p><p class="username">@${
          ctx.user.login
        }</p><a href="/logout" class="logout">Logout</a></div></div></body></html>`,
        { headers: { "Content-Type": "text/html;charset=utf8" } }
      );
    },
    { isLoginRequired: true }
  ),
};
