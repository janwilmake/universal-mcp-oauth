# 2025-06-18

Initial prompt: https://letmeprompt.com/httpsuithubcomj-uiq7t40

- ✅ Add `withSimplerAuth(handler,config?:{scope?:string})` fetch wrapper to have a one-liner that logs in if unauthenticated and passes user simple user-do access to ctx.
- ✅ Create minimal demo `withSimplerAuth`
- ✅ Create `withPathKv(handler,config:{binding:string})` that can wrap this to add the path-kv pattern allowing public exceptions

# 2025-08-20

- ✅ Moved to https://github.com/janwilmake/simplerauth-provider
- ✅ Refactored to align with pattern of `x-oauth-provider`: now supports multi-client state, dynamic client registration, and more.
- ✅ Deploy and test, confirm it works.
- ✅ Remove emails from user if present, document what fields user has
- ✅ Work on explaining, focus on a blog about building 'login with Parallel' and the thought process. Focus on the why
