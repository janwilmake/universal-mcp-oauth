# Scalability

- Figure out how I can reduce load on aggregate.
  - Cache `/me` from `simplerauth-client`?
  - Only connect to aggregate once per 15 minutes (from user DO, not exported handler?)
- Add per-apex (or per-user) ratelimit (1200 requests per minute should do) to prevent capacity constraints and DDOS problems

# Work on potenital MCP protocol change proposoal (SEP)

Look at https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1405 again and see what I can change to the SPEC without breaking anything and without adding complexity. The main thing this solves is spoofing attacks when allowing for DCR (although spoofing can still be done if people confuse hostnames with similar ones)

# Use AI SDK?

Q: How does the AI SDK spec work and compare to other specs? might learn a lot from looking at custom providers

https://uithub.com/vercel/ai/tree/main/packages/provider/src/language-model/v2?lines=false
https://ai-sdk.dev/docs/foundations/providers-and-models

This could be a great integration.

# Discoverability (`.well-known/mcp`)

This is not something that's determined yet. For now this repo will focus on post-oauth initialization and getting details from there, rather over HTTP.

https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1147

https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization.md
