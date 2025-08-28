# Security is a real problem

Any enabled tool (including built-in tools like web-search) that may provide untrusted information into the context-window can affect other tools to do things the user didn't ask for. This is the [context poisoning problem](https://www.backslash.security/blog/simulating-a-vulnerable-mcp-server-for-context-poisoning) and isn't solved yet.

# People are just using tools

Although the spec clearly specifies tools, resources, and prompts, most clients just support tools. This disincentivizes MCP builders to use the other two. Practically this means most MCPs end up providing resources and prompts as tools, polluting the MCP ecosystem.
