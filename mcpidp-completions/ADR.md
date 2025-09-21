MCP implementations that are already there:

- https://docs.anthropic.com/en/api/messages#body-mcp-servers
- https://platform.openai.com/docs/api-reference/responses/create#responses-create-tools

However, most chat completions implementations don't offer MCP support. This implementation allows any provider to implement it in a similar way. Before i made this I pondered on instead using the above implementations but it's just too limited and not moving fast.
