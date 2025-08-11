@client-authorization-steps.md

make a stateless web-standard js function (with jsdoc comments) that follows these steps

Input: mcp url and callback url (no further options)

Result: a constructed authorization url, the response from registration, and other things needed for token exchange after callback

NB: use this for initial contact. if `resource_metadata` wasn't found, use mcp server hostname as base

```sh
curl -v -X POST ${mcpUrl} \
  -H "Content-Type: application/json" -H "Accept:application/json,text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-06-18",
      "capabilities": {
        "roots": {
          "listChanged": true
        },
        "sampling": {}
      },
      "clientInfo": {
        "name": "curl-client",
        "title": "cURL MCP Client",
        "version": "1.0.0"
      }
    }
  }'
```
