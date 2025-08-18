# Tasks with Tools Arena

Parallel Tasks support [MCP Tool Calling](https://docs.parallel.ai/features/mcp-tool-call). This is great, but how can we easily build apps where we can authenticate the MCPs correctly?

The idea with the **Tasks with Tools Arena** is to provide a place where you can login with multiple MCPs, and then execute tasks that use toolcalling.

worker.ts

- endpoint POST /set-api-key that sets apiKey provided by user
- endpoint /task that takes mcpUrls:string[] and input, and performs an auto-task https://docs.parallel.ai/api-reference/task-api-v1/create-task-run.md and redirects to /poll?id={id} (using api key from getMetadata)
- endpoint /poll?id={id} that retrieves the result using https://docs.parallel.ai/api-reference/task-api-v1/retrieve-task-run-result.md (using api key)
