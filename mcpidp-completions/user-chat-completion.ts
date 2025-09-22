import {
  createMCPOAuthHandler,
  getAuthorization,
  getMCPProviders,
  MCPOAuthEnv,
  MCPProviders,
} from "universal-mcp-oauth";
export { MCPProviders };

interface MCPTool {
  type: "mcp";
  server_url: string;
  allowed_tools?: { tool_names: string[] };
  require_approval?: "never";
}

export interface ChatCompletionRequest {
  model: string;
  messages: Array<{
    role: "system" | "user" | "assistant" | "tool" | "function";
    content?: string | null;
    name?: string;
    tool_calls?: Array<{
      id: string;
      type: "function";
      function: { name: string; arguments: string };
    }>;
    tool_call_id?: string;
  }>;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop?: string | string[];
  stream?: boolean;
  tools?: Array<
    | {
        type: "function";
        function: {
          name: string;
          description?: string;
          parameters?: Record<string, any>;
        };
      }
    | MCPTool
  >;
  tool_choice?:
    | "none"
    | "auto"
    | { type: "function"; function: { name: string } };
  user?: string;
  [key: string]: any;
}

interface StreamChunk {
  id: string;
  object: "chat.completion.chunk";
  created: number;
  model: string;
  choices: Array<{
    index: number;
    delta: {
      role?: "assistant";
      content?: string | null;
      reasoning_content?: string | null;
      refusal?: string | null;
      tool_calls?: Array<{
        index: number;
        id?: string;
        type?: "function";
        function?: {
          name?: string;
          arguments?: string;
        };
      }>;
    };
    finish_reason?: "stop" | "length" | "tool_calls" | "content_filter" | null;
  }>;
}

interface MCPSession {
  sessionId?: string;
  initialized: boolean;
  serverInfo?: {
    name: string;
    version: string;
  };
  capabilities?: {
    tools?: {
      listChanged?: boolean;
    };
  };
  tools?: Array<{
    name: string;
    description?: string;
    inputSchema?: any;
  }>;
}

// In-memory session storage (you might want to use a more persistent storage)
const mcpSessions = new Map<string, MCPSession>();

// Generate a cache key for MCP sessions
function getMCPSessionKey(userId: string, serverUrl: string): string {
  return `${userId}:${serverUrl}`;
}

// Utility function to parse MCP responses (both JSON and event-stream) - IMPROVED VERSION
async function parseMCPResponse(response: Response): Promise<any> {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("text/event-stream")) {
    // Handle Server-Sent Events response - IMPROVED: Return immediately after first valid response
    if (!response.body) {
      throw new Error("No response body for event stream");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value);
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const trimmedLine = line.trim();

          // Skip empty lines and comments
          if (!trimmedLine || trimmedLine.startsWith(":")) {
            continue;
          }

          // Handle data lines
          if (trimmedLine.startsWith("data: ")) {
            const data = trimmedLine.slice(6);

            // Skip [DONE] marker
            if (data === "[DONE]") {
              continue;
            }

            try {
              const parsed = JSON.parse(data);

              // IMPROVEMENT: Return immediately when we get a valid JSON-RPC response
              if (parsed.jsonrpc === "2.0") {
                // Close the reader to stop consuming the stream
                reader.releaseLock();
                return parsed;
              }
            } catch (parseError) {
              console.warn("Failed to parse SSE data as JSON:", data);
              // Continue processing other lines instead of throwing
            }
          }

          // Handle event lines (if needed) - just log for debugging
          else if (trimmedLine.startsWith("event: ")) {
            const eventType = trimmedLine.slice(7);
            console.log("SSE event type:", eventType);
          }

          // Handle id lines (if needed) - just log for debugging
          else if (trimmedLine.startsWith("id: ")) {
            const eventId = trimmedLine.slice(4);
            console.log("SSE event id:", eventId);
          }
        }
      }
    } finally {
      // Ensure reader is always released
      if (reader.locked) {
        reader.releaseLock();
      }
    }

    // If we get here, no valid JSON-RPC response was found
    throw new Error("No valid JSON-RPC response received from event stream");
  } else {
    // Handle regular JSON response - unchanged, already fast
    const responseText = await response.text();

    if (!responseText.trim()) {
      throw new Error("Empty response body");
    }

    try {
      return JSON.parse(responseText);
    } catch (parseError) {
      throw new Error(`Invalid JSON response: ${responseText}`);
    }
  }
}

// Initialize MCP session following the proper lifecycle
async function initializeMCPSession(
  originUrl: string,
  env: MCPOAuthEnv,
  userId: string,
  serverUrl: string
): Promise<MCPSession> {
  const sessionKey = getMCPSessionKey(userId, serverUrl);

  // Check if we already have an initialized session
  const existingSession = mcpSessions.get(sessionKey);
  if (existingSession?.initialized) {
    return existingSession;
  }

  const authHeaders = await getAuthorization(env, userId, serverUrl);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json,text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
  };

  if (authHeaders?.Authorization) {
    headers.Authorization = authHeaders.Authorization;
  }

  console.log(`Initializing MCP session for ${serverUrl}`);

  // Step 1: Send initialize request
  const initializeRequest = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {
        roots: {
          listChanged: true,
        },
        sampling: {},
      },
      clientInfo: {
        name: "ChatCompletionsProxy",
        version: "1.0.0",
      },
    },
  };

  const initResponse = await fetch(serverUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(initializeRequest),
  });

  if (!initResponse.ok) {
    if (initResponse.status === 401) {
      const hostname = new URL(serverUrl).hostname;
      throw new Error(
        `Authentication required for ${hostname}. Please authenticate at: ${originUrl}/mcp/login?url=${encodeURIComponent(
          serverUrl
        )}`
      );
    }
    const errorText = await initResponse.text();
    throw new Error(
      `MCP initialization failed for ${serverUrl}: ${initResponse.status} ${errorText}`
    );
  }

  let initResult;
  try {
    initResult = await parseMCPResponse(initResponse);
  } catch (e) {
    throw new Error(
      `Failed to parse MCP initialization response from ${serverUrl}: ${e.message}`
    );
  }

  if (initResult.error) {
    throw new Error(
      `MCP initialization error: ${initResult.error.message} (code: ${initResult.error.code})`
    );
  }

  // Extract session ID if provided
  const sessionId = initResponse.headers.get("Mcp-Session-Id");

  // Update headers for subsequent requests if we have a session ID
  if (sessionId) {
    headers["Mcp-Session-Id"] = sessionId;
  }

  // Step 2: Send initialized notification
  const initializedNotification = {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  };

  const notificationResponse = await fetch(serverUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(initializedNotification),
  });

  if (!notificationResponse.ok) {
    throw new Error(
      `MCP initialized notification failed for ${serverUrl}: ${notificationResponse.status}`
    );
  }

  // Step 3: List available tools
  const toolsListRequest = {
    jsonrpc: "2.0",
    id: Date.now() + 1,
    method: "tools/list",
  };

  const toolsResponse = await fetch(serverUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(toolsListRequest),
  });

  if (!toolsResponse.ok) {
    throw new Error(
      `MCP tools/list failed for ${serverUrl}: ${toolsResponse.status}`
    );
  }

  let toolsResult;
  try {
    toolsResult = await parseMCPResponse(toolsResponse);
  } catch (e) {
    throw new Error(
      `Failed to parse MCP tools/list response from ${serverUrl}: ${e.message}`
    );
  }

  if (toolsResult.error) {
    throw new Error(
      `MCP tools/list error: ${toolsResult.error.message} (code: ${toolsResult.error.code})`
    );
  }

  const session: MCPSession = {
    sessionId,
    initialized: true,
    serverInfo: initResult.result?.serverInfo,
    capabilities: initResult.result?.capabilities,
    tools: toolsResult.result?.tools || [],
  };

  // Cache the session
  mcpSessions.set(sessionKey, session);

  console.log(`MCP session initialized for ${serverUrl}:`, {
    sessionId,
    serverInfo: session.serverInfo,
    toolCount: session.tools?.length || 0,
  });

  return session;
}

// Execute MCP tool with proper session management
async function executeMCPTool(
  originUrl: string,
  env: MCPOAuthEnv,
  userId: string,
  serverUrl: string,
  toolName: string,
  args: any
): Promise<string> {
  const toolCallId = `${toolName}-${Date.now()}`;
  const hostname = new URL(serverUrl).hostname;

  const startTime = Date.now();
  let initStartTime: number;
  let initEndTime: number;
  let toolCallStartTime: number;
  let toolCallEndTime: number;

  try {
    // Phase 1: Session initialization
    initStartTime = Date.now();

    let session: MCPSession;
    try {
      session = await initializeMCPSession(originUrl, env, userId, serverUrl);
      initEndTime = Date.now();
    } catch (error) {
      initEndTime = Date.now();

      if (error.message.includes("Authentication required")) {
        console.log(
          `🔐 [${toolCallId}] Authentication required for ${hostname}`
        );
        return `# MCP Server Authentication Required

${error.message}`;
      }
      throw error;
    }

    const authHeaders = await getAuthorization(env, userId, serverUrl);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json,text/event-stream",
      "MCP-Protocol-Version": "2025-06-18",
    };

    if (authHeaders?.Authorization) {
      headers.Authorization = authHeaders.Authorization;
    }

    if (session.sessionId) {
      headers["Mcp-Session-Id"] = session.sessionId;
    }

    // Phase 3: Execute the actual tool call
    toolCallStartTime = Date.now();

    const response = await fetch(serverUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now(),
        method: "tools/call",
        params: {
          name: toolName,
          arguments: args,
        },
      }),
    });

    // Handle session expiration (404 with session ID)
    if (response.status === 404 && session.sessionId) {
      console.log(`🔄 [${toolCallId}] Session expired, reinitializing...`);
      const reinitStartTime = Date.now();

      // Clear the cached session and reinitialize
      mcpSessions.delete(getMCPSessionKey(userId, serverUrl));

      try {
        session = await initializeMCPSession(originUrl, env, userId, serverUrl);

        const reinitEndTime = Date.now();
        console.log(
          `✅ [${toolCallId}] Session reinitialized in ${
            reinitEndTime - reinitStartTime
          }ms`
        );

        // Retry the tool call with the new session
        const retryHeaders = { ...headers };
        if (session.sessionId) {
          retryHeaders["Mcp-Session-Id"] = session.sessionId;
        }

        const retryStartTime = Date.now();
        console.log(`🔄 [${toolCallId}] Retrying tool call with new session`);

        const retryResponse = await fetch(serverUrl, {
          method: "POST",
          headers: retryHeaders,
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: Date.now(),
            method: "tools/call",
            params: {
              name: toolName,
              arguments: args,
            },
          }),
        });

        const retryNetworkEndTime = Date.now();
        console.log(
          `🌐 [${toolCallId}] Retry network request completed in ${
            retryNetworkEndTime - retryStartTime
          }ms`
        );
        console.log(`   Retry response status: ${retryResponse.status}`);

        if (!retryResponse.ok) {
          const errorText = await retryResponse.text();
          const errorEndTime = Date.now();
          console.log(
            `❌ [${toolCallId}] Retry failed after ${
              errorEndTime - retryStartTime
            }ms: ${retryResponse.status}`
          );
          return `**Error**: Tool ${toolName} failed after session renewal with status ${retryResponse.status}: ${errorText}`;
        }

        const parseRetryStartTime = Date.now();
        let retryResult;
        try {
          retryResult = await parseMCPResponse(retryResponse);
          const parseRetryEndTime = Date.now();
          console.log(
            `📝 [${toolCallId}] Retry response parsed in ${
              parseRetryEndTime - parseRetryStartTime
            }ms`
          );
        } catch (parseError) {
          const parseRetryEndTime = Date.now();
          console.log(
            `❌ [${toolCallId}] Retry response parsing failed after ${
              parseRetryEndTime - parseRetryStartTime
            }ms`
          );
          return `**Error**: Tool ${toolName} returned invalid response after retry: ${parseError.message}`;
        }

        if (retryResult.error) {
          const totalTime = Date.now() - startTime;
          console.log(
            `❌ [${toolCallId}] Retry completed with error in ${totalTime}ms total`
          );
          return `**Error**: ${retryResult.error.message} (code: ${retryResult.error.code})`;
        }

        const totalTime = Date.now() - startTime;
        console.log(
          `✅ [${toolCallId}] Tool execution completed successfully after retry in ${totalTime}ms total`
        );
        return formatToolResult(retryResult, toolName);
      } catch (reinitError) {
        const reinitEndTime = Date.now();
        console.log(
          `❌ [${toolCallId}] Session reinitialization failed after ${
            reinitEndTime - reinitStartTime
          }ms`
        );
        return `**Error**: Failed to reinitialize session for ${toolName}: ${reinitError.message}`;
      }
    }

    // Handle other non-200 status codes
    if (!response.ok) {
      toolCallEndTime = Date.now();
      console.log(
        `❌ [${toolCallId}] Tool call failed with status ${
          response.status
        } after ${toolCallEndTime - toolCallStartTime}ms`
      );

      if (response.status === 401) {
        const hostname = new URL(serverUrl).hostname;
        console.log(`🔐 [${toolCallId}] Authentication failed for ${hostname}`);
        return `# MCP Server Authentication Required

Authentication failed for ${hostname}. Please re-authenticate:

- [Authorize ${hostname}](${originUrl}/mcp/login?url=${encodeURIComponent(
          serverUrl
        )})

After authentication, retry your request.`;
      } else {
        const errorText = await response.text();
        console.error(`❌ [${toolCallId}] Error response body:`, errorText);
        return `**Error**: Tool ${toolName} failed with status ${response.status}: ${errorText}`;
      }
    }

    // Phase 4: Parse the response
    const parseStartTime = Date.now();
    console.log(
      `📝 [${toolCallId}] Starting response parsing (${
        parseStartTime - startTime
      }ms since start)`
    );

    let result;
    try {
      result = await parseMCPResponse(response);
      toolCallEndTime = Date.now();
      console.log(
        `✅ [${toolCallId}] Response parsed successfully in ${
          toolCallEndTime - parseStartTime
        }ms`
      );

      // Log response structure info
      if (result.result?.content) {
        const contentLength = JSON.stringify(result.result.content).length;
        const contentCount = Array.isArray(result.result.content)
          ? result.result.content.length
          : 1;
        console.log(
          `   Response content: ${contentCount} items, ${contentLength} bytes`
        );
      }
    } catch (parseError) {
      toolCallEndTime = Date.now();
      console.log(
        `❌ [${toolCallId}] Response parsing failed after ${
          toolCallEndTime - parseStartTime
        }ms`
      );
      console.error(`   Parse error:`, parseError);
      return `**Error**: Tool ${toolName} returned invalid response: ${parseError.message}`;
    }

    // Check for JSON-RPC error
    if (result.error) {
      const totalTime = Date.now() - startTime;
      console.log(
        `❌ [${toolCallId}] Tool returned error after ${totalTime}ms total`
      );
      console.error(`   MCP error:`, result.error);
      return `**Error**: ${result.error.message} (code: ${result.error.code})`;
    }

    // Phase 5: Format the result
    const formatStartTime = Date.now();
    console.log(
      `🎨 [${toolCallId}] Formatting result (${
        formatStartTime - startTime
      }ms since start)`
    );

    const formattedResult = formatToolResult(result, toolName);

    const formatEndTime = Date.now();
    const totalTime = formatEndTime - startTime;

    console.log(`✅ [${toolCallId}] Tool execution completed successfully!`);
    console.log(`   Total time: ${totalTime}ms`);
    console.log(
      `   ├─ Initialization: ${initEndTime - initStartTime}ms (${(
        ((initEndTime - initStartTime) / totalTime) *
        100
      ).toFixed(1)}%)`
    );
    console.log(
      `   ├─ Tool execution: ${toolCallEndTime - toolCallStartTime}ms (${(
        ((toolCallEndTime - toolCallStartTime) / totalTime) *
        100
      ).toFixed(1)}%)`
    );
    console.log(
      `   └─ Result formatting: ${formatEndTime - formatStartTime}ms (${(
        ((formatEndTime - formatStartTime) / totalTime) *
        100
      ).toFixed(1)}%)`
    );
    console.log(`   Result size: ${formattedResult.length} characters`);

    return formattedResult;
  } catch (error) {
    const errorTime = Date.now();
    const totalTime = errorTime - startTime;
    console.error(
      `💥 [${toolCallId}] Tool execution failed after ${totalTime}ms:`,
      error
    );

    // Log timing breakdown even for errors
    if (initEndTime) {
      console.log(`   Time breakdown at failure:`);
      console.log(`   ├─ Initialization: ${initEndTime - initStartTime}ms`);
      if (toolCallEndTime) {
        console.log(
          `   └─ Tool execution: ${toolCallEndTime - toolCallStartTime}ms`
        );
      }
    }

    return `**Error**: Tool ${toolName} execution failed: ${error.message}`;
  }
}

function formatToolResult(result: any, toolName: string): string {
  const content = result.result?.content;

  if (!content || !Array.isArray(content)) {
    console.error(
      `MCP tool ${toolName} returned invalid content structure:`,
      result
    );
    const jsonString = JSON.stringify(result, null, 2);
    return `<details><summary>Error Result (±${Math.round(
      jsonString.length / 5
    )} tokens)</summary>

\`\`\`json
${jsonString}
\`\`\`

</details>

Tool returned invalid response structure`;
  }

  // Format each content item as a separate codeblock
  const contentBlocks = content
    .map((item, index) => {
      if (item.type === "text") {
        // Try to parse as JSON first
        try {
          const parsed = JSON.parse(item.text);
          return `\`\`\`json
${JSON.stringify(parsed, null, 2)}
\`\`\``;
        } catch {
          // If not JSON, render as markdown
          return `\`\`\`markdown
${item.text}
\`\`\``;
        }
      } else if (item.type === "image") {
        return `\`\`\`
[Image: ${item.data}]
\`\`\``;
      } else {
        return `\`\`\`json
${JSON.stringify(item, null, 2)}
\`\`\``;
      }
    })
    .join("\n\n");

  // Calculate total size for the summary
  const totalSize = content.reduce((size, item) => {
    if (item.type === "text") {
      return size + (item.text?.length || 0);
    }
    return size + JSON.stringify(item).length;
  }, 0);

  return `<details><summary>Result (±${Math.round(
    totalSize / 5
  )} tokens)</summary>

${contentBlocks}

</details>`;
}

function transformMCPTools(
  mcpProviders: any[],
  tools: Array<any>
): {
  transformedTools: Array<any>;
  mcpToolMap: Map<string, { serverUrl: string; originalName: string }>;
  missingAuth: string[];
  errors: string[];
} {
  const transformedTools: Array<any> = [];
  const mcpToolMap = new Map<
    string,
    { serverUrl: string; originalName: string }
  >();
  const missingAuth: string[] = [];
  const errors: string[] = [];

  for (const tool of tools) {
    if (tool.type === "function") {
      transformedTools.push(tool);
    } else if (tool.type === "mcp") {
      // Check require_approval - only "never" is supported
      if (tool.require_approval && tool.require_approval !== "never") {
        errors.push(
          `MCP tool with server_url ${tool.server_url} has unsupported require_approval: ${tool.require_approval}. Only "never" is supported.`
        );
        continue;
      }

      const provider = mcpProviders.find((x) => x.mcp_url === tool.server_url);

      if (!provider || !provider.access_token) {
        missingAuth.push(tool.server_url);
        continue;
      }

      // Use the tools from the provider's cached information
      const availableTools = provider.tools || [];

      for (const mcpTool of availableTools) {
        if (
          tool.allowed_tools?.tool_names &&
          !tool.allowed_tools.tool_names.includes(mcpTool.name)
        ) {
          continue;
        }

        const functionName = `mcp_${provider.hostname.replaceAll(".", "-")}_${
          mcpTool.name
        }`;

        mcpToolMap.set(functionName, {
          serverUrl: tool.server_url,
          originalName: mcpTool.name,
        });

        transformedTools.push({
          type: "function",
          function: {
            name: functionName,
            description: `${
              mcpTool.description || mcpTool.name
            } (via MCP server: ${provider.name})`,
            parameters: mcpTool.inputSchema || {},
          },
        });
      }
    }
  }

  return { transformedTools, mcpToolMap, missingAuth, errors };
}

// Create a streaming response for authentication instructions
function createAuthInstructionStream(
  missingAuthUrls: string[],
  baseUrl: string,
  requestId: string,
  model: string
): ReadableStream {
  const loginLinks = missingAuthUrls
    .map((url) => {
      const loginUrl = `${baseUrl}/mcp/login?url=${encodeURIComponent(url)}`;
      return `- [Authorize ${new URL(url).hostname}](${loginUrl})`;
    })
    .join("\n");

  const content = `# MCP Server Authentication Required

To use the requested MCP tools, you need to authenticate with the following servers:

${loginLinks}

After authentication, retry your request.`;

  const encoder = new TextEncoder();

  return new ReadableStream({
    async start(controller) {
      try {
        const roleChunk = {
          id: requestId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [
            {
              index: 0,
              delta: { role: "assistant" },
              finish_reason: null,
            },
          ],
        };
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(roleChunk)}\n\n`)
        );

        await new Promise((resolve) => setTimeout(resolve, 10));

        const contentChunk = {
          id: requestId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [
            {
              index: 0,
              delta: { content },
              finish_reason: null,
            },
          ],
        };
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(contentChunk)}\n\n`)
        );

        await new Promise((resolve) => setTimeout(resolve, 10));

        const finalChunk = {
          id: requestId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [
            {
              index: 0,
              delta: {},
              finish_reason: "stop",
            },
          ],
        };
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`)
        );

        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
  });
}

// Create a streaming response for errors
function createErrorStream(
  errors: string[],
  requestId: string,
  model: string
): ReadableStream {
  const content = `# Configuration Error

The following errors were found in your MCP tool configuration:

${errors.map((error) => `- ${error}`).join("\n")}

Please fix these configuration issues and retry your request.`;

  const encoder = new TextEncoder();

  return new ReadableStream({
    async start(controller) {
      try {
        const roleChunk = {
          id: requestId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [
            {
              index: 0,
              delta: { role: "assistant" },
              finish_reason: null,
            },
          ],
        };
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(roleChunk)}\n\n`)
        );

        await new Promise((resolve) => setTimeout(resolve, 10));

        const contentChunk = {
          id: requestId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [
            {
              index: 0,
              delta: { content },
              finish_reason: null,
            },
          ],
        };
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(contentChunk)}\n\n`)
        );

        await new Promise((resolve) => setTimeout(resolve, 10));

        const finalChunk = {
          id: requestId,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model,
          choices: [
            {
              index: 0,
              delta: {},
              finish_reason: "stop",
            },
          ],
        };
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`)
        );

        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
  });
}

// Execute a single request to the chat completions API
async function executeChatRequest(
  targetUrl: string,
  requestBody: ChatCompletionRequest,
  headers: Record<string, string>,
  controller: ReadableStreamDefaultController<Uint8Array>,
  encoder: TextEncoder,
  requestId: string
): Promise<{
  messages: any[];
  toolCalls: Array<{
    id: string;
    name: string;
    arguments: any;
  }>;
  finished: boolean;
}> {
  const response = await fetch(targetUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(
      `API request failed: ${targetUrl} -  ${response.status} - ${message}`
    );
  }

  if (!response.body) {
    throw new Error("No response body");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let assistantMessage = "";
  let toolCalls: Array<{ id: string; name: string; arguments: any }> = [];
  let toolCallBuffer = new Map<number, any>();
  let finished = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value);
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data: ") || line === "data: [DONE]") {
          continue;
        }

        try {
          const data: StreamChunk = JSON.parse(line.slice(6));
          const choice = data.choices[0];

          // Stream content chunks directly to the controller
          if (
            choice?.delta?.content ||
            choice.delta?.refusal ||
            choice.delta?.reasoning_content
          ) {
            assistantMessage += choice.delta.content || "";

            // Forward the content chunk with our request ID and model
            const contentChunk = {
              id: requestId,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: requestBody.model,
              choices: [
                {
                  index: 0,
                  delta: {
                    content: choice.delta.content,
                    refusal: choice.delta.refusal,
                    reasoning_content: choice.delta.reasoning_content,
                  },
                  finish_reason: null,
                },
              ],
            };
            controller.enqueue(
              encoder.encode(`data: ${JSON.stringify(contentChunk)}\n\n`)
            );
          }

          if (choice?.delta?.tool_calls) {
            for (const toolCall of choice.delta.tool_calls) {
              const toolIndex = toolCall.index;

              if (!toolCallBuffer.has(toolIndex)) {
                toolCallBuffer.set(toolIndex, {
                  id: "",
                  name: "",
                  arguments: "",
                });
              }

              const bufferedCall = toolCallBuffer.get(toolIndex);
              if (toolCall.id) bufferedCall.id = toolCall.id;
              if (toolCall.function?.name) {
                bufferedCall.name += toolCall.function.name;
              }
              if (toolCall.function?.arguments) {
                bufferedCall.arguments += toolCall.function.arguments;
              }
            }
          }

          if (choice?.finish_reason === "tool_calls") {
            // Process all buffered tool calls
            for (const bufferedCall of toolCallBuffer.values()) {
              if (bufferedCall.name && bufferedCall.arguments) {
                try {
                  const args = JSON.parse(bufferedCall.arguments);
                  toolCalls.push({
                    id: bufferedCall.id,
                    name: bufferedCall.name,
                    arguments: args,
                  });
                } catch (e) {
                  console.error("Error parsing tool call arguments:", e);
                }
              }
            }
            break;
          }

          if (choice?.finish_reason === "stop") {
            finished = true;
            break;
          }
        } catch (e) {
          // Ignore invalid JSON
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  // Build the messages to return
  const messages = [...requestBody.messages];

  if (assistantMessage || toolCalls.length > 0) {
    const assistantMsg: any = {
      role: "assistant",
      content: assistantMessage || null,
    };

    if (toolCalls.length > 0) {
      assistantMsg.tool_calls = toolCalls.map((tc) => ({
        id: tc.id,
        type: "function",
        function: {
          name: tc.name,
          arguments: JSON.stringify(tc.arguments),
        },
      }));
    }

    messages.push(assistantMsg);
  }

  return { messages, toolCalls, finished };
}
export const chatCompletionsMiddleware = async (
  request: Request,
  env: any,
  ctx: ExecutionContext,
  config: {
    llmEndpoint: string;
    headers: any;
    body: ChatCompletionRequest;
    userId: string;
  }
) => {
  const { body, headers, llmEndpoint, userId } = config;
  const url = new URL(request.url);

  // Require streaming
  if (!body.stream) {
    return new Response(
      JSON.stringify({
        error: {
          message: "This middleware requires stream: true to be set",
          type: "invalid_request_error",
        },
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  try {
    const requestId = `chatcmpl-${Date.now()}`;

    // Transform MCP tools if present
    let mcpToolMap:
      | Map<string, { serverUrl: string; originalName: string }>
      | undefined;

    if (body.tools && body.tools.length > 0) {
      // Get MCP providers (this is already available)
      const mcpProviders = await getMCPProviders(env, userId);

      const {
        transformedTools,
        mcpToolMap: toolMap,
        missingAuth,
        errors,
      } = transformMCPTools(mcpProviders, body.tools);

      // If there are configuration errors, return error stream
      if (errors.length > 0) {
        const stream = createErrorStream(errors, requestId, body.model);
        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          },
        });
      }

      // If authentication is missing, return auth instructions as stream
      if (missingAuth.length > 0) {
        const stream = createAuthInstructionStream(
          missingAuth,
          url.origin,
          requestId,
          body.model
        );

        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          },
        });
      }

      body.tools = transformedTools;
      mcpToolMap = toolMap;
    }

    // Create streaming response
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        try {
          let currentMessages = [...body.messages];
          let iterationCount = 0;
          const maxIterations = 10; // Prevent infinite loops

          // Send initial role chunk
          const roleChunk = {
            id: requestId,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: body.model,
            choices: [
              {
                index: 0,
                delta: { role: "assistant" },
                finish_reason: null,
              },
            ],
          };
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify(roleChunk)}\n\n`)
          );

          while (iterationCount < maxIterations) {
            iterationCount++;
            console.log(`🔄 Chat iteration:`, iterationCount);
            const requestBody = {
              ...body,
              model: body.model,
              messages: currentMessages,
              stream: true,
            };

            const { messages, toolCalls, finished } = await executeChatRequest(
              llmEndpoint,
              requestBody,
              headers,
              controller,
              encoder,
              requestId
            );

            currentMessages = messages;

            // If no tool calls or finished, we're done
            if (toolCalls.length === 0 || finished) {
              break;
            }

            console.log(`🛠️  Processing ${toolCalls.length} tool calls`);

            // Execute tool calls and add results to conversation
            for (const toolCall of toolCalls) {
              if (mcpToolMap && toolCall.name.startsWith("mcp_")) {
                const toolInfo = mcpToolMap.get(toolCall.name);
                if (toolInfo) {
                  const hostname = new URL(toolInfo.serverUrl).hostname;
                  const toolInput = `

<details><summary>🔧 ${toolInfo.originalName} (${hostname})</summary>

\`\`\`json
${JSON.stringify(toolCall.arguments, undefined, 2)}
\`\`\`

</details>`;

                  const inputChunk = {
                    id: requestId,
                    object: "chat.completion.chunk",
                    created: Math.floor(Date.now() / 1000),
                    model: body.model,
                    choices: [
                      {
                        index: 0,
                        delta: { content: toolInput },
                        finish_reason: null,
                      },
                    ],
                  };
                  controller.enqueue(
                    encoder.encode(`data: ${JSON.stringify(inputChunk)}\n\n`)
                  );

                  // Session initialization happens here, when tools are actually executed
                  const result = await executeMCPTool(
                    url.origin,
                    env,
                    userId,
                    toolInfo.serverUrl,
                    toolInfo.originalName,
                    toolCall.arguments
                  );

                  currentMessages.push({
                    role: "tool",
                    tool_call_id: toolCall.id,
                    content: result,
                  });

                  // Stream tool execution result
                  const toolFeedback = `\n\n${result}\n\n`;

                  const toolChunk = {
                    id: requestId,
                    object: "chat.completion.chunk",
                    created: Math.floor(Date.now() / 1000),
                    model: body.model,
                    choices: [
                      {
                        index: 0,
                        delta: { content: toolFeedback },
                        finish_reason: null,
                      },
                    ],
                  };
                  controller.enqueue(
                    encoder.encode(`data: ${JSON.stringify(toolChunk)}\n\n`)
                  );
                }
              }
            }
          }

          // Send final chunk
          const finalChunk = {
            id: requestId,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: body.model,
            choices: [
              {
                index: 0,
                delta: {},
                finish_reason: "stop",
              },
            ],
          };
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`)
          );

          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
        } catch (error) {
          console.error("Stream error:", error);
          controller.error(error);
        }
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  } catch (error) {
    console.error("Proxy error:", error);
    return new Response(
      JSON.stringify({
        error: {
          message: "Internal server error",
          type: "internal_error",
        },
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
};
