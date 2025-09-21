import {
  createMCPOAuthHandler,
  getAuthorization,
  getMCPProviders,
  MCPOAuthEnv,
} from "universal-mcp-oauth";

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

// Execute MCP tool and return result content
async function executeMCPTool(
  env: MCPOAuthEnv,
  userId: string,
  serverUrl: string,
  toolName: string,
  args: any
): Promise<string> {
  try {
    const authHeaders = await getAuthorization(env, userId, serverUrl);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json,text/event-stream",
      "MCP-Protocol-Version": "2025-06-18",
    };

    if (authHeaders?.Authorization) {
      headers.Authorization = authHeaders.Authorization;
    }

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

    if (!response.ok) {
      return `Tool ${toolName} failed with status ${response.status}`;
    }

    const result = await response.json();
    const content = result.result?.content;

    if (!content || !Array.isArray(content)) {
      return `Tool ${toolName} returned invalid response`;
    }

    // Combine all content items into a single string
    let combinedContent = "";
    for (const item of content) {
      if (item.type === "text") {
        combinedContent += item.text;
      } else if (item.type === "image") {
        combinedContent += `[Image: ${item.data}]`;
      } else {
        combinedContent += JSON.stringify(item);
      }
    }

    return combinedContent;
  } catch (error) {
    return `Tool ${toolName} execution failed: ${error.message}`;
  }
}

// Transform MCP tools to function tools
async function transformMCPTools(
  env: MCPOAuthEnv,
  userId: string,
  tools: Array<any>
): Promise<{
  transformedTools: Array<any>;
  mcpToolMap: Map<string, { serverUrl: string; originalName: string }>;
  missingAuth: string[];
}> {
  const transformedTools: Array<any> = [];
  const mcpToolMap = new Map<
    string,
    { serverUrl: string; originalName: string }
  >();
  const missingAuth: string[] = [];

  const mcpProviders = await getMCPProviders(env, userId);

  for (const tool of tools) {
    if (tool.type === "function") {
      transformedTools.push(tool);
    } else if (tool.type === "mcp") {
      const provider = mcpProviders.find((x) => x.mcp_url === tool.server_url);

      if (!provider || !provider.access_token) {
        missingAuth.push(tool.server_url);
        continue;
      }

      const availableTools = (provider.tools as unknown as any[]) || [];

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

  return { transformedTools, mcpToolMap, missingAuth };
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
            assistantMessage += choice.delta.content;

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

export const userChatCompletion = async (
  request: Request,
  env: MCPOAuthEnv,
  ctx: ExecutionContext,
  config: {
    targetUrl: string;
    headers: any;
    body: ChatCompletionRequest;
    clientInfo: {
      name: string;
      title: string;
      version: string;
    };
    userId: string;
  }
) => {
  const { body, clientInfo, headers, targetUrl, userId } = config;
  const url = new URL(request.url);

  const mcpOAuthHandler = createMCPOAuthHandler({
    userId,
    clientInfo,
    baseUrl: url.origin,
  });

  const mcpResponse = await mcpOAuthHandler(request, env, ctx);
  if (mcpResponse) {
    return mcpResponse;
  }

  try {
    // Force streaming for internal requests (we'll handle the final streaming)
    const requestId = `chatcmpl-${Date.now()}`;

    // Transform MCP tools if present
    let mcpToolMap:
      | Map<string, { serverUrl: string; originalName: string }>
      | undefined;

    if (body.tools && body.tools.length > 0) {
      const {
        transformedTools,
        mcpToolMap: toolMap,
        missingAuth,
      } = await transformMCPTools(env, userId, body.tools);

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
            console.log(`iteration:`, iterationCount);
            const requestBody = {
              ...body,
              model: body.model,
              messages: currentMessages,
              stream: true,
            };

            const { messages, toolCalls, finished } = await executeChatRequest(
              targetUrl,
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

            // Execute tool calls and add results to conversation
            for (const toolCall of toolCalls) {
              if (mcpToolMap && toolCall.name.startsWith("mcp_")) {
                const toolInfo = mcpToolMap.get(toolCall.name);
                if (toolInfo) {
                  const hostname = new URL(toolInfo.serverUrl).hostname;
                  const toolInput = `\n\n**🔧 ${
                    toolInfo.originalName
                  }** (${hostname}): ${JSON.stringify(toolCall.arguments)}`;

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

                  const result = await executeMCPTool(
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

                  // Stream tool execution feedback
                  const toolFeedback = `\n\n**Result**\n\n (${result?.length} characters)\n\n`;

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
