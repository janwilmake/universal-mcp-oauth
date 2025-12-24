/// <reference types="@cloudflare/workers-types" />
import {
  createUniversalOAuthHandler,
  OAuthProviders,
  UniversalOAuthEnv,
  OAuthProvider,
} from "./universal-oauth";

export { OAuthProviders };

export interface MCPOAuthEnv extends UniversalOAuthEnv {}

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: any;
  outputSchema?: any;
}

export interface MCPProvider extends OAuthProvider {
  tools?: MCPTool[];
}

export interface ClientInfo {
  name: string;
  title: string;
  version: string;
}

// --- MCP-Specific Functions ---

async function parseMCPSSEResponse(response: Response): Promise<any> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const jsonStr = line.substring(6);
          try {
            const data = JSON.parse(jsonStr);
            if (data.result) return data;
          } catch (e) {
            continue;
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  throw new Error("Could not parse SSE response");
}

export async function extractMCPServerInfo(
  clientInfo: ClientInfo,
  mcpUrl: string,
  accessToken?: string,
): Promise<{ serverName: string; tools: MCPTool[] }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json,text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  // Initialize connection
  const initResponse = await fetch(mcpUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: { roots: { listChanged: true }, sampling: {} },
        clientInfo: { name: clientInfo.name, version: clientInfo.version },
      },
    }),
  });

  if (!initResponse.ok) {
    const errorText = await initResponse.text();
    throw new Error(`MCP init failed: ${initResponse.status} - ${errorText}`);
  }

  const sessionId = initResponse.headers.get("Mcp-Session-Id");
  const contentType = initResponse.headers.get("content-type") || "";
  let serverName: string;

  if (contentType.includes("text/event-stream")) {
    const initResult = await parseMCPSSEResponse(initResponse);
    if (!initResult.result?.serverInfo?.name) {
      throw new Error("Could not extract server name from SSE response");
    }
    serverName = initResult.result.serverInfo.name;
  } else {
    const initData = (await initResponse.json()) as any;
    if (!initData.result?.serverInfo?.name) {
      throw new Error("Could not extract server name from JSON response");
    }
    serverName = initData.result.serverInfo.name;
  }

  // Send initialized notification
  if (sessionId) {
    const notifyHeaders = { ...headers, "Mcp-Session-Id": sessionId };
    await fetch(mcpUrl, {
      method: "POST",
      headers: notifyHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialized",
        params: {},
      }),
    });
  }

  // List tools
  const toolsHeaders = sessionId
    ? { ...headers, "Mcp-Session-Id": sessionId }
    : headers;
  const toolsResponse = await fetch(mcpUrl, {
    method: "POST",
    headers: toolsHeaders,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    }),
  });

  let tools: MCPTool[] = [];

  if (toolsResponse.ok) {
    const toolsContentType = toolsResponse.headers.get("content-type") || "";

    try {
      if (toolsContentType.includes("text/event-stream")) {
        const toolsResult = await parseMCPSSEResponse(toolsResponse);
        if (Array.isArray(toolsResult.result?.tools)) {
          tools = toolsResult.result.tools;
        }
      } else {
        const toolsData = (await toolsResponse.json()) as any;
        if (Array.isArray(toolsData.result?.tools)) {
          tools = toolsData.result.tools;
        }
      }
    } catch (e) {
      // Tools list failed, continue without tools
    }
  }

  return { serverName, tools };
}

// --- MCP OAuth Handler ---

export interface MCPOAuthConfig {
  userId: string;
  clientInfo: ClientInfo;
  baseUrl?: string;
  pathPrefix?: string;
}

export interface MCPOAuthHandlers {
  middleware: (
    request: Request,
    env: MCPOAuthEnv,
    ctx: ExecutionContext,
  ) => Promise<Response | null>;
  removeMcp: (url: string) => Promise<void>;
  getProviders: () => Promise<(MCPProvider & { reauthorizeUrl: string })[]>;
  refreshProviders: (urls: string[]) => Promise<void>;
  getAuthorizationForUrl: (
    url: string,
  ) => Promise<{ Authorization: string } | null>;
}

export function createMCPOAuthHandler(
  config: MCPOAuthConfig,
  env: MCPOAuthEnv,
): MCPOAuthHandlers | null {
  const { userId, baseUrl, clientInfo, pathPrefix = "/mcp" } = config;

  const universalHandler = createUniversalOAuthHandler(
    {
      userId,
      clientInfo: { name: clientInfo.name, version: clientInfo.version },
      baseUrl,
      pathPrefix,
      onAuthSuccess: async (resourceUrl: string, accessToken: string) => {
        // For MCP servers, extract server info and tools
        try {
          const { serverName, tools } = await extractMCPServerInfo(
            clientInfo,
            resourceUrl,
            accessToken || undefined,
          );
          return {
            name: serverName,
            metadata: { tools, type: "mcp" },
          };
        } catch (e) {
          const hostname = new URL(resourceUrl).hostname;
          return { name: hostname, metadata: { type: "mcp" } };
        }
      },
    },
    env,
  );

  if (!universalHandler) return null;

  return {
    middleware: universalHandler.middleware,
    removeMcp: universalHandler.removeProvider,
    refreshProviders: universalHandler.refreshProviders,
    getAuthorizationForUrl: universalHandler.getAuthorizationForUrl,
    getProviders: async () => {
      const providers = await universalHandler.getProviders();
      return providers.map((p) => ({
        ...p,
        tools: p.metadata?.tools as MCPTool[] | undeined,
      }));
    },
  };
}
