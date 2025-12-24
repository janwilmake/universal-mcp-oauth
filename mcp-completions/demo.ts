import { withSimplerAuth } from "simplerauth-client";
import { chatCompletionsProxy, OAuthProviders } from "./mcp-completions";

export { OAuthProviders };

const HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Completions Demo</title>
    <style>
        @font-face {
            font-family: 'FTSystemMono';
            src: url('https://assets.p0web.com/FTSystemMono-Regular.woff2') format('woff2');
            font-weight: 400;
            font-style: normal;
        }

        :root {
            --off-white: #fcfcfa;
            --index-black: #1d1b16;
            --neural: #d8d0bf;
            --signal: #fb631b;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'FTSystemMono', monospace;
            background: var(--off-white);
            color: var(--index-black);
            line-height: 1.4;
            min-height: 100vh;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        h1 {
            font-size: 2rem;
            margin-bottom: 1rem;
            color: var(--signal);
        }

        .user-info {
            background: var(--neural);
            padding: 0.75rem 1rem;
            border-radius: 4px;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }

        .section {
            background: white;
            border: 1px solid var(--neural);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .section h2 {
            font-size: 1.1rem;
            margin-bottom: 1rem;
            color: var(--signal);
        }

        textarea {
            width: 100%;
            font-family: 'FTSystemMono', monospace;
            font-size: 0.85rem;
            padding: 1rem;
            border: 1px solid var(--neural);
            border-radius: 4px;
            background: #f8f9fa;
            resize: vertical;
        }

        #requestBody {
            min-height: 400px;
        }

        button {
            background: var(--signal);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-family: 'FTSystemMono', monospace;
            font-size: 0.9rem;
            font-weight: 500;
            margin-top: 1rem;
        }

        button:hover:not(:disabled) {
            opacity: 0.9;
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .response {
            min-height: 200px;
            white-space: pre-wrap;
            font-size: 0.85rem;
            line-height: 1.6;
            overflow-x: auto;
        }

        .response.streaming {
            border-left: 3px solid var(--signal);
            padding-left: 1rem;
        }

        .error {
            color: #dc2626;
            background: #fef2f2;
            padding: 1rem;
            border-radius: 4px;
        }

        .info {
            font-size: 0.8rem;
            color: #666;
            margin-top: 0.5rem;
        }
    </style>
    <script id="user-data" type="application/json"></script>
</head>
<body>
    <div class="container">
        <h1>MCP Completions Demo</h1>
        
        <div class="user-info" id="userInfo">Loading...</div>

        <div class="section">
            <h2>Request Body (POST /chat/completions)</h2>
            <textarea id="requestBody"></textarea>
            <p class="info">Edit the JSON above to modify the request. The request will be sent to the proxy endpoint.</p>
            <button id="submitBtn" onclick="submitRequest()">Submit Request</button>
        </div>

        <div class="section">
            <h2>Response</h2>
            <div id="response" class="response">Response will appear here...</div>
        </div>
    </div>

    <script>
        const DEFAULT_REQUEST = {
            model: "gpt-4o",
            stream: true,
            stream_options: { include_usage: true },
            tools: [
                {
                    type: "mcp",
                    server_url: "https://task-mcp.parallel.ai/mcp",
                    require_approval: "never"
                },
                {
                    type: "url_context",
                    max_urls: 5
                }
            ],
            messages: [
                {
                    role: "user",
                    content: "Please read this file and summarize what it does: https://raw.githubusercontent.com/anthropics/anthropic-cookbook/main/misc/prompt_caching.ipynb"
                }
            ]
        };

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Set user info
            try {
                const userData = JSON.parse(document.getElementById('user-data').textContent);
                if (userData && userData.name) {
                    document.getElementById('userInfo').textContent = 'Logged in as: ' + (userData.name || userData.username || userData.id);
                } else {
                    document.getElementById('userInfo').textContent = 'Authenticated';
                }
            } catch (e) {
                document.getElementById('userInfo').textContent = 'Authenticated';
            }

            // Set default request body
            document.getElementById('requestBody').value = JSON.stringify(DEFAULT_REQUEST, null, 2);
        });

        async function submitRequest() {
            const requestBody = document.getElementById('requestBody').value;
            const responseDiv = document.getElementById('response');
            const submitBtn = document.getElementById('submitBtn');

            // Validate JSON
            let parsedBody;
            try {
                parsedBody = JSON.parse(requestBody);
            } catch (e) {
                responseDiv.className = 'response error';
                responseDiv.textContent = 'Invalid JSON: ' + e.message;
                return;
            }

            submitBtn.disabled = true;
            responseDiv.textContent = '';
            responseDiv.className = 'response streaming';

            try {
                const response = await fetch('/chat/completions', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: requestBody
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error('HTTP ' + response.status + ': ' + errorText);
                }

                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                let fullContent = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value);
                    const lines = buffer.split('\\n');
                    buffer = lines.pop() || '';

                    for (const line of lines) {
                        if (!line.startsWith('data: ') || line === 'data: [DONE]') {
                            continue;
                        }

                        try {
                            const data = JSON.parse(line.slice(6));
                            const choice = data.choices?.[0];
                            if (choice?.delta) {
                                if (choice.delta.content) {
                                    fullContent += choice.delta.content;
                                    responseDiv.textContent = fullContent;
                                }
                                if (choice.delta.reasoning_content) {
                                    fullContent += choice.delta.reasoning_content;
                                    responseDiv.textContent = fullContent;
                                }
                            }
                            if (data.usage) {
                                fullContent += '\\n\\n---\\nUsage: ' + JSON.stringify(data.usage);
                                responseDiv.textContent = fullContent;
                            }
                        } catch (e) {
                            // Ignore parse errors
                        }
                    }
                }

                responseDiv.className = 'response';

            } catch (error) {
                console.error('Request failed:', error);
                responseDiv.textContent = 'Error: ' + error.message;
                responseDiv.className = 'response error';
            } finally {
                submitBtn.disabled = false;
            }
        }
    </script>
</body>
</html>
`;

class DataInjector {
  userData: any;
  constructor(userData: any) {
    this.userData = userData;
  }

  element(element: Element) {
    element.setInnerContent(JSON.stringify(this.userData || {}), {
      html: false,
    });
  }
}

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      const url = new URL(request.url);

      // Initialize the proxy with user context
      const { idpMiddleware, fetchProxy, getProviders, removeMcp } =
        chatCompletionsProxy(env, {
          baseUrl: new URL(request.url).origin,
          userId: ctx.user!.id,
          clientInfo: {
            name: "MCP Completions Demo",
            title: "MCP Completions Demo",
            version: "1.0.0",
          },
        });

      // Handle MCP OAuth routes
      const mcpResponse = await idpMiddleware(request, env, ctx);
      if (mcpResponse) {
        return mcpResponse;
      }

      // Handle main page
      if (url.pathname === "/" && request.method === "GET") {
        const response = new Response(HTML_TEMPLATE, {
          headers: { "Content-Type": "text/html" },
        });

        return new HTMLRewriter()
          .on('script[id="user-data"]', new DataInjector(ctx.user))
          .transform(response);
      }

      // Handle chat completions endpoint
      if (url.pathname === "/chat/completions" && request.method === "POST") {
        // Use OpenAI as the default backend
        const llmEndpoint = "https://api.openai.com/v1/chat/completions";

        return fetchProxy(llmEndpoint, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.OPENAI_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: request.body,
        });
      }

      return new Response("Not Found", { status: 404 });
    },
    { isLoginRequired: true },
  ),
};
