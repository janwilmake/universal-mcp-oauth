# OAuth MCP Server Test Results

## ✅ Working Servers (OAuth2.1)

These servers successfully completed the OAuth registration process:

- **Audioscrape** - RAG-as-a-Service (`https://mcp.audioscrape.com`)
- **Cloudflare Workers** - Software Development (`https://bindings.mcp.cloudflare.com/sse`)
- **Cloudflare Observability** - Observability (`https://observability.mcp.cloudflare.com/sse`)
- **Linear** - Project Management (`https://mcp.linear.app/sse`)
- **Listenetic** - Productivity (`https://mcp.listenetic.com/v1/mcp`)
- **Neon** - Software Development (`https://mcp.neon.tech/sse`)
- **Notion** - Project Management (`https://mcp.notion.com/sse`)
- **PayPal** - Payments (`https://mcp.paypal.com/sse`)
- **Prisma Postgres** - Database (`https://mcp.prisma.io/mcp`)
- **Scorecard** - AI Evaluation (`https://scorecard-mcp.dare-d5b.workers.dev/sse`)
- **Square** - Payments (`https://mcp.squareup.com/sse`)
- **Webflow** - CMS (`https://mcp.webflow.com/sse`)
- **Wix** - CMS (`https://mcp.wix.com/sse`)
- **Simplescraper** - Web Scraping (`https://mcp.simplescraper.io/mcp`)

## 🚫 Redirect URI Not Allowed

These servers rejected the redirect URI `https://connect.simplerauth.com`:

- **Asana** - Project Management
- **Atlassian** - Software Development
- **Canva** - Design
- **Intercom** - Customer Support
- **Stripe** - Payments

## 🔧 Requires Code Challenge (PKCE)

These servers require PKCE implementation for OAuth flow:

- **Meta Ads by Pipeboard** - Advertising
- **Kollektiv** - Documentation

## 🌐 CORS Errors

These servers have cross-origin request issues:

- **Octagon** - Market Intelligence
- **WayStation** - Productivity

## 📋 Registration Required / Account Issues

These servers work but require additional setup:

- **Dialer** - Outbound Phone Calls (registration needed, call not received)
- **Turkish Airlines** - Airlines (requires account, no easy signup)
- **monday.com** - Productivity (seems OK but no easy registration)

## ❓ Missing Well-Known Server Info

These servers don't provide proper OAuth discovery endpoints:

- **GitHub** - Software Development
- **Invidio** - Video Platform
- **OpenZeppelin Cairo Contracts** - Software Development
- **OpenZeppelin Solidity Contracts** - Software Development
- **OpenZeppelin Stellar Contracts** - Software Development
- **OpenZeppelin Stylus Contracts** - Software Development
- **Plaid** - Payments
- **Sentry** - Software Development
- **Grafbase** - Software Development

## 🔑 API Key Authentication

These servers use API key authentication instead of OAuth:

- **OneContext** - RAG-as-a-Service (requires filling API Key)
- **HubSpot** - CRM
- **Needle** - RAG-as-a-service
- **Zapier** - Automation
- **Apify** - Web Data Extraction Platform
- **Dappier** - RAG-as-a-Service
- **Mercado Libre** - E-Commerce
- **Mercado Pago** - Payments
- **Short.io** - Link shortener
- **Telnyx** - Communication
- **Dodo Payments** - Payments
- **Polar Signals** - Software Development

## 🔓 Open Authentication

These servers don't require authentication:

- **Find-A-Domain** - Productivity (no well-known server info)
- **Cloudflare Docs** - Documentation
- **Astro Docs** - Documentation
- **DeepWiki** - RAG-as-a-Service
- **Hugging Face** - Software Development
- **Semgrep** - Software Development
- **Remote MCP** - MCP Directory
- **LLM Text** - Data Analysis
- **GitMCP** - Software Development
- **Manifold** - Forecasting

## 📊 Summary Statistics

- **Working OAuth2.1 Servers**: 14/39 (36%)
- **Redirect URI Issues**: 5/39 (13%)
- **Technical Issues (CORS/PKCE)**: 4/39 (10%)
- **Missing Discovery**: 9/39 (23%)
- **API Key Only**: 12/39 (31%)
- **Open Access**: 9/39 (23%)

_Note: Some servers may fall into multiple categories_
