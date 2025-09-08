# RFC: Simplify OAuth with Domain-as-Client-ID Principle - Alternative to SEP 991

<!-- Drafted: https://letmeprompt.com/rules-httpsuithu-qja9600 -->

## Background

I've been following the discussion around [SEP 991: OAuth Client ID Metadata Documents](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991) and while I appreciate the problem it's trying to solve, I believe there's a simpler and more secure approach that addresses the same core issues without the complexity and attack vectors.

## The Problem with Current Approaches

As highlighted in SEP 991, MCP faces a critical challenge:

- **Pre-registration** creates too much friction for the "no pre-existing relationship" scenario
- **DCR (current recommendation)** allows spoofing and requires servers to manage unbounded databases
- **Client ID Metadata Documents** introduce SSRF risks and localhost impersonation vulnerabilities

The localhost impersonation issue from SEP 991 is particularly concerning:

> An attacker can claim to be any client by providing the legitimate client's metadata URL as their client_id and binding to the same localhost port the legitimate client uses

## Proposed Solution: Domain-as-Client-ID Principle

I propose a radically simpler approach where:

**The `client_id` MUST equal the hostname of all `redirect_uris`**

### Core Rules

1. `client_id` = hostname of redirect URIs (e.g., `app.example.com`)
2. All `redirect_uris` must be on the same hostname as `client_id`
3. No external metadata fetching required
4. No client pre-registration or DCR needed

### Example Request

```json
{
  "client_id": "app.example.com",
  "redirect_uri": "https://app.example.com/oauth/callback",
  "response_type": "code",
  "scope": "read"
}
```

## How This Solves SEP 991's Problems

### ✅ Eliminates Localhost Impersonation

- Cannot use another domain's `client_id` with your `redirect_uri`
- Localhost clients are clearly identified as `localhost`
- **No metadata fetching means no impersonation vector**

### ✅ Prevents SSRF Attacks

- **Zero external URL fetching** eliminates Server-Side Request Forgery entirely
- No outbound HTTP requests to untrusted URLs

### ✅ Eliminates DDoS Risk

- No outbound requests means no DDoS amplification vector

### ✅ Perfect Transparency

- Users see exactly where they'll be redirected (the `client_id` hostname)
- No deception possible - can't fake the domain you redirect to

### ✅ Zero Infrastructure Requirements

- Clients need no HTTPS endpoints or JSON hosting
- Works perfectly for desktop/native applications

## Security Comparison

| Approach                | SSRF Risk | Localhost Safe | Infrastructure | Transparency |
| ----------------------- | --------- | -------------- | -------------- | ------------ |
| Pre-registration        | None      | Yes            | Server DB      | Medium       |
| DCR                     | None      | **No**         | Server DB      | **Poor**     |
| Metadata Documents      | **High**  | **No**         | Client HTTPS   | Medium       |
| **Domain-as-Client-ID** | **None**  | **Yes**        | **None**       | **Perfect**  |

## Implementation Simplicity

Server validation becomes trivial:

```javascript
function validateClient(clientId, redirectUri) {
  const redirectUrl = new URL(redirectUri);
  return clientId === redirectUrl.hostname;
}
```

No HTTP clients, no caching, no JSON parsing, no SSRF protection needed.

## Real-World Usage

I've been implementing this pattern in my [simplerauth](https://simplerauth.com) project (in particular: [simplerauth-provider](https://github.com/janwilmake/simplerauth-provider)) and it works beautifully. The user experience is actually better because:

1. **Clear identity**: Users know exactly what domain they're trusting
2. **No confusion**: Client name = domain name (honest and consistent)
3. **Instant trust decision**: "Do I trust app.example.com with my data?"

## Addressing Potential Concerns

**"What about client metadata like names and logos?"**

- Client name = domain name (more honest anyway)
- Logo = favicon from the domain (automated)
- Reduces opportunity for deception

**"What about multiple redirect URIs?"**

- All must be on same hostname as `client_id`
- Subdomains can be supported with clear policies
- Maintains security model

**"What about native/mobile apps?"**

- Custom URL schemes: `myapp://` client_id matches `myapp://callback`
- App store validation provides trust anchor
- Could require additional attestation if needed

## Comparison to SEP 991

| Aspect            | SEP 991 Metadata Docs                | Domain-as-Client-ID          |
| ----------------- | ------------------------------------ | ---------------------------- |
| Implementation    | Complex (HTTP client, caching, JSON) | Simple (hostname comparison) |
| Security          | SSRF + localhost risks               | No attack vectors            |
| Infrastructure    | Requires HTTPS hosting               | Zero requirements            |
| User transparency | Shows fetched metadata               | Shows actual destination     |
| Localhost safety  | Vulnerable to impersonation          | Naturally safe               |

## Next Steps

I'd love to get community feedback on this approach. If there's interest, I can:

1. Create a formal SEP document with detailed specification
2. Provide a complete prototype implementation
3. Show how this integrates with existing MCP auth flows

This approach achieves all the goals of SEP 991 (no pre-coordination, server-controlled trust) but with significantly better security properties and implementation simplicity.

What do you think? Does this address the core issue in a cleaner way?

## References

- [My detailed blog post on this approach](https://github.com/janwilmake/simplerauth-provider/blob/main/BLOG.md)
- [SEP 991: OAuth Client ID Metadata Documents](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991)
- [Simplerauth website](https://simplerauth.com)

---

_This is my first post here. Looking forward to the discussion and happy to iterate on this proposal based on community feedback!_
