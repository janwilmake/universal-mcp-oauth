# SEP: Domain-as-Client-ID OAuth for MCP

**Title:** Domain-as-Client-ID OAuth Authentication for Model Context Protocol  
**Author:** Jan Wilmake (@janwilmake)  
**Status:** Draft  
**Type:** Standards Track  
**Created:** 2025-08-30

## Abstract

This SEP proposes a simplified OAuth client identification mechanism where `client_id` must equal the hostname of all redirect URIs. This eliminates the need for metadata documents, client registration, or Dynamic Client Registration while providing stronger security guarantees and solving the localhost impersonation issue identified in the Client ID Metadata Documents proposal.

## Motivation

The current Client ID Metadata Documents SEP (SEP-XXX) introduces complexity through HTTPS fetching, caching, and SSRF risks while still being vulnerable to localhost URL impersonation. The Domain-as-Client-ID principle provides a simpler, more secure alternative that:

1. **Eliminates localhost impersonation** - Attackers cannot claim arbitrary client identities
2. **Removes infrastructure requirements** - No metadata hosting needed
3. **Prevents SSRF attacks** - No URL fetching required
4. **Increases transparency** - Users see exactly which domain they're authorizing
5. **Reduces deception** - Cannot fake the domain you redirect to

## Specification

### Client Requirements

- `client_id` MUST equal the hostname portion of all `redirect_uris`
- All `redirect_uris` MUST use the same hostname as `client_id`
- For custom schemes: `client_id` MUST equal the scheme (e.g., `myapp://`)

### Server Requirements

- Servers MUST validate that `client_id` equals the hostname of all `redirect_uris`
- Servers MUST reject requests where this validation fails
- Servers MAY automatically derive client metadata from the domain (favicon, name)

### Example

```json
{
  "client_id": "app.example.com",
  "redirect_uris": [
    "https://app.example.com/oauth/callback",
    "https://app.example.com/auth/complete"
  ],
  "response_type": "code",
  "scope": "read"
}
```

## Security Analysis

This approach eliminates the key vulnerabilities in the Metadata Documents approach:

1. **No localhost impersonation** - An attacker cannot claim `client_id: "trustedapp.com"` while using `localhost` redirect URIs
2. **No SSRF attacks** - No URL fetching means no server-side requests
3. **No metadata manipulation** - No external documents to forge
4. **Cryptographic binding** - The redirect destination IS the client identity

## Comparison with Metadata Documents Approach

| Aspect             | Metadata Documents          | Domain-as-Client-ID          |
| ------------------ | --------------------------- | ---------------------------- |
| Infrastructure     | Requires HTTPS hosting      | None required                |
| Security           | SSRF + localhost risks      | No additional attack vectors |
| Complexity         | HTTP client + caching       | Simple string comparison     |
| Transparency       | Shows metadata name         | Shows actual destination     |
| Localhost handling | Vulnerable to impersonation | Naturally secure             |

## Rationale

The core insight is that what users really need to understand is **where they'll be redirected after authorization**. By making the `client_id` equal to that destination, we:

- Eliminate the possibility of deception
- Remove the need for external metadata
- Provide perfect transparency about what the user is authorizing
- Maintain the same "no pre-coordination" benefit

## Implementation

Servers can implement this with a simple validation:

```javascript
function validateDomainClientId(clientId, redirectUris) {
  return redirectUris.every((uri) => {
    const url = new URL(uri);
    return url.hostname === clientId;
  });
}
```
