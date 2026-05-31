# HTB Partial Encryption - Packer Behavior

## Description

Static-Analysis on this program didn't reveal much. There must be a better way to approach this...

## Solution

Running the program, we can see that we need to run it with the flag as an argument. The program was compiled with MSVC (we can determine that since it uses functions such as `__scrt_initialize_crt`, `_get_initial_narrow_environment`).

Analyzing it in Ghidra, we can go straight to the entry point. From there we can locate the main, by looking for argc and argv and jumping to the function that uses them:  
![main](posts/images/partial-encryption/image.png)

The main function calls 4 different functions. Each one has the same behavior: It calls the `FUN_140001050` function with some arguments, gets back a pointer to code (`code *` in Ghidra), calls the code and calls `VirtualFree`.

```c

void FUN_140001130(undefined8 param_1,undefined8 param_2,int param_3)

{
  code *pcVar1;
  
  if (param_3 != 2) {
    pcVar1 = (code *)FUN_140001050(0x140004000,0x70);
    (*pcVar1)(param_1,param_2);
    VirtualFree(pcVar1,0,0x8000);
    pcVar1 = (code *)FUN_140001050(0x140004110,0x30);
    (*pcVar1)(param_1,param_2);
    VirtualFree(pcVar1,0,0x8000);
  }
  return;
}
```

This is a very interesting behavior. Let's analyze the `FUN_140001050` function:
```c

LPVOID FUN_140001050(longlong param_1,int param_2)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  undefined8 extraout_XMM0_Qb;
  int local_38;
  DWORD local_34;
  LPVOID local_30;
  undefined1 local_28 [16];
  undefined1 local_18 [24];
  
  local_30 = VirtualAlloc((LPVOID)0x0,(longlong)param_2,0x1000,4);
  for (local_38 = 0; local_38 < (int)(param_2 + (param_2 >> 0x1f & 0xfU)) >> 4;
      local_38 = local_38 + 1) {
    local_28._0_2_ = CONCAT11((undefined1)local_38,(undefined1)local_38);
    local_28._2_2_ = local_28._0_2_;
    puVar1 = (undefined8 *)(param_1 + (longlong)local_38 * 0x10);
    local_18._0_8_ = *puVar1;
    local_18._8_8_ = puVar1[1];
    local_28._4_4_ = local_28._0_4_;
    local_28._8_4_ = local_28._0_4_;
    local_28._12_4_ = local_28._0_4_;
    uVar2 = FUN_140001000((undefined1 (*) [16])local_18,&local_28);
    puVar1 = (undefined8 *)((longlong)local_30 + (longlong)local_38 * 0x10);
    *puVar1 = uVar2;
    puVar1[1] = extraout_XMM0_Qb;
  }
  VirtualProtect(local_30,(longlong)param_2,0x20,&local_34);
  return local_30;
}
```
The function is allocating memory for writing (4 in `VirtualAlloc` is `PAGE_READWRITE`). It is looping through some data, in blocks of 16 bytes, and calling the `FUN_140001000` function with the data and some other parameters. The result of the function is being written to the allocated memory. Finally, it changes the permissions of the allocated memory to `PAGE_EXECUTE_READ`, meaning it can execute the code that was written there.  
This is a classic packer behavior - decrypting code at runtime, writing it to memory and executing it. The decryption function is `FUN_140001000`, and it does some AES operations:
```c

undefined8 FUN_140001000(undefined1 (*param_1) [16],undefined1 (*param_2) [16])

{
  undefined1 auVar1 [16];
  undefined1 auVar2 [16];
  
  auVar1 = aeskeygenassist(*param_2,0);
  auVar2 = aeskeygenassist(*param_2,0x10);
  auVar1 = aesdeclast(*param_1 ^ auVar2,auVar1);
  return auVar1._0_8_;
}
```  
Essentially, every time we want to execute some code, we pass its encrypted code to the `FUN_140001050` function, which decrypts and executes it.

From the description it seems that we should just analyze it at runtime, and dump the decrypted code from memory.  

There are multiple ways to do this, but I just debugged the code in IDA. Every time I saw the decryption stub being called, I set a breakpoint on the instruction which jumps to the decrypted code:
![IDA](posts/images/partial-encryption/image-1.png)

The first function is checking that we provided an argument. The second one is checking the flag length (we don't need to see the decrypted code to figure that out):
```c

void FUN_1400012b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,longlong param_4)

{
  code *pcVar1;
  undefined4 local_38;
  
  for (local_38 = 0; local_38 < 0x16; local_38 = local_38 + 1) {
    if (*(char *)(*(longlong *)(param_4 + 8) + (longlong)local_38) == '\0') {
      pcVar1 = (code *)FUN_140001050(0x140004070,0x40);
      (*pcVar1)(param_1,param_2);
      VirtualFree(pcVar1,0,0x8000);
      pcVar1 = (code *)FUN_140001050(0x140004110,0x30);
      (*pcVar1)(param_1,param_2);
      VirtualFree(pcVar1,0,0x8000);
    }
  }
  return;
}

```

After that, we can analyze at runtime the decrypted code, which is simply checking the flag, character by character, for example:
![flag](posts/images/partial-encryption/image-2.png)  

Following the same process for every character, we eventually get the full flag. We can also write an IDA script to do it automatically.
