# HTB VirtuallyMad — Custom VM Reverse Engineering

The challenge binary implements a simple virtual machine. We supply a string of hex-encoded opcodes and the VM executes them. The goal is to produce exactly 5 instructions that leave the registers in a specific state.

## VM Architecture

The VM context is a 56-byte struct (`0x38`) allocated with `calloc`. It holds four 32-bit registers and four pointer-sized entries pointing back to those registers:

```c
undefined4 * init_vm(void) {
    undefined4 *vm = calloc(1, 0x38);
    // regs[0..3] initialised to 0
    vm->reg_ptrs[0] = &vm->regs[0];
    vm->reg_ptrs[1] = &vm->regs[1];
    vm->reg_ptrs[2] = &vm->regs[2];
    vm->reg_ptrs[3] = &vm->regs[3];
    return vm;
}
```

The binary reads the input as pairs of 8 hex characters, converting each to a 32-bit opcode. It validates exactly 5 opcodes and dispatches each through a function table indexed by the top 8 bits.

## Instruction Set

Each 32-bit opcode encodes the operation in bits 28–24, a destination register in bits 23–16, a mode flag in bits 15–12, and an immediate or source-register index in bits 11–0.

| Opcode byte | Operation | Constraint |
|-------------|-----------|-----------|
| `0x01`      | MOV       | bits 20–16 = dest; mode 0 = immediate, mode 1 = reg |
| `0x02`      | ADD       | adds immediate or reg to dest |
| `0x03`      | SUB       | subtracts immediate or reg from dest |
| `0x04`      | (special) | sets `vm->extra` field |

The immediate value in the lower 12 bits must be `<= 0x100`.

## Win Condition

The program prints the flag when all five conditions are satisfied:

```c
if (regs[0] == 0x200 &&
    regs[1] == 0xFFFFFFFF &&
    regs[2] == 0xFFFFFFFF &&
    regs[3] == 0 &&
    vm->extra == 0x10000000 &&
    instruction_count == 5)
```

## Crafting the Payload

- **reg[0] = 0x200**: `ADD reg[0], 0x100` twice (max immediate is `0x100`)
- **reg[1] = 0xFFFFFFFF**: `SUB reg[1], 1` (wraps to −1 for an unsigned 32-bit value)
- **reg[2] = 0xFFFFFFFF**: `MOV reg[2], reg[1]` — copy from reg[1] using mode 1
- **vm->extra = 0x10000000**: opcode `0x04` with destination `0x13` and value `0x000` triggers an internal shift that produces `0x10000000`

Encoded as the final input string:

```
0210010002100100031100010112110004130000
```

Sending this to the binary:

```python
from pwn import *

p = process('./virtually.mad')
p.recvuntil(b"execute:")
p.sendline(b"0210010002100100031100010112110004130000")
p.interactive()
```

The VM validates all five conditions and prints `HTB{<input>}` with the input string as the flag.
