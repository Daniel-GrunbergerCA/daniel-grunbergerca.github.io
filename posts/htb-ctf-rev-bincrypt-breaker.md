# HTB BinCrypt Breaker - XOR Decrypt and Reverse the Hidden Binary

The challenge provides two files: `checker` (an ELF executable) and `file.bin` (an encrypted binary). The objective is to uncover the original executable hidden inside `file.bin`.

## Stage 1: Decrypting the Binary

Analyzing `checker` in Ghidra reveals a `decrypt` function that reads `file.bin` byte by byte and XORs each byte with `0xab`:

```c
while( true ) {
    local-20 = fgetc(local-18);
    if (local-20 == 0xffffffff) break;
    local-20 = local-20 ^ 0xab;
    write(local-1c, &local-20, 1);
}
```

Running `checker` directly fails because it tries to `open(".", O-WRONLY | O-CREAT | O-TRUNC)` - opening a directory for writing, which the Linux kernel forbids. Since the decryption logic is trivially a single-byte XOR, we can replicate it in Python:

```python
def decrypt-file(input-path, output-path, key):
    with open(input-path, "rb") as f-in:
        encrypted-data = f-in.read()
    decrypted-data = bytes([b ^ key for b in encrypted-data])
    with open(output-path, "wb") as f-out:
        f-out.write(decrypted-data)

decrypt-file("file.bin", "file-decrypted", 0xab)
```

This produces a valid ELF binary.

## Stage 2: Reversing the Decrypted Binary

Loading `file-decrypted` in Ghidra, the main function prompts for the flag (without the `HTB{}` wrapper) and passes it to a validation function. The validator:

1. Checks the input is exactly `0x1c` (28) characters long
2. Applies a series of byte swaps (`FUN-0010127d`)
3. Splits the result into two 14-character halves
4. Runs each half through a shuffle + XOR function (`FUN-001012e4`) with keys `2` and `3`
5. Concatenates and compares against the target: `RV{r15]-vcP3o]L-tazmfSTaa3s0`

### Reversing FUN-001012e4

This function does 8 rounds of character permutation using a fixed index map, then XORs 6 specific positions with the key:

```python
def undo-manipulate(data-str, param-2):
    data = list(data-str)
    xor-indices = [2, 4, 6, 8, 11, 13]
    for idx in xor-indices:
        data[idx] = chr(ord(data[idx]) ^ param-2)
    p-map = [9, 12, 2, 10, 4, 1, 6, 3, 8, 5, 7, 11, 0, 13]
    for - in range(8):
        prev-round = [None] * 14
        for i in range(14):
            prev-round[p-map[i]] = data[i]
        data = prev-round
    return "".join(data)
```

### Reversing the Swaps

The swap function `FUN-0010127d` swaps pairs at positions `(0, 0xc)`, `(0xe, 0x1a)`, `(4, 8)`, `(0x14, 0x17)`. Since swaps are self-inverse, applying the same swaps reverses them:

```python
def apply-swaps(data-list):
    def swap(arr, i, j):
        arr[i], arr[j] = arr[j], arr[i]
    swap(data-list, 0, 0x0c)
    swap(data-list, 0x0e, 0x1a)
    swap(data-list, 4, 8)
    swap(data-list, 0x14, 0x17)
    return data-list
```

### Final Solution

```python
target = "RV{r15]-vcP3o]L-tazmfSTaa3s0"

part-a-unmanipulated = undo-manipulate(target[:14], 2)
part-b-unmanipulated = undo-manipulate(target[14:], 3)

full-string-list = list(part-a-unmanipulated + part-b-unmanipulated)
final-flag = apply-swaps(full-string-list)
print("HTB{" + "".join(final-flag) + "}")
```
