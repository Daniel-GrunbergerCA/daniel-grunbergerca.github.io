# HTB BinCrypt Breaker — XOR Decrypt and Reverse the Hidden Binary

The challenge provides two files: `checker` (an ELF executable) and `file.bin` (an encrypted binary). The objective is to uncover the original executable hidden inside `file.bin`.

## Stage 1: Decrypting the Binary

Analyzing `checker` in Ghidra reveals a `decrypt` function that reads `file.bin` byte by byte and XORs each byte with `0xab`:

```c
while( true ) {
    local_20 = fgetc(local_18);
    if (local_20 == 0xffffffff) break;
    local_20 = local_20 ^ 0xab;
    write(local_1c, &local_20, 1);
}
```

Running `checker` directly fails because it tries to `open(".", O_WRONLY | O_CREAT | O_TRUNC)` — opening a directory for writing, which the Linux kernel forbids. Since the decryption logic is trivially a single-byte XOR, we can replicate it in Python:

```python
def decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f_in:
        encrypted_data = f_in.read()
    decrypted_data = bytes([b ^ key for b in encrypted_data])
    with open(output_path, "wb") as f_out:
        f_out.write(decrypted_data)

decrypt_file("file.bin", "file_decrypted", 0xab)
```

This produces a valid ELF binary.

## Stage 2: Reversing the Decrypted Binary

Loading `file_decrypted` in Ghidra, the main function prompts for the flag (without the `HTB{}` wrapper) and passes it to a validation function. The validator:

1. Checks the input is exactly `0x1c` (28) characters long
2. Applies a series of byte swaps (`FUN_0010127d`)
3. Splits the result into two 14-character halves
4. Runs each half through a shuffle + XOR function (`FUN_001012e4`) with keys `2` and `3`
5. Concatenates and compares against the target: `RV{r15]_vcP3o]L_tazmfSTaa3s0`

### Reversing FUN_001012e4

This function does 8 rounds of character permutation using a fixed index map, then XORs 6 specific positions with the key:

```python
def undo_manipulate(data_str, param_2):
    data = list(data_str)
    xor_indices = [2, 4, 6, 8, 11, 13]
    for idx in xor_indices:
        data[idx] = chr(ord(data[idx]) ^ param_2)
    p_map = [9, 12, 2, 10, 4, 1, 6, 3, 8, 5, 7, 11, 0, 13]
    for _ in range(8):
        prev_round = [None] * 14
        for i in range(14):
            prev_round[p_map[i]] = data[i]
        data = prev_round
    return "".join(data)
```

### Reversing the Swaps

The swap function `FUN_0010127d` swaps pairs at positions `(0, 0xc)`, `(0xe, 0x1a)`, `(4, 8)`, `(0x14, 0x17)`. Since swaps are self-inverse, applying the same swaps reverses them:

```python
def apply_swaps(data_list):
    def swap(arr, i, j):
        arr[i], arr[j] = arr[j], arr[i]
    swap(data_list, 0, 0x0c)
    swap(data_list, 0x0e, 0x1a)
    swap(data_list, 4, 8)
    swap(data_list, 0x14, 0x17)
    return data_list
```

### Final Solution

```python
target = "RV{r15]_vcP3o]L_tazmfSTaa3s0"

part_a_unmanipulated = undo_manipulate(target[:14], 2)
part_b_unmanipulated = undo_manipulate(target[14:], 3)

full_string_list = list(part_a_unmanipulated + part_b_unmanipulated)
final_flag = apply_swaps(full_string_list)
print("HTB{" + "".join(final_flag) + "}")
```
