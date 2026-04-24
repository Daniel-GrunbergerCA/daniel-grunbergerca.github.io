# HTB Coffee Invocation - JNI Dynamic Class Loading with Obfuscated Verification

The challenge binary loads two Java classes dynamically at runtime via JNI (`DefineClass`), then runs verification logic against the user's input. The name is a nod to Java - "coffee invocation" through native code.

## Understanding the Structure

The binary sets up corrupted bytes and shorts in memory before loading the classes. Two Java class bytecodes are embedded in the binary's data section. Extracting and decompiling them reveals the verification logic.

## Verify1 - Byte/Short Comparison

The first class (`Verify1`) compares each character of a substring of the input against a hardcoded target string `~PL{A;PL{?;:=|PIC{HzP:A;~x`:

```java
public class Verify1 {
    private static boolean compareByte(Byte var0, Short var1) {
        return var0 == var1;
    }

    public static void main(String[] var0) {
        // var0[0] = first 26 chars of input
        // var0[1] = "~PL{A;PL{?;:=|PIC{HzP:A;~x"
        for (int var3 = 0; var3 < var1.length(); ++var3) {
            if (!compareByte((byte) var1.charAt(var3), (short) ((byte) var2.charAt(var3)))) {
                System.exit(3);
            }
        }
    }
}
```

The comparison is `(byte)input[i] == (short)((byte)target[i])`. Since the bytes and shorts in memory were tampered with at startup, we need to account for the actual conversion tables applied. The native code injects a byte lookup table and a short lookup table before the verification runs.

### Reversing the Conversion Tables

The byte table maps each index `i` to `(0x51 + i) % 256`. The short table maps `0` to `0` and `i` to `256 - i` for `i > 0`.

To find the correct input character for each target character, we reverse the pipeline:

```python
def solve-password():
    target-string = "~PL{A;PL{?;:=|PIC{HzP:A;~x"

    short-table = [0] + [256 - i for i in range(1, 256)]
    byte-table = [(0x51 + i) % 256 for i in range(256)]

    password = ""
    for char in target-string:
        target-ascii = ord(char)
        internal-val = short-table[target-ascii]
        input-char-code = byte-table.index(internal-val)
        password += chr(input-char-code)

    print(f"Decoded Pass: {password}")

solve-password()
```

## Verify2 - Character Mapping Tables

The second verification stage uses a set of per-position mapping tables. Each pair of characters in the remaining input is mapped through a unique table. Reversing each table gives the expected input characters:

```python
for i in range(0, len(s), 2):
    mappingTable = characterTables[i // 2]
    for j in range(len(mapping)):
        if mapping[j] == s[i]:
            print(chr(j), end='')
```

Combining both parts produces the full flag.
