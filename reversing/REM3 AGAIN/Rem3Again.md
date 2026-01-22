## 🧩 KCTF Reverse Engineering Write-Up — rem3_again

Category: Reverse Engineering

Flag format: KCTF{}

## 📌 Challenge Overview

We are given a 64-bit ELF binary named `rem3_again`.
The program asks for a string and validates it through several obfuscated routines.
The flag is not stored directly — instead, the binary builds an internal reference buffer from static seeds and transforms it before comparing against user input.

Our task is to reverse this entire chain.

## 🔍 1. Initial Recon

```bash
file rem3_again
checksec rem3_again
strings rem3_again

```

**Observations:**

>ELF 64-bit, dynamically linked

>NX enabled

>No visible flag

>Multiple non-string constants in `.rodata`

This confirms the flag is algorithmically generated.

## 🧠 2. Static Analysis (IDA)

After loading the binary in IDA, we identify:

`main()` performs a strict length check (`0x26` → 38 bytes)

Calls a function chain:

```scss
chk_first()
cat3()
p()
t()
eq()
```

Only the last comparison decides success.

So the real logic is:

```makefile
expected = t(p(cat3(x_r2, x_r1, x_r0)))
if user_input == expected → WIN
```

## 🧬 3. Control Flow & Logic
**3.1 Length constraint**

```asm
cmp rsi, 0x26
jne fail
```
So input must be exactly **38 bytes**.

**3.2 Fake paths (`chk_first`)**

The binary first runs checks against `x_d*`, `x_f*`, `x_g*`.
These are decoys.
Even if passed, they do not produce the final comparison buffer.

They exist only to mislead brute-force and pattern solvers.

## 🔎 4. Extracting Static Seeds (Professional Method)

The real flag is derived from three `.rodata` blocks:

>`x_r2`

>`x_r1`

>`x_r0`

We enumerate them using:

```bash
nm -n rem3_again | grep " x_r"
```

Then dump `.rodata` and extract exact bytes by virtual address mapping.

Final extracted blocks:

```ini
x_r2 = d0 8b 99 5a e7 f5 46 37 82 48 fb fe 0b 00 00 00
x_r1 = d2 4c a4 79 4a f7 18 cf 68 78 26 fc 37 00 00 00
x_r0 = 0f 5f 6f f7 01 0f b2 18 ee d3 37 84 00 00 00 00
```
Each is 16 bytes.

## 🧩 5. Seed Reconstruction `(cat3)`

The function `cat3()` does not concatenate normally.

It performs overlapping copies into a single buffer.

Disassembly pattern:

```asm

mov [dst],      qword ptr [x]
mov [dst+8],    dword ptr [x+8]

mov [dst+0Ch],  qword ptr [x]
mov [dst+11h],  qword ptr [x+5]

mov [dst+19h],  qword ptr [x]
mov [dst+1Eh],  qword ptr [x+5]

```
Each block contributes 38 bytes after overlapping.

After running cat3(`x_r2`, `x_r1`, `x_r0`) we obtain a 38-byte seed buffer.

This matches the enforced input length.

## 🧬 6. Transformation Stage (p() + t())
**6.1 Byte permutation**

This function:

>iterates over the 38-byte buffer

>applies index-dependent XOR

>swaps positions

Simplified decompilation:

```c
buf[i] = (buf[i] ^ (i + 0x2F)) + 3;
```
The final produced buffer is what `eq()` compares against user input.

## 🔁 7. Inversion Strategy

Instead of brute-forcing, we reverse the pipeline:

```ini
user_input == t(p(seed))
```
So : 

```ini
seed == p⁻¹(t⁻¹(user_input))
```
But easier:

We reconstruct the pipeline and generate the expected result directly.


<details>
<summary>Click to reveal the Flag</summary>

KCTF{aN0Th3r_r3_I_h0PE_y0U_eNj0YED_IT}

</details>
