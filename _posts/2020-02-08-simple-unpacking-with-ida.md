---
layout: post
title:  "Simple unpacking using IDA (Python)"
date:   2020-02-09 17:1:47 -0400
categories: Reverse engineering
---
Unpacking binaries is a common thing in malware analysis and binaries in CTFs. I used to put a breakpoint just before the unpacked was called, dumped the memory and analyzed it, but this comes with a lot of disadvantages (I still do it though.). In this post, I'll show how I unpack binaries using IDA with its script engine in Python.

## Quick look on the binary
The context of the binary is a simple challenge where the user enters an input and the binary validates it. I made a simple custom packer that xors a blob of data and jump into it right after.

![Loop of unpacking](/assets/unpacking/loop.png)

What happens here is in (1) `i` is put in `eax` register (and its value is 0), then the packed code is put in `rdx` register (2). The binary xors one byte at a time the blob in `code` with `0x0B` (3). This is repeated until `i` is equal of below `0x96`. At (4), the unpacked code is moved in `rdx`, and the code is finally called at (5).

The C code will look like:
``` c
int i;
for (i = 0; i <= 0x96; i++) {
	code[i] ^= 0x0b;
}
(*(void(*)()) code)();
```

What the code blob looks like:

![Code blob](/assets/unpacking/code.png)

And IDA wrongly disassembled some code. We can undefine what was disassembled by pressing `u`.

One could put a breakpoint just before `call rdx`, dump the memory and analyze it, but we are here to unpack it using IDA.

## IDA Python

IDA supports scripting using Python and IDC. This can be done via `File -> Script Command` or `SHIFT + F2`.
Running the following script will do our unpacking:

``` python
import idaapi
import idautils

ea_code = 0
for ea, name in idautils.Names(): # Go through all global variables
	if name == 'code': # If the name is 'code', the blob we want to unpack
		ea_code = ea
		break

for i in range(0x97):
	b = idaapi.get_byte(ea_code + i) # Get the byte at the offset
	b ^= 0x0b
	idaapi.patch_byte(ea_code + i, b) # Patch the byte with the xored one
```

Looking at our `code` blob, we can confirm they have been patched.

![Patched code](/assets/unpacking/patched.png)

## Creating the function
Now that we unpacked the `code`, we can to tell IDA to disasemble it. This can be done via `Edit -> Code` or by pressing `c`.

![Diassembly of patched code](/assets/unpacking/patched_disassembly.png)

Having this in a function where we can analyze it with the Graph View would help. Pressing `p` with create a function. Finally, pressing the space bar and we get this:

![Created function graph](/assets/unpacking/graph.png)


## IPyIDA
IPyIDA is a pluging giving us an IPython console, which is way more conveniant than the script command window.
I highly recommand to check it out: [https://github.com/eset/ipyida](https://github.com/eset/ipyida).
