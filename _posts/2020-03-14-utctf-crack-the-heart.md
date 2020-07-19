---
layout: post
title:  "UTCTF 2020 - Crack the heart"
summary: "Patching a binary and pin it!"
date:   2020-03-14 20:40:00 -0400
categories: Reverse engineering
---
There was this challenge called `Crack the heart` during the UTCTF. Although it wasn't particularly difficult, there were differents ways to solve this challenge: angr, digging deep down into the reversing, etc. My solution was to patch the binary and then pin it. As I like to not over reverse engineer a binary, I don't know what really was the binary. It looked like some "Virtual Machine", but I can't tell much.


## Quick look

Doing a `file` on the binary:

`crackme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped`

Then put it in IDA, get this unusual start.
![Start](/assets/crack_the_heart/start.png)

The content at `unk_404527` is:

```
.data:0000000000404527 unk_404527      db 0CFh
.data:0000000000404528                 db  21h
.data:0000000000404529                 db  40h
.data:000000000040452A                 db    0
.data:000000000040452B                 db    0
.data:000000000040452C                 db    0
.data:000000000040452D                 db    0
.data:000000000040452E                 db    0
````

So, the binary will load `0x4021cf` into `RCX`, then will jump to this adress. IDA didn't recognize it was code and didn't disassembled it.

```
.data:00000000004021CF                 db  51h ; Q
.data:00000000004021D0                 db 0BFh
.data:00000000004021D1                 db    0
.data:00000000004021D2                 db    0
.data:00000000004021D3                 db    0
.data:00000000004021D4                 db    0
.data:00000000004021D5                 db 0BEh
.data:00000000004021D6                 db    0
.data:00000000004021D7                 db    0
.data:00000000004021D8                 db    0
.data:00000000004021D9                 db    0
.data:00000000004021DA                 db 0BAh
.data:00000000004021DB                 db    1
.data:00000000004021DC                 db    0
.data:00000000004021DD                 db    0
[...]
```

We can transform it to code by pressing `<c>`. This makes more sense, but parts are missing. There is no user input, no flag validation. As there is a call to `ptrace`, I replaced it with `nop`s to be able to debug it.

The following part contains the code flow, and that is why IDA didn't recognize everything.
```
.data:00000000004021C6                 mov     rdx, [rcx]
.data:00000000004021C9                 lea     rcx, [rcx+8]
.data:00000000004021CD                 jmp     rdx
```

By looking around the code, we can find now code blocks. I found code blocks from `0x402000` to `0x0402242`. There were three interesting strings: `Why should I go with out?`, `uwu very cool!` and `that was pretty cringe`.

At `0x040218B`, there is `syscall` to `read`, and it will displays the first interesting string. Of course, if `that was pretty cringe` is printed, the flag we entered was wrong. If we look at how this is handled, we can see a `if` condition at `0x040221B`.

![test rbp, rbp](/assets/crack_the_heart/if_good_flag.png)

So, if `rbp` is not equal to zero, our flag is wrong. We can look where `rbp` is set.

![mov rbp, 1](/assets/crack_the_heart/char_validation.png)

Here, we can see the flag validation. It checks one character at a time. If the character is bad, it sets `rbp` to 1, otherwise it jumps over that `mov`.

## Patch and pin it!

As `rbp` is set to 1 and after all the characters were checked before printing the last string, we cannot pin it.

The C code is something like:

``` C
ret = 0;
int i;

for (i = 0, i < FLAG_LENGTH; i++) {
    if (user_input[i] != flag[i]) {
        ret = 1;
    }
}
if (ret) {
    puts("Wrong");
} else {
    puts("Good");
}
```

If we want to pin it, we must have a way to make the binary quits when a bad character is entered:

```
ret = 0;
int i;

for (i = 0, i < FLAG_LENGTH; i++) {
    if (user_input[i] != flag[i]) {
        exit(1);
    }
}
if (ret) {
    puts("Wrong");
} else {
    puts("Good");
}
```

To do so, we can patch the `mov ebp, 1` to `ret`, and add `nop`s.

![Patched binary with ret and nops](/assets/crack_the_heart/ret_nops.png)

To test if everything is working, we can try a few characters.

```
Why should I go out with you?
test

 Performance counter stats for './crackme':

             21,915      instructions:u
```

```
Why should I go out with you?
u     

 Performance counter stats for './crackme':

             22,063      instructions:u 
```
```
Why should I go out with you?
ut

 Performance counter stats for './crackme':

             22,195      instructions:u                                              
```

```
Why should I go out with you?
test

 Performance counter stats for './crackme':

             21,915      instructions:u 
```

It seems to work, more instructions are executed when the flag is good.

I made up that quick and dirty Python script.

``` python
from pwn import *

def test_char(flag):
	# Open the binary, submit a flag
        r = process('perf stat -e instructions:u ./crackme', shell=True)
        r.sendline(flag)

	# Read the response, get the number of instructions it executed
        instr = r.recvall()
        n = instr.split('\n')[4].split("instructions")[0].split()[0].replace(',', '') 
        return int(n)


flag = '' 
nb = 21915

for i in range(0, 90): # Arbitrary length
    for j in string.printable:
        flag_test = flag + (j)   
        tmp = test_char(flag_test)
        if tmp > (nb + 30): # If more instructions were executed, the character is good
            flag = flag_test
            nb = tmp
            print(flag)
            break
print(flag)
```

And, after a few minutes, the flag should be printed:

`utflag{what_1f....i_mapp3d_mY_m3m0ry_n3xt_to_y0urs....ahahaha, jkjk....unless ;)?}`

## Angr

Angr was also more efficient than this Python script...

``` python
import angr

proj = angr.Project("./crackme")
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"cool" in s.posix.dumps(1))
s = simgr.found[0]
print(s.posix.dumps(0))
```
