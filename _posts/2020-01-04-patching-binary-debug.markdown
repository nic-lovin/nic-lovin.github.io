---
layout: post
title:  "Patching binary in order to debug child process"
date:   2020-01-04 12:39:47 -0400
categories: Reverse engineering
---
I sometimes stumble into binaries that use `CreateProcess`, `CreateProcessInternal`, `CreateThread` or any functions like that. In this case, the binary is using `CreateProcess` function. When debugging with `xdbg`, we cannot follow the code excution. In order to debug the binary, I often patch it, then run it and hook to it. I am not an expert in reverse engineering and I am pretty confident that there might be as good or even better ways to do it.

> TLDR: patch the binary with `0xebfe`, execute and attach it.

## Hooking `CreateProcess`
I have a binary that will create child process using `CreateProcessA`. I knew this function was called using `Process Monitor` from sysinternals (and from `Imports` in IDA), so I ran `xdbg` with `debug.exe`, put a breakpoint using `bp CreateProcessA`. I executed it until it hit the breakpoint.

![Breakpoint on CreateProcessA](/assets/bp_createprocess.png)

We don't really want to debug `CreateProcessA` function, so we can step until we get back to the user code (`F4`). From there, we can see the stack (or look at registers for x64 binaries) and take a look on how the process was created with its arguments.

![After CreateProcessA](/assets/return_createprocess.png) 

![Stack before CreateProcessA](/assets/stack_createprocess.png)

As it is not a post on how to reverse engineer and find functions in binary, I won't go in details on how I found the function called when the binary is calling itself with arguments. One could look at the arguments, find the string in the binary and go from there and find where that string is used (`xref` in IDA).

When I found where it all led, the function looked like:

![Function called when CreateProcessA is used](/assets/createprocess_function.png)

## And that infinite loop
`0xebfe` is 2-byte instruction that creates and infinite loop. Patching the first bytes with `0xebfe` with cause the function to run infinitely and that's perfect for use. We will want to attach the binary as soon as the function is being executed to be able to debug everything.

In IDA, we can patch bytes using `Edit > Patch program > Change Byte`. Save the first bytes and instructions that will be overwritten somewhere with `EB FE`. The call graph should change to:

![Breakpoint on CreateProcessA](/assets/function_ebfe.png)

We were lucky this time that the first instructions were 1-byte long. If you encounter a multi-byte instructions, you can fill it with `0x90`, which is a `NOP` instruction.

## Attach the patched binary
Next thing, run the original binary without `xdbg` and check at the processes list with `Process explorer`.

![Breakpoint on CreateProcessA](/assets/ebfe_binary.png)

If we right-click, select `Properties...`, we should see the same `Command line` as in `xdbg`.

Now, launch `xdbg`, attach the binary being ran, `File > Attach`, and find the function we earlier modified: `CTRL + G`, and we should see our `EB FE` bytes.

![Breakpoint on CreateProcessA](/assets/ebfe_xdbg.png)

From there, we can to patch again the binary; click on the instruction and press `Space`. Change instruction to the orignals one and the function should be as it was at first:

![Breakpoint on CreateProcessA](/assets/original_function_xdbg.png) 

And you can now debug your function as it was originally.

## Summary

We saw how patching a binary with 2 bytes can help us debugging a binary when it creates a child process:
- Find where the `CreateProcessA` is used
- Find what it calls
- Replace the first bytes of the function with `0xebfe`
- Run the binary, attach to it
- Find our patched function, patch it again to the original instructions
- Debug it.

Using this technique can also bypass some anti-debuggers and might be useful when dealing with malware. However, run malware in a sandbox/virtual machine only!
