from angr import *
from claripy import *

project = Project("./funnyre")
state = project.factory.entry_state(addr = 0x400605) # 设置state开始运行时的地址

flag = BVS('flag',8*32) # 32位BYTE BVS转成二进制赋给flag变量
state.memory.store(0x603055+0x300+5,flag) # 程序没有输入 所以直接把字符串设置到内存
# 0x603055: bss段
state.regs.rdx = 0x603055+0x300
state.regs.rdi = 0x603055+0x300+5 # 设置两个寄存器

sim = project.factory.simgr(state)
sim.explore(find = 0x401DAE)

if sim.found:
    print(f"[+] Success! The Solution is {sim.found[0].solver.eval(flag,cast_to=bytes)}")
else:
    print("[+] Not Found!")