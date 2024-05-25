from angr import *
from claripy import *

def good(state):
    stdout_output = state.posix.dumps(1)
    if b'Good Job.' in stdout_output:
        return True
    else: 
        return False
def bad(state):
    stdout_output = state.posix.dumps(1)
    if b'Try again.' in stdout_output:
        return True
    else: 
        return False

p = Project("./06_angr_symbolic_dynamic_memory")

state = p.factory.entry_state(addr = 0x08048699)
print(f"[+] esp: {state.regs.esp}")

buffer0_addr = 0x0ABCC8A4
buffer1_addr = 0x0ABCC8AC

buffer0 = state.regs.esp - 0x100
buffer1= state.regs.esp - 0x200

# 把buffer0的地址放栈上的地址
state.memory.store(buffer0_addr,buffer0,endness = p.arch.memory_endness) # 要指定端序 不然默认大端序..
state.memory.store(buffer1_addr,buffer1,endness = p.arch.memory_endness) 

pass1 = BVS('pass1',64)
pass2 = BVS('pass2',64)

state.memory.store(buffer0,pass1)
state.memory.store(buffer1,pass2)

sim = p.factory.simgr(state)

sim.explore(find = good,avoid = bad)

if sim.found:
    res = sim.found[0]
    pass1 = sim.found[0].solver.eval(pass1,cast_to=bytes)
    pass2 = sim.found[0].solver.eval(pass2,cast_to=bytes)

    print(f"[+] Success! The solution is {pass1.decode()} {pass2.decode()}")
