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

p = Project("./05_angr_symbolic_memory")
state = p.factory.entry_state(addr = 0x80485FE)

pass1 = BVS('pass1',64)
pass2 = BVS('pass2',64)
pass3 = BVS('pass3',64)
pass4 = BVS('pass4',64)

state.memory.store(0xA1BA1C0,pass1)
state.memory.store(0xA1BA1C0+0x8,pass2)
state.memory.store(0xA1BA1C0+0x10,pass3)
state.memory.store(0xA1BA1C0+0x18,pass4)


sim = p.factory.simgr(state)

sim.explore(find = good,avoid = bad)

if sim.found:
    res = sim.found[0]
    pass1 = sim.found[0].solver.eval(pass1,cast_to=bytes)
    pass2 = sim.found[0].solver.eval(pass2,cast_to=bytes)
    pass3 = sim.found[0].solver.eval(pass3,cast_to=bytes)
    pass4 = sim.found[0].solver.eval(pass4,cast_to=bytes)

    print(f"[+] Success! The solution is {pass1.decode()} {pass2.decode()} {pass3.decode()} {pass4.decode()}")
