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

p = Project("./03_angr_symbolic_registers")
state = p.factory.entry_state(addr = 0x8048980)
pass1 = BVS('pass1',32)
pass2 = BVS('pass2',32)
pass3 = BVS('pass3',32)

state.regs.eax = pass1
state.regs.ebx = pass2
state.regs.edx = pass3

sim = p.factory.simgr(state)

sim.explore(find = good,avoid = bad)

if sim.found:
    res = sim.found[0]
    pass1 = sim.found[0].solver.eval(pass1)
    pass2 = sim.found[0].solver.eval(pass2)
    pass3 = sim.found[0].solver.eval(pass3)
    print("[+] Success! The solution is {:x} {:x} {:x}".format(pass1,pass2,pass3))
