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

p = Project("./04_angr_symbolic_stack")
state = p.factory.entry_state(addr = 0x08048697)
state.stack_push(state.regs.ebp)
state.regs.ebp = state.regs.esp
# 上面两句模拟 push ebp; mov ebp,esp;
state.regs.esp -= 8

pass1 = BVS('pass1',32)
pass2 = BVS('pass2',32)

state.stack_push(pass1)
state.stack_push(pass2)

sim = p.factory.simgr(state)

sim.explore(find = good,avoid = bad)

if sim.found:
    res = sim.found[0]
    pass1 = sim.found[0].solver.eval(pass1)
    pass2 = sim.found[0].solver.eval(pass2)
    print("[+] Success! The solution is {:d} {:d}".format(pass1,pass2))
