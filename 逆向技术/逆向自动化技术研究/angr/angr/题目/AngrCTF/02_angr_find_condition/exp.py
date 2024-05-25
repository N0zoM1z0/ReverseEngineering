from angr import *
from claripy import *

def good(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.' in stdout_output:
        return True
    else: 
        return False
def bad(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.' in stdout_output:
        return True
    else: 
        return False

p = Project("./02_angr_find_condition")
state = p.factory.entry_state()
sim = p.factory.simgr(state)

sim.explore(find = good,avoid = bad)

if sim.found:
    res = sim.found[0]
    res = res.posix.dumps(0)
    print(f"[+] Success! The solution is {res.decode()}")