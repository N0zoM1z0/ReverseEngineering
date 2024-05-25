from angr import *
from claripy import *

p = Project("./01_angr_avoid")
state = p.factory.entry_state()
sim = p.factory.simgr(state)

sim.explore(find = 0x80485E0,avoid = 0x80485A8)

if sim.found:
    res = sim.found[0]
    res = res.posix.dumps(0)
    print(f"[+] Success! The solution is {res.decode()}")