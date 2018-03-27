from z3 import *

f = open("ysnp_constraints_massaged.txt", "r")
constraints = f.readlines()

s = Solver()

a1 = []
for i in range(0, 45):
	a1.append(BitVec('{}'.format(i), 64))
	s.add(a1[i] >= 0x20)
	s.add(a1[i] <= 0x7f)


for c in constraints:
	print("CONSTRAINT: {}".format(c))
	exec(c)

if s.check() == sat:
	m = s.model()
	flag = ''.join([chr(m[x].as_long()) for x in sorted(m.decls(), key=lambda x: int(x.name()))])
	print(flag)

else:
	print("Unsat :((")
