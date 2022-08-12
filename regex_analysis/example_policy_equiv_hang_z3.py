from z3 import *

##
# A simple demonstration of the solving capabilities of the z3 strings solver
# through the Python API.
# In this example, we are trying find equivalence of formulas.
# F1: x \in R1 where R1 is the regular expression /sys([a-z]|[0-9][_/])*
# F2: x \in R2 where R2 is the regular expression /([a-z]|[0-9][_/])*
# Prove if F1->F2 or F2 -> F2
# In this above example, F1 -> F2 is valid as R2 is superset of R1
# while F2->F1 is not true. It is satisfiable but not valid
# To prove a formula, F, is valid, we prove NOT(F) is unsatisfiable.
# That is, NOT(F1->F2) is unsat. This implies F1->F2 is valid and hence proved.
##

charset = set('abcdefghijklmnopqrstuvwxyz0123456789_/')

path_chars= Union([Re(StringVal(c)) for c in charset])
#path_chars = Union([Re(StringVal("a")),Re(StringVal("b"))])
re_all_path_chars = Star(path_chars)
s1 = Concat(Re('/sys'),re_all_path_chars) #abc*
s2 = Concat(Re('/'),re_all_path_chars)  #a*
x= String('x')

x1 = InRe(x,s1)
x2 = InRe(x,s2)
print("Using prove method ---")
prove(Implies(x2,x1), show=True) # s2 is a superset of s1. Formula is satisfiable but not valid
                                 # Note prove method tries to prove by proving  Not(F) as unsat, otherwise give counterexample in case of satisfiable. 


print('Using Solver method ----- ')
s = Solver()
s.add(Not(Implies(x1,x2)))
#s.add(Not(Implies(x2,x1)))    #sat
print(s)
print('S-Expression: ----')
print(s.sexpr())   # we get smt expression and use it directly to prove the formula is sat or unsat.
r = s.check()
#print(r)
print('Conclusion:-----')
if r == unsat:
    print("proved")
elif r == unknown:
    print("failed to prove")
    print(s.model())
else:
    print("counterexample")
    print(s.sexpr())
    print(s.model()) 
    
