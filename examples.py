from cloudz3sec.core import TapisPolicyManager, PolicyEquivalenceChecker
import z3

# convenience instance for creating policies
t = TapisPolicyManager()

# create two sets of policies, p and q

# example 1:
# In this example, policy set 1 is more permissive than set 2, as it allows any method on sys1:
p1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', '*', 'allow')
p2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny')
p = [p1, p2]

q1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow')
q2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny')
q = [q1, q2]
chk_1 = PolicyEquivalenceChecker(policy_set_1=p, policy_set_2=q)

# z3 proves that the Q policy set is less permissive than P:
# >>> z3.prove(z3.Implies(chk_1.Q, chk_1.P))
# proved
# 
# and it finds a counter example when we ask it to prove that P => Q:
# >>> z3.prove(z3.Implies(chk_1.P, chk_1.Q))
# counterexample
# [action = "PUT",
#  resource = "tacc.dev.systems./sys1",
 # principal = "tacc.dev.testuser1"]


# example 2:
# In this example, the two policy sets are incomparable (note the required trailing slash in p1), 
# and z3 finds counter examples for each implication.
p1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1/*', '*', 'allow')
p2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny')
p = [p1, p2]

q1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow')
q2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny')
q = [q1, q2]
chk_2 = PolicyEquivalenceChecker(policy_set_1=p, policy_set_2=q)

# >>> z3.prove(z3.Implies(chk_2.P, chk_2.Q))
# counterexample
# [resource = "tacc.dev.systems./sys1/",
# action = "POST",
# principal = "tacc.dev.testuser1"]
#
# >>> z3.prove(z3.Implies(chk_2.Q, chk_2.P))
# counterexample
# [action = "GET",
# resource = "tacc.dev.systems./sys1",
# principal = "tacc.dev.testuser1"]


# example 3: 
# In this example, policy set P is striclty less permissive that policy set Q,
# as P allows GETs on paths /sys1/* while Q allows all GETs.
p1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys1/*', 'GET', 'allow')
p2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny')
p = [p1, p2]

q1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./*', 'GET', 'allow')
q2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny')
q = [q1, q2]
chk_3 = PolicyEquivalenceChecker(policy_set_1=p, policy_set_2=q)

# In this case, z3 can find a counter example to Q => P
# >>> z3.prove(z3.Implies(chk_3.Q, chk_3.P))
# counterexample
# [resource = "tacc.dev.files./",
# action = "GET",
# principal = "tacc.dev.testuser1"]

# However, in this case z3 gets stuck trying to prove that P => Q
# z3.prove(z3.Implies(chk_3.P, chk_3.Q))
# (... hangs ....)
#