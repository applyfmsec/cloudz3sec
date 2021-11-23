from cloudz3sec.core import TapisPolicyManager, PolicyEquivalenceChecker
import z3

# convenience instance for creating policies
t = TapisPolicyManager()

# create two sets of policies, p and q

# example 1:
p1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1/*', '*', 'allow')
p2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', 'deny')
p = [p1, p2]

q1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', 'GET', 'allow')
q2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', 'GET', 'deny')
q = [q1, q2]
chk_1 = PolicyEquivalenceChecker(policy_set_1=p, policy_set_2=q)


# note that policy set p is strictly more permissive than posicy set q
p1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys1/*', 'GET', 'allow')
p2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny')
p = [p1, p2]

q1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./*', 'GET', 'allow')
q2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys2/*', 'GET', 'deny')
q = [q1, q2]

# create a checker for the two policy sets
chk_2 = PolicyEquivalenceChecker(policy_set_1=p, policy_set_2=q)

# z3.prove(z3.Implies(chk.statements[0], chk.statements[1]))