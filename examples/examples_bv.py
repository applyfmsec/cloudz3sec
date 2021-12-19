import sys
sys.path.append('/home/cloudz3sec')
from cloudz3sec.cloud import CloudPolicy, CloudPolicyManager
from cloudz3sec.core import PolicyEquivalenceChecker
import z3

# convenience instance for creating policies
t = CloudPolicyManager()
#example 4
p1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', '*','11.22.33.0/24', 'allow')
p2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', '11.23.33.0/24','deny')
p = [p1]

q1 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys1', '*', '11.22.0.0/16','allow')
q2 = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.systems./sys2', '*', '11.23.0.0/16','deny')
q = [q1]
chk_1 = PolicyEquivalenceChecker(policy_type=CloudPolicy, policy_set_p=p, policy_set_q=q)

chk_1.p_implies_q()
chk_1.q_implies_p()

