
import sys
import timeit
import numpy as np
from matplotlib import pyplot as plt

# add the current working directory to the python path so that the tests can run easily from
# within the tests Docker container
sys.path.append('/home/cloudz3sec')
print(f"Python path: {sys.path}")

from cloudz3sec import cloud, core
from test_performance import DynamicEnum, DynamicEnumPolicy, AlphaNumStringRe, AlphaNumPolicy

def load_enum_policies(n: int):
    """
    Generate two sets of enum policies as wefor performance testing.
    """
    policy_p = []
    en = DynamicEnum(N=n)
    for i in range(n):
        # create a policy allowing each possible value:
        en.set_data(str(i))
        dp = DynamicEnumPolicy(de=en, decision=core.Decision('allow'))
        policy_p.append(dp)
    
    # create a single policy with a wildcard for the enum
    en.set_data("*")
    policy_q = [DynamicEnumPolicy(de=en, decision=core.Decision('allow'))]
    # create the policy checker for both of these
    chk = core.PolicyEquivalenceChecker(policy_type=DynamicEnumPolicy, 
    policy_set_p=policy_p, 
    policy_set_q=policy_q)
    return policy_p, policy_q, chk


def load_string_wild_card_policies(n: int):
    policy_p = []
    policy_q = []
    for i in range(n):
        # todo -- could also vary the length of the base string
        p_val = f'a1b2c3d4e5/{i}'
        # the q policy value is the p value with a * at the end.
        q_val = f'{p_val}*'
        field_1 = AlphaNumStringRe()
        field_1.set_data(p_val)
        pol = AlphaNumPolicy(field_1=field_1, decision=core.Decision('allow'))
        policy_p.append(pol)
        field_1.set_data(q_val)
        pol = AlphaNumPolicy(field_1=field_1, decision=core.Decision('allow'))
        policy_q.append(pol)

    # create the policy checker for both of these
    chk = core.PolicyEquivalenceChecker(policy_type=AlphaNumPolicy, policy_set_p=policy_p, policy_set_q=policy_q)
    return policy_p, policy_q, chk


def measure_enum(ns=[10, 100, 1000], test_reps=4):
    result = {}
    with open('enum_results.csv', 'w') as f:
        f.write('Enum Test\n')
        f.write('n, Data Load, P => Q, Q => P\n')
        for n in ns:
            result[n] = []
            for i in range(test_reps):
                ts_1 = timeit.default_timer()
                _, _, chk = load_enum_policies(n)
                ts_2 = timeit.default_timer()
                chk.p_implies_q()
                ts_3 = timeit.default_timer()
                chk.q_implies_p()
                ts_4 = timeit.default_timer()
                new_times = {'data_load': ts_2-ts_1, 'p_imp_q': ts_3-ts_2, 'q_imp_p': ts_4-ts_3}
                result[n].append(new_times)
                f.write(f"{n}, {new_times['data_load']}, {new_times['p_imp_q']}, {new_times['q_imp_p']}\n")
    return result

def measure_string_wc(ns=[10, 100, 1000], test_reps=4):
    result = {}
    with open('string_re_wc_results.csv', 'w') as f:
        f.write('StringRe Wildcard Test\n')
        f.write('n, Data Load, P => Q\n')
        for n in ns:
            result[n] = []
            for i in range(test_reps):
                ts_1 = timeit.default_timer()
                _, _, chk = load_string_wild_card_policies(n)
                ts_2 = timeit.default_timer()
                chk.p_implies_q()
                ts_3 = timeit.default_timer()
                new_times = {'data_load': ts_2-ts_1, 'p_imp_q': ts_3-ts_2}
                result[n].append(new_times)
                f.write(f"{n}, {new_times['data_load']}, {new_times['p_imp_q']}\n")
    return result


#         
# measure_enum(ns=[10+(30*i) for i in range(34)], test_reps=4)
# measure_enum(ns=[], test_reps=4)


