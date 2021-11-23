from z3 import *

#allowed_name_chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
#name_chars = Union([Re(StringVal(c)) for c in allowed_name_chars])
name_chars = Union([Range("a","z"),Range("0","9")])
re_all_name_chars = Star(name_chars)

#allowed_path_chars = allowed_name_chars + '/'
#path_chars = Union([Re(StringVal(c)) for c in allowed_path_chars])
path_chars = Union([Range("a","z"),Range("0","9"),Option(Re(StringVal("/")))])
re_all_path_chars = Star(path_chars)


http_verbs = Union([Re(StringVal("GET")), Re(StringVal("POST"))])

"""
an example where we create regular expression which matches tacc.tacc.*.systems, where * is any number of characters in chars
tn = Re(StringVal('tacc.tacc.'))
sm = Re(StringVal('.systems'))
rule_re = Concat(tn, Star(chars), sm)

now we can test if different strings match the rule:
In [12]: simplify(InRe('aa', rule_template))
Out[12]: False

In [13]: simplify(InRe('tacc.tacc', rule_template))
Out[13]: False

In [14]: simplify(InRe('tacc.tacc.foobar.systems', rule_template))
Out[14]: True

In [15]: simplify(InRe('tacc.tacc.foo.systems', rule_template))
Out[15]: True

In [16]: simplify(InRe('tacc.tacc.foobar.system', rule_template))
Out[16]: False
"""


class BaseRe(object):

    def to_re(self, str, path=False):
        """
        Converts a string, str, to a regular expression. Only supports allowed_chars and a wild card (*) character.
        :param str:
        :return:
        """
        # every instance of a * character
        re_chars = re_all_name_chars
        if path:
            re_chars = re_all_path_chars
        if str == '*':
            return re_chars
        if not '*' in str:
            return Re(StringVal(str))
        parts = str.split('*')
        # compute the first one since Concat requires at least two args.
        result = Concat(Re(StringVal(parts[0])), re_chars)
        # handle the case of str containing a single * in the last char
        if len(parts) == 2 and str[-1] == '*':
            return result
        for idx, part in enumerate(parts[1:]):
            # it is possible the str ends in a '*', in which case we only need to add a single re_all_chars,
            # unless we already did because this is the
            if part == '':
                if idx == 0:
                    return result
                return Concat(result, re_chars)
            # handle whether this is the final part or not:
            if idx + 2 == len(parts):
                return Concat(result, Re(StringVal(part)))
            result = Concat(result, Re(StringVal(part)))


class Principal(BaseRe):
    """
    class to represent a principal (subject) in a service request.
    Test:
    p = Principal('tacc', 'dev', 'test*use*')
    simplify(InRe('tacc.dev.testuser1', p.re))
    Out: True
    simplify(InRe('tacc.dev.testFOOuseBARr1123', p.re))
    Out: False (note: upper case letters are not allowed)

    p = Principal('tacc', 'dev', 'testuser*')
    simplify(InRe('tacc.dev.testuser1', p.re))
    Out: True
    simplify(InRe('tacc.dev.testuser123', p.re))
    Out: True
    simplify(InRe('tacc.dev.testuser123.bar', p.re))
    Out: False
    """
    def __init__(self, site, tenant, username):
        self.site = site
        self.tenant = tenant
        self.username = username
        self.re = Concat(self.to_re(site), Re(StringVal('.')), self.to_re(tenant), Re(StringVal('.')), self.to_re(username))


class Resource(BaseRe):
    """
    class to represent a resource being acted upon.

    r = Resource('tacc', 'dev', 'systems', '/sys1')
    simplify(InRe('tacc.dev.systems./sys1', r.re))
    Out: True
    simplify(InRe('tacc.dev.systems./sys2', r.re))
    Out: False

    r = Resource('tacc', 'dev', 'systems', '/*')
    simplify(InRe('tacc.dev.systems./sys1', r.re))
    Out: True
    simplify(InRe('tacc.dev.systems./sys1/some/file/path', r.re))
    Out: True

    r = Resource('tacc', 'dev', 'systems', '/sys1/*')
    simplify(InRe('tacc.dev.systems./sys1/some/path', r.re))
    Out: True
    simplify(InRe('tacc.dev.systems./sys2/some/path', r.re))
    Out: False
    simplify(InRe('tacc.tacc.systems./sys1/some/file/path', r.re))
    Out: False

    """
    def __init__(self, site, tenant, service, path):
        self.site = site
        self.tenant = tenant
        self.service = service
        self.path = path
        self.re = Concat(self.to_re(site), Re(StringVal('.')),
                         self.to_re(tenant), Re(StringVal('.')),
                         self.to_re(service), Re(StringVal('.')),
                         self.to_re(path, path=True))

class Action(BaseRe):
    """
    class to represent a HTTP verb
    """
    def __init__(self, action):
        self.action = action
        self.re = self.to_re(action)
    def to_re(self, str, path=False):

        if str == '*':
            return http_verbs
        if not '*' in str:
            return Re(StringVal(str))

class Policy(object):
    """
    class to represent a security policy.
    """
    def __init__(self, principal, resource, action, decision="allow"):
        self.principal = principal
        self.resource = resource
        self.action = action
        self.decision = decision  # "allow" or "deny"
        if not decision == 'allow':
            self.decision = 'deny'


class PolicyEngine(object):
    """
    work with policies
    """
    def __init__(self, policies):
        self.policies = policies
        self.principal = String('principal')
        self.resource = String('resource')

    def get_solver(self):
        """
        create a solver that can be used to examine the set of policies
        :return:
        """
        s = Solver()
        allow_policies = []
        deny_policies  = []
        for p in self.policies:
            if p.decision == 'allow':
                allow_policies.append(p)
            else:
                deny_policies.append(p)
        # add each of the allowed --
        allowed = [And(InRe(self.principal, p.principal.re), InRe(self.resource, p.resource.re)) for p in allow_policies]
        s.add(Or(*allowed))
        # remove each of the denied --
        for p in deny_policies:
            s.add(Not(And(InRe(self.principal, p.principal.re), InRe(self.resource, p.resource.re))))
        return s


class PolicyEquivChecker(object):

    def __init__(self, policy_set_1, policy_set_2):
        self.policy_set_1 = policy_set_1
        self.policy_set_2 = policy_set_2
        self.principal = String('principal')
        self.resource = String('resource')
        self.action = String('action')
        self.solver = self.get_solver()

    def get_solver(self):
        allow_policies_1 = []
        deny_policies_1 = []
        for p in self.policy_set_1:
            if p.decision == 'allow':
                allow_policies_1.append(p)
            else:
                deny_policies_1.append(p)
        self.allow_policies_set_1 = allow_policies_1
        self.deny_policies_set_1 = deny_policies_1
        allowed_1 = [And(InRe(self.principal, p.principal.re), InRe(self.resource, p.resource.re), InRe(self.action,p.action.re)) for p in
                   allow_policies_1]

        deny_and_list_1 = [And(InRe(self.principal, p.principal.re), InRe(self.resource, p.resource.re), InRe(self.action,p.action.re)) for p in deny_policies_1]
        if len(deny_and_list_1) == 0:
            P = Or(*allowed_1)
        else:
            print(f'here, deny_and_list_1: {deny_and_list_1}')
            P = And( Or(*allowed_1), Not(And(*deny_and_list_1)))
        self.P = P

        allow_policies_2 = []
        deny_policies_2 = []
        for p in self.policy_set_2:
            if p.decision == 'allow':
                allow_policies_2.append(p)
            else:
                deny_policies_2.append(p)
        self.allow_policies_set_2 = allow_policies_2
        self.deny_policies_set_2 = deny_policies_2
        allowed_2 = [And(InRe(self.principal, p.principal.re), InRe(self.resource, p.resource.re), InRe(self.action,p.action.re)) for p in
                     allow_policies_2]

        deny_and_list_2 = [And(InRe(self.principal, p.principal.re), InRe(self.resource, p.resource.re), InRe(self.action,p.action.re)) for p in deny_policies_2]
        if len(deny_and_list_2) == 0:
            Q = Or(*allowed_2)
        else:
            Q = And( Or(*allowed_2), Not(And(*deny_and_list_2)))
        s = Solver()
        s.add(Implies(P, Q))
        self.Q = Q
        return s

# Examples:
u1 = Principal('tacc', 'dev', 'testuser1')
u2 = Principal('tacc', 'dev', 'testuser2')

s1 = Resource('tacc', 'dev', 'systems', '/sys1')
s2 = Resource('tacc', 'dev', 'systems', '/sys2')
s3 = Resource('tacc', 'dev', 'systems', '/*')

#a1 = Resource('tacc', 'dev', 'apps', '/fooApp')

hv1 = Action('*')
hv2  = Action('GET')

# this first set of policies states that u1 is allowed to do anything on all systems except s2.
#p1 = Policy(u1, s3, 'allow')
#p2 = Policy(u1, s2, 'deny')
p1 = Policy(u1, s3, hv1,'allow')
p2 = Policy(u1, s2, hv1, 'deny')

# this policy set states that u1 is allowed to do anything on s1 but nothing on s2:
#q1 = Policy(u1, s1, 'allow')
#q2 = Policy(u1, s2, 'deny')

q1 = Policy(u1, s1, hv2,'allow')
q2 = Policy(u1, s2,hv2, 'deny')

# it should be true that p => q but q does NOT imply p
checker = PolicyEquivChecker(policy_set_1=[p1,p2], policy_set_2=[q1,q2])

"""
>>> prove(Implies(checker.P, checker.Q))
Out: counterexample
[resource = "tacc.dev.systems./",
 principal = "tacc.dev.testuser1"]

>>> prove(Implies(checker.Q, checker.P))
Out: proved
"""


# now check2.P does NOT imply checker2.Q

"""
Given a set of policies, P = {p1, ..., pn} and another policy, q, can ask does P => q ?
For example: 
  * P is the set of actual existing (in SK) policies
  * q could be some "bad" policy; e.g., the policy that some resource is publicly accessible. 

If P => q then our security policies are bad...

So, being able to answer does P => q is useful.

More generally,
P = {p1, ..., pn} and another set of policies, Q = {q1, ...., qs} , can ask does P <=> Q ?


----

P => q is equivalent to:  q AND ~P is unsat.

if q AND ~P is sat then P /not => q



<=> ~q => ~P











"""


# p3 = Policy(u1, a1, 'deny')
# p4 = Policy(u1, s3, 'deny')
# policies = [p1, p2]
# eng1 = PolicyEngine(policies)
# s = eng1.get_solver()

# policies2 = [p1, p2, p4]
# eng2 = PolicyEngine(policies2)
# s2 = eng2.get_solver()


"""
Examples:
s = Solver()
resource = String('string')

s1 = Resource('tacc', '*', 'systems', '/systems/sys1')
s.add(InRe(resource, s1.re))
s2 = Resource('tacc', 'dev', 'systems', '/systems/*')
s.add(InRe(resource, s2.re))

s.check()
s.model()

s3 = Resource('tacc', 'dev', 'systems', '*')
s = Solver()
s.add(Or(InRe(resource, s2.re), InRe(resource, s3.re)))
s.check()
s.model()
Out[58]: [string = "tacc.dev.systems.7"]

"""

