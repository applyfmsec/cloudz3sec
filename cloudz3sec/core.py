from enum import Enum
from typing import Any, Dict
import z3
from cloudz3sec.errors import InvalidValueError, InvalidCharacterError, InvalidStringTupleStructure, \
     InvalidStringTupleData, MissingStringEnumData, MissingStringTupleData


RESERVED_CHARS = set('.',)

ALPHANUM_SET = set('abcdefghijklmnopqrstuvwxyz0123456789')

PATH_CHAR_SET = set('abcdefghijklmnopqrstuvwxyz0123456789_/')


class StringEnumRe(object):
    """
    Base class for working with types that are restricted to a set of valid strings.

    Examples include the 
        * HTTPVerbs type, which can take values ["GET", "POST", "PUT", "DELETE", ...]
        * Types from the application domain which are pre-determined finite lists (e.g., tenants).

    """
    
    def __init__(self, values: list[str]):
        """
        `values` - the allowable string values
        """
        for v in values:
            for c in RESERVED_CHARS:
                if c in v:
                    msg = f'The character {c} is reserved and cannot be used; it was used in {v}.'
                    raise InvalidCharacterError(message=msg)
        self.values = values
        self.z_all_vals_re_ref = z3.Union([z3.Re(z3.StringVal(v)) for v in values])
        self.re = self.to_re

    def to_re(self, value):        
        if value == '*':
            return self.z_all_vals_re_ref
        if value not in self.values:
            message=f"value {value} is not allowed for type {type(self)}; allowed values are {self.values}"
            raise InvalidValueError(message=message)
        return z3.Re(z3.StringVal(value))


class HTTPVerbRe(StringEnumRe):
    """
    Class representing HTTP verbs.
    """
    def __init__(self) -> None:
        values = ['GET', 'POST', 'PUT', 'DELETE']
        super().__init__(values)


class SiteRe(StringEnumRe):
    """
    Class representing the sites in a platform.

    `sites` - the list of sites defined in the platform.
    """
    def __init__(self, sites: list[str]):
        super().__init__(sites)


class TenantRe(StringEnumRe):
    """
    Class representing the set of tenants in a platform.
    `tenants` - the list of tenants defined in the platform.
    """
    def __init__(self, tenants: list[str]):
        super().__init__(tenants)


class ServiceRe(StringEnumRe):
    """
    Class representing the set of services in a platform.
    `services` - the list of allo
    """
    def __init__(self, services: list[str]):
        super().__init__(services)


class StringRe(object):
    """
    Base class for working with types that are strings that allow a full character set.
    Example: path, username
    """
    
    def __init__(self, charset: set[chr]) -> None:
        """
        `charset` - the set of allowable characters for this type.
        """
        if charset.intersection(RESERVED_CHARS):
            raise InvalidCharacterError(f'The provided charset includes a reserved character and cannot be used.')
        self.charset = charset
        self.z_all_vals_re_ref = z3.Star(z3.Union([z3.Re(z3.StringVal(c)) for c in charset]))
    
    def to_re(self, value):
        if value == '*':
            return self.z_all_vals_re_ref
        if not '*' in value:
            return z3.Re(z3.StringVal(value))
        parts = value.split('*')
        # compute the first one since Concat requires at least two args.
        result = z3.Concat(z3.Re(z3.StringVal(parts[0])), self.z_all_vals_re_ref)
        # handle the case of str containing a single * in the last char
        if len(parts) == 2 and value[-1] == '*':
            return result
        for idx, part in enumerate(parts[1:]):
            # it is possible the str ends in a '*', in which case we only need to add a single re_all_chars,
            # unless we already did because this is the
            if part == '':
                if idx == 0:
                    return result
                return z3.Concat(result, self.z_all_vals_re_ref)
            # handle whether this is the final part or not:
            if idx + 2 == len(parts):
                return z3.Concat(result, z3.Re(z3.StringVal(part)))
            result = z3.Concat(result, z3.Re(z3.StringVal(part)))
        return result

 
class StringTupleRe(object):
    """
    Base class for working with types that are tuples of string types.  
    """

    def __init__(self, fields: list[Dict[str, Any]]) -> None:
        for f in fields:
            if not 'name' in f:
                raise InvalidStringTupleStructure(message=f'field {f} missing required "name" key.')
            if not type(f['name']) == str:
                raise InvalidStringTupleStructure(message=f'field {f} "name" property should be type string.')
            if not 'type' in f:
                raise InvalidStringTupleStructure(message=f'field {f} missing required "type" key.')
            if not type(f['type']) == type:
                raise InvalidStringTupleStructure(message=f'field {f} "type" property should be type Type.')
            # create an instance of f['type'] passing the **f['kwargs'] as the key-word arguments to the constructor.
            val = f['type'](**f['kwargs'])
            setattr(self, f['name'], val)
            
        self.fields = fields
        self.field_names = [f['name'] for f in self.fields]
        self.data = {}

    def to_re(self):
        if not self.data:
            raise MissingStringTupleData(f'No data found on {type(self)} object; was set_data() called?')
        res = []
        for idx, field in enumerate(self.fields):
            value = self.data[field['name']]
            res.append(field['type'].to_re(getattr(self, field['name']), value))
            # separate each field in the tuple with a dot ('.') character, but not after the very last field:
            if idx < len(self.fields)-1:
                res.append(z3.Re(z3.StringVal('.')))
        self.re = z3.Concat(*res)
        return self.re

    def set_data(self, **kwargs):
        for k, v in kwargs.items():
            if k not in self.field_names:
                raise InvalidStringTupleData(message=f'Got unexpected argument {k} to set_data(). Fields are: {self.field_names}')
            self.data[k] = v
        # check that all fields were set
        for f in self.field_names:
            if f not in self.data.keys():
                raise InvalidStringTupleData(message=f'Required field {f} missing in call to set_data.')


class Prinicipal(StringTupleRe):
    """
    Class representing a "principal"; i.e., an identity in a cloud system.
    
    Examples:
    sites = ['tacc', 'uh']
    tenants = ['dev', 'cii', 'admmin', 'tacc']
    p = core.Prinicipal(sites=sites, tenants=tenants)
    p.set_data(site='tacc', tenant='dev', username='testuser*')
    simplify(InRe('tacc.dev.testuser12', p.to_re()))
    Out: True
    simplify(InRe('uh.dev.testuser12', p.to_re()))
    Out: False

    """
    
    def __init__(self, sites: list[str], tenants: list[str]) -> None:
        self.sites = sites
        self.tenants = tenants
        fields = [
            {'name': 'site', 'type': SiteRe, 'kwargs': {'sites': sites} },
            {'name': 'tenant', 'type': TenantRe, 'kwargs': {'tenants': tenants}},
            {'name': 'username', 'type': StringRe, 'kwargs': {'charset': ALPHANUM_SET }}
        ]
        super().__init__(fields)


class Resource(StringTupleRe):
    """
    Class representing a "resource"; i.e., a path on a service within a tenant at some site.

    Examples:
    sites = ['tacc', 'uh']
    tenants = ['dev', 'cii', 'admmin', 'tacc']
    services = ['actors', 'apps', 'files, 'jobs', 'systems']
    r = core.Resource(sites=sites, tenants=tenants, services=services)
    r.set_data(site='tacc', tenant='dev', service='apps', path='/app1')

    r.set_data(site='tacc', tenant='dev', service='files', path='/sys1/*')
    simplify(InRe('tacc.dev.files./sys1/some/path/on/sys1', r.to_re()))
      Out: True
    """
    
    def __init__(self, sites: list[str], tenants: list[str], services: list[str]) -> None:
        self.sites = sites
        self.tenants = tenants
        self.services = services
        fields = [
            {'name': 'site', 'type': SiteRe, 'kwargs': {'sites': sites} },
            {'name': 'tenant', 'type': TenantRe, 'kwargs': {'tenants': tenants} },
            {'name': 'service', 'type': ServiceRe, 'kwargs': {'services': services} },
            {'name': 'path', 'type': StringRe, 'kwargs': {'charset': PATH_CHAR_SET} },
        ]
        super().__init__(fields=fields)


class Action(HTTPVerbRe):
    """
    Class representing an action on a resource; i.e., an HTTP verb.
    a = Action()
    a.set_data('GET')
    """
    def __init__(self) -> None:
        super().__init__()
        self.data = {}

    def set_data(self, verb):
        self.data['verb'] = verb
    
    def to_re(self):
        if not self.data:
            raise MissingStringEnumData(message=f'No data found on {type(self)} object; was set_data() called?')
        self.re = super().to_re(value=self.data['verb'])
        return self.re


class Policy(object):
    """
    Class representing a security policy.
    """

    def __init__(self, principal: Prinicipal, resource: Resource, action: Action, decision: Enum('allow', 'deny')) -> None:
        if not decision in ('allow', 'deny'):
            raise InvalidValueError(message=f'Policy decision must be allow or deny, got {decision}.' )
        self.principal = principal
        self.resource = resource
        self.action = action
        self.decision = decision


class PolicyManager():
    """
    Convenience class for creaing policies.
    """
    def __init__(self, sites, tenants, services):
        self.sites = sites
        self.tenants = tenants
        self.services = services

    def policy_from_strs(self, principal: str, resource: str, action: str, decision: str):
        p = Prinicipal(sites=self.sites, tenants=self.tenants)
        parts = principal.split('.')
        if not len(parts) == 3:
            raise InvalidValueError(f'principal should be contain exactly 2 dot characters; got {principal}')
        p.set_data(site=parts[0], tenant=parts[1], username=parts[2])
        r = Resource(sites=self.sites, tenants=self.tenants, services=self.services)
        parts = resource.split('.')
        if not len(parts) == 4:
            raise InvalidValueError(f'resource should be contain exactly 3 dot characters; got {resource}')
        r.set_data(site=parts[0], tenant=parts[1], service=parts[2], path=parts[3])
        a = Action()
        a.set_data(action)
        return Policy(p, r, a, decision)


class TapisPolicyManager(PolicyManager):
    """
    Convenience class for working with Tapis policies.

    Examples:
    t = core.TapisPolicyManager()
    p = t.policy_from_strs('tacc.dev.testuser1', 'tacc.dev.files./sys1/*', 'GET', 'allow')
    """
    def __init__(self):
        super().__init__(sites=['tacc', 'uh'], 
                         tenants=['admin', 'cii', 'dev', 'a2cps', 'tacc'], 
                         services=['actors', 'apps', 'files', 'jobs', 'systems'])


class PolicyEquivalenceChecker(object):
    """
    Class for reasoning formally about two sets of policies.
    """
    
    def __init__(self, policy_set_1: list[Policy], policy_set_2: list[Policy]):
        self.policy_set_1 = policy_set_1
        self.policy_set_2 = policy_set_2
        
        # one free string variable for each dimensions of a policy
        self.principal = z3.String('principal')
        self.resource = z3.String('resource')
        self.action = z3.String('action')
        
        # statements related to the policy sets (1 for each)
        self.statements = []
        # a z3 solver that can be used to prove implication theorms about the policy sets        
        self.solver = self.get_solver()

    def get_allow_policies(self, policy_set: list[Policy]):
        return [p for p in policy_set if p.decision == 'allow']
    
    def get_deny_policies(self, policy_set: list[Policy]):
        return [p for p in policy_set if p.decision == 'deny']
    
    def get_match_list(self, policy_set: list[Policy]):
        return [z3.And(z3.InRe(self.principal, p.principal.to_re()), 
                       z3.InRe(self.resource, p.resource.to_re()), z3.InRe(self.action, p.action.to_re())) 
                       for p in policy_set]

    def get_policy_set_re(self, allow_match_list: list, deny_match_list: list):
        if len(deny_match_list) == 0:
            return z3.Or(*deny_match_list)
        else:
            return z3.And(z3.Or(*allow_match_list), z3.Not(z3.And(*deny_match_list)))

    def get_solver(self):
        # s = z3.Solver()
        for p_set in [self.policy_set_1, self.policy_set_2]:
            allow_match_list = self.get_match_list(self.get_allow_policies(p_set))
            deny_match_list = self.get_match_list(self.get_deny_policies(p_set))
            self.statements.append(self.get_policy_set_re(allow_match_list, deny_match_list))
        # 
        # s.add(z3.Implies(self.statements[0], self.statements[1]))
        # return s

