from enum import Enum
from typing import Any, Dict
import z3
from cloudz3sec import errors
from cloudz3sec.errors import InvalidValueError, InvalidCharacterError, InvalidStringTupleStructure, \
     InvalidStringTupleData, MissingStringTupleData, InvalidPolicyStructure, MissingPolicyField, MissingStringEnumData, \
         MissingStringReData, InvalidPolicyFieldType

#from cloudz3sec.cloudz3sec.cloud import SrcIp

RESERVED_CHARS = set('.',)


class BaseRe(object):
    """
    The base class for all classes equpied with z3 regular expressions.
    """
    
    def to_re(self, value=None):
        raise NotImplementedError()

    def set_data(self, value):
        """
        Set the data for the instance.
        Override this method in child classes for more complex types/behavior.
        """
        self.data = value

    def get_z3_boolref(self, name: str) -> z3.z3.BoolRef:
        """
        Generate a z3 boolean expression in one or more free variables that equals the constraint in the free variable(s)
        represented by the value specified for this instance. 
        `name` - the name to use when generating the free varaible(s). Typically, the `name` will be given by the name of the
        field in the policy.

        Note: this function can only be called once set_data() has been called on the instance.
        """
        if not hasattr(self, 'data') or not self.data:
            raise MissingStringEnumData('No data on instance. get_z3_boolref requires data. Was set_data called()?')
        free_var = z3.String(name)
        return z3.InRe(free_var, self.to_re())


class StringEnumRe(BaseRe):
    """
    Base class for working with types that are restricted to a set of valid strings.

    Examples include the 
        * Action type, which is an HTTP verb and can take values like "GET", "POST", "PUT", "DELETE", ...
        * Types from the application domain which are pre-determined finite lists, e.g., "sites", "tenants", "services", etc.

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
    
    def to_re(self, value=None):
        if not value:
            if hasattr(self, 'data'):
                value = self.data
            else:
                raise MissingStringEnumData('No value passed to to_re() and no data on instance. Was set_data called()?')
        if value == '*':
            return self.z_all_vals_re_ref
        if value not in self.values:
            message=f"value {value} is not allowed for type {type(self)}; allowed values are {self.values}"
            raise InvalidValueError(message=message)
        return z3.Re(z3.StringVal(value))


class StringRe(BaseRe):
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
    
    def to_re(self, value=None):
        if not value:
            if hasattr(self, 'data'):
                value = self.data
            else:
                raise MissingStringReData('No value passed to to_re() and no data on instance. Was set_data called()?')
        # check that the value is contained within the charset plus the * character
        if not self.charset.union(set('*')).intersection(set(value)) == set(value):
            raise errors.InvalidValueError("Data must be contained within the charset for this StringrRe.")
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

 
class StringTupleRe(BaseRe):
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
        return z3.Concat(*res)

    def set_data(self, **kwargs):
        for k, v in kwargs.items():
            if k not in self.field_names:
                raise InvalidStringTupleData(message=f'Got unexpected argument {k} to set_data(). Fields are: {self.field_names}')
            self.data[k] = v
        # check that all fields were set
        for f in self.field_names:
            if f not in self.data.keys():
                raise InvalidStringTupleData(message=f'Required field {f} missing in call to set_data.')


class IpAddr2(object):
    """
    A class representing string of the IP address in the CIDR format.
    """

    def __init__(self, netmasklen: int):
        self.netmasklen = netmasklen
        if self.netmasklen == 24:
            self.netmask_bv = self.convert_to_bv('255.255.255.0')
        # TODO -- is this right?
        elif self.netmasklen == 16: # 16 bit
            self.netmask_bv = self.convert_to_bv('255.255.0.0')
        elif self.netmasklen == 8: # 8 bit 
            self.netmask_bv = self.convert_to_bv('255.0.0.0')
        else:
            raise InvalidValueError(f"Value {netmasklen} is not a supported netmaskelen. Valid values are: 8,16,24.") 

    def convert_to_bv(self, ip: str):
        """
        Convert an IP address (string) to a z3 bit vector value.
        """
        parts = ip.split('.')
        if not len(parts) == 4:
            raise InvalidValueError("Invalid IP address; format must be A.B.C.D")
        # TODO -- why 8?
        addr_bit_vecs = [z3.BitVecVal(part, 8) for part in parts]
        return z3.Concat(*addr_bit_vecs)

    def set_data(self, ip_addr: str):
        """
        Set the actual IP address for this instance.
        """
        self.ip_addr = ip_addr
        self.ip_bv = self.convert_to_bv(ip_addr)
        self.masked_ip_bv = self.ip_bv & self.netmask_bv

    def get_z3_boolref(self, name):
        # TODO -- test this for correctness
        free_vars = z3.Concat(z3.BitVec(f'{name}_a', 8), 
                              z3.BitVec(f'{name}_b', 8), 
                              z3.BitVec(f'{name}_c', 8), 
                              z3.BitVec(f'{name}_d', 8))
        return z3.simplify(free_vars & self.netmask_bv == self.masked_ip_bv)



class IpAddr(object):
    """
    A class representing string of the IP address in the CIDR format
    """
    def __init__(self, ip_addr:str) ->None:
        # TODO check if the format of the ip address is a.b.c.d/[0..32]
        # TODO where a,b,c,d  each lies between 0 and 255
        ip_split = ip_addr.split('/')
        self.ip = ip_split[0]
        self.netmasklen = ip_split[1]
        print(self.netmasklen)

    def convert_to_bv(self,ip:str) :
        #ip_split = ip_addr.split('/')
        print(" converting ip to bit vec: "+ ip)
        abcd = ip.split('.')
        addr_bit_vec = []
        for i in range(0, 4):
           addr_bit_vec.append(z3.BitVecVal(abcd[i], 8))
        ip_bit_vec = z3.Concat(addr_bit_vec[0], addr_bit_vec[1], addr_bit_vec[2], addr_bit_vec[3])
        print("sexpr :"+ str(ip_bit_vec.sexpr()) )
        return ip_bit_vec

    #def netmask_bv(self, ip_bit_vec:z3.BitVecRef, netmask_bit_vec:z3.BitVecRef):
    #    return ip_bit_vec & netmask_bit_vec

    def set_data(self):
        ip_bv = self.convert_to_bv(self.ip)
        if self.netmasklen == '24':
            netmask_bv = self.convert_to_bv('255.255.255.0')
        else: # 16 bit
            netmask_bv = self.convert_to_bv('255.255.0.0')

        self.masked_ip_bv = ip_bv & netmask_bv
        print('masked_ip_bv: ' + str(z3.simplify(self.masked_ip_bv)))
    #def match(self, bit_vec_1: z3.BitVecRef,bit_vec_2:z3.BitVecRef ):
    #    return z3.simplify(bit_vec_1 == bit_vec_2)
    def to_masked_bv(self):
        return self.masked_ip_bv


class Decision(object):
    """
    A class representing a decision in a policy. 
    In the current implementation, every Policy must have exactly one decision field.
    """
    def __init__(self, decision: str) -> None:
        if not decision in ['allow', 'deny']:
            raise InvalidValueError(f'Decisions must have value allow or deny; got {decision}.')
        self.decision = decision


class BasePolicy(object):
    """
    Base class for working with policies. Decend from this class and specify the fields for your policy engine.
    """
    def __init__(self, fields: list[Dict[str, Any]], **kwargs) -> None:
        # every policy is currently required to have exactly one decision field, because the decision property is critical to the
        # current implementation of the policy equivalence checker.
        found_decision = False
        # we want to track the fields that are not the decision field, as these will be analyzed together by the policy equivalence checker
        not_decision_fields = []
        for f in fields:
            if not 'name' in f:
                raise InvalidPolicyStructure(message=f'field {f} missing required "name" key.')
            if not type(f['name']) == str:
                raise InvalidPolicyStructure(message=f'field {f} "name" property should be type string.')
            if not 'type' in f:
                raise InvalidPolicyStructure(message=f'field {f} missing required "type" key.')
            if not type(f['type']) == type:
                raise InvalidPolicyStructure(message=f'field {f} "type" property should be type Type.')
            # TODO -- we could check that the value of f['type'] is one of the classes that we recognize, i.e.,
            # a StringEnumRe, StringRe, StringTupleRe, etc.

            # create an attribute on the policy for each field defined. 
            property = f['name']
            prop_type = f['type']
            if prop_type == Decision:
                # if we already found a Decision, this is the 2nd one and that is an error.
                if found_decision:
                    raise InvalidPolicyStructure(message=f'A property can have only one Decision field; found 2 or more.')
                found_decision = True
                self.decision_field = property
            else:
                not_decision_fields.append(f)
            if not property in kwargs.keys():
                raise MissingPolicyField(message=f'Policy requires the {property} parameter. Found: {kwargs.keys()}')
            if not type(kwargs[property]) == prop_type:
                raise InvalidPolicyFieldType(message=f'field {property} must be of type {prop_type}; got {type(kwargs[property])}.')
            # check that at the least, each field that is not a Decision field has a function on it that
            # can return the z3 free variable
            if not prop_type == Decision:
                if not hasattr(kwargs[property], 'get_z3_boolref'):
                    raise InvalidPolicyFieldType(message=f'field {property} must have a function get_z3_boolref but it does not.')
            # this creates an attribute on the Policy object whose name is the name of the field and whose 
            # value is the value of the kwarg of the same name.
            setattr(self, property, kwargs[property])
        # todo -- decide about this
        # if we did not find a decision, we can either raise an error or add one automatically. for now, we will raise an error
        if not found_decision:
            raise InvalidPolicyStructure(message='A policy class is required to have exactly one Deciion field; and did not find one.')
        self.all_fields = fields
        self.fields = not_decision_fields
        self.field_names = [f['name'] for f in self.fields]        
        

class PolicyEquivalenceChecker(object):
    """
    Class for reasoning formally about two sets of policies.
    """
    
    def __init__(self, policy_type: type, policy_set_p: list[BasePolicy], policy_set_q: list[BasePolicy]):
        # the type of policies this policy checker is working with. Should be a child of BasePolicy
        self.policy_type = policy_type
        
        # the two sets of policies
        self.policy_set_p = policy_set_p
        self.policy_set_q = policy_set_q
        
        # one free string variable for each dimensions of a policy
        self.free_variables = {}
        self.free_variables_type = {}
        # the list of proerty names that will be contributing to the z3 boolean expression constraints. 
        # the Decision field is treated in a special way and does not contribute a z3 boolean expression so we skip it
        # here.
        self.z3_constraint_property_names = [f['name'] for f in self.policy_type.fields if not f['type'] == Decision]
        # statements related to the policy sets (1 for each)
        self.P, self.Q = self.get_statements()

    # def get_masked_bv(self, netmasklen):

    #     if netmasklen == '24':
    #         netmask_ip = IpAddr('255.255.255.0/24')
    #         netmask_ip.set_data()

    #     else:  # 16 bit
    #         netmask_ip = IpAddr('255.255.0.0/16')
    #         netmask_ip.set_data()
    #     netmask_bv = netmask_ip.to_masked_bv()
    #     return netmask_bv
        # self.masked_ip_bv = x & netmask_bv
    
    def get_allow_policies(self, policy_set: list[BasePolicy]):
        return [p for p in policy_set if getattr(p, p.decision_field).decision == 'allow']
    
    def get_deny_policies(self, policy_set: list[BasePolicy]):
        return [p for p in policy_set if getattr(p, p.decision_field).decision == 'deny']
    
    def get_match_list(self, policy_set: list[BasePolicy]):
        and_list = []
        for p in policy_set:
            # and_re = [ z3.InRe(self.free_variables[f], getattr(p, f).to_re()) if self.free_variables_type[f] != IpAddr  else z3.simplify(self.free_variables[f] & self.get_masked_bv(getattr(p,f).netmasklen) == getattr(p,f).to_masked_bv()) for f in self.free_variables.keys() ]
            # and_re = [getattr(p, f).get_z3_boolref(f) for f in self.free_variables.keys()]
            boolrefs = [getattr(p, f).get_z3_boolref(f) for f in self.z3_constraint_property_names]
            and_list.append(z3.And(*boolrefs))

        print(and_list)
        return and_list

    def get_policy_set_re(self, allow_match_list: list, deny_match_list: list):
        if len(deny_match_list) == 0:
            return z3.Or(*allow_match_list)
        else:
            return z3.And(z3.Or(*allow_match_list), z3.Not(z3.And(*deny_match_list)))

    def get_statements(self):
        for p_set in [self.policy_set_p, self.policy_set_q]:
            allow_match_list = self.get_match_list(self.get_allow_policies(p_set))
            deny_match_list = self.get_match_list(self.get_deny_policies(p_set))
            yield self.get_policy_set_re(allow_match_list, deny_match_list)

    def prove(self, statement_1, statement_2):
        return z3.prove(z3.Implies(statement_1, statement_2))

    def p_implies_q(self):
        return self.prove(self.P, self.Q)

    def q_implies_p(self):
        return self.prove(self.Q, self.P)
