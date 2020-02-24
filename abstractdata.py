# Members of all of these classes are kinda not supposed to be directly constructed,
# use the functions at the end of this file instead

class AbstractValue:
    """
    Abstract representation of any value, either public or secret.
    Note that as of this writing, the secret/public distinction is only used by SpectreExplicitState.

    Intended to be a base class: don't directly instantiate this, instantiate one of its subclasses below
    """
    def __init__(self, *, bits=64, value=None, secret):  # secret is a required argument but must be keyworded by caller
        """
        bits: how many bits long the value is
        value: If not None, then a (concrete or symbolic) value which this AbstractValue must be equal to
        secret: boolean, whether the value is secret or not
        """
        self.bits = bits
        self.secret = secret
        self.value = value

class AbstractNonPointer(AbstractValue):
    """
    A non-pointer value, either public or secret
    """
    pass

class AbstractPointer(AbstractValue):
    """
    A (public) pointer to another AbstractValue, or array of AbstractValues, or struct of AbstractValues
    """
    def __init__(self, pointee, maxPointeeSize=0x10000, cannotPointSecret=False):
        """
        pointee: the AbstractValue, array of AbstractValues, or struct of AbstractValues being pointed to
        maxPointeeSize: upper bound on the size of the value/array/struct being pointed to
        cannotPointSecret: if True, we assert that this pointer _cannot_ point (directly) to any secret data,
            even by aliasing with a pointer to secret data
        """
        super().__init__(bits=64, secret=False)  # we assume 64-bit pointers
        assert isinstance(pointee, AbstractValue) or \
            (isinstance(pointee, list) and all(isinstance(v, AbstractValue) for v in pointee))
        self.pointee = pointee
        self.maxPointeeSize = maxPointeeSize
        self.cannotPointSecret = cannotPointSecret

class AbstractPointerToUnconstrainedPublic(AbstractValue):
    """
    A (public) pointer to unconstrained public data, which could be a public value,
        an array (of unconstrained size) of public values, or a public data structure
    """
    def __init__(self, maxPointeeSize=0x10000, cannotPointSecret=False):
        """
        maxPointeeSize: upper bound on the size of the value/array/struct being pointed to
        cannotPointSecret: if True, we assert that this pointer _cannot_ point (directly)
            to any secret data, even by aliasing with a pointer to secret data
        """
        super().__init__(bits=64, secret=False)  # we assume 64-bit pointers
        self.maxPointeeSize = maxPointeeSize
        self.cannotPointSecret = cannotPointSecret

class AbstractSecretPointer(AbstractValue):
    """
    A pointer where the pointer value itself is a secret
    """
    def __init__(self):
        # Currently treat this the same as a secret non-pointer, but reserve the right to treat it differently in the future
        super().__init__(bits=64, secret=True)  # we assume 64-bit pointers

# Use these functions to create abstract values

def publicValue(value=None, bits=64):
    """
    A single public value
    bits: how many bits long the value is
    value: if not None, then a specific (concrete or symbolic) value which this value takes on
    """
    return AbstractNonPointer(bits=bits, value=value, secret=False)

def secretValue(value=None, bits=64):
    """
    A single secret value
    bits: how many bits long the value is
    value: if not None, then a specific (concrete or symbolic) value which this value takes on
    """
    return AbstractNonPointer(bits=bits, value=value, secret=True)

def pointerTo(pointee, maxPointeeSize=0x10000, cannotPointSecret=False):
    """
    A (public) pointer to another thing constructed with one of these functions
    maxPointeeSize: upper bound on the size of the value/array/struct being pointed to
    cannotPointSecret: if True, we assert that this pointer _cannot_ point (directly)
        to any secret data, even by aliasing with a pointer to secret data
    """
    return AbstractPointer(pointee, maxPointeeSize=maxPointeeSize, cannotPointSecret=cannotPointSecret)

def pointerToUnconstrainedPublic(maxPointeeSize=0x10000, cannotPointSecret=False):
    """
    A (public) pointer to unconstrained public data, which could be a public value,
        an array (of unconstrained size) of public values, or a public data structure
    maxPointeeSize: upper bound on the size of the value/array/struct being pointed to
    cannotPointSecret: if True, we assert that this pointer _cannot_ point (directly)
        to any secret data, even by aliasing with a pointer to secret data
    """
    return AbstractPointerToUnconstrainedPublic(maxPointeeSize=maxPointeeSize, cannotPointSecret=cannotPointSecret)

def publicArray(lengthInBytes):
    """
    An array containing entirely unconstrained public values
    lengthInBytes: length in *bytes*
    """
    if lengthInBytes % 8 != 0:
        raise ValueError("not implemented yet: array sizes not multiples of 8 bytes")
    return [publicValue() for _ in range(lengthInBytes//8)]

def secretArray(lengthInBytes):
    """
    An array containing entirely secret values
    lengthInBytes: length in *bytes*
    """
    if lengthInBytes % 8 != 0:
        raise ValueError("not implemented yet: array sizes not multiples of 8 bytes")
    return [secretValue() for _ in range(lengthInBytes//8)]

def array(values):
    """
    An array of other AbstractValues
    values: the AbstractValues in the array
        The length of `values` indicates the length of the array
    """
    for val in values: assert isinstance(val, AbstractValue)
    return values

def flatten(elements):
    final = []
    for el in elements:
        if isinstance(el, list):
            final += flatten(el)
        else:
            final.append(el)
    return final

def struct(elements):
    """
    A struct of other AbstractValues
    elements: the AbstractValues in the struct
    """
    flattened = flatten(elements)
    for el in flattened: assert isinstance(el, AbstractValue)
    return flattened
