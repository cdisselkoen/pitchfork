# Members of all of these classes are kinda not supposed to be directly constructed,
# use the functions at the end of this file instead

class AbstractValue:
    """
    Abstract representation of a 64-bit value, either public or secret.
    Note that as of this writing, the secret/public distinction is only used by SpectreExplicitState.

    Intended to be a base class: don't directly instantiate this, instantiate one of its subclasses below
    """
    def __init__(self, secret):
        """
        secret: boolean, whether the value is secret or not
        """
        self.secret = secret

class AbstractNonPointer(AbstractValue):
    """
    A non-pointer value, either public or secret
    """
    pass

class AbstractPointer(AbstractValue):
    """
    A (public) pointer to another AbstractValue, or array of AbstractValues, or struct of AbstractValues
    """
    def __init__(self, pointee, maxPointeeSize=0x10000):
        """
        pointee: the AbstractValue, array of AbstractValues, or struct of AbstractValues being pointed to
        pointeeSize: upper bound on the size of the value/array/struct being pointed to
        """
        super().__init__(secret=False)
        assert isinstance(pointee, AbstractValue) or \
            (isinstance(pointee, list) and all(isinstance(v, AbstractValue) for v in pointee))
        self.pointee = pointee
        self.maxPointeeSize = maxPointeeSize

class AbstractPointerToUnconstrainedPublic(AbstractValue):
    """
    A (public) pointer to unconstrained public data, which could be a public value,
        an array (of unconstrained size) of public values, or a public data structure
    """
    def __init__(self):
        # Currently treat this the same as a public non-pointer, but reserve the right to treat it differently in the future
        super().__init__(secret=False)

class AbstractSecretPointer(AbstractValue):
    """
    A pointer where the pointer value itself is a secret
    """
    def __init__(self):
        # Currently treat this the same as a secret non-pointer, but reserve the right to treat it differently in the future
        super().__init__(secret=True)

# Use these functions to create abstract values

def publicValue():
    """
    A single public 64-bit value
    """
    return AbstractNonPointer(secret=False)

def secretValue():
    """
    A single secret 64-bit value
    """
    return AbstractNonPointer(secret=True)

def pointerTo(pointee, maxPointeeSize=0x10000):
    """
    A (public) pointer to another thing constructed with one of these functions
    maxPointeeSize: upper bound on the size of the value/array/struct being pointed to
    """
    return AbstractPointer(pointee, maxPointeeSize)

def pointerToUnconstrainedPublic():
    """
    A (public) pointer to unconstrained public data, which could be a public value,
        an array (of unconstrained size) of public values, or a public data structure
    """
    return AbstractPointerToUnconstrainedPublic()

def publicArray(lengthInBytes):
    """
    An array containing entirely unconstrained public values
    lengthInBytes: length in *bytes*
    """
    if lengthInBytes % 8 != 0:
        raise ValueError("not implemented yet: array sizes not multiples of 8 bytes")
    return [AbstractValue(False) for _ in range(lengthInBytes//8)]

def secretArray(lengthInBytes):
    """
    An array containing entirely secret values
    lengthInBytes: length in *bytes*
    """
    if lengthInBytes % 8 != 0:
        raise ValueError("not implemented yet: array sizes not multiples of 8 bytes")
    return [AbstractValue(True) for _ in range(lengthInBytes//8)]

def array(values):
    """
    An array of other AbstractValues
    values: the AbstractValues in the array
        The length of `values` indicates the length of the array
    """
    for val in values: assert isinstance(val, AbstractValue)
    return values

def struct(elements):
    """
    A struct of other AbstractValues
    elements: the AbstractValues in the struct
    """
    for el in elements: assert isinstance(el, AbstractValue)
    return elements
