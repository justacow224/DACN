import os
import ML_KEM_internal
import K_PKE



def KeyGen():
    """
    REF PAGE 35-36
    
    """
    d = os.urandom(32)
    z = os.urandom(32)
    if d is None or z is None:
        raise ValueError("Random bit generation failed")
    ek, dk = ML_KEM_internal.KeyGen_internal(d, z)
    return ek, dk

def Encaps(ek):
    """
    REF PAGE 36-37
    
    """
    pass

def Decaps(dk, c):
    """
    REF PAGE 37-38
    
    """
    pass