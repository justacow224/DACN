from GLOBAL import k, n, q
import SamplingAlgr
import CryptoFunc
import NTT
import GeneralAlgr

def KeyGen(d):
    """
    REF PAGE 28-29
    
    """
    p, o = CryptoFunc.G(d+k)
    N = 0
    A_hat = [[0 for _ in range(k)] for _ in range(k)]
    s = [0 for _ in range(k)]
    e = [0 for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A_hat[i][j] = SamplingAlgr.SampleNTT(p+i.to_bytes(1, 'big')+j.to_bytes(1, 'big'))

    for i in range(k):
        s[i] = SamplingAlgr.SamplePolyCBD(CryptoFunc.PRF(o, N))
        N += 1
    
    for i in range(k):
        e[i] = SamplingAlgr.SamplePolyCBD(CryptoFunc.PRF(o, N))
        N += 1
    
    s_hat = NTT.NTT(s)
    e_hat = NTT.NTT(e)
    t_hat = NTT.MultiplyNTTs(A_hat, s_hat) + e_hat

    ek_PKE = GeneralAlgr.ByteEncode(t_hat) + p
    dk_PKE = GeneralAlgr.ByteEncode(s_hat)
    return ek_PKE, dk_PKE

def Encrypt(ek_PKE, m, r):
    """
    REF PAGE 29-30
    
    """
    pass

def Decrypt(dk_PKE, c):
    """
    REF PAGE 30
    
    """
    pass

