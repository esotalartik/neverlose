G='<QQ'
F=Exception
import idaapi as P,idautils as Q,idc,re
from struct import pack as E
R=re.compile('_mm_xor_ps\\(\\s*(v\\d+),\\s*(v\\d+)\\s*\\);')
S=re.compile('(v\\d+)\\.m128_u64\\[(\\d)\\] = 0x([0-9A-Fa-f]+)LL')
def T(encrypted_low,encrypted_high,key):A=E(G,encrypted_low,encrypted_high);B=bytes(A^B for(A,B)in zip(A,key));return B.rstrip(b'\x00').decode(errors='ignore')
def A():
	for H in Q.Functions():
		try:
			U=P.decompile(H);V=str(U).splitlines();A={}
			for I in V:
				J=S.search(I)
				if J:
					B,C,D=J.groups();C=int(C);D=int(D,16)
					if B not in A:A[B]=[None,None]
					A[B][C]=D
				K=R.search(I)
				if K:
					L,M=K.groups()
					if L in A and M in A:
						W,N=A[L];X,O=A[M]
						if N==O:
							Y=E(G,X,O)
							try:Z=T(W,N,Y);print(f"[{hex(H)}]: {Z}")
							except F as a:continue
		except F as a:continue
A()