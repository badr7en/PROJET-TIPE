import numpy
import numpy as np
import sys
#On saisit les matrices définissant le système de Cryptographie
G =numpy.array([[1,0,0,0,1,1,0],[0,1,0,0,1,0,1],[0,0,1,0,0,1,1 ],[0,0,0,1,1,1,1],[0,0,0,1,1,0,1],[0,0,0,1,1,1,0],[0,1,0,1,1,1,1],[0,0,1,1,1,1,1]])
S =numpy.array([[1,1,0,1,1,0,1],[1,0,0,1,1,0,1],[0,1,1,1,1,0,1],[1,1,0,0,1,0,1],[1,1,0,0,1,1,1],[1,1,1,0,1,0,1],[0,1,0,0,1,1,0]])
P=numpy.array([[0,1,0,0,0,0,0,0],[0,0,0,1,0,0,0,0],[0,0,0,0,0,0,0,1],[1,0,0,0,0,0,0,0],[0,0,1,0,0,0,0,0],[0,0,0,0,0,1,0,0],[0,0,0,0,1,0,0,0],[0,0,0,0,0,0,1,0]])
#On calcule la matrice G'
matrix = np.dot(P,G)
G_1 = np.dot(matrix,S)
#On calcule l'inverse de la matrice p
P_1=numpy.linalg.inv(P)
#On calcule l'inverse de S
S_1=numpy.linalg.inv(S)

#On convertit un mot sous forme de liste de vecteurs binaires
def Bin_Vecteur(mot):
    a=mot
    a_byte_array = bytearray(a, "utf8")
    byte_list = []
    for byte in a_byte_array:
        x = int(byte)
        binary_representation = [int(d) for d in bin((1<<8)+x)[-7:]]
        byte_list.append(binary_representation)
    return byte_list
#On commence la procédure de cryptage
def Crypt(G_1,erreur,message):
    mot=message
    mot_bin=Bin_Vecteur(mot)
    n=len(mot_bin)
    e=erreur
    c_list=[]
    c=''
    for i in range(n):
        m=mot_bin[i]
        res=numpy.dot(G_1,m)
        res = numpy.add(res,e)
        c_list.append(res)
        for j in range(8):
            c=c+str(int(res[j])%2)
    return c,c_list
#On commence la procédure de décryptage
#On calcule Sm par la méthode de Pivot de Gauss
def Cal_LU_pivot(D,g):
    A=np.array((D),dtype=float)
    f=np.array((g),dtype=float)
    m = A.shape[1]
    n = f.size
    for i in range(0,m-1):     # Loop through the columns of the matrix
        if np.abs(A[i,i])==0:
            for k in range(i+1,m):
                if np.abs(A[k,i])>np.abs(A[i,i]):
                    A[[i,k]]=A[[k,i]]             # Swaps ith and kth rows to each other
                    f[[i,k]]=f[[k,i]]
                    break

        for j in range(i+1,m):     # Loop through rows below diagonal for each column
            x = A[j,i]/A[i,i]
            A[j,:] = A[j,:] - x*A[i,:]
            f[j] = f[j] - x*f[i]
    return A,f

def Back_Subs(A,f):
    n = A.shape[1]
    x = np.zeros(n)             # Initialize the solution vector, x, to zero
    x[n-1] = f[n-1]/A[n-1,n-1]    # Solve for last entry first
    for i in range(n-2,-1,-1):      # Loop from the end to the beginning
        sum_ = 0
        for j in range(i+1,n):        # For known x values, sum and move to rhs
            sum_ = sum_ + A[i,j]*x[j]
        x[i] = (f[i] - sum_)/A[i,i]
    return x
#Procédure de décryptage
def Decrypt(P_1,S_1,G,e,msgcrypt):
    messagedecryt=[]
    c_list = np.array(msgcrypt)
    p,q = c_list.shape
    for k in range(p):
        y = numpy.dot(P_1,c_list[k])
        res=-numpy.dot(P_1,e)
        GSm=numpy.add(y,res)
        B,g = Cal_LU_pivot(G,GSm)
        Sm= Back_Subs(B,g)
        d = np.dot(S_1,Sm)
        messagedecryt.append(d)
    return messagedecryt
#On convertit le mot sous forme binaire en caractères
def encaracteres(motbinaire):
    motbin = motbinaire
    mot=''
    n=len(motbin)
    for l in range(n) :
        dec = 0
        for i in range(7):
            dec = dec + motbin[l][i]*(2**(6-i))
        mot = mot + chr(int(dec))
    return mot

message = 'Bonjour'
e = ([0,0,0,0,1,0,0,1])
print('Message original:',message)
print('Message crypté:', Crypt(G_1,e,message)[0])
msgcrypt=Crypt(G_1,e,message)[1]
print('Message decrypté:', Decrypt(P_1,S_1,G,e,msgcrypt))
motbinaire = Decrypt(P_1,S_1,G,e,msgcrypt)
print('Message decrypté en lettres:', encaracteres(motbinaire))

