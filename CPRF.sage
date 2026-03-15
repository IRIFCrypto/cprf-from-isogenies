import time
import hashlib
import sys
import os
import pathlib

submodule_path = pathlib.Path(os.getcwd()) / "qt-pegasis-Fp" / "Sage_Code"
sys.path.insert(0, str(submodule_path))

from qt_pegasis import qtPegasisFp

"""
Computes a hash from the concatenation of a binary vector x
and the j-invariant of an elliptic curve using SHA3-256.
In:
    a binary vector x,
    an elliptic curve E, assumed to be defined over the based field
Out:
    a hexadecimal string representation of the SHA3-256 hash of x||j(E)
"""
def hash_curve(x,E):
    bin_j = bin(E.j_invariant());
    bin_x = bin(int(''.join(str(b) for b in x), 2));
    bytes_input = bytes('0b'+bin_x[2:]+bin_j[2:],"utf-8");
    hash_output = hashlib.sha3_256(bytes_input);
    return hash_output.hexdigest()

"""
Computes the inner product <x,y> of two vectors x,y.
In:
    two binary vectors x,y of same length
Out:
    the inner product <x,y>
"""
def inner_product(x,y):
    assert len(x) == len(y), "The two lists have different lengths";
    return sum([ x[i]*y[i] for i in range(len(x))]);

"""
Computes the fractional O-ideal (as a SageMath object) 
corresponding to a list of generators provided by EGA.sample_ideal()
In:
    a pair of generator L of an O-ideal, provided by EGA.sample_ideal(),
    the corresponding order O
Out:
    the corresponding fractional O-ideal (as a SageMath object) 
"""
def gens_to_ideal_qtPegasis(L,O):
    return O.fractional_ideal([L[0], L[1]]);

"""
Computes the product of fractional O-ideals (k[i]^x[i])_{i < len(x)} 
In:
    an order O,
    a list of fractional O-ideals k,
    a list of binary integers x,
Out: the product of fractional O-ideals (k[i]^x[i])_{i < len(x)}
"""
def vector_product(O,k,x):
    #We reduce the ideal, every m times
    m = 15; #m=15 seems to be a sweet spot in term of efficiency

    assert len(x) == len(k), "The lengths of the inputs do not match";
    
    i = 0;
    I = O.fractional_ideal(1)
    while i < len(x):
        if x[i] == 1:
            I = I*gens_to_ideal_qtPegasis(k[i],O);
        if i%m == 0:
            I = I.reduce_equiv();
        i += 1;
    return I;

"""
Computes a random binary vector of length n
In:
    a positive integer n
Out:
    a random binary vector of length n
"""
def random_z(n):
    return [ randint(0,1) for i in range(n)];

"""
Generates a master secret key for the CPRF using binary vectors of length n
and relying on the qt-Pegasis framework of level lvl
the corresponding EGA is also returned.
In:
    an integer lvl among 500,1000,1500,2000,4000
    a positive integer n,
    a boolean timing,
    a booleean return_timing,
Out:
   an efficient group action EGA of level lvl computed by the PEGASIS algorithm, including the public curve t0,
   a master secret key (t,k) where t is an oriented elliptic curve and k is a list of n fractional ideals,
   when timing = True, the algorithm print the runtime with details on the different costs,
   when return_timing = True, it also returns these timings.
"""
def KeyGen(lvl,n,timing=False,return_timing=False):

    assert lvl in [500,1000,1500,2000,4000], "The provided level is not chosen among the values 500, 1000, 1500, 2000, 4000";
    
    time0 = time.time();
    EGA = qtPegasisFp(lvl);
    
    time1 = time.time();
    k = [];
    for i in range(n):
        k += [EGA.sample_ideal()];
        
    time2 = time.time();
    k0 = EGA.sample_sage_ideal();
    t = EGA.sage_action(k0);
    
    time3 = time.time();
    if timing:
        print("KeyGen:");
        print("EGA computed in ", (time1-time0),"s");
        print("Ideals computed in ", (time2-time1),"s");
        print("Actions computed in ", (time3-time2),"s");
        print("Total computation in ", (time3-time0),"s");
    if return_timing:
        T = (time1-time0,time2-time1,time3-time2,time3-time0);
        return (EGA,(t,k)),T;
    return (EGA,(t,k))

"""
Evaluates the CPRF on an input x given the master secret key msk
of a CPRF relying on an efficient group action EGA
In:
    the efficient group action EGA used to instantiate the CPRF,
    a master secret key msk,
    a binary vector x,
    a boolean timing,
    a boolean return_timing
Out:
    the evaluation of the CPRF on the input x, 
    given as a hexadecimal string representation of a SHA3-256 hash.
    when timing = True, the algorithm print the runtime with details on the different costs,
    when return_timing = True, it also returns these timings.
"""
def Eval(EGA,msk,x,timing=False,return_timing=False): 
    E0 = msk[0];
    
    time0 = time.time();
    I = vector_product(EGA.K.maximal_order(),msk[1],x).reduce_equiv().gens();
    I = (ZZ(I[0]),I[1])
    
    time1 = time.time();
    if I[0]%4 == 2:
        E0 = EGA.two_isogeny(E0,I[1]);
        I = (ZZ(I[0]//2),I[1]);
    E = EllipticCurve([0,EGA.qt_action(I,E0),0,1,0]);
    
    time2 = time.time();
    if timing:
        print("Eval:");
        print("Ideals computed in ", (time1-time0), "s");
        print("Actions computed in ", (time2-time1), "s");
        print("Total computation in ", (time2-time0),"s");
    if return_timing:
        T = (time1-time0,time2-time1,time2-time0);
        return hash_curve(x,E),T;
    return hash_curve(x,E)

"""
Generates the constrained key corresponding to a circuit C 
from a master secret key msk of a CPRF relying on an efficient group action EGA
In:
    an efficient group action EGA
    a master secret key msk
    a circuit C = (S,z) 
    where z is binary vector of length n 
    and S is a subset of [n] 
Out:
    a constrained key ck = (ts,alpha,C)
    where ts is is list of elliptic curves,
    alpha is a list ideals (as returned by EGA.sample_ideal()),
    and C is the input circuit,
    when timing = True, the algorithm print the runtime with details on the different costs,
    when return_timing = True, it also returns these timings.
"""
def Constrain(EGA,msk,C,timing = False,return_timing=False):
    time_begin = time.time();
    S,z = C;
    n = len(z);

    time_ideal = 0;
    time_action = 0;
    
    t = msk[0];
    k = msk[1];
    time0 = time.time();
    r = gens_to_ideal_qtPegasis(EGA.sample_ideal(),EGA.K.maximal_order());
    time1 = time.time();
    time_ideal += time1 - time0;
    
    ts = [];
    alpha = [];
    s_previous = 0;
    ts_temp = t

    for s in S:
        s_temp = s - s_previous;
        time0 = time.time();
        
        r_temp = r^s_temp;
        
        time1 = time.time();
        if s_temp != 0:
            ts_temp = EGA.sage_action(r_temp,ts_temp);
        time2 = time.time();

        time_ideal += time1 - time0;
        time_action += time2 - time1;
        
        ts += [ts_temp];
        s_previous = s;

    time0 = time.time();
    r_inverse = r.inverse();
    for i in range(n):
        if z[i] == 0:
            alpha += [k[i]];
        else:
            alpha += [(r_inverse*k[i]).gens()];
    time1 = time.time();

    time_ideal += time1 - time0;
    time_end = time.time();
    if timing:
        print("Constrain:");
        print("Ideals computed in ", time_ideal, "s");
        print("Actions computed in ", time_action, "s");
        print("Total computation in ", time_end-time_begin,"s");

    ck = (ts,alpha,C);
    if return_timing:
        T = (time_ideal,time_action,time_end-time_begin);
        return ck,T;
    return ck;

"""
Evaluates the CPRF on an input x given the constrained key ck
of a CPRF relying on an efficient group action EGA
In:
    the efficient group action EGA used to instantiate the CPRF,
    a constrained key ck,
    a binary vector x,
    a boolean timing,
    a boolean return_timing
Out:
    the evaluation of the CPRF on the input x, 
    given as a hexadecimal string representation of a SHA3-256 hash.
    when timing = True, the algorithm print the runtime with details on the different costs,
    when return_timing = True, it also returns these timings.
    If x does not verify the inner-product membership property,
    it returns an error.
"""
def CEval(EGA,ck,x,timing=False,return_timing=False):
    # In:
    #
    #
    # Out:
    time0 = time.time();
    ts,alpha,C = ck;
    S,z = C;
    sx = inner_product(x,z);
    assert sx in S;
    E0 = ts[S.index(sx)];
    
    I = vector_product(EGA.K.maximal_order(),alpha,x).reduce_equiv().gens();
    I = (ZZ(I[0]),I[1])

    if I[0]%4 == 2:
        E0 = EGA.two_isogeny(E0,I[1]);
        I = (ZZ(I[0]//2),I[1]);
    
    time1 = time.time();
    E = EllipticCurve([0,EGA.qt_action(I,E0),0,1,0]);
    time2 = time.time();

    if timing:
        print("CEval:");
        print("Ideals computed in ", time1-time0, "s");
        print("Actions computed in ", time2-time1, "s");
        print("Total computation in ", time2-time0,"s");
    if return_timing:
        T = (time1-time0,time2-time1,time2-time0);
        return hash_curve(x,E),T;
    return hash_curve(x,E)

"""
Computes the subset BIPSW(S) of [n]
In:
    a positive integer n
Out:
    the subset BIPSW(S) of [n] 
"""
def BIPSW(n):
    S = [k for k in range(n+1) if k%6 in [0,1,2]];
    return S;

"""
Computes a random binary vector of length n
In:
    a positive integer n
Out:
    a random binary vector of length n
"""
def random_binary_vector(n):
    return [ randint(0,1) for i in range(n)];

"""
Computes a random binary vector x of length n such that <x,z> is in the subset S of [n]
In:
    a positive integer n,
    a binary vector z of length n,
    a subset S of [n],
Out:
     a random binary vector x of length n such that <x,z> is in the subset S of [n]
"""
def random_x_in_S(n,z,S):
    v0 = [0 for i in range(n)];
    x = random_z(n);
    while inner_product(x,z) not in S or x == v0:
        x = random_z(n);
    return x;


"""
Computes the average timings for N KeyGen/Constain evaluations and M Eval/CEval evaluations for each of them,
for the efficient group action of level lvl and for the CPRF using binary vectors of length n.
The constain part is only executed when constrained = True.
We use S = BIPSW(n);
"""
def CPRF_test(N,M,lvl,n,constrained=False):
    S = BIPSW(n);
    
    T_KeyGen = [0,0,0,0];
    T_Constrain = [0,0,0];
    T_Eval = [0,0,0];
    T_CEval = [0,0,0];
    
    for i in range(N):
        (EGA,msk),T = KeyGen(lvl,n,return_timing=True)
        T_KeyGen[0] += T[0];
        T_KeyGen[1] += T[1];
        T_KeyGen[2] += T[2];
        T_KeyGen[3] += T[3];

        
        z = random_z(n);
        C = (S,z)

        if constrained:
            ck,T = Constrain(EGA,msk,C, return_timing=True);
            ts,alpha,C = ck;
            T_Constrain[0] += T[0];
            T_Constrain[1] += T[1];
            T_Constrain[2] += T[2];
        
        for i in range(M):
            x = random_x_in_S(n,z,S);
            eval_x,T = Eval(EGA,msk,x,return_timing=True);
            T_Eval[0] += T[0];
            T_Eval[1] += T[1];
            T_Eval[2] += T[2];

            if constrained:
                ceval_x,T = CEval(EGA,ck,x, return_timing=True);
                T_CEval[0] += T[0];
                T_CEval[1] += T[1];
                T_CEval[2] += T[2];

                assert ceval_x == eval_x;
                
    print("For the parameters lvl =",lvl,"n =",n);
    if constrained:
        print(M," evaluations of Eval and CEval have been runfor ", N, " different keys and constrained keys",'\n');
    else:
        print(M," evaluations of Eval have been run for ", N, " different keys",'\n');
              
    print("For the KeyGen algorithm:")
    print("EGA computed on average in ", float(T_KeyGen[0]/N), "s");
    print("Ideals computed on average in  ", float(T_KeyGen[1]/N), "s");
    print("Actions computed on average in  ", float(T_KeyGen[2]/N), "s");
    print("Total computation on average in  ", float(T_KeyGen[3]/N),"s",'\n');

    print("For the Constrain algorithm:")
    print("Ideals computed on average in  ", float(T_Constrain[0]/N), "s");
    print("Actions computed on average in  ", float(T_Constrain[1]/N), "s");
    print("Total computation on average in  ", float(T_Constrain[2]/N),"s",'\n');

    print("For the Evaluation algorithm:")
    print("Ideals computed on average in  ", float(T_Eval[0]/(M*N)), "s");
    print("Actions computed on average in  ", float(T_Eval[1]/(M*N)), "s");
    print("Total computation on average in  ", float(T_Eval[2]/(M*N)),"s",'\n');

    print("For the CEvaluation algorithm:")
    print("Ideals computed on average in  ", float(T_CEval[0]/(M*N)), "s");
    print("Actions computed on average in  ", float(T_CEval[1]/(M*N)), "s");
    print("Total computation on average in  ", float(T_CEval[2]/(M*N)),"s",'\n');

lvl = 1000;
n = 770;
S = BIPSW(n);

"""
Smaller parameters to run tests:
"""

#lvl = 500;
#n = 3;
#S = BIPSW(n);

"""
Minimal example without constrained key:
"""
#(EGA,msk) = KeyGen(lvl,n,timing=True);
#x = random_binary_vector(n);
#eval_x = Eval(EGA,msk,x,timing=True);
#print("eval_x = ", eval_x);

"""
Minimal example with constrained key:
"""
#(EGA,msk) = KeyGen(lvl,n,timing=True);
#z = random_binary_vector(n);
#C = (S,z);
#ck = Constrain(EGA,msk,C,timing=True);
#x = random_x_in_S(n,z,S);
#eval_x = Eval(EGA,msk,x,timing=True);
#ceval_x = CEval(EGA,ck,x,timing=True);
#print("eval_x == ceval_x:",eval_x == ceval_x);

"""
Running the test function:
"""
#CPRF_test(1,3,500,5,constrained = True)
