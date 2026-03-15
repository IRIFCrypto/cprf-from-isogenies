# CPRF for inner-product membership predicates from isogenies

This code provides an implementation in SageMath/Python of a constrained pseudorandom function (CPRF) for inner-product membership predicates based on isogeny-based cryptography.
It accompanies the paper "Compressed Post-Quantum Silent OT from Isogenies" by Pouria Fallahpour, Arthur Herlédan Le Merdy, and Mahshid Riahinia, where the CPRF is described and proved.
The implementation of the qt\-Pegasis framework by Pierrick Dartois and Max Duparc is used as a central subprocedure in this work.

## Repository structure

- 'qt\-pegasis\-Fp': the qt-Pegasis implementation, as a git submodule, accompanying the paper [Chasing Rabbits Through Hypercubes: Better algorithms for higher dimensional 2-isogeny computations](https://eprint.iacr.org/2026/114.pdf) by Pierrick Dartois and Max Duparc. 
- 'CPRF.sage': the proof of concept implementation of the isogeny-based CPRF

## How to run

From the directory containing CPRF.sage run, in a Sage terminal, the command
```
load("CPRF.sage")
```

to load all the necessary packages and set the parameters of the CPRF at security level 128, i.e. n=770, lvl=1000, S = BIPSW(n).

One can then run a minimal example without constrained key, such as
```
(EGA,msk) = KeyGen(lvl,n,timing=True);
x = random_binary_vector(n);
eval_x = Eval(EGA,msk,x,timing=True);
print("eval_x = ", eval_x);
```
in approximately 15s.

A minimal example with constrained key, such as
```
(EGA,msk) = KeyGen(lvl,n,timing=True);
z = random_binary_vector(n);
C = (S,z);
ck = Constrain(EGA,msk,C,timing=True);
x = random_x_in_S(n,z,S);
eval_x = Eval(EGA,msk,x,timing=True);
ceval_x = CEval(EGA,ck,x,timing=True);
print("eval_x == ceval_x:",eval_x == ceval_x);
```
might take more than 30 minutes to terminate.

To test the code more rapidly, one can change the parameters to a lower level lvl and vectors of shorter length n, by running for instance
```
lvl = 500;
n = 10;
S = BIPSW(n);
```

There is a test function
```
CPRF_test(N,M,lvl,n,constrained=True);
```
to directly run M evaluations of Eval (and CEval when constrained is True) for N different keys (and constrained keys when constrained is True).
It will print the average runtime for each algorithm and check their correctness.

## SageMath/Python Version

The code has been developed using SageMath version 10.5 and Python 3.12.3. 

## License

This work is under an MIT license.
It relies on code which is itself under an MIT license.
Please refer to the LICENSE file for more information.

## Disclaimer

This implementation is only a proof of concept, it is neither optimized nor secured. 
Hence, it should not be used for any real cryptographic purposes.
