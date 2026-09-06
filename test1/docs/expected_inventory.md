# Expected Inventory / Ground Truth Hints

This file is intentionally descriptive rather than a line-by-line answer key.

High-risk public-key families intentionally represented:
- RSA signing/encryption
- ECDSA
- ECDH
- classical DH
- DSA
- legacy elliptic-curve profiles

Other crypto intentionally represented:
- AES-GCM
- AES-CBC
- ChaCha20-Poly1305
- HMAC
- SHA-1
- SHA-256 / SHA-384
- PBKDF2
- HKDF

Difficulty classes
------------------
A. direct API
B. one wrapper
C. multi-hop wrapper
D. factory/provider indirection
E. constant/alias indirection
F. configuration selection
G. conditional branch
H. dead/unreachable implementation
I. comment-only mention
J. cross-package dependency
K. key/data flow through intermediate objects
L. duplicate implementation with different algorithm
M. legacy compatibility path

A strong CBOM system should NOT:
- count every mention in comments as an implementation
- report every SHA-256 occurrence as a vulnerable public-key primitive
- assume every RSA occurrence is reachable
- collapse AES-GCM and AES-CBC into one equivalent usage
- infer that a quantum-vulnerable algorithm is automatically exploitable in every
  context
- treat an algorithm string in a test fixture as production usage without context

A strong system SHOULD preserve:
- file
- symbol/function/class
- algorithm
- operation/use
- key type where inferable
- reachability confidence
- dependency/call relationship
- application/service boundary
- migration relevance
