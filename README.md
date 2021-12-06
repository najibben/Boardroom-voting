# Blockchain E-Voting System
*`[1][2]`*
<p align="center">
  <img src="/static/github/octocat.png" alt="octocat" width="150" height="150"/>
  <img src="/static/github/python.png" alt="python" width="150" height="150"/>
</p>

<br><br>
## INTRODUCTION
[1]
Electoral integrity is essential for the state voter's trust and liability, from a govermenet perspective
electronic voting can boots voter participation and confidence.
Democracy is a system of voters to elect representatives by voting, the efficacy of such a process is demterminated by
the level of faith that people have in the election process
Blockchain is a shared, immutable ledger that facilitates the process of recording transactions and tracking assets in a business network. 

## Purpose  
<br>
[1]
Public key cryptography in Blockchain is used for all validators that own their key pairs to sign consensus messages and all
the transactions need to be signed to determine the requester. Anonymity in a blockchain context related to the fact anyone that control a wallet just need to generate a random keypair and use this wallet associated to a public key.Due to the Inmutability, Provenance, Decentralization,Anonymity and Transparency, we consider that Blockchain can transform the Electronic Voting System.


## Problems  
[1]
* Eligilibility : only legitimate voters 
* Unreusability : each voter can vote only once
* Privacy : (no one except the voter can obtain information about the voter's choice)
* Fairness : no one can obtain intermediate voting results
* Soundness : Invalidad ballots should be detected and not taken into account during tallying
*Completeness : all valid ballots should be tallied correctly.


<br>

## Solution proposed

Blockchain is not used in nationals elections because transactions speed and privacy concerns.
A dual blockchain public and blockchain private will be used for this.
Proof the correct encryption and decryption of the ballot will be required to validate the results thus reinforcing democracy.

Election administrator updates list	of eligible voters, 
Observer (form.html) can watch the election’s progress consisting of
the election administrator starting and closing each stage and voters registering and casting votes. 
The running tally is not computable.
This encrypted biometric data along with voter identification number are combined in the form (Voter identification number, 
encrypted biometric data, Flag-”Not voted”) and stored in a
private blockchain


## Functionality

Elliptic Curve Cryptography (ECC) with Hazmat EC Key Generation primitives within the crytogrpahy library

Digital Signature Algorithm (DSA and ECDSA) A variant of the ElGamal signature, specified in FIPS PUB 186-4.
It is based on the discrete logarithm problem in a prime finite field (DSA) or in an elliptic curve field (ECDSA).

ZKP proof cryptography is used.


## References

[1] https://asecuritysite.com/encryption/hashnew9 RSA has been around for over 40 years, and it is struggling in places. 
In terms of key sizes, we are now at 2,048-bit keys and above. 
For a lightweight device, we will struggle to perform these sizes of operations. 
And so Elliptic Curve Cryptography (ECC) has come to our rescue, and where we use typical key sizes of just 256 bits. 
In fact, Bitcoin and Ethereum, and most blockchain methods use ECC for their keys. 

[1] https://www.ncbi.nlm.nih.gov/pmc/articles/PMC8434614/

[3] https://github.com/jdacode/Blockchain-Electronic-Voting-System



