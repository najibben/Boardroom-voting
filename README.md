#  PoC Boardroom Voting
A PoC of a secure end-to-end verifiable e-voting system using zero knowledge based blockchain PoC for testing a mixture
of public and private EC e-voting. the user will commit the ballot ( 0 or 1), once is legit he can proceed to vote, transacions
will be recorded in the private blockchain. [2] We can extend the above single-candidate protocol to cater for multiple candidates Obviously, if there are only two candidates, the same protocol can be used – instead of sending ‘yes/no’, one simply sends ‘A/B’. 

We will use this protocol as a cryptographic primitive that allows one to commit to a chosen value (or chosen statement) while keeping it hidden to others in the public bulletin, with the ability to reveal the committed value later, voting on the blockchain will be an encrypted piece of data that is fully open and publicly stored on a distributed blockchain network rather than a single server., [5].To lower the risk of mass interference thite data would be encrypted after biometrics we will use a PIN assigned to the user and ID in the private blockchain


 Katuni [4] demostrated that The Chaum-Pedersen protocol also can be used to prove that an ElGamal ciphertext [5] `(G′,M′) = (Gys,Mgs)` is a reencryption of `(G,M) = (myr,gr)` without revealing the randomization factor s. The proof is, `CP (y,G′/G,g,M′/M)` which implies that there exists a value s such that `logy(G′/G) = logg(M′/M)`. Moreover, the Chaum-Pedersen protocol can be used to prove that an ElGamal ciphertext has been correctly decrypted.



TODO
[5] implementation of Cramer-Damgård-Schoenmakers Protocol
The witness hiding/indistinguishable protocol was introduced by Cramer et al. [22]; therefore, it is also known as the CDS protocol. It can be used to prove that a party knows the solution of k out of n problems without revealing which problems she can solve. This protocol is normally used in verifiable voting schemes to prove that a ciphertext is an encryption of one value within a subset of different values

web: python node.py
register : http://url/form.html

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
Tallying voting protocol for boardroom voting 


## Problems  
[1]
* Eligilibility : only legitimate voters 
* Unreusability : each voter can vote only once
* Privacy : (no one except the voter can obtain information about the voter's choice)
* Fairness : no one can obtain intermediate voting results
* Soundness : Invalidad ballots should be detected and not taken into account during tallying
* Completeness : all valid ballots should be tallied correctly.


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


Private blockchain : Elliptic Curve Cryptography (ECC) with Hazmat EC Key Generation primitives within the crytogrpahy library to verifiy the transactions.the security of remote participation must be viable, and for scalability, transaction speed must be addressed. Due to these concerns, it was determined that the existing frameworks need to be improved to be utilized in voting systems.

Digital Signature Algorithm (DSA and ECDSA) A variant of the ElGamal signature, specified in FIPS PUB 186-4.
It is based on the discrete logarithm problem in a prime finite field (DSA) or in an elliptic curve field (ECDSA).

Public blockchain :  ballots need to be accepted anonymously but only from eligible voters, so a blockchain by itself definitely cannot solve the issue of voter privacy. The voter encrypts their ballot  and casts it, so that the voting officials received the encrypted ballot.
The voting officials post encrypted ballots on a bulletin board

Secure Tallying: Homomorphic Encryption ElGamal accept elliptic curve variants. They rely on hardness of discrete logarithm on elliptic curves, which is distinct from discrete logarithms modulo a big prime. Elliptic curve variants can use smaller fieldsso the performance is better.




## References

[1] https://asecuritysite.com/encryption/hashnew9 RSA has been around for over 40 years, and it is struggling in places. 
In terms of key sizes, we are now at 2,048-bit keys and above. 
For a lightweight device, we will struggle to perform these sizes of operations. 
And so Elliptic Curve Cryptography (ECC) has come to our rescue, and where we use typical key sizes of just 256 bits. 
In fact, Bitcoin and Ethereum, and most blockchain methods use ECC for their keys. 

[2] http://homepages.cs.ncl.ac.uk/feng.hao/files/OpenVote_IET.pdf

[3] https://github.com/jdacode/Blockchain-Electronic-Voting-System

[4] https://github.com/kantuni/ZKP

[5] https://www.sciencedirect.com/topics/computer-science/knowledge-proof

[6] https://www.ncbi.nlm.nih.gov/pmc/articles/PMC8434614/ 



