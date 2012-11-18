# Peer-Assisted Key Derivation Function (PAKDF)

## Abstract

Our protocol combines Chaumian blind signatures and Shamir's Secret Sharing Scheme to create a zero-knowledge, rate limited key derivation function using _k-of-n_ entropy servers. Our scheme is secure against _k-1_ malicious parties and requires _k_ honest parties to succeed.


## Motivation

Alice wishes to generate a cryptographically strong key from a relatively weak password. She wants better security against offline attacks than an algorithmic key derivation function (KDF) can provide and wants to have less reliance on third parties than a single-server-based authentication scheme requires.


## Entropy Generation Phase

Alice would like untrusted servers to provide her with repeatable entropy, but she doesn't want these servers to learn any information about her password. To accomplish this, she can use Chaumian blind signatures. (Chaum, 1983)

First, Alice contacts _n_ entropy servers, sending them each _m' = mr<sup>e</sup>_ where _m_ is her low-entropy secret, _r_ is a random value (different for each server contacted) and _e_ is the server's public exponent.

The entropy servers respond with ![](http://chart.apis.google.com/chart?chf=bg,s,fffff0&cht=tx&chl=s%27%20%3D%20(mr%5Ee%29%5Ed) where _d<sub>i</sub>_ is the server's private value.

Alice then computes each server's share of the entropy pool:

![](http://chart.apis.google.com/chart?chf=bg,s,fffff0&cht=tx&chl=s_i%20%3D%20r%5E%7B-1%7D%20(mr%5Ee%29%5Ed%20%3D%20m%5Ed)

The reason that this is more secure than simply performing local key derivation is because the servers can impose an arbitrary performance restriction on the blind signing rounds. For example a server may restrict the number of verifications to one per second per source IP.

Alice now possesses a set of private random values _s<sub>i</sub>_ that she can reproduce assuming the servers remain online. However, we would like to introduce fault tolerance such that if _s-k_ of the servers are offline or malicious, we can still reconstruct our key.


## Constructing Public Authentication Metadata

We would like to generate a data package that can safely be made public and that allows us to:

a) Remember which servers to query and their order,
a) Determine which servers provided accurate private values and
b) Generate the same secret even if _s-k_ of the servers are no longer available.

For a) we simply create a list of servers by their hostnames/IPs.

To accomplish b) we calculate message digests using a message authentication code. We use HMAC-SHA256 using _s<sub>i</sub> || m_ as the key and `PAKDF_1_0_0_VALID_ENTROPY` as the message. We store these values _HMAC<sub>i</sub>_ for all _s<sub>i</sub> (1 <= i <= n)_.

To provide fault tolerance c) we can use a threshold secret sharing scheme such as Shamir's. (Shamir, 1979) First, we calculate masking values _c<sub>0</sub>_ to _c<sub>k</sub>_. We then calculate points _P<sub>i</sub>(i, s<sub>i</sub> ^ r<sub>i</sub>)_ and with that solve a polynomial _f(x)_ of order _k-1_. We then calculate the remaining points _P<sub>i</sub>(i, f(i))_ and consequently the remaining correction values _c<sub>n-k</sub> ... c<sub>n</sub>_.

  ![c i equals s i xor f of i](http://chart.apis.google.com/chart?chf=bg,s,fffff0&cht=tx&chl=c_i%20%3D%20s_i%20%5Coplus%20f(i%29)

Since values _s<sub>i</sub>_ are private, the correction values _c<sub>i</sub>_ do not contain any information about the polynomial and are therefore safe to publish. A malicious server can only compromise their own share of the entropy.

The final public authentication package looks as follows:

``` protobuf
message AuthData {

  message Server {
    // Server hostname
    required string host = 1;

    // Correction value
    required uint256 correction = 2;

    // Verification digest
    optional uint256 verify = 3;
  }
  
  repeated Server server = 1;
}
```


## Deriving the Secret

To derive the secret at runtime we first retrieve the publically available authentication package. Next, we repeat the entropy generation phase of the protocol. We then verify the returned values using the verification hashes and discard any invalid values. We can then apply the correction values, reconstruct the polynomial using the remaining values (if there are at least k of them) and derive the secret.

Finally, to maintain at least the security of a classic key derivation scheme even if k or more servers are colluding/compromised we can derive a key from our original username and password and XOR it with the secret provided by this scheme. The classic key derivation can be performed while we are waiting for the entropy servers to reply to our requests.


## Brute-force Resistance

We're interested specifically in the security compared to classic password stretching algorithms.

Online key derivation has a number of important advantages when compared to offline key derivation.

* __Rate-limiting independent of local computation resources.__

  With offline key derivation difficulty parameters are limited by the performance a mobile phone or even it's JavaScript engine can provide. At the same attackers have increasingly access to customized hardware and advances in parallel computing techniques.
  
* __Adaptive rate-limiting__

  Online key derivation can provide a further slowdown for attackers by increasing delays when faced with sustained load.
  
* __Visibility of attacks__

  With online attacks, it is usually easy for the hosts of entropy servers to notice that an attack is in progress. This leads to a situation similar to DDoS defense where various techniques may be available to try to stop or at least slow down the attackers.

### Example Calculation:

The largest threat to an online key derivation scheme comes from very large botnets that are able to submit many requests without being affected very much by IP-based rate limits.

The estimates for the largest botnets historically seem to be around the 10-30 million nodes. For our attack scenario we'll assume a botnet controlling 400 million nodes or about 10% of the IPv4 address space.

Assuming adaptive rate limiting to an average of one attempt per 30 minutes per IP, the number of passwords a botnet of that size would theoretically be able to try is 222,222 per second.

At this speed, an eight character password containing mixed-case letters, numbers and common punctuation would take up to 131 years to recover.


## Long-term Security/Reliability

Over longer periods of time, even carefully chosen authentication nodes may go offline or be compromised, so it is wise for us to refresh our authentication package from time to time. To do that, we simply repeat the initialization stage of the protocol with a new server list and new random values and update our authentication package.

Honest authentication nodes may dispose of their private values in regular intervals, for example every five years. The goal is that the long term integrity of the private data is preserved because enough of the keys needed to decrypt it are eventually irretrievably destroyed.

The data may still be compromised once advances in cryptanalysis and information technology make it feasible to brute force the encryption keys or otherwise break the underlying cryptographic primitives. This scheme is therefore only recommended as a password stretching protocol for data that requires high security and usability in the short to medium term, but can be (mostly) invalidated if required. Our motivating example is private keys in a decentralized digital currency scheme.

Another option for ultimate long term security would be the use of storage providers who promise to securely dispose of data on demand or after a certain date. This could be implemented using a threshold based redundant storage scheme.


## Storing the Authentication Package

The authentication package is public and may therefore be stored in one or more databases, indexed by a globally unique key such as a username or email address.

However, to verify the authenticity/legitimacy of the authentication package in a decentralized fashion requires a distributed consensus network. Such a network must provide a hashtable implementation which is able to assign ownership of keys to specific cryptographic identities and which requires signatures for any attempted update of the values related to such keys.


## References

Chaum, David (1983) _Blind signatures for untraceable payments_. Advances in Cryptology Proceedings of Crypto 82 (3): 199-203

Shamir, Adi (1979) _How to share a secret_. Communications of the ACM 22 (11): 612-613