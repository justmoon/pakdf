# Peer-Assisted Key Derivation Function (PAKDF)

## Abstract

Our protocol combines Chaumian blind signatures and Shamir's Secret Sharing Scheme to create a zero-knowledge, rate limited key derivation function using _k-of-n_ entropy servers. Our scheme is secure against _k-1_ malicious parties and requires _k_ honest parties to succeed.


## Motivation

Alice wishes to generate a cryptographically strong key from a relatively weak password. She wants better security against offline attacks than an algorithmic key derivation function (KDF) can provide and wants to have less reliance on third parties than a single-server-based authentication scheme requires.


## Entropy Generation Phase

Alice would like untrusted servers to provide her with repeatable entropy, but she doesn't want these servers to learn any information about her password. To accomplish this, she can use Chaumian blind signatures. (Chaum, 1983)

First, Alice contacts _n_ entropy servers, sending them each _m' = mr<sup>e</sup>_ where _m_ is her low-entropy secret, _r_ is a random value (different for each server contacted) and _e_ is the server's public exponent.

The entropy servers respond with ![s dash equals open parenthesis m times r to the e close parenthesis to the d](http://chart.apis.google.com/chart?chf=bg,s,ffffff&cht=tx&chl=s%27%20%3D%20(mr%5Ee%29%5Ed) where _d_ is the server's private value.

Alice then computes each server's share of the entropy pool:

![s equals r to the minus 1 times open parenthesis m times r to the e close parenthesis to the d equals m to the d](http://chart.apis.google.com/chart?chf=bg,s,ffffff&cht=tx&chl=s%20%3D%20r%5E%7B-1%7D%20(mr%5Ee%29%5Ed%20%3D%20m%5Ed)

The reason that this is more secure than simply performing local key derivation is because the servers can impose an arbitrary performance restriction on the blind signing rounds. For example a server may restrict the number of verifications to one per second per source IP.

### Chosen-plaintext attack

A naive implementation of Chaum's protocol is subject to a chosen-plaintext attack. If an attacker can factorize _m_, they need only to run the protocol once per prime factor which is a significant attack for small _m_. To make this infeasible, we recommend adding Michels et al's (1998) padding to _m_:

![m' equals a 1 concatenate dot dot dot concatenate a t](http://chart.apis.google.com/chart?chf=bg,s,fffff0&cht=tx&chl=m%27%20%3D%20a_1%20%7C%7C%20...%20%7C%7C%20a_t)

![a 1 equals m and a i equals hash of a 1 concatenate dot dot dot a i minus 1](http://chart.apis.google.com/chart?chf=bg,s,fffff0&cht=tx&chl=a_1%20%3D%20m%5C%5Ca_i%20%3D%20H(a_1%20%7C%7C%20...%20%7C%7C%20a_%7Bi-1%7D%29)

For _1 < i ≤ t_ and _|m'| = |n|_.

## Constructing Public Authentication Metadata

Alice now possesses a set of private random values _s<sub>i</sub>_ that she can reproduce assuming the servers remain online. However, we would like to introduce fault tolerance such that if _n-k_ of the servers are offline or malicious, she can still reconstruct her key.

We would like to generate a data package that can safely be made public and that allows us to:

&emsp;<b>a)</b>&ensp; Remember which servers to query and their order,

&emsp;<b>b)</b>&ensp; Determine which servers provided accurate private values and

&emsp;<b>c)</b>&ensp; Generate the same secret even if _s-k_ of the servers are no longer available.

For a) we simply create a list of servers by their hostnames/IPs.

To accomplish b) we calculate message digests using a message authentication code. We use HMAC-SHA256 using _s<sub>i</sub> || m_ as the key and `PAKDF_1_0_0_VALID_ENTROPY` as the message. We store these values _HMAC<sub>i</sub>_ for all _s<sub>i</sub> (1 <= i <= n)_.

To provide fault tolerance c) we can use a threshold secret sharing scheme such as Shamir's. (Shamir, 1979) First, we calculate masking values _c<sub>1</sub>_ to _c<sub>k</sub>_. We then calculate points _P<sub>i</sub>(i, s<sub>i</sub> ^ c<sub>i</sub>)_ and with that solve a polynomial _f(x)_ of order _k-1_. We then calculate the remaining points _P<sub>i</sub>(i, f(i))_ and consequently the remaining correction values _c<sub>n-k</sub> ... c<sub>n</sub>_.

  ![c i equals s i xor f of i](http://chart.apis.google.com/chart?chf=bg,s,ffffff&cht=tx&chl=c_i%20%3D%20s_i%20%5Coplus%20f(i%29)

Since values _s<sub>i</sub>_ are private, the correction values _c<sub>i</sub>_ do not contain any information about the polynomial and are therefore safe to publish. A malicious server can still only compromise their own share of the entropy.

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

  With offline key derivation difficulty parameters are limited by the performance a mobile phone or, even worse, its JavaScript engine can provide. At the same time, attackers increasingly have access to customized hardware and advances in parallel computing technology.

* __Adaptive rate-limiting__

  Online key derivation can provide a further slowdown for attackers by increasing delays when faced with sustained load.

* __Visibility of attacks__

  With online attacks, it is usually easy for the hosts of entropy servers to notice that an attack is in progress. This leads to a situation similar to DDoS defense where various techniques may be available to try to stop or at least slow down the attackers.

### Example Calculation:

The largest threat to an online key derivation scheme comes from very large botnets that are able to submit many requests without being affected very much by IP-based rate limits.

The estimates for the largest botnets historically seem to be around the 10-30 million nodes. For our attack scenario we'll assume a botnet controlling 400 million nodes or about 10% of the IPv4 address space.

Assuming adaptive rate limiting to an average of one attempt per 30 minutes per IP, the number of passwords a botnet of that size would theoretically be able to try is 222,222 per second.

At this speed, a six character password containing mixed-case letters, numbers and common punctuation would last at most six days. An eight character password of the same type would take up to 131 years to recover.

In practice it is unlikely that any attacker would be able to sustain the attack for very long. The average duration for DDoS attacks in the second half of 2011 was 9.5 hours, although the longest attack lasted a full 80 days according to a report by Kaspersky. (Garnaeva et al, 2012)

It should also be noted that the extreme request volume stated above is more likely to be a DoS issue then a security issue - the authentication servers would need tremendous capacity to handle such load.

### Comparison with offline KDF

In the scenario above we assume a botnet of 400 million nodes. We'll assume some offline KDF algorithm with parameters set such that users can still login in one second on the minimum supported mobile hardware. Further, we'll assume the average node in the botnet is about five times faster than such a device.

Under these (conservative) assumptions the botnet will be able to try 2 billion passwords per second or about 100x faster than the online attack. The five character password now takes only 8 seconds to break whereas the eight character password takes 83.5 days.

Note that the above scenario does not take into account attackers who have access to large amounts of unique IPs but relatively little computation power. (See section "Proof-of-work challenge")

## Denial of Service

There are two types of denial of service against an entropy server:

1. __Flooding the server with requests.__

   The single exponentiation from a request is fairly expensive, however due to the fairly stringent rate limiting this calculation expense would only affect a very small percentage of requests.

   Furthermore, due to the fault-tolerant nature of the scheme, attackers would have to successfully cause _n-(k+1)_ servers to be unavailable, which may dilute their resources somewhat, especially if different users use different sets of servers.

2. __Intentionally triggering rate limits.__

   As intended, the rate limits are per-IP, so clients can only trigger their own rate limits. However, the implementations must take care to prevent IP spoofing which would allow an attacker to impersonate another client and trigger their rate limit.

### Proof-of-work challenge

In order to reduce the impact of certain DoS-type attacks and to stop attackers with large numbers of IPs, but little computation power the entropy servers could pose clients with a proof-of-work challenge, similar to a protocol proposed by Goyal et al. (Goyal et al, 2005)

Adapted for a distributed set of authentication servers, we propose a slightly different protocol.

Servers publish their official `HostInfo`, which includes a unique identifier based on a hash of their hostname, e.g.

``` protobuf
message HostInfo {
  // Unique host identifier (based on hostname)
  required uint256 hostid = 1;
}
```

The client loads this information once and caches it locally afterwards subject to an expiry date set by the server. Before starting a request to a group of entropy servers, the client generates a challenge as follows:

``` protobuf
message Challenge {
  // Current time
  required uint32 timestamp = 1;

  // Unique ID
  required uint256 unique = 2;

  // Nonce
  required uint32 nonce = 3;

  message Server {
    // Hash of the server hostname
    required uint256 hostid = 1;
  }

  // List of servers to prove work to
  repeated Server server = 4;
}
```

Next, the client starts incrementing the nonce and hashing the package using a hashing function defined by the protocol, such as scrypt. When all possible nonces have been tried, a new random unique ID is generated and/or the timestamp updated and the process is restarted.

The client includes the proof-of-work challenge when making a request to any of the authentication server.

A server verifies the package by confirming:

* The package contains its official unique `hostid` as one of the hostids listed.
* The package does not contain any duplicate hostids.
* The `timestamp` is in the past.
* The `timestamp` is at most an hour in the past.
* The `unique` ID has not been used in the last hour.
* The hash of the package meets the difficulty requirement.

If the proof-of-work does not meet the current difficulty target required for a given request, the server will respond with the correct difficulty target and the client will retry as soon as it has a challenge message that meets it. As soon as enough servers have been successfully contacted to complete the key derivation protocol, the client stops hashing.


## Long-term Security/Reliability

Over longer periods of time, even carefully chosen authentication nodes may go offline or be compromised, so it is wise for us to refresh our authentication package from time to time. To do that, we simply repeat the initialization stage of the protocol with a new server list and new random values and update our authentication package.

Honest authentication nodes may dispose of their private values in regular intervals, for example every five years. The goal is that the long term integrity of the private data is preserved because enough of the keys needed to decrypt it are eventually irretrievably destroyed.

The data may still be compromised once advances in cryptanalysis and information technology make it feasible to brute force the encryption keys or otherwise break the underlying cryptographic primitives. This scheme is therefore only recommended as a password stretching protocol for data that requires high security and usability in the short to medium term, but can be (mostly) invalidated if required. Our motivating example is private keys in a decentralized digital currency scheme that allows users to invalidate old keys.

Another option for ultimate long term security would be the use of storage providers who promise to securely dispose of data on demand or after a certain date. This could be implemented using a threshold based redundant storage scheme.


## Storing the Authentication Package

The authentication package is public and may therefore be stored in one or more databases, indexed by a globally unique key such as a username or email address.

Updating the authentication package would require a signature from the very user who is using that package to authenticate.


## Advanced Security

Modern login systems often employ more advanced rules to protect user accounts. For example, login attempts from an unexpected geolocation may trigger additional security checks.

In principle we can implement such measures in a PAKDF scheme, with the caveat that we have to meet two extra challenges:

* The entropy servers would need to collect extra information, most notably a value to distinguish users, such as a username. We do not believe this makes a big difference since for security purposes we should assume usernames to be publicly known anyway.

  Other values may be more sensitive, such as the user's email address and cell phone number and users may not wish to share them with a set of authentication servers.

* Since we are dealing with multiple servers instead of one, it may seem cumbersome to pass extra verification with each of them. However, if these steps are standardized, the client could hide much of this complexity.

### Unique usernames

It is a desirable property of the system that usernames are globally unique. This is non-trivial to enforce if the set of authentication servers varies from user to user. In our motivating example, a distributed consensus network can take on the role of assigning and managing ownership of unique usernames.

Alternatively, each server can enforce locally unique usernames and clients will choose a username during the initialization phase which is available on all of them.

### Account-specific rate-limiting

In order to protect against attacks targeting specific accounts, an authentication server might add account-specific rate limiting. The rate limits for individual accounts can be very tight and can be enforced in addition to per-IP limits. Recall that all rate-limiting would be done via proof-of-work, i.e. the server would make each successive attempt more expensive until the rate of attempts is equal to or less than the desired limit.

If we wish to rate-limit on a per-user basis, the server needs to have a way to prove on each request which user it is signing for. The way to accomplish this is via a partial blind signature. We employ the protocol described by Cao et al. (2005)

The public component `info` of the message to be signed is:

> _info = length of username || username_

The blinded component `m` of the message to be signed is:

> _m = H(length of username || username || password)_

`// XXX Describe protocol`

### Prior successful login token

In the case of a DoS attack against a specific user, we want that user to be affected as little as possible. In order to do this, we award users a special token they can use to bypass any proof-of-work requirements.

After a user has logged in successfully, they will sign a message using their private key and send it to the authentication server in order to prove that they have successfully decrypted their blob. As part of its response, the server can then issue a n-time-use token, e.g. a ten-time-use token which the client can store persistently and which allows it to log in, even if there is currently a DoS attacks in progress against this account which causes the proof-of-work for logging in to this specific account to be very high.

In addition, we propose that when initializing a new device, clients implement a pairing protocol that allows the existing client and the new client to exchange some data, including this login token. That means that an honest user will never be affected by a DoS attack unless she logs in from a new machine without employing a pairing protocol or exhausts her n-time-use token.


## References

Cao, Z., Zhu H., Lu R. (2005) _Provably secure robust threshold partial blind signature_. Science in China Series F: Information Sciences 49 (5): 604-615

Chaum, D. (1983) _Blind signatures for untraceable payments_. Advances in Cryptology Proceedings of Crypto 82 (3): 199-203

Garnaeva, M., Namestnikov, Y. (2012) _DDoS attacks in H2 2011_. [[link]](http://www.securelist.com/en/analysis/204792221/DDoS_attacks_in_H2_2011#p1)

Goyal, V., Kumar, V., Singh, M., Abraham, A., Sanyai, S. (2005) _A new protocol to counter online dictionary attacks_. Computers & Security 25 (2): 114-120

Michels, M., Stadler, M., Sun H-M. (1998) _On the security of some variants of the RSA signature scheme_. European Symposium on Research in Computer Security – ES-ORICS’98: 85–96

Shamir, A. (1979) _How to share a secret_. Communications of the ACM 22 (11): 612-613
