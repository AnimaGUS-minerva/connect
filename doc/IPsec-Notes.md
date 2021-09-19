The IPsec POLICY
================

The basic policy that is created from the GRASP message is:

    LOCAL                                 REMOTE
    leftid:                               rightid:
     otherName=rfc8994...1234@example       otherName=*
    leftsubnet=::/0                       rightsubnet=::/0
    left=fe80::abcd                       right=fe80::cdef

(Neither my Fountain Registrar nor Openswan have implemented the otherName SAN for nodeName yet.)


In Openswan terminology:
::/0===fe80::d4d4:9aff:fe37:72c0[E=rfc8994+fd739fc23c3440112233445500000300+@acp.example.com]
    ...fe80::e0d0:4eff:fee4:79d6[E=*]===::/0

First note: it is very odd to create a policy that accepts any identity on the right(remote),
while actually locking the right hand side IP address down.
In general, this creates a template policy which is then instantiated as remote peers arrive.
Locking down to a single IP address, because of IPv4 NAPT44 could actually still have multiple peers on the right.

Normally, such a template can not be initiated, but some changes were made to enable this template to initiate if the righthand IP address is present.  Upon reflection, it might be that an override to the policy system to disable that the wildcard creates a template might have been better.
This change is being considered.
The template, plus single instance works, but is kinda a of a mess.

An alternative is that the GRASP announcement could be extended to include the DN of the announcing node.   This could be done by adding a fourth element to the locator that was
the DER encoded DN of the announcing node.
There are privacy implications of this as the DN contains the assigned ULA prefix for the node.

Simultaenous Initiation
-----------------------

RFC7296 section 2.8 deals with rekeying, and 2.8.1 deals with simultaneous CHILD SA rekeying.
A few comments about this:

1) the issue simultaneous keying (not rekeying) is not addressed, but it seems straightforward to follow the same instructions.

2) it says that "four nonces" are to be compared.  Two (Initiator/Responder) from each SA.
It does not say how they are compared.  Each node has a nonce it's end of each SA.
It makes little sense for each end to compare their own nonces. so it must be that
each node should compare the two initiator nonces, and then the two responder nonces.
This ordering is not specified in 2.8.1.

3) it's not entirely clear what consititutes identical PARENT SAs.  At first, it was believed that two states that referred to the same policy would be enough.
But, due to the templates involved this does not work.
What was needed was to compare the two asserted IDi/IDr values.
From an implementation point of view, it  was necessary to make sure that the all the right values wound up in the Parent SA state object. Normally, one doesn't care what ID one has asserted, as it's in the policy.

Testing simultaneous initiation took a bit of ingenuity, but fortunately, Openswan has very good unit tests which do not depend upon time.


