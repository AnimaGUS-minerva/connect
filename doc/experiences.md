# Timing

There is a delay upon receiving a GRASP message to installing the policy.
Since the GRASP messages may be emitted without any synchronization, the other peer may not have seen this peer's message yet, and may not have installed any policy.

* a blanket policy could be created that was not IPv6-LL specific.

Instead what has been done is to install the policy immediately, but then wait 100ms, plus 3* the lowest octet of the IPv6-LL address of the peer.
This deterministically makes one peer initiate first, eliminating much of the duplicate SA annoyances.  But, 100ms might still not be enough, so in fact what
has to happen is some kind of DPD action that will attempt to bring the SA
up periodically.

# Debugging

Turning on control debugging may cause the system to slow enough enough so that the interface is actually ready when told to --listen.  This is unclear.

