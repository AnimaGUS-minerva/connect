These are some random thoughts about implementation of RFC8994.

Architecture
============
There are some diagrams, container-arrangement.{png,svg,dia} and two-acp.{dia.svg} in this directory.

This design is intended to live in hypervisors (Xen, KVM), in OpenWRT based switch systems, and in small boxes designed to bring RFC8994 functionality to existing systems.  For instance, a three port device could daisy chain to each other, while the third port connects to the management port of an enterprise switch, or IPMI interface.

There are six major components to the target nodes:

1. Hermes Connect
2. Unstrung RPL routing daemon
3. OpenswanEmbedded IPsec daemon
4. BRSKI Join Proxy
5. BRSKI Pledge Client (Trenton)
6. Full GRASP Daemon

There are three network namespaces involved.

A. The host namespace ('0')
B. The DULL namespace
C. The ACP namespace

Note that at present only new network and mount namespaces are created.
The PID, UID, and file system are shared with the host.  This likely will change.
A part of the host file system space will be used for logs, but at present this is not done.

Hermes Connect
--------------

This process performs all the coordination.
It is intended to be as free from configuration options as possible.
It is the newest code, and it is written in Rust.

It is started from the host namespace.
It creates two namespaces: DULL and ACP namespace.

Within the DULL namespace a thread is started that sends GRASP ACP M_FLOOD multicast messages, and it also listens for them.
Another thread listens to the kernel NETLINK socket looking for new interfaces, any that are found are put into the "up" state, and added to the list of possible adjacencies.

The use of Rust async functions are very lightweight, and as they do not require a kernel thread for each use, each interface is tended to by a simple RUST async level thread.

A process is forked within the DULL namespace, and the minimalistic OpenswanEmbedded Pluto (IKEv2 daemon) is started within that namespace.

When GRASP M_FLOOD announcements are received for new nodes, then an IPsec policy is created, and then communicated via CBOR format (WHACK) messages to the pluto daemon.
In addition, a Virtual Tunnel Interface (VTI) is created for each peer that is seen, and a VTI number is allocated to it.  The VTI number becomes part of the IPsec policy, while the interface itself is transfered into the ACP namespace.

The result is that the IKEv2 daemon negotiates an ESP+IPIP policy between the DULL namespace and the peer, but packets that arrive within that tunnel are placed into the ACP namespace.

Additionally, the parent process (in the host(A) namespace) scans the network interfaces in the host namespace, and when new ones are found they are examined.  If they are attached to a bridge, then an ethernet pair is created, one side is attached to the bridge, and the other side is pushed into the DULL namespace.  If they are not attached to a bridge, then a MACVLAN interface is created and pushed into the DULL namespace.

Within the ACP namespace, a thread also listens for new interfaces.
When they are arrive, and have a name like "acp_XXXX", then the IPsec policy for them is disabled, allowing the tunnel to carry any packets.

Within each namespace, the standard out and standard error are redirected to different files,
which are inheirited by the IKEv2 and RPL daemons for logging.


Unstrung RPL routing daemon
---------------------------

The ACP daemon starts an RFC6550 RPL routing daemon, named "unstrung".
This is not as well automated, and each node currently has a shell script that adjusts the arguments to suit.
Most nodes will just be listening, but at least one node has to be marked as the DODAG Root.
This needs to be better automated, with multiple possible DODAG roots possible.

The DODAG root would usually only be enabled in the NOC.
The choice of what prefix to announce is also something that normally would be set only in the NOC.

RPL normally would listen to PIO messages in the DIO, and then would form addresses for each interface using that prefix and the local IID.  In the RFC8994, the full address is found in the certificate (also used by the IKEv2 daemon).  The address found is used to configure a /128 prefix on the loopback interface, and then it is advertised upward by DAO messages.


OpenswanEmbedded IPsec (pluto) IKEv2 daemon
-------------------------------------------

More details [[IPsec-Notes]].

A problem that was observed is that each end of the IPsec tunnel notices the other side pretty quickly.  When both ends are started at a similar time, GRASP M_FLOOD messages come out within 1s of each other, and both ends get their policy very quickly.

The result is that both nodes do their IKEv2 initiation at almost the same time.
There are a number of things that can be done about this.
The problem with simultaneous initiation is that it results in two PARENT SAs and two CHILD SAs.
This is part of the problem of the wildcard on the remote side: we don't know who the other peer until essentially the key agreement is over.  At which point there is a tie breaking mechanism from RFC7296 which then deterministically selects one SA to survive and one SA to be deleted.

In practice, this shouldn't really be an issue as GRASP messages shouldn't get coordinated so well, but in testing it happens repeatedly.

Delaying the initiation at the GRASP DULL level by a number of miliseconds given by the last byte of the peer's link-local address seems like a good way to break the ties.

A mis-feature in Openswan is that when told to do initiate a connection: there needs to be more checking that the connection isn't already up.

A problem with the simultaenous initiation is that if the CHILD SA to be deleted is the second one that was made, then it is a challenge to make sure that the policy from the first connection is restored correctly.  Normally, new SAs replace older ones and there isn't a problem.

BRSKI Join Proxy
----------------

This component is not yet implemented.
It might be a thread within Hermes Connect, but it would be safer if it was another process that had no root permission in any container.

The Join Proxy needs to run within the ACP namespace so that it can open sockets within the routed ACP namespace.

It also needs to listen to GRASP M_FLOOD announcements from the Registrar to learn where the (set) of Registrars are in order to connect to them.  The task of listening to that may be taken on by the GRASP daemon with either some IPC to the Join Proxy, or more likely there will just be a file that is updated when the Registrar address changes.

A challenge for this process is that it must listen to connections from Pledges within the DULL namespace.   This will be done by having the DULL daemon in Connect open one or more sockets within the DULL namespace, and then pass the sockets via Unix Domain socket to the Join Proxy.
It is unclear whether a socket per interface will be necessary in order to properly bind the socket to the IPv6 LL address.

The DULL Connect daemon will be responsible to sending out Pledge M\_FLOOD joins, which will be combined with ACP M\_FLOOD messages.

BRSKI Pledge Client (Trenton)
-----------------------------

A key part of the mechanism is that it auto-enrolls using BRSKI (RFC8995).

This requires presences of an IDevID keypair.

If the host-certificate (LDevID) is missing, then the ACP M\_FLOOD messages are suppressed.
The pledge client runs within the DULL namespace.

Ideally, no private keys would be visible within the DULL namespace, but at present the pledge client and Openswan system need access to them.

This will be replaced with ARM Platform Crypto API access at a later point, when mbedtls is incorporated.


Full GRASP Daemon
-----------------

The full GRASP daemon runs within the ACP namespace.
