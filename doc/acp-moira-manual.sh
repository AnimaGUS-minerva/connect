#!/bin/sh

# this script sets up two VTI connections in a pair of namespaces.

# namespace 1: DULL
# namespace 2: ACP

# Two pair of ethernet pairs are created, each attached to a different outside bridge.
# The IPsec SAs are created in the DULL namespace.
# The VTI are pushed into the ACP namespace.

# these bridges are assumed to already exist
bridge1=trusted
#bridge1=virbr0
bridge2=ietf

mkdir -p /run/acp

ip netns delete dull
ip netns delete acp
ip link delete t0
sleep 5

# make the DULL and ACP namespace
# use unshare to make sure that there is a PID, which is needed to make the
# ip link set work right.
acppid=$(unshare -f -n sh -c 'sleep 1h >/dev/null& echo $!')
dullpid=$(unshare -f -n sh -c 'sleep 1h >/dev/null& echo $!')
echo $dullpid >/run/acp/dull.pid
echo $acppid  >/run/acp/acp.pid
ip netns attach dull $dullpid
ip netns attach acp  $acppid

echo ACP: $acppid
ps ax | grep $acppid

echo DULL: $dullpid
ps ax | grep $dullpid

# using nsenter rather than "ip netns exec" removes buffering from
# output of commands: some pty gets interspersed.
dull() {
    nsenter -t $dullpid -n $*
}
acp() {
    nsenter -t $acppid -n $*
}

# put interface to first bridge in.
ip link add t0 type veth peer t1
ip link set t0 master $bridge1

# move t1 end into dull
ip link set t1 netns dull
dull ip link set t1 up
ip link set t0 up

# avoid randomized LLv6 addr
dull ip addr add fe80::2222/64 dev t1

echo DULL SETUP
read ans
#dull ping -c1 fe80::3333

#dull bash

# PEER 1 - hermes
# PEER 2 - moira
# PEER 3 - ovid

# setup an IPsec tunnel SA 1: moira<->ovid
OSPI1=0x00200030
ISPI1=0x00300020
MARK1=0x1

# moira makes a second SA 2: moira<->hermes
OSPI2=0x00300010
ISPI2=0x00100030
MARK2=0x2

ME=fe80::2222
THEM1=fe80::3333
THEM2=fe80::4444

# set up the first SA
cipher1=0xf6ddb555acfd9d77b03ea3843f265325
integ1=0x96358c90783bbfa3d7b196ceabe0536b
algo=aes
dull ip xfrm state add src $ME dst $THEM1 proto esp spi $OSPI1 \
        auth sha1 $integ1 \
        enc $algo $cipher1 \
        mode tunnel \
        if_id $MARK1

dull ip xfrm state add src $THEM1 dst $ME proto esp spi $ISPI1 \
        auth sha1 $integ1 \
        enc $algo $cipher1 \
        mode tunnel \
        if_id $MARK1

if true; then
dull ip xfrm policy add src fe80::/64 dst fe80::/64 proto ipv6-icmp \
     dir out ptype main \
     action allow \
     priority 100 \
     if_id $MARK1
fi

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir out ptype main \
        tmpl src $ME dst $THEM1 \
        proto esp mode tunnel \
        if_id $MARK1

if true; then
dull ip xfrm policy add src fe80::/64 dst fe80::/64 proto ipv6-icmp \
        dir in ptype main \
        action allow \
        priority 100 \
        if_id $MARK1

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir in ptype main \
        tmpl src $THEM1 dst $ME \
        proto esp mode tunnel \
        if_id $MARK1
fi

# turn off policy for the interface on which ESP occurs
#dull sysctl -w net.ipv6.conf.t1.disable_policy=1

# stuff the ND table
#dull ip -6 neigh add $THEM1 lladdr 10:00:00:00:22:22 dev t1

# create an xfrm-interface in DULL, move it to ACP.
dull ip link add acp_001 type xfrm if_id $MARK1
#dull bash
#dull ip link ls

#set -x
#echo MOVING interfaces
#acp ip link ls
dull ip link set acp_001 netns $acppid

echo MOVED interface

acp ip link set acp_001 up
acp ip addr add fe80::1:2222/64 dev acp_001
#acp sysctl -w net.ipv6.conf.acp_001.disable_policy=1
#acp ip link ls

if true
then
# set up the second SA
cipher2=0xf6ddb555acfd9d77b03ea3843f263255
integ2=0x96358c90783bbfa3d7b196ceabe036b5
algo=aes
#algo=null
#mode=transport
mode=tunnel
dull ip xfrm state add src $ME dst $THEM2 proto esp spi $OSPI2 \
        auth sha1 $integ2 \
        enc $algo $cipher2 \
        mode $mode \
        if_id $MARK2

dull ip xfrm state add src $THEM2 dst $ME proto esp spi $ISPI2 \
        auth sha1 $integ2 \
        enc $algo $cipher2 \
        mode $mode \
        if_id $MARK2

dull ip xfrm policy add src $ME/128 dst $THEM2/128 \
     dir out ptype main \
     action allow \
     if_id $MARK2

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir out ptype main \
        tmpl src $ME dst $THEM2 \
        proto esp mode $mode \
        if_id $MARK2

dull ip xfrm policy add src $THEM2/128 dst $ME/128 \
        dir in ptype main \
        action allow \
        if_id $MARK2

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir in ptype main \
        tmpl src $THEM2 dst $ME \
        proto esp mode $mode \
        if_id $MARK2

# create a VTI interface in DULL, move it to ACP.
dull ip link add acp_002 type xfrm if_id $MARK2
#dull ip link ls

#necho MOVING interfaces
#acp ip link ls
dull ip link set acp_002 netns $acppid
echo MOVED interface

acp ip link set acp_002 up
acp ip addr add fe80::2:2222/64 dev acp_002
#acp sysctl -w net.ipv6.conf.acp_002.disable_policy=1
acp ip link ls
fi

#dull tcpdump -X -e -i any -n -p esp -w espstuff.pcap &
#dull tcpdump -e -i any -n -p ip6 and not port 5353 &
#dull tcpdump -e -i any -n -p esp &
#tcpdumppid=$!

echo HIT ENTER TO PING
read ans

acp ping6 -c1 fe80::1:3333%acp_001
#acp ping6 -c1 fe80::1:4444%acp_002

echo HIT ENTER TO END
read ans

#kill $tcpdumpid
ip netns delete dull
ip netns delete acp
kill $acppid
kill $dullpid
