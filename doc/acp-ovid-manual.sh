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
ip netns attach dull $dullpid
ip netns attach acp  $acppid
mkdir -p /run/acp
echo $dullpid >/run/acp/dull.pid
echo $acppid  >/run/acp/acp.pid

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

dull ip link set lo up
acp  ip link set lo up

# put interface to first bridge in.
ip link add t0 type veth peer t1
ip link set t0 address 10:00:00:00:33:33
ip link set t1 address 10:00:00:01:33:33
ip link set t0 master $bridge1

# move t1 end into dull
ip link set t1 netns dull
dull ip link set t1 up
# avoid randomized LLv6 addr
dull ip addr add fe80::3333/64 dev t1
ip link set t0 up

echo DULL SETUP
read ans
# stuff the ND table
#dull ping -c1 fe80::2222

# setup an IPsec tunnel SA.
OSPI1=0x00300020
ISPI1=0x00200030
MARK1=0x1
THEM1=fe80::2222

OSPI2=0x00300010
ISPI2=0x00100030
MARK2=0x2
THEM2=fe80::1111

ME=fe80::3333

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

#dull sysctl -w net.ipv6.conf.t1.disable_policy=1

# stuff the ND table
#dull ip -6 neigh add $THEM1 lladdr 10:00:00:01:22:22 dev t1

# create a VTI interface in DULL, connected to $MARK1, move it to ACP.
dull ip link add acp_001 type xfrm if_id $MARK1
dull ip link ls

dull ip link set acp_001 netns $acppid
echo MOVED interface

acp ip link set acp_001 up
acp ip addr add fe80::1:3333/64 dev acp_001
#acp sysctl -w net.ipv6.conf.acp_001.disable_policy=1
#acp sysctl -w net.ipv4.conf.acp_001.disable_policy=1
acp ip link ls

dull ip xfrm state ls

echo HIT ENTER TO PING
read ans

#dull tcpdump -X -e -i any -n -p esp -w espstuff.pcap &
dull tcpdump -e -i any -n -p ip6 and not port 5353 &
tcpdumppid=$!
acp ping6 -c1 fe80::1:2222%acp_001
#acp ping6 -c1 fe80::1:1111%acp_002

sleep 5;

echo HIT ENTER TO END
read ans
killall tcpdump
ip netns delete dull
ip netns delete acp
ip link delete t0
kill $acppid
kill $dullpid
