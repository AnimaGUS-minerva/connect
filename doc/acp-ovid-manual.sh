#!/bin/sh

# this script sets up two VTI connections in a pair of namespaces.

# namespace 1: DULL
# namespace 2: ACP

# Two pair of ethernet pairs are created, each attached to a different outside bridge.
# The IPsec SAs are created in the DULL namespace.
# The VTI are pushed into the ACP namespace.

# these bridges are assumed to already exist
#bridge1=trusted
bridge1=virbr0
bridge2=ietf

# make the DULL and ACP namespace
# use unshare to make sure that there is a PID, which is needed to make the
# ip link set work right.
acppid=$(unshare -f -n sh -c 'sleep 1d >/dev/null& echo $!')
dullpid=$(unshare -f -n sh -c 'sleep 1d >/dev/null& echo $!')
ip netns attach dull $dullpid
ip netns attach acp  $acppid

echo ACP: $acppid
ps ax | grep $acppid

echo DULL: $dullpid
ps ax | grep $dullpid

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
dull ip addr add fe80::1111/128 dev t1

# setup an IPsec tunnel SA.
ME=0x
OSPI1=0x00300020
ISPI1=0x00200030
OSPI2=0x00300010
ISPI2=0x00100030
MARK1=0x1
MARK2=0x2
ME=fe80::1111
THEM1=fe80::2222
THEM2=fe80::3333

# set up the first SA
cipher1=0xf6ddb555acfd9d77b03ea3843f265325
integ1=0x96358c90783bbfa3d7b196ceabe0536b
algo=aes
dull ip xfrm state add src $ME dst $THEM1 proto esp spi $OSPI1 \
        auth sha1 $integ1 \
        enc $algo $cipher1 \
        mode tunnel \
        mark $MARK1

dull ip xfrm state add src $THEM1 dst $ME proto esp spi $ISPI1 \
        auth sha1 $integ1 \
        enc $algo $cipher1 \
        mode tunnel \
        mark $MARK1

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir out ptype main \
        tmpl src $ME dst $THEM1 \
        proto esp mode tunnel \
        mark $MARK1 mask 0xffffffff

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir in ptype main \
        tmpl src $THEM1 dst $ME \
        proto esp mode tunnel \
        mark $MARK1 mask 0xffffffff

# stuff the ND table
dull ip -6 neigh add $THEM1 lladdr 10:00:00:00:22:22 dev t1

# create a VTI interface in DULL, move it to ACP.
dull ip -6 tunnel add acp_001 mode vti6 local $ME remote $THEM1 key $MARK1
#dull ip link ls

#set -x
#echo MOVING interfaces
#acp ip link ls
dull ip link set acp_001 netns $acppid
echo MOVED interface
acp ip link ls

acp ip link set acp_001 up
acp sysctl -w net.ipv6.conf.acp_001.disable_policy=1


# set up the second SA
cipher2=0xf6ddb555acfd9d77b03ea3843f263255
integ2=0x96358c90783bbfa3d7b196ceabe036b5
algo=aes
dull ip xfrm state add src $ME dst $THEM2 proto esp spi $OSPI2 \
        auth sha1 $integ2 \
        enc $algo $cipher2 \
        mode tunnel \
        mark $MARK2

dull ip xfrm state add src $THEM2 dst $ME proto esp spi $ISPI2 \
        auth sha1 $integ2 \
        enc $algo $cipher2 \
        mode tunnel \
        mark $MARK2

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir out ptype main \
        tmpl src $ME dst $THEM2 \
        proto esp mode tunnel \
        mark $MARK2 mask 0xffffffff

dull ip xfrm policy add src ::/0 dst ::/0 \
        dir in ptype main \
        tmpl src $THEM2 dst $ME \
        proto esp mode tunnel \
        mark $MARK2 mask 0xffffffff

dull ip -6 neigh add $THEM2 lladdr 10:00:00:00:33:33 dev t1

# create a VTI interface in DULL, move it to ACP.
dull ip -6 tunnel add acp_002 mode vti6 local $ME remote $THEM2 key $MARK2
#dull ip link ls

#necho MOVING interfaces
#acp ip link ls
dull ip link set acp_002 netns $acppid
echo MOVED interface

acp ip link set acp_002 up
acp sysctl -w net.ipv6.conf.acp_002.disable_policy=1
acp ip link ls

dull tcpdump -e -i any -n -p esp &
tcpdumppid=$!
acp ping6 -c1 fe80::1:1111%acp_001
acp ping6 -c1 fe80::1:1111%acp_002

sleep 5;
ip netns delete dull
ip netns delete acp
kill $acppid
kill $dullpid
kill $tcpdumppid
