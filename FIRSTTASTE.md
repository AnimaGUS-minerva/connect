Hi, please get:
   https://www.sandelman.ca/tmp/hermes-0.1.tgz

It contains two things:

1) connect. a 50M Rust executable.
   code is at: https://github.com/AnimaGUS-minerva/connect.git
   You can build it with "cargo build" if you care to install rustcc,
   but there are likely some relative paths in the Cargo.toml.
   I'm not sure which ones are required, but I can sort that out if you want.
   I think that the apt-get'able one will suffice.

2) tunnel. please put this in /root/tunnel
   Tunnel is a shell script that is used because the IKEv2 daemon is
   not ready yet.  It's all static keys.

connect expects to find a bridge called "ietf".
It will eventually run on all interfaces, and where it finds a raw interface,
it will create a macvlan, and where it finds a bridge a virtual-ethernet
pair.  You can't macvlan an interface which has been put into a bridge, as
they use the same kernel hooks.  macvlan is basically an invisible bridge.

On an ubuntu/debian machine, you can make the ietfvirtual by putting the
following in your /etc/network/interfaces
(If your system uses netplan, there are also options)

auto ietf
iface ietf inet dhcp
	bridge_ports eth0       # or whatever your system calls it.

This probably requires at least service networking restart, but maybe a reboot.
(It's hard to do this remotely, but it can be done using IPv6-LL IPs. ACP
needed...)

Some caveats: something in the way that "connect" creates network namespaces
upsets the (Ubuntu) systemd-login daemon.  The effect is that after it's run
(perhaps after more than one run after boot), the sshd service hangs.
It doesn't affect non-systemd systems.  This will have to be solved, but for
the moment, I use VMs, and I just reboot the Ubuntu one, and I converted the
other one back to devuan.

connect will create some log files in $CWD:
        acp_stderr.log
        acp_stdout.log
        child_stderr.log
        child_stdout.log

After starting ./connect, in a new window, I suggest:
      "tail --follow=name *.log &"

You'll see:
hermes# ./connect
Hermes Connect 1.0.0
Hermes started new ACP network namespace: 17037
Hermes started new network namespace: 17038
waiting for ACP  startup
waiting for DULL startup
child ready, now starting netlink thread


It has created two network namespaces.
   The GRASP DULL runs in 17038
   The ACP namespace is   17037
here.
I should write those values to a file to make it easier to automate some things.

Do:
        ip link ls

then do:
     nsenter --net --target 17037 ip link ls

and:
     nsenter --net --target 17038 ip link ls

I get:

hermes# nsenter --net --target 17037 ip link ls
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ip6tnl0@NONE: <NOARP> mtu 1452 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/tunnel6 :: brd ::
3: ip6_vti0@NONE: <NOARP> mtu 1332 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/tunnel6 :: brd ::
4: acp_001@if148: <POINTOPOINT,NOARP> mtu 1460 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/tunnel6 fe80::3cc5:10ff:fee3:dbf2 peer fe80::3104:f420:4060:6fa1 link-netnsid 0

hermes# nsenter --net --target 17038 ip link ls
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ip6tnl0@NONE: <NOARP> mtu 1452 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/tunnel6 :: brd ::
3: ip6_vti0@NONE: <NOARP> mtu 1332 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/tunnel6 :: brd ::
148: dull0@if149: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 3e:c5:10:e3:db:f2 brd ff:ff:ff:ff:ff:ff link-netnsid 0


Some notes:
1) iptnl0/ip_vti0 (and lo) are default in every namespace.
2) acp_001 has been created.  You can see this one is not yet up, because I
   didn't start another instance yet.  This would be the interface that goes
   *INTO* the tunnel.  So graspy.py should be run in this namespace and
   allowed to see this interface.

3) dull0 is an ethernet pair.  You'll see on the host, a "pull0", which is
   the other side of the ethernet pair, which is attached to the bridge:

   hermes# brctl show
   bridge name     bridge id               STP enabled     interfaces
   ietf            8000.52540087e4e2       no              eth1
                                                           pull0
   trusted         8000.52540051dafb       no              eth0

   So, dull0 is the second interface onto the "wire", on which the DULL runs.

4) If you omit the command to nsenter, then you'll get a shell within that
   network namespace.  It's just the network namespace, the mounts, pid,
   user, etc. are all the same as the parent, so you have all the same
   permissions, and the same files, but your network is a bit different.
   This can be confusing... use "PS1=acp#" or something to help.

--
]               Never tell me the odds!                 | ipv6 mesh networks [
]   Michael Richardson, Sandelman Software Works        |    IoT architect   [
]     mcr@sandelman.ca  http://www.sandelman.ca/        |   ruby on rails    [

