# icmpd

A netfilter extension and an iptables extension to modify source IP statelessly.

Originally used on a router to give a correct router IP to end users. 

## Install

```
cd ko
make install
cd so
make install
```

## Usage

```
iptables -t mangle -A OUTPUT -p icmp -m icmp --icmp-type 11 -j ICMPD --to 10.0.0.1
```

Use 10.0.0.1 as source IP to send all icmp unreachable packets.

```
iptables -t mangle -A OUTPUT -p icmp -m icmp --icmp-type 11 -j ICMPD --ifaddr eth1
```
Use an address on eth1 as source IP to send all icmp unreachable packets.
