# NAME

xdpcookie -- XDP-based synproxy implementation

# SYNOPSIS

`xdpcookie --attach --iface <iface> --port <port1> [--port <port2> ...]
[--vlan <vlan1> ...] [--mss4 <mss ipv4> --mss6 <mss ipv6> --wscale <wscale> --ttl <ttl>]
[--calcsum] [--checksum] [--checkack]`

`xdpcookie --detach --iface <iface>`

`xdpcookie --iface <iface>`

`xdpcookie --help`

`xdpcookie --version`

# DESCRIPTION

xdpcookie implementation moves initial SYN+ACK conversation into XDP hook of a network interface.

It accelerates the original synproxy implementation in nftables with a custom eBPF program.

# PREREQUISITES

Linux Kernel version:
---------------------

The implementation requires at least Linux Kernel v6.8 or compatible.

It relies on eBPF SYN Cookie helpers, e.g., `bpf_tcp_raw_gen_syncookie_ipv4()`. For details see
https://docs.ebpf.io/linux/helper-function/bpf_tcp_raw_gen_syncookie_ipv4/ to check if it is available.

To support VLAN-tagged traffic and its HW offload, it relies on eBPF XDP metadata kfuncs, e.g.,
`bpf_xdp_metadata_rx_vlan_tag()`. For details see https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_vlan_tag/
to check if it is available on your system and supported by the network card.

Network driver:
---------------

The program is "XDP fragment aware" to support large MTU (maximum transmission unit), i.e., packets
that are larger than a single memory page. However, XDP fragments are not supported by all network
drivers. See https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/#driver-support to check the
driver support table.

VLAN offloading:
----------------

To support VLAN-tagged traffic, the program must be attached to the physical interface of the network
card, not the virtual interfaces on top of it, e.g., vlan, bond, or other master interfaces. When
deploying the program in combination with a bond interface, the program must be attached separately
to all its slave interfaces.

Further, ensure that VLAN offloading is enabled:

```
ethtool --show-offload <iface> | grep vlan-offload
> rx-vlan-offload: on
> tx-vlan-offload: on
```

If necessary, turn on the VLAN offloading:

```
ethtool --offload <iface> rxvlan on txvlan on
```

Checksum offloading:
--------------------

To increase the program performance, ensure the TX checksum offloading is enabled:

```
ethtool --show-priv-flags <iface> | grep tx_xdp_hw_checksum
```

If necessary, turn on the TX checksum offloading:

```
ethtool --set-priv-flags <iface> tx_xdp_hw_checksum on
```

In case your network interface card does not support such an offload, use `--calcsum` option to
enable software-based TX checksum calculation.

Netfilter configuration:
------------------------

The XDP implementation accelerates synproxy implementation in netfilter, thus the synproxy module
must be configured accordingly.

Disable the conntrack loose tracking option:

```
echo 0 >/proc/sys/net/netfilter/nf_conntrack_tcp_loose
```

Ensure syncookies and tcp timestamps are enabled:

```
echo 2 >/proc/sys/net/ipv4/tcp_syncookies
echo 1 >/proc/sys/net/ipv4/tcp_timestamps
```

Configure synproxy module in netfilter using iptables:

```
iptables -t raw -I PREROUTING  -i <iface> -p tcp -m tcp --syn --dport <port> -j CT --notrack
iptables -t filter -A INPUT -i <iface> -p tcp -m tcp --dport <port> -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -t filter -A INPUT -i <iface> -m state --state INVALID -j DROP
```

or using nftables:

```
table inet raw {
	chain prerouting {
		type filter hook prerouting priority raw
		policy accept

		iifname <iface> tcp flags syn / fin,syn,rst,ack tcp dport <port> notrack
	}
}

table inet filter {
	chain input {
		type filter hook input priority filter
		policy accept

		iifname <iface> dport <port> ct state invalid,untracked synproxy sack-perm timestamp wscale 7 mss 1460
		iifname <iface> ct state invalid drop
	}
}
```

For details of synproxy configuration in netfilter see its documentation for nftables: https://wiki.nftables.org/wiki-nftables/index.php/Synproxy.

# EXECUTION

To run the XDP program, attach it to the network interface using the following command:

`xdpcookie --attach --iface <iface> --port <port>`

# OPTIONS

`-a`, `--attach`
: Attach the program to the interface speficified by `--iface` option.

`-d`, `--detach`
: Detach the program from the interface speficified by `--iface` option.

`-i <iface>`, `--iface <iface>`
: In combination with `--attach` or `--detach` it attaches/detaches the program to/from the specified interface `<iface>`.
	Otherwise, it outputs the specified interface `<iface>` program statistics.

`-p <port>`, `--port <port>`
: Specify a TCP port to apply the program to. The option may be specified multiple times.

`-v <vlan>`, `--vlan <vlan>`
: Specify a VLAN tag to apply the program to. The option may be specified multiple times.

`-4 <mss>`, `--mss4 <mss>`
: Set maximum segment size for IPv4 output response. The default value is 1460.

`-6 <mss>`, `--mss6 <mss>`
: Set maximum segment size for IPv6 output response. The default value is 1440.

`-w <wscale>`, `--wscale <wscale>`
: Set TCP window scale for output response. The default value is 7.

`-t <ttl>`, `--ttl <ttl>`
: Set IPv4 time to live or IPv6 hop limit for output response. The default value is 64.

`-c`, `--calcsum`
: Enable software-based TX checksums calculation. By default, TX checksums are not calculated by the program. They are inserted by the network card.

`-C`, `--checksum`
: Enable software-based RX checksums validation. By default, RX checksums are not validated to increace the performance.

`-A`, `--checkack`
: Enable ACK responses validation. By default, ACK responses holding the cookie are not validated by the XDP program. They are passed directly to kernel to be processed.

`-h`, `--help`
: Display usage and exit.

`-V`, `--version`
: Output version and exit.

# EXAMPLES

Attach the program:
-------------------

`xdpcookie --attach --iface ens4f0np0 --port 80 --port 443 --vlan 86 --mss4 1460 --mss6 1440 --wscale 7 --ttl 64 --checksum`

`xdpcookie -a -i ens4f0np0 -p 80 -p 443 -v 86 -4 1460 -6 1440 -w 7 -t 64 -C`

It attaches the program for VLAN tag `86` and TCP ports `80` (HTTP) and `443` (HTTPS) to interface `ens4f0np0`
and overwrites the default TTL, TCP window scale and maximum segment size for IPv4 and IPv6.

Show program statistics:
------------------------

`xdpcookie --iface ens4f0np0`

`xdpcookie -i ens4f0np0`

Detach the program:
-------------------

`xdpcookie --detach --iface ens4f0np0`

`xdpcookie -d -i ens4f0np0`

# TROUBLESHOOTING

bpf_ct_release not found in kernel or module BTFs:
--------------------------------------------------

Conntrack netfilter module not loaded. Load it using the following command:

```
modprobe nf_conntrack
```

xdpcookie_bpf__load() has failed: -7:
-------------------------------------

Network driver cannot allocate enough memory to attach the program. See the output of `dmesg` for details.
Optionally, try to tune some of the network device parameters.

Turn off RX striding if enabled:

```
ethtool --show-priv-flags <iface> | grep striding
> rx_striding_rq : on
```

```
ethtool --set-priv-flags <iface> rx_striding_rq off
```

Decrease the number of RX/TX ring entries alocated:

```
ethtool --show-ring <iface>
> Current hardware settings:
> RX: 8192
> TX: 8192
```

```
ethtool --set-ring <iface> rx 4096 tx 4096
```

# SOURCES

For sources please visit: https://github.com/highpps/xdpcookie.

The implementation is originally based on Linux Kernel BPF selftests (https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf) and BPF examples from XDP project (https://github.com/xdp-project/bpf-examples).

Install dependencies:
---------------------

`apt install make pkg-config gcc clang bpftool libbpf-dev libc6-dev-i386 pandoc`

Build from sources:
-------------------

`./configure; make`

Installation:
-------------

`sudo make install`

# LICENSE

SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
