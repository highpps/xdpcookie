# NAME

xdpcookie -- XDP-based synproxy implementation

# DESCRIPTION

xdpcookie implementation moves initial SYN+ACK conversation into XDP hook of a network interface.

It accelerates the original synproxy implementation in nftables with a custom eBPF program.

# LICENSE

SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
