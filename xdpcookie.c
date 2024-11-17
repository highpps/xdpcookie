// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause

// Copyright (c) 2024, Jan Kucera <kucera@highpps.net>

// Based on implementation created by Maxim Mikityanskiy <maximmi@nvidia.com>
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

#include <bpf/libbpf.h>

#include "xdpcookie.h"
#include "xdpcookie.bpf.h"

#include <bpf/bpf.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <sys/resource.h>
#include <unistd.h>

// Should be defined in bpf/bpf.h, but it is not
// available in the current linux-libc-dev pkg.
#ifndef BPF_F_XDP_DEV_BOUND_ONLY
#define BPF_F_XDP_DEV_BOUND_ONLY (1U << 6)
#endif

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#ifndef VERSION
#define VERSION unknown version
#endif

static const char *short_options = "VhadcACi:4:6:w:t:p:v:";

static struct option long_options[] = {
    { "version", no_argument, NULL, 'V' },
    { "help", no_argument, NULL, 'h' },
    { "attach", no_argument, NULL, 'a' },
    { "detach", no_argument, NULL, 'd' },
    { "calcsum", no_argument, NULL, 'c' },
    { "checksum", no_argument, NULL, 'C' },
    { "checkack", no_argument, NULL, 'A' },
    { "iface", required_argument, NULL, 'i' },
    { "mss4", required_argument, NULL, '4' },
    { "mss6", required_argument, NULL, '6' },
    { "wscale", required_argument, NULL, 'w' },
    { "ttl", required_argument, NULL, 't' },
    { "port", required_argument, NULL, 'p' },
    { "vlan", required_argument, NULL, 'v' },
    { NULL, 0, NULL, 0 },
};

static noreturn void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s -a -i<iface> -p<port1> [-p<port2> ...] [-v<vlan1> ...] "
        "[-4<mssip4> -6<mssip6> -w<wscale> -t<ttl>] [-cCA]\n", progname);
    fprintf(stderr, "       %s -d -i<iface>\n", progname);
    fprintf(stderr, "       %s -i<iface>\n", progname);
    fprintf(stderr, "       %s -h\n", progname);
    fprintf(stderr, "       %s -V\n", progname);

    exit(EXIT_FAILURE);
}

static noreturn void version(const char *progname)
{
    fprintf(stderr, "%s %s\n", progname, STRINGIFY(VERSION));

    exit(EXIT_SUCCESS);
}

static unsigned int parse_ifname(const char *progname, const char *arg)
{
    unsigned int ret = if_nametoindex(arg);
    if (ret == 0)
        usage(progname);

    return ret;
}

static unsigned long parse_unsigned(const char *progname, const char *arg, unsigned long limit)
{
    unsigned long ret;
    char *endptr = NULL;

    ret = strtoul(arg, &endptr, 10);
    if (*endptr != '\0' || ret > limit)
        usage(progname);

    return ret;
}

static void parse_arguments(
    int argc,
    char *argv[],
    unsigned int *ifindex,
    struct xdpcookie_conf *conf,
    int *attach,
    int *detach,
    int *show)
{
    const char *progname = argv[0];

    unsigned int port_idx = 0;
    unsigned int vlan_idx = 0;

    if (argc < 2)
        usage(progname);

    while (true) {
        int opt = getopt_long(argc, argv, short_options, long_options, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'V':
            version(progname);
            break;
        case 'h':
            usage(progname);
            break;
        case 'i':
            *ifindex = parse_ifname(progname, optarg);
            break;
        case '4':
            conf->opts.mss4 = parse_unsigned(progname, optarg, UINT16_MAX);
            break;
        case '6':
            conf->opts.mss6 = parse_unsigned(progname, optarg, UINT16_MAX);
            break;
        case 'w':
            conf->opts.wscale = parse_unsigned(progname, optarg, 14);
            break;
        case 't':
            conf->opts.ttl = parse_unsigned(progname, optarg, UINT8_MAX);
            break;
        case 'p':
            if (port_idx < MAX_PORTS_ALLOWED) {
                conf->ports[port_idx++] = parse_unsigned(progname, optarg, UINT16_MAX);
                conf->ports[port_idx] = 0;
            }

            break;
        case 'v':
            if (vlan_idx < MAX_VLANS_ALLOWED) {
                conf->vlans[vlan_idx++] = parse_unsigned(progname, optarg, 4095);
                conf->vlans[vlan_idx] = 0;
            }

            break;
        case 'a':
            *attach = true;
            break;
        case 'd':
            *detach = true;
            break;
        case 'c':
            conf->calc_sums = true;
            break;
        case 'C':
            conf->check_sums = true;
            break;
        case 'A':
            conf->check_acks = true;
            break;
        default:
            usage(progname);
        }
    }

    if (optind < argc)
        usage(progname);

    if (*ifindex == 0)
        usage(progname);

    if (*attach && *detach)
        usage(progname);

    if (*attach && conf->ports[0] == 0)
        usage(progname);

    *show = !*attach && !*detach;
}

static int xdpcookie_get_maps(__u32 prog_id, __u32 map_ids[], __u32 *nr_map_ids)
{
    struct bpf_prog_info prog_info = {
        .nr_map_ids = *nr_map_ids,
        .map_ids = (__u64)(unsigned long) map_ids,
    };

    __u32 info_len = sizeof(prog_info);

    int prog_fd;
    int ret;

    prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) {
        fprintf(stderr, "bpf_prog_get_fd_by_id() has failed: %d\n", prog_fd);
        return prog_fd;
    }

    ret = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);

    close(prog_fd);

    if (ret < 0) {
        fprintf(stderr, "bpf_obj_get_info_by_fd() has failed: %d\n", ret);
        return ret;
    }

    *nr_map_ids = prog_info.nr_map_ids;

    return ret;
}

static void xdpcookie_close_maps(int values_fd)
{
    if (values_fd != -1)
        close(values_fd);
}

static int xdpcookie_open_maps(__u32 prog_id, int *values_map_fd)
{
    __u32 map_ids[8];
    __u32 nr_map_ids = 8;

    *values_map_fd = -1;

    int ret = xdpcookie_get_maps(prog_id, map_ids, &nr_map_ids);
    if (ret < 0) {
        fprintf(stderr, "xdpcookie_get_maps() has failed: %d\n", ret);
        return ret;
    }

    if (nr_map_ids < 1) {
        fprintf(stderr, "xdpcookie_get_maps() found %u BPF maps, 1 expected\n", nr_map_ids);
        return -ENOENT;
    }

    for (int i = 0; i < nr_map_ids; i++) {
        struct bpf_map_info map_info = {};
        __u32 info_len = sizeof(map_info);

        int map_fd;

        map_fd = bpf_map_get_fd_by_id(map_ids[i]);
        if (map_fd < 0) {
            fprintf(stderr, "bpf_map_get_fd_by_id() has failed: %d\n", map_fd);
            xdpcookie_close_maps(*values_map_fd);
            return map_fd;
        }

        ret = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len);
        if (ret < 0) {
            fprintf(stderr, "bpf_obj_get_info_by_fd() has failed: %d\n", ret);
            xdpcookie_close_maps(*values_map_fd);
            close(map_fd);
        }

        if (strcmp(map_info.name, "values") == 0) {
            *values_map_fd = map_fd;
            continue;
        }

        close(map_fd);
    }

    if (*values_map_fd != -1)
        return 0;

    xdpcookie_close_maps(*values_map_fd);
    return -ENOENT;
}

static int xdpcookie_detach(unsigned int ifindex, __u32 prog_id)
{
    int flags = 0;
    int ret = bpf_xdp_detach(ifindex, flags, NULL);
    if (ret)
        fprintf(stderr, "bpf_xdp_detach(%d) has failed: %d\n", ifindex, ret);

    return ret;
}

static void xdpcookie_write_vlans(struct xdpcookie_bpf *obj, __u16 vlans[])
{
    for (unsigned i = 0; i < MAX_VLANS_ALLOWED; i++) {
        if (vlans[i] == 0)
            break;

        obj->rodata->conf.vlans[i] = vlans[i];
        fprintf(stderr, "Allowed VLAN %u\n", vlans[i]);
    }
}

static void xdpcookie_write_ports(struct xdpcookie_bpf *obj, __u16 ports[])
{
    for (unsigned i = 0; i < MAX_PORTS_ALLOWED; i++) {
        if (ports[i] == 0)
            break;

        obj->rodata->conf.ports[i] = ports[i];
        fprintf(stderr, "Allowed TCP port %u\n", ports[i]);
    }
}

static void xdpcookie_write_tcpipopts(
    struct xdpcookie_bpf *obj,
    struct xdpcookie_opts *opts)
{
    if (opts->mss4 != 0) {
        obj->rodata->conf.opts.mss4 = opts->mss4;
        fprintf(stderr, "IPv4 MSS %u\n", opts->mss4);
    }

    if (opts->mss6 != 0) {
        obj->rodata->conf.opts.mss6 = opts->mss6;
        fprintf(stderr, "IPv6 MSS %u\n", opts->mss6);
    }

    if (opts->wscale != 0) {
        obj->rodata->conf.opts.wscale = opts->wscale;
        fprintf(stderr, "Window scale %u\n", opts->wscale);
    }

    if (opts->ttl != 0) {
        obj->rodata->conf.opts.ttl = opts->ttl;
        fprintf(stderr, "TTL %u\n", opts->ttl);
    }
}

static void xdpcookie_write_conf(
    struct xdpcookie_bpf *obj,
    struct xdpcookie_conf *conf)
{
    xdpcookie_write_vlans(obj, conf->vlans);
    xdpcookie_write_ports(obj, conf->ports);
    xdpcookie_write_tcpipopts(obj, &conf->opts);

    if (conf->check_sums != 0) {
        obj->rodata->conf.check_sums = conf->check_sums;
        fprintf(stderr, "Check RX checksums\n");
    }

    if (conf->check_acks != 0) {
        obj->rodata->conf.check_acks = conf->check_acks;
        fprintf(stderr, "Check ACK responses\n");
    }

    if (conf->calc_sums != 0) {
        obj->rodata->conf.calc_sums = conf->calc_sums;
        fprintf(stderr, "Calculate TX checksums\n");
    }
}

static int xdpcookie_attach(
    unsigned int ifindex,
    struct xdpcookie_conf *conf,
    __u32 *prog_id)
{
    int flags = XDP_FLAGS_DRV_MODE; // Always attach the program in driver mode
    int prog_flags = BPF_F_XDP_DEV_BOUND_ONLY | BPF_F_XDP_HAS_FRAGS;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    struct xdpcookie_bpf *obj;
    struct bpf_program *prog;
    int prog_fd;
    int ret;

    obj = xdpcookie_bpf__open();
    if (!obj) {
        int _errno = -errno;
        fprintf(stderr, "xdpcookie_bpf__open() has failed: %d\n", _errno);
        return _errno;
    }

    prog = obj->progs.xdpcookie;

    bpf_program__set_ifindex(prog, ifindex);

    ret = bpf_program__set_flags(prog, prog_flags);
    if (ret < 0) {
        fprintf(stderr, "bpf_program__set_flags() has failed: %d\n", ret);
        xdpcookie_bpf__destroy(obj);
        return ret;
    }

    xdpcookie_write_conf(obj, conf);

    ret = xdpcookie_bpf__load(obj);
    if (ret < 0) {
        fprintf(stderr, "xdpcookie_bpf__load() has failed: %d\n", ret);
        xdpcookie_bpf__destroy(obj);
        return ret;
    }

    prog_fd = bpf_program__fd(prog);

    ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
    if (ret < 0) {
        fprintf(stderr, "bpf_xdp_attach(%d) has failed: %d\n", ifindex, ret);
        xdpcookie_bpf__destroy(obj);
        return ret;
    }

    ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (ret < 0) {
        fprintf(stderr, "bpf_obj_get_info_by_fd() has failed: %d\n", ret);
        xdpcookie_bpf__destroy(obj);
        return ret;
    }

    *prog_id = info.id;

    xdpcookie_bpf__destroy(obj);
    return ret;
}

static int xdpcookie_read_counters(int values_fd)
{
    const unsigned int cpus = libbpf_num_possible_cpus();

    __u32 key = 0;
    __u64 sum = 0;
    __u64 values[cpus];

    int ret = bpf_map_lookup_elem(values_fd, &key, values);
    if (ret < 0) {
        fprintf(stderr, "bpf_map_update_elem() has failed: %d\n", ret);
        return ret;
    }

    for (int i = 0; i < cpus; i++)
        sum += values[i];

    fprintf(stdout, "SYN-ACK responses generated: %llu\n", sum);

    for (int i = 0; i < cpus; i++)
        fprintf(stdout, "\tCPU%02d responses: %llu\n", i, values[i]);

    return ret;
}

int main(int argc, char *argv[])
{
    struct xdpcookie_conf conf = {};
    unsigned int ifindex = 0;

    int attach = false;
    int detach = false;
    int show = false;

    __u32 prog_id;
    int ret;

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    parse_arguments(argc, argv, &ifindex, &conf, &attach, &detach, &show);

    ret = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (ret < 0) {
        fprintf(stderr, "setrlimit() has failed: %d\n", ret);
        return EXIT_FAILURE;
    }

    ret = bpf_xdp_query_id(ifindex, 0, &prog_id);
    if (ret < 0) {
        fprintf(stderr, "bpf_xdp_query_id(%d) has failed: %d\n", ifindex, ret);
        return EXIT_FAILURE;
    }

    if (detach) {
        if (prog_id == 0)
            return EXIT_SUCCESS;

        ret = xdpcookie_detach(ifindex, prog_id);
        if (ret < 0) {
            fprintf(stderr, "xdpcookie_detach(%d) has failed: %d\n", ifindex, ret);
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    if (attach) {
        ret = xdpcookie_attach(ifindex, &conf, &prog_id);
        if (ret < 0) {
            fprintf(stderr, "xdpcookie_attach(%d) has failed: %d\n", ifindex, ret);
            return EXIT_FAILURE;
        }
    }

    if (show) {
        int values_fd;

        ret = xdpcookie_open_maps(prog_id, &values_fd);
        if (ret < 0) {
            fprintf(stderr, "xdpcookie_open_maps() has failed: %d\n", ret);
            return ret;
        }

        ret = xdpcookie_read_counters(values_fd);
        if (ret < 0) {
            fprintf(stderr, "xdpcookie_read_conters() has failed: %d\n", ret);
            xdpcookie_close_maps(values_fd);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
