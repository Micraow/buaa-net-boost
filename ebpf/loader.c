// SPDX-License-Identifier: GPL-2.0
// 加载 connect_redirect.bpf.o，设置 target/redirect，并挂到指定 cgroup。
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/magic.h>

static volatile int running = 1;

static void on_sig(int sig)
{
    (void)sig;
    running = 0;
}

static void *trace_reader(void *arg)
{
    (void)arg;
    const char *paths[] = {
        "/sys/kernel/tracing/trace_pipe",
        "/sys/kernel/debug/tracing/trace_pipe",
        NULL,
    };
    FILE *f = NULL;
    for (int i = 0; paths[i]; i++) {
        f = fopen(paths[i], "r");
        if (f)
            break;
    }
    if (!f) {
        fprintf(stderr, "trace_pipe not available\n");
        return NULL;
    }
    char buf[512];
    while (running && fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, "race redirect")) {
            fputs(buf, stdout);
            fflush(stdout);
        }
    }
    fclose(f);
    return NULL;
}

static int parse_spec(const char *spec, unsigned long long *out)
{
    char buf[64];
    if (snprintf(buf, sizeof(buf), "%s", spec) >= (int)sizeof(buf))
        return -1;
    char *colon = strrchr(buf, ':');
    if (!colon)
        return -1;
    *colon = '\0';

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1)
        return -1;

    errno = 0;
    char *end = NULL;
    unsigned long port = strtoul(colon + 1, &end, 10);
    if (errno || !end || *end || port < 1 || port > 65535)
        return -1;

    *out = ((unsigned long long)addr.s_addr << 32) | (port & 0xffff);
    return 0;
}

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}

static int set_map(struct bpf_object *obj, const char *name, unsigned long long val)
{
    int fd = bpf_object__find_map_fd_by_name(obj, name);
    if (fd < 0) {
        fprintf(stderr, "map %s not found\n", name);
        return -1;
    }
    unsigned int key = 0;
    if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "map %s update: %s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: %s <bpf.o> <cgroup> <target ip:port> <redirect ip:port> [seconds]\n", argv[0]);
        return 1;
    }

    const char *obj_path = argv[1];
    const char *cgroup = argv[2];
    unsigned long long target, redirect;
    if (parse_spec(argv[3], &target) || parse_spec(argv[4], &redirect)) {
        fprintf(stderr, "bad spec (want ipv4:port): %s / %s\n", argv[3], argv[4]);
        return 1;
    }
    int seconds = argc == 6 ? atoi(argv[5]) : 0;

    struct statfs sfs;
    if (statfs(cgroup, &sfs) != 0) {
        fprintf(stderr, "statfs %s: %s\n", cgroup, strerror(errno));
        return 1;
    }
    if ((unsigned long)sfs.f_type != (unsigned long)CGROUP2_SUPER_MAGIC) {
        fprintf(stderr, "%s 不是 cgroup v2 目录\n", cgroup);
        return 1;
    }

    libbpf_set_print(print_fn);

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    long err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "open %s: %s\n", obj_path, strerror(-err));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    if (set_map(obj, "target", target) || set_map(obj, "redirect", redirect)) {
        bpf_object__close(obj);
        return 1;
    }

    int cg = open(cgroup, O_RDONLY | O_DIRECTORY);
    if (cg < 0) {
        fprintf(stderr, "open cgroup %s: %s\n", cgroup, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *links[8] = {0};
    int nlinks = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (nlinks >= 8) {
            fprintf(stderr, "too many programs\n");
            break;
        }
        struct bpf_link *link = bpf_program__attach_cgroup(prog, cg);
        err = libbpf_get_error(link);
        if (err) {
            fprintf(stderr, "attach %s: %s\n", bpf_program__name(prog), strerror(-err));
            for (int i = 0; i < nlinks; i++)
                bpf_link__destroy(links[i]);
            bpf_object__close(obj);
            return 1;
        }
        links[nlinks++] = link;
        printf("attached %s to %s\n", bpf_program__name(prog), cgroup);
    }

    printf("ready: target=%s redirect=%s\n", argv[3], argv[4]);
    fflush(stdout);

    pthread_t tid;
    if (pthread_create(&tid, NULL, trace_reader, NULL) == 0)
        pthread_detach(tid);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    time_t start = time(NULL);
    while (running && (seconds <= 0 || time(NULL) - start < seconds))
        sleep(1);

    for (int i = 0; i < nlinks; i++)
        bpf_link__destroy(links[i]);
    fflush(stdout);
    _exit(0);
}
