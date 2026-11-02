// SPDX-License-Identifier: GPL-2.0
// 加载 connect_redirect.bpf.o，设置 target/redirect，并挂到指定 cgroup。
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

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

static unsigned long long pack(const char *spec)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *colon = strrchr(buf, ':');
    if (!colon) {
        fprintf(stderr, "bad spec: %s (want ip:port)\n", spec);
        exit(1);
    }
    *colon = '\0';
    unsigned int ip = inet_addr(buf);
    unsigned int port = (unsigned int)atoi(colon + 1);
    return ((unsigned long long)ip << 32) | port;
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
    unsigned long long target = pack(argv[3]);
    unsigned long long redirect = pack(argv[4]);
    int seconds = argc == 6 ? atoi(argv[5]) : 0;

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    long err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "open %s: %s\n", obj_path, strerror(-err));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed\n");
        return 1;
    }

    if (set_map(obj, "target", target) || set_map(obj, "redirect", redirect))
        return 1;

    int cg = open(cgroup, O_RDONLY | O_DIRECTORY);
    if (cg < 0) {
        fprintf(stderr, "open cgroup %s: %s\n", cgroup, strerror(errno));
        return 1;
    }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach_cgroup(prog, cg);
        err = libbpf_get_error(link);
        if (err) {
            fprintf(stderr, "attach %s: %s\n", bpf_program__name(prog), strerror(-err));
            return 1;
        }
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

    fflush(stdout);
    _exit(0);
}
