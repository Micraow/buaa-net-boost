// synspray: 在同一个 5 元组上，把内核发出的 SYN 原样复读多次。
// 需要 root（AF_PACKET 抓包 + raw IPv6 发送）。
//
// 用法:
//   sudo ./synspray <target-v6> <port> <local-port> <copies> <interval-ms> <timeout-ms> [iface]
// 例:
//   sudo ./synspray 2402:f000:1:400::2 443 40000 4 20 3000 wlan0
//
// 原理: 先让内核 socket 正常 connect（内核发第一个 SYN），抓下这个 SYN，
// 然后在同一 5 元组上按间隔复读同一份字节（含相同 ISN/TCP 时间戳）。
// 如果设备只丢“新流首包”，复读包会被当作后续包放行，连接在几十毫秒内完成；
// 如果设备按会话丢弃/限速，复读也不会更快。

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static uint32_t sum16(const void *data, size_t len, uint32_t sum)
{
    const uint8_t *p = data;
    while (len > 1) {
        sum += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

// 重算复读包的 TCP 校验和（抓包时可能是 checksum offload 的半成品）
static void fix_tcp_csum(uint8_t *pkt, size_t iplen)
{
    if (iplen < 40 + 20)
        return;
    uint8_t *tcp = pkt + 40;
    size_t tcp_len = iplen - 40;
    tcp[16] = 0;
    tcp[17] = 0;

    uint32_t sum = 0;
    sum = sum16(pkt + 8, 32, sum);              // src + dst
    sum += (uint32_t)((tcp_len >> 16) & 0xffff);
    sum += (uint32_t)(tcp_len & 0xffff);
    sum += 6;                                    // next header TCP
    sum = sum16(tcp, tcp_len, sum);
    uint16_t c = csum_fold(sum);
    tcp[16] = (uint8_t)(c >> 8);
    tcp[17] = (uint8_t)(c & 0xff);
}

int main(int argc, char **argv)
{
    if (argc < 7 || argc > 8) {
        fprintf(stderr, "usage: %s <target-v6> <port> <local-port> "
                        "<copies> <interval-ms> <timeout-ms> [iface]\n", argv[0]);
        return 2;
    }
    const char *target = argv[1];
    int port = atoi(argv[2]);
    int lport = atoi(argv[3]);
    int copies = atoi(argv[4]);
    int interval = atoi(argv[5]);
    int timeout = atoi(argv[6]);
    const char *iface = argc == 8 ? argv[7] : "wlan0";

    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons((uint16_t)port);
    if (inet_pton(AF_INET6, target, &dst.sin6_addr) != 1) {
        fprintf(stderr, "bad target: %s\n", target);
        return 2;
    }

    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket tcp"); return 1; }
    struct sockaddr_in6 local;
    memset(&local, 0, sizeof(local));
    local.sin6_family = AF_INET6;
    local.sin6_port = htons((uint16_t)lport);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind local port"); return 1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    int pf = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (pf < 0) { perror("AF_PACKET (需要 root)"); return 1; }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex(iface);
    if (sll.sll_ifindex == 0) { perror("if_nametoindex"); return 1; }
    if (bind(pf, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        perror("bind AF_PACKET"); return 1;
    }

    double t0 = now_ms();
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0 && errno != EINPROGRESS) {
        perror("connect"); return 1;
    }

    uint8_t cap[4096], syn[4096];
    size_t synlen = 0;
    while (now_ms() - t0 < 500 && synlen == 0) {
        struct pollfd p = { .fd = pf, .events = POLLIN };
        if (poll(&p, 1, 10) <= 0)
            continue;
        ssize_t n = recv(pf, cap, sizeof(cap), 0);
        if (n < 54)
            continue;
        if (cap[12] != 0x86 || cap[13] != 0xdd)
            continue;
        uint8_t *ip6 = cap + 14;
        size_t avail = (size_t)n - 14;
        if (avail < 40 || ip6[6] != 6)
            continue;
        size_t iplen = 40 + (((size_t)ip6[4] << 8) | ip6[5]);
        if (iplen > avail)
            iplen = avail;
        uint8_t *tcp = ip6 + 40;
        uint16_t sp = ((uint16_t)tcp[0] << 8) | tcp[1];
        uint16_t dp = ((uint16_t)tcp[2] << 8) | tcp[3];
        if (sp != (uint16_t)lport || dp != (uint16_t)port)
            continue;
        if (!(tcp[13] & 0x02))
            continue;
        if (memcmp(ip6 + 24, &dst.sin6_addr, 16) != 0)
            continue;
        memcpy(syn, ip6, iplen);
        synlen = iplen;
        fix_tcp_csum(syn, synlen);
    }
    if (synlen == 0) {
        fprintf(stderr, "没有抓到自己发出的 SYN（检查 iface/端口）\n");
        close(fd); close(pf);
        return 1;
    }

    int raw = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (raw < 0) { perror("raw socket (需要 root)"); return 1; }

    for (int i = 0; i < copies; i++) {
        if (sendto(raw, syn, synlen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
            perror("sendto raw");
        if (i + 1 < copies)
            usleep((useconds_t)interval * 1000);
    }

    int ok = 0;
    double dt = 0;
    while (now_ms() - t0 < timeout) {
        struct pollfd p = { .fd = fd, .events = POLLOUT };
        if (poll(&p, 1, 20) > 0) {
            int err = 0;
            socklen_t el = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
            dt = now_ms() - t0;
            if (err == 0) { ok = 1; break; }
            break;
        }
    }
    printf("ok=%d time=%.1fms copies=%d synlen=%zu\n", ok, dt, copies, synlen);
    close(fd); close(pf); close(raw);
    return ok ? 0 : 1;
}
