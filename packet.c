/*
 BSD 3-Clause License
 
 Copyright (c) 2025 Silverskin Information Security OY  <contact+github@silverskin.fi> <me@k4m1.net>
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 
 1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.
 
 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
 
 3. Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <errno.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdbool.h>
#include <stdint.h>

#include <unistd.h>

#include "buffer.h"
#include "packet.h"

static inline uint16_t packet_size(packet_options *opts) {
    if (opts->payload) {
        return hdr_size + opts->payload->len;
    }
    return hdr_size;
}

typedef struct {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
} pseudo_packet;

static uint16_t csum(uint16_t *data, uint16_t len) {
    uint64_t sum = 0;
    for ( ; len > 1; len -= 2)
            sum += *data++;
    if (len == 1)
            sum += (data[0] & 0xFF);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void populate_ip(buffer *packet, packet_options *opts) {
    uint16_t len = packet_size(opts);
    struct ip *hdr = (struct ip *)packet->buf;
    hdr->ip_hl = 5;
    hdr->ip_v = 4;
    hdr->ip_tos = 16;
    hdr->ip_len = len;
    hdr->ip_id = htons(opts->ip_id);
    hdr->ip_off = 0;
    hdr->ip_ttl = 64;
    hdr->ip_p = IPPROTO_TCP;
    hdr->ip_src.s_addr = inet_addr(opts->ip_src);
    hdr->ip_dst.s_addr = inet_addr(opts->ip_dst);
    hdr->ip_sum = csum((uint16_t *)hdr, sizeof(struct ip));
}

void populate_tcp(buffer *packet, packet_options *opts) {
    uint16_t len = packet_size(opts);
    struct tcphdr *hdr = (struct tcphdr *)(packet->buf + sizeof(struct ip));
    hdr->th_sport = htons(opts->tcp_src);
    hdr->th_dport = htons(opts->tcp_dst);
    hdr->th_flags = opts->tcp_flags;
    hdr->th_win = htons(opts->tcp_ws);
    hdr->th_urp = 0;
    hdr->th_seq = htonl(1);
    hdr->th_ack = 0;
    hdr->th_off = opts->tcp_off;

    pseudo_packet *psd = calloc(1, sizeof(pseudo_packet));
    if (psd) {
        psd->src = inet_addr(opts->ip_src);
        psd->dst = inet_addr(opts->ip_dst);
        psd->proto = IPPROTO_TCP;
        psd->len = htons(len);
        hdr->th_sum = csum((uint16_t *)psd, sizeof(pseudo_packet));
        free(psd);
    }
}

bool populate_packet(buffer *packet, packet_options *opts) {
    if ((opts->payload->len + hdr_size) > 0xFFFF) {
        errno = EPROTO;
        return false;
    }
    populate_ip(packet, opts);
    populate_tcp(packet, opts);
    return true;
}

bool tx_pkt(buffer *packet, packet_options *opts) {
    for (int i = 0; i < 3; i++) {
        int sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock == -1) {
            return false;
        }
        int one = 1;
        int stat = setsockopt(sock, IPPROTO_IP, 
                        IP_HDRINCL, (char *)&one, sizeof(one));
        if (stat == -1) {
            close(sock);
            return false;
        }
        size_t sent = sendto(sock, packet->buf, packet->len, 0,
                (struct sockaddr *)&opts->saddr, sizeof(opts->saddr));
        close(sock);
        if (sent == packet_size(opts)) {
            return true;
        }
    }
    return false;
}


