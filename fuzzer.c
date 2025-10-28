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

#include "buffer.h"
#include "packet.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef struct {
    packet_options *p_opts;
    bool fuzz_off;
    bool fuzz_ws;
} fuzz_options;

void fuzz_flags(buffer *pkt, packet_options *opts, uint32_t max_iterations) {
    printf("Fuzzing TCP flags, this'll take a while...\n");
    for (uint8_t flags = 0; flags < 0xFF; flags++) {
        for (uint32_t i = 0; i < max_iterations; i++) {
            if ((i % 100) == 0) {
                printf("\rFLAGS: %x: %d / %d sent", flags, i, max_iterations);
            }
            opts->tcp_flags = flags;
            populate_packet(pkt, opts);
            bool stat = tx_pkt(pkt, opts);
            if (stat == false) {
                fprintf(stderr, "\nUnable to communicate with %s:%d: %s/%d\n",
                        opts->ip_dst, opts->tcp_dst, strerror(errno), errno);
                fprintf(stderr, "\nBailing out\n");
                return;
            }
        }
    }
    printf("\nDone\n");
}

void fuzz_hdr_off(buffer *pkt, packet_options *opts, uint32_t max_iterations) {
    printf("TCP Offset 0 -> 15\n");
    for (opts->tcp_off = 0; opts->tcp_off < 0xf; opts->tcp_off++) {
        fuzz_flags(pkt, opts, max_iterations);
    }
    opts->tcp_off = 5;
}

void fuzz_ws(buffer *pkt, packet_options *opts, uint32_t max_iterations) {
    printf("TCP WS 0 -> 65535\n");
    for (opts->tcp_ws = 0; opts->tcp_ws < 0xFFFF; opts->tcp_ws += 1024) {
        fuzz_flags(pkt, opts, max_iterations);
    }
    opts->tcp_ws = 0;
}

void usage(const char *name) {
    printf("Usage: %s <target IP> <target tcp port> [options]\n", name);
    printf("Options:\n");
    printf("-h:                    show this help window\n");
    printf("-sa <source-address>:  source IPv4 address to use (default: 192.168.20.20)\n");
    printf("-sp <source port>:     source TCP port to use (default: 1234)\n");
    printf("-fo:                   fuzz with incremental header offset\n");
    printf("-fw:                   fuzz with incremental window size\n");
}

const char *get_opt(int i, int argc, char *argv[]) {
    if ((i + 1) > argc) {
        return NULL;
    }
    return argv[i + 1];
}

int opt_is_set(const char *name, int argc, char *argv[]) {
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], name)) {
            return i;
        }
    }
    return 0;
}

fuzz_options *parse_args(int argc, char *argv[]) {
    if (argc < 2 || opt_is_set("-h", argc, argv)) {
        usage(argv[0]);
        return NULL;
    }
    fuzz_options *opts = calloc(1, sizeof(fuzz_options));
    if (!opts) {
        // ?!?
        return NULL;
    }
    opts->p_opts = calloc(1, sizeof(packet_options));
    if (!opts->p_opts) {
        free(opts);
        return NULL;
    }

    opts->p_opts->ip_dst = argv[1];
    opts->p_opts->tcp_dst = atoi(argv[2]);

    if (opt_is_set("-fo", argc, argv)) {
        opts->fuzz_off = true;
    }
    if (opt_is_set("-fw", argc, argv)) {
        opts->fuzz_ws = true;
    }

    int off = opt_is_set("-sa", argc, argv);
    if (off) {
        opts->p_opts->ip_src = get_opt(off, argc, argv);
    } else {
        opts->p_opts->ip_src = "192.168.20.20";
    }
    off = opt_is_set("-sp", argc, argv);
    if (off) {
        opts->p_opts->tcp_src = atoi(get_opt(off, argc, argv));
    } else {
        opts->p_opts->tcp_src = 1234;
    }

    return opts;
}

int main(int argc, char *argv[]) {
    buffer *pkt = new_buffer(hdr_size);
    fuzz_options *fops = parse_args(argc, argv);

    fops->p_opts->payload = new_buffer(0); // TODO
    fops->p_opts->ip_id = 128; // TODO
    fops->p_opts->tcp_off = 5;
    
    fops->p_opts->saddr.sin_addr.s_addr = inet_addr(fops->p_opts->ip_dst);
    fops->p_opts->saddr.sin_family = AF_INET;
    fops->p_opts->saddr.sin_port = htons(fops->p_opts->tcp_dst);
    fops->p_opts->saddr.sin_len = hdr_size;
    
    if (fops->fuzz_ws) {
        fuzz_ws(pkt, fops->p_opts, 65535);
    }
    if (fops->fuzz_off) {
        fuzz_hdr_off(pkt, fops->p_opts, 65535);
    }
    fuzz_flags(pkt, fops->p_opts, 65535);
}

