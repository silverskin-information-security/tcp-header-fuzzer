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


#ifndef __FUZZ_PKT_H__
#define __FUZZ_PKT_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdbool.h>
#include <stdint.h>
#include "buffer.h"

typedef struct {
    const char *ip_src;
    const char *ip_dst;
    uint16_t ip_id;
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint8_t tcp_flags;
    uint8_t tcp_off;
    uint16_t tcp_ws;
    buffer *payload;
    struct sockaddr_in saddr;
} packet_options;

static const uint16_t hdr_size = (sizeof(struct ip) + sizeof(struct tcphdr));

void populate_ip(buffer *packet, packet_options *opts);
void populate_tcp(buffer *packet, packet_options *opts);
bool populate_packet(buffer *packet, packet_options *opts);

bool tx_pkt(buffer *packet, packet_options *opts);

#endif
