/*
 BSD 3-Clause License
 
 Copyright (c) 2025, k4m1  <me@k4m1.net>
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
#ifndef __HELPER_BUFFER_H__
#define __HELPER_BUFFER_H__

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Simple helper data structure to pass
 * messages and packets around across different
 * protocol layers.
 *
 * @member len Is the size of the allocated buffer
 * @member buf Is the buffer itself
 */
typedef struct {
    uint64_t len;
    uint8_t buf[];
} buffer;

/**
 * Allocate a new buffer with a given size. Set the 
 * size parameter if the allocation succeeds.
 *
 * The content of the buffer is preinitialised to zero.
 *
 * @param size is the size of buffer to allocate
 * @return a pointer to the allocated buffer on success or
 *         NULL on error.
 */
static inline buffer *new_buffer(uint64_t size) {
    buffer *ret = (buffer *)calloc(1, sizeof(buffer) + size);
    if (ret) {
        ret->len = size;
    }
    return ret;
}

/**
 * Resize a pre-existing buffer to a given size. Set the size
 * parameter if the (re)allocation succeeds. 
 *
 * @param buf is a pointer to the already allocated buffer
 * @param size is the new size to adjust the buffer to
 * @return a pointer to the new/resized buffer on success or
 *         NULL on error.
 */
static inline buffer *resize_buffer(buffer *buf, uint64_t size) {
    buffer *ret = (buffer *)realloc(buf, sizeof(buffer) + size);
    if (ret) {
        ret->len = size;
    }
    return ret;
}

/**
 * Copy a pre-existing buffer to a new one.
 *
 * @param buf is a pointer to the buffer to copy
 * @return pointer to a copy of 'buf' on success or NULL on error.
 */
static inline buffer *copy_buffer(buffer *buf) {
    buffer *ret = (buffer *)calloc(1, buf->len);
    if (ret) {
        memcpy(ret->buf, buf->buf, buf->len);
    }
    return ret;
}

/**
 * Add content of a buffer to another one.
 *
 * @param dst is a pointer to the buffer to append to 
 * @param src is a pointer to the buffer to append from 
 * @return a pointer to the destination buffer on success or NULL on error
 */
static inline buffer *append_buffer(buffer *dst, buffer *src) {
    uint64_t old_len = dst->len;
    buffer *ret = resize_buffer(dst, (dst->len + src->len));
    if (ret) {
        memcpy(ret->buf + old_len, src->buf, src->len);
        ret->len = old_len + src->len;
    }
    return ret;
}

#endif // __HELPER_BUFFER_H__
