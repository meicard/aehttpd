/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "strext.h"

static const unsigned int STATIC = 1<<0;
static const unsigned int DYNAMICALLY_ALLOCATED = 1<<1;
static const size_t DEFAULT_BUF_SIZE = 64;

static size_t find_next_power_of_two(size_t number)
{
    number--;
    number |= number >> 1;
    number |= number >> 2;
    number |= number >> 4;
    number |= number >> 8;
    number |= number >> 16;

    return number + 1;
}

static inline size_t align_size(size_t unaligned_size)
{
    const size_t aligned_size = find_next_power_of_two(unaligned_size);

    if (unaligned_size >= aligned_size)
        return 0;

    return aligned_size;
}


static inline __attribute__((always_inline))
size_t max(size_t one, size_t another)
{
    return (one > another) ? one : another;
}

static bool grow_buffer_if_needed(strbuf *s, size_t size)
{
    if (s->flags & STATIC) {
        const size_t aligned_size = align_size(max(size + 1, s->len.buffer));
        if (!aligned_size)
            return false;

        char *buffer = malloc(aligned_size);
        if (!buffer)
            return false;

        memcpy(buffer, s->value.static_buffer, s->len.buffer);
        buffer[s->len.buffer + 1] = '\0';

        s->flags &= ~STATIC;
        s->len.allocated = aligned_size;
        s->value.buffer = buffer;

        return true;
    }

    if (s->len.allocated < size) {
        const size_t aligned_size = align_size(size + 1);
        if (!aligned_size)
            return false;

        char *buffer = realloc(s->value.buffer, aligned_size);
        if (!buffer)
            return false;
        s->len.allocated = aligned_size;
        s->value.buffer = buffer;
    }

    return true;
}

bool
strbuf_init_with_size(strbuf *s, size_t size)
{
    if (!s)
        return false;

    memset(s, 0, sizeof(*s));

    if (!grow_buffer_if_needed(s, size))
        return false;

    s->len.buffer = 0;
    s->value.buffer[0] = '\0';

    return true;
}

inline __attribute__((always_inline))
bool strbuf_init(strbuf *s)
{
    return strbuf_init_with_size(s, DEFAULT_BUF_SIZE);
}

strbuf *
strbuf_new_with_size(size_t size)
{
    strbuf *s = malloc(sizeof(*s));
    if (!strbuf_init_with_size(s, size)) {
        free(s);
        s = NULL;
    } else {
        s->flags |= DYNAMICALLY_ALLOCATED;
    }
    return s;
}

inline __attribute__((always_inline)) strbuf *
strbuf_new(void)
{
    return strbuf_new_with_size(DEFAULT_BUF_SIZE);
}

inline __attribute__((always_inline)) strbuf *
strbuf_new_static(const char *str, size_t size)
{
    strbuf *s = malloc(sizeof(*s));

    if (!s)
        return NULL;

    s->flags = STATIC | DYNAMICALLY_ALLOCATED;
    s->value.static_buffer = str;
    s->len.buffer = s->len.allocated = size;

    return s;
}

void strbuf_free(strbuf *s)
{
    if (!s)
        return;
    if (!(s->flags & STATIC))
        free(s->value.buffer);
    if (s->flags & DYNAMICALLY_ALLOCATED)
        free(s);
}

bool
strbuf_append_char(strbuf *s, const char c)
{
    if (!grow_buffer_if_needed(s, s->len.buffer + 2))
        return false;

    *(s->value.buffer + s->len.buffer++) = c;
    *(s->value.buffer + s->len.buffer) = '\0';

    return true;
}

bool
strbuf_append_str(strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (!grow_buffer_if_needed(s1, s1->len.buffer + sz + 2))
        return false;

    memcpy(s1->value.buffer + s1->len.buffer, s2, sz);
    s1->len.buffer += sz;
    s1->value.buffer[s1->len.buffer] = '\0';

    return true;
}

bool
strbuf_set_static(strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (!(s1->flags & STATIC))
        free(s1->value.buffer);
    s1->value.static_buffer = s2;
    s1->len.allocated = s1->len.buffer = sz;
    s1->flags |= STATIC;

    return true;
}

bool
strbuf_set(strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (!grow_buffer_if_needed(s1, sz + 1))
        return false;

    memcpy(s1->value.buffer, s2, sz);
    s1->len.buffer = sz;
    s1->value.buffer[sz] = '\0';

    return true;
}

inline __attribute__((always_inline))
int strbuf_cmp(strbuf *s1, strbuf *s2)
{
    if (s1 == s2)
        return 0;
    int result = memcmp(s1->value.buffer, s2->value.buffer, s1->len.buffer < s2->len.buffer ? s1->len.buffer : s2->len.buffer);
    if (!result)
        return (int)(s1->len.buffer - s2->len.buffer);
    return result;
}

static inline __attribute__((always_inline))
bool internal_printf(strbuf *s1, bool (*save_str)(strbuf *, const char *, size_t), const char *fmt, va_list values)
{
    char *s2;
    int len;

    if ((len = vasprintf(&s2, fmt, values)) < 0)
        return false;

    bool success = save_str(s1, s2, (size_t)len);
    free(s2);

    return success;
}

bool
strbuf_printf(strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = internal_printf(s, strbuf_set, fmt, values);
    va_end(values);

    return could_printf;
}

bool
strbuf_append_printf(strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = internal_printf(s, strbuf_append_str, fmt, values);
    va_end(values);

    return could_printf;
}

bool
strbuf_shrink_to(strbuf *s, size_t new_size)
{
    if (s->len.allocated <= new_size)
        return true;

    if (s->flags & STATIC)
        return true;

    size_t aligned_size = align_size(new_size + 1);
    if (!aligned_size)
        return false;

    char *buffer = realloc(s->value.buffer, aligned_size);
    if (!buffer)
        return false;

    s->value.buffer = buffer;
    s->len.allocated = aligned_size;
    if (s->len.buffer > aligned_size) {
        s->len.buffer = aligned_size - 1;
        s->value.buffer[s->len.buffer + 1] = '\0';
    }

    return true;
}

inline __attribute__((always_inline))
bool strbuf_shrink_to_default(strbuf *s)
{
    return strbuf_shrink_to(s, DEFAULT_BUF_SIZE);
}

inline __attribute__((always_inline))
bool strbuf_reset(strbuf *s)
{
    strbuf_shrink_to_default(s);
    s->len.buffer = 0;
    return false;
}

bool
strbuf_grow_to(strbuf *s, size_t new_size)
{
    return grow_buffer_if_needed(s, new_size + 1);
}

bool
strbuf_reset_length(strbuf *s)
{
    if (s->flags & STATIC) {
        s->flags &= ~STATIC;
        s->value.buffer = malloc(s->len.allocated);
        if (!s->value.buffer)
            return false;
    }

    s->len.buffer = 0;
    s->value.buffer[0] = '\0';

    return true;
}

