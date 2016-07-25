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

#pragma once 

#include <stdbool.h>
#include <stdio.h>

typedef struct {
    char *value;
    size_t len;     /* strlen of value */
    size_t sz;      /* sizeof *value */
} string;

static string *string_new(char *value, size_t len, size_t sz) {
    string *str = malloc(sizeof(string));
    if (!str)
        return NULL;
    str->value = value;
    str->len = len;
    str->sz = sz;
    return str;
}

static void string_free(void *s) {
    string *str = s;
    if (!str)
        return;

    if (!str->value)
        free(str->value);

    free(str);
}

typedef struct {
    union {
        char *buffer;
        const char *static_buffer;
    } value;
    struct {
        size_t allocated;
        size_t buffer;
    } len;
    unsigned int flags;
} strbuf;

bool strbuf_init_with_size(strbuf *buf, size_t size);
bool strbuf_init(strbuf *buf);
strbuf	*strbuf_new_static(const char *str, size_t size);
strbuf	*strbuf_new_with_size(size_t size);
strbuf	*strbuf_new(void);
void strbuf_free(strbuf *s);
bool strbuf_append_char(strbuf *s, const char c);
bool strbuf_append_str(strbuf *s1, const char *s2, size_t sz);
bool strbuf_set_static(strbuf *s1, const char *s2, size_t sz);
bool strbuf_set(strbuf *s1, const char *s2, size_t sz);
int strbuf_cmp(strbuf *s1, strbuf *s2);
bool strbuf_append_printf(strbuf *s, const char *fmt, ...);
bool strbuf_printf(strbuf *s1, const char *fmt, ...);
bool strbuf_shrink_to(strbuf *s, size_t new_size);
bool strbuf_shrink_to_default(strbuf *s);
bool strbuf_grow_to(strbuf *s, size_t new_size);
bool strbuf_reset(strbuf *s);
bool strbuf_reset_length(strbuf *s);

#define strbuf_get_length(s)	(((strbuf *)(s))->len.buffer)
#define strbuf_get_buffer(s)	(((strbuf *)(s))->value.buffer)

