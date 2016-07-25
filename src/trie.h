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
#include <stdint.h>

struct trie_node {
    struct trie_node *next[8];
    struct trie_leaf *leaf;
    int ref_cnt;
};

struct trie_leaf {
    char *key;
    void *data;
    struct trie_leaf *next;
};

struct trie {
    struct trie_node *root;
    void (*free_node)(void *data);
};

bool trie_init(struct trie *t, void (*free_node)(void *data));
void trie_destroy(struct trie *t);
void trie_add(struct trie *t, const char *key, void *data);
void *trie_lookup_full(struct trie *t, const char *key, bool prefix);
void *trie_lookup_prefix(struct trie *t, const char *key);
void *trie_lookup_exact(struct trie *t, const char *key);
int32_t trie_entry_count(struct trie *t);


