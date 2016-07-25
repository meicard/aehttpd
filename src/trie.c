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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "server.h"
#include "trie.h"

bool trie_init(struct trie *t, void (*free_node)(void *data)) {
    if (!t)
        return false;
    
    t->root = NULL;
    t->free_node = free_node;
    return true;
}

static struct trie_leaf *
find_leaf_with_key(struct trie_node *node, const char *key, size_t len) {
    struct trie_leaf *leaf = node->leaf;
    if (!leaf)
        return NULL;
    
    if (!leaf->next)
        return leaf;
    
    for (; leaf; leaf = leaf->next) {
        if (!strncmp(leaf->key, key, len-1))
            return leaf;
    }
    return NULL;
}

#define GET_NODE() \
    do {\
        if (!(node = *knode)) {\
            *knode = node = calloc(1, sizeof(*node));\
            if (!node) \
                goto oom;\
        }\
        ++node->ref_cnt;\
    } while(0)


void trie_add(struct trie *t, const char *key, void *data) {
    if (!t || !key || !data)
        return;
    
    struct trie_node **knode, *node;
    const char *orig_key = key;
    
    for (knode = &t->root; *key; knode = &node->next[(int)(*key++ & 7)])
        GET_NODE();
    
    GET_NODE();
    
    struct trie_leaf *leaf;
    leaf = find_leaf_with_key(node, orig_key, (size_t)(key-orig_key));
    bool had_key = leaf;
    if (!leaf) {
        leaf = malloc(sizeof(*leaf));
        if (!leaf) {
            fprintf(stderr, "malloc\n");
            exit(1);
        }
    }
    
    leaf->data = data;
    if (!had_key) {
        leaf->key = strdup(orig_key);
        leaf->next = node->leaf;
        node->leaf = leaf;
    }
    
    return ;

oom:
    DIE("calloc");
}
#undef GET_NODE

static struct trie_node *
lookup_node(struct trie_node *root, const char *key, bool prefix, size_t *prefix_len) {
    struct trie_node *node, *prev_node = NULL;
    const char *orig_key = key;
    
    for (node = root; node && *key; node = node->next[(int)(*key++ & 7)]) {
        if (node->leaf)
            prev_node = node;
    }
    
    *prefix_len = (size_t)(key - orig_key);
    if (node && node->leaf)
        return node;
    if (prefix && prev_node)
        return prev_node;
    return NULL;
}

void *trie_lookup_full(struct trie *t, const char *key, bool prefix) {
    if (!t)
        return NULL;
    
    size_t prefix_len;
    struct trie_node *node = lookup_node(t->root, key, prefix, &prefix_len);
    if (!node)
        return NULL;
    struct trie_leaf *leaf = find_leaf_with_key(node, key, prefix_len);
    return leaf ? leaf->data : NULL;
}

void *trie_lookup_prefix(struct trie *t, const char *key) {
    return trie_lookup_full(t, key, true);
}

void *trie_lookup_exact(struct trie *t, const char *key) {
    return trie_lookup_full(t, key, false);
}

int32_t trie_entry_count(struct trie *t) {
    return (t && t->root) ? t->root->ref_cnt : 0;
}

static void trie_node_destroy(struct trie *trie, struct trie_node *node) {
    if (!node)
        return;
    
    int32_t nodes_destroyed = node->ref_cnt;
    struct trie_leaf *leaf;
    for (leaf = node->leaf; leaf; ) {
        struct trie_leaf *tmp = leaf->next;
        if (trie->free_node)
            trie->free_node(leaf->data);
        
        free(leaf->key);
        free(leaf);
        leaf = tmp;
    }
    
    int32_t i;
    for (i = 0; nodes_destroyed > 0 && i < 8; i++) {
        if (node->next[i]) {
            trie_node_destroy(trie, node->next[i]);
            --nodes_destroyed;
        }
    }
    
    free(node);
}


void trie_destroy(struct trie *t) {
    if (!t || !t->root)
        return;
    trie_node_destroy(t, t->root);
}

