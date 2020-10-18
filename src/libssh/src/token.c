/*
 * token.c - Token list handling functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 * Copyright (c) 2019 by Anderson Toshiyuki Sasaki - Red Hat, Inc.
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "libssh/priv.h"
#include "libssh/token.h"

/**
 * @internal
 *
 * @brief Free the given tokens list structure. The used buffer is overwritten
 * with zeroes before freed.
 *
 * @param[in] tokens    The pointer to a structure to be freed;
 */
void ssh_tokens_free(struct ssh_tokens_st *tokens)
{
    int i;
    if (tokens == NULL) {
        return;
    }

    if (tokens->tokens != NULL) {
        for (i = 0; tokens->tokens[i] != NULL; i++) {
            explicit_bzero(tokens->tokens[i], strlen(tokens->tokens[i]));
        }
    }

    SAFE_FREE(tokens->buffer);
    SAFE_FREE(tokens->tokens);
    SAFE_FREE(tokens);
}

/**
 * @internal
 *
 * @brief Split a given string on the given separator character. The returned
 * structure holds an array of pointers (tokens) pointing to the obtained
 * parts and a buffer where all the content of the list is stored. The last
 * element of the array will always be set as NULL.
 *
 * @param[in] chain         The string to split
 * @param[in] separator     The character used to separate the tokens.
 *
 * @return  A newly allocated tokens list structure; NULL in case of error.
 */
struct ssh_tokens_st *ssh_tokenize(const char *chain, char separator)
{

    struct ssh_tokens_st *tokens = NULL;
    size_t num_tokens = 1, i = 1;

    char *found, *c;

    if (chain == NULL) {
        return NULL;
    }

    tokens = calloc(1, sizeof(struct ssh_tokens_st));
    if (tokens == NULL) {
        return NULL;
    }

    tokens->buffer= strdup(chain);
    if (tokens->buffer == NULL) {
        goto error;
    }

    c = tokens->buffer;
    do {
        found = strchr(c, separator);
        if (found != NULL) {
            c = found + 1;
            num_tokens++;
        }
    } while(found != NULL);

    /* Allocate tokens list */
    tokens->tokens = calloc(num_tokens + 1, sizeof(char *));
    if (tokens->tokens == NULL) {
        goto error;
    }

    /* First token starts in the beginning of the chain */
    tokens->tokens[0] = tokens->buffer;
    c = tokens->buffer;

    for (i = 1; i < num_tokens; i++) {
        /* Find next separator */
        found = strchr(c, separator);
        if (found == NULL) {
            break;
        }

        /* Replace it with a string terminator */
        *found = '\0';

        /* The next token starts in the next byte */
        c = found + 1;

        /* If we did not reach the end of the chain yet, set the next token */
        if (*c != '\0') {
            tokens->tokens[i] = c;
        } else {
            break;
        }
    }

    return tokens;

error:
    ssh_tokens_free(tokens);
    return NULL;
}

/**
 * @internal
 *
 * @brief Given two strings, the first containing a list of available tokens and
 * the second containing a list of tokens to be searched ordered by preference,
 * returns a copy of the first preferred token present in the available list.
 *
 * @param[in] available_list    The list of available tokens
 * @param[in] preferred_list    The list of tokens to search, ordered by
 * preference
 *
 * @return  A newly allocated copy of the token if found; NULL otherwise
 */
char *ssh_find_matching(const char *available_list,
                        const char *preferred_list)
{
    struct ssh_tokens_st *a_tok = NULL, *p_tok = NULL;

    int i, j;
    char *ret = NULL;

    if ((available_list == NULL) || (preferred_list == NULL)) {
        return NULL;
    }

    a_tok = ssh_tokenize(available_list, ',');
    if (a_tok == NULL) {
        return NULL;
    }

    p_tok = ssh_tokenize(preferred_list, ',');
    if (p_tok == NULL) {
        goto out;
    }

    for (i = 0; p_tok->tokens[i]; i++) {
        for (j = 0; a_tok->tokens[j]; j++) {
            if (strcmp(a_tok->tokens[j], p_tok->tokens[i]) == 0) {
                ret = strdup(a_tok->tokens[j]);
                goto out;
            }
        }
    }

out:
    ssh_tokens_free(a_tok);
    ssh_tokens_free(p_tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given two strings, the first containing a list of available tokens and
 * the second containing a list of tokens to be searched ordered by preference,
 * returns a list of all matching tokens ordered by preference.
 *
 * @param[in] available_list    The list of available tokens
 * @param[in] preferred_list    The list of tokens to search, ordered by
 * preference
 *
 * @return  A newly allocated string containing the list of all matching tokens;
 * NULL otherwise
 */
char *ssh_find_all_matching(const char *available_list,
                            const char *preferred_list)
{
    struct ssh_tokens_st *a_tok = NULL, *p_tok = NULL;
    int i, j;
    char *ret = NULL;
    size_t max, len, pos = 0;
    int match;

    if ((available_list == NULL) || (preferred_list == NULL)) {
        return NULL;
    }

    max = MAX(strlen(available_list), strlen(preferred_list));

    ret = calloc(1, max + 1);
    if (ret == NULL) {
        return NULL;
    }

    a_tok = ssh_tokenize(available_list, ',');
    if (a_tok == NULL) {
        SAFE_FREE(ret);
        goto out;
    }

    p_tok = ssh_tokenize(preferred_list, ',');
    if (p_tok == NULL) {
        SAFE_FREE(ret);
        goto out;
    }

    for (i = 0; p_tok->tokens[i] ; i++) {
        for (j = 0; a_tok->tokens[j]; j++) {
            match = !strcmp(a_tok->tokens[j], p_tok->tokens[i]);
            if (match) {
                if (pos != 0) {
                    ret[pos] = ',';
                    pos++;
                }

                len = strlen(a_tok->tokens[j]);
                memcpy(&ret[pos], a_tok->tokens[j], len);
                pos += len;
                ret[pos] = '\0';
            }
        }
    }

    if (ret[0] == '\0') {
        SAFE_FREE(ret);
    }

out:
    ssh_tokens_free(a_tok);
    ssh_tokens_free(p_tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given a string containing a list of elements, remove all duplicates
 * and return in a newly allocated string.
 *
 * @param[in] list  The list to be freed of duplicates
 *
 * @return  A newly allocated copy of the string free of duplicates; NULL in
 * case of error.
 */
char *ssh_remove_duplicates(const char *list)
{
    struct ssh_tokens_st *tok = NULL;

    size_t i, j, num_tokens, max_len;
    char *ret = NULL;
    bool *should_copy = NULL, need_comma = false;

    if (list == NULL) {
        return NULL;
    }

    /* The maximum number of tokens is the size of the list */
    max_len = strlen(list);
    if (max_len == 0) {
        return NULL;
    }

    /* Add space for ending '\0' */
    max_len++;

    tok = ssh_tokenize(list, ',');
    if ((tok == NULL) || (tok->tokens == NULL) || (tok->tokens[0] == NULL)) {
        goto out;
    }

    should_copy = calloc(1, max_len);
    if (should_copy == NULL) {
        goto out;
    }

    if (strlen(tok->tokens[0]) > 0) {
        should_copy[0] = true;
    }

    for (i = 1; tok->tokens[i]; i++) {
        for (j = 0; j < i; j++) {
            if (strcmp(tok->tokens[i], tok->tokens[j]) == 0) {
                /* Found a duplicate; do not copy */
                should_copy[i] = false;
                break;
            }
        }

        /* No matching token before */
        if (j == i) {
            /* Only copy if it is not an empty string */
            if (strlen(tok->tokens[i]) > 0) {
                should_copy[i] = true;
            } else {
                should_copy[i] = false;
            }
        }
    }

    num_tokens = i;

    ret = calloc(1, max_len);
    if (ret == NULL) {
        goto out;
    }

    for (i = 0; i < num_tokens; i++) {
        if (should_copy[i]) {
            if (need_comma) {
                strncat(ret, ",", (max_len - strlen(ret) - 1));
            }
            strncat(ret, tok->tokens[i], (max_len - strlen(ret) - 1));
            need_comma = true;
        }
    }

    /* If no comma is needed, nothing was copied */
    if (!need_comma) {
        SAFE_FREE(ret);
    }

out:
    SAFE_FREE(should_copy);
    ssh_tokens_free(tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given two strings containing lists of tokens, return a newly
 * allocated string containing all the elements of the first list appended with
 * all the elements of the second list, without duplicates. The order of the
 * elements will be preserved.
 *
 * @param[in] list             The first list
 * @param[in] appended_list    The list to be appended
 *
 * @return  A newly allocated copy list containing all the elements of the
 * kept_list appended with the elements of the appended_list without duplicates;
 * NULL in case of error.
 */
char *ssh_append_without_duplicates(const char *list,
                                    const char *appended_list)
{
    size_t concat_len = 0;
    char *ret = NULL, *concat = NULL;

    if (list != NULL) {
        concat_len = strlen(list);
    }

    if (appended_list != NULL) {
        concat_len += strlen(appended_list);
    }

    if (concat_len == 0) {
        return NULL;
    }

    /* Add room for ending '\0' and for middle ',' */
    concat_len += 2;
    concat = calloc(1, concat_len);
    if (concat == NULL) {
        return NULL;
    }

    if (list != NULL) {
        strcpy(concat, list);
        strncat(concat, ",", concat_len - strlen(concat) - 1);
    }
    if (appended_list != NULL) {
        strncat(concat, appended_list, concat_len - strlen(concat) - 1);
    }

    ret = ssh_remove_duplicates(concat);

    SAFE_FREE(concat);

    return ret;
}
