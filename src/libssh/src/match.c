/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Simple pattern matching, with '*' and '?' as wildcards.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <ctype.h>
#include <stdbool.h>
#include <sys/types.h>

#include "libssh/priv.h"

#define MAX_MATCH_RECURSION 32

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 */
static int match_pattern(const char *s, const char *pattern, size_t limit)
{
  bool had_asterisk = false;
  if (s == NULL || pattern == NULL || limit <= 0) {
    return 0;
  }

  for (;;) {
    /* If at end of pattern, accept if also at end of string. */
    if (*pattern == '\0') {
        return (*s == '\0');
    }

    while (*pattern == '*') {
      /* Skip the asterisk. */
      had_asterisk = true;
      pattern++;
    }

    if (had_asterisk) {
      /* If at end of pattern, accept immediately. */
      if (!*pattern)
        return 1;

      /* If next character in pattern is known, optimize. */
      if (*pattern != '?') {
        /*
         * Look instances of the next character in
         * pattern, and try to match starting from
         * those.
         */
        for (; *s; s++)
          if (*s == *pattern && match_pattern(s + 1, pattern + 1, limit - 1)) {
            return 1;
          }
        /* Failed. */
        return 0;
      }
      /*
       * Move ahead one character at a time and try to
       * match at each position.
       */
      for (; *s; s++) {
        if (match_pattern(s, pattern, limit - 1)) {
          return 1;
        }
      }
      /* Failed. */
      return 0;
    }
    /*
     * There must be at least one more character in the string.
     * If we are at the end, fail.
     */
    if (!*s) {
      return 0;
    }

    /* Check if the next character of the string is acceptable. */
    if (*pattern != '?' && *pattern != *s) {
      return 0;
    }

    /* Move to the next character, both in string and in pattern. */
    s++;
    pattern++;
  }

  /* NOTREACHED */
  return 0;
}

/*
 * Tries to match the string against the comma-separated sequence of subpatterns
 * (each possibly preceded by ! to indicate negation).
 * Returns -1 if negation matches, 1 if there is a positive match, 0 if there is
 * no match at all.
 */
int match_pattern_list(const char *string, const char *pattern,
    unsigned int len, int dolower) {
  char sub[1024];
  int negated;
  int got_positive;
  unsigned int i, subi;

  got_positive = 0;
  for (i = 0; i < len;) {
    /* Check if the subpattern is negated. */
    if (pattern[i] == '!') {
      negated = 1;
      i++;
    } else {
      negated = 0;
    }

    /*
     * Extract the subpattern up to a comma or end.  Convert the
     * subpattern to lowercase.
     */
    for (subi = 0;
        i < len && subi < sizeof(sub) - 1 && pattern[i] != ',';
        subi++, i++) {
      sub[subi] = dolower && isupper(pattern[i]) ?
        (char)tolower(pattern[i]) : pattern[i];
    }

    /* If subpattern too long, return failure (no match). */
    if (subi >= sizeof(sub) - 1) {
      return 0;
    }

    /* If the subpattern was terminated by a comma, skip the comma. */
    if (i < len && pattern[i] == ',') {
      i++;
    }

    /* Null-terminate the subpattern. */
    sub[subi] = '\0';

    /* Try to match the subpattern against the string. */
    if (match_pattern(string, sub, MAX_MATCH_RECURSION)) {
      if (negated) {
        return -1;        /* Negative */
      } else {
        got_positive = 1; /* Positive */
      }
    }
  }

  /*
   * Return success if got a positive match.  If there was a negative
   * match, we have already returned -1 and never get here.
   */
  return got_positive;
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).
 * Returns -1 if negation matches, 1 if there is a positive match, 0 if there
 * is no match at all.
 */
int match_hostname(const char *host, const char *pattern, unsigned int len) {
  return match_pattern_list(host, pattern, len, 1);
}
