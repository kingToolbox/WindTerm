/*
 * simple.c
 */
#include <stdio.h>
#include <string.h>
#include "oniguruma.h"

extern int main(int argc, char* argv[])
{
  OnigPosition r;
  OnigPosition start, range, end;
  regex_t* reg;
  OnigErrorInfo einfo;
  OnigRegion *region;

  static UChar* pattern = (UChar* )"a(.*)b|[e-f]+";
  static UChar* str     = (UChar* )"zzzzaffffffffb";
  OnigIterator it = {onig_default_charat, str};

  r = onig_new(&reg, pattern, pattern + strlen((char* )pattern),
	ONIG_OPTION_DEFAULT, ONIG_ENCODING_ASCII, ONIG_SYNTAX_DEFAULT, &einfo);
  if (r != ONIG_NORMAL) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r, &einfo);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  region = onig_region_new();

  end   = strlen((char* )str);
  start = 0;
  range = end;
  r = onig_search(&it, reg, 0, end, start, range, region, ONIG_OPTION_NONE);
  if (r >= 0) {
    int i;

    fprintf(stderr, "match at %d\n", r);
    for (i = 0; i < region->num_regs; i++) {
      fprintf(stderr, "%d: (%ld-%ld)\n", i, (int)region->beg[i], (int)region->end[i]);
    }
  }
  else if (r == ONIG_MISMATCH) {
    fprintf(stderr, "search fail\n");
  }
  else { /* error */
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
  onig_free(reg);
  onig_end();
  return 0;
}
