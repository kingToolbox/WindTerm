/*
 * syntax.c
 */
#include <stdio.h>
#include <string.h>
#include "oniguruma.h"

extern int exec(OnigSyntaxType* syntax,
		char* apattern, char* astr)
{
  int r;
  unsigned char *start, *range, *end;
  regex_t* reg;
  OnigErrorInfo einfo;
  OnigRegion *region;
  UChar* pattern = (UChar* )apattern;
  UChar* str     = (UChar* )astr;

  r = onig_new(&reg, pattern, pattern + strlen((char* )pattern),
	       ONIG_OPTION_DEFAULT, ONIG_ENCODING_ASCII, syntax, &einfo);
  if (r != ONIG_NORMAL) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r, &einfo);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  region = onig_region_new();

  end   = str + strlen((char* )str);
  start = str;
  range = end;
  r = onig_search(reg, str, end, start, range, region, ONIG_OPTION_NONE);
  if (r >= 0) {
    int i;

    fprintf(stderr, "match at %d\n", r);
    for (i = 0; i < region->num_regs; i++) {
      fprintf(stderr, "%d: (%ld-%ld)\n", i, region->beg[i], region->end[i]);
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

extern int main(int argc, char* argv[])
{
  int r;

  r = exec(ONIG_SYNTAX_PERL,
	   "\\p{XDigit}\\P{XDigit}\\p{^XDigit}\\P{^XDigit}\\p{XDigit}",
	   "bgh3a");

  r = exec(ONIG_SYNTAX_JAVA,
	   "\\p{XDigit}\\P{XDigit}[a-c&&b-g]", "bgc");

  r = exec(ONIG_SYNTAX_ASIS,
           "abc def* e+ g?ddd[a-rvvv] (vv){3,7}hv\\dvv(?:aczui ss)\\W\\w$",
           "abc def* e+ g?ddd[a-rvvv] (vv){3,7}hv\\dvv(?:aczui ss)\\W\\w$");
  onig_end();
  return 0;
}
