/*
 * sql.c
 */
#include <stdio.h>
#include <string.h>
#include "oniguruma.h"

extern int main(int argc, char* argv[])
{
  static OnigSyntaxType SQLSyntax;

  int r;
  unsigned char *start, *range, *end;
  regex_t* reg;
  OnigErrorInfo einfo;
  OnigRegion *region;

  static UChar* pattern = (UChar* )"\\_%\\\\__zz";
  static UChar* str = (UChar* )"a_abcabcabc\\ppzz";

  onig_set_syntax_op      (&SQLSyntax, ONIG_SYN_OP_VARIABLE_META_CHARACTERS);
  onig_set_syntax_op2     (&SQLSyntax, 0);
  onig_set_syntax_behavior(&SQLSyntax, 0);
  onig_set_syntax_options (&SQLSyntax, ONIG_OPTION_MULTILINE);
  onig_set_meta_char(&SQLSyntax, ONIG_META_CHAR_ESCAPE, (OnigCodePoint )'\\');
  onig_set_meta_char(&SQLSyntax, ONIG_META_CHAR_ANYCHAR, (OnigCodePoint )'_');
  onig_set_meta_char(&SQLSyntax, ONIG_META_CHAR_ANYTIME,
		     ONIG_INEFFECTIVE_META_CHAR);
  onig_set_meta_char(&SQLSyntax, ONIG_META_CHAR_ZERO_OR_ONE_TIME,
		     ONIG_INEFFECTIVE_META_CHAR);
  onig_set_meta_char(&SQLSyntax, ONIG_META_CHAR_ONE_OR_MORE_TIME,
		     ONIG_INEFFECTIVE_META_CHAR);
  onig_set_meta_char(&SQLSyntax, ONIG_META_CHAR_ANYCHAR_ANYTIME,
		     (OnigCodePoint )'%');

  r = onig_new(&reg, pattern, pattern + strlen((char* )pattern),
	       ONIG_OPTION_DEFAULT, ONIG_ENCODING_ASCII, &SQLSyntax, &einfo);
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
