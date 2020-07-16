/*
 * crnl.c  2007/05/30  K.Kosako
 *
 * !!! You should enable USE_CRNL_AS_LINE_TERMINATOR. !!!
 *
 * USE_CRNL_AS_LINE_TERMINATOR config test program.
 */
#include <stdio.h>
#include <string.h>
#include "oniguruma.h"

/* #define USE_UNICODE_ALL_LINE_TERMINATORS */

static int nfail = 0;

static void result(int no, int from, int to,
		   int expected_from, int expected_to)
{
  fprintf(stderr, "%3d: ", no);
  if (from == expected_from && to == expected_to) {
    fprintf(stderr, "Success\n");
  }
  else {
    fprintf(stderr, "Fail: expected: (%d-%d), result: (%d-%d)\n",
	    expected_from, expected_to, from, to);

    nfail++;
  }
}

static int
x0(int no, char* pattern_arg, char* str_arg,
   int start_offset, int expected_from, int expected_to, int backward)
{
  int r;
  unsigned char *start, *range, *end;
  regex_t* reg;
  OnigErrorInfo einfo;
  OnigRegion *region;
  UChar *pattern, *str;

  pattern = (UChar* )pattern_arg;
  str     = (UChar* )str_arg;

  r = onig_new(&reg, pattern, pattern + strlen((char* )pattern),
	ONIG_OPTION_NEWLINE_CRLF, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &einfo);
  if (r != ONIG_NORMAL) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r, &einfo);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  region = onig_region_new();

  end   = str + strlen((char* )str);
  if (backward) {
    start = end + start_offset;
    range = str;
  }
  else {
    start = str + start_offset;
    range = end;
  }
  r = onig_search(reg, str, end, start, range, region, ONIG_OPTION_NONE);
  if (r >= 0 || r == ONIG_MISMATCH) {
    result(no, region->beg[0], region->end[0], expected_from, expected_to);
  }
  else if (r == ONIG_MISMATCH) {
    result(no, r, -1, expected_from, expected_to);
  }
  else { /* error */
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
  onig_free(reg);
  return 0;
}

static int
x(int no, char* pattern_arg, char* str_arg,
  int expected_from, int expected_to)
{
  return x0(no, pattern_arg, str_arg, 0, expected_from, expected_to, 0);
}

static int
f0(int no, char* pattern_arg, char* str_arg, int start_offset, int backward)
{
  return x0(no, pattern_arg, str_arg, start_offset, -1, -1, backward);
}

static int
f(int no, char* pattern_arg, char* str_arg)
{
  return x(no, pattern_arg, str_arg, -1, -1);
}

extern int main(int argc, char* argv[])
{
  x( 1, "",        "\r\n",        0,  0);
/*  x( 2, ".",       "\r\n",        0,  1); */
  f( 2, ".",       "\r\n");
  f( 3, "..",      "\r\n");
  x( 4, "^",       "\r\n",        0,  0);
  x( 5, "\\n^",    "\r\nf",       1,  2);
  x( 6, "\\n^a",   "\r\na",       1,  3);
  x( 7, "$",       "\r\n",        0,  0);
  x( 8, "T$",      "T\r\n",       0,  1);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x( 9, "T$",      "T\raT\r\n",   0,  1);
#else
  x( 9, "T$",      "T\raT\r\n",   3,  4);
#endif
  x(10, "\\z",     "\r\n",        2,  2);
  f(11, "a\\z",    "a\r\n");
  x(12, "\\Z",     "\r\n",        0,  0);
  x(13, "\\Z",     "\r\na",       3,  3);
  x(14, "\\Z",     "\r\n\r\n\n",  4,  4);
  x(15, "\\Z",     "\r\n\r\nX",   5,  5);
  x(16, "a\\Z",    "a\r\n",       0,  1);
  x(17, "aaaaaaaaaaaaaaa\\Z",   "aaaaaaaaaaaaaaa\r\n",  0,  15);
  x(18, "a|$",     "b\r\n",       1,  1);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x(19, "$|b",     "\rb",         0,  0);
#else
  x(19, "$|b",     "\rb",         1,  2);
#endif
  x(20, "a$|ab$",  "\r\nab\r\n",  2,  4);

  x(21, "a|\\Z",       "b\r\n",       1,  1);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x(22, "\\Z|b",       "\rb",         0,  0);
#else
  x(22, "\\Z|b",       "\rb",         1,  2);
#endif
  x(23, "a\\Z|ab\\Z",  "\r\nab\r\n",  2,  4);
  x(24, "(?=a$).",     "a\r\n",       0,  1);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x(25, "(?=a$).",     "a\r",         0,  1);
  f(26, "(?!a$)..",    "a\r");
#else
  f(25, "(?=a$).",     "a\r");
  x(26, "(?!a$)..",    "a\r",         0,  2);
#endif
/*  x(27, "(?<=a$).\\n", "a\r\n",       1,  3); */
  x(27, "(?<=a$)\\r\\n", "a\r\n",       1,  3);
/*  f(28, "(?<!a$).\\n", "a\r\n"); */
  f(28, "(?<!a$)\\r\\n", "a\r\n");
  x(29, "(?=a\\Z).",     "a\r\n",       0,  1);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x(30, "(?=a\\Z).",     "a\r",         0,  1);
  f(31, "(?!a\\Z)..",    "a\r");
#else
  f(30, "(?=a\\Z).",     "a\r");
  x(31, "(?!a\\Z)..",    "a\r",         0,  2);
#endif

  x(32, ".*$",     "aa\r\n",      0,  2);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x(33, ".*$",     "aa\r",        0,  2);
#else
  x(33, ".*$",     "aa\r",        0,  3);
#endif
  x(34, "\\R{3}",  "\r\r\n\n",    0,  4);
  x(35, "$",       "\n",          0,  0);
  x(36, "T$",      "T\n",         0,  1);
  x(37, "(?m).",   "\r\n",        0,  1);
  x(38, "(?m)..",  "\r\n",        0,  2);
  x0(39, "^",      "\n.",     1,  1,  1,  0);
  x0(40, "^",      "\r\n.",   1,  2,  2,  0);
  x0(41, "^",      "\r\n.",   2,  2,  2,  0);
  x0(42, "$",      "\n\n",    1,  1,  1,  0);
  x0(43, "$",      "\r\n\n",  1,  2,  2,  0);
  x0(44, "$",      "\r\n\n",  2,  2,  2,  0);
#ifdef USE_UNICODE_ALL_LINE_TERMINATORS
  x0(45, "^$",     "\n\r",    1,  1,  1,  0);
#else
  f0(45, "^$",     "\n\r",    1,  0);
#endif
  x0(46, "^$",     "\n\r\n",  1,  1,  1,  0);
  x0(47, "^$",     "\r\n\n",  1,  2,  2,  0);
  x0(48, "\\Z",    "\r\n\n",  1,  2,  2,  0);
  f0(49, ".(?=\\Z)", "\r\n",  1,  0);
  x0(50, "(?=\\Z)", "\r\n",   1,  2,  2,  0);
  x0(51, "(?<=^).", "\r\n.",  0,  2,  3,  0);
  x0(52, "(?<=^).", "\r\n.",  1,  2,  3,  0);
  x0(53, "(?<=^).", "\r\n.",  2,  2,  3,  0);
  x0(54, "^a",      "\r\na",  0,  2,  3,  0);
  x0(55, "^a",      "\r\na",  1,  2,  3,  0);
  x0(56, "(?m)$.{1,2}a", "\r\na", 0,  0,  3,  0);
  f0(57, "(?m)$.{1,2}a", "\r\na", 1,  0);
  x0(58, ".*b",      "\r\naaab\r\n",  1,  2,  6,  0);

  /* backward search */
/*  x0(59, "$",      "\n\n",    0,  1,  1,  1); */	/* BUG? */
  x0(60, "$",      "\n\n",   -1,  1,  1,  1);
  x0(61, "$",      "\n\r\n", -1,  1,  1,  1);
  x0(62, "$",      "\n\r\n", -2,  1,  1,  1);
  x0(63, "^$",     "\n\r\n", -1,  1,  1,  1);
  x0(64, "^$",     "\n\r\n",  0,  1,  1,  1);
  x0(65, "^$",     "\r\n\n",  0,  2,  2,  1);
  x0(66, "^a",     "\r\na",   0,  2,  3,  1);
  x0(67, "^a",     "\r\na",  -1,  2,  3,  1);
  f0(68, "^a",     "\r\na",  -2,  1);

  onig_end();

  if (nfail > 0) {
    fprintf(stderr, "\n");
    fprintf(stderr, "!!! You have to enable USE_CRNL_AS_LINE_TERMINATOR\n");
    fprintf(stderr, "!!! in regenc.h for this test program.\n");
    fprintf(stderr, "\n");
  }

  return 0;
}
