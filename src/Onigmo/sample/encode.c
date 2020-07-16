/*
 * encode.c
 */
#include <stdio.h>
#include "oniguruma.h"

static int
search(regex_t* reg, unsigned char* str, unsigned char* end)
{
  int r;
  unsigned char *start, *range;
  OnigRegion *region;

  region = onig_region_new();

  start = str;
  range = end;
  r = onig_search(reg, str, end, start, range, region, ONIG_OPTION_NONE);
  if (r >= 0) {
    int i;

    fprintf(stderr, "match at %d  (%s)\n", r,
            ONIGENC_NAME(onig_get_encoding(reg)));
    for (i = 0; i < region->num_regs; i++) {
      fprintf(stderr, "%d: (%ld-%ld)\n", i, region->beg[i], region->end[i]);
    }
  }
  else if (r == ONIG_MISMATCH) {
    fprintf(stderr, "search fail (%s)\n",
            ONIGENC_NAME(onig_get_encoding(reg)));
  }
  else { /* error */
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r);
    fprintf(stderr, "ERROR: %s\n", s);
    fprintf(stderr, "  (%s)\n", ONIGENC_NAME(onig_get_encoding(reg)));
    return -1;
  }

  onig_region_free(region, 1 /* 1:free self, 0:free contents only */);
  return 0;
}

static int
exec(OnigEncoding enc, OnigOptionType options,
     char* apattern, char* astr)
{
  int r;
  unsigned char *end;
  regex_t* reg;
  OnigErrorInfo einfo;
  UChar* pattern = (UChar* )apattern;
  UChar* str     = (UChar* )astr;

  r = onig_new(&reg, pattern,
               pattern + onigenc_str_bytelen_null(enc, pattern),
               options, enc, ONIG_SYNTAX_DEFAULT, &einfo);
  if (r != ONIG_NORMAL) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r, &einfo);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  end   = str + onigenc_str_bytelen_null(enc, str);
  r = search(reg, str, end);

  onig_free(reg);
  onig_end();
  return 0;
}

static OnigCaseFoldType CF = ONIGENC_CASE_FOLD_MIN;

#if 0
static void
set_case_fold(OnigCaseFoldType cf)
{
  CF = cf;
}
#endif

static int
exec_deluxe(OnigEncoding pattern_enc, OnigEncoding str_enc,
            OnigOptionType options, char* apattern, char* astr)
{
  int r;
  unsigned char *end;
  regex_t* reg;
  OnigCompileInfo ci;
  OnigErrorInfo einfo;
  UChar* pattern = (UChar* )apattern;
  UChar* str     = (UChar* )astr;

  ci.num_of_elements = 5;
  ci.pattern_enc = pattern_enc;
  ci.target_enc  = str_enc;
  ci.syntax      = ONIG_SYNTAX_DEFAULT;
  ci.option      = options;
  ci.case_fold_flag  = CF;

  r = onig_new_deluxe(&reg, pattern,
                      pattern + onigenc_str_bytelen_null(pattern_enc, pattern),
                      &ci, &einfo);
  if (r != ONIG_NORMAL) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r, &einfo);
    fprintf(stderr, "ERROR: %s\n", s);
    return -1;
  }

  end = str + onigenc_str_bytelen_null(str_enc, str);
  r = search(reg, str, end);

  onig_free(reg);
  onig_end();
  return 0;
}

extern int main(int argc, char* argv[])
{
  int r;
  /* ISO 8859-1 test */
  static unsigned char str[] = { 0xc7, 0xd6, 0xfe, 0xea, 0xe0, 0xe2, 0x00 };
  static unsigned char pattern[] = { 0xe7, 0xf6, 0xde, '\\', 'w', '+', 0x00 };

  r = exec(ONIG_ENCODING_CP1251, ONIG_OPTION_IGNORECASE,
	   "aBc", " AbC");

  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
	   " [a-c\337z] ", "  SS  ");
  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
	   " [\330-\341] ", "  SS  ");

  r = exec(ONIG_ENCODING_ISO_8859_2, ONIG_OPTION_IGNORECASE,
	   "\337          ", "          Ss          ");
  r = exec(ONIG_ENCODING_ISO_8859_2, ONIG_OPTION_IGNORECASE,
	   "SS          ", "          \337          ");
  r = exec(ONIG_ENCODING_ISO_8859_2, ONIG_OPTION_IGNORECASE,
	   "\\A\\S\\z", "ss");

  r = exec(ONIG_ENCODING_ISO_8859_2, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");

  r = exec(ONIG_ENCODING_ISO_8859_3, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_4, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_5, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_6, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_7, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_8, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_9, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_10, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_11, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_13, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_14, ONIG_OPTION_IGNORECASE,
	   "[ac]+", "bbbaAaCCC");
  r = exec(ONIG_ENCODING_ISO_8859_15, ONIG_OPTION_IGNORECASE,
	   (char* )pattern, (char* )str);
  r = exec(ONIG_ENCODING_ISO_8859_16, ONIG_OPTION_IGNORECASE,
	   (char* )pattern, (char* )str);

  r = exec(ONIG_ENCODING_KOI8_R, ONIG_OPTION_NONE, "a+", "bbbaaaccc");
  r = exec(ONIG_ENCODING_EUC_TW, ONIG_OPTION_NONE, "b*a+?c+", "bbbaaaccc");
  r = exec(ONIG_ENCODING_EUC_KR, ONIG_OPTION_NONE, "a+", "bbbaaaccc");
  r = exec(ONIG_ENCODING_EUC_CN, ONIG_OPTION_NONE, "c+", "bbbaaaccc");
  r = exec(ONIG_ENCODING_BIG5,   ONIG_OPTION_NONE, "a+", "bbbaaaccc");

  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
           "\337", "SS");
  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
           "SS", "\337");
  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
           "SSb\337ssc", "a\337bSS\337cd");
  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
           "[a\337]{0,2}", "aSS");
  r = exec(ONIG_ENCODING_ISO_8859_1, ONIG_OPTION_IGNORECASE,
           "is", "iss");

  r = exec_deluxe(ONIG_ENCODING_ASCII, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_NONE, "a+",
                  "\000b\000a\000a\000a\000c\000c\000\000");

  r = exec_deluxe(ONIG_ENCODING_ASCII, ONIG_ENCODING_UTF16_LE,
                  ONIG_OPTION_NONE, "a+",
                  "b\000a\000a\000a\000a\000c\000\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_LE,
                  ONIG_OPTION_NONE,
                  "\000b\000a\000a\000a\000c\000c\000\000",
                  "x\000b\000a\000a\000a\000c\000c\000\000\000");

  r = exec_deluxe(ONIG_ENCODING_ISO_8859_1, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
                  "\337", "\000S\000S\000\000");

  r = exec_deluxe(ONIG_ENCODING_ISO_8859_1, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
                  "SS", "\000\337\000\000");

  r = exec_deluxe(ONIG_ENCODING_ISO_8859_1, ONIG_ENCODING_UTF16_LE,
                  ONIG_OPTION_IGNORECASE,
                  "\337", "S\000S\000\000\000");

  r = exec_deluxe(ONIG_ENCODING_ISO_8859_1, ONIG_ENCODING_UTF32_BE,
                  ONIG_OPTION_IGNORECASE,
                  "SS", "\000\000\000\337\000\000\000\000");

  r = exec_deluxe(ONIG_ENCODING_ISO_8859_1, ONIG_ENCODING_UTF32_LE,
                  ONIG_OPTION_IGNORECASE,
                  "\337", "S\000\000\000S\000\000\000\000\000\000\000");

  r = exec(ONIG_ENCODING_UTF16_BE, ONIG_OPTION_NONE,
	   "\000[\000[\000:\000a\000l\000n\000u\000m\000:\000]\000]\000+\000\000",
           "\000#\002\120\000a\000Z\012\077\012\076\012\075\000\000");
  /* 0x0a3d == \012\075 : is not alnum */
  /* 0x0a3e == \012\076 : is alnum */

  r = exec(ONIG_ENCODING_UTF16_BE, ONIG_OPTION_NONE,
	   "\000\\\000d\000+\000\000",
           "\0003\0001\377\020\377\031\377\032\000\000");

  r = exec(ONIG_ENCODING_GB18030, ONIG_OPTION_IGNORECASE,
	   "(Aa\\d)+", "BaA5Aa0234");

  r = exec_deluxe(ONIG_ENCODING_ISO_8859_1, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_NONE,
		  "^\\P{Hiragana}\\p{^Hiragana}(\\p{Hiragana}+)$",
		  "\060\100\060\240\060\101\060\102\060\226\060\237\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\000[\000\337\000]\000\000", "\000S\000S\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\000[\000\337\000]\000\000", "\000s\000S\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\000^\000[\000\001\000-\377\375\000]\000$\000\000",
		  "\000s\000S\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\000S\000S\000\000",
		  "\000S\000T\000\337\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\000S\000T\000S\000S\000\000",
		  "\000S\000t\000s\000S\000\000");

  {
    UChar pat[]  = { 0x1f, 0xfc, 0x00, 0x00 };
    UChar str1[] = { 0x21, 0x26, 0x1f, 0xbe, 0x00, 0x00 };
    UChar str2[] = { 0x1f, 0xf3, 0x00, 0x00 };

    r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
		    ONIG_OPTION_IGNORECASE,
		    (char* )pat, (char* )str1);

    r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
		    ONIG_OPTION_IGNORECASE,
		    (char* )pat, (char* )str2);
  }

#if 0
  /* You should define USE_UNICODE_CASE_FOLD_TURKISH_AZERI in regenc.h. */

  set_case_fold(ONIGENC_CASE_FOLD_TURKISH_AZERI);

  r = exec_deluxe(ONIG_ENCODING_UTF8, ONIG_ENCODING_UTF8,
                  ONIG_OPTION_IGNORECASE,
		  "Ii", "\304\261\304\260");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\000I\000i\000\000", "\001\061\001\060\000\000");

  r = exec_deluxe(ONIG_ENCODING_UTF16_BE, ONIG_ENCODING_UTF16_BE,
                  ONIG_OPTION_IGNORECASE,
		  "\001\061\001\060\000\000", "\000I\000i\000\000");

  set_case_fold(ONIGENC_CASE_FOLD_MIN);
#endif

  return 0;
}
