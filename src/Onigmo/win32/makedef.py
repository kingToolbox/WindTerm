#!/usr/bin/env python

from __future__ import print_function
import re

header_files = (
    "oniguruma.h", "regenc.h",
    "oniggnu.h", "onigposix.h"
)

exclude_symbols = (
    "OnigEncodingKOI8",

    # USE_UPPER_CASE_TABLE
    "OnigEncAsciiToUpperCaseTable",
    "OnigEncISO_8859_1_ToUpperCaseTable",

    # USE_RECOMPILE_API
    "onig_recompile",
    "onig_recompile_deluxe",
    "re_recompile_pattern",

    # USE_VARIABLE_META_CHARS
    #"onig_set_meta_char",

    # USE_CAPTURE_HISTORY
    #"onig_get_capture_tree",
)

symbols = set()

rx1 = re.compile("(ONIG_EXTERN.*)$")
rx2 = re.compile(r"(\w+)( +PV?_\(\(.*\)\)|\[.*\])?;\s*(/\*.*\*/)?$")
for filename in header_files:
    with open(filename, "r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            m = rx1.match(line)
            if not m:
                continue
            s = m.group(1)
            if s[-1] != ';':
                s += ' ' + f.readline()
            m2 = rx2.search(s)
            if m2 and (not m2.group(1) in exclude_symbols):
                symbols.add(m2.group(1))

print('EXPORTS')
for s in sorted(symbols):
    print('\t' + s)
