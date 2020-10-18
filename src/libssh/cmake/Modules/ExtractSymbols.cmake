#
#  Copyright (c) 2018 Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

#.rst:
# ExtractSymbols
# --------------
#
# This is a helper script for FindABImap.cmake.
#
# Extract symbols from header files and output a list to a file.
# This script is run in build time to extract symbols from the provided header
# files. This way, symbols added or removed can be checked and used to update
# the symbol version script.
#
# All symbols followed by the character ``'('`` are extracted. If a
# ``FILTER_PATTERN`` is provided, only the lines containing the given string are
# considered.
#
# Expected defined variables
# --------------------------
#
# ``HEADERS_LIST_FILE``:
#   Required, expects a file containing the list of header files to be parsed.
#
# ``OUTPUT_PATH``:
#   Required, expects the output file path.
#
# Optionally defined variables
# ----------------------------
#
# ``FILTER_PATTERN``:
#   Expects a string. Only lines containing the given string will be considered
#   when extracting symbols.
#

if (NOT DEFINED OUTPUT_PATH)
    message(SEND_ERROR "OUTPUT_PATH not defined")
endif()

if (NOT DEFINED HEADERS_LIST_FILE)
    message(SEND_ERROR "HEADERS not defined")
endif()

file(READ ${HEADERS_LIST_FILE} HEADERS_LIST)

set(symbols)
foreach(header ${HEADERS_LIST})

    # Filter only lines containing the FILTER_PATTERN
    file(STRINGS ${header} contain_filter
      REGEX "^.*${FILTER_PATTERN}.*[(]"
    )

    # Remove function-like macros
    foreach(line ${contain_filter})
        if (NOT ${line} MATCHES ".*#[ ]*define")
            list(APPEND not_macro ${line})
        endif()
    endforeach()

    set(functions)

    # Get only the function names followed by '('
    foreach(line ${not_macro})
        string(REGEX MATCHALL "[a-zA-Z0-9_]+[ ]*[(]" func ${line})
        list(APPEND functions ${func})
    endforeach()

    set(extracted_symbols)

    # Remove '('
    foreach(line ${functions})
        string(REGEX REPLACE "[(]" "" symbol ${line})
        string(STRIP "${symbol}" symbol)
        list(APPEND extracted_symbols ${symbol})
    endforeach()

    list(APPEND symbols ${extracted_symbols})
endforeach()

list(REMOVE_DUPLICATES symbols)

list(SORT symbols)

string(REPLACE ";" "\n" symbols_list "${symbols}")

file(WRITE ${OUTPUT_PATH} "${symbols_list}")
