#
#  Copyright (c) 2018 Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

#.rst:
# GetFilesList
# ------------
#
# This is a helper script for FindABImap.cmake.
#
# Search in the provided directories for files matching the provided pattern.
# The list of files is then written to the output file.
#
# Expected defined variables
# --------------------------
#
# ``DIRECTORIES``:
#   Required, expects a list of directories paths.
#
# ``FILES_PATTERNS``:
#   Required, expects a list of patterns to be used to search files
#
# ``OUTPUT_PATH``:
#   Required, expects the output file path.

if (NOT DEFINED DIRECTORIES)
    message(SEND_ERROR "DIRECTORIES not defined")
endif()

if (NOT DEFINED FILES_PATTERNS)
    message(SEND_ERROR "FILES_PATTERNS not defined")
endif()

if (NOT DEFINED OUTPUT_PATH)
    message(SEND_ERROR "OUTPUT_PATH not defined")
endif()

string(REPLACE " " ";" DIRECTORIES_LIST "${DIRECTORIES}")
string(REPLACE " " ";" FILES_PATTERNS_LIST "${FILES_PATTERNS}")

# Create the list of expressions for the files
set(glob_expressions)
foreach(dir ${DIRECTORIES_LIST})
    foreach(exp ${FILES_PATTERNS_LIST})
        list(APPEND glob_expressions
          "${dir}/${exp}"
        )
    endforeach()
endforeach()

# Create the list of files
file(GLOB files ${glob_expressions})

# Write to the output
file(WRITE ${OUTPUT_PATH} "${files}")
