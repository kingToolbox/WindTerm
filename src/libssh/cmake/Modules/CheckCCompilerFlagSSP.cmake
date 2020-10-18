# - Check whether the C compiler supports a given flag in the
# context of a stack checking compiler option.

# CHECK_C_COMPILER_FLAG_SSP(FLAG VARIABLE)
#
#  FLAG - the compiler flag
#  VARIABLE - variable to store the result
#
#  This actually calls check_c_source_compiles.
#  See help for CheckCSourceCompiles for a listing of variables
#  that can modify the build.

# Copyright (c) 2006, Alexander Neundorf, <neundorf@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

# Requires cmake 3.10
#include_guard(GLOBAL)
include(CheckCSourceCompiles)

macro(CHECK_C_COMPILER_FLAG_SSP _FLAG _RESULT)
   set(SAFE_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
   set(CMAKE_REQUIRED_FLAGS "${_FLAG}")

   check_c_source_compiles("int main(int argc, char **argv) { char buffer[256]; return buffer[argc]=0;}" ${_RESULT})

   set(CMAKE_REQUIRED_FLAGS "${SAFE_CMAKE_REQUIRED_FLAGS}")
endmacro(CHECK_C_COMPILER_FLAG_SSP)
