# - Try to find NSIS
# Once done this will define
#
#  NSIS_ROOT_PATH - Set this variable to the root installation of NSIS
#
# Read-Only variables:
#
#  NSIS_FOUND - system has NSIS
#  NSIS_MAKE - NSIS creator executable
#
#=============================================================================
#  Copyright (c) 2010-2013 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

if (WIN32)
    set(_x86 "(x86)")

    set(_NSIS_ROOT_PATHS
        "$ENV{ProgramFiles}/NSIS"
        "$ENV{ProgramFiles${_x86}}/NSIS"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\NSIS;Default]")

    find_path(NSIS_ROOT_PATH
        NAMES
            Include/Library.nsh
        PATHS
            ${_NSIS_ROOT_PATHS}
        )
    mark_as_advanced(NSIS_ROOT_PATH)
endif (WIN32)

find_program(NSIS_MAKE
    NAMES
        makensis
    PATHS
        ${NSIS_ROOT_PATH}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NSIS DEFAULT_MSG NSIS_MAKE)

if (NSIS_MAKE)
    set(NSIS_FOUND TRUE)
endif (NSIS_MAKE)

mark_as_advanced(NSIS_MAKE)
