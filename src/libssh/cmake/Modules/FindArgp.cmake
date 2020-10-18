# - Try to find ARGP
# Once done this will define
#
#  ARGP_ROOT_DIR - Set this variable to the root installation of ARGP
#
# Read-Only variables:
#  ARGP_FOUND - system has ARGP
#  ARGP_INCLUDE_DIR - the ARGP include directory
#  ARGP_LIBRARIES - Link these to use ARGP
#  ARGP_DEFINITIONS - Compiler switches required for using ARGP
#
#=============================================================================
#  Copyright (c) 2011-2016 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

set(_ARGP_ROOT_HINTS
)

set(_ARGP_ROOT_PATHS
    "$ENV{PROGRAMFILES}/argp"
)

find_path(ARGP_ROOT_DIR
    NAMES
        include/argp.h
    HINTS
        ${_ARGP_ROOT_HINTS}
    PATHS
        ${_ARGP_ROOT_PATHS}
)
mark_as_advanced(ARGP_ROOT_DIR)

find_path(ARGP_INCLUDE_DIR
    NAMES
        argp.h
    PATHS
        ${ARGP_ROOT_DIR}/include
)

find_library(ARGP_LIBRARY
    NAMES
        argp
    PATHS
        ${ARGP_ROOT_DIR}/lib
)

if (ARGP_LIBRARY)
  set(ARGP_LIBRARIES
      ${ARGP_LIBRARIES}
      ${ARGP_LIBRARY}
  )
endif (ARGP_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ARGP DEFAULT_MSG ARGP_LIBRARIES ARGP_INCLUDE_DIR)

# show the ARGP_INCLUDE_DIR and ARGP_LIBRARIES variables only in the advanced view
mark_as_advanced(ARGP_INCLUDE_DIR ARGP_LIBRARIES)
