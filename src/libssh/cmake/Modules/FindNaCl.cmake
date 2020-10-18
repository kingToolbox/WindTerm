# - Try to find NaCl
# Once done this will define
#
#  NACL_FOUND - system has NaCl
#  NACL_INCLUDE_DIRS - the NaCl include directory
#  NACL_LIBRARIES - Link these to use NaCl
#  NACL_DEFINITIONS - Compiler switches required for using NaCl
#
#  Copyright (c) 2010 Andreas Schneider <asn@cryptomilk.org>
#  Copyright (c) 2013 Aris Adamantiadis <aris@badcode.be>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (NACL_LIBRARIES AND NACL_INCLUDE_DIRS)
  # in cache already
  set(NACL_FOUND TRUE)
else (NACL_LIBRARIES AND NACL_INCLUDE_DIRS)

  find_path(NACL_INCLUDE_DIR
    NAMES
      nacl/crypto_box_curve25519xsalsa20poly1305.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

  find_library(NACL_LIBRARY
    NAMES
      nacl
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(NACL_INCLUDE_DIRS
    ${NACL_INCLUDE_DIR}
  )

  if (NACL_LIBRARY)
    set(NACL_LIBRARIES
        ${NACL_LIBRARIES}
        ${NACL_LIBRARY}
    )
  endif (NACL_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(NaCl DEFAULT_MSG NACL_LIBRARIES NACL_INCLUDE_DIRS)

  # show the NACL_INCLUDE_DIRS and NACL_LIBRARIES variables only in the advanced view
  mark_as_advanced(NACL_INCLUDE_DIRS NACL_LIBRARIES)

endif (NACL_LIBRARIES AND NACL_INCLUDE_DIRS)

