# - Try to find GSSAPI
# Once done this will define
#
#  KRB5_CONFIG - Path to krb5-config
#  GSSAPI_ROOT_DIR - Set this variable to the root installation of GSSAPI
#
# Read-Only variables:
#  GSSAPI_FLAVOR_MIT - set to TURE if MIT Kerberos has been found
#  GSSAPI_FLAVOR_HEIMDAL - set to TRUE if Heimdal Keberos has been found
#  GSSAPI_FOUND - system has GSSAPI
#  GSSAPI_INCLUDE_DIR - the GSSAPI include directory
#  GSSAPI_LIBRARIES - Link these to use GSSAPI
#  GSSAPI_DEFINITIONS - Compiler switches required for using GSSAPI
#
#=============================================================================
#  Copyright (c) 2013 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

find_path(GSSAPI_ROOT_DIR
    NAMES
        include/gssapi.h
        include/gssapi/gssapi.h
    HINTS
        ${_GSSAPI_ROOT_HINTS}
    PATHS
        ${_GSSAPI_ROOT_PATHS}
)
mark_as_advanced(GSSAPI_ROOT_DIR)

if (UNIX)
    find_program(KRB5_CONFIG
        NAMES
            krb5-config
        PATHS
            ${GSSAPI_ROOT_DIR}/bin
            /opt/local/bin)
    mark_as_advanced(KRB5_CONFIG)

    if (KRB5_CONFIG)
        # Check if we have MIT KRB5
        execute_process(
            COMMAND
                ${KRB5_CONFIG} --vendor
            RESULT_VARIABLE
                _GSSAPI_VENDOR_RESULT
            OUTPUT_VARIABLE
                _GSSAPI_VENDOR_STRING)

        if ((_GSSAPI_VENDOR_STRING MATCHES ".*Massachusetts.*") OR (_GSSAPI_VENDOR_STRING
                        MATCHES ".*MITKerberosShim.*"))
            set(GSSAPI_FLAVOR_MIT TRUE)
        else()
            execute_process(
                COMMAND
                    ${KRB5_CONFIG} --libs gssapi
                RESULT_VARIABLE
                    _GSSAPI_LIBS_RESULT
                OUTPUT_VARIABLE
                    _GSSAPI_LIBS_STRING)

            if (_GSSAPI_LIBS_STRING MATCHES ".*roken.*")
                set(GSSAPI_FLAVOR_HEIMDAL TRUE)
            endif()
        endif()

        # Get the include dir
        execute_process(
            COMMAND
                ${KRB5_CONFIG} --cflags gssapi
            RESULT_VARIABLE
                _GSSAPI_INCLUDE_RESULT
            OUTPUT_VARIABLE
                _GSSAPI_INCLUDE_STRING)
        string(REGEX REPLACE "(\r?\n)+$" "" _GSSAPI_INCLUDE_STRING "${_GSSAPI_INCLUDE_STRING}")
        string(REGEX REPLACE " *-I" "" _GSSAPI_INCLUDEDIR "${_GSSAPI_INCLUDE_STRING}")
    endif()

    if (NOT GSSAPI_FLAVOR_MIT AND NOT GSSAPI_FLAVOR_HEIMDAL)
        # Check for HEIMDAL
        find_package(PkgConfig)
        if (PKG_CONFIG_FOUND)
            pkg_check_modules(_GSSAPI heimdal-gssapi)
        endif (PKG_CONFIG_FOUND)

        if (_GSSAPI_FOUND)
            set(GSSAPI_FLAVOR_HEIMDAL TRUE)
        else()
            find_path(_GSSAPI_ROKEN
                NAMES
                    roken.h
                PATHS
                    ${GSSAPI_ROOT_DIR}/include
                    ${_GSSAPI_INCLUDEDIR})
            if (_GSSAPI_ROKEN)
                set(GSSAPI_FLAVOR_HEIMDAL TRUE)
            endif()
        endif ()
    endif()
endif (UNIX)

find_path(GSSAPI_INCLUDE_DIR
    NAMES
        gssapi.h
        gssapi/gssapi.h
    PATHS
        ${GSSAPI_ROOT_DIR}/include
        ${_GSSAPI_INCLUDEDIR}
)

if (GSSAPI_FLAVOR_MIT)
    find_library(GSSAPI_LIBRARY
        NAMES
            gssapi_krb5
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(KRB5_LIBRARY
        NAMES
            krb5
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(K5CRYPTO_LIBRARY
        NAMES
            k5crypto
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(COM_ERR_LIBRARY
        NAMES
            com_err
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    if (GSSAPI_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${GSSAPI_LIBRARY}
        )
    endif (GSSAPI_LIBRARY)

    if (KRB5_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${KRB5_LIBRARY}
        )
    endif (KRB5_LIBRARY)

    if (K5CRYPTO_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${K5CRYPTO_LIBRARY}
        )
    endif (K5CRYPTO_LIBRARY)

    if (COM_ERR_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${COM_ERR_LIBRARY}
        )
    endif (COM_ERR_LIBRARY)
endif (GSSAPI_FLAVOR_MIT)

if (GSSAPI_FLAVOR_HEIMDAL)
    find_library(GSSAPI_LIBRARY
        NAMES
            gssapi
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(KRB5_LIBRARY
        NAMES
            krb5
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(HCRYPTO_LIBRARY
        NAMES
            hcrypto
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(COM_ERR_LIBRARY
        NAMES
            com_err
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(HEIMNTLM_LIBRARY
        NAMES
            heimntlm
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(HX509_LIBRARY
        NAMES
            hx509
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(ASN1_LIBRARY
        NAMES
            asn1
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(WIND_LIBRARY
        NAMES
            wind
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    find_library(ROKEN_LIBRARY
        NAMES
            roken
        PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBDIR}
    )

    if (GSSAPI_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${GSSAPI_LIBRARY}
        )
    endif (GSSAPI_LIBRARY)

    if (KRB5_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${KRB5_LIBRARY}
        )
    endif (KRB5_LIBRARY)

    if (HCRYPTO_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${HCRYPTO_LIBRARY}
        )
    endif (HCRYPTO_LIBRARY)

    if (COM_ERR_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${COM_ERR_LIBRARY}
        )
    endif (COM_ERR_LIBRARY)

    if (HEIMNTLM_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${HEIMNTLM_LIBRARY}
        )
    endif (HEIMNTLM_LIBRARY)

    if (HX509_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${HX509_LIBRARY}
        )
    endif (HX509_LIBRARY)

    if (ASN1_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${ASN1_LIBRARY}
        )
    endif (ASN1_LIBRARY)

    if (WIND_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${WIND_LIBRARY}
        )
    endif (WIND_LIBRARY)

    if (ROKEN_LIBRARY)
        set(GSSAPI_LIBRARIES
            ${GSSAPI_LIBRARIES}
            ${WIND_LIBRARY}
        )
    endif (ROKEN_LIBRARY)
endif (GSSAPI_FLAVOR_HEIMDAL)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GSSAPI DEFAULT_MSG GSSAPI_LIBRARIES GSSAPI_INCLUDE_DIR)

if (GSSAPI_INCLUDE_DIRS AND GSSAPI_LIBRARIES)
    set(GSSAPI_FOUND TRUE)
endif (GSSAPI_INCLUDE_DIRS AND GSSAPI_LIBRARIES)

# show the GSSAPI_INCLUDE_DIRS and GSSAPI_LIBRARIES variables only in the advanced view
mark_as_advanced(GSSAPI_INCLUDE_DIRS GSSAPI_LIBRARIES)
