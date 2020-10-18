cmake_minimum_required(VERSION 3.3.0)
cmake_policy(SET CMP0048 NEW)

# Specify search path for CMake modules to be loaded by include() 
# and find_package()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

# Add defaults for cmake
# Those need to be set before the project() call.
include(DefineCMakeDefaults)
include(DefineCompilerFlags)

project(libssh VERSION 0.9.5 LANGUAGES C)

# global needed variable
set(APPLICATION_NAME ${PROJECT_NAME})

# SOVERSION scheme: CURRENT.AGE.REVISION
#   If there was an incompatible interface change:
#     Increment CURRENT. Set AGE and REVISION to 0
#   If there was a compatible interface change:
#     Increment AGE. Set REVISION to 0
#   If the source code was changed, but there were no interface changes:
#     Increment REVISION.
set(LIBRARY_VERSION "4.8.6")
set(LIBRARY_SOVERSION "4")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked

# add definitions
include(DefinePlatformDefaults)
include(DefineOptions.cmake)
include(CPackConfig.cmake)
include(GNUInstallDirs)

include(CompilerChecks.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# Copy library files to a lib sub-directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# search for libraries
if (WITH_ZLIB)
    find_package(ZLIB REQUIRED)
endif (WITH_ZLIB)

if (WITH_GCRYPT)
  find_package(GCrypt 1.5.0 REQUIRED)
  if (NOT GCRYPT_FOUND)
    message(FATAL_ERROR "Could not find GCrypt")
  endif (NOT GCRYPT_FOUND)
elseif(WITH_MBEDTLS)
    find_package(MbedTLS REQUIRED)
    if (NOT MBEDTLS_FOUND)
      message(FATAL_ERROR "Could not find mbedTLS")
    endif (NOT MBEDTLS_FOUND)
else (WITH_GCRYPT)
  find_package(OpenSSL)
  if (NOT OPENSSL_FOUND)
    find_package(GCrypt)
    if (NOT GCRYPT_FOUND)
      find_package(MbedTLS)
      if (NOT MBEDTLS_FOUND)
        message(FATAL_ERROR "Could not find OpenSSL, GCrypt or mbedTLS")
      endif (NOT MBEDTLS_FOUND)
    endif (NOT GCRYPT_FOUND)
  endif (NOT OPENSSL_FOUND)
endif(WITH_GCRYPT)

if (UNIT_TESTING)
    find_package(CMocka REQUIRED)
endif ()

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)

if (WITH_GSSAPI)
    find_package(GSSAPI)
endif (WITH_GSSAPI)

if (WITH_NACL)
    find_package(NaCl)
    if (NOT NACL_FOUND)
        set(WITH_NACL OFF)
    endif (NOT NACL_FOUND)
endif (WITH_NACL)

if (BSD OR SOLARIS OR OSX)
    find_package(Argp)
endif (BSD OR SOLARIS OR OSX)

# Disable symbol versioning in non UNIX platforms
if (UNIX)
    find_package(ABIMap 0.3.1)
else (UNIX)
    set(WITH_SYMBOL_VERSIONING OFF)
endif (UNIX)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(src)

# pkg-config file
if (UNIX)
configure_file(libssh.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/pkgconfig
  COMPONENT
    pkgconfig
)
endif (UNIX)

# CMake config files
include(CMakePackageConfigHelpers)

set(LIBSSH_LIBRARY_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}ssh${CMAKE_SHARED_LIBRARY_SUFFIX})

# libssh-config-version.cmake
write_basic_package_version_file(libssh-config-version.cmake
                                 VERSION ${PROJECT_VERSION}
                                 COMPATIBILITY SameMajorVersion)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
    DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    COMPONENT
        devel)

if (WITH_EXAMPLES)
    add_subdirectory(examples)
endif (WITH_EXAMPLES)

if (UNIT_TESTING)
    include(AddCMockaTest)
    add_subdirectory(tests)
endif (UNIT_TESTING)

### SOURCE PACKAGE
if (WITH_SYMBOL_VERSIONING AND ABIMAP_FOUND)
    # Get the current ABI version from source
    get_filename_component(current_abi_path
                           "${CMAKE_SOURCE_DIR}/src/ABI/current"
                           ABSOLUTE)

    # Check if the ABI version should be updated
    file(READ ${current_abi_path} CURRENT_ABI_CONTENT)
    string(STRIP "${CURRENT_ABI_CONTENT}" CURRENT_ABI_VERSION)

    if (LIBRARY_VERSION VERSION_GREATER CURRENT_ABI_VERSION)
        set(UPDATE_ABI TRUE)
    endif ()

    if (UPDATE_ABI)
        message(STATUS "Library version bumped to ${LIBRARY_VERSION}: Updating ABI")

        # Get the list of header files
        get_file_list(${PROJECT_NAME}_header_list
                      DIRECTORIES "${CMAKE_SOURCE_DIR}/include/libssh"
                      FILES_PATTERNS "*.h")

        # Extract the symbols marked as "LIBSSH_API" from the header files
        extract_symbols(${PROJECT_NAME}.symbols
                        HEADERS_LIST ${PROJECT_NAME}_header_list
                        FILTER_PATTERN "LIBSSH_API"
                        COPY_TO "${CMAKE_SOURCE_DIR}/src/ABI/${PROJECT_NAME}-${LIBRARY_VERSION}.symbols")

        if (WITH_ABI_BREAK)
            set(ALLOW_ABI_BREAK "BREAK_ABI")
        endif()

        # Target we can depend on in 'make dist'
        set(_SYMBOL_TARGET "${PROJECT_NAME}.map")

        # Set the path to the current map file
        set(MAP_PATH "${CMAKE_SOURCE_DIR}/src/${_SYMBOL_TARGET}")

        # Generate the symbol version map file
        generate_map_file(${_SYMBOL_TARGET}
                          SYMBOLS ${PROJECT_NAME}.symbols
                          RELEASE_NAME_VERSION ${PROJECT_NAME}_${LIBRARY_VERSION}
                          CURRENT_MAP ${MAP_PATH}
                          COPY_TO ${MAP_PATH}
                          FINAL
                          ${ALLOW_ABI_BREAK})

        # Write the current version to the source
        file(WRITE ${current_abi_path} ${LIBRARY_VERSION})
    endif(UPDATE_ABI)
endif (WITH_SYMBOL_VERSIONING AND ABIMAP_FOUND)

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source DEPENDS ${_SYMBOL_TARGET})

# Link compile database for clangd
execute_process(COMMAND cmake -E create_symlink
                "${CMAKE_BINARY_DIR}/compile_commands.json"
                "${CMAKE_SOURCE_DIR}/compile_commands.json")

message(STATUS "********************************************")
message(STATUS "********** ${PROJECT_NAME} build options : **********")

message(STATUS "zlib support: ${WITH_ZLIB}")
message(STATUS "libgcrypt support: ${WITH_GCRYPT}")
message(STATUS "libmbedTLS support: ${WITH_MBEDTLS}")
message(STATUS "libnacl support: ${WITH_NACL}")
message(STATUS "SFTP support: ${WITH_SFTP}")
message(STATUS "Server support : ${WITH_SERVER}")
message(STATUS "GSSAPI support : ${WITH_GSSAPI}")
message(STATUS "GEX support : ${WITH_GEX}")
message(STATUS "Pcap debugging support : ${WITH_PCAP}")
message(STATUS "Build shared library: ${BUILD_SHARED_LIBS}")
message(STATUS "Unit testing: ${UNIT_TESTING}")
message(STATUS "Client code testing: ${CLIENT_TESTING}")
message(STATUS "Blowfish cipher support: ${WITH_BLOWFISH_CIPHER}")
set(_SERVER_TESTING OFF)
if (WITH_SERVER)
    set(_SERVER_TESTING ${SERVER_TESTING})
endif()
message(STATUS "Server code testing: ${_SERVER_TESTING}")
if (WITH_INTERNAL_DOC)
    message(STATUS "Internal documentation generation")
else (WITH_INTERNAL_DOC)
    message(STATUS "Public API documentation generation")
endif (WITH_INTERNAL_DOC)
message(STATUS "Benchmarks: ${WITH_BENCHMARKS}")
message(STATUS "Symbol versioning: ${WITH_SYMBOL_VERSIONING}")
message(STATUS "Allow ABI break: ${WITH_ABI_BREAK}")
message(STATUS "Release is final: ${WITH_FINAL}")
message(STATUS "Global client config: ${GLOBAL_CLIENT_CONFIG}")
if (WITH_SERVER)
message(STATUS "Global bind config: ${GLOBAL_BIND_CONFIG}")
endif()
message(STATUS "********************************************")

