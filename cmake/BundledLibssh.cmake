# Build the bundled libssh (0.9.5).
#
# libssh is built through ExternalProject rather than add_subdirectory on
# purpose. Its CMakeLists.txt writes into ${CMAKE_SOURCE_DIR} (ABI symbol
# files, a compile_commands.json symlink), so as a plain subdirectory it would
# scribble into the WindTerm source root. ExternalProject gives it its own
# CMAKE_SOURCE_DIR and keeps that to src/libssh.
#
# It also declares cmake_minimum_required(VERSION 3.3.0), which CMake 4 refuses
# outright; CMAKE_POLICY_VERSION_MINIMUM is the supported escape hatch.

include(ExternalProject)

set(WINDTERM_LIBSSH_STAGE "${CMAKE_CURRENT_BINARY_DIR}/libssh-install")

find_package(OpenSSL REQUIRED)

# libssh looks for OpenSSL itself; point it at the same one we resolved so a
# Homebrew keg-only OpenSSL is not silently swapped for the system LibreSSL.
get_filename_component(WINDTERM_OPENSSL_ROOT "${OPENSSL_INCLUDE_DIR}" DIRECTORY)

set(WINDTERM_LIBSSH_CMAKE_ARGS
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5
	-DCMAKE_BUILD_TYPE=$<CONFIG>
	-DCMAKE_INSTALL_PREFIX=${WINDTERM_LIBSSH_STAGE}
	-DCMAKE_INSTALL_LIBDIR=lib
	-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
	-DCMAKE_C_STANDARD=99
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON
	-DOPENSSL_ROOT_DIR=${WINDTERM_OPENSSL_ROOT}
	-DBUILD_SHARED_LIBS=${WINDTERM_BUILD_SHARED}
	-DWITH_EXAMPLES=OFF
	-DWITH_NACL=OFF
	-DWITH_INTERNAL_DOC=OFF
	-DWITH_BENCHMARKS=OFF
	-DUNIT_TESTING=OFF
	-DCLIENT_TESTING=OFF
	-DSERVER_TESTING=OFF
	-DWITH_SFTP=ON
	-DWITH_ZLIB=ON
	-DWITH_PCAP=ON
	-DWITH_GEX=ON
)

if(APPLE)
	list(APPEND WINDTERM_LIBSSH_CMAKE_ARGS
		-DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
		-DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}
		-DCMAKE_MACOSX_RPATH=ON
		-DCMAKE_INSTALL_NAME_DIR=@rpath
	)
	# GSSAPI on macOS resolves to the Heimdal shim in the SDK, whose headers are
	# not always present. Leave it opt-in instead of failing the build.
	option(WINDTERM_LIBSSH_GSSAPI "Build libssh with GSSAPI support" OFF)
else()
	option(WINDTERM_LIBSSH_GSSAPI "Build libssh with GSSAPI support" ON)
endif()

list(APPEND WINDTERM_LIBSSH_CMAKE_ARGS -DWITH_GSSAPI=${WINDTERM_LIBSSH_GSSAPI})

ExternalProject_Add(bundled_libssh
	SOURCE_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/src/libssh"
	BINARY_DIR       "${CMAKE_CURRENT_BINARY_DIR}/libssh-build"
	INSTALL_DIR      "${WINDTERM_LIBSSH_STAGE}"
	CMAKE_ARGS       ${WINDTERM_LIBSSH_CMAKE_ARGS}
	BUILD_ALWAYS     OFF
	USES_TERMINAL_CONFIGURE ON
	USES_TERMINAL_BUILD     ON
)

# Fold the staged tree into the WindTerm install prefix so a single `cmake
# --install` (and therefore a single .pkg payload) carries libssh too.
install(DIRECTORY "${WINDTERM_LIBSSH_STAGE}/lib/"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	USE_SOURCE_PERMISSIONS
)
install(DIRECTORY "${WINDTERM_LIBSSH_STAGE}/include/"
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
