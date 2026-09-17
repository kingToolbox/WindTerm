# Copyright 2025, WindTerm.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build system for the open source part of WindTerm.
#
# This repository is a *partial* open source release: it ships the reusable
# libraries (regex engine, ssh, pty, protocols, widgets) but not the WindTerm
# application itself. What this file produces is therefore an SDK - a set of
# libraries and headers - and not WindTerm.app.

cmake_minimum_required(VERSION 3.21)

# CMAKE_OSX_ARCHITECTURES has to be decided before project(), otherwise the
# compiler feature checks are run against the host ABI instead of the target
# one and a cross/universal build silently picks up the wrong results.
if(APPLE OR CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
	set(WINDTERM_OSX_ARCHITECTURES "arm64" CACHE STRING
		"macOS target architectures: arm64 (Apple Silicon native), x86_64, or 'arm64;x86_64' for universal2")
	set(WINDTERM_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING
		"Minimum macOS version. arm64 requires 11.0 or later.")

	if(NOT DEFINED CMAKE_OSX_ARCHITECTURES OR CMAKE_OSX_ARCHITECTURES STREQUAL "")
		set(CMAKE_OSX_ARCHITECTURES "${WINDTERM_OSX_ARCHITECTURES}" CACHE STRING "" FORCE)
	endif()
	if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET OR CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL "")
		set(CMAKE_OSX_DEPLOYMENT_TARGET "${WINDTERM_OSX_DEPLOYMENT_TARGET}" CACHE STRING "" FORCE)
	endif()
endif()

project(WindTerm
	VERSION 2.7.0
	DESCRIPTION "WindTerm open source libraries"
	HOMEPAGE_URL "https://github.com/kingToolbox/WindTerm"
	LANGUAGES C CXX
)

if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS 11.0
   AND "arm64" IN_LIST CMAKE_OSX_ARCHITECTURES)
	message(FATAL_ERROR
		"CMAKE_OSX_DEPLOYMENT_TARGET is ${CMAKE_OSX_DEPLOYMENT_TARGET} but arm64 requires 11.0 or later.")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(WINDTERM_BUILD_SHARED  "Build the WindTerm libraries as shared libraries" OFF)
option(WINDTERM_WITH_LIBSSH   "Build the bundled libssh"                         ON)
option(WINDTERM_WITH_ONIGMO   "Build the bundled Onigmo regex engine"            ON)
option(WINDTERM_WITH_QT       "Build the Qt based libraries (Pty, Protocols, Utility, Widgets)" ON)
option(WINDTERM_WITH_WIDGETS  "Build the Qt Widgets library"                     ON)
option(WINDTERM_WITH_UTILITY  "Build the Utility library (needs OpenSSL and Boost)" ON)

set(BUILD_SHARED_LIBS ${WINDTERM_BUILD_SHARED})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

if(APPLE)
	# Let installed shared libraries find their siblings next to them, and keep
	# the build tree usable without DYLD_LIBRARY_PATH.
	set(CMAKE_MACOSX_RPATH ON)
	set(CMAKE_INSTALL_RPATH "@loader_path;@loader_path/../${CMAKE_INSTALL_LIBDIR}")
	set(CMAKE_BUILD_WITH_INSTALL_NAME_DIR ON)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------

set(WINDTERM_EXPORTED_TARGETS "")

if(WINDTERM_WITH_ONIGMO)
	add_subdirectory(src/Onigmo)
	list(APPEND WINDTERM_EXPORTED_TARGETS onigmo)
endif()

if(WINDTERM_WITH_LIBSSH)
	include(BundledLibssh)
endif()

if(WINDTERM_WITH_QT)
	find_package(Qt6 6.2 COMPONENTS Core QUIET)

	if(Qt6_FOUND)
		set(WINDTERM_QT_VERSION_MAJOR 6)
	else()
		find_package(Qt5 5.15 COMPONENTS Core QUIET)
		if(Qt5_FOUND)
			set(WINDTERM_QT_VERSION_MAJOR 5)
		endif()
	endif()

	if(NOT WINDTERM_QT_VERSION_MAJOR)
		message(FATAL_ERROR
			"WINDTERM_WITH_QT is ON but neither Qt6 (>= 6.2) nor Qt5 (>= 5.15) was found.\n"
			"Install Qt (brew install qt) or configure with -DWINDTERM_WITH_QT=OFF.")
	endif()

	message(STATUS "WindTerm: building against Qt${WINDTERM_QT_VERSION_MAJOR}")

	set(CMAKE_AUTOMOC ON)

	add_subdirectory(src/Protocols)
	add_subdirectory(src/Pty)
	list(APPEND WINDTERM_EXPORTED_TARGETS windterm_protocols windterm_pty)

	if(WINDTERM_WITH_UTILITY)
		add_subdirectory(src/Utility)
		list(APPEND WINDTERM_EXPORTED_TARGETS windterm_utility)
	endif()

	if(WINDTERM_WITH_WIDGETS)
		add_subdirectory(src/Widgets)
		list(APPEND WINDTERM_EXPORTED_TARGETS windterm_widgets)
	endif()
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------

if(WINDTERM_EXPORTED_TARGETS)
	install(EXPORT WindTermTargets
		FILE WindTermTargets.cmake
		NAMESPACE WindTerm::
		DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/WindTerm"
	)
endif()

# Recorded in WindTermConfig.cmake so consumers only look for the
# dependencies of the parts that were actually built.
set(WINDTERM_HAS_UTILITY 0)
set(WINDTERM_HAS_WIDGETS 0)
if(TARGET windterm_utility)
	set(WINDTERM_HAS_UTILITY 1)
endif()
if(TARGET windterm_widgets)
	set(WINDTERM_HAS_WIDGETS 1)
endif()

configure_package_config_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/WindTermConfig.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/WindTermConfig.cmake"
	INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/WindTerm"
)

write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/WindTermConfigVersion.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY SameMajorVersion
)

if(WINDTERM_EXPORTED_TARGETS)
	install(FILES
		"${CMAKE_CURRENT_BINARY_DIR}/WindTermConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/WindTermConfigVersion.cmake"
		DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/WindTerm"
	)
endif()

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/LICENSE"
	DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/WindTerm"
)

message(STATUS "WindTerm ${PROJECT_VERSION}")
if(APPLE)
	message(STATUS "  architectures     : ${CMAKE_OSX_ARCHITECTURES}")
	message(STATUS "  deployment target : ${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()
message(STATUS "  shared libraries  : ${WINDTERM_BUILD_SHARED}")
message(STATUS "  targets           : ${WINDTERM_EXPORTED_TARGETS}")
