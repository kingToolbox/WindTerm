# Small utility library: AES helpers on top of OpenSSL, thread-local storage.

find_package(OpenSSL REQUIRED)

# CMake 4 removed the bundled FindBoost; Boost ships its own config package.
if(POLICY CMP0167)
	cmake_policy(SET CMP0167 NEW)
endif()
find_package(Boost REQUIRED COMPONENTS thread)

# QPasswordDigestor is part of QtCore in Qt 5 and of QtNetwork in Qt 6.
if(WINDTERM_QT_VERSION_MAJOR GREATER_EQUAL 6)
	find_package(Qt6 REQUIRED COMPONENTS Network)
	set(WINDTERM_UTILITY_QT_EXTRA Qt6::Network)
endif()

add_library(windterm_utility
	Cryptographic.cpp
	ThreadLocal.cpp
	CircularBuffer.h
	Cryptographic.h
	MemoryPointer.h
	ScopeGuard.h
	Spin.h
	ThreadLocal.h
)
add_library(WindTerm::utility ALIAS windterm_utility)

target_link_libraries(windterm_utility
	PUBLIC
		Qt${WINDTERM_QT_VERSION_MAJOR}::Core
		${WINDTERM_UTILITY_QT_EXTRA}
		Boost::thread
	PRIVATE
		OpenSSL::Crypto
)

target_include_directories(windterm_utility
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/windterm/Utility>
)

set_target_properties(windterm_utility PROPERTIES
	# Keeps the exported name aligned with the in-tree alias, so consumers
	# write WindTerm::utility in both cases.
	EXPORT_NAME "utility"
	OUTPUT_NAME "windterm-utility"
	VERSION     "${PROJECT_VERSION}"
	SOVERSION   "${PROJECT_VERSION_MAJOR}"
	CXX_VISIBILITY_PRESET hidden
)

install(TARGETS windterm_utility
	EXPORT WindTermTargets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES
	CircularBuffer.h Cryptographic.h MemoryPointer.h ScopeGuard.h Spin.h ThreadLocal.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/Utility"
)
