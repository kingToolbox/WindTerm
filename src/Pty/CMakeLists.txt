# Pseudo terminal backends.
#
# Only the platform's own backend is compiled: UnixPty on macOS and Linux,
# ConPty/WinPty on Windows. The files guard themselves with Q_OS_* too, but
# leaving the Windows sources out of the build keeps winpty off the dependency
# list on Unix.

set(WINDTERM_PTY_SOURCES
	Pty.cpp
	Pty.h
)

if(WIN32)
	list(APPEND WINDTERM_PTY_SOURCES ConPty.cpp ConPty.h WinPty.cpp WinPty.h)
else()
	list(APPEND WINDTERM_PTY_SOURCES UnixPty.cpp UnixPty.h)
endif()

add_library(windterm_pty ${WINDTERM_PTY_SOURCES})
add_library(WindTerm::pty ALIAS windterm_pty)

target_link_libraries(windterm_pty PUBLIC Qt${WINDTERM_QT_VERSION_MAJOR}::Core)

# Pty.h includes "Spin.h", which lives in Utility.
target_include_directories(windterm_pty
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../Utility>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/windterm/Pty>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/windterm/Utility>
)

set_target_properties(windterm_pty PROPERTIES
	# Keeps the exported name aligned with the in-tree alias, so consumers
	# write WindTerm::pty in both cases.
	EXPORT_NAME "pty"
	OUTPUT_NAME "windterm-pty"
	VERSION     "${PROJECT_VERSION}"
	SOVERSION   "${PROJECT_VERSION_MAJOR}"
	CXX_VISIBILITY_PRESET hidden
)

install(TARGETS windterm_pty
	EXPORT WindTermTargets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES Pty.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/Pty"
)

if(WIN32)
	install(FILES ConPty.h WinPty.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/Pty")
else()
	install(FILES UnixPty.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/Pty")
endif()
