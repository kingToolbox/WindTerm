# Protocol implementations (Telnet).

add_library(windterm_protocols
	TelnetProtocol.cpp
	Protocol.h
	TelnetProtocol.h
)
add_library(WindTerm::protocols ALIAS windterm_protocols)

target_link_libraries(windterm_protocols PUBLIC Qt${WINDTERM_QT_VERSION_MAJOR}::Core)

target_include_directories(windterm_protocols
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/windterm/Protocols>
)

set_target_properties(windterm_protocols PROPERTIES
	# Keeps the exported name aligned with the in-tree alias, so consumers
	# write WindTerm::protocols in both cases.
	EXPORT_NAME "protocols"
	OUTPUT_NAME "windterm-protocols"
	VERSION     "${PROJECT_VERSION}"
	SOVERSION   "${PROJECT_VERSION_MAJOR}"
	CXX_VISIBILITY_PRESET hidden
)

install(TARGETS windterm_protocols
	EXPORT WindTermTargets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES Protocol.h TelnetProtocol.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/Protocols"
)
