# Reusable Qt widgets.

find_package(Qt${WINDTERM_QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

add_library(windterm_widgets
	PopupWidget.cpp
	ScrollBar.cpp
	Splitter.cpp
	PopupWidget.h
	ScrollBar.h
	Splitter.h
)
add_library(WindTerm::widgets ALIAS windterm_widgets)

target_link_libraries(windterm_widgets PUBLIC Qt${WINDTERM_QT_VERSION_MAJOR}::Widgets)

target_include_directories(windterm_widgets
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/windterm/Widgets>
)

set_target_properties(windterm_widgets PROPERTIES
	# Keeps the exported name aligned with the in-tree alias, so consumers
	# write WindTerm::widgets in both cases.
	EXPORT_NAME "widgets"
	OUTPUT_NAME "windterm-widgets"
	VERSION     "${PROJECT_VERSION}"
	SOVERSION   "${PROJECT_VERSION_MAJOR}"
	CXX_VISIBILITY_PRESET hidden
)

install(TARGETS windterm_widgets
	EXPORT WindTermTargets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES PopupWidget.h ScrollBar.h Splitter.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/Widgets"
)
