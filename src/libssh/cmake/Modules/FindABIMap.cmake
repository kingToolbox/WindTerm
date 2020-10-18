#
#  Copyright (c) 2018 Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

#.rst:
# FindABIMap
# ----------
#
# This file provides functions to generate the symbol version script. It uses
# the ``abimap`` tool to generate and update the linker script file. It can be
# installed by calling::
#
#   $ pip install abimap
#
# The ``function generate_map_file`` generates a symbol version script
# containing the provided symbols. It defines a custom command which sets
# ``target_name`` as its ``OUTPUT``.
#
# The experimental function ``extract_symbols()`` is provided as a simple
# parser to extract the symbols from C header files. It simply extracts symbols
# followed by an opening '``(``'. It is recommended to use a filter pattern to
# select the lines to be considered. It defines a custom command which sets
# ``target_name`` as its output.
#
# The helper function ``get_files_list()`` is provided to find files given a
# name pattern. It defines a custom command which sets ``target_name`` as its
# output.
#
# Functions provided
# ------------------
#
# ::
#
#   generate_map_file(target_name
#                     RELEASE_NAME_VERSION release_name
#                     SYMBOLS symbols_target
#                     [CURRENT_MAP cur_map]
#                     [FINAL]
#                     [BREAK_ABI]
#                     [COPY_TO output]
#                    )
#
# ``target_name``:
#   Required, expects the name of the file to receive the generated symbol
#   version script. It should be added as a dependency for the library. Use the
#   linker option ``--version-script filename`` to add the version information
#   to the symbols when building the library.
#
# ``RELEASE_NAME_VERSION``:
#   Required, expects a string containing the name and version information to be
#   added to the symbols in the format ``lib_name_1_2_3``.
#
# ``SYMBOLS``:
#   Required, expects a target with the property ``LIST_FILE`` containing a path
#   to a file containing the list of symbols to be added to the symbol version
#   script.
#
# ``CURRENT_MAP``:
#   Optional. If given, the new set of symbols will be checked against the
#   ones contained in the ``cur_map`` file and updated properly. If an
#   incompatible change is detected and ``BREAK_ABI`` is not defined, the build
#   will fail.
#
# ``FINAL``:
#   Optional. If given, will provide the ``--final`` option to ``abimap`` tool,
#   which will mark the modified release in the symbol version script with a
#   special comment, preventing later changes. This option should be set when
#   creating a library release and the resulting map file should be stored with
#   the source code.
#
# ``BREAK_ABI``:
#   Optional. If provided, will use ``abimap`` ``--allow-abi-break`` option, which
#   accepts incompatible changes to the set of symbols. This is necessary if any
#   previously existing symbol were removed.
#
# ``COPY_TO``:
#   Optional, expects a string containing the path to where the generated
#   map file will be copied.
#
# Example:
#
# .. code-block:: cmake
#
#   find_package(ABIMap)
#   generate_map_file("lib.map"
#                     RELEASE_NAME_VERSION "lib_1_0_0"
#                     SYMBOLS symbols
#                    )
#
# Where the target ``symbols`` has its property ``LIST_FILE`` set to the path to
# a file containing::
#
#  ``symbol1``
#  ``symbol2``
#
# This example would result in the symbol version script to be created in
# ``${CMAKE_CURRENT_BINARY_DIR}/lib.map`` containing the provided symbols.
#
# ::
#
#   get_files_list(target_name
#                   DIRECTORIES dir1 [dir2 ...]
#                   FILES_PATTERNS exp1 [exp2 ...]
#                   [COPY_TO output]
#                  )
#
# ``target_name``:
#   Required, expects the name of the target to be created. A file named as
#   ``${target_name}.list`` will be created in
#   ``${CMAKE_CURRENT_BINARY_DIR}`` to receive the list of files found.
#
# ``DIRECTORIES``:
#   Required, expects a list of directories paths. Only absolute paths are
#   supported.
#
# ``FILES_PATTERN``:
#   Required, expects a list of matching expressions to find the files to be
#   considered in the directories.
#
# ``COPY_TO``:
#   Optional, expects a string containing the path to where the file containing
#   the list of files will be copied.
#
# This command searches the directories provided in ``DIRECTORIES`` for files
# matching any of the patterns provided in ``FILES_PATTERNS``. The obtained list
# is written to the path specified by ``output``. A target named ``target_name``
# will be created and its property ``LIST_FILE`` will be set to contain
# ``${CMAKE_CURRENT_BINARY_DIR}/${target_name}.list``
#
# Example:
#
# .. code-block:: cmake
#
#   find_package(ABIMap)
#   get_files_list(target
#     DIRECTORIES "/include/mylib"
#     FILES_PATTERNS "*.h"
#     COPY_TO "my_list.txt"
#   )
#
# Consider that ``/include/mylib`` contains 3 files, ``h1.h``, ``h2.h``, and
# ``h3.hpp``
#
# Will result in a file ``my_list.txt`` containing::
#
#   ``h1.h;h2.h``
#
# And the target ``target`` will have its property ``LIST_FILE`` set to contain
# ``${CMAKE_CURRENT_BINARY_DIR}/target.list``
#
# ::
#
#   extract_symbols(target_name
#                   HEADERS_LIST headers_list_target
#                   [FILTER_PATTERN pattern]
#                   [COPY_TO output]
#                  )
#
# ``target_name``:
#   Required, expects the name of the target to be created. A file named after
#   the string given in ``target_name`` will be created in
#   ``${CMAKE_CURRENT_BINARY_DIR}`` to receive the list of symbols.
#
# ``HEADERS_LIST``:
#   Required, expects a target with the property ``LIST_FILE`` set, containing a
#   file path. Such file must contain a list of files paths.
#
# ``FILTER_PATTERN``:
#   Optional, expects a string. Only the lines containing the filter pattern
#   will be considered.
#
# ``COPY_TO``:
#   Optional, expects a string containing the path to where the file containing
#   the found symbols will be copied.
#
# This command extracts the symbols from the files listed in
# ``headers_list`` and write them on the ``output`` file. If ``pattern``
# is provided, then only the lines containing the string given in ``pattern``
# will be considered. It is recommended to provide a ``FILTER_PATTERN`` to mark
# the lines containing exported function declaration, since this function is
# experimental and can return wrong symbols when parsing the header files. A
# target named ``target_name`` will be created with the property ``LIST_FILE``
# set to contain ``${CMAKE_CURRENT_BINARY_DIR}/${target_name}.list``.
#
# Example:
#
# .. code-block:: cmake
#
#   find_package(ABIMap)
#   extract_symbols("lib.symbols"
#     HEADERS_LIST "headers_target"
#     FILTER_PATTERN "API_FUNCTION"
#   )
#
# Where ``LIST_FILE`` property in ``headers_target`` points to a file
# containing::
#
#   header1.h;header2.h
#
# Where ``header1.h`` contains::
#
#   API_FUNCTION int exported_func1(int a, int b);
#
# ``header2.h`` contains::
#
#   API_FUNCTION int exported_func2(int a);
#
#   int private_func2(int b);
#
# Will result in a file ``lib.symbols.list`` in ``${CMAKE_CURRENT_BINARY_DIR}``
# containing::
#
#   ``exported_func1``
#   ``exported_func2``
#

# Search for python which is required
if (ABIMap_FIND_REQURIED)
    find_package(PythonInterp REQUIRED)
else()
    find_package(PythonInterp)
endif()


if (PYTHONINTERP_FOUND)
    # Search for abimap tool used to generate the map files
    find_program(ABIMAP_EXECUTABLE NAMES abimap DOC "path to the abimap executable")
    mark_as_advanced(ABIMAP_EXECUTABLE)

    if (NOT ABIMAP_EXECUTABLE AND UNIX)
        message(STATUS "Could not find `abimap` in PATH."
                       " It can be found in PyPI as `abimap`"
                       " (try `pip install abimap`)")
    endif ()

    if (ABIMAP_EXECUTABLE)
        # Get the abimap version
        execute_process(COMMAND ${ABIMAP_EXECUTABLE} version
                        OUTPUT_VARIABLE ABIMAP_VERSION_STRING
                        OUTPUT_STRIP_TRAILING_WHITESPACE)

        # If the version string starts with abimap-, strip it
        if ("abimap" STRLESS_EQUAL ${ABIMAP_VERSION_STRING})
            string(REGEX REPLACE "abimap-" "" ABIMAP_VERSION_STRING "${ABIMAP_VERSION_STRING}")
        endif()
    endif()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(ABIMap
                                      REQUIRED_VARS ABIMAP_EXECUTABLE
                                      VERSION_VAR ABIMAP_VERSION_STRING)
endif()


if (ABIMAP_FOUND)

# Define helper scripts
set(_EXTRACT_SYMBOLS_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/ExtractSymbols.cmake)
set(_GENERATE_MAP_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/GenerateMap.cmake)
set(_GET_FILES_LIST_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/GetFilesList.cmake)

function(get_file_list _TARGET_NAME)

    set(one_value_arguments
        COPY_TO
    )

    set(multi_value_arguments
        DIRECTORIES
        FILES_PATTERNS
    )

    cmake_parse_arguments(_get_files_list
        ""
        "${one_value_arguments}"
        "${multi_value_arguments}"
        ${ARGN}
    )

    # The DIRS argument is required
    if (NOT DEFINED _get_files_list_DIRECTORIES)
        message(FATAL_ERROR "No directories paths provided. Provide a list of"
                            " directories paths containing header files.")
    endif()

    # The FILES_PATTERNS argument is required
    if (NOT DEFINED _get_files_list_FILES_PATTERNS)
        message(FATAL_ERROR "No matching expressions provided. Provide a list"
                            " of matching patterns for the header files.")
    endif()

    set(_FILES_LIST_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}.list)

    get_filename_component(_get_files_list_OUTPUT_PATH
                           "${_FILES_LIST_OUTPUT_PATH}"
                           ABSOLUTE)

    add_custom_target(
        ${_TARGET_NAME}_int ALL
        COMMAND ${CMAKE_COMMAND}
          -DOUTPUT_PATH="${_get_files_list_OUTPUT_PATH}"
          -DDIRECTORIES="${_get_files_list_DIRECTORIES}"
          -DFILES_PATTERNS="${_get_files_list_FILES_PATTERNS}"
          -P ${_GET_FILES_LIST_SCRIPT}
        COMMENT
          "Searching for files"
    )

    if (DEFINED _get_files_list_COPY_TO)
        # Copy the generated file back to the COPY_TO
        add_custom_target(${_TARGET_NAME} ALL
            COMMAND
              ${CMAKE_COMMAND} -E copy_if_different
              ${_FILES_LIST_OUTPUT_PATH} ${_get_files_list_COPY_TO}
            DEPENDS ${_TARGET_NAME}_int
            COMMENT "Copying ${_TARGET_NAME} to ${_get_files_list_COPY_TO}"
        )
    else()
        add_custom_target(${_TARGET_NAME} ALL
            DEPENDS ${_TARGET_NAME}_int
        )
    endif()

    set_target_properties(${_TARGET_NAME}
        PROPERTIES LIST_FILE ${_FILES_LIST_OUTPUT_PATH}
    )

endfunction()

function(extract_symbols _TARGET_NAME)

    set(one_value_arguments
        FILTER_PATTERN
        HEADERS_LIST
        COPY_TO
    )

    set(multi_value_arguments
    )

    cmake_parse_arguments(_extract_symbols
        ""
        "${one_value_arguments}"
        "${multi_value_arguments}"
        ${ARGN}
    )

    # The HEADERS_LIST_FILE argument is required
    if (NOT DEFINED _extract_symbols_HEADERS_LIST)
        message(FATAL_ERROR "No target provided in HEADERS_LIST. Provide a"
                            " target with the property LIST_FILE set as the"
                            " path to the file containing the list of headers.")
    endif()

    get_filename_component(_SYMBOLS_OUTPUT_PATH
                           "${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}.list"
                           ABSOLUTE
    )

    get_target_property(_HEADERS_LIST_FILE
        ${_extract_symbols_HEADERS_LIST}
        LIST_FILE
    )

    add_custom_target(
        ${_TARGET_NAME}_int ALL
        COMMAND ${CMAKE_COMMAND}
          -DOUTPUT_PATH="${_SYMBOLS_OUTPUT_PATH}"
          -DHEADERS_LIST_FILE="${_HEADERS_LIST_FILE}"
          -DFILTER_PATTERN=${_extract_symbols_FILTER_PATTERN}
          -P ${_EXTRACT_SYMBOLS_SCRIPT}
        DEPENDS ${_extract_symbols_HEADERS_LIST}
        COMMENT "Extracting symbols from headers"
    )

    if (DEFINED _extract_symbols_COPY_TO)
        # Copy the generated file back to the COPY_TO
        add_custom_target(${_TARGET_NAME} ALL
            COMMAND
              ${CMAKE_COMMAND} -E copy_if_different
              ${_SYMBOLS_OUTPUT_PATH} ${_extract_symbols_COPY_TO}
            DEPENDS ${_TARGET_NAME}_int
            COMMENT "Copying ${_TARGET_NAME} to ${_extract_symbols_COPY_TO}"
        )
    else()
        add_custom_target(${_TARGET_NAME} ALL
            DEPENDS ${_TARGET_NAME}_int
        )
    endif()

    set_target_properties(${_TARGET_NAME}
        PROPERTIES LIST_FILE ${_SYMBOLS_OUTPUT_PATH}
    )

endfunction()

function(generate_map_file _TARGET_NAME)

    set(options
        FINAL
        BREAK_ABI
    )

    set(one_value_arguments
        RELEASE_NAME_VERSION
        SYMBOLS
        CURRENT_MAP
        COPY_TO
    )

    set(multi_value_arguments
    )

    cmake_parse_arguments(_generate_map_file
        "${options}"
        "${one_value_arguments}"
        "${multi_value_arguments}"
        ${ARGN}
    )

    if (NOT DEFINED _generate_map_file_SYMBOLS)
        message(FATAL_ERROR "No target provided in SYMBOLS. Provide a target"
                            " with the property LIST_FILE set as the path to"
                            " the file containing the list of symbols.")
    endif()

    if (NOT DEFINED _generate_map_file_RELEASE_NAME_VERSION)
        message(FATAL_ERROR "Release name and version not provided."
          " (e.g. libname_1_0_0)")
    endif()


    get_target_property(_SYMBOLS_FILE
        ${_generate_map_file_SYMBOLS}
        LIST_FILE
    )

    # Set generated map file path
    get_filename_component(_MAP_OUTPUT_PATH
                           "${CMAKE_CURRENT_BINARY_DIR}/${_TARGET_NAME}"
                           ABSOLUTE
    )

    add_custom_target(
        ${_TARGET_NAME}_int ALL
        COMMAND ${CMAKE_COMMAND}
          -DABIMAP_EXECUTABLE=${ABIMAP_EXECUTABLE}
          -DSYMBOLS="${_SYMBOLS_FILE}"
          -DCURRENT_MAP=${_generate_map_file_CURRENT_MAP}
          -DOUTPUT_PATH="${_MAP_OUTPUT_PATH}"
          -DFINAL=${_generate_map_file_FINAL}
          -DBREAK_ABI=${_generate_map_file_BREAK_ABI}
          -DRELEASE_NAME_VERSION=${_generate_map_file_RELEASE_NAME_VERSION}
          -P ${_GENERATE_MAP_SCRIPT}
        DEPENDS ${_generate_map_file_SYMBOLS}
        COMMENT "Generating the map ${_TARGET_NAME}"
    )

    # Add a custom command setting the map as OUTPUT to allow it to be added as
    # a generated source
    add_custom_command(
        OUTPUT ${_MAP_OUTPUT_PATH}
        DEPENDS ${_TARGET_NAME}
    )

    if (DEFINED _generate_map_file_COPY_TO)
        # Copy the generated map back to the COPY_TO
        add_custom_target(${_TARGET_NAME} ALL
            COMMAND
              ${CMAKE_COMMAND} -E copy_if_different ${_MAP_OUTPUT_PATH}
              ${_generate_map_file_COPY_TO}
            DEPENDS ${_TARGET_NAME}_int
            COMMENT "Copying ${_MAP_OUTPUT_PATH} to ${_generate_map_file_COPY_TO}"
        )
    else()
        add_custom_target(${_TARGET_NAME} ALL
            DEPENDS ${_TARGET_NAME}_int
        )
    endif()
endfunction()

endif (ABIMAP_FOUND)
