include(AddCCompilerFlag)
include(CheckCCompilerFlagSSP)

if (UNIX)
    #
    # Check for -Werror turned on if possible
    #
    # This will prevent that compiler flags are detected incorrectly.
    #
    check_c_compiler_flag("-Werror" REQUIRED_FLAGS_WERROR)
    if (REQUIRED_FLAGS_WERROR)
        set(CMAKE_REQUIRED_FLAGS "-Werror")

        if (PICKY_DEVELOPER)
            list(APPEND SUPPORTED_COMPILER_FLAGS "-Werror")
        endif()
    endif()

    add_c_compiler_flag("-std=gnu99" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wpedantic" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wall" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wshadow" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wmissing-prototypes" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wcast-align" SUPPORTED_COMPILER_FLAGS)
    #add_c_compiler_flag("-Wcast-qual" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=address" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wstrict-prototypes" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=strict-prototypes" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wwrite-strings" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=write-strings" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror-implicit-function-declaration" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wpointer-arith" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=pointer-arith" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wdeclaration-after-statement" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=declaration-after-statement" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wreturn-type" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=return-type" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wuninitialized" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=uninitialized" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wimplicit-fallthrough" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=strict-overflow" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wstrict-overflow=2" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wno-format-zero-length" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wmissing-field-initializers" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Wsign-compare" SUPPORTED_COMPILER_FLAGS)

    check_c_compiler_flag("-Wformat" REQUIRED_FLAGS_WFORMAT)
    if (REQUIRED_FLAGS_WFORMAT)
        list(APPEND SUPPORTED_COMPILER_FLAGS "-Wformat")
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Wformat")
    endif()
    add_c_compiler_flag("-Wformat-security" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("-Werror=format-security" SUPPORTED_COMPILER_FLAGS)

    # Allow zero for a variadic macro argument
    string(TOLOWER "${CMAKE_C_COMPILER_ID}" _C_COMPILER_ID)
    if ("${_C_COMPILER_ID}" STREQUAL "clang")
        add_c_compiler_flag("-Wno-gnu-zero-variadic-macro-arguments" SUPPORTED_COMPILER_FLAGS)
    endif()

    add_c_compiler_flag("-fno-common" SUPPORTED_COMPILER_FLAGS)

    if (CMAKE_BUILD_TYPE)
        string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)
        if (CMAKE_BUILD_TYPE_LOWER MATCHES (release|relwithdebinfo|minsizerel))
            add_c_compiler_flag("-Wp,-D_FORTIFY_SOURCE=2" SUPPORTED_COMPILER_FLAGS)
        endif()
    endif()

    check_c_compiler_flag_ssp("-fstack-protector-strong" WITH_STACK_PROTECTOR_STRONG)
    if (WITH_STACK_PROTECTOR_STRONG)
        list(APPEND SUPPORTED_COMPILER_FLAGS "-fstack-protector-strong")
        # This is needed as Solaris has a seperate libssp
        if (SOLARIS)
            list(APPEND SUPPORTED_LINKER_FLAGS "-fstack-protector-strong")
        endif()
    else (WITH_STACK_PROTECTOR_STRONG)
        check_c_compiler_flag_ssp("-fstack-protector" WITH_STACK_PROTECTOR)
        if (WITH_STACK_PROTECTOR)
            list(APPEND SUPPORTED_COMPILER_FLAGS "-fstack-protector")
            # This is needed as Solaris has a seperate libssp
            if (SOLARIS)
                list(APPEND SUPPORTED_LINKER_FLAGS "-fstack-protector")
            endif()
        endif()
    endif (WITH_STACK_PROTECTOR_STRONG)

    check_c_compiler_flag_ssp("-fstack-clash-protection" WITH_STACK_CLASH_PROTECTION)
    if (WITH_STACK_CLASH_PROTECTION)
        list(APPEND SUPPORTED_COMPILER_FLAGS "-fstack-clash-protection")
    endif()

    if (PICKY_DEVELOPER)
        add_c_compiler_flag("-Wno-error=deprecated-declarations" SUPPORTED_COMPILER_FLAGS)
        add_c_compiler_flag("-Wno-error=tautological-compare" SUPPORTED_COMPILER_FLAGS)
    endif()

    add_c_compiler_flag("-Wno-deprecated-declarations" DEPRECATION_COMPILER_FLAGS)

    # Unset CMAKE_REQUIRED_FLAGS
    unset(CMAKE_REQUIRED_FLAGS)
endif()

if (MSVC)
    add_c_compiler_flag("/D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("/D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("/D _CRT_NONSTDC_NO_WARNINGS=1" SUPPORTED_COMPILER_FLAGS)
    add_c_compiler_flag("/D _CRT_SECURE_NO_WARNINGS=1" SUPPORTED_COMPILER_FLAGS)
endif()

# This removes this annoying warning
# "warning: 'BN_CTX_free' is deprecated: first deprecated in OS X 10.7 [-Wdeprecated-declarations]"
if (OSX)
    add_c_compiler_flag("-Wno-deprecated-declarations" SUPPORTED_COMPILER_FLAGS)
endif()

set(DEFAULT_C_COMPILE_FLAGS ${SUPPORTED_COMPILER_FLAGS} CACHE INTERNAL "Default C Compiler Flags" FORCE)
set(DEFAULT_LINK_FLAGS ${SUPPORTED_LINKER_FLAGS} CACHE INTERNAL "Default C Linker Flags" FORCE)

if (DEPRECATION_COMPILER_FLAGS)
    set(DEFAULT_C_NO_DEPRECATION_FLAGS ${DEPRECATION_COMPILER_FLAGS} CACHE INTERNAL "Default no deprecation flags" FORCE)
endif()
