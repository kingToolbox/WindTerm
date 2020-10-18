if (UNIX AND NOT WIN32)
    # Activate with: -DCMAKE_BUILD_TYPE=Profiling
    set(CMAKE_C_FLAGS_PROFILING "-O0 -g -fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the C compiler during PROFILING builds.")
    set(CMAKE_CXX_FLAGS_PROFILING "-O0 -g -fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the CXX compiler during PROFILING builds.")
    set(CMAKE_SHARED_LINKER_FLAGS_PROFILING "-fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during PROFILING builds.")
    set(CMAKE_MODULE_LINKER_FLAGS_PROFILING "-fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during PROFILING builds.")
    set(CMAKE_EXEC_LINKER_FLAGS_PROFILING "-fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the linker during PROFILING builds.")

    # Activate with: -DCMAKE_BUILD_TYPE=AddressSanitizer
    set(CMAKE_C_FLAGS_ADDRESSSANITIZER "-g -O1 -fsanitize=address -fno-omit-frame-pointer"
        CACHE STRING "Flags used by the C compiler during ADDRESSSANITIZER builds.")
    set(CMAKE_CXX_FLAGS_ADDRESSSANITIZER "-g -O1 -fsanitize=address -fno-omit-frame-pointer"
        CACHE STRING "Flags used by the CXX compiler during ADDRESSSANITIZER builds.")
    set(CMAKE_SHARED_LINKER_FLAGS_ADDRESSSANITIZER "-fsanitize=address"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during ADDRESSSANITIZER builds.")
    set(CMAKE_MODULE_LINKER_FLAGS_ADDRESSSANITIZER "-fsanitize=address"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during ADDRESSSANITIZER builds.")
    set(CMAKE_EXEC_LINKER_FLAGS_ADDRESSSANITIZER "-fsanitize=address"
        CACHE STRING "Flags used by the linker during ADDRESSSANITIZER builds.")

    # Activate with: -DCMAKE_BUILD_TYPE=MemorySanitizer
    set(CMAKE_C_FLAGS_MEMORYSANITIZER "-g -O2 -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer"
        CACHE STRING "Flags used by the C compiler during MEMORYSANITIZER builds.")
    set(CMAKE_CXX_FLAGS_MEMORYSANITIZER "-g -O2 -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer"
        CACHE STRING "Flags used by the CXX compiler during MEMORYSANITIZER builds.")
    set(CMAKE_SHARED_LINKER_FLAGS_MEMORYSANITIZER "-fsanitize=memory"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during MEMORYSANITIZER builds.")
    set(CMAKE_MODULE_LINKER_FLAGS_MEMORYSANITIZER "-fsanitize=memory"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during MEMORYSANITIZER builds.")
    set(CMAKE_EXEC_LINKER_FLAGS_MEMORYSANITIZER "-fsanitize=memory"
        CACHE STRING "Flags used by the linker during MEMORYSANITIZER builds.")

    # Activate with: -DCMAKE_BUILD_TYPE=UndefinedSanitizer
    set(CMAKE_C_FLAGS_UNDEFINEDSANITIZER "-g -O1 -fsanitize=undefined -fsanitize=null -fsanitize=alignment -fno-sanitize-recover"
        CACHE STRING "Flags used by the C compiler during UNDEFINEDSANITIZER builds.")
    set(CMAKE_CXX_FLAGS_UNDEFINEDSANITIZER "-g -O1 -fsanitize=undefined -fsanitize=null -fsanitize=alignment -fno-sanitize-recover"
        CACHE STRING "Flags used by the CXX compiler during UNDEFINEDSANITIZER builds.")
    set(CMAKE_SHARED_LINKER_FLAGS_UNDEFINEDSANITIZER "-fsanitize=undefined"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during UNDEFINEDSANITIZER builds.")
    set(CMAKE_MODULE_LINKER_FLAGS_UNDEFINEDSANITIZER "-fsanitize=undefined"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during UNDEFINEDSANITIZER builds.")
    set(CMAKE_EXEC_LINKER_FLAGS_UNDEFINEDSANITIZER "-fsanitize=undefined"
        CACHE STRING "Flags used by the linker during UNDEFINEDSANITIZER builds.")
endif()
