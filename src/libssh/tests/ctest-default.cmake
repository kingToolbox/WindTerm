## The directory to run ctest in.
set(CTEST_DIRECTORY "$ENV{HOME}/workspace/tmp/dashboards/libssh")

## The hostname of the machine
set(CTEST_SITE "host.libssh.org")
## The buildname
set(CTEST_BUILD_NAME "Linux_2.6-GCC_4.5-x86_64-default")

## The Makefile generator to use
set(CTEST_CMAKE_GENERATOR "Unix Makefiles")

## The Build configuration to use.
set(CTEST_BUILD_CONFIGURATION "Debug")

## The build options for the project
set(CTEST_BUILD_OPTIONS "-DUNIT_TESTING=ON -WITH_SFTP=ON -DWITH_SERVER=ON -DWITH_ZLIB=ON -DWITH_PCAP=ON -DDEBUG_CRYPTO=ON -DWITH_GCRYPT=OFF")

#set(CTEST_CUSTOM_MEMCHECK_IGNORE torture_rand)

## The Model to set: Nightly, Continous, Experimental
set(CTEST_MODEL "Experimental")

## The branch
#set(CTEST_GIT_BRANCH "--branch v0-5")

## Wether to enable memory checking.
set(WITH_MEMCHECK FALSE)

## Wether to enable code coverage.
set(WITH_COVERAGE FALSE)

#######################################################################

if (WITH_COVERAGE AND NOT WIN32)
    set(CTEST_BUILD_CONFIGURATION "Profiling")
endif (WITH_COVERAGE AND NOT WIN32)

set(CTEST_SOURCE_DIRECTORY "${CTEST_DIRECTORY}/${CTEST_BUILD_NAME}/source")
set(CTEST_BINARY_DIRECTORY "${CTEST_DIRECTORY}/${CTEST_BUILD_NAME}/build")

set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE ${CMAKE_SOURCE_DIR}/tests/valgrind.supp)
set(CTEST_MEMORYCHECK_COMMAND_OPTIONS " --trace-children-skip=${SSHD_EXECUTABLE}")

find_program(CTEST_GIT_COMMAND NAMES git)
find_program(CTEST_COVERAGE_COMMAND NAMES gcov)
find_program(CTEST_MEMORYCHECK_COMMAND NAMES valgrind)

if(NOT EXISTS "${CTEST_SOURCE_DIRECTORY}")
    set(CTEST_CHECKOUT_COMMAND "${CTEST_GIT_COMMAND} clone ${CTEST_GIT_BRANCH} git://git.libssh.org/projects/libssh.git ${CTEST_SOURCE_DIRECTORY}")
endif()

set(CTEST_UPDATE_COMMAND "${CTEST_GIT_COMMAND}")

set(CTEST_CONFIGURE_COMMAND "${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE:STRING=${CTEST_BUILD_CONFIGURATION}")
set(CTEST_CONFIGURE_COMMAND "${CTEST_CONFIGURE_COMMAND} -DUNIT_TESTING:BOOL=ON ${CTEST_BUILD_OPTIONS}")
set(CTEST_CONFIGURE_COMMAND "${CTEST_CONFIGURE_COMMAND} \"-G${CTEST_CMAKE_GENERATOR}\"")
set(CTEST_CONFIGURE_COMMAND "${CTEST_CONFIGURE_COMMAND} \"${CTEST_SOURCE_DIRECTORY}\"")

ctest_empty_binary_directory(${CTEST_BINARY_DIRECTORY})

ctest_start(${CTEST_MODEL} TRACK ${CTEST_MODEL})
ctest_update(SOURCE ${CTEST_SOURCE_DIRECTORY})
ctest_configure(BUILD ${CTEST_BINARY_DIRECTORY})
ctest_build(BUILD ${CTEST_BINARY_DIRECTORY})
ctest_test(BUILD ${CTEST_BINARY_DIRECTORY})
if (WITH_COVERAGE)
  ctest_coverage(BUILD ${CTEST_BINARY_DIRECTORY})
endif ()
if (WITH_MEMCHECK)
  ctest_memcheck(BUILD ${CTEST_BINARY_DIRECTORY})
endif ()
ctest_submit()
