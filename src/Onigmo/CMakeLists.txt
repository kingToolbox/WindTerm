# Onigmo regex engine, built for the WindTerm SDK.
#
# Source list mirrors libonig_la_SOURCES in Makefile.am.

include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)

set(ONIGMO_VERSION "5.13.5")

check_include_file(alloca.h    HAVE_ALLOCA_H)
check_include_file(dlfcn.h     HAVE_DLFCN_H)
check_include_file(inttypes.h  HAVE_INTTYPES_H)
check_include_file(memory.h    HAVE_MEMORY_H)
check_include_file(stdint.h    HAVE_STDINT_H)
check_include_file(stdlib.h    HAVE_STDLIB_H)
check_include_file(strings.h   HAVE_STRINGS_H)
check_include_file(string.h    HAVE_STRING_H)
check_include_file(sys/stat.h  HAVE_SYS_STAT_H)
check_include_file(sys/times.h HAVE_SYS_TIMES_H)
check_include_file(sys/time.h  HAVE_SYS_TIME_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(unistd.h    HAVE_UNISTD_H)

if(HAVE_STDLIB_H AND HAVE_STRING_H AND HAVE_SYS_STAT_H AND HAVE_SYS_TYPES_H)
	set(STDC_HEADERS 1)
endif()
if(HAVE_SYS_TIME_H)
	set(TIME_WITH_SYS_TIME 1)
endif()

check_symbol_exists(alloca "alloca.h" HAVE_ALLOCA)

check_type_size("int"   SIZEOF_INT   LANGUAGE C)
check_type_size("short" SIZEOF_SHORT LANGUAGE C)
check_type_size("long"  SIZEOF_LONG  LANGUAGE C)

# x86_64 and arm64 both grow the stack towards lower addresses.
set(STACK_DIRECTION -1)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/config.h"
)

set(ONIGMO_SOURCES
	regerror.c regparse.c regext.c regcomp.c regexec.c reggnu.c
	regenc.c regsyntax.c regtrav.c regversion.c st.c
	regposix.c regposerr.c
	enc/unicode.c enc/ascii.c enc/utf8.c
	enc/utf16_be.c enc/utf16_le.c
	enc/utf32_be.c enc/utf32_le.c
	enc/euc_jp.c enc/sjis.c enc/cp932.c
	enc/iso8859_1.c  enc/iso8859_2.c  enc/iso8859_3.c  enc/iso8859_4.c
	enc/iso8859_5.c  enc/iso8859_6.c  enc/iso8859_7.c  enc/iso8859_8.c
	enc/iso8859_9.c  enc/iso8859_10.c enc/iso8859_11.c enc/iso8859_13.c
	enc/iso8859_14.c enc/iso8859_15.c enc/iso8859_16.c
	enc/euc_tw.c enc/euc_kr.c enc/big5.c
	enc/gb18030.c enc/koi8_r.c enc/cp1251.c
)

add_library(onigmo ${ONIGMO_SOURCES})
add_library(WindTerm::onigmo ALIAS onigmo)

# regint.h does "#include \"config.h\"", so the generated header must come
# first on the include path.
target_include_directories(onigmo
	PRIVATE
		"${CMAKE_CURRENT_BINARY_DIR}"
		"${CMAKE_CURRENT_SOURCE_DIR}"
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/windterm/onigmo>
)

target_compile_definitions(onigmo PRIVATE HAVE_CONFIG_H=1)

# Onigmo predates a few warnings clang now emits by default; they are noise
# here and would drown the warnings that matter in WindTerm's own code.
target_compile_options(onigmo PRIVATE
	-Wno-unused-parameter
	-Wno-unused-but-set-variable
	-Wno-deprecated-non-prototype
)

# AArch64 supports unaligned word access, but Onigmo only enables the fast
# path for x86/m68k. Off by default: enabling it changes how the matcher reads
# memory and has not been benchmarked here.
option(ONIGMO_UNALIGNED_WORD_ACCESS
	"Enable Onigmo's unaligned word access fast path on arm64" OFF)
if(ONIGMO_UNALIGNED_WORD_ACCESS)
	target_compile_definitions(onigmo PRIVATE PLATFORM_UNALIGNED_WORD_ACCESS=1)
endif()

set_target_properties(onigmo PROPERTIES
	OUTPUT_NAME     "onigmo"
	VERSION         "${ONIGMO_VERSION}"
	SOVERSION       "5"
	C_VISIBILITY_PRESET hidden
)

install(TARGETS onigmo
	EXPORT WindTermTargets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES
	oniguruma.h
	oniggnu.h
	onigposix.h
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/windterm/onigmo"
)
