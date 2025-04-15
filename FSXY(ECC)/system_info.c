// SPDX-License-Identifier: MIT


#include <stdio.h>
#include <string.h>

#include "system_info.h"

// based on macros in https://sourceforge.net/p/predef/wiki/Compilers/
void print_compiler_info(void) {
#if defined(__clang__)
	printf("Compiler:         clang (%s)\n", __clang_version__);
#elif defined(__GNUC_PATCHLEVEL__)
	printf("Compiler:         gcc (%d.%d.%d)\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__GNUC_MINOR__)
	printf("Compiler:         gcc (%d.%d)\n", __GNUC__, __GNUC_MINOR__);
#elif defined(__INTEL_COMPILER)
	printf("Compiler:         Intel C/C++ (%d)\n", __INTEL_COMPILER);
#elif defined(_MSC_FULL_VER)
	printf("Compiler:         Microsoft C/C++ (%d)\n", _MSC_FULL_VER);
#else
	printf("Compiler:         Unknown"\n);
#endif
}

// based on macros in https://sourceforge.net/p/predef/wiki/Architectures/
void print_platform_info(void) {
#if defined(_WIN64)
	printf("Target platform:  Windows (64-bit)");
#elif defined(_WIN32)
	printf("Target platform:  Windows (32-bit)");
#else
	printf("Target platform:  Unknown");
#endif
	printf("\n");
}


#define  C_OR_NI_OR_ARM(stmt_c, stmt_ni, stmt_arm) \
    stmt_c;


void print_oqs_configuration(void) {

	C_OR_NI_OR_ARM(
	    printf("AES:              C\n"),
	    printf("AES:              NI\n"),
	    printf("AES:              C and ARM CRYPTO extensions\n")
	)

	printf("SHA-2:            C\n");

	printf("SHA-3:            C\n");

	printf("Build flags:  ");
#ifdef BUILD_SHARED_LIBS
	printf("BUILD_SHARED_LIBS ");
#endif

#ifdef USE_SANITIZER
	printf("USE_SANITIZER=%s ", USE_SANITIZER);
#endif

#ifdef CMAKE_BUILD_TYPE
	printf("CMAKE_BUILD_TYPE=%s ", CMAKE_BUILD_TYPE);
#else
	printf("CMAKE_BUILD_TYPE=Release ");
#endif
	printf("\n");
}

void print_system_info(void) {
	printf("Configuration info\n");
	printf("==================\n");
	print_platform_info();
	print_compiler_info();
	print_oqs_configuration();
	printf("\n");
}
