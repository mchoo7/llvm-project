#include "stdio.h"

char src[64];
char dst[64];
unsigned len64 = 64;

#if defined(__FreeBSD__) && defined(__aarch64__)
#include <stdint.h>
#include <sys/auxv.h>
#include <machine/ifunc.h>
#ifdef _IFUNC_ARG_HWCAP
unsigned has_ifunc_arg_structure = 1;
#else
unsigned has_ifunc_arg_structure = 0;
#endif
#endif

#ifdef _IFUNC_ARG_HWCAP
static unsigned long expected_hwcap, expected_hwcap2;
static int valid_ifunc_args(void) { return 42; }
static int invalid_ifunc_args(void) { return -1; }

DEFINE_UIFUNC(, int, ifunc_answer, (void)) {
  if (!ifunc_arg || ifunc_arg->_size < 3 * sizeof(unsigned long) ||
      at_hwcap != (expected_hwcap | _IFUNC_ARG_HWCAP) ||
      ifunc_arg->_hwcap != at_hwcap || ifunc_arg->_hwcap2 != expected_hwcap2 ||
      _arg3 || _arg4 || _arg5 || _arg6 || _arg7 || _arg8)
    return invalid_ifunc_args;
  return valid_ifunc_args;
}
#endif

int main(int argc, char **argv) {
#ifdef _IFUNC_ARG_HWCAP
  elf_aux_info(AT_HWCAP, &expected_hwcap, sizeof(expected_hwcap));
  elf_aux_info(AT_HWCAP2, &expected_hwcap2, sizeof(expected_hwcap2));
#endif
  // Call a libc function so that we know there is a real libc in our process.
  puts("s"); // break here
  return 0;
}
