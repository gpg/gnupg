/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Defined if the host has big endian byte ordering */
#undef BIG_ENDIAN_HOST

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
#undef CRAY_STACKSEG_END

/* Define to 1 if using `alloca.c'. */
#undef C_ALLOCA

/* define to disable keyserver helpers */
#undef DISABLE_KEYSERVER_HELPERS

/* define to disable exec-path for keyserver helpers */
#undef DISABLE_KEYSERVER_PATH

/* define to disable photo viewing */
#undef DISABLE_PHOTO_VIEWER

/* Define to disable regular expression support */
#undef DISABLE_REGEX

/* Define if you don't want the default EGD socket name. For details see
   cipher/rndegd.c */
#undef EGD_SOCKET_NAME

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#undef ENABLE_NLS

/* if set, restrict photo-viewer to this */
#undef FIXED_PHOTO_VIEWER

/* Define to 1 if you have `alloca', as a function or macro. */
#undef HAVE_ALLOCA

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#undef HAVE_ALLOCA_H

/* Define to 1 if you have the <argz.h> header file. */
#undef HAVE_ARGZ_H

/* Define to 1 if you have the `asprintf' function. */
#undef HAVE_ASPRINTF

/* Define to 1 if you have the `atexit' function. */
#define HAVE_ATEXIT	1

/* Define if `gethrtime(2)' does not work correctly i.e. issues a SIGILL. */
#undef HAVE_BROKEN_GETHRTIME

/* Defined if the mlock() call does not work */
#undef HAVE_BROKEN_MLOCK

/* Defined if a `byte' is typedef'd */
#undef HAVE_BYTE_TYPEDEF

/* Defined if the bz2 compression library is available */
#undef HAVE_BZIP2

/* Define to 1 if you have the `clock_gettime' function. */
#undef HAVE_CLOCK_GETTIME

/* Define to 1 if you have the `ctermid' function. */
#undef HAVE_CTERMID

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#undef HAVE_DCGETTEXT

/* Define to 1 if you have the declaration of `feof_unlocked', and to 0 if you
   don't. */
#define HAVE_DECL_FEOF_UNLOCKED		0

/* Define to 1 if you have the declaration of `fgets_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_FGETS_UNLOCKED	0

/* Define to 1 if you have the declaration of `getc_unlocked', and to 0 if you
   don't. */
#define HAVE_DECL_GETC_UNLOCKED		0

/* Define to 1 if you have the declaration of `sys_siglist', and to 0 if you
   don't. */
#define HAVE_DECL_SYS_SIGLIST		0

/* Define to 1 if you have the declaration of `_snprintf', and to 0 if you
   don't. */
#define HAVE_DECL__SNPRINTF			1

/* Define to 1 if you have the declaration of `_snwprintf', and to 0 if you
   don't. */
#define HAVE_DECL__SNWPRINTF		1

/* defined if the system supports a random device */
#undef HAVE_DEV_RANDOM

/* Define to 1 if you have the <direct.h> header file. */
#define HAVE_DIRECT_H	1

/* Define to 1 if you have the `dlopen' function. */
#undef HAVE_DLOPEN

/* Defined when the dlopen function family is available */
#undef HAVE_DL_DLOPEN

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
#undef HAVE_DOPRNT

/* defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
   with special properties like no file modes */
#define HAVE_DOSISH_SYSTEM	1

/* defined if we must run on a stupid file system */
#undef HAVE_DRIVE_LETTERS

/* Define to 1 if you have the `fork' function. */
#undef HAVE_FORK

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#undef HAVE_FSEEKO

/* Define to 1 if you have the `getcwd' function. */
#define HAVE_GETCWD	1

/* Define to 1 if you have the `getegid' function. */
#undef HAVE_GETEGID

/* Define to 1 if you have the `geteuid' function. */
#undef HAVE_GETEUID

/* Define to 1 if you have the `getgid' function. */
#undef HAVE_GETGID

/* Define if you have the `gethrtime(2)' function. */
#undef HAVE_GETHRTIME

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H		1

/* Define to 1 if you have the `getpagesize' function. */
#undef HAVE_GETPAGESIZE

/* Define to 1 if you have the `getrusage' function. */
#undef HAVE_GETRUSAGE

/* Define if the GNU gettext() function is already present or preinstalled. */
#undef HAVE_GETTEXT

/* Define to 1 if you have the `gettimeofday' function. */
#undef HAVE_GETTIMEOFDAY

/* Define to 1 if you have the `getuid' function. */
#undef HAVE_GETUID

/* Define if you have the iconv() function. */
#undef HAVE_ICONV

/* Define if you have the 'intmax_t' type in <stdint.h> or <inttypes.h>. */
#undef HAVE_INTMAX_T

/* Define if <inttypes.h> exists and doesn't clash with <sys/types.h>. */
#undef HAVE_INTTYPES_H

/* Define if <inttypes.h> exists, doesn't clash with <sys/types.h>, and
   declares uintmax_t. */
#undef HAVE_INTTYPES_H_WITH_UINTMAX

/* Define if you have <langinfo.h> and nl_langinfo(CODESET). */
#undef HAVE_LANGINFO_CODESET

/* Define to 1 if you have the <langinfo.h> header file. */
#undef HAVE_LANGINFO_H

/* Define if your <locale.h> file defines LC_MESSAGES. */
#define HAVE_LC_MESSAGES	1

/* Define if the LDAP library has ldap_get_option */
#undef HAVE_LDAP_GET_OPTION

/* Define if the LDAP library supports ld_errno */
#undef HAVE_LDAP_LD_ERRNO

/* Define to 1 if you have the `dl' library (-ldl). */
#undef HAVE_LIBDL

/* Define to 1 if you have the `rt' library (-lrt). */
#undef HAVE_LIBRT

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H	1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H	1

/* Define if you have the 'long double' type. */
#undef HAVE_LONG_DOUBLE

/* Define if you have the 'long long' type. */
#define HAVE_LONG_LONG	1mempcp

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H	1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE	1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H	1

/* Define to 1 if you have the `mempcpy' function. */
#undef HAVE_MEMPCPY

/* Define to 1 if you have the `mkdtemp' function. */
#undef HAVE_MKDTEMP

/* Defined if the system supports an mlock() call */
#undef HAVE_MLOCK

/* Define to 1 if you have the `mmap' function. */
#undef HAVE_MMAP

/* Define to 1 if you have the `munmap' function. */
#undef HAVE_MUNMAP

/* Define to 1 if you have the `nl_langinfo' function. */
#undef HAVE_NL_LANGINFO

/* Define to 1 if you have the <nl_types.h> header file. */
#undef HAVE_NL_TYPES_H

/* Define to 1 if you have the `pipe' function. */
#undef HAVE_PIPE

/* Define to 1 if you have the `plock' function. */
#undef HAVE_PLOCK

/* Define if your printf() function supports format strings with positions. */
#undef HAVE_POSIX_PRINTF

/* Define to 1 if you have the `putenv' function. */
#undef HAVE_PUTENV

/* Define to 1 if you have the `raise' function. */
#define HAVE_RAISE	1

/* Define to 1 if you have the `rand' function. */
#define HAVE_RAND	1

/* Define to 1 if you have the `setenv' function. */
#undef HAVE_SETENV

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE	1

/* Define to 1 if you have the `setrlimit' function. */
#undef HAVE_SETRLIMIT

/* Define to 1 if you have the `sigaction' function. */
#undef HAVE_SIGACTION

/* Define to 1 if you have the `sigprocmask' function. */
#undef HAVE_SIGPROCMASK

/* Define to 1 if the system has the type `sigset_t'. */
#undef HAVE_SIGSET_T

/* Define to 1 if you have the `snprintf' function. */
#undef HAVE_SNPRINTF

/* Define to 1 if you have the `stat' function. */
#define HAVE_STAT 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H	1

/* Define to 1 if you have the <stdint.h> header file. */
#undef HAVE_STDINT_H

/* Define if <stdint.h> exists, doesn't clash with <sys/types.h>, and declares
   uintmax_t. */
#undef HAVE_STDINT_H_WITH_UINTMAX

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H	1

/* Define to 1 if you have the `stpcpy' function. */
#undef HAVE_STPCPY

/* Define to 1 if you have the `strcasecmp' function. */
#undef HAVE_STRCASECMP

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR	1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP	1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR	1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME	1

/* Define to 1 if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H	1

/* Define to 1 if you have the `strlwr' function. */
#define HAVE_STRLWR	1

/* Define to 1 if you have the `strncasecmp' function. */
#undef HAVE_STRNCASECMP

/* Define to 1 if you have the `strsep' function. */
#undef HAVE_STRSEP

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL	1

/* Define to 1 if the system has the type `struct sigaction'. */
#undef HAVE_STRUCT_SIGACTION

/* Define to 1 if you have the <sys/capability.h> header file. */
#undef HAVE_SYS_CAPABILITY_H

/* Define to 1 if you have the <sys/ipc.h> header file. */
#undef HAVE_SYS_IPC_H

/* Define to 1 if you have the <sys/mman.h> header file. */
#undef HAVE_SYS_MMAN_H

/* Define to 1 if you have the <sys/param.h> header file. */
#undef HAVE_SYS_PARAM_H

/* Define to 1 if you have the <sys/shm.h> header file. */
#undef HAVE_SYS_SHM_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H	1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the `tcgetattr' function. */
#undef HAVE_TCGETATTR

/* Define to 1 if you have the <termio.h> header file. */
#undef HAVE_TERMIO_H

/* Define to 1 if you have the `times' function. */
#undef HAVE_TIMES

/* Define to 1 if you have the `tsearch' function. */
#undef HAVE_TSEARCH

/* Defined if a `u16' is typedef'd */
#undef HAVE_U16_TYPEDEF

/* Defined if a `u32' is typedef'd */
#undef HAVE_U32_TYPEDEF

/* Define if you have the 'uintmax_t' type in <stdint.h> or <inttypes.h>. */
#undef HAVE_UINTMAX_T

/* Defined if a `ulong' is typedef'd */
#undef HAVE_ULONG_TYPEDEF

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Define if you have the unsigned long long type. */
#define HAVE_UNSIGNED_LONG_LONG 1

/* Defined if a `ushort' is typedef'd */
#undef HAVE_USHORT_TYPEDEF

/* Define to 1 if you have the `vfork' function. */
#undef HAVE_VFORK

/* Define to 1 if you have the <vfork.h> header file. */
#undef HAVE_VFORK_H

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF	1

/* Define to 1 if you have the `wait4' function. */
#undef HAVE_WAIT4

/* Define to 1 if you have the `waitpid' function. */
#undef HAVE_WAITPID

/* Define if you have the 'wchar_t' type. */
#undef HAVE_WCHAR_T

/* Define to 1 if you have the `wcslen' function. */
#undef HAVE_WCSLEN

/* Define if you have the 'wint_t' type. */
#undef HAVE_WINT_T

/* Define to 1 if `fork' works. */
#undef HAVE_WORKING_FORK

/* Define to 1 if `vfork' works. */
#undef HAVE_WORKING_VFORK

/* Define to 1 if you have the `__argz_count' function. */
#undef HAVE___ARGZ_COUNT

/* Define to 1 if you have the `__argz_next' function. */
#undef HAVE___ARGZ_NEXT

/* Define to 1 if you have the `__argz_stringify' function. */
#undef HAVE___ARGZ_STRINGIFY

/* Define to 1 if you have the `__fsetlocking' function. */
#undef HAVE___FSETLOCKING

/* Define as const if the declaration of iconv() needs const. */
#undef ICONV_CONST

/* Define if integer division by zero raises signal SIGFPE. */
#undef INTDIV0_RAISES_SIGFPE

/* Defined if a SysV shared memory supports the LOCK flag */
#undef IPC_HAVE_SHM_LOCK

/* Defined if we can do a deferred shm release */
#undef IPC_RMID_DEFERRED_RELEASE

/* Defined if this is not a regular release */
#undef IS_DEVELOPMENT_VERSION

/* Defined if the host has little endian byte ordering */
#define LITTLE_ENDIAN_HOST

/* Defined if mkdir() does not take permission flags */
#define MKDIR_TAKES_ONE_ARG	1

/* Define to use the (obsolete) malloc guarding feature */
#undef M_GUARD

/* defined to the name of the strong random device */
#undef NAME_OF_DEV_RANDOM

/* defined to the name of the weaker random device */
#undef NAME_OF_DEV_URANDOM

/* Define if the LDAP library requires including lber.h before ldap.h */
#undef NEED_LBER_H

/* Define to disable all external program execution */
#undef NO_EXEC

/* Name of package */
#define	PACKAGE	"GPG-1.2.4"

/* Define to the address where bug reports for this package should be sent. */
#undef PACKAGE_BUGREPORT

/* Define to the full name of this package. */
#undef PACKAGE_NAME

/* Define to the full name and version of this package. */
#undef PACKAGE_STRING

/* Define to the one symbol short name of this package. */
#undef PACKAGE_TARNAME

/* Define to the version of this package. */
#undef PACKAGE_VERSION

/* Size of the key and UID caches */
#define PK_UID_CACHE_SIZE	4096

/* A human readable text with the name of the OS */
#undef	PRINTABLE_OS_NAME

/* Define if <inttypes.h> exists and defines unusable PRI* macros. */
#undef PRI_MACROS_BROKEN

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE	void

/* The size of a `uint64_t', as computed by sizeof. */
#undef SIZEOF_UINT64_T

/* The size of a `unsigned int', as computed by sizeof. */
#define SIZEOF_UNSIGNED_INT	4

/* The size of a `unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG	4

/* The size of a `unsigned long long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG_LONG	8

/* The size of a `unsigned short', as computed by sizeof. */
#define SIZEOF_UNSIGNED_SHORT	2

/* Define as the maximum value of type 'size_t', if the system doesn't define
   it. */
#undef SIZE_MAX

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at run-time.
        STACK_DIRECTION > 0 => grows toward higher addresses
        STACK_DIRECTION < 0 => grows toward lower addresses
        STACK_DIRECTION = 0 => direction of growth unknown */
#undef STACK_DIRECTION

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS	1

/* Define to include the AES, AES192, and AES256 ciphers */
#define USE_AES	1

/* Allow to select random modules at runtime. */
#undef USE_ALL_RANDOM_MODULES

/* Define to include the BLOWFISH cipher */
#undef USE_BLOWFISH

/* define if capabilities should be used */
#undef USE_CAPABILITIES

/* Define to include the CAST5 cipher */
#define USE_CAST5	1

/* define to use DNS SRV */
#undef USE_DNS_SRV

/* define to enable the use of extensions */
#define USE_DYNAMIC_LINKING	1

/* Define if you want to use the included regex lib */
#define USE_GNU_REGEX	1

/* Define to include the IDEA cipher */
#undef USE_IDEA

/* Define to use the old fake OID for TIGER/192 digest support */
#undef USE_OLD_TIGER

/* set this to limit filenames to the 8.3 format */
#undef USE_ONLY_8DOT3

/* Defined if the EGD based RNG should be used. */
#undef USE_RNDEGD

/* Defined if the /dev/random based RNG should be used. */
#undef USE_RNDLINUX

/* Defined if the default Unix RNG should be used. */
#undef USE_RNDUNIX

/* Defined if the Windows specific RNG should be used. */
#define	USE_RNDW32	1

/* Define to include the SHA-256 digest */
#define USE_SHA256	1

/* Define to include the SHA-384 and SHA-512 digests */
#undef USE_SHA512

/* define if the shared memory interface should be made available */
#undef USE_SHM_COPROCESSING

/* because the Unix gettext has too much overhead on MingW32 systems and these
   systems lack Posix functions, we use a simplified version of gettext */
#define USE_SIMPLE_GETTEXT	1

/* Define to include the TIGER/192 digest */
#undef USE_TIGER

/* Define to include the TWOFISH cipher */
#undef USE_TWOFISH

/* Version number of package */
#define VERSION	"1.2.4-BRG"

/* Defined if compiled symbols have a leading underscore */
#define WITH_SYMBOL_UNDERSCORE	1

/* Number of bits in a file offset, on hosts where this is settable. */
#undef _FILE_OFFSET_BITS

/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# undef _GNU_SOURCE
#endif

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
#undef _LARGEFILE_SOURCE

/* Define for large files, on AIX-style hosts. */
#undef _LARGE_FILES

/* Define to empty if `const' does not conform to ANSI C. */
#undef const

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#define inline	__inline
#endif

/* Define to `int' if <sys/types.h> does not define. */
#undef mode_t

/* Define to `long' if <sys/types.h> does not define. */
#undef off_t

/* Define to `int' if <sys/types.h> does not define. */
#undef pid_t

/* Define as the type of the result of subtracting two pointers, if the system
   doesn't define it. */
#undef ptrdiff_t

/* Define to empty if the C compiler doesn't support this keyword. */
#undef signed

/* Define to `unsigned' if <sys/types.h> does not define. */
#define size_t	unsigned

/* Define to unsigned long or unsigned long long if <inttypes.h> and
   <stdint.h> don't define. */
#undef uintmax_t

/* Define as `fork' if `vfork' does not work. */
#undef vfork

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
#undef volatile

#if !(defined(HAVE_FORK) && defined(HAVE_PIPE) && defined(HAVE_WAITPID))
#define EXEC_TEMPFILE_ONLY
#endif

#include "g10defs.h"

