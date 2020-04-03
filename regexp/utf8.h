#ifndef UTF8_UTIL_H
#define UTF8_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * UTF-8 utility functions
 *
 * (c) 2010-2016 Steve Bennett <steveb@workware.net.au>
 *
 * See LICENCE for licence details.
 */

/* Currently we support unicode points up to 2^22-1 */
#define MAX_UTF8_LEN 4

/**
 * Converts the given unicode codepoint (0 - 0x1fffff) to utf-8
 * and stores the result at 'p'.
 *
 * Returns the number of utf-8 characters (up to MAX_UTF8_LEN).
 */
int utf8_fromunicode(char *p, unsigned uc);

#ifndef JIM_UTF8
#include <ctype.h>

/* No utf-8 support. 1 byte = 1 char */
#define utf8_tounicode(S, CP) (*(CP) = (unsigned char)*(S), 1)
#define utf8_getchars(CP, C) (*(CP) = (C), 1)
#define utf8_upper(C) toupper(C)
#define utf8_index(C, I) (I)
#define utf8_charlen(C) 1

#else
#if !defined(JIM_BOOTSTRAP)

#define utf8_getchars utf8_fromunicode

/**
 * Returns the length of the utf-8 sequence starting with 'c'.
 *
 * Returns 1-4.
 * If 'c' is not a valid start byte, returns 1.
 */
int utf8_charlen(int c);

/**
 * Returns the byte index of the given character in the utf-8 string.
 *
 * The string *must* be null terminated.
 *
 * This will return the byte length of a utf-8 string
 * if given the char length.
 */
int utf8_index(const char *str, int charindex);

/**
 * Returns the unicode codepoint corresponding to the
 * utf-8 sequence 'str'.
 *
 * Stores the result in *uc and returns the number of bytes
 * consumed.
 *
 * If 'str' is null terminated, then an invalid utf-8 sequence
 * at the end of the string will be returned as individual bytes.
 *
 * If it is not null terminated, the length *must* be checked first.
 *
 * Does not support unicode code points > \u1fffff
 */
int utf8_tounicode(const char *str, int *uc);

/**
 * Returns the upper-case variant of the given unicode codepoint.
 *
 * Unicode code points > \uffff are returned unchanged.
 */
int utf8_upper(int uc);
#endif /* JIM_BOOTSTRAP */

#endif

#ifdef __cplusplus
}
#endif

#endif
