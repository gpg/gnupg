/**
 * UTF-8 utility functions
 *
 * (c) 2010-2016 Steve Bennett <steveb@workware.net.au>
 *
 * See LICENCE for licence details.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "utf8.h"

/* This one is always implemented */
int utf8_fromunicode(char *p, unsigned uc)
{
    if (uc <= 0x7f) {
        *p = uc;
        return 1;
    }
    else if (uc <= 0x7ff) {
        *p++ = 0xc0 | ((uc & 0x7c0) >> 6);
        *p = 0x80 | (uc & 0x3f);
        return 2;
    }
    else if (uc <= 0xffff) {
        *p++ = 0xe0 | ((uc & 0xf000) >> 12);
        *p++ = 0x80 | ((uc & 0xfc0) >> 6);
        *p = 0x80 | (uc & 0x3f);
        return 3;
    }
    /* Note: We silently truncate to 21 bits here: 0x1fffff */
    else {
        *p++ = 0xf0 | ((uc & 0x1c0000) >> 18);
        *p++ = 0x80 | ((uc & 0x3f000) >> 12);
        *p++ = 0x80 | ((uc & 0xfc0) >> 6);
        *p = 0x80 | (uc & 0x3f);
        return 4;
    }
}

#if defined(USE_UTF8) && !defined(JIM_BOOTSTRAP)
int utf8_charlen(int c)
{
    if ((c & 0x80) == 0) {
        return 1;
    }
    if ((c & 0xe0) == 0xc0) {
        return 2;
    }
    if ((c & 0xf0) == 0xe0) {
        return 3;
    }
    if ((c & 0xf8) == 0xf0) {
        return 4;
    }
    /* Invalid sequence, so treat it as a single byte */
    return 1;
}

int utf8_index(const char *str, int index)
{
    const char *s = str;
    while (index--) {
        s += utf8_charlen(*s);
    }
    return s - str;
}

int utf8_tounicode(const char *str, int *uc)
{
    unsigned const char *s = (unsigned const char *)str;

    if (s[0] < 0xc0) {
        *uc = s[0];
        return 1;
    }
    if (s[0] < 0xe0) {
        if ((s[1] & 0xc0) == 0x80) {
            *uc = ((s[0] & ~0xc0) << 6) | (s[1] & ~0x80);
            if (*uc >= 0x80) {
                return 2;
            }
            /* Otherwise this is an invalid sequence */
        }
    }
    else if (s[0] < 0xf0) {
        if (((str[1] & 0xc0) == 0x80) && ((str[2] & 0xc0) == 0x80)) {
            *uc = ((s[0] & ~0xe0) << 12) | ((s[1] & ~0x80) << 6) | (s[2] & ~0x80);
            if (*uc >= 0x800) {
                return 3;
            }
            /* Otherwise this is an invalid sequence */
        }
    }
    else if (s[0] < 0xf8) {
        if (((str[1] & 0xc0) == 0x80) && ((str[2] & 0xc0) == 0x80) && ((str[3] & 0xc0) == 0x80)) {
            *uc = ((s[0] & ~0xf0) << 18) | ((s[1] & ~0x80) << 12) | ((s[2] & ~0x80) << 6) | (s[3] & ~0x80);
            if (*uc >= 0x10000) {
                return 4;
            }
            /* Otherwise this is an invalid sequence */
        }
    }

    /* Invalid sequence, so just return the byte */
    *uc = *s;
    return 1;
}

struct casemap {
    unsigned short code;        /* code point */
    unsigned short altcode;     /* alternate case code point */
};


/* Generated mapping tables */
#include "_unicode_mapping.c"

#define ARRAYSIZE(A) sizeof(A) / sizeof(*(A))

static int cmp_casemap(const void *key, const void *cm)
{
    return *(int *)key - (int)((const struct casemap *)cm)->code;
}

static int utf8_map_case(const struct casemap *mapping, int num, int ch)
{
    /* We only support 16 bit case mapping */
    if (ch <= 0xffff) {
        const struct casemap *cm =
            bsearch(&ch, mapping, num, sizeof(*mapping), cmp_casemap);

        if (cm) {
            return cm->altcode;
        }
    }
    return ch;
}

int utf8_upper(int ch)
{
    if (isascii(ch)) {
        return toupper(ch);
    }
    return utf8_map_case(unicode_case_mapping_upper, ARRAYSIZE(unicode_case_mapping_upper), ch);
}
#endif /* JIM_BOOTSTRAP */
