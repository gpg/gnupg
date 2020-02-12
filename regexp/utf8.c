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

int utf8_strlen(const char *str, int bytelen)
{
    int charlen = 0;
    if (bytelen < 0) {
        bytelen = strlen(str);
    }
    while (bytelen > 0) {
        int c;
        int l = utf8_tounicode(str, &c);
        charlen++;
        str += l;
        bytelen -= l;
    }
    return charlen;
}

int utf8_strwidth(const char *str, int charlen)
{
    int width = 0;
    while (charlen) {
        int c;
        int l = utf8_tounicode(str, &c);
        width += utf8_width(c);
        str += l;
        charlen--;
    }
    return width;
}

int utf8_index(const char *str, int index)
{
    const char *s = str;
    while (index--) {
        s += utf8_charlen(*s);
    }
    return s - str;
}

int utf8_prev_len(const char *str, int len)
{
    int n = 1;

    assert(len > 0);

    /* Look up to len chars backward for a start-of-char byte */
    while (--len) {
        if ((str[-n] & 0x80) == 0) {
            /* Start of a 1-byte char */
            break;
        }
        if ((str[-n] & 0xc0) == 0xc0) {
            /* Start of a multi-byte char */
            break;
        }
        n++;
    }
    return n;
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

struct utf8range {
    unsigned lower;     /* lower inclusive */
    unsigned upper;     /* upper exclusive */
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

static int cmp_range(const void *key, const void *cm)
{
    const struct utf8range *range = (const struct utf8range *)cm;
    unsigned ch = *(unsigned *)key;
    if (ch < range->lower) {
        return -1;
    }
    if (ch >= range->upper) {
        return 1;
    }
    return 0;
}

static int utf8_in_range(const struct utf8range *range, int num, int ch)
{
    const struct utf8range *r =
        bsearch(&ch, range, num, sizeof(*range), cmp_range);

    if (r) {
        return 1;
    }
    return 0;
}

int utf8_upper(int ch)
{
    if (isascii(ch)) {
        return toupper(ch);
    }
    return utf8_map_case(unicode_case_mapping_upper, ARRAYSIZE(unicode_case_mapping_upper), ch);
}

int utf8_lower(int ch)
{
    if (isascii(ch)) {
        return tolower(ch);
    }
    return utf8_map_case(unicode_case_mapping_lower, ARRAYSIZE(unicode_case_mapping_lower), ch);
}

int utf8_title(int ch)
{
    if (!isascii(ch)) {
        int newch = utf8_map_case(unicode_case_mapping_title, ARRAYSIZE(unicode_case_mapping_title), ch);
        if (newch != ch) {
            return newch ? newch : ch;
        }
    }
    return utf8_upper(ch);
}

int utf8_width(int ch)
{
    if (!isascii(ch)) {
        if (utf8_in_range(unicode_range_combining, ARRAYSIZE(unicode_range_combining), ch)) {
            return 0;
        }
        if (utf8_in_range(unicode_range_wide, ARRAYSIZE(unicode_range_wide), ch)) {
            return 2;
        }
    }
    return 1;
}

#endif /* JIM_BOOTSTRAP */
