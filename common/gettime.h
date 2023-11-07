/* gettime.h - Wrapper for time functions
 * Copyright (C) 2010, 2012 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_GETTIME_H
#define GNUPG_COMMON_GETTIME_H

#include <time.h>      /* We need time_t. */
#include <gpg-error.h> /* We need gpg_error_t. */
#include <stdint.h>    /* We use uint64_t.     */

/* A type to hold the ISO time.  Note that this is the same as
   the KSBA type ksba_isotime_t. */
typedef char gnupg_isotime_t[16];

/* Constant string of 16-byte, which is compatible to the type
   gnupg_iso_time_t.  */
#define GNUPG_ISOTIME_NONE \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#ifndef HAVE_TIMEGM
time_t timegm (struct tm *tm);
#endif /*!HAVE_TIMEGM*/
uint64_t timegm_u64 (struct tm *tm);

time_t gnupg_get_time (void);
struct tm *gnupg_gmtime (const time_t *timep, struct tm *result);
void   gnupg_get_isotime (gnupg_isotime_t timebuf);
void   gnupg_set_time (time_t newtime, int freeze);
int    gnupg_faked_time_p (void);
u32    make_timestamp (void);
char *elapsed_time_string (time_t since, time_t now);

u32    scan_secondsstr (const char *string);
u32    scan_isodatestr (const char *string);
int    isotime_p (const char *string);
int    isotime_human_p (const char *string, int date_only);
size_t string2isotime (gnupg_isotime_t atime, const char *string);
time_t isotime2epoch (const char *string);
uint64_t isotime2epoch_u64 (const char *string);
void   epoch2isotime (gnupg_isotime_t timebuf, time_t atime);
int    isodate_human_to_tm (const char *string, struct tm *t);
time_t parse_timestamp (const char *timestamp, char **endp);
u32    add_days_to_timestamp (u32 stamp, u16 days);
const char *strtimevalue (u32 stamp);
const char *strtimestamp (u32 stamp); /* GMT */
const char *isotimestamp (u32 stamp); /* GMT */
const char *asctimestamp (u32 stamp); /* localized */
char *rfctimestamp (u32 stamp);       /* RFC format, malloced. */
gpg_error_t add_seconds_to_isotime (gnupg_isotime_t atime, int nseconds);
gpg_error_t add_days_to_isotime (gnupg_isotime_t atime, int ndays);
gpg_error_t check_isotime (const gnupg_isotime_t atime);
void dump_isotime (const gnupg_isotime_t atime);
void gnupg_copy_time (gnupg_isotime_t d, const gnupg_isotime_t s);


#endif /*GNUPG_COMMON_GETTIME_H*/
