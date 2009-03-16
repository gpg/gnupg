/* gettime.c - Wrapper for time functions
 *	Copyright (C) 1998, 2002, 2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#include "util.h"
#include "i18n.h"

static unsigned long timewarp;
static enum { NORMAL = 0, FROZEN, FUTURE, PAST } timemode;

/* Correction used to map to real Julian days. */
#define JD_DIFF 1721060L


/* Wrapper for the time(3).  We use this here so we can fake the time
   for tests */
time_t 
gnupg_get_time () 
{
  time_t current = time (NULL);
  if (timemode == NORMAL)
    return current;
  else if (timemode == FROZEN)
    return timewarp;
  else if (timemode == FUTURE)
    return current + timewarp;
  else
    return current - timewarp;
}


/* Return the current time (possibly faked) in ISO format. */
void
gnupg_get_isotime (gnupg_isotime_t timebuf)
{
  time_t atime = gnupg_get_time ();
    
  if (atime < 0)
    *timebuf = 0;
  else 
    {
      struct tm *tp;
#ifdef HAVE_GMTIME_R
      struct tm tmbuf;
      
      tp = gmtime_r (&atime, &tmbuf);
#else
      tp = gmtime (&atime);
#endif
      snprintf (timebuf, 16, "%04d%02d%02dT%02d%02d%02d",
                1900 + tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                tp->tm_hour, tp->tm_min, tp->tm_sec);
    }
}


/* Set the time to NEWTIME so that gnupg_get_time returns a time
   starting with this one.  With FREEZE set to 1 the returned time
   will never change.  Just for completeness, a value of (time_t)-1
   for NEWTIME gets you back to reality.  Note that this is obviously
   not thread-safe but this is not required. */
void
gnupg_set_time (time_t newtime, int freeze)
{
  time_t current = time (NULL);

  if ( newtime == (time_t)-1 || current == newtime)
    {
      timemode = NORMAL;
      timewarp = 0;
    }
  else if (freeze)
    {
      timemode = FROZEN;
      timewarp = current;
    }
  else if (newtime > current)
    {
      timemode = FUTURE;
      timewarp = newtime - current;
    }
  else
    {
      timemode = PAST;
      timewarp = current - newtime;
    }
}

/* Returns true when we are in timewarp mode */
int
gnupg_faked_time_p (void)
{
  return timemode;
}


/* This function is used by gpg because OpenPGP defines the timestamp
   as an unsigned 32 bit value. */
u32 
make_timestamp (void)
{
  time_t t = gnupg_get_time ();

  if (t == (time_t)-1)
    log_fatal ("gnupg_get_time() failed\n");
  return (u32)t;
}



/****************
 * Scan a date string and return a timestamp.
 * The only supported format is "yyyy-mm-dd"
 * Returns 0 for an invalid date.
 */
u32
scan_isodatestr( const char *string )
{
    int year, month, day;
    struct tm tmbuf;
    time_t stamp;
    int i;

    if( strlen(string) != 10 || string[4] != '-' || string[7] != '-' )
	return 0;
    for( i=0; i < 4; i++ )
	if( !digitp (string+i) )
	    return 0;
    if( !digitp (string+5) || !digitp(string+6) )
	return 0;
    if( !digitp(string+8) || !digitp(string+9) )
	return 0;
    year = atoi(string);
    month = atoi(string+5);
    day = atoi(string+8);
    /* some basic checks */
    if( year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 )
	return 0;
    memset( &tmbuf, 0, sizeof tmbuf );
    tmbuf.tm_mday = day;
    tmbuf.tm_mon = month-1;
    tmbuf.tm_year = year - 1900;
    tmbuf.tm_isdst = -1;
    stamp = mktime( &tmbuf );
    if( stamp == (time_t)-1 )
	return 0;
    return stamp;
}

/* Scan am ISO timestamp and return an Epoch based timestamp.  The only
   supported format is "yyyymmddThhmmss" delimited by white space, nul, a
   colon or a comma.  Returns (time_t)(-1) for an invalid string.  */
time_t
isotime2epoch (const char *string)
{
  const char *s;
  int year, month, day, hour, minu, sec;
  struct tm tmbuf;
  int i;

  if (!*string)
    return (time_t)(-1);
  for (s=string, i=0; i < 8; i++, s++)
    if (!digitp (s))
      return (time_t)(-1);
  if (*s != 'T')
      return (time_t)(-1);
  for (s++, i=9; i < 15; i++, s++)
    if (!digitp (s))
      return (time_t)(-1);
  if ( !(!*s || (isascii (*s) && isspace(*s)) || *s == ':' || *s == ','))
    return (time_t)(-1);  /* Wrong delimiter.  */

  year  = atoi_4 (string);
  month = atoi_2 (string + 4);
  day   = atoi_2 (string + 6);
  hour  = atoi_2 (string + 9);
  minu  = atoi_2 (string + 11);
  sec   = atoi_2 (string + 13);

  /* Basic checks.  */
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31
      || hour > 23 || minu > 59 || sec > 61 )
    return (time_t)(-1);

  memset (&tmbuf, 0, sizeof tmbuf);
  tmbuf.tm_sec  = sec;
  tmbuf.tm_min  = minu;
  tmbuf.tm_hour = hour;
  tmbuf.tm_mday = day;
  tmbuf.tm_mon  = month-1;
  tmbuf.tm_year = year - 1900;
  tmbuf.tm_isdst = -1;
  return timegm (&tmbuf);
}


/* Convert an Epoch time to an iso time stamp. */
void
epoch2isotime (gnupg_isotime_t timebuf, time_t atime)
{
  if (atime < 0)
    *timebuf = 0;
  else 
    {
      struct tm *tp;
#ifdef HAVE_GMTIME_R
      struct tm tmbuf;
      
      tp = gmtime_r (&atime, &tmbuf);
#else
      tp = gmtime (&atime);
#endif
      snprintf (timebuf, 16, "%04d%02d%02dT%02d%02d%02d",
                1900 + tp->tm_year, tp->tm_mon+1, tp->tm_mday,
                tp->tm_hour, tp->tm_min, tp->tm_sec);
    }
}




u32
add_days_to_timestamp( u32 stamp, u16 days )
{
    return stamp + days*86400L;
}


/****************
 * Return a string with a time value in the form: x Y, n D, n H
 */

const char *
strtimevalue( u32 value )
{
    static char buffer[30];
    unsigned int years, days, hours, minutes;

    value /= 60;
    minutes = value % 60;
    value /= 60;
    hours = value % 24;
    value /= 24;
    days = value % 365;
    value /= 365;
    years = value;

    sprintf(buffer,"%uy%ud%uh%um", years, days, hours, minutes );
    if( years )
	return buffer;
    if( days )
	return strchr( buffer, 'y' ) + 1;
    return strchr( buffer, 'd' ) + 1;
}


/*
 * Note: this function returns GMT
 */
const char *
strtimestamp( u32 stamp )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = stamp;
    
    if (atime < 0) {
        strcpy (buffer, "????" "-??" "-??");
    }
    else {
        tp = gmtime( &atime );
        sprintf(buffer,"%04d-%02d-%02d",
                1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
    return buffer;
}


/*
 * Note: this function returns GMT
 */
const char *
isotimestamp (u32 stamp)
{
  static char buffer[25+5];
  struct tm *tp;
  time_t atime = stamp;
  
  if (atime < 0)
    {
      strcpy (buffer, "????" "-??" "-??" " " "??" ":" "??" ":" "??");
    }
  else
    {
      tp = gmtime ( &atime );
      sprintf (buffer,"%04d-%02d-%02d %02d:%02d:%02d",
               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
               tp->tm_hour, tp->tm_min, tp->tm_sec);
    }
  return buffer;
}


/****************
 * Note: this function returns local time
 */
const char *
asctimestamp( u32 stamp )
{
    static char buffer[50];
#if defined (HAVE_STRFTIME) && defined (HAVE_NL_LANGINFO)
      static char fmt[50];
#endif
    struct tm *tp;
    time_t atime = stamp;

    if (atime < 0) {
        strcpy (buffer, "????" "-??" "-??");
        return buffer;
    }

    tp = localtime( &atime );
#ifdef HAVE_STRFTIME
#if defined(HAVE_NL_LANGINFO)
      mem2str( fmt, nl_langinfo(D_T_FMT), DIM(fmt)-3 );
      if( strstr( fmt, "%Z" ) == NULL )
	strcat( fmt, " %Z");
      /* NOTE: gcc -Wformat-noliteral will complain here.  I have
         found no way to suppress this warning .*/
      strftime (buffer, DIM(buffer)-1, fmt, tp);
#else
      /* FIXME: we should check whether the locale appends a " %Z"
       * These locales from glibc don't put the " %Z":
       * fi_FI hr_HR ja_JP lt_LT lv_LV POSIX ru_RU ru_SU sv_FI sv_SE zh_CN
       */
      strftime( buffer, DIM(buffer)-1, "%c %Z", tp );
#endif
    buffer[DIM(buffer)-1] = 0;
#else
    mem2str( buffer, asctime(tp), DIM(buffer) );
#endif
    return buffer;
}



static int
days_per_year (int y)
{
  int s ;

  s = !(y % 4);
  if ( !(y % 100))
    if ((y%400))
      s = 0;
  return s ? 366 : 365;
}

static int
days_per_month (int y, int m)
{
  int s;
    
  switch(m)
    {
    case 1: case 3: case 5: case 7: case 8: case 10: case 12:
      return 31 ;
    case 2:
      s = !(y % 4);
      if (!(y % 100))
        if ((y % 400))
          s = 0;
      return s? 29 : 28 ;
    case 4: case 6: case 9: case 11:
      return 30;
    }
  BUG();
}


/* Convert YEAR, MONTH and DAY into the Julian date.  We assume that
   it is already noon.  We do not support dates before 1582-10-15. */
static unsigned long
date2jd (int year, int month, int day)
{
  unsigned long jd;

  jd = 365L * year + 31 * (month-1) + day + JD_DIFF;
  if (month < 3)
    year-- ;
  else
    jd -= (4 * month + 23) / 10;

  jd += year / 4 - ((year / 100 + 1) *3) / 4;

  return jd ;
}

/* Convert a Julian date back to YEAR, MONTH and DAY.  Return day of
   the year or 0 on error.  This function uses some more or less
   arbitrary limits, most important is that days before 1582 are not
   supported. */
static int
jd2date (unsigned long jd, int *year, int *month, int *day)
{
  int y, m, d;
  long delta;

  if (!jd)
    return 0 ;
  if (jd < 1721425 || jd > 2843085)
    return 0;

  y = (jd - JD_DIFF) / 366;
  d = m = 1;

  while ((delta = jd - date2jd (y, m, d)) > days_per_year (y))
    y++;

  m = (delta / 31) + 1;
  while( (delta = jd - date2jd (y, m, d)) > days_per_month (y,m))
    if (++m > 12)
      { 
        m = 1;
        y++;
      }

  d = delta + 1 ;
  if (d > days_per_month (y, m))
    { 
      d = 1;
      m++;
    }
  if (m > 12)
    { 
      m = 1;
      y++;
    }

  if (year)
    *year = y;
  if (month)
    *month = m;
  if (day)
    *day = d ;

  return (jd - date2jd (y, 1, 1)) + 1;
}


/* Check that the 15 bytes in ATIME represent a valid ISO time.  Note
   that this function does not expect a string but a plain 15 byte
   isotime buffer. */
gpg_error_t
check_isotime (const gnupg_isotime_t atime)
{
  int i;
  const char *s;

  if (!*atime)
    return gpg_error (GPG_ERR_NO_VALUE);
  
  for (s=atime, i=0; i < 8; i++, s++)
    if (!digitp (s))
      return gpg_error (GPG_ERR_INV_TIME);
  if (*s != 'T')
      return gpg_error (GPG_ERR_INV_TIME);
  for (s++, i=9; i < 15; i++, s++)
    if (!digitp (s))
      return gpg_error (GPG_ERR_INV_TIME);
  return 0;
}


void
dump_isotime (const gnupg_isotime_t t)
{
  if (!t || !*t)
    log_printf (_("[none]"));
  else
    log_printf ("%.4s-%.2s-%.2s %.2s:%.2s:%s",
                t, t+4, t+6, t+9, t+11, t+13);
}


/* Add SECONDS to ATIME.  SECONDS may not be negative and is limited
   to about the equivalent of 62 years which should be more then
   enough for our purposes. */
gpg_error_t
add_seconds_to_isotime (gnupg_isotime_t atime, int nseconds)
{
  gpg_error_t err;
  int year, month, day, hour, minute, sec, ndays;
  unsigned long jd;

  err = check_isotime (atime);
  if (err)
    return err;

  if (nseconds < 0 || nseconds >= (0x7fffffff - 61) )
    return gpg_error (GPG_ERR_INV_VALUE);

  year  = atoi_4 (atime+0);
  month = atoi_2 (atime+4);
  day   = atoi_2 (atime+6);
  hour  = atoi_2 (atime+9);
  minute= atoi_2 (atime+11);
  sec   = atoi_2 (atime+13);

  if (year <= 1582) /* The julian date functions don't support this. */
    return gpg_error (GPG_ERR_INV_VALUE); 

  sec    += nseconds;
  minute += sec/60;
  sec    %= 60;
  hour   += minute/60;
  minute %= 60;
  ndays  = hour/24;
  hour   %= 24;
  
  jd = date2jd (year, month, day) + ndays;
  jd2date (jd, &year, &month, &day);

  if (year > 9999 || month > 12 || day > 31
      || year < 0 || month < 1 || day < 1)
    return gpg_error (GPG_ERR_INV_VALUE); 
    
  snprintf (atime, 16, "%04d%02d%02dT%02d%02d%02d",
            year, month, day, hour, minute, sec);
  return 0;
}


gpg_error_t
add_days_to_isotime (gnupg_isotime_t atime, int ndays)
{
  gpg_error_t err;
  int year, month, day, hour, minute, sec;
  unsigned long jd;

  err = check_isotime (atime);
  if (err)
    return err;

  if (ndays < 0 || ndays >= 9999*366 )
    return gpg_error (GPG_ERR_INV_VALUE);

  year  = atoi_4 (atime+0);
  month = atoi_2 (atime+4);
  day   = atoi_2 (atime+6);
  hour  = atoi_2 (atime+9);
  minute= atoi_2 (atime+11);
  sec   = atoi_2 (atime+13);

  if (year <= 1582) /* The julian date functions don't support this. */
    return gpg_error (GPG_ERR_INV_VALUE); 

  jd = date2jd (year, month, day) + ndays;
  jd2date (jd, &year, &month, &day);

  if (year > 9999 || month > 12 || day > 31
      || year < 0 || month < 1 || day < 1)
    return gpg_error (GPG_ERR_INV_VALUE); 
    
  snprintf (atime, 16, "%04d%02d%02dT%02d%02d%02d",
            year, month, day, hour, minute, sec);
  return 0;
}
