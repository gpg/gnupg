/* gettime.c - Wrapper for time functions
 *	Copyright (C) 1998, 2002 Free Software Foundation, Inc.
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
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#include "util.h"

static unsigned long timewarp;
static enum { NORMAL = 0, FROZEN, FUTURE, PAST } timemode;

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
      sprintf (timebuf,"%04d%02d%02dT%02d%02d%02d",
               1900 + tp->tm_year, tp->tm_mon+1, tp->tm_mday,
               tp->tm_hour, tp->tm_min, tp->tm_sec);
    }
}


/* set the time to NEWTIME so that gnupg_get_time returns a time
   starting with this one.  With FREEZE set to 1 the returned time
   will never change.  Just for completeness, a value of (time_t)-1
   for NEWTIME gets you back to rality. Note that this is obviously
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














