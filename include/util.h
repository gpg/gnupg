/* util.h
 *	Copyright (C) 1998,1999 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef GPG_UTIL_H
#define GPG_UTIL_H

#ifdef _GCRYPT_IN_LIBGCRYPT
  #error This header should not be used internally by libgcrypt
#endif

#include <stdio.h>
#include "types.h"
#include "errors.h"
#include "../jnlib/mischelp.h"
#include "../jnlib/stringhelp.h"
#include "../jnlib/argparse.h"
#include "../jnlib/dotlock.h"


/*-- logger.c --*/
void log_set_logfile( const char *name, int fd );
FILE *log_stream(void);
void gpg_log_print_prefix(const char *text);
void log_set_name( const char *name );
const char *log_get_name(void);
void log_set_pid( int pid );
int  log_get_errorcount( int clear );
void gpg_log_hexdump( const char *text, const char *buf, size_t len );

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
  void gpg_log_bug( const char *fmt, ... )
			    __attribute__ ((noreturn, format (printf,1,2)));
  void gpg_log_bug0( const char *, int, const char * ) __attribute__ ((noreturn));
  void gpg_log_fatal( const char *fmt, ... )
			    __attribute__ ((noreturn, format (printf,1,2)));
  void gpg_log_error( const char *fmt, ... ) __attribute__ ((format (printf,1,2)));
  void gpg_log_info( const char *fmt, ... )  __attribute__ ((format (printf,1,2)));
  void gpg_log_debug( const char *fmt, ... ) __attribute__ ((format (printf,1,2)));
  void gpg_log_fatal_f( const char *fname, const char *fmt, ... )
			    __attribute__ ((noreturn, format (printf,2,3)));
  void gpg_log_error_f( const char *fname, const char *fmt, ... )
			    __attribute__ ((format (printf,2,3)));
  void gpg_log_info_f( const char *fname, const char *fmt, ... )
			    __attribute__ ((format (printf,2,3)));
  void gpg_log_debug_f( const char *fname,  const char *fmt, ... )
			    __attribute__ ((format (printf,2,3)));
  #define BUG() gpg_log_bug0(  __FILE__ , __LINE__, __FUNCTION__ )
#else
  void gpg_log_bug( const char *fmt, ... );
  void gpg_log_bug0( const char *, int );
  void gpg_log_fatal( const char *fmt, ... );
  void gpg_log_error( const char *fmt, ... );
  void gpg_log_info( const char *fmt, ... );
  void gpg_log_debug( const char *fmt, ... );
  void gpg_log_fatal_f( const char *fname, const char *fmt, ... );
  void gpg_log_error_f( const char *fname, const char *fmt, ... );
  void gpg_log_info_f( const char *fname, const char *fmt, ... );
  void gpg_log_debug_f( const char *fname, const char *fmt, ... );
  #define BUG() gpg_log_bug0( __FILE__ , __LINE__ )
#endif

#define log_hexdump gpg_log_hexdump
#define log_bug     gpg_log_bug
#define log_bug0    gpg_log_bug0
#define log_fatal   gpg_log_fatal
#define log_error   gpg_log_error
#define log_info    gpg_log_info
#define log_debug   gpg_log_debug
#define log_fatal_f gpg_log_fatal_f
#define log_error_f gpg_log_error_f
#define log_info_f  gpg_log_info_f
#define log_debug_f gpg_log_debug_f


/*-- errors.c --*/
const char * gpg_errstr( int no );



/*-- fileutil.c --*/
char * make_basename(const char *filepath);
char * make_dirname(const char *filepath);
char *make_filename( const char *first_part, ... );
int compare_filenames( const char *a, const char *b );
const char *print_fname_stdin( const char *s );
const char *print_fname_stdout( const char *s );


/*-- miscutil.c --*/
u32 make_timestamp(void);
u32 scan_isodatestr( const char *string );
u32 add_days_to_timestamp( u32 stamp, u16 days );
const char *strtimevalue( u32 stamp );
const char *strtimestamp( u32 stamp ); /* GMT */
const char *asctimestamp( u32 stamp ); /* localized */
void print_string( FILE *fp, const byte *p, size_t n, int delim );
void  print_utf8_string( FILE *fp, const byte *p, size_t n );
char *make_printable_string( const byte *p, size_t n, int delim );
int answer_is_yes( const char *s );
int answer_is_yes_no_quit( const char *s );

/*-- strgutil.c --*/
void free_strlist( STRLIST sl );
#define FREE_STRLIST(a) do { free_strlist((a)); (a) = NULL ; } while(0)
STRLIST add_to_strlist( STRLIST *list, const char *string );
STRLIST add_to_strlist2( STRLIST *list, const char *string, int is_utf8 );
STRLIST append_to_strlist( STRLIST *list, const char *string );
STRLIST append_to_strlist2( STRLIST *list, const char *string, int is_utf8 );
STRLIST strlist_prev( STRLIST head, STRLIST node );
STRLIST strlist_last( STRLIST node );
int string_count_chr( const char *string, int c );
int set_native_charset( const char *newset );
const char* get_native_charset(void);
char *native_to_utf8( const char *string );
char *utf8_to_native( const char *string, size_t length );
int  check_utf8_string( const char *string );


/**** other missing stuff ****/
#ifndef HAVE_ATEXIT  /* For SunOS */
  #define atexit(a)    (on_exit((a),0))
#endif

#ifndef HAVE_RAISE
  #define raise(a) kill(getpid(), (a))
#endif

/******** some macros ************/
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

#endif /*GPG_UTIL_H*/
