/* argparse.h - Argument parser for option handling.
 *	Copyright (C) 1998,1999,2000,2001,2006 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_ARGPARSE_H
#define GNUPG_COMMON_ARGPARSE_H

#include <stdio.h>
#include <gpg-error.h>

#if GPGRT_VERSION_NUMBER < 0x012600 /* 1.38 */

#define USE_INTERNAL_ARGPARSE 1

/* We use a copy of the code from the new gpgrt parser.  */

struct _argparse_internal_s;
typedef struct
{
  int  *argc;	      /* Pointer to ARGC (value subject to change). */
  char ***argv;	      /* Pointer to ARGV (value subject to change). */
  unsigned int flags; /* Global flags.  May be set prior to calling the
                         parser.  The parser may change the value.  */
  int err;            /* Print error description for last option.
                         Either 0,  ARGPARSE_PRINT_WARNING or
                         ARGPARSE_PRINT_ERROR.  */
  unsigned int lineno;/* The current line number.  */
  int r_opt; 	      /* Returns option code. */
  int r_type;	      /* Returns type of option value.  */
  union {
    int   ret_int;
    long  ret_long;
    unsigned long ret_ulong;
    char *ret_str;
  } r;		      /* Return values */

  struct _argparse_internal_s *internal;
} gnupg_argparse_t;


typedef struct
{
  int          short_opt;
  const char  *long_opt;
  unsigned int flags;
  const char  *description; /* Optional option description. */
} gnupg_opt_t;


typedef gnupg_argparse_t ARGPARSE_ARGS;
typedef gnupg_opt_t      ARGPARSE_OPTS;

/* Short options.  */
#define ARGPARSE_SHORTOPT_HELP 32768
#define ARGPARSE_SHORTOPT_VERSION 32769
#define ARGPARSE_SHORTOPT_WARRANTY 32770
#define ARGPARSE_SHORTOPT_DUMP_OPTIONS 32771


/* Global flags (ARGPARSE_ARGS).  */
#define ARGPARSE_FLAG_KEEP       1   /* Do not remove options form argv.     */
#define ARGPARSE_FLAG_ALL        2   /* Do not stop at last option but return
                                        remaining args with R_OPT set to -1. */
#define ARGPARSE_FLAG_MIXED      4   /* Assume options and args are mixed.   */
#define ARGPARSE_FLAG_NOSTOP     8   /* Do not stop processing at "--".      */
#define ARGPARSE_FLAG_ARG0      16   /* Do not skip the first arg.           */
#define ARGPARSE_FLAG_ONEDASH   32   /* Allow long options with one dash.    */
#define ARGPARSE_FLAG_NOVERSION 64   /* No output for "--version".           */
#define ARGPARSE_FLAG_RESET     128  /* Request to reset the internal state. */
#define ARGPARSE_FLAG_STOP_SEEN 256  /* Set to true if a "--" has been seen. */
#define ARGPARSE_FLAG_NOLINENO  512  /* Do not zero the lineno field.        */
#define ARGPARSE_FLAG_SYS      1024  /* Use system config file.              */
#define ARGPARSE_FLAG_USER     2048  /* Use user config file.                */
#define ARGPARSE_FLAG_VERBOSE  4096  /* Print additional argparser info.     */
#define ARGPARSE_FLAG_USERVERS 8192  /* Try version-ed user config files.    */
#define ARGPARSE_FLAG_WITHATTR 16384 /* Return attribute bits.               */

/* Flags for each option (ARGPARSE_OPTS).  The type code may be
   ORed with the OPT flags.  */
#define ARGPARSE_TYPE_NONE        0  /* Does not take an argument.        */
#define ARGPARSE_TYPE_INT         1  /* Takes an int argument.            */
#define ARGPARSE_TYPE_STRING      2  /* Takes a string argument.          */
#define ARGPARSE_TYPE_LONG        3  /* Takes a long argument.            */
#define ARGPARSE_TYPE_ULONG       4  /* Takes an unsigned long argument.  */
#define ARGPARSE_OPT_OPTIONAL (1<<3) /* Argument is optional.             */
#define ARGPARSE_OPT_PREFIX   (1<<4) /* Allow 0x etc. prefixed values.    */
#define ARGPARSE_OPT_IGNORE   (1<<6) /* Ignore command or option.         */
#define ARGPARSE_OPT_COMMAND  (1<<7) /* The argument is a command.        */
#define ARGPARSE_OPT_CONFFILE (1<<8) /* The value is a conffile.          */
#define ARGPARSE_OPT_HEADER   (1<<9) /* The value is printed as a header. */
#define ARGPARSE_OPT_VERBATIM (1<<10)/* The value is printed verbatim.    */
#define ARGPARSE_ATTR_FORCE   (1<<14)/* Attribute force is set.           */
#define ARGPARSE_ATTR_IGNORE  (1<<15)/* Attribute ignore is set.          */

#define ARGPARSE_TYPE_MASK  7  /* Mask for the type values (internal).  */

/* A set of macros to make option definitions easier to read.  */
#define ARGPARSE_x(s,l,t,f,d) \
     { (s), (l), ARGPARSE_TYPE_ ## t | (f), (d) }

#define ARGPARSE_s(s,l,t,d) \
     { (s), (l), ARGPARSE_TYPE_ ## t, (d) }
#define ARGPARSE_s_n(s,l,d) \
     { (s), (l), ARGPARSE_TYPE_NONE, (d) }
#define ARGPARSE_s_i(s,l,d) \
     { (s), (l), ARGPARSE_TYPE_INT, (d) }
#define ARGPARSE_s_s(s,l,d) \
     { (s), (l), ARGPARSE_TYPE_STRING, (d) }
#define ARGPARSE_s_l(s,l,d) \
     { (s), (l), ARGPARSE_TYPE_LONG, (d) }
#define ARGPARSE_s_u(s,l,d) \
     { (s), (l), ARGPARSE_TYPE_ULONG, (d) }

#define ARGPARSE_o(s,l,t,d) \
     { (s), (l), (ARGPARSE_TYPE_ ## t  | ARGPARSE_OPT_OPTIONAL), (d) }
#define ARGPARSE_o_n(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_NONE   | ARGPARSE_OPT_OPTIONAL), (d) }
#define ARGPARSE_o_i(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_INT    | ARGPARSE_OPT_OPTIONAL), (d) }
#define ARGPARSE_o_s(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_STRING | ARGPARSE_OPT_OPTIONAL), (d) }
#define ARGPARSE_o_l(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_LONG   | ARGPARSE_OPT_OPTIONAL), (d) }
#define ARGPARSE_o_u(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_ULONG  | ARGPARSE_OPT_OPTIONAL), (d) }

#define ARGPARSE_p(s,l,t,d) \
     { (s), (l), (ARGPARSE_TYPE_ ## t  | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_p_n(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_NONE   | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_p_i(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_INT    | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_p_s(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_STRING | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_p_l(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_LONG   | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_p_u(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_ULONG  | ARGPARSE_OPT_PREFIX), (d) }

#define ARGPARSE_op(s,l,t,d) \
     { (s), (l), (ARGPARSE_TYPE_ ## t \
                  | ARGPARSE_OPT_OPTIONAL | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_op_n(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_NONE \
                  | ARGPARSE_OPT_OPTIONAL | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_op_i(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_INT \
                  | ARGPARSE_OPT_OPTIONAL | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_op_s(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_STRING \
                  | ARGPARSE_OPT_OPTIONAL | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_op_l(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_LONG \
                  | ARGPARSE_OPT_OPTIONAL | ARGPARSE_OPT_PREFIX), (d) }
#define ARGPARSE_op_u(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_ULONG \
                  | ARGPARSE_OPT_OPTIONAL | ARGPARSE_OPT_PREFIX), (d) }

#define ARGPARSE_c(s,l,d) \
     { (s), (l), (ARGPARSE_TYPE_NONE | ARGPARSE_OPT_COMMAND), (d) }

#define ARGPARSE_conffile(s,l,d) \
  { (s), (l), (ARGPARSE_TYPE_STRING|ARGPARSE_OPT_CONFFILE), (d) }

#define ARGPARSE_noconffile(s,l,d) \
  { (s), (l), (ARGPARSE_TYPE_NONE|ARGPARSE_OPT_CONFFILE), (d) }

#define ARGPARSE_ignore(s,l) \
     { (s), (l), (ARGPARSE_OPT_IGNORE), "@" }

#define ARGPARSE_group(s,d) \
     { (s), NULL, 0, (d) }

/* Verbatim print the string D in the help output.  It does not make
 * use of the "@" hack as ARGPARSE_group does.  */
#define ARGPARSE_verbatim(d) \
  { 1, NULL, (ARGPARSE_OPT_VERBATIM), (d) }

/* Same as ARGPARSE_verbatim but also print a colon and a LF.  N can
 * be used give a symbolic name to the header.  Nothing is printed if
 * D is the empty string.  */
#define ARGPARSE_header(n,d) \
  { 1, (n), (ARGPARSE_OPT_HEADER), (d) }

/* Mark the end of the list (mandatory).  */
#define ARGPARSE_end() \
  { 0, NULL, 0, NULL }


/* Other constants.  */
#define ARGPARSE_PRINT_WARNING  1
#define ARGPARSE_PRINT_ERROR    2


/* Error values.  */
#define ARGPARSE_IS_ARG            (-1)
#define ARGPARSE_INVALID_OPTION    (-2)
#define ARGPARSE_MISSING_ARG       (-3)
#define ARGPARSE_KEYWORD_TOO_LONG  (-4)
#define ARGPARSE_READ_ERROR        (-5)
#define ARGPARSE_UNEXPECTED_ARG    (-6)
#define ARGPARSE_INVALID_COMMAND   (-7)
#define ARGPARSE_AMBIGUOUS_OPTION  (-8)
#define ARGPARSE_AMBIGUOUS_COMMAND (-9)
#define ARGPARSE_INVALID_ALIAS     (-10)
#define ARGPARSE_OUT_OF_CORE       (-11)
#define ARGPARSE_INVALID_ARG       (-12)
#define ARGPARSE_PERMISSION_ERROR  (-13)
#define ARGPARSE_NO_CONFFILE       (-14)
#define ARGPARSE_CONFFILE          (-15)
#define ARGPARSE_INVALID_META      (-16)
#define ARGPARSE_UNKNOWN_META      (-17)
#define ARGPARSE_UNEXPECTED_META   (-18)

/* Values used for gnupg_set_confdir.  */
#define GNUPG_CONFDIR_USER 1   /* The user's configuration dir.    */
#define GNUPG_CONFDIR_SYS  2   /* The systems's configuration dir. */

/* Take care: gpgrt_argparse keeps state in ARG and requires that
 * either ARGPARSE_FLAG_RESET is used after OPTS has been changed or
 * gpgrt_argparse (NULL, ARG, NULL) is called first.  */
int gnupg_argparse (gpgrt_stream_t fp,
                    gnupg_argparse_t *arg, gnupg_opt_t *opts);
int gnupg_argparser (gnupg_argparse_t *arg, gnupg_opt_t *opts,
                     const char *confname);

const char *strusage (int level);
void set_strusage (const char *(*f)( int ));
void gnupg_set_usage_outfnc (int (*f)(int, const char *));
void gnupg_set_fixed_string_mapper (const char *(*f)(const char*));
void gnupg_set_confdir (int what, const char *name);

#else /* !USE_INTERNAL_ARGPARSE */

#define GNUPG_CONFDIR_USER GPGRT_CONFDIR_USER
#define GNUPG_CONFDIR_SYS  GPGRT_CONFDIR_SYS

typedef gpgrt_argparse_t gnupg_argparse_t;
typedef gpgrt_opt_t      gnupg_opt_t;
typedef gpgrt_argparse_t ARGPARSE_ARGS;
typedef gpgrt_opt_t      ARGPARSE_OPTS;

#define gnupg_argparse(a,b,c)            gpgrt_argparse ((a),(b),(c))
#define gnupg_argparser(a,b,c)           gpgrt_argparser ((a),(b),(c))
#define strusage(a)                      gpgrt_strusage (a)
#define set_strusage(a)                  gpgrt_set_strusage (a)
#define gnupg_set_usage_outfnc(a)        gpgrt_set_usage_outfnc ((a))
#define gnupg_set_fixed_string_mapper(a) gpgrt_set_fixed_string_mapper ((a))
#define gnupg_set_confdir(a,b)           gpgrt_set_confdir ((a),(b))

#endif /* !USE_INTERNAL_ARGPARSE */

void usage (int level);

#endif /*GNUPG_COMMON_ARGPARSE_H*/
