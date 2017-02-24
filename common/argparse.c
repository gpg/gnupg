/* [argparse.c wk 17.06.97] Argument Parser for option handling
 * Copyright (C) 1998-2001, 2006-2008, 2012 Free Software Foundation, Inc.
 * Copyright (C) 1997-2001, 2006-2008, 2013-2017 Werner Koch
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
 * if not, see <https://gnu.org/licenses/>.
 */

/* This file may be used as part of GnuPG or standalone.  A GnuPG
   build is detected by the presence of the macro GNUPG_MAJOR_VERSION.
   Some feature are only availalbe in the GnuPG build mode.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>

#ifdef GNUPG_MAJOR_VERSION
# include "util.h"
# include "common-defs.h"
# include "i18n.h"
# include "mischelp.h"
# include "stringhelp.h"
# include "logging.h"
# include "utf8conv.h"
#endif /*GNUPG_MAJOR_VERSION*/

#include "argparse.h"

/* GnuPG uses GPLv3+ but a standalone version of this defaults to
   GPLv2+ because that is the license of this file.  Change this if
   you include it in a program which uses GPLv3.  If you don't want to
   set a copyright string for your usage() you may also hardcode it
   here.  */
#ifndef GNUPG_MAJOR_VERSION

# define ARGPARSE_GPL_VERSION      2
# define ARGPARSE_CRIGHT_STR "Copyright (C) YEAR NAME"

#else /* Used by GnuPG  */

# define ARGPARSE_GPL_VERSION      3
# define ARGPARSE_CRIGHT_STR "Copyright (C) 2017 Free Software Foundation, Inc."

#endif /*GNUPG_MAJOR_VERSION*/

/* Replacements for standalone builds.  */
#ifndef GNUPG_MAJOR_VERSION
# ifndef _
#  define _(a)  (a)
# endif
# ifndef DIM
#  define DIM(v)           (sizeof(v)/sizeof((v)[0]))
# endif
# define xtrymalloc(a)    malloc ((a))
# define xtryrealloc(a,b) realloc ((a), (b))
# define xtrystrdup(a)    strdup ((a))
# define xfree(a)         free ((a))
# define log_error        my_log_error
# define log_bug	  my_log_bug
# define trim_spaces(a)   my_trim_spaces ((a))
# define map_static_macro_string(a)  (a)
#endif /*!GNUPG_MAJOR_VERSION*/


#define ARGPARSE_STR(v) #v
#define ARGPARSE_STR2(v) ARGPARSE_STR(v)


/* Replacements for standalone builds.  */
#ifndef GNUPG_MAJOR_VERSION
static void
my_log_error (const char *fmt, ...)
{
  va_list arg_ptr ;

  va_start (arg_ptr, fmt);
  fprintf (stderr, "%s: ", strusage (11));
  vfprintf (stderr, fmt, arg_ptr);
  va_end (arg_ptr);
}

static void
my_log_bug (const char *fmt, ...)
{
  va_list arg_ptr ;

  va_start (arg_ptr, fmt);
  fprintf (stderr, "%s: Ohhhh jeeee: ", strusage (11));
  vfprintf (stderr, fmt, arg_ptr);
  va_end (arg_ptr);
  abort ();
}

/* Return true if the native charset is utf-8.  */
static int
is_native_utf8 (void)
{
  return 1;
}

static char *
my_trim_spaces (char *str)
{
  char *string, *p, *mark;

  string = str;
  /* Find first non space character. */
  for (p=string; *p && isspace (*(unsigned char*)p) ; p++)
    ;
  /* Move characters. */
  for ((mark = NULL); (*string = *p); string++, p++)
    if (isspace (*(unsigned char*)p))
      {
        if (!mark)
          mark = string;
      }
    else
      mark = NULL;
  if (mark)
    *mark = '\0' ;  /* Remove trailing spaces. */

  return str ;
}

#endif /*!GNUPG_MAJOR_VERSION*/



/*********************************
 * @Summary arg_parse
 *  #include "argparse.h"
 *
 *  typedef struct {
 *	char *argc;		  pointer to argc (value subject to change)
 *	char ***argv;		  pointer to argv (value subject to change)
 *	unsigned flags; 	  Global flags (DO NOT CHANGE)
 *	int err;		  print error about last option
 *				  1 = warning, 2 = abort
 *	int r_opt;		  return option
 *	int r_type;		  type of return value (0 = no argument found)
 *	union {
 *	    int   ret_int;
 *	    long  ret_long
 *	    ulong ret_ulong;
 *	    char *ret_str;
 *	} r;			  Return values
 *	struct {
 *	    int idx;
 *	    const char *last;
 *	    void *aliases;
 *	} internal;		  DO NOT CHANGE
 *  } ARGPARSE_ARGS;
 *
 *  typedef struct {
 *	int	    short_opt;
 *	const char *long_opt;
 *	unsigned flags;
 *  } ARGPARSE_OPTS;
 *
 *  int arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts );
 *
 * @Description
 *  This is my replacement for getopt(). See the example for a typical usage.
 *  Global flags are:
 *     Bit 0 : Do not remove options form argv
 *     Bit 1 : Do not stop at last option but return other args
 *	       with r_opt set to -1.
 *     Bit 2 : Assume options and real args are mixed.
 *     Bit 3 : Do not use -- to stop option processing.
 *     Bit 4 : Do not skip the first arg.
 *     Bit 5 : allow usage of long option with only one dash
 *     Bit 6 : ignore --version
 *     all other bits must be set to zero, this value is modified by the
 *     function, so assume this is write only.
 *  Local flags (for each option):
 *     Bit 2-0 : 0 = does not take an argument
 *		 1 = takes int argument
 *		 2 = takes string argument
 *		 3 = takes long argument
 *		 4 = takes ulong argument
 *     Bit 3 : argument is optional (r_type will the be set to 0)
 *     Bit 4 : allow 0x etc. prefixed values.
 *     Bit 6 : Ignore this option
 *     Bit 7 : This is a command and not an option
 *  You stop the option processing by setting opts to NULL, the function will
 *  then return 0.
 * @Return Value
 *   Returns the args.r_opt or 0 if ready
 *   r_opt may be -2/-7 to indicate an unknown option/command.
 * @See Also
 *   ArgExpand
 * @Notes
 *  You do not need to process the options 'h', '--help' or '--version'
 *  because this function includes standard help processing; but if you
 *  specify '-h', '--help' or '--version' you have to do it yourself.
 *  The option '--' stops argument processing; if bit 1 is set the function
 *  continues to return normal arguments.
 *  To process float args or unsigned args you must use a string args and do
 *  the conversion yourself.
 * @Example
 *
 *     ARGPARSE_OPTS opts[] = {
 *     { 'v', "verbose",   0 },
 *     { 'd', "debug",     0 },
 *     { 'o', "output",    2 },
 *     { 'c', "cross-ref", 2|8 },
 *     { 'm', "my-option", 1|8 },
 *     { 300, "ignored-long-option, ARGPARSE_OP_IGNORE},
 *     { 500, "have-no-short-option-for-this-long-option", 0 },
 *     {0} };
 *     ARGPARSE_ARGS pargs = { &argc, &argv, 0 }
 *
 *     while( ArgParse( &pargs, &opts) ) {
 *	   switch( pargs.r_opt ) {
 *	     case 'v': opt.verbose++; break;
 *	     case 'd': opt.debug++; break;
 *	     case 'o': opt.outfile = pargs.r.ret_str; break;
 *	     case 'c': opt.crf = pargs.r_type? pargs.r.ret_str:"a.crf"; break;
 *	     case 'm': opt.myopt = pargs.r_type? pargs.r.ret_int : 1; break;
 *	     case 500: opt.a_long_one++;  break
 *	     default : pargs.err = 1; break; -- force warning output --
 *	   }
 *     }
 *     if( argc > 1 )
 *	   log_fatal( "Too many args");
 *
 */

typedef struct alias_def_s *ALIAS_DEF;
struct alias_def_s {
    ALIAS_DEF next;
    char *name;   /* malloced buffer with name, \0, value */
    const char *value; /* ptr into name */
};


/* Object to store the names for the --ignore-invalid-option option.
   This is a simple linked list.  */
typedef struct iio_item_def_s *IIO_ITEM_DEF;
struct iio_item_def_s
{
  IIO_ITEM_DEF next;
  char name[1];      /* String with the long option name.  */
};

static const char *(*strusage_handler)( int ) = NULL;
static int (*custom_outfnc) (int, const char *);

static int  set_opt_arg(ARGPARSE_ARGS *arg, unsigned flags, char *s);
static void show_help(ARGPARSE_OPTS *opts, unsigned flags);
static void show_version(void);
static int writestrings (int is_error, const char *string, ...)
#if __GNUC__ >= 4
  __attribute__ ((sentinel(0)))
#endif
  ;


void
argparse_register_outfnc (int (*fnc)(int, const char *))
{
  custom_outfnc = fnc;
}


/* Write STRING and all following const char * arguments either to
   stdout or, if IS_ERROR is set, to stderr.  The list of strings must
   be terminated by a NULL.  */
static int
writestrings (int is_error, const char *string, ...)
{
  va_list arg_ptr;
  const char *s;
  int count = 0;

  if (string)
    {
      s = string;
      va_start (arg_ptr, string);
      do
        {
          if (custom_outfnc)
            custom_outfnc (is_error? 2:1, s);
          else
            fputs (s, is_error? stderr : stdout);
          count += strlen (s);
        }
      while ((s = va_arg (arg_ptr, const char *)));
      va_end (arg_ptr);
    }
  return count;
}


static void
flushstrings (int is_error)
{
  if (custom_outfnc)
    custom_outfnc (is_error? 2:1, NULL);
  else
    fflush (is_error? stderr : stdout);
}


static void
initialize( ARGPARSE_ARGS *arg, const char *filename, unsigned *lineno )
{
  if( !(arg->flags & (1<<15)) )
    {
      /* Initialize this instance. */
      arg->internal.idx = 0;
      arg->internal.last = NULL;
      arg->internal.inarg = 0;
      arg->internal.stopped = 0;
      arg->internal.aliases = NULL;
      arg->internal.cur_alias = NULL;
      arg->internal.iio_list = NULL;
      arg->err = 0;
      arg->flags |= 1<<15; /* Mark as initialized.  */
      if ( *arg->argc < 0 )
        log_bug ("invalid argument for arg_parse\n");
    }


  if (arg->err)
    {
      /* Last option was erroneous.  */
      const char *s;

      if (filename)
        {
          if ( arg->r_opt == ARGPARSE_UNEXPECTED_ARG )
            s = _("argument not expected");
          else if ( arg->r_opt == ARGPARSE_READ_ERROR )
            s = _("read error");
          else if ( arg->r_opt == ARGPARSE_KEYWORD_TOO_LONG )
            s = _("keyword too long");
          else if ( arg->r_opt == ARGPARSE_MISSING_ARG )
            s = _("missing argument");
          else if ( arg->r_opt == ARGPARSE_INVALID_ARG )
            s = _("invalid argument");
          else if ( arg->r_opt == ARGPARSE_INVALID_COMMAND )
            s = _("invalid command");
          else if ( arg->r_opt == ARGPARSE_INVALID_ALIAS )
            s = _("invalid alias definition");
          else if ( arg->r_opt == ARGPARSE_OUT_OF_CORE )
            s = _("out of core");
          else
            s = _("invalid option");
          log_error ("%s:%u: %s\n", filename, *lineno, s);
	}
      else
        {
          s = arg->internal.last? arg->internal.last:"[??]";

          if ( arg->r_opt == ARGPARSE_MISSING_ARG )
            log_error (_("missing argument for option \"%.50s\"\n"), s);
          else if ( arg->r_opt == ARGPARSE_INVALID_ARG )
            log_error (_("invalid argument for option \"%.50s\"\n"), s);
          else if ( arg->r_opt == ARGPARSE_UNEXPECTED_ARG )
            log_error (_("option \"%.50s\" does not expect an argument\n"), s);
          else if ( arg->r_opt == ARGPARSE_INVALID_COMMAND )
            log_error (_("invalid command \"%.50s\"\n"), s);
          else if ( arg->r_opt == ARGPARSE_AMBIGUOUS_OPTION )
            log_error (_("option \"%.50s\" is ambiguous\n"), s);
          else if ( arg->r_opt == ARGPARSE_AMBIGUOUS_COMMAND )
            log_error (_("command \"%.50s\" is ambiguous\n"),s );
          else if ( arg->r_opt == ARGPARSE_OUT_OF_CORE )
            log_error ("%s\n", _("out of core\n"));
          else
            log_error (_("invalid option \"%.50s\"\n"), s);
	}
      if (arg->err != ARGPARSE_PRINT_WARNING)
        exit (2);
      arg->err = 0;
    }

  /* Zero out the return value union.  */
  arg->r.ret_str = NULL;
  arg->r.ret_long = 0;
}


static void
store_alias( ARGPARSE_ARGS *arg, char *name, char *value )
{
    /* TODO: replace this dummy function with a rea one
     * and fix the probelms IRIX has with (ALIAS_DEV)arg..
     * used as lvalue
     */
  (void)arg;
  (void)name;
  (void)value;
#if 0
    ALIAS_DEF a = xmalloc( sizeof *a );
    a->name = name;
    a->value = value;
    a->next = (ALIAS_DEF)arg->internal.aliases;
    (ALIAS_DEF)arg->internal.aliases = a;
#endif
}


/* Return true if KEYWORD is in the ignore-invalid-option list.  */
static int
ignore_invalid_option_p (ARGPARSE_ARGS *arg, const char *keyword)
{
  IIO_ITEM_DEF item = arg->internal.iio_list;

  for (; item; item = item->next)
    if (!strcmp (item->name, keyword))
      return 1;
  return 0;
}


/* Add the keywords up to the next LF to the list of to be ignored
   options.  After returning FP will either be at EOF or the next
   character read wll be the first of a new line.  The function
   returns 0 on success or true on malloc failure.  */
static int
ignore_invalid_option_add (ARGPARSE_ARGS *arg, FILE *fp)
{
  IIO_ITEM_DEF item;
  int c;
  char name[100];
  int namelen = 0;
  int ready = 0;
  enum { skipWS, collectNAME, skipNAME, addNAME} state = skipWS;

  while (!ready)
    {
      c = getc (fp);
      if (c == '\n')
        ready = 1;
      else if (c == EOF)
        {
          c = '\n';
          ready = 1;
        }
    again:
      switch (state)
        {
        case skipWS:
          if (!isascii (c) || !isspace(c))
            {
              namelen = 0;
              state = collectNAME;
              goto again;
            }
          break;

        case collectNAME:
          if (isspace (c))
            {
              state = addNAME;
              goto again;
            }
          else if (namelen < DIM(name)-1)
            name[namelen++] = c;
          else /* Too long.  */
            state = skipNAME;
          break;

        case skipNAME:
          if (isspace (c))
            {
              state = skipWS;
              goto again;
            }
          break;

        case addNAME:
          name[namelen] = 0;
          if (!ignore_invalid_option_p (arg, name))
            {
              item = xtrymalloc (sizeof *item + namelen);
              if (!item)
                return 1;
              strcpy (item->name, name);
              item->next = (IIO_ITEM_DEF)arg->internal.iio_list;
              arg->internal.iio_list = item;
            }
          state = skipWS;
          goto again;
        }
    }
  return 0;
}


/* Clear the entire ignore-invalid-option list.  */
static void
ignore_invalid_option_clear (ARGPARSE_ARGS *arg)
{
  IIO_ITEM_DEF item, tmpitem;

  for (item = arg->internal.iio_list; item; item = tmpitem)
    {
      tmpitem = item->next;
      xfree (item);
    }
  arg->internal.iio_list = NULL;
}



/****************
 * Get options from a file.
 * Lines starting with '#' are comment lines.
 * Syntax is simply a keyword and the argument.
 * Valid keywords are all keywords from the long_opt list without
 * the leading dashes. The special keywords "help", "warranty" and "version"
 * are not valid here.
 * The special keyword "alias" may be used to store alias definitions,
 * which are later expanded like long options.
 * The option
 *   ignore-invalid-option OPTIONNAMEs
 * is recognized and updates a list of option which should be ignored if they
 * are not defined.
 * Caller must free returned strings.
 * If called with FP set to NULL command line args are parse instead.
 *
 * Q: Should we allow the syntax
 *     keyword = value
 *    and accept for boolean options a value of 1/0, yes/no or true/false?
 * Note: Abbreviation of options is here not allowed.
 */
int
optfile_parse (FILE *fp, const char *filename, unsigned *lineno,
	       ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts)
{
  int state, i, c;
  int idx=0;
  char keyword[100];
  char *buffer = NULL;
  size_t buflen = 0;
  int in_alias=0;
  int unread_buf[3];  /* We use an int so that we can store EOF.  */
  int unread_buf_count = 0;

  if (!fp) /* Divert to arg_parse() in this case.  */
    return arg_parse (arg, opts);

  initialize (arg, filename, lineno);

  /* If the LINENO is zero we assume that we are at the start of a
   * file and we skip over a possible Byte Order Mark.  */
  if (!*lineno)
    {
      unread_buf[0] = getc (fp);
      unread_buf[1] = getc (fp);
      unread_buf[2] = getc (fp);
      if (unread_buf[0] != 0xef
          || unread_buf[1] != 0xbb
          || unread_buf[2] != 0xbf)
        unread_buf_count = 3;
    }

  /* Find the next keyword.  */
  state = i = 0;
  for (;;)
    {
      if (unread_buf_count)
        c = unread_buf[3 - unread_buf_count--];
      else
        c = getc (fp);
      if (c == '\n' || c== EOF )
        {
          if ( c != EOF )
            ++*lineno;
          if (state == -1)
            break;
          else if (state == 2)
            {
              keyword[i] = 0;
              for (i=0; opts[i].short_opt; i++ )
                {
                  if (opts[i].long_opt && !strcmp (opts[i].long_opt, keyword))
                    break;
                }
              idx = i;
              arg->r_opt = opts[idx].short_opt;
              if ((opts[idx].flags & ARGPARSE_OPT_IGNORE))
                {
                  state = i = 0;
                  continue;
                }
              else if (!opts[idx].short_opt )
                {
                  if (!strcmp (keyword, "ignore-invalid-option"))
                    {
                      /* No argument - ignore this meta option.  */
                      state = i = 0;
                      continue;
                    }
                  else if (ignore_invalid_option_p (arg, keyword))
                    {
                      /* This invalid option is in the iio list.  */
                      state = i = 0;
                      continue;
                    }
                  arg->r_opt = ((opts[idx].flags & ARGPARSE_OPT_COMMAND)
                                ? ARGPARSE_INVALID_COMMAND
                                : ARGPARSE_INVALID_OPTION);
                }
              else if (!(opts[idx].flags & ARGPARSE_TYPE_MASK))
                arg->r_type = 0; /* Does not take an arg. */
              else if ((opts[idx].flags & ARGPARSE_OPT_OPTIONAL) )
                arg->r_type = 0; /* Arg is optional.  */
              else
                arg->r_opt = ARGPARSE_MISSING_ARG;

              break;
	    }
          else if (state == 3)
            {
              /* No argument found.  */
              if (in_alias)
                arg->r_opt = ARGPARSE_MISSING_ARG;
              else if (!(opts[idx].flags & ARGPARSE_TYPE_MASK))
                arg->r_type = 0; /* Does not take an arg. */
              else if ((opts[idx].flags & ARGPARSE_OPT_OPTIONAL))
                arg->r_type = 0; /* No optional argument. */
              else
                arg->r_opt = ARGPARSE_MISSING_ARG;

              break;
	    }
          else if (state == 4)
            {
              /* Has an argument. */
              if (in_alias)
                {
                  if (!buffer)
                    arg->r_opt = ARGPARSE_UNEXPECTED_ARG;
                  else
                    {
                      char *p;

                      buffer[i] = 0;
                      p = strpbrk (buffer, " \t");
                      if (p)
                        {
                          *p++ = 0;
                          trim_spaces (p);
			}
                      if (!p || !*p)
                        {
                          xfree (buffer);
                          arg->r_opt = ARGPARSE_INVALID_ALIAS;
                        }
                      else
                        {
                          store_alias (arg, buffer, p);
                        }
		    }
		}
              else if (!(opts[idx].flags & ARGPARSE_TYPE_MASK))
                arg->r_opt = ARGPARSE_UNEXPECTED_ARG;
              else
                {
                  char *p;

                  if (!buffer)
                    {
                      keyword[i] = 0;
                      buffer = xtrystrdup (keyword);
                      if (!buffer)
                        arg->r_opt = ARGPARSE_OUT_OF_CORE;
		    }
                  else
                    buffer[i] = 0;

                  if (buffer)
                    {
                      trim_spaces (buffer);
                      p = buffer;
                      if (*p == '"')
                        {
                          /* Remove quotes. */
                          p++;
                          if (*p && p[strlen(p)-1] == '\"' )
                            p[strlen(p)-1] = 0;
                        }
                      if (!set_opt_arg (arg, opts[idx].flags, p))
                        xfree (buffer);
                      else
                        gpgrt_annotate_leaked_object (buffer);
                    }
                }
              break;
            }
          else if (c == EOF)
            {
              ignore_invalid_option_clear (arg);
              if (ferror (fp))
                arg->r_opt = ARGPARSE_READ_ERROR;
              else
                arg->r_opt = 0; /* EOF. */
              break;
            }
          state = 0;
          i = 0;
        }
      else if (state == -1)
        ; /* Skip. */
      else if (state == 0 && isascii (c) && isspace(c))
        ; /* Skip leading white space.  */
      else if (state == 0 && c == '#' )
        state = 1;	/* Start of a comment.  */
      else if (state == 1)
        ; /* Skip comments. */
      else if (state == 2 && isascii (c) && isspace(c))
        {
          /* Check keyword.  */
          keyword[i] = 0;
          for (i=0; opts[i].short_opt; i++ )
            if (opts[i].long_opt && !strcmp (opts[i].long_opt, keyword))
              break;
          idx = i;
          arg->r_opt = opts[idx].short_opt;
          if ((opts[idx].flags & ARGPARSE_OPT_IGNORE))
            {
              state = 1; /* Process like a comment.  */
            }
          else if (!opts[idx].short_opt)
            {
              if (!strcmp (keyword, "alias"))
                {
                  in_alias = 1;
                  state = 3;
                }
              else if (!strcmp (keyword, "ignore-invalid-option"))
                {
                  if (ignore_invalid_option_add (arg, fp))
                    {
                      arg->r_opt = ARGPARSE_OUT_OF_CORE;
                      break;
                    }
                  state = i = 0;
                  ++*lineno;
                }
              else if (ignore_invalid_option_p (arg, keyword))
                state = 1; /* Process like a comment.  */
              else
                {
                  arg->r_opt = ((opts[idx].flags & ARGPARSE_OPT_COMMAND)
                                ? ARGPARSE_INVALID_COMMAND
                                : ARGPARSE_INVALID_OPTION);
                  state = -1; /* Skip rest of line and leave.  */
                }
            }
          else
            state = 3;
        }
      else if (state == 3)
        {
          /* Skip leading spaces of the argument.  */
          if (!isascii (c) || !isspace(c))
            {
              i = 0;
              keyword[i++] = c;
              state = 4;
            }
        }
      else if (state == 4)
        {
          /* Collect the argument. */
          if (buffer)
            {
              if (i < buflen-1)
                buffer[i++] = c;
              else
                {
                  char *tmp;
                  size_t tmplen = buflen + 50;

                  tmp = xtryrealloc (buffer, tmplen);
                  if (tmp)
                    {
                      buflen = tmplen;
                      buffer = tmp;
                      buffer[i++] = c;
                    }
                  else
                    {
                      xfree (buffer);
                      arg->r_opt = ARGPARSE_OUT_OF_CORE;
                      break;
                    }
                }
            }
          else if (i < DIM(keyword)-1)
            keyword[i++] = c;
          else
            {
              size_t tmplen = DIM(keyword) + 50;
              buffer = xtrymalloc (tmplen);
              if (buffer)
                {
                  buflen = tmplen;
                  memcpy(buffer, keyword, i);
                  buffer[i++] = c;
                }
              else
                {
                  arg->r_opt = ARGPARSE_OUT_OF_CORE;
                  break;
                }
            }
        }
      else if (i >= DIM(keyword)-1)
        {
          arg->r_opt = ARGPARSE_KEYWORD_TOO_LONG;
          state = -1; /* Skip rest of line and leave.  */
        }
      else
        {
          keyword[i++] = c;
          state = 2;
        }
    }

  return arg->r_opt;
}



static int
find_long_option( ARGPARSE_ARGS *arg,
		  ARGPARSE_OPTS *opts, const char *keyword )
{
    int i;
    size_t n;

    (void)arg;

    /* Would be better if we can do a binary search, but it is not
       possible to reorder our option table because we would mess
       up our help strings - What we can do is: Build a nice option
       lookup table when this function is first invoked */
    if( !*keyword )
	return -1;
    for(i=0; opts[i].short_opt; i++ )
	if( opts[i].long_opt && !strcmp( opts[i].long_opt, keyword) )
	    return i;
#if 0
    {
	ALIAS_DEF a;
	/* see whether it is an alias */
	for( a = args->internal.aliases; a; a = a->next ) {
	    if( !strcmp( a->name, keyword) ) {
		/* todo: must parse the alias here */
		args->internal.cur_alias = a;
		return -3; /* alias available */
	    }
	}
    }
#endif
    /* not found, see whether it is an abbreviation */
    /* aliases may not be abbreviated */
    n = strlen( keyword );
    for(i=0; opts[i].short_opt; i++ ) {
	if( opts[i].long_opt && !strncmp( opts[i].long_opt, keyword, n ) ) {
	    int j;
	    for(j=i+1; opts[j].short_opt; j++ ) {
		if( opts[j].long_opt
		    && !strncmp( opts[j].long_opt, keyword, n )
                    && !(opts[j].short_opt == opts[i].short_opt
                         && opts[j].flags == opts[i].flags ) )
		    return -2;	/* abbreviation is ambiguous */
	    }
	    return i;
	}
    }
    return -1;  /* Not found.  */
}

int
arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts)
{
  int idx;
  int argc;
  char **argv;
  char *s, *s2;
  int i;

  initialize( arg, NULL, NULL );
  argc = *arg->argc;
  argv = *arg->argv;
  idx = arg->internal.idx;

  if (!idx && argc && !(arg->flags & ARGPARSE_FLAG_ARG0))
    {
      /* Skip the first argument.  */
      argc--; argv++; idx++;
    }

 next_one:
  if (!argc)
    {
      /* No more args.  */
      arg->r_opt = 0;
      goto leave; /* Ready. */
    }

  s = *argv;
  arg->internal.last = s;

  if (arg->internal.stopped && (arg->flags & ARGPARSE_FLAG_ALL))
    {
      arg->r_opt = ARGPARSE_IS_ARG;  /* Not an option but an argument.  */
      arg->r_type = 2;
      arg->r.ret_str = s;
      argc--; argv++; idx++; /* set to next one */
    }
  else if( arg->internal.stopped )
    {
      arg->r_opt = 0;
      goto leave; /* Ready.  */
    }
  else if ( *s == '-' && s[1] == '-' )
    {
      /* Long option.  */
      char *argpos;

      arg->internal.inarg = 0;
      if (!s[2] && !(arg->flags & ARGPARSE_FLAG_NOSTOP))
        {
          /* Stop option processing.  */
          arg->internal.stopped = 1;
          arg->flags |= ARGPARSE_FLAG_STOP_SEEN;
          argc--; argv++; idx++;
          goto next_one;
	}

      argpos = strchr( s+2, '=' );
      if ( argpos )
        *argpos = 0;
      i = find_long_option ( arg, opts, s+2 );
      if ( argpos )
        *argpos = '=';

      if ( i < 0 && !strcmp ( "help", s+2) )
        show_help (opts, arg->flags);
      else if ( i < 0 && !strcmp ( "version", s+2) )
        {
          if (!(arg->flags & ARGPARSE_FLAG_NOVERSION))
            {
              show_version ();
              exit(0);
            }
	}
      else if ( i < 0 && !strcmp( "warranty", s+2))
        {
          writestrings (0, strusage (16), "\n", NULL);
          exit (0);
	}
      else if ( i < 0 && !strcmp( "dump-options", s+2) )
        {
          for (i=0; opts[i].short_opt; i++ )
            {
              if (opts[i].long_opt && !(opts[i].flags & ARGPARSE_OPT_IGNORE))
                writestrings (0, "--", opts[i].long_opt, "\n", NULL);
	    }
          writestrings (0, "--dump-options\n--help\n--version\n--warranty\n",
                        NULL);
          exit (0);
	}

      if ( i == -2 )
        arg->r_opt = ARGPARSE_AMBIGUOUS_OPTION;
      else if ( i == -1 )
        {
          arg->r_opt = ARGPARSE_INVALID_OPTION;
          arg->r.ret_str = s+2;
	}
      else
        arg->r_opt = opts[i].short_opt;
      if ( i < 0 )
        ;
      else if ( (opts[i].flags & ARGPARSE_TYPE_MASK) )
        {
          if ( argpos )
            {
              s2 = argpos+1;
              if ( !*s2 )
                s2 = NULL;
	    }
          else
            s2 = argv[1];
          if ( !s2 && (opts[i].flags & ARGPARSE_OPT_OPTIONAL) )
            {
              arg->r_type = ARGPARSE_TYPE_NONE; /* Argument is optional.  */
	    }
          else if ( !s2 )
            {
              arg->r_opt = ARGPARSE_MISSING_ARG;
	    }
          else if ( !argpos && *s2 == '-'
                    && (opts[i].flags & ARGPARSE_OPT_OPTIONAL) )
            {
              /* The argument is optional and the next seems to be an
                 option.  We do not check this possible option but
                 assume no argument */
              arg->r_type = ARGPARSE_TYPE_NONE;
	    }
          else
            {
              set_opt_arg (arg, opts[i].flags, s2);
              if ( !argpos )
                {
                  argc--; argv++; idx++; /* Skip one.  */
		}
	    }
	}
      else
        {
          /* Does not take an argument. */
          if ( argpos )
            arg->r_type = ARGPARSE_UNEXPECTED_ARG;
          else
            arg->r_type = 0;
	}
      argc--; argv++; idx++; /* Set to next one.  */
    }
    else if ( (*s == '-' && s[1]) || arg->internal.inarg )
      {
        /* Short option.  */
	int dash_kludge = 0;

	i = 0;
	if ( !arg->internal.inarg )
          {
	    arg->internal.inarg++;
	    if ( (arg->flags & ARGPARSE_FLAG_ONEDASH) )
              {
                for (i=0; opts[i].short_opt; i++ )
                  if ( opts[i].long_opt && !strcmp (opts[i].long_opt, s+1))
                    {
                      dash_kludge = 1;
                      break;
		    }
              }
          }
	s += arg->internal.inarg;

	if (!dash_kludge )
          {
	    for (i=0; opts[i].short_opt; i++ )
              if ( opts[i].short_opt == *s )
                break;
          }

	if ( !opts[i].short_opt && ( *s == 'h' || *s == '?' ) )
          show_help (opts, arg->flags);

	arg->r_opt = opts[i].short_opt;
	if (!opts[i].short_opt )
          {
	    arg->r_opt = (opts[i].flags & ARGPARSE_OPT_COMMAND)?
              ARGPARSE_INVALID_COMMAND:ARGPARSE_INVALID_OPTION;
	    arg->internal.inarg++; /* Point to the next arg.  */
	    arg->r.ret_str = s;
          }
	else if ( (opts[i].flags & ARGPARSE_TYPE_MASK) )
          {
	    if ( s[1] && !dash_kludge )
              {
		s2 = s+1;
		set_opt_arg (arg, opts[i].flags, s2);
              }
	    else
              {
		s2 = argv[1];
		if ( !s2 && (opts[i].flags & ARGPARSE_OPT_OPTIONAL) )
                  {
		    arg->r_type = ARGPARSE_TYPE_NONE;
                  }
		else if ( !s2 )
                  {
		    arg->r_opt = ARGPARSE_MISSING_ARG;
                  }
		else if ( *s2 == '-' && s2[1]
                          && (opts[i].flags & ARGPARSE_OPT_OPTIONAL) )
                  {
		    /* The argument is optional and the next seems to
	               be an option.  We do not check this possible
	               option but assume no argument.  */
		    arg->r_type = ARGPARSE_TYPE_NONE;
                  }
		else
                  {
		    set_opt_arg (arg, opts[i].flags, s2);
		    argc--; argv++; idx++; /* Skip one.  */
                  }
              }
	    s = "x"; /* This is so that !s[1] yields false.  */
          }
	else
          {
            /* Does not take an argument.  */
	    arg->r_type = ARGPARSE_TYPE_NONE;
	    arg->internal.inarg++; /* Point to the next arg.  */
          }
	if ( !s[1] || dash_kludge )
          {
            /* No more concatenated short options.  */
	    arg->internal.inarg = 0;
	    argc--; argv++; idx++;
          }
      }
  else if ( arg->flags & ARGPARSE_FLAG_MIXED )
    {
      arg->r_opt = ARGPARSE_IS_ARG;
      arg->r_type = 2;
      arg->r.ret_str = s;
      argc--; argv++; idx++; /* Set to next one.  */
    }
  else
    {
      arg->internal.stopped = 1; /* Stop option processing.  */
      goto next_one;
    }

 leave:
  *arg->argc = argc;
  *arg->argv = argv;
  arg->internal.idx = idx;
  return arg->r_opt;
}


/* Returns: -1 on error, 0 for an integer type and 1 for a non integer
   type argument.  */
static int
set_opt_arg (ARGPARSE_ARGS *arg, unsigned flags, char *s)
{
  int base = (flags & ARGPARSE_OPT_PREFIX)? 0 : 10;
  long l;

  switch ( (arg->r_type = (flags & ARGPARSE_TYPE_MASK)) )
    {
    case ARGPARSE_TYPE_LONG:
    case ARGPARSE_TYPE_INT:
      errno = 0;
      l = strtol (s, NULL, base);
      if ((l == LONG_MIN || l == LONG_MAX) && errno == ERANGE)
        {
          arg->r_opt = ARGPARSE_INVALID_ARG;
          return -1;
        }
      if (arg->r_type == ARGPARSE_TYPE_LONG)
        arg->r.ret_long = l;
      else if ( (l < 0 && l < INT_MIN) || l > INT_MAX )
        {
          arg->r_opt = ARGPARSE_INVALID_ARG;
          return -1;
        }
      else
        arg->r.ret_int = (int)l;
      return 0;

    case ARGPARSE_TYPE_ULONG:
      while (isascii (*s) && isspace(*s))
        s++;
      if (*s == '-')
        {
          arg->r.ret_ulong = 0;
          arg->r_opt = ARGPARSE_INVALID_ARG;
          return -1;
        }
      errno = 0;
      arg->r.ret_ulong = strtoul (s, NULL, base);
      if (arg->r.ret_ulong == ULONG_MAX && errno == ERANGE)
        {
          arg->r_opt = ARGPARSE_INVALID_ARG;
          return -1;
        }
      return 0;

    case ARGPARSE_TYPE_STRING:
    default:
      arg->r.ret_str = s;
      return 1;
    }
}


static size_t
long_opt_strlen( ARGPARSE_OPTS *o )
{
  size_t n = strlen (o->long_opt);

  if ( o->description && *o->description == '|' )
    {
      const char *s;
      int is_utf8 = is_native_utf8 ();

      s=o->description+1;
      if ( *s != '=' )
        n++;
      /* For a (mostly) correct length calculation we exclude
         continuation bytes (10xxxxxx) if we are on a native utf8
         terminal. */
      for (; *s && *s != '|'; s++ )
        if ( is_utf8 && (*s&0xc0) != 0x80 )
          n++;
    }
  return n;
}


/****************
 * Print formatted help. The description string has some special
 * meanings:
 *  - A description string which is "@" suppresses help output for
 *    this option
 *  - a description,ine which starts with a '@' and is followed by
 *    any other characters is printed as is; this may be used for examples
 *    ans such.
 *  - A description which starts with a '|' outputs the string between this
 *    bar and the next one as arguments of the long option.
 */
static void
show_help (ARGPARSE_OPTS *opts, unsigned int flags)
{
  const char *s;
  char tmp[2];

  show_version ();
  writestrings (0, "\n", NULL);
  s = strusage (42);
  if (s && *s == '1')
    {
      s = strusage (40);
      writestrings (1, s, NULL);
      if (*s && s[strlen(s)] != '\n')
        writestrings (1, "\n", NULL);
    }
  s = strusage(41);
  writestrings (0, s, "\n", NULL);
  if ( opts[0].description )
    {
      /* Auto format the option description.  */
      int i,j, indent;

      /* Get max. length of long options.  */
      for (i=indent=0; opts[i].short_opt; i++ )
        {
          if ( opts[i].long_opt )
            if ( !opts[i].description || *opts[i].description != '@' )
              if ( (j=long_opt_strlen(opts+i)) > indent && j < 35 )
                indent = j;
	}

      /* Example: " -v, --verbose   Viele Sachen ausgeben" */
      indent += 10;
      if ( *opts[0].description != '@' )
        writestrings (0, "Options:", "\n", NULL);
      for (i=0; opts[i].short_opt; i++ )
        {
          s = map_static_macro_string (_( opts[i].description ));
          if ( s && *s== '@' && !s[1] ) /* Hide this line.  */
            continue;
          if ( s && *s == '@' )  /* Unindented comment only line.  */
            {
              for (s++; *s; s++ )
                {
                  if ( *s == '\n' )
                    {
                      if( s[1] )
                        writestrings (0, "\n", NULL);
		    }
                  else
                    {
                      tmp[0] = *s;
                      tmp[1] = 0;
                      writestrings (0, tmp, NULL);
                    }
                }
              writestrings (0, "\n", NULL);
              continue;
	    }

          j = 3;
          if ( opts[i].short_opt < 256 )
            {
              tmp[0] = opts[i].short_opt;
              tmp[1] = 0;
              writestrings (0, " -", tmp, NULL );
              if ( !opts[i].long_opt )
                {
                  if (s && *s == '|' )
                    {
                      writestrings (0, " ", NULL); j++;
                      for (s++ ; *s && *s != '|'; s++, j++ )
                        {
                          tmp[0] = *s;
                          tmp[1] = 0;
                          writestrings (0, tmp, NULL);
                        }
                      if ( *s )
                        s++;
		    }
		}
	    }
          else
            writestrings (0, "   ", NULL);
          if ( opts[i].long_opt )
            {
              tmp[0] = opts[i].short_opt < 256?',':' ';
              tmp[1] = 0;
              j += writestrings (0, tmp, " --", opts[i].long_opt, NULL);
              if (s && *s == '|' )
                {
                  if ( *++s != '=' )
                    {
                      writestrings (0, " ", NULL);
                      j++;
		    }
                  for ( ; *s && *s != '|'; s++, j++ )
                    {
                      tmp[0] = *s;
                      tmp[1] = 0;
                      writestrings (0, tmp, NULL);
                    }
                  if ( *s )
                    s++;
		}
              writestrings (0, "   ", NULL);
              j += 3;
	    }
          for (;j < indent; j++ )
            writestrings (0, " ", NULL);
          if ( s )
            {
              if ( *s && j > indent )
                {
                  writestrings (0, "\n", NULL);
                  for (j=0;j < indent; j++ )
                    writestrings (0, " ", NULL);
		}
              for (; *s; s++ )
                {
                  if ( *s == '\n' )
                    {
                      if ( s[1] )
                        {
                          writestrings (0, "\n", NULL);
                          for (j=0; j < indent; j++ )
                            writestrings (0, " ", NULL);
			}
		    }
                  else
                    {
                      tmp[0] = *s;
                      tmp[1] = 0;
                      writestrings (0, tmp, NULL);
                    }
		}
	    }
          writestrings (0, "\n", NULL);
	}
	if ( (flags & ARGPARSE_FLAG_ONEDASH) )
          writestrings (0, "\n(A single dash may be used "
                        "instead of the double ones)\n", NULL);
    }
  if ( (s=strusage(19)) )
    {
      writestrings (0, "\n", NULL);
      writestrings (0, s, NULL);
    }
  flushstrings (0);
  exit(0);
}

static void
show_version ()
{
  const char *s;
  int i;

  /* Version line.  */
  writestrings (0, strusage (11), NULL);
  if ((s=strusage (12)))
    writestrings (0, " (", s, ")", NULL);
  writestrings (0, " ", strusage (13), "\n", NULL);
  /* Additional version lines. */
  for (i=20; i < 30; i++)
    if ((s=strusage (i)))
      writestrings (0, s, "\n", NULL);
  /* Copyright string.  */
  if ((s=strusage (14)))
    writestrings (0, s, "\n", NULL);
  /* Licence string.  */
  if( (s=strusage (10)) )
    writestrings (0, s, "\n", NULL);
  /* Copying conditions. */
  if ( (s=strusage(15)) )
    writestrings (0, s, NULL);
  /* Thanks. */
  if ((s=strusage(18)))
    writestrings (0, s, NULL);
  /* Additional program info. */
  for (i=30; i < 40; i++ )
    if ( (s=strusage (i)) )
      writestrings (0, s, NULL);
  flushstrings (0);
}


void
usage (int level)
{
  const char *p;

  if (!level)
    {
      writestrings (1, strusage(11), " ", strusage(13), "; ",
                    strusage (14), "\n", NULL);
      flushstrings (1);
    }
  else if (level == 1)
    {
      p = strusage (40);
      writestrings (1, p, NULL);
      if (*p && p[strlen(p)] != '\n')
        writestrings (1, "\n", NULL);
      exit (2);
    }
  else if (level == 2)
    {
      p = strusage (42);
      if (p && *p == '1')
        {
          p = strusage (40);
          writestrings (1, p, NULL);
          if (*p && p[strlen(p)] != '\n')
            writestrings (1, "\n", NULL);
        }
      writestrings (0, strusage(41), "\n", NULL);
      exit (0);
    }
}

/* Level
 *     0: Print copyright string to stderr
 *     1: Print a short usage hint to stderr and terminate
 *     2: Print a long usage hint to stdout and terminate
 *    10: Return license info string
 *    11: Return the name of the program
 *    12: Return optional name of package which includes this program.
 *    13: version  string
 *    14: copyright string
 *    15: Short copying conditions (with LFs)
 *    16: Long copying conditions (with LFs)
 *    17: Optional printable OS name
 *    18: Optional thanks list (with LFs)
 *    19: Bug report info
 *20..29: Additional lib version strings.
 *30..39: Additional program info (with LFs)
 *    40: short usage note (with LF)
 *    41: long usage note (with LF)
 *    42: Flag string:
 *          First char is '1':
 *             The short usage notes needs to be printed
 *             before the long usage note.
 */
const char *
strusage( int level )
{
  const char *p = strusage_handler? strusage_handler(level) : NULL;

  if ( p )
    return map_static_macro_string (p);

  switch ( level )
    {

    case 10:
#if ARGPARSE_GPL_VERSION == 3
      p = ("License GPLv3+: GNU GPL version 3 or later "
           "<https://gnu.org/licenses/gpl.html>");
#else
      p = ("License GPLv2+: GNU GPL version 2 or later "
           "<https://gnu.org/licenses/>");
#endif
      break;
    case 11: p = "foo"; break;
    case 13: p = "0.0"; break;
    case 14: p = ARGPARSE_CRIGHT_STR; break;
    case 15: p =
"This is free software: you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n";
      break;
    case 16: p =
"This is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation; either version "
ARGPARSE_STR2(ARGPARSE_GPL_VERSION)
" of the License, or\n"
"(at your option) any later version.\n\n"
"It is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n\n"
"You should have received a copy of the GNU General Public License\n"
"along with this software.  If not, see <https://gnu.org/licenses/>.\n";
      break;
    case 40: /* short and long usage */
    case 41: p = ""; break;
    }

  return p;
}


/* Set the usage handler.  This function is basically a constructor.  */
void
set_strusage ( const char *(*f)( int ) )
{
  strusage_handler = f;
}


#ifdef TEST
static struct {
    int verbose;
    int debug;
    char *outfile;
    char *crf;
    int myopt;
    int echo;
    int a_long_one;
} opt;

int
main(int argc, char **argv)
{
  ARGPARSE_OPTS opts[] = {
    ARGPARSE_x('v', "verbose", NONE, 0, "Laut sein"),
    ARGPARSE_s_n('e', "echo"   , ("Zeile ausgeben, damit wir sehen, "
                                  "was wir eingegeben haben")),
    ARGPARSE_s_n('d', "debug", "Debug\nfalls mal etwas\nschief geht"),
    ARGPARSE_s_s('o', "output", 0 ),
    ARGPARSE_o_s('c', "cross-ref", "cross-reference erzeugen\n" ),
    /* Note that on a non-utf8 terminal the ß might garble the output. */
    ARGPARSE_s_n('s', "street","|Straße|set the name of the street to Straße"),
    ARGPARSE_o_i('m', "my-option", 0),
    ARGPARSE_s_n(500, "a-long-option", 0 ),
    ARGPARSE_end()
  };
  ARGPARSE_ARGS pargs = { &argc, &argv, (ARGPARSE_FLAG_ALL
                                         | ARGPARSE_FLAG_MIXED
                                         | ARGPARSE_FLAG_ONEDASH) };
  int i;

  while (arg_parse  (&pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case ARGPARSE_IS_ARG :
          printf ("arg='%s'\n", pargs.r.ret_str);
          break;
        case 'v': opt.verbose++; break;
        case 'e': opt.echo++; break;
        case 'd': opt.debug++; break;
        case 'o': opt.outfile = pargs.r.ret_str; break;
        case 'c': opt.crf = pargs.r_type? pargs.r.ret_str:"a.crf"; break;
        case 'm': opt.myopt = pargs.r_type? pargs.r.ret_int : 1; break;
        case 500: opt.a_long_one++;  break;
        default : pargs.err = ARGPARSE_PRINT_WARNING; break;
	}
    }
  for (i=0; i < argc; i++ )
    printf ("%3d -> (%s)\n", i, argv[i] );
  puts ("Options:");
  if (opt.verbose)
    printf ("  verbose=%d\n", opt.verbose );
  if (opt.debug)
    printf ("  debug=%d\n", opt.debug );
  if (opt.outfile)
    printf ("  outfile='%s'\n", opt.outfile );
  if (opt.crf)
    printf ("  crffile='%s'\n", opt.crf );
  if (opt.myopt)
    printf ("  myopt=%d\n", opt.myopt );
  if (opt.a_long_one)
    printf ("  a-long-one=%d\n", opt.a_long_one );
  if (opt.echo)
    printf ("  echo=%d\n", opt.echo );

  return 0;
}
#endif /*TEST*/

/**** bottom of file ****/
