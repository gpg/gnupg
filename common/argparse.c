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

/* This is a modified version of gpgrt/libgpg-error src/argparse.c.
 * We use this to require a dependency on a newer gpgrt version.
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
#include <unistd.h>
#include <time.h>

#include "util.h"
#include "common-defs.h"
#include "i18n.h"
#include "mischelp.h"
#include "stringhelp.h"
#include "logging.h"
#include "utf8conv.h"
#include "sysutils.h"
#include "argparse.h"


/* Optional handler to write strings.  See gnupg_set_usage_outfnc.  */
static int (*custom_outfnc) (int, const char *);


#if USE_INTERNAL_ARGPARSE

/* The almost always needed user handler for strusage.  */
static const char *(*strusage_handler)( int ) = NULL;
/* Optional handler to map strings.  See gnupg_set_fixed_string_mapper.  */
static const char *(*fixed_string_mapper)(const char*);


/* Hidden argparse flag used to mark the object as initialized.  */
#define ARGPARSE_FLAG__INITIALIZED  (1u << ((8*4)-1))

/* Special short options which are auto-inserterd.  Must fit into an
 * unsigned short.  */
#define ARGPARSE_SHORTOPT_HELP 32768
#define ARGPARSE_SHORTOPT_VERSION 32769
#define ARGPARSE_SHORTOPT_WARRANTY 32770
#define ARGPARSE_SHORTOPT_DUMP_OPTIONS 32771
#define ARGPARSE_SHORTOPT_DUMP_OPTTBL 32772


/* The malloced configuration directories or NULL.  */
static struct
{
  char *user;
  char *sys;
} confdir;


/* The states for the gnupg_argparser machinery.  */
enum argparser_states
  {
   STATE_init = 0,
   STATE_open_sys,
   STATE_open_user,
   STATE_open_cmdline,
   STATE_read_sys,
   STATE_read_user,
   STATE_read_cmdline,
   STATE_finished
  };


/* An internal object used to store the user provided option table and
 * some meta information.  */
typedef struct
{
  unsigned short short_opt;
  unsigned short ordinal;     /* (for --help)  */
  unsigned int   flags;
  const char    *long_opt;    /* Points into the user provided table. */
  const char    *description; /* Points into the user provided table. */
  unsigned int   forced:1;    /* Forced to use the sysconf value.  */
  unsigned int   ignore:1;    /* Ignore this option everywhere but in
                               * the sysconf file.  */
  unsigned int   explicit_ignore:1; /* Ignore was explicitly set.  */
} opttable_t;


/* Internal object of the public gnupg_argparse_t object.  */
struct _argparse_internal_s
{
  int idx;   /* Note that this is saved and restored in gnupg_argparser. */
  int inarg;                       /* (index into args) */
  unsigned int verbose:1;          /* Print diagnostics.                */
  unsigned int stopped:1;          /* Option processing has stopped.    */
  unsigned int in_sysconf:1;       /* Processing global config file.    */
  unsigned int mark_forced:1;      /* Mark options as forced.           */
  unsigned int mark_ignore:1;      /* Mark options as to be ignored.    */
  unsigned int explicit_ignore:1;  /* Option has explicitly been set
                                    * to ignore or unignore.  */
  unsigned int ignore_all_seen:1;  /* [ignore-all] has been seen.       */
  unsigned int user_seen:1;        /* A [user] has been seen.           */
  unsigned int user_wildcard:1;    /* A [user *] has been seen.         */
  unsigned int user_any_active:1;  /* Any user section was active.      */
  unsigned int user_active:1;      /* User section active.              */
  unsigned int explicit_confopt:1; /* A conffile option has been given. */
  char *explicit_conffile;         /* Malloced name of an explicit
                                    * conffile. */
  char *username;                  /* Malloced current user name.       */
  unsigned int opt_flags;          /* Current option flags.             */
  enum argparser_states state;     /* State of the gnupg_argparser.     */
  const char *last;
  void *aliases;
  const void *cur_alias;
  void *iio_list;
  estream_t conffp;
  char *confname;
  opttable_t *opts;            /* Malloced option table.  */
  unsigned int nopts;          /* Number of items in OPTS.  */
};


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


static int  set_opt_arg (gnupg_argparse_t *arg, unsigned int flags, char *s);
static void show_help (opttable_t *opts, unsigned int nopts,unsigned int flags);
static void show_version (void);
static void dump_option_table (gnupg_argparse_t *arg);
static int writestrings (int is_error, const char *string,
                         ...) GPGRT_ATTR_SENTINEL(0);

static int arg_parse (gnupg_argparse_t *arg, gnupg_opt_t *opts, int no_init);



/* Set a function to write strings which is then used instead of
 * estream.  The first arg of that function is MODE and the second the
 * STRING to write.  A mode of 1 is used for writing to stdout and a
 * mode of 2 to write to stderr.  Other modes are reserved and should
 * not output anything.  A NULL for STRING requests a flush.  */
void
gnupg_set_usage_outfnc (int (*f)(int, const char *))
{
  custom_outfnc = f;
}


/* Register function F as a string mapper which takes a string as
 * argument, replaces known "@FOO@" style macros and returns a new
 * fixed string.  Warning: The input STRING must have been allocated
 * statically.  */
void
gnupg_set_fixed_string_mapper (const char *(*f)(const char*))
{
  fixed_string_mapper = f;
}


/* Register a configuration directory for use by the argparse
 * functions.  The defined values for WHAT are:
 *
 *   GNUPG_CONFDIR_SYS   The systems's configuration dir.
 *                       The default is /etc
 *
 *   GNUPG_CONFDIR_USER  The user's configuration directory.
 *                       The default is $HOME.
 *
 * A trailing slash is ignored; to have the function lookup
 * configuration files in the current directory, use ".".  There is no
 * error return; more configuraion values may be added in future
 * revisions of this library.
 */
void
gnupg_set_confdir (int what, const char *name)
{
  char *buf, *p;

  if (what == GNUPG_CONFDIR_SYS)
    {
      xfree (confdir.sys);
      buf = confdir.sys = xtrystrdup (name);
    }
  else if (what == GNUPG_CONFDIR_USER)
    {
      xfree (confdir.user);
      buf = confdir.user = xtrystrdup (name);
    }
  else
    return;

  if (!buf)
    log_fatal ("out of core in %s\n", __func__);
#ifdef HAVE_W32_SYSTEM
  for (p=buf; *p; p++)
    if (*p == '\\')
      *p = '/';
#endif
  /* Strip trailing slashes unless buf is "/" or any other single char
   * string.  */
  if (*buf)
    {
      for (p=buf + strlen (buf)-1; p > buf; p--)
        if (*p == '/')
          *p = 0;
        else
          break;
    }
}



static const char *
map_fixed_string (const char *string)
{
  return fixed_string_mapper? fixed_string_mapper (string) : string;
}

#endif /* USE_INTERNAL_ARGPARSE */


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
        {  /* Fixme: Swicth to estream?  */
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


#if USE_INTERNAL_ARGPARSE

static void
deinitialize (gnupg_argparse_t *arg)
{
  if (arg->internal)
    {
      xfree (arg->internal->username);
      xfree (arg->internal->explicit_conffile);
      xfree (arg->internal->opts);
      xfree (arg->internal);
      arg->internal = NULL;
    }

  arg->flags &= ARGPARSE_FLAG__INITIALIZED;
  arg->lineno = 0;
  arg->err = 0;
}

/* Our own exit handler to clean up used memory.  */
static void
my_exit (gnupg_argparse_t *arg, int code)
{
  deinitialize (arg);
  exit (code);
}


static gpg_err_code_t
initialize (gnupg_argparse_t *arg, gnupg_opt_t *opts, estream_t fp)
{
  /* We use a dedicated flag to detect whether *ARG has been
   * initialized.  This is because the old version of that struct, as
   * used in GnuPG, had no requirement to zero out all fields of the
   * object and existing code still sets only argc,argv and flags.  */
  if (!(arg->flags & ARGPARSE_FLAG__INITIALIZED)
      || (arg->flags & ARGPARSE_FLAG_RESET)
      || !arg->internal)
    {
      /* Allocate internal data.  */
      if (!(arg->flags & ARGPARSE_FLAG__INITIALIZED) || !arg->internal)
        {
          arg->internal = xtrymalloc (sizeof *arg->internal);
          if (!arg->internal)
            return gpg_err_code_from_syserror ();
          arg->flags |= ARGPARSE_FLAG__INITIALIZED; /* Mark as initialized.  */
        }
      else if (arg->internal->opts)
        xfree (arg->internal->opts);
      arg->internal->opts = NULL;
      arg->internal->nopts = 0;

      /* Initialize this instance. */
      arg->internal->idx = 0;
      arg->internal->last = NULL;
      arg->internal->inarg = 0;
      arg->internal->stopped = 0;
      arg->internal->in_sysconf = 0;
      arg->internal->user_seen = 0;
      arg->internal->user_wildcard = 0;
      arg->internal->user_any_active = 0;
      arg->internal->user_active = 0;
      arg->internal->username = NULL;
      arg->internal->mark_forced = 0;
      arg->internal->mark_ignore = 0;
      arg->internal->explicit_ignore = 0;
      arg->internal->ignore_all_seen = 0;
      arg->internal->explicit_confopt = 0;
      arg->internal->explicit_conffile = NULL;
      arg->internal->opt_flags = 0;
      arg->internal->state = STATE_init;
      arg->internal->aliases = NULL;
      arg->internal->cur_alias = NULL;
      arg->internal->iio_list = NULL;
      arg->internal->conffp = NULL;
      arg->internal->confname = NULL;

      /* Clear the copy of the option list.  */
      /* Clear the error indicator.  */
      arg->err = 0;

      /* Usually an option file will be parsed from the start.
       * However, we do not open the stream and thus we have no way to
       * know the current lineno.  Using this flag we can allow the
       * user to provide a lineno which we don't reset.  */
      if (fp || arg->internal->conffp || !(arg->flags & ARGPARSE_FLAG_NOLINENO))
        arg->lineno = 0;

      /* Need to clear the reset request.  */
      arg->flags &= ~ARGPARSE_FLAG_RESET;

      /* Check initial args.  */
      if ( *arg->argc < 0 )
        log_bug ("invalid argument passed to gnupg_argparse\n");

    }

  /* Create an array with pointers to the provided list of options.
   * Keeping a copy is useful to sort that array and thus do a binary
   * search and to allow for extra space at the end to insert the
   * hidden options.  An ARGPARSE_FLAG_RESET can be used to reinit
   * this array.  */
  if (!arg->internal->opts)
    {
      int seen_help = 0;
      int seen_version = 0;
      int seen_warranty = 0;
      int seen_dump_options = 0;
      int seen_dump_option_table = 0;
      int i;

      for (i=0; opts[i].short_opt; i++)
        {
          if (opts[i].long_opt)
            {
              if (!strcmp(opts[i].long_opt, "help"))
                seen_help = 1;
              else if (!strcmp(opts[i].long_opt, "version"))
                seen_version = 1;
              else if (!strcmp(opts[i].long_opt, "warranty"))
                seen_warranty = 1;
              else if (!strcmp(opts[i].long_opt, "dump-options"))
                seen_dump_options = 1;
              else if (!strcmp(opts[i].long_opt, "dump-option-table"))
                seen_dump_option_table = 1;
            }
        }
      i += 5; /* The number of the above internal options.  */
      i++;    /* End of list marker.  */
      arg->internal->opts = xtrycalloc (i, sizeof *arg->internal->opts);
      if (!arg->internal->opts)
        return gpg_err_code_from_syserror ();
      for(i=0; opts[i].short_opt; i++)
        {
          arg->internal->opts[i].short_opt   = opts[i].short_opt;
          arg->internal->opts[i].flags       = opts[i].flags;
          arg->internal->opts[i].long_opt    = opts[i].long_opt;
          arg->internal->opts[i].description = opts[i].description;
          arg->internal->opts[i].ordinal = i;
        }

      if (!seen_help)
        {
          arg->internal->opts[i].short_opt   = ARGPARSE_SHORTOPT_HELP;
          arg->internal->opts[i].flags       = ARGPARSE_TYPE_NONE;
          arg->internal->opts[i].long_opt    = "help";
          arg->internal->opts[i].description = "@";
          arg->internal->opts[i].ordinal = i;
          i++;
        }
      if (!seen_version)
        {
          arg->internal->opts[i].short_opt   = ARGPARSE_SHORTOPT_VERSION;
          arg->internal->opts[i].flags       = ARGPARSE_TYPE_NONE;
          arg->internal->opts[i].long_opt    = "version";
          arg->internal->opts[i].description = "@";
          arg->internal->opts[i].ordinal = i;
          i++;
        }

      if (!seen_warranty)
        {
          arg->internal->opts[i].short_opt   = ARGPARSE_SHORTOPT_WARRANTY;
          arg->internal->opts[i].flags       = ARGPARSE_TYPE_NONE;
          arg->internal->opts[i].long_opt    = "warranty";
          arg->internal->opts[i].description = "@";
          arg->internal->opts[i].ordinal = i;
          i++;
        }

      if (!seen_dump_option_table)
        {
          arg->internal->opts[i].short_opt   = ARGPARSE_SHORTOPT_DUMP_OPTTBL;
          arg->internal->opts[i].flags       = ARGPARSE_TYPE_NONE;
          arg->internal->opts[i].long_opt    = "dump-option-table";
          arg->internal->opts[i].description = "@";
          arg->internal->opts[i].ordinal = i;
          i++;
        }

      if (!seen_dump_options)
        {
          arg->internal->opts[i].short_opt   = ARGPARSE_SHORTOPT_DUMP_OPTIONS;
          arg->internal->opts[i].flags       = ARGPARSE_TYPE_NONE;
          arg->internal->opts[i].long_opt    = "dump-options";
          arg->internal->opts[i].description = "@";
          arg->internal->opts[i].ordinal = i;
          i++;
        }
      /* Take care: When adding new options remember to increase the
       * size of the array.  */

      arg->internal->opts[i].short_opt = 0;

      /* Note that we do not count the end marker but keep it in the
       * table anyway as an extra item.  */
      arg->internal->nopts = i;
    }

  if (arg->err)
    {
      /* Last option was erroneous.  */
      const char *s;

      if (!fp && arg->internal->conffp)
        fp = arg->internal->conffp;

      if (fp)
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
          else if ( arg->r_opt == ARGPARSE_PERMISSION_ERROR )
            s = _("permission error");
          else if ( arg->r_opt == ARGPARSE_OUT_OF_CORE )
            s = _("out of core");
          else if ( arg->r_opt == ARGPARSE_NO_CONFFILE )
            s = NULL;  /* Error has already been printed.  */
          else if ( arg->r_opt == ARGPARSE_INVALID_META )
            s = _("invalid meta command");
          else if ( arg->r_opt == ARGPARSE_UNKNOWN_META )
            s = _("unknown meta command");
          else if ( arg->r_opt == ARGPARSE_UNEXPECTED_META )
            s = _("unexpected meta command");
          else
            s = _("invalid option");
          if (s)
            log_error ("%s:%u: %s\n",
                              gpgrt_fname_get (fp), arg->lineno, s);
	}
      else
        {
          s = arg->internal->last? arg->internal->last:"[??]";

          if ( arg->r_opt == ARGPARSE_MISSING_ARG )
            log_error (_("missing argument for option \"%.50s\"\n"), s);
          else if ( arg->r_opt == ARGPARSE_INVALID_ARG )
            log_error (_("invalid argument for option \"%.50s\"\n"), s);
          else if ( arg->r_opt == ARGPARSE_UNEXPECTED_ARG )
            log_error (_("option \"%.50s\" does not expect "
                                "an argument\n"), s);
          else if ( arg->r_opt == ARGPARSE_INVALID_COMMAND )
            log_error (_("invalid command \"%.50s\"\n"), s);
          else if ( arg->r_opt == ARGPARSE_AMBIGUOUS_OPTION )
            log_error (_("option \"%.50s\" is ambiguous\n"), s);
          else if ( arg->r_opt == ARGPARSE_AMBIGUOUS_COMMAND )
            log_error (_("command \"%.50s\" is ambiguous\n"),s );
          else if ( arg->r_opt == ARGPARSE_OUT_OF_CORE )
            log_error ("%s\n", _("out of core"));
          else if ( arg->r_opt == ARGPARSE_PERMISSION_ERROR )
            log_error ("%s\n", _("permission error"));
          else if ( arg->r_opt == ARGPARSE_NO_CONFFILE)
            ;  /* Error has already been printed.  */
          else if ( arg->r_opt == ARGPARSE_INVALID_META )
            log_error ("%s\n", _("invalid meta command"));
          else if ( arg->r_opt == ARGPARSE_UNKNOWN_META )
            log_error ("%s\n", _("unknown meta command"));
          else if ( arg->r_opt == ARGPARSE_UNEXPECTED_META )
            log_error ("%s\n",_("unexpected meta command"));
          else
            log_error (_("invalid option \"%.50s\"\n"), s);
	}
      if (arg->err != ARGPARSE_PRINT_WARNING)
        my_exit (arg, 2);
      arg->err = 0;
    }

  /* Zero out the return value union.  */
  arg->r.ret_str = NULL;
  arg->r.ret_long = 0;

  return 0;
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
  IIO_ITEM_DEF item = arg->internal->iio_list;

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
ignore_invalid_option_add (ARGPARSE_ARGS *arg, estream_t fp)
{
  IIO_ITEM_DEF item;
  int c;
  char name[100];
  int namelen = 0;
  int ready = 0;
  enum { skipWS, collectNAME, skipNAME, addNAME} state = skipWS;

  while (!ready)
    {
      c = gpgrt_getc (fp);
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
              item->next = (IIO_ITEM_DEF)arg->internal->iio_list;
              arg->internal->iio_list = item;
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

  for (item = arg->internal->iio_list; item; item = tmpitem)
    {
      tmpitem = item->next;
      xfree (item);
    }
  arg->internal->iio_list = NULL;
}


/* Make sure the username field is filled.  Return 0 on success.  */
static int
assure_username (gnupg_argparse_t *arg)
{
  if (!arg->internal->username)
    {
      arg->internal->username = gnupg_getusername ();
      if (!arg->internal->username)
        {
          log_error ("%s:%u: error getting current user's name: %s\n",
                            arg->internal->confname, arg->lineno,
                            gpg_strerror (gpg_error_from_syserror ()));
          /* Not necessary the correct error code but given that we
           * either have a malloc error or some internal system error,
           * it is the best we can do.  */
          return ARGPARSE_PERMISSION_ERROR;
        }
    }
  return 0;
}


/* Implementation of the "user" command.  ARG is the context.  ARGS is
 * a non-empty string which this function is allowed to modify.  */
static int
handle_meta_user (gnupg_argparse_t *arg, unsigned int alternate, char *args)
{
  int rc;

  (void)alternate;

  rc = assure_username (arg);
  if (rc)
    return rc;

  arg->internal->user_seen = 1;
  if (*args == '*' && !args[1])
    {
      arg->internal->user_wildcard = 1;
      arg->internal->user_active = !arg->internal->user_any_active;
    }
  else if (arg->internal->user_wildcard)
    {
      /* All other user statements are ignored after a wildcard.  */
      arg->internal->user_active = 0;
    }
  else if (!strcasecmp (args, arg->internal->username))
    {
      arg->internal->user_any_active = 1;
      arg->internal->user_active = 1;
    }
  else
    {
      arg->internal->user_active = 0;
    }

  return 0;
}


/* Implementation of the "force" command.  ARG is the context.  A
 * value of 0 for ALTERNATE is "force", a value of 1 requests an
 * unforce".  ARGS is the empty string and not used.  */
static int
handle_meta_force (gnupg_argparse_t *arg, unsigned int alternate, char *args)
{
  (void)args;

  arg->internal->mark_forced = alternate? 0 : 1;

  return 0;
}


/* Implementation of the "ignore" command.  ARG is the context.  A
 * value of 0 for ALTERNATE is a plain "ignore", a value of 1 request
 * an "unignore, a value of 2 requests an "ignore-all".  ARGS is the
 * empty string and not used.  */
static int
handle_meta_ignore (gnupg_argparse_t *arg, unsigned int alternate, char *args)
{
  (void)args;

  if (!alternate)
    {
      arg->internal->mark_ignore = 1;
      arg->internal->explicit_ignore = 1;
    }
  else if (alternate == 1)
    {
      arg->internal->mark_ignore = 0;
      arg->internal->explicit_ignore = 1;
    }
  else
    arg->internal->ignore_all_seen = 1;

  return 0;
}


/* Implementation of the "echo" command.  ARG is the context.  If
 * ALTERNATE is true the filename is not printed.  ARGS is the string
 * to log.  */
static int
handle_meta_echo (gnupg_argparse_t *arg, unsigned int alternate, char *args)
{
  int rc = 0;
  char *p, *pend;

  if (alternate)
    log_info ("%s", "");
  else
    log_info ("%s:%u: ", arg->internal->confname, arg->lineno);

  while (*args)
    {
      p = strchr (args, '$');
      if (!p)
        {
          log_printf ("%s", args);
          break;
        }
      *p = 0;
      log_printf ("%s", args);
      if (p[1] == '$')
        {
          log_printf ("$");
          args = p+2;
          continue;
        }
      if (p[1] != '{')
        {
          log_printf ("$");
          args = p+1;
          continue;
        }
      pend = strchr (p+2, '}');
      if (!pend)  /* No closing brace.  */
        {
          log_printf ("$");
          args = p+1;
          continue;
        }
      p += 2;
      *pend = 0;
      args = pend+1;
      if (!strcmp (p, "user"))
        {
          rc = assure_username (arg);
          if (rc)
            goto leave;
          log_printf ("%s", arg->internal->username);
        }
      else if (!strcmp (p, "file"))
        log_printf ("%s", arg->internal->confname);
      else if (!strcmp (p, "line"))
        log_printf ("%u", arg->lineno);
      else if (!strcmp (p, "epoch"))
        log_printf ("%lu",  (unsigned long)time (NULL));
    }

 leave:
  log_printf ("\n");
  return rc;
}


/* Implementation of the "verbose" command.  ARG is the context.  If
 * ALTERNATE is true the verbosity is disabled.  ARGS is not used.  */
static int
handle_meta_verbose (gnupg_argparse_t *arg, unsigned int alternate, char *args)
{
  (void)args;

  if (alternate)
    arg->internal->verbose = 0;
  else
    arg->internal->verbose = 1;
  return 0;
}

/* Handle a meta command.  KEYWORD has the content inside the brackets
 * with leading and trailing spaces removed.  The function may modify
 * KEYWORD.  On success 0 is returned, on error an ARGPARSE_ error
 * code is returned.  */
static int
handle_metacmd (gnupg_argparse_t *arg, char *keyword)
{
  static struct {
    const char *name;          /* Name of the command.                   */
    unsigned short alternate;  /* Use alternate version of the command.  */
    unsigned short needarg:1;  /* Command requires an argument.          */
    unsigned short always:1;   /* Command allowed in all conf files.     */
    unsigned short noskip:1;   /* Even done in non-active [user] mode.   */
    int (*func)(gnupg_argparse_t *arg,
                unsigned int alternate, char *args); /*handler*/
  } cmds[] =
      {{ "user",        0, 1, 0, 1, handle_meta_user },
       { "force",       0, 0, 0, 0, handle_meta_force },
       { "+force",      0, 0, 0, 0, handle_meta_force },
       { "-force",      1, 0, 0, 0, handle_meta_force },
       { "ignore",      0, 0, 0, 0, handle_meta_ignore },
       { "+ignore",     0, 0, 0, 0, handle_meta_ignore },
       { "-ignore",     1, 0, 0, 0, handle_meta_ignore },
       { "ignore-all",  2, 0, 0, 0, handle_meta_ignore },
       { "+ignore-all", 2, 0, 0, 0, handle_meta_ignore },
       { "verbose",     0, 0, 1, 1, handle_meta_verbose },
       { "+verbose",    0, 0, 1, 1, handle_meta_verbose },
       { "-verbose",    1, 0, 1, 1, handle_meta_verbose },
       { "echo",        0, 1, 1, 1, handle_meta_echo },
       { "-echo",       1, 1, 1, 1, handle_meta_echo },
       { "info",        0, 1, 1, 0, handle_meta_echo },
       { "-info",       1, 1, 1, 0, handle_meta_echo }
      };
  char *rest;
  int i;

  for (rest = keyword; *rest && !(isascii (*rest) && isspace (*rest)); rest++)
    ;
  if (*rest)
    {
      *rest++ = 0;
      trim_spaces (rest);
    }

  for (i=0; i < DIM (cmds); i++)
    if (!strcmp (cmds[i].name, keyword))
      break;
  if (!(i < DIM (cmds)))
    return ARGPARSE_UNKNOWN_META;
  if (cmds[i].needarg && !*rest)
    return ARGPARSE_MISSING_ARG;
  if (!cmds[i].needarg && *rest)
    return ARGPARSE_UNEXPECTED_ARG;
  if (!arg->internal->in_sysconf && !cmds[i].always)
    return ARGPARSE_UNEXPECTED_META;

  if (!cmds[i].noskip
      && arg->internal->in_sysconf
      && arg->internal->user_seen
      && !arg->internal->user_active)
    return 0; /* Skip this meta command.  */

  return cmds[i].func (arg, cmds[i].alternate, rest);
}


/* Helper for gnupg_argparse.  */
static void
prepare_arg_return (gnupg_argparse_t *arg, opttable_t *opts,
                    int idx, int in_alias, int set_ignore)
{
  /* No argument found at the end of the line.  */
  if (in_alias)
    arg->r_opt = ARGPARSE_MISSING_ARG;
  else if (!(opts[idx].flags & ARGPARSE_TYPE_MASK))
    arg->r_type = ARGPARSE_TYPE_NONE; /* Does not take an arg. */
  else if ((opts[idx].flags & ARGPARSE_OPT_OPTIONAL))
    arg->r_type = ARGPARSE_TYPE_NONE; /* No optional argument. */
  else if (!(opts[idx].ignore && !opts[idx].forced) && !set_ignore)
    arg->r_opt = ARGPARSE_MISSING_ARG;

  /* If the caller wants us to return the attributes or
   * ignored options, or these flags in.  */
  if ((arg->flags & ARGPARSE_FLAG_WITHATTR))
    {
      if (opts[idx].ignore)
        arg->r_type |= ARGPARSE_ATTR_IGNORE;
      if (opts[idx].forced)
        arg->r_type |= ARGPARSE_ATTR_FORCE;
      if (set_ignore)
        arg->r_type |= ARGPARSE_OPT_IGNORE;
    }
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
gnupg_argparse (estream_t fp, gnupg_argparse_t *arg, gnupg_opt_t *opts_orig)
{
  enum { Ainit,
         Acomment,     /* In a comment line.           */
         Acopykeyword, /* Collecting a keyword.        */
         Awaitarg,     /* Wait for an argument.        */
         Acopyarg,     /* Copy the argument.           */
         Akeyword_eol, /* Got keyword at end of line.  */
         Akeyword_spc, /* Got keyword at space.        */
         Acopymetacmd, /* Copy a meta command.         */
         Askipmetacmd, /* Skip spaces after metacmd.   */
         Askipmetacmd2,/* Skip comment after metacmd.  */
         Ametacmd,     /* Process the metacmd.         */
         Askipandleave /* Skip the rest of the line and then leave.  */
  } state;
  opttable_t *opts;
  unsigned int nopts;
  int i, c;
  int idx = 0;
  char keyword[100];
  char *buffer = NULL;
  size_t buflen = 0;
  int in_alias=0;
  int set_ignore = 0;
  int unread_buf[3];  /* We use an int so that we can store EOF.  */
  int unread_buf_count = 0;

  if (arg && !opts_orig)
    {
      deinitialize (arg);
      return 0;
    }

  if (!fp) /* Divert to arg_parse() in this case.  */
    return arg_parse (arg, opts_orig, 0);

  if (initialize (arg, opts_orig, fp))
    return (arg->r_opt = ARGPARSE_OUT_OF_CORE);

  opts = arg->internal->opts;
  nopts = arg->internal->nopts;

  /* If the LINENO is zero we assume that we are at the start of a
   * file and we skip over a possible Byte Order Mark.  */
  if (!arg->lineno)
    {
      unread_buf[0] = gpgrt_fgetc (fp);
      unread_buf[1] = gpgrt_fgetc (fp);
      unread_buf[2] = gpgrt_fgetc (fp);
      if (unread_buf[0] != 0xef
          || unread_buf[1] != 0xbb
          || unread_buf[2] != 0xbf)
        unread_buf_count = 3;
    }

  arg->internal->opt_flags = 0;

  /* Find the next keyword.  */
  state = Ainit;
  i = 0;
  for (;;)
    {
    nextstate:
      /* Before scanning the next char handle the keyword seen states.  */
      if (state == Akeyword_eol || state == Akeyword_spc)
        {
          /* We are either at the end of a line or right after a
           * keyword.  In the latter case we need to find the keyword
           * so that we can decide whether an argument is required.  */

          /* Check the keyword.  */
          for (idx=0; idx < nopts; idx++ )
            {
              if (opts[idx].long_opt && !strcmp (opts[idx].long_opt, keyword))
                break;
            }
          arg->r_opt = opts[idx].short_opt;
          if (!(idx < nopts))
            {
              /* The option (keyword) is not known - check for
               * internal keywords before returning an error.  */
              if (state == Akeyword_spc && !strcmp (keyword, "alias"))
                {
                  in_alias = 1;
                  state = Awaitarg;
                }
              else if (!strcmp (keyword, "ignore-invalid-option"))
                {
                  /* We might have keywords as argument - add them to
                   * the list of ignored keywords.  Note that we
                   * ignore empty argument lists and thus do not to
                   * call the function in the Akeyword_eol state. */
                  if (state == Akeyword_spc)
                    {
                      if (ignore_invalid_option_add (arg, fp))
                        {
                          arg->r_opt = ARGPARSE_OUT_OF_CORE;
                          goto leave;
                        }
                      arg->lineno++;
                    }
                  state = Ainit;
                  i = 0;
                }
              else if (ignore_invalid_option_p (arg, keyword))
                {
                  /* This invalid option is already in the iio list.  */
                  state = state == Akeyword_eol? Ainit : Acomment;
                  i = 0;
                }
              else
                {
                  arg->r_opt = ((opts[idx].flags & ARGPARSE_OPT_COMMAND)
                                ? ARGPARSE_INVALID_COMMAND
                                : ARGPARSE_INVALID_OPTION);
                  if (state == Akeyword_spc)
                    state = Askipandleave;
                  else
                    goto leave;
                }
            }
          else if (state != Akeyword_spc
                   && arg->internal->in_sysconf
                   && arg->internal->user_seen
                   && !arg->internal->user_active)
            {
              /* We are in a [user] meta command and it is not active.
               * Skip the command.  */
              state = state == Akeyword_eol? Ainit : Acomment;
              i = 0;
            }
          else if (state != Akeyword_spc
                   && (opts[idx].flags & ARGPARSE_OPT_IGNORE))
            {
              /* Known option is configured to be ignored.  Start from
               * scratch (new line) or process like a comment.  */
              state = state == Akeyword_eol? Ainit : Acomment;
              i = 0;
            }
          else /* Known option */
            {
              set_ignore = 0;

              if (arg->internal->in_sysconf)
                {
                  /* Set the current forced and ignored attributes.  */
                  if (arg->internal->mark_forced)
                    opts[idx].forced = 1;
                  if (arg->internal->mark_ignore)
                    opts[idx].ignore = 1;
                  if (arg->internal->explicit_ignore)
                    opts[idx].explicit_ignore = 1;

                  if (opts[idx].ignore && !opts[idx].forced)
                    {
                      if (arg->internal->verbose)
                        log_info ("%s:%u: ignoring option \"--%s\"\n",
                                  arg->internal->confname,
                                  arg->lineno,
                                  opts[idx].long_opt);
                      if ((arg->flags & ARGPARSE_FLAG_WITHATTR))
                        set_ignore = 1;
                      else
                        {
                          state = state == Akeyword_eol? Ainit : Acomment;
                          i = 0;
                          goto nextstate;  /* Ignore this one.  */
                        }
                    }
                }
              else /* Non-sysconf file  */
                {  /* Act upon the forced and ignored attributes.  */
                  if (opts[idx].ignore || opts[idx].forced)
                    {
                      if (arg->internal->verbose)
                        log_info ("%s:%u: ignoring option \"--%s\""
                                         " due to attributes:%s%s\n",
                                         arg->internal->confname,
                                         arg->lineno,
                                         opts[idx].long_opt,
                                         opts[idx].forced? " forced":"",
                                         opts[idx].ignore? " ignore":"");
                      if ((arg->flags & ARGPARSE_FLAG_WITHATTR))
                        set_ignore = 1;
                      else
                        {
                          state = state == Akeyword_eol? Ainit : Acomment;
                          i = 0;
                          goto nextstate;  /* Ignore this one.  */
                        }
                    }
                }

              if (state == Akeyword_spc)
                {
                  /* If we shall ignore but not set the option we skip
                   * the argument.  Otherwise we would need to use a
                   * made-up but not used args in the conf file. */
                  if (set_ignore || (opts[idx].ignore && !opts[idx].forced))
                    {
                      prepare_arg_return (arg, opts, idx, 0, set_ignore);
                      set_ignore = 0;
                      state = Askipandleave;
                    }
                  else
                    state = Awaitarg;
                }
              else
                {
                  prepare_arg_return (arg, opts, idx, 0, set_ignore);
                  set_ignore = 0;
                  goto leave;
                }

            }
        } /* (end state Akeyword_eol/Akeyword_spc) */
      else if (state == Ametacmd)
        {
          /* We are at the end of a line.  */
          log_assert (*keyword == '[');
          trim_spaces (keyword+1);
          if (!keyword[1])
            {
              arg->r_opt = ARGPARSE_INVALID_META; /* Empty.  */
              goto leave;
            }
          c = handle_metacmd (arg, keyword+1);
          if (c)
            {
              arg->r_opt = c;   /* Return error.  */
              goto leave;
            }
          state = Ainit;
          i = 0;
        }

      /* Get the next character from the line.  */
      if (unread_buf_count)
        c = unread_buf[3 - unread_buf_count--];
      else
        c = gpgrt_fgetc (fp);

      if (c == '\n' || c== EOF )
        { /* Handle end of line.  */
          if ( c != EOF )
            arg->lineno++;
          if (state == Askipandleave)
            goto leave;
          else if (state == Acopykeyword)
            {
              keyword[i] = 0;
              state = Akeyword_eol;
              goto nextstate;
	    }
          else if (state == Acopymetacmd)
            {
              arg->r_opt = ARGPARSE_INVALID_META;  /* "]" missing */
              goto leave;
	    }
          else if (state == Askipmetacmd || state == Askipmetacmd2)
            {
              state = Ametacmd;
              goto nextstate;
            }
          else if (state == Awaitarg)
            {
              /* No argument found at the end of the line.  */
              prepare_arg_return (arg, opts, idx, in_alias, set_ignore);
              set_ignore = 0;
              goto leave;
	    }
          else if (state == Acopyarg)
            {
              /* Has an argument at the end of a line. */
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
              goto leave;
            }
          else if (c == EOF)
            {
              ignore_invalid_option_clear (arg);
              if (gpgrt_ferror (fp))
                arg->r_opt = ARGPARSE_READ_ERROR;
              else
                arg->r_opt = 0; /* EOF. */
              goto leave;
            }
          state = Ainit;
          i = 0;
        } /* (end handle end of line) */
      else if (state == Askipandleave)
        ; /* Skip. */
      else if (state == Ainit && isascii (c) && isspace(c))
        ; /* Skip leading white space.  */
      else if (state == Ainit && c == '#' )
        state = Acomment;	/* Start of a comment.  */
      else if (state == Acomment || state == Askipmetacmd2)
        ; /* Skip comments. */
      else if (state == Askipmetacmd)
        {
          if (c == '#')
            state = Askipmetacmd2;
          else if (!(isascii (c) && isspace(c)))
            {
              arg->r_opt = ARGPARSE_INVALID_META;
              state = Askipandleave;
            }
        }
      else if (state == Acopykeyword && isascii (c) && isspace(c))
        {
          keyword[i] = 0;
          state = Akeyword_spc;
          goto nextstate;
        }
      else if (state == Acopymetacmd && c == ']')
        {
          keyword[i] = 0;
          state = Askipmetacmd;
          goto nextstate;
        }
      else if (state == Awaitarg)
        {
          /* Skip leading spaces of the argument.  */
          if (!isascii (c) || !isspace(c))
            {
              i = 0;
              keyword[i++] = c;
              state = Acopyarg;
            }
        }
      else if (state == Acopyarg)
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
                      goto leave;
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
                  goto leave;
                }
            }
        }
      else if (i >= DIM(keyword)-1)
        {
          arg->r_opt = ARGPARSE_KEYWORD_TOO_LONG;
          state = Askipandleave; /* Skip rest of line and leave.  */
        }
      else if (!i)
        {
          state = c == '[' ? Acopymetacmd : Acopykeyword;
          keyword[i++] = c;
        }
      else
        {
          keyword[i++] = c;
        }
    }

 leave:
  return arg->r_opt;
}


/* Return true if the list of options OPTS has any option marked with
 * ARGPARSE_OPT_CONFFILE.  */
static int
any_opt_conffile (opttable_t *opts, unsigned int nopts)
{
  int i;

  for (i=0; i < nopts; i++ )
    if ((opts[i].flags & ARGPARSE_OPT_CONFFILE))
      return 1;
  return 0;
}


/* Return true if FNAME is an absolute filename.  */
static int
is_absfname (const char *fname)
{
  const char *s;

#ifdef HAVE_W32_SYSTEM
  s = strchr (fname, ':');
  if (s)
    s++;
  else
    s = fname;
#else
  s = fname;
#endif

  return (*s == '/'
#ifdef HAVE_W32_SYSTEM
          || *s == DIRSEP_C
#endif
          );
}


/* If FNAME specifies two files of the form
 *   NAME1:/NAME2    (Unix)
 * or
 *   NAME1;[x:]/NAME2  (Windows)
 * return a pointer to the delimiter or NULL if there is none.
 */
static const char *
is_twopartfname (const char *fname)
{
  const char *s;

  if ((s = strchr (fname, PATHSEP_C)) && is_absfname (s+1) && s != fname)
    return s;
  return NULL;
}


/* Try to use a version-ed config file name.  A version-ed config file
 * name is one which has the packages version number appended.  For
 * example if the standard config file name is "foo.conf" and the
 * version of the foo program is 1.2.3-beta1 the following config
 * files are tried in order until one is readable:
 *
 *   foo.conf-1.2.3-beta1
 *   foo.conf-1.2.3
 *   foo.conf-1.2
 *   foo.conf-1
 *   foo.conf
 *
 * The argument CONFIGNAME should already be expanded.  On success a
 * newly allocated file name is returned.  On error NULL is returned.
 */
static char *
try_versioned_conffile (const char *configname)
{
  const char *version = strusage (13);
  char *name;
  char *dash, *endp;

  if (!version || !*version)
    return NULL; /* No program version known. */

  name = strconcat (configname, "-", version, NULL);
  if (!name)
    return NULL;  /* Oops: Out of core - ignore.  */
  dash = name + strlen (configname);

  endp = dash + strlen (dash) - 1;
  while (endp > dash)
    {
      if (!gnupg_access (name, R_OK))
        {
          return name;
        }
      for (; endp > dash; endp--)
        {
          if (*endp == '-' || *endp == '.')
            {
              *endp = 0;
              break;
            }
        }
    }

  xfree (name);
  return NULL;
}


/* This function is called after a sysconf file has been read.  */
static void
finish_read_sys (gnupg_argparse_t *arg)
{
  opttable_t *opts = arg->internal->opts;
  unsigned int nopts = arg->internal->nopts;
  int i;

  if (arg->internal->ignore_all_seen)
    {
      /* [ignore-all] was used: Set all options which have not
       * explictly been set as ignore or not ignore to ignore.  */
      for (i = 0; i < nopts; i++)
        {
          if (!opts[i].explicit_ignore)
            opts[i].ignore = 1;
        }
    }

  /* Reset all flags which pertain only to sysconf files.  */
  arg->internal->in_sysconf = 0;
  arg->internal->user_active = 0;
  arg->internal->mark_forced = 0;
  arg->internal->mark_ignore = 0;
  arg->internal->explicit_ignore = 0;
  arg->internal->ignore_all_seen = 0;
}

/* The full arg parser which handles option files and command line
 * arguments.  The behaviour depends on the combinations of CONFNAME
 * and the ARGPARSE_FLAG_xxx values:
 *
 * | CONFNAME | SYS | USER | Action             |
 * |----------+-----+------+--------------------|
 * | NULL     |   - |    - | cmdline            |
 * | string   |   0 |    1 | user, cmdline      |
 * | string   |   1 |    0 | sys, cmdline       |
 * | string   |   1 |    1 | sys, user, cmdline |
 *
 * Note that if an option has been flagged with ARGPARSE_OPT_CONFFILE
 * and a type of ARGPARSE_TYPE_STRING that option is not returned but
 * the specified configuration file is processed directly; if
 * ARGPARSE_TYPE_NONE is used no user configuration files are
 * processed and from the system configuration files only those which
 * are immutable are processed.  The string values for CONFNAME shall
 * not include a directory part because that is taken from the values
 * set by gnupg_set_confdir.  However, if CONFNAME is a twopart
 * filename delimited by a colon (semicolon on Windows) with the
 * second part being an absolute filename, the first part is used for
 * the SYS file and the the entire second part for the USER file.
 */
int
gnupg_argparser (gnupg_argparse_t *arg, gnupg_opt_t *opts,
                 const char *confname)
{
  /* First check whether releasing the resources has been requested.  */
  if (arg && !opts)
    {
      deinitialize (arg);
      return 0;
    }

  /* Make sure that the internal data object is ready and also print
   * warnings or errors from the last iteration.  */
  if (initialize (arg, opts, NULL))
    return (arg->r_opt = ARGPARSE_OUT_OF_CORE);

 next_state:
  switch (arg->internal->state)
    {
    case STATE_init:
      if (arg->argc && arg->argv && *arg->argc
          && any_opt_conffile (arg->internal->opts, arg->internal->nopts))
        {
          /* The list of option allow for conf files
           * (e.g. gpg's "--option FILE" and "--no-options")
           * Now check whether one was really given on the command
           * line.  Note that we don't need to run this code if no
           * argument array was provided. */
          int  save_argc = *arg->argc;
          char **save_argv = *arg->argv;
          unsigned int save_flags = arg->flags;
          int save_idx = arg->internal->idx;
          int any_no_conffile = 0;

          arg->flags = (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION
                        | ARGPARSE_FLAG__INITIALIZED);
          while (arg_parse (arg, opts, 1))
            {
              if ((arg->internal->opt_flags & ARGPARSE_OPT_CONFFILE))
                {
                  arg->internal->explicit_confopt = 1;
                  if ((arg->r_type & ARGPARSE_TYPE_MASK) == ARGPARSE_TYPE_STRING
                      && !arg->internal->explicit_conffile)
                    {
                      /* Store the first conffile name.  All further
                       * conf file options are not handled.  */
                      arg->internal->explicit_conffile
                        = xtrystrdup (arg->r.ret_str);
                      if (!arg->internal->explicit_conffile)
                        return (arg->r_opt = ARGPARSE_OUT_OF_CORE);

                    }
                  else if ((arg->r_type & ARGPARSE_TYPE_MASK)
                            == ARGPARSE_TYPE_NONE)
                    any_no_conffile = 1;
                }
            }
          if (any_no_conffile)
            {
              /* A NoConffile option overrides any other conf file option.  */
              xfree (arg->internal->explicit_conffile);
              arg->internal->explicit_conffile = NULL;
            }
          /* Restore parser.  */
          *arg->argc = save_argc;
          *arg->argv = save_argv;
          arg->flags = save_flags;
          arg->internal->idx = save_idx;
        }

      if (confname && *confname)
        {
          if ((arg->flags & ARGPARSE_FLAG_SYS))
            arg->internal->state = STATE_open_sys;
          else if ((arg->flags & ARGPARSE_FLAG_USER))
            arg->internal->state = STATE_open_user;
          else
            return (arg->r_opt = ARGPARSE_INVALID_ARG);
        }
      else
        arg->internal->state = STATE_open_cmdline;
      goto next_state;

    case STATE_open_sys:
      {
        /* If it is a two part name take the first part.  */
        const char *s;
        char *tmpname = NULL;

        if ((s = is_twopartfname (confname)))
          {
            tmpname = xtrymalloc (s - confname + 1);
            if (!tmpname)
              return (arg->r_opt = ARGPARSE_OUT_OF_CORE);
            memcpy (tmpname, confname, s-confname);
            tmpname[s-confname] = 0;
            s = tmpname;
          }
        else
          s = confname;
        xfree (arg->internal->confname);
        arg->internal->confname = make_filename_try
          (confdir.sys? confdir.sys : "/etc", s, NULL);
        xfree (tmpname);
        if (!arg->internal->confname)
          return (arg->r_opt = ARGPARSE_OUT_OF_CORE);
      }
      arg->lineno = 0;
      arg->internal->idx = 0;
      arg->internal->verbose = 0;
      arg->internal->stopped = 0;
      arg->internal->inarg = 0;
      gpgrt_fclose (arg->internal->conffp);
      arg->internal->conffp = gpgrt_fopen (arg->internal->confname, "r");
      if (!arg->internal->conffp)
        {
          if ((arg->flags & ARGPARSE_FLAG_VERBOSE) || arg->internal->verbose)
            log_info (_("Note: no default option file '%s'\n"),
                             arg->internal->confname);
          if ((arg->flags & ARGPARSE_FLAG_USER))
            arg->internal->state = STATE_open_user;
          else
            arg->internal->state = STATE_open_cmdline;
          goto next_state;
        }

      if ((arg->flags & ARGPARSE_FLAG_VERBOSE) || arg->internal->verbose)
        log_info (_("reading options from '%s'\n"),
                         arg->internal->confname);
      arg->internal->state = STATE_read_sys;
      arg->internal->in_sysconf = 1;
      arg->r.ret_str = xtrystrdup (arg->internal->confname);
      if (!arg->r.ret_str)
        arg->r_opt = ARGPARSE_OUT_OF_CORE;
      else
        {
          gpgrt_annotate_leaked_object (arg->r.ret_str);
          arg->r_opt = ARGPARSE_CONFFILE;
          arg->r_type = ARGPARSE_TYPE_STRING;
        }
      break;

    case STATE_open_user:
      if (arg->internal->explicit_confopt
          && arg->internal->explicit_conffile)
        {
          /* An explict option to use a specific configuration file
           * has been given - use that one.  */
          xfree (arg->internal->confname);
          arg->internal->confname
            = xtrystrdup (arg->internal->explicit_conffile);
          if (!arg->internal->confname)
            return (arg->r_opt = ARGPARSE_OUT_OF_CORE);
        }
      else if (arg->internal->explicit_confopt)
        {
          /* An explict option not to use a configuration file has
           * been given - leap direct to command line reading.  */
          arg->internal->state = STATE_open_cmdline;
          goto next_state;
        }
      else
        {
          /* Use the standard configure file.  If it is a two part
           * name take the second part.  If it is the standard name
           * and ARGPARSE_FLAG_USERVERS is set try versioned config
           * files. */
          const char *s;
          char *nconf;

          xfree (arg->internal->confname);
          if ((s = is_twopartfname (confname)))
            {
              arg->internal->confname = make_filename_try (s + 1, NULL);
              if (!arg->internal->confname)
                return (arg->r_opt = ARGPARSE_OUT_OF_CORE);
            }
          else
            {
              arg->internal->confname = make_filename_try
                (confdir.user? confdir.user : "~/.config", confname, NULL);
              if (!arg->internal->confname)
                return (arg->r_opt = ARGPARSE_OUT_OF_CORE);
              if ((arg->flags & ARGPARSE_FLAG_USERVERS)
                  && (nconf = try_versioned_conffile (arg->internal->confname)))
                {
                  xfree (arg->internal->confname);
                  arg->internal->confname = nconf;
                }
            }
        }
      arg->lineno = 0;
      arg->internal->idx = 0;
      arg->internal->verbose = 0;
      arg->internal->stopped = 0;
      arg->internal->inarg = 0;
      arg->internal->in_sysconf = 0;
      gpgrt_fclose (arg->internal->conffp);
      arg->internal->conffp = gpgrt_fopen (arg->internal->confname, "r");
      if (!arg->internal->conffp)
        {
          arg->internal->state = STATE_open_cmdline;
          if (arg->internal->explicit_confopt)
            {
              log_error (_("option file '%s': %s\n"),
                                arg->internal->confname, strerror (errno));
              return (arg->r_opt = ARGPARSE_NO_CONFFILE);
            }
          else
            {
              if ((arg->flags & ARGPARSE_FLAG_VERBOSE)
                  || arg->internal->verbose)
                log_info (_("Note: no default option file '%s'\n"),
                                 arg->internal->confname);
              goto next_state;
            }
        }

      if ((arg->flags & ARGPARSE_FLAG_VERBOSE) || arg->internal->verbose)
        log_info (_("reading options from '%s'\n"),
                         arg->internal->confname);
      arg->internal->state = STATE_read_user;
      arg->r.ret_str = xtrystrdup (arg->internal->confname);
      if (!arg->r.ret_str)
        arg->r_opt = ARGPARSE_OUT_OF_CORE;
      else
        {
          gpgrt_annotate_leaked_object (arg->r.ret_str);
          arg->r_opt = ARGPARSE_CONFFILE;
          arg->r_type = ARGPARSE_TYPE_STRING;
        }
      break;

    case STATE_open_cmdline:
      gpgrt_fclose (arg->internal->conffp);
      arg->internal->conffp = NULL;
      xfree (arg->internal->confname);
      arg->internal->confname = NULL;
      arg->internal->idx = 0;
      arg->internal->verbose = 0;
      arg->internal->stopped = 0;
      arg->internal->inarg = 0;
      arg->internal->in_sysconf = 0;
      if (!arg->argc || !arg->argv || !*arg->argv)
        {
          /* No or empty argument vector - don't bother to parse things.  */
          arg->internal->state = STATE_finished;
          goto next_state;
        }
      arg->r_opt = ARGPARSE_CONFFILE;
      arg->r_type = ARGPARSE_TYPE_NONE;
      arg->r.ret_str = NULL;
      arg->internal->state = STATE_read_cmdline;
      break;

    case STATE_read_sys:
     arg->r_opt = gnupg_argparse (arg->internal->conffp, arg, opts);
      if (!arg->r_opt)
        {
          finish_read_sys (arg);
          arg->internal->state = STATE_open_user;
          goto next_state;
        }
      if ((arg->internal->opt_flags & ARGPARSE_OPT_CONFFILE))
        goto next_state;  /* Already handled - again.  */
      break;

    case STATE_read_user:
      arg->r_opt = gnupg_argparse (arg->internal->conffp, arg, opts);
      if (!arg->r_opt)
        {
          arg->internal->state = STATE_open_cmdline;
          goto next_state;
        }
      if ((arg->internal->opt_flags & ARGPARSE_OPT_CONFFILE))
        goto next_state;  /* Already handled - again.  */
      break;

    case STATE_read_cmdline:
      arg->r_opt = arg_parse (arg, opts, 1);
      if (!arg->r_opt)
        {
          arg->internal->state = STATE_finished;
          goto next_state;
        }
      if ((arg->internal->opt_flags & ARGPARSE_OPT_CONFFILE))
        goto next_state;  /* Already handled - again.  */
      break;

    case STATE_finished:
      arg->r_opt = 0;
      break;
    }

  return arg->r_opt;
}



/* Given the list of options in ARG and a keyword, return the index of
 * the long option matching KEYWORD.  On error -1 is returned for not
 * found or -2 for ambigious keyword.  */
static int
find_long_option (gnupg_argparse_t *arg, const char *keyword)
{
  int i;
  size_t n;
  opttable_t *opts   = arg->internal->opts;
  unsigned int nopts = arg->internal->nopts;

  /* Would be better if we can do a binary search, but it is not
   * possible to reorder our option table because we would mess up our
   * help strings.  What we can do is: Build an option lookup table
   * when this function is first invoked.  The latter has already been
   * done. */
  if (!*keyword)
    return -1;
  for (i=0; i < nopts; i++ )
    if (opts[i].long_opt && !strcmp (opts[i].long_opt, keyword))
      return i;
  /* Not found.  See whether it is an abbreviation.  Aliases may not
   * be abbreviated, though. */
  n = strlen (keyword);
  for (i=0; i < nopts; i++)
    {
      if (opts[i].long_opt && !strncmp (opts[i].long_opt, keyword, n))
        {
          int j;
          for (j=i+1; j < nopts; j++)
            {
              if (opts[j].long_opt
                  && !strncmp (opts[j].long_opt, keyword, n)
                  && !(opts[j].short_opt == opts[i].short_opt
                       && opts[j].flags == opts[i].flags ) )
                return -2;  /* Abbreviation is ambiguous.  */
	    }
          return i;
	}
    }
  return -1;  /* Not found.  */
}


/* The option parser for command line options.  */
static int
arg_parse (gnupg_argparse_t *arg, gnupg_opt_t *opts_orig, int no_init)
{
  int idx;
  opttable_t *opts;
  unsigned int nopts;
  int argc;
  char **argv;
  char *s, *s2;
  int i;

  if (no_init)
    ;
  else if (initialize (arg, opts_orig, NULL))
    return (arg->r_opt = ARGPARSE_OUT_OF_CORE);

  opts = arg->internal->opts;
  nopts = arg->internal->nopts;
  argc = *arg->argc;
  argv = *arg->argv;
  idx = arg->internal->idx;

  if (!idx && argc && !(arg->flags & ARGPARSE_FLAG_ARG0))
    {
      /* Skip the first argument.  */
      argc--; argv++; idx++;
    }

 next_one:
  if (!argc || (s = *argv) == NULL)
    {
      /* No more args.  */
      arg->r_opt = 0;
      goto leave; /* Ready. */
    }

  arg->internal->last = s;
  arg->internal->opt_flags = 0;

  if (arg->internal->stopped && (arg->flags & ARGPARSE_FLAG_ALL))
    {
      arg->r_opt = ARGPARSE_IS_ARG;  /* Not an option but an argument.  */
      arg->r_type = ARGPARSE_TYPE_STRING;
      arg->r.ret_str = s;
      argc--; argv++; idx++; /* set to next one */
    }
  else if (arg->internal->stopped)
    {
      arg->r_opt = 0;
      goto leave; /* Ready.  */
    }
  else if ( *s == '-' && s[1] == '-' )
    {
      /* Long option.  */
      char *argpos;

      arg->internal->inarg = 0;
      if (!s[2] && !(arg->flags & ARGPARSE_FLAG_NOSTOP))
        {
          /* Stop option processing.  */
          arg->internal->stopped = 1;
          arg->flags |= ARGPARSE_FLAG_STOP_SEEN;
          argc--; argv++; idx++;
          goto next_one;
	}

      argpos = strchr( s+2, '=' );
      if ( argpos )
        *argpos = 0;
      i = find_long_option (arg, s+2);
      if ( argpos )
        *argpos = '=';

      if (i > 0 && opts[i].short_opt == ARGPARSE_SHORTOPT_HELP)
        {
          show_help (opts, nopts, arg->flags);
          my_exit (arg, 0);
        }
      else if (i > 0 && opts[i].short_opt == ARGPARSE_SHORTOPT_VERSION)
        {
          if (!(arg->flags & ARGPARSE_FLAG_NOVERSION))
            {
              show_version ();
              my_exit (arg, 0);
            }
	}
      else if (i > 0 && opts[i].short_opt == ARGPARSE_SHORTOPT_WARRANTY)
        {
          writestrings (0, strusage (16), "\n", NULL);
          my_exit (arg, 0);
	}
      else if (i > 0 && opts[i].short_opt == ARGPARSE_SHORTOPT_DUMP_OPTTBL)
        dump_option_table (arg);
      else if (i > 0 && opts[i].short_opt == ARGPARSE_SHORTOPT_DUMP_OPTIONS)
        {
          for (i=0; i < nopts; i++ )
            {
              if (opts[i].long_opt && !(opts[i].flags & ARGPARSE_OPT_IGNORE))
                writestrings (0, "--", opts[i].long_opt, "\n", NULL);
	    }
          my_exit (arg, 0);
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
            {
              arg->internal->opt_flags = opts[i].flags;
              arg->r_type = ARGPARSE_TYPE_NONE;
            }
	}
      argc--; argv++; idx++; /* Set to next one.  */
    }
  else if ( (*s == '-' && s[1]) || arg->internal->inarg )
    {
      /* Short option.  */
      int dash_kludge = 0;

      i = 0;
      if ( !arg->internal->inarg )
        {
          arg->internal->inarg++;
          if ( (arg->flags & ARGPARSE_FLAG_ONEDASH) )
            {
              for (i=0; i < nopts; i++ )
                if ( opts[i].long_opt && !strcmp (opts[i].long_opt, s+1))
                  {
                    dash_kludge = 1;
                    break;
                  }
            }
        }
      s += arg->internal->inarg;

      if (!dash_kludge )
        {
          for (i=0; i < nopts; i++ )
            if ( opts[i].short_opt == *s )
              break;
        }

      if ( !opts[i].short_opt && ( *s == 'h' || *s == '?' ) )
        {
          show_help (opts, nopts, arg->flags);
          my_exit (arg, 0);
        }

      arg->r_opt = opts[i].short_opt;
      if (!opts[i].short_opt )
        {
          arg->r_opt = (opts[i].flags & ARGPARSE_OPT_COMMAND)?
            ARGPARSE_INVALID_COMMAND:ARGPARSE_INVALID_OPTION;
          arg->internal->inarg++; /* Point to the next arg.  */
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
                  arg->internal->opt_flags = opts[i].flags;
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
                  arg->internal->opt_flags = opts[i].flags;
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
          arg->internal->opt_flags = opts[i].flags;
          arg->internal->inarg++; /* Point to the next arg.  */
        }
      if ( !s[1] || dash_kludge )
        {
          /* No more concatenated short options.  */
          arg->internal->inarg = 0;
          argc--; argv++; idx++;
        }
    }
  else if ( arg->flags & ARGPARSE_FLAG_MIXED )
    {
      arg->r_opt = ARGPARSE_IS_ARG;
      arg->r_type = ARGPARSE_TYPE_STRING;
      arg->r.ret_str = s;
      argc--; argv++; idx++; /* Set to next one.  */
    }
  else
    {
      arg->internal->stopped = 1; /* Stop option processing.  */
      goto next_one;
    }

  if (arg->r_opt > 0 && i >= 0 && i < nopts
      && ((opts[i].ignore && opts[i].explicit_ignore) || opts[i].forced))
    {

      if ((arg->flags & ARGPARSE_FLAG_WITHATTR))
        {
          if (opts[i].ignore)
            arg->r_type |= ARGPARSE_ATTR_IGNORE;
          if (opts[i].forced)
            arg->r_type |= ARGPARSE_ATTR_FORCE;
          arg->r_type |= ARGPARSE_OPT_IGNORE;
        }
      else
        {
          log_info (_("Note: ignoring option \"--%s\""
                             " due to global config\n"),
                           opts[i].long_opt);
          goto next_one;  /* Skip ignored/forced option.  */
        }
    }

 leave:
  *arg->argc = argc;
  *arg->argv = argv;
  arg->internal->idx = idx;
  return arg->r_opt;
}



/* Returns: -1 on error, 0 for an integer type and 1 for a non integer
   type argument.  */
static int
set_opt_arg (gnupg_argparse_t *arg, unsigned flags, char *s)
{
  int base = (flags & ARGPARSE_OPT_PREFIX)? 0 : 10;
  long l;

  arg->internal->opt_flags = flags;
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


/* Return the length of the option O.  This needs to consider the
 * description as well as the option name.  */
static size_t
long_opt_strlen (opttable_t *o)
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
       * continuation bytes (10xxxxxx) if we are on a native utf8
       * terminal. */
      for (; *s && *s != '|'; s++ )
        if ( is_utf8 && (*s&0xc0) != 0x80 )
          n++;
    }
  return n;
}


/* Qsort compare for show_help.  */
static int
cmp_ordtbl (const void *a_v, const void *b_v)
{
  const unsigned short *a = a_v;
  const unsigned short *b = b_v;

  return *a - *b;
}


/****************
 * Print formatted help. The description string has some special
 * meanings:
 *  - A description string which is "@" suppresses help output for
 *    this option
 *  - a description which starts with a '@' and is followed by
 *    any other characters is printed as is; this may be used for examples
 *    and such.  This is a legacy methiod, moder codes uses the flags
 *    ARGPARSE_OPT_VERBATIM or ARGPARSE_OPT_HEADER.
 *  - A description which starts with a '|' outputs the string between this
 *    bar and the next one as arguments of the long option.
 */
static void
show_help (opttable_t *opts, unsigned int nopts, unsigned int flags)
{
  const char *s;
  char tmp[2];
  unsigned int *ordtbl = NULL;

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
  if ( nopts )
    {
      /* Auto format the option description.  */
      int i,j,indent;
      const char *last_header = NULL;

      ordtbl = xtrycalloc (nopts, sizeof *ordtbl);
      if (!ordtbl)
        {
          writestrings (1, "\nOoops: Out of memory whilst printing the help.\n",
                        NULL);
          goto leave;
        }

      /* Get max. length of long options.  */
      for (i=indent=0; i < nopts; i++ )
        {
          if ( opts[i].long_opt )
            if ( !opts[i].description || *opts[i].description != '@' )
              if ( (j=long_opt_strlen(opts+i)) > indent && j < 35 )
                indent = j;
          ordtbl[i] = opts[i].ordinal;
	}

      qsort (ordtbl, nopts, sizeof *ordtbl, cmp_ordtbl);

      /* The first option needs to have a description; if not do not
       * print the help at all.  */
      if (!opts[ordtbl[0]].description)
        goto leave;

      /* Example: " -v, --verbose   Viele Sachen ausgeben" */
      indent += 10;
      if ( *opts[ordtbl[0]].description != '@'
           && !(opts[ordtbl[0]].flags
                & (ARGPARSE_OPT_VERBATIM|ARGPARSE_OPT_HEADER)))
        writestrings (0, "Options:", "\n", NULL);
      for (i=0; i < nopts; i++ )
        {
          s = map_fixed_string (_( opts[ordtbl[i]].description ));
          if ( s && *s== '@' && !s[1] ) /* Hide this line.  */
            continue;
          if ( s && (opts[ordtbl[i]].flags & ARGPARSE_OPT_HEADER))
            {
              /* We delay printing until we have found one real output
               * line.  This avoids having a header above an empty
               * section.  */
              last_header = s;
              continue;
	    }
          if (last_header)
            {
              if (*last_header)
                writestrings (0, "\n", last_header, ":\n", NULL);
              last_header = NULL;
            }
          if ( s && (opts[ordtbl[i]].flags & ARGPARSE_OPT_VERBATIM))
            {
              writestrings (0, s, NULL);
              continue;
	    }
          if ( s && *s == '@' )  /* Unindented legacy comment only line.  */
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
          if ( opts[ordtbl[i]].short_opt < 256 )
            {
              tmp[0] = opts[ordtbl[i]].short_opt;
              tmp[1] = 0;
              writestrings (0, " -", tmp, NULL );
              if ( !opts[ordtbl[i]].long_opt )
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
          if ( opts[ordtbl[i]].long_opt )
            {
              tmp[0] = opts[ordtbl[i]].short_opt < 256?',':' ';
              tmp[1] = 0;
              j += writestrings (0, tmp, " --", opts[ordtbl[i]].long_opt, NULL);
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

 leave:
  flushstrings (0);
  xfree (ordtbl);
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


/* Print the table of options with flags etc.  */
static void
dump_option_table (gnupg_argparse_t *arg)
{
  opttable_t *opts;
  unsigned int nopts;
  const char *s;
  char tmp[50];
  unsigned int *ordtbl = NULL;
  int i;

  opts = arg->internal->opts;
  nopts = arg->internal->nopts;
  if (!nopts)
    return;

  ordtbl = xtrycalloc (nopts, sizeof *ordtbl);
  if (!ordtbl)
    {
      writestrings (1, "\nOoops: Out of memory whilst dumping the table.\n",
                    NULL);
      flushstrings (1);
      my_exit (arg, 2);
    }
  for (i=0; i < nopts; i++ )
    ordtbl[i] = opts[i].ordinal;
  qsort (ordtbl, nopts, sizeof *ordtbl, cmp_ordtbl);
  for (i=0; i < nopts; i++ )
    {
      if (!opts[ordtbl[i]].long_opt)
        continue;
      writestrings (0, opts[ordtbl[i]].long_opt, ":", NULL);
      snprintf (tmp, sizeof tmp, "%u:%u:",
                opts[ordtbl[i]].short_opt,
                opts[ordtbl[i]].flags);
      writestrings (0, tmp, NULL);
      s = opts[ordtbl[i]].description;
      if (s)
        {
          for (; *s; s++)
            {
              if (*s == '%' || *s == ':' || *s == '\n')
                snprintf (tmp, sizeof tmp, "%%%02X", *s);
              else
                {
                  tmp[0] = *s;
                  tmp[1] = 0;
                }
              writestrings (0, tmp, NULL);
            }
        }
      writestrings (0, ":\n", NULL);
    }

  flushstrings (0);
  xfree (ordtbl);
  my_exit (arg, 0);
}



/* Level
 *     0: Print copyright string to stderr
 *     1: Print a short usage hint to stderr and terminate
 *     2: Print a long usage hint to stdout and terminate
 *     8: Return NULL for UTF-8 or string with the native charset.
 *     9: Return the SPDX License tag.
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
  const char *tmp;

  if ( p )
    return map_static_macro_string (p);

  switch ( level )
    {

    case 8: break; /* Default to utf-8.  */
    case 9: p = "GPL-3.0-or-later"; break;
    case 10:
      tmp = strusage (9);
      if (tmp && !strcmp (tmp, "LGPL-2.1-or-later"))
        p = ("License GNU LGPL-2.1-or-later <https://gnu.org/licenses/>");
      else /* Default to GPLv3+.  */
        p =("License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>");
      break;
    case 11: p = "foo"; break;
    case 13: p = "0.0"; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 15: p =
"This is free software: you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n";
      break;
    case 16:
      tmp = strusage (9);
      if (tmp && !strcmp (tmp, "LGPL-2.1-or-later"))
        p =
"This is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU Lesser General Public License as\n"
"published by the Free Software Foundation; either version 2.1 of\n"
"the License, or (at your option) any later version.\n\n"
"It is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU Lesser General Public License for more details.\n\n"
"You should have received a copy of the GNU Lesser General Public License\n"
"along with this software.  If not, see <https://gnu.org/licenses/>.\n";
      else /* Default */
        p =
"This is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation; either version 3 of the License, or\n"
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

#endif /* USE_INTERNAL_ARGPARSE */


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
