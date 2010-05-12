/* preset-passphrase.c - A tool to preset a passphrase.
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif
#ifdef HAVE_DOSISH_SYSTEM
#include <fcntl.h> /* for setmode() */
#endif
#ifdef HAVE_W32_SYSTEM
#include <windows.h>  /* To initialize the sockets.  fixme */
#endif

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"
#include "minip12.h"
#include "simple-pwquery.h"
#include "i18n.h"
#include "sysutils.h"


enum cmd_and_opt_values 
{ aNull = 0,
  oVerbose	  = 'v',
  oPassphrase     = 'P',

  oPreset         = 'c',
  oForget         = 'f',
  
  oNoVerbose = 500,

  oHomedir,

aTest };


static const char *opt_homedir;
static const char *opt_passphrase;

static ARGPARSE_OPTS opts[] = {
  
  { 301, NULL, 0, N_("@Options:\n ") },

  { oVerbose, "verbose",   0, "verbose" },
  { oPassphrase, "passphrase", 2, "|STRING|use passphrase STRING" },
  { oPreset,  "preset",   256, "preset passphrase"},
  { oForget,  "forget",  256, "forget passphrase"},

  { oHomedir, "homedir", 2, "@" }, 
  {0}
};


static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "gpg-preset-passphrase (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: 
      p =  _("Usage: gpg-preset-passphrase [options] KEYGRIP (-h for help)\n");
      break;
    case 41:
      p = _("Syntax: gpg-preset-passphrase [options] KEYGRIP\n"
                    "Password cache maintenance\n");
    break;
    
    default: p = NULL;
    }
  return p;
}




/* Include the implementation of map_spwq_error.  */
MAP_SPWQ_ERROR_IMPL
      

static void
preset_passphrase (const char *keygrip)
{
  int  rc;
  char *line;
  /* FIXME: Use secure memory.  */
  char passphrase[500];
  char *passphrase_esc;

  if (!opt_passphrase)
    {
      rc = read (0, passphrase, sizeof (passphrase) - 1);
      if (rc < 0)
        {
          log_error ("reading passphrase failed: %s\n",
                     gpg_strerror (gpg_error_from_syserror ()));
          return;
        }
      passphrase[rc] = '\0';
      line = strchr (passphrase, '\n');
      if (line)
        {
          if (line > passphrase && line[-1] == '\r')
            line--;
          *line = '\0';
        }

      /* FIXME: How to handle empty passwords?  */
    }

  {
    const char *s = opt_passphrase ? opt_passphrase : passphrase;
    passphrase_esc = bin2hex (s, strlen (s), NULL);
  }
  if (!passphrase_esc)
    {
      log_error ("can not escape string: %s\n",
		 gpg_strerror (gpg_error_from_syserror ()));
      return;
    }

  rc = asprintf (&line, "PRESET_PASSPHRASE %s -1 %s\n", keygrip,
		 passphrase_esc);
  wipememory (passphrase_esc, strlen (passphrase_esc));
  xfree (passphrase_esc);

  if (rc < 0)
    {
      log_error ("caching passphrase failed: %s\n",
		 gpg_strerror (gpg_error_from_syserror ()));
      return;
    }
  if (!opt_passphrase)
    wipememory (passphrase, sizeof (passphrase));

  rc = map_spwq_error (simple_query (line));
  if (rc)
    {
      log_error ("caching passphrase failed: %s\n", gpg_strerror (rc));
      return;
    }

  wipememory (line, strlen (line));
  xfree (line);
}


static void
forget_passphrase (const char *keygrip)
{
  int rc;
  char *line;

  rc = asprintf (&line, "CLEAR_PASSPHRASE %s\n", keygrip);
  if (rc < 0)
    rc = gpg_error_from_syserror ();
  else
    rc = map_spwq_error (simple_query (line));
  if (rc)
    {
      log_error ("clearing passphrase failed: %s\n", gpg_strerror (rc));
      return;
    }

  xfree (line);
}


int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int cmd = 0;
  const char *keygrip = NULL;

  set_strusage (my_strusage);
  log_set_prefix ("gpg-preset-passphrase", 1); 

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems ();

  opt_homedir = default_homedir ();

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* (do not remove the args) */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oHomedir: opt_homedir = pargs.r.ret_str; break;

        case oPreset: cmd = oPreset; break;
        case oForget: cmd = oForget; break;
        case oPassphrase: opt_passphrase = pargs.r.ret_str; break;
          
        default : pargs.err = 2; break;
	}
    }
  if (log_get_errorcount(0))
    exit(2);

  if (argc == 1)
    keygrip = *argv;
  else
    usage (1);

  /* Tell simple-pwquery about the the standard socket name.  */
  {
    char *tmp = make_filename (opt_homedir, "S.gpg-agent", NULL);
    simple_pw_set_socket (tmp);
    xfree (tmp);
  }

  if (cmd == oPreset)
    preset_passphrase (keygrip);
  else if (cmd == oForget)
    forget_passphrase (keygrip);
  else
    log_error ("one of the options --preset or --forget must be given\n");

  agent_exit (0);
  return 8; /*NOTREACHED*/
}


void
agent_exit (int rc)
{
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}
