/* sc-investigate.c - A tool to look around on smartcards.
 *	Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JNLIB_NEED_LOG_LOGV
#include "scdaemon.h"
#include <gcrypt.h>

#include "apdu.h" /* for open_reader */
#include "atr.h"
#include "app-common.h"

#define _(a) (a)


enum cmd_and_opt_values 
{ oVerbose	  = 'v',
  oReaderPort     = 500,
  oDebug,
  oDebugAll,

aTest };


static ARGPARSE_OPTS opts[] = {
  
  { 301, NULL, 0, "@Options:\n " },

  { oVerbose, "verbose",   0, "verbose" },
  { oReaderPort, "reader-port", 1, "|N|connect to reader at port N"},
  { oDebug,	"debug"     ,4|16, "set debugging flags"},
  { oDebugAll, "debug-all" ,0, "enable full debugging"},
  {0}
};

static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "sc-investigate (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p =  _("Usage: sc-investigate [options] (-h for help)\n");
      break;
    case 41: p =  _("Syntax: sc-investigate [options] [args]]\n"
                    "Have a look at smartcards\n");
    break;
    
    default: p = NULL;
    }
  return p;
}

/* Used by gcry for logging */
static void
my_gcry_logger (void *dummy, int level, const char *fmt, va_list arg_ptr)
{
  /* translate the log levels */
  switch (level)
    {
    case GCRY_LOG_CONT: level = JNLIB_LOG_CONT; break;
    case GCRY_LOG_INFO: level = JNLIB_LOG_INFO; break;
    case GCRY_LOG_WARN: level = JNLIB_LOG_WARN; break;
    case GCRY_LOG_ERROR:level = JNLIB_LOG_ERROR; break;
    case GCRY_LOG_FATAL:level = JNLIB_LOG_FATAL; break;
    case GCRY_LOG_BUG:  level = JNLIB_LOG_BUG; break;
    case GCRY_LOG_DEBUG:level = JNLIB_LOG_DEBUG; break;
    default:            level = JNLIB_LOG_ERROR; break;  
    }
  log_logv (level, fmt, arg_ptr);
}


int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int slot, rc;
  int reader_port = 32768; /* First USB reader. */
  struct app_ctx_s appbuf;

  memset (&appbuf, 0, sizeof appbuf);

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix ("sc-investigate", 1); 

  /* check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  gcry_set_log_handler (my_gcry_logger, NULL);
  /* FIXME? gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);*/

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oDebug: opt.debug |= pargs.r.ret_ulong; break;
        case oDebugAll: opt.debug = ~0; break;
        default : pargs.err = 2; break;
	}
    }
  if (log_get_errorcount(0))
    exit(2);

  if (argc)
    usage (1);

  slot = apdu_open_reader (reader_port);
  if (slot == -1)
    exit (1);

  rc = atr_dump (slot, stdout); 
  if (rc)
    log_error ("can't dump ATR: %s\n", gpg_strerror (rc));

  appbuf.slot = slot;
  rc = app_select_openpgp (&appbuf, NULL, NULL);
  if (rc)
    log_error ("selecting openpgp failed: %s\n", gpg_strerror (rc));
  else
    log_info ("openpgp application selected\n");


  return 0;
}



void
send_status_info (CTRL ctrl, const char *keyword, ...)
{
  /* DUMMY */
}
