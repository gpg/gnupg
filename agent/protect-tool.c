/* protect-tool.c - A tool to text the secret key protection
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gcrypt.h>

#define JNLIB_NEED_LOG_LOGV
#include "agent.h"

#define N_(a) a
#define _(a) a


enum cmd_and_opt_values 
{ aNull = 0,
  oVerbose	  = 'v',
  oArmor          = 'a',
  oPassphrase     = 'P',

  oProtect        = 'p',
  oUnprotect      = 'u',
  
  oNoVerbose = 500,

aTest };


static int opt_armor;
static const char *passphrase = "abc";

static ARGPARSE_OPTS opts[] = {
  
  { 301, NULL, 0, N_("@Options:\n ") },

  { oVerbose, "verbose",   0, "verbose" },
  { oArmor,   "armor",     0, "write output in advanced format" },
  { oPassphrase, "passphrase", 2, "|STRING| Use passphrase STRING" },
  { oProtect, "protect",     256, "protect a private key"},
  { oUnprotect, "unprotect", 256, "unprotect a private key"},

  {0}
};

static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case 11: p = "protect-tool (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p =  _("Usage: protect-tool [options] (-h for help)\n");
      break;
    case 41: p =  _("Syntax: protect-tool [options] [args]]\n"
                    "INTERNAL USE ONLY!\n");
    break;
    
    default: p = NULL;
    }
  return p;
}



static void
i18n_init (void)
{
#ifdef USE_SIMPLE_GETTEXT
    set_gettext_file( PACKAGE );
#else
#ifdef ENABLE_NLS
    /* gtk_set_locale (); HMMM: We have not yet called gtk_init */
    bindtextdomain( PACKAGE, GNUPG_LOCALEDIR );
    textdomain( PACKAGE );
#endif
#endif
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


static unsigned char *
make_canonical (const char *fname, const char *buf, size_t buflen)
{
  int rc;
  size_t erroff, len;
  GCRY_SEXP sexp;
  unsigned char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, buf, buflen);
  if (rc)
    {
      log_error ("invalid S-Expression in `%s' (off=%u): %s\n",
                 fname, (unsigned int)erroff, gcry_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  result = xmalloc (len);
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, result, len);
  assert (len);
  gcry_sexp_release (sexp);
  return result;
}

static char *
make_advanced (const unsigned char *buf, size_t buflen)
{
  int rc;
  size_t erroff, len;
  GCRY_SEXP sexp;
  unsigned char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, buf, buflen);
  if (rc)
    {
      log_error ("invalid canonical S-Expression (off=%u): %s\n",
                 (unsigned int)erroff, gcry_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  assert (len);
  result = xmalloc (len);
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, result, len);
  assert (len);
  gcry_sexp_release (sexp);
  return result;
}


static unsigned char *
read_key (const char *fname)
{
  FILE *fp;
  struct stat st;
  char *buf;
  size_t buflen;
  unsigned char *key;
  
  fp = fopen (fname, "rb");
  if (!fp)
    {
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      return NULL;
    }
  
  if (fstat (fileno(fp), &st))
    {
      log_error ("can't stat `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      log_error ("error reading `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      xfree (buf);
      return NULL;
    }
  fclose (fp);

  key = make_canonical (fname, buf, buflen);
  xfree (buf);
  return key;
}



static void
read_and_protect (const char *fname)
{
  int  rc;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  
  key = read_key (fname);
  if (!key)
    return;

  rc = agent_protect (key, passphrase, &result, &resultlen);
  xfree (key);
  if (rc)
    {
      log_error ("protecting the key failed: %s\n", gnupg_strerror (rc));
      return;
    }
  
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}


static void
read_and_unprotect (const char *fname)
{
  int  rc;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  
  key = read_key (fname);
  if (!key)
    return;

  rc = agent_unprotect (key, passphrase, &result, &resultlen);
  xfree (key);
  if (rc)
    {
      log_error ("unprotecting the key failed: %s\n", gnupg_strerror (rc));
      return;
    }
  
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}



int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int cmd = 0;

  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix ("protect-tool", 1); 
  i18n_init ();

  if (!gcry_check_version ( "1.1.5" ) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 "1.1.5", gcry_check_version (NULL) );
    }

  gcry_set_log_handler (my_gcry_logger, NULL);
  
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
  while (arg_parse (&pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oArmor:   opt_armor=1; break;

        case oProtect: cmd = oProtect; break;
        case oUnprotect: cmd = oUnprotect; break;

        case oPassphrase: passphrase = pargs.r.ret_str; break;

        default : pargs.err = 2; break;
	}
    }
  if (log_get_errorcount(0))
    exit(2);

  if (argc != 1)
    usage (1);

  if (cmd == oProtect)
    read_and_protect (*argv);
  else if (cmd == oUnprotect)
    read_and_unprotect (*argv);
  else
    log_info ("no action requested\n");

  return 0;
}

void
agent_exit (int rc)
{
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}
