/* protect-tool.c - A tool to test the secret key protection
 * Copyright (C) 2002, 2003, 2004, 2006 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
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

#define INCLUDED_BY_MAIN_MODULE 1
#include "agent.h"
#include "../common/i18n.h"
#include "../common/get-passphrase.h"
#include "../common/sysutils.h"
#include "../common/init.h"


enum cmd_and_opt_values
{
  aNull = 0,
  oVerbose	  = 'v',
  oArmor          = 'a',
  oPassphrase     = 'P',

  oProtect        = 'p',
  oUnprotect      = 'u',

  oNoVerbose = 500,
  oShadow,
  oShowShadowInfo,
  oShowKeygrip,
  oS2Kcalibration,
  oCanonical,

  oStore,
  oForce,
  oHaveCert,
  oNoFailOnExist,
  oHomedir,
  oPrompt,
  oStatusMsg,
  oDebugUseOCB,

  oAgentProgram
};


struct rsa_secret_key_s
{
  gcry_mpi_t n;	    /* public modulus */
  gcry_mpi_t e;	    /* public exponent */
  gcry_mpi_t d;	    /* exponent */
  gcry_mpi_t p;	    /* prime  p. */
  gcry_mpi_t q;	    /* prime  q. */
  gcry_mpi_t u;	    /* inverse of p mod q. */
};


static int opt_armor;
static int opt_canonical;
static int opt_store;
static int opt_force;
static int opt_no_fail_on_exist;
static int opt_have_cert;
static const char *opt_passphrase;
static char *opt_prompt;
static int opt_status_msg;
static const char *opt_agent_program;

static char *get_passphrase (int promptno);
static void release_passphrase (char *pw);


static gpgrt_opt_t opts[] = {
  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (oProtect,   "protect",   "protect a private key"),
  ARGPARSE_c (oUnprotect, "unprotect", "unprotect a private key"),
  ARGPARSE_c (oShadow,    "shadow", "create a shadow entry for a public key"),
  ARGPARSE_c (oShowShadowInfo,  "show-shadow-info", "return the shadow info"),
  ARGPARSE_c (oShowKeygrip, "show-keygrip", "show the \"keygrip\""),
  ARGPARSE_c (oS2Kcalibration, "s2k-calibration", "@"),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", "verbose"),
  ARGPARSE_s_n (oArmor, "armor", "write output in advanced format"),
  ARGPARSE_s_n (oCanonical, "canonical", "write output in canonical format"),

  ARGPARSE_s_s (oPassphrase, "passphrase", "|STRING|use passphrase STRING"),
  ARGPARSE_s_n (oHaveCert, "have-cert",
                "certificate to export provided on STDIN"),
  ARGPARSE_s_n (oStore,    "store",
                "store the created key in the appropriate place"),
  ARGPARSE_s_n (oForce,    "force",
                "force overwriting"),
  ARGPARSE_s_n (oNoFailOnExist, "no-fail-on-exist", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_s (oPrompt,  "prompt",
                "|ESCSTRING|use ESCSTRING as prompt in pinentry"),
  ARGPARSE_s_n (oStatusMsg, "enable-status-msg", "@"),

  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),

  ARGPARSE_s_n (oDebugUseOCB,  "debug-use-ocb", "@"), /* For hacking only.  */

  ARGPARSE_end ()
};

static const char *
my_strusage (int level)
{
  const char *p;
  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "gpg-protect-tool (" GNUPG_NAME ")";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p =  _("Usage: gpg-protect-tool [options] (-h for help)\n");
      break;
    case 41: p =  _("Syntax: gpg-protect-tool [options] [args]\n"
                    "Secret key maintenance tool\n");
    break;

    default: p = NULL;
    }
  return p;
}


/*  static void */
/*  print_mpi (const char *text, gcry_mpi_t a) */
/*  { */
/*    char *buf; */
/*    void *bufaddr = &buf; */
/*    int rc; */

/*    rc = gcry_mpi_aprint (GCRYMPI_FMT_HEX, bufaddr, NULL, a); */
/*    if (rc) */
/*      log_info ("%s: [error printing number: %s]\n", text, gpg_strerror (rc)); */
/*    else */
/*      { */
/*        log_info ("%s: %s\n", text, buf); */
/*        gcry_free (buf); */
/*      } */
/*  } */



static unsigned char *
make_canonical (const char *fname, const char *buf, size_t buflen)
{
  int rc;
  size_t erroff, len;
  gcry_sexp_t sexp;
  unsigned char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, buf, buflen);
  if (rc)
    {
      log_error ("invalid S-Expression in '%s' (off=%u): %s\n",
                 fname, (unsigned int)erroff, gpg_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  log_assert (len);
  result = xmalloc (len);
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_CANON, result, len);
  log_assert (len);
  gcry_sexp_release (sexp);
  return result;
}

static char *
make_advanced (const unsigned char *buf, size_t buflen)
{
  int rc;
  size_t erroff, len;
  gcry_sexp_t sexp;
  char *result;

  rc = gcry_sexp_sscan (&sexp, &erroff, (const char*)buf, buflen);
  if (rc)
    {
      log_error ("invalid canonical S-Expression (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  log_assert (len);
  result = xmalloc (len);
  len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, result, len);
  log_assert (len);
  gcry_sexp_release (sexp);
  return result;
}


static char *
read_file (const char *fname, size_t *r_length)
{
  estream_t fp;
  char *buf;
  size_t buflen;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = es_stdin;
      es_set_binary (fp);
      buf = NULL;
      buflen = 0;
#define NCHUNK 8192
      do
        {
          bufsize += NCHUNK;
          if (!buf)
            buf = xmalloc (bufsize);
          else
            buf = xrealloc (buf, bufsize);

          nread = es_fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && es_ferror (fp))
            {
              log_error ("error reading '[stdin]': %s\n", strerror (errno));
              xfree (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK

    }
  else
    {
      struct stat st;

      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          log_error ("can't open '%s': %s\n", fname, strerror (errno));
          return NULL;
        }

      if (fstat (es_fileno (fp), &st))
        {
          log_error ("can't stat '%s': %s\n", fname, strerror (errno));
          es_fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = xmalloc (buflen+1);
      if (es_fread (buf, buflen, 1, fp) != 1)
        {
          log_error ("error reading '%s': %s\n", fname, strerror (errno));
          es_fclose (fp);
          xfree (buf);
          return NULL;
        }
      es_fclose (fp);
    }

  *r_length = buflen;
  return buf;
}


static unsigned char *
read_key (const char *fname)
{
  char *buf;
  size_t buflen;
  unsigned char *key;

  buf = read_file (fname, &buflen);
  if (!buf)
    return NULL;
  if (buflen >= 4 && !memcmp (buf, "Key:", 4))
    {
      log_error ("Extended key format is not supported by this tool\n");
      xfree (buf);
      return NULL;
    }
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
  char *pw;

  key = read_key (fname);
  if (!key)
    return;

  pw = get_passphrase (1);
  rc = agent_protect (key, pw, &result, &resultlen, 0);
  release_passphrase (pw);
  xfree (key);
  if (rc)
    {
      log_error ("protecting the key failed: %s\n", gpg_strerror (rc));
      return;
    }

  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}


static void
read_and_unprotect (ctrl_t ctrl, const char *fname)
{
  gpg_error_t err;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  char *pw;
  gnupg_isotime_t protected_at;

  key = read_key (fname);
  if (!key)
    return;

  err = agent_unprotect (ctrl, key, (pw=get_passphrase (1)),
                         protected_at, &result, &resultlen);
  release_passphrase (pw);
  xfree (key);
  if (err)
    {
      if (opt_status_msg)
        log_info ("[PROTECT-TOOL:] bad-passphrase\n");
      log_error ("unprotecting the key failed: %s\n", gpg_strerror (err));
      return;
    }
  if (opt.verbose)
    {
      if (*protected_at)
        log_info ("key protection done at %.4s-%.2s-%.2s %.2s:%.2s:%s\n",
                  protected_at, protected_at+4, protected_at+6,
                  protected_at+9, protected_at+11, protected_at+13);
      else
        log_info ("key protection done at [unknown]\n");
    }

  err = fixup_when_ecc_private_key (result, &resultlen);
  if (err)
    {
      log_error ("malformed key: %s\n", gpg_strerror (err));
      return;
    }
  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}



static void
read_and_shadow (const char *fname)
{
  int  rc;
  unsigned char *key;
  unsigned char *result;
  size_t resultlen;
  unsigned char dummy_info[] = "(8:313233342:43)";

  key = read_key (fname);
  if (!key)
    return;

  rc = agent_shadow_key (key, dummy_info, &result);
  xfree (key);
  if (rc)
    {
      log_error ("shadowing the key failed: %s\n", gpg_strerror (rc));
      return;
    }
  resultlen = gcry_sexp_canon_len (result, 0, NULL,NULL);
  log_assert (resultlen);

  if (opt_armor)
    {
      char *p = make_advanced (result, resultlen);
      xfree (result);
      if (!p)
        return;
      result = (unsigned char*)p;
      resultlen = strlen (p);
    }

  fwrite (result, resultlen, 1, stdout);
  xfree (result);
}

static void
show_shadow_info (const char *fname)
{
  int  rc;
  unsigned char *key;
  const unsigned char *info;
  size_t infolen;

  key = read_key (fname);
  if (!key)
    return;

  rc = agent_get_shadow_info (key, &info);
  xfree (key);
  if (rc)
    {
      log_error ("get_shadow_info failed: %s\n", gpg_strerror (rc));
      return;
    }
  infolen = gcry_sexp_canon_len (info, 0, NULL,NULL);
  log_assert (infolen);

  if (opt_armor)
    {
      char *p = make_advanced (info, infolen);
      if (!p)
        return;
      fwrite (p, strlen (p), 1, stdout);
      xfree (p);
    }
  else
    fwrite (info, infolen, 1, stdout);
}


static void
show_file (const char *fname)
{
  unsigned char *key;
  size_t keylen;
  char *p;

  key = read_key (fname);
  if (!key)
    return;

  keylen = gcry_sexp_canon_len (key, 0, NULL,NULL);
  log_assert (keylen);

  if (opt_canonical)
    {
      fwrite (key, keylen, 1, stdout);
    }
  else
    {
      p = make_advanced (key, keylen);
      if (p)
        {
          fwrite (p, strlen (p), 1, stdout);
          xfree (p);
        }
    }
  xfree (key);
}

static void
show_keygrip (const char *fname)
{
  unsigned char *key;
  gcry_sexp_t private;
  unsigned char grip[20];
  int i;

  key = read_key (fname);
  if (!key)
    return;

  if (gcry_sexp_new (&private, key, 0, 0))
    {
      log_error ("gcry_sexp_new failed\n");
      return;
    }
  xfree (key);

  if (!gcry_pk_get_keygrip (private, grip))
    {
      log_error ("can't calculate keygrip\n");
      return;
    }
  gcry_sexp_release (private);

  for (i=0; i < 20; i++)
    printf ("%02X", grip[i]);
  putchar ('\n');
}





int
main (int argc, char **argv )
{
  gpgrt_argparse_t pargs;
  int cmd = 0;
  const char *fname;
  ctrl_t ctrl;

  early_system_init ();
  gpgrt_set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix ("gpg-protect-tool", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= ARGPARSE_FLAG_KEEP;
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt.verbose++; break;
        case oArmor:   opt_armor=1; break;
        case oCanonical: opt_canonical=1; break;
        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;

        case oAgentProgram: opt_agent_program = pargs.r.ret_str; break;

        case oProtect: cmd = oProtect; break;
        case oUnprotect: cmd = oUnprotect; break;
        case oShadow: cmd = oShadow; break;
        case oShowShadowInfo: cmd = oShowShadowInfo; break;
        case oShowKeygrip: cmd = oShowKeygrip; break;
        case oS2Kcalibration: cmd = oS2Kcalibration; break;

        case oPassphrase: opt_passphrase = pargs.r.ret_str; break;
        case oStore: opt_store = 1; break;
        case oForce: opt_force = 1; break;
        case oNoFailOnExist: opt_no_fail_on_exist = 1; break;
        case oHaveCert: opt_have_cert = 1; break;
        case oPrompt: opt_prompt = pargs.r.ret_str; break;
        case oStatusMsg: opt_status_msg = 1; break;
        case oDebugUseOCB: /* dummy */; break;

        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }
  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (log_get_errorcount (0))
    exit (2);

  fname = "-";
  if (argc == 1)
    fname = *argv;
  else if (argc > 1)
    gpgrt_usage (1);

  /* Allocate an CTRL object.  An empty object should be sufficient.  */
  ctrl = xtrycalloc (1, sizeof *ctrl);
  if (!ctrl)
    {
      log_error ("error allocating connection control data: %s\n",
                 strerror (errno));
      agent_exit (1);
    }

  /* Set the information which can't be taken from envvars.  */
  gnupg_prepare_get_passphrase (GPG_ERR_SOURCE_DEFAULT,
                                opt.verbose,
                                opt_agent_program,
                                NULL, NULL, NULL);

  if (opt_prompt)
    opt_prompt = percent_plus_unescape (opt_prompt, 0);

  if (cmd == oProtect)
    read_and_protect (fname);
  else if (cmd == oUnprotect)
    read_and_unprotect (ctrl, fname);
  else if (cmd == oShadow)
    read_and_shadow (fname);
  else if (cmd == oShowShadowInfo)
    show_shadow_info (fname);
  else if (cmd == oShowKeygrip)
    show_keygrip (fname);
  else if (cmd == oS2Kcalibration)
    {
      if (!opt.verbose)
        opt.verbose++; /* We need to see something.  */
      get_standard_s2k_count ();
    }
  else
    show_file (fname);

  xfree (ctrl);

  agent_exit (0);
  return 8; /*NOTREACHED*/
}

void
agent_exit (int rc)
{
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


/* Return the passphrase string and ask the agent if it has not been
   set from the command line  PROMPTNO select the prompt to display:
     0 = default
     1 = taken from the option --prompt
     2 = for unprotecting a pkcs#12 object
     3 = for protecting a new pkcs#12 object
     4 = for protecting an imported pkcs#12 in our system
*/
static char *
get_passphrase (int promptno)
{
  char *pw;
  int err;
  const char *desc;
  char *orig_codeset;
  int repeat = 0;

  if (opt_passphrase)
    return xstrdup (opt_passphrase);

  orig_codeset = i18n_switchto_utf8 ();

  if (promptno == 1 && opt_prompt)
    {
      desc = opt_prompt;
    }
  else if (promptno == 2)
    {
      desc = _("Please enter the passphrase to unprotect the "
               "PKCS#12 object.");
    }
  else if (promptno == 3)
    {
      desc = _("Please enter the passphrase to protect the "
               "new PKCS#12 object.");
      repeat = 1;
    }
  else if (promptno == 4)
    {
      desc = _("Please enter the passphrase to protect the "
               "imported object within the GnuPG system.");
      repeat = 1;
    }
  else
    desc = _("Please enter the passphrase or the PIN\n"
             "needed to complete this operation.");

  i18n_switchback (orig_codeset);

  err = gnupg_get_passphrase (NULL, NULL, _("Passphrase:"), desc,
                              repeat, repeat, 1, &pw);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_CANCELED
          || gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
        log_info (_("cancelled\n"));
      else
        log_error (_("error while asking for the passphrase: %s\n"),
                   gpg_strerror (err));
      agent_exit (0);
    }
  log_assert (pw);

  return pw;
}


static void
release_passphrase (char *pw)
{
  if (pw)
    {
      wipememory (pw, strlen (pw));
      xfree (pw);
    }
}


/* Stub function.  */
int
agent_key_available (ctrl_t ctrl, const unsigned char *grip)
{
  (void)ctrl;
  (void)grip;
  return -1;  /* Not available.  */
}

char *
agent_get_cache (ctrl_t ctrl, const char *key, cache_mode_t cache_mode)
{
  (void)ctrl;
  (void)key;
  (void)cache_mode;
  return NULL;
}

gpg_error_t
agent_askpin (ctrl_t ctrl,
              const char *desc_text, const char *prompt_text,
              const char *initial_errtext,
              struct pin_entry_info_s *pininfo,
              const char *keyinfo, cache_mode_t cache_mode)
{
  gpg_error_t err;
  unsigned char *passphrase;
  size_t size;

  (void)ctrl;
  (void)desc_text;
  (void)prompt_text;
  (void)initial_errtext;
  (void)keyinfo;
  (void)cache_mode;

  *pininfo->pin = 0; /* Reset the PIN. */
  passphrase = get_passphrase (0);
  size = strlen (passphrase);
  if (size >= pininfo->max_length)
    {
      xfree (passphrase);
      return gpg_error (GPG_ERR_TOO_LARGE);
    }

  memcpy (&pininfo->pin, passphrase, size);
  xfree (passphrase);
  pininfo->pin[size] = 0;
  if (pininfo->check_cb)
    {
      /* More checks by utilizing the optional callback. */
      pininfo->cb_errtext = NULL;
      err = pininfo->check_cb (pininfo);
    }
  else
    err = 0;
  return err;
}

/* Replacement for the function in findkey.c.  Here we write the key
 * to stdout. */
gpg_error_t
agent_write_private_key (ctrl_t ctrl, const unsigned char *grip,
                         const void *buffer, size_t length, int force,
                         const char *serialno, const char *keyref,
                         const char *dispserialno, time_t timestamp)
{
  char hexgrip[40+4+1];
  char *p;

  (void)ctrl;
  (void)force;
  (void)serialno;
  (void)keyref;
  (void)timestamp;
  (void)dispserialno;

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");
  p = make_advanced (buffer, length);
  if (p)
    {
      printf ("# Begin dump of %s\n%s%s# End dump of %s\n",
              hexgrip, p, (*p && p[strlen(p)-1] == '\n')? "":"\n", hexgrip);
      xfree (p);
    }

  return 0;
}
