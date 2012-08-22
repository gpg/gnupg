/* genkey.c - Generate a keypair
 *	Copyright (C) 2002, 2003, 2004, 2007 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "agent.h"
#include "i18n.h"
#include "exechelp.h"
#include "sysutils.h"

static int
store_key (gcry_sexp_t private, const char *passphrase, int force)
{
  int rc;
  unsigned char *buf;
  size_t len;
  unsigned char grip[20];

  if ( !gcry_pk_get_keygrip (private, grip) )
    {
      log_error ("can't calculate keygrip\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = gcry_malloc_secure (len);
  if (!buf)
      return out_of_core ();
  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  if (passphrase)
    {
      unsigned char *p;

      rc = agent_protect (buf, passphrase, &p, &len);
      if (rc)
        {
          xfree (buf);
          return rc;
        }
      xfree (buf);
      buf = p;
    }

  rc = agent_write_private_key (grip, buf, len, force);
  xfree (buf);
  return rc;
}


/* Count the number of non-alpha characters in S.  Control characters
   and non-ascii characters are not considered.  */
static size_t
nonalpha_count (const char *s)
{
  size_t n;

  for (n=0; *s; s++)
    if (isascii (*s) && ( isdigit (*s) || ispunct (*s) ))
      n++;

  return n;
}


/* Check PW against a list of pattern.  Return 0 if PW does not match
   these pattern.  */
static int
check_passphrase_pattern (ctrl_t ctrl, const char *pw)
{
  gpg_error_t err = 0;
  const char *pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CHECK_PATTERN);
  FILE *infp;
  const char *argv[10];
  pid_t pid;
  int result, i;

  (void)ctrl;

  infp = gnupg_tmpfile ();
  if (!infp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating temporary file: %s\n"), gpg_strerror (err));
      return 1; /* Error - assume password should not be used.  */
    }

  if (fwrite (pw, strlen (pw), 1, infp) != 1)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error writing to temporary file: %s\n"),
                 gpg_strerror (err));
      fclose (infp);
      return 1; /* Error - assume password should not be used.  */
    }
  rewind (infp);

  i = 0;
  argv[i++] = "--null";
  argv[i++] = "--",
  argv[i++] = opt.check_passphrase_pattern,
  argv[i] = NULL;
  assert (i < sizeof argv);

  if (gnupg_spawn_process_fd (pgmname, argv, fileno (infp), -1, -1, &pid))
    result = 1; /* Execute error - assume password should no be used.  */
  else if (gnupg_wait_process (pgmname, pid, NULL))
    result = 1; /* Helper returned an error - probably a match.  */
  else
    result = 0; /* Success; i.e. no match.  */

  /* Overwrite our temporary file. */
  rewind (infp);
  for (i=((strlen (pw)+99)/100)*100; i > 0; i--)
    putc ('\xff', infp);
  fflush (infp);
  fclose (infp);
  return result;
}


static int
take_this_one_anyway2 (ctrl_t ctrl, const char *desc, const char *anyway_btn)
{
  gpg_error_t err;

  if (opt.enforce_passphrase_constraints)
    {
      err = agent_show_message (ctrl, desc, _("Enter new passphrase"));
      if (!err)
        err = gpg_error (GPG_ERR_CANCELED);
    }
  else
    err = agent_get_confirmation (ctrl, desc,
                                  anyway_btn, _("Enter new passphrase"), 0);
  return err;
}


static int
take_this_one_anyway (ctrl_t ctrl, const char *desc)
{
  return take_this_one_anyway2 (ctrl, desc, _("Take this one anyway"));
}


/* Check whether the passphrase PW is suitable. Returns 0 if the
   passphrase is suitable and true if it is not and the user should be
   asked to provide a different one.  If SILENT is set, no message are
   displayed.  */
int
check_passphrase_constraints (ctrl_t ctrl, const char *pw, int silent)
{
  gpg_error_t err;
  unsigned int minlen = opt.min_passphrase_len;
  unsigned int minnonalpha = opt.min_passphrase_nonalpha;

  if (!pw)
    pw = "";

  if (utf8_charcount (pw) < minlen )
    {
      char *desc;

      if (silent)
        return gpg_error (GPG_ERR_INV_PASSPHRASE);

      desc = xtryasprintf
        ( ngettext ("Warning: You have entered an insecure passphrase.%%0A"
                    "A passphrase should be at least %u character long.",
                    "Warning: You have entered an insecure passphrase.%%0A"
                    "A passphrase should be at least %u characters long.",
                    minlen), minlen );
      if (!desc)
        return gpg_error_from_syserror ();
      err = take_this_one_anyway (ctrl, desc);
      xfree (desc);
      if (err)
        return err;
    }

  if (nonalpha_count (pw) < minnonalpha )
    {
      char *desc;

      if (silent)
        return gpg_error (GPG_ERR_INV_PASSPHRASE);

      desc = xtryasprintf
        ( ngettext ("Warning: You have entered an insecure passphrase.%%0A"
                    "A passphrase should contain at least %u digit or%%0A"
                    "special character.",
                    "Warning: You have entered an insecure passphrase.%%0A"
                    "A passphrase should contain at least %u digits or%%0A"
                    "special characters.",
                    minnonalpha), minnonalpha );
      if (!desc)
        return gpg_error_from_syserror ();
      err = take_this_one_anyway (ctrl, desc);
      xfree (desc);
      if (err)
        return err;
    }

  /* If configured check the passphrase against a list of know words
     and pattern.  The actual test is done by an external program.
     The warning message is generic to give the user no hint on how to
     circumvent this list.  */
  if (*pw && opt.check_passphrase_pattern &&
      check_passphrase_pattern (ctrl, pw))
    {
      const char *desc =
        /* */     _("Warning: You have entered an insecure passphrase.%%0A"
                    "A passphrase may not be a known term or match%%0A"
                    "certain pattern.");

      if (silent)
        return gpg_error (GPG_ERR_INV_PASSPHRASE);

      err = take_this_one_anyway (ctrl, desc);
      if (err)
        return err;
    }

  /* The final check is to warn about an empty passphrase. */
  if (!*pw)
    {
      const char *desc = (opt.enforce_passphrase_constraints?
                          _("You have not entered a passphrase!%0A"
                            "An empty passphrase is not allowed.") :
                          _("You have not entered a passphrase - "
                            "this is in general a bad idea!%0A"
                            "Please confirm that you do not want to "
                            "have any protection on your key."));

      if (silent)
        return gpg_error (GPG_ERR_INV_PASSPHRASE);

      err = take_this_one_anyway2 (ctrl, desc,
                                   _("Yes, protection is not needed"));
      if (err)
        return err;
    }

  return 0;
}


/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static int
reenter_compare_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  return -1;
}



/* Generate a new keypair according to the parameters given in
   KEYPARAM */
int
agent_genkey (ctrl_t ctrl, const char *keyparam, size_t keyparamlen,
              membuf_t *outbuf)
{
  gcry_sexp_t s_keyparam, s_key, s_private, s_public;
  struct pin_entry_info_s *pi, *pi2;
  int rc;
  size_t len;
  char *buf;

  rc = gcry_sexp_sscan (&s_keyparam, NULL, keyparam, keyparamlen);
  if (rc)
    {
      log_error ("failed to convert keyparam: %s\n", gpg_strerror (rc));
      return gpg_error (GPG_ERR_INV_DATA);
    }

  /* Get the passphrase now, cause key generation may take a while. */
  {
    const char *text1 = _("Please enter the passphrase to%0A"
                               "protect your new key");
    const char *text2 = _("Please re-enter this passphrase");
    const char *initial_errtext = NULL;

    pi = gcry_calloc_secure (2, sizeof (*pi) + 100);
    pi2 = pi + (sizeof *pi + 100);
    pi->max_length = 100;
    pi->max_tries = 3;
    pi->with_qualitybar = 1;
    pi2->max_length = 100;
    pi2->max_tries = 3;
    pi2->check_cb = reenter_compare_cb;
    pi2->check_cb_arg = pi->pin;

  next_try:
    rc = agent_askpin (ctrl, text1, NULL, initial_errtext, pi);
    initial_errtext = NULL;
    if (!rc)
      {
        if (check_passphrase_constraints (ctrl, pi->pin, 0))
          {
            pi->failed_tries = 0;
            pi2->failed_tries = 0;
            goto next_try;
          }
        if (pi->pin && *pi->pin)
          {
            rc = agent_askpin (ctrl, text2, NULL, NULL, pi2);
            if (rc == -1)
              { /* The re-entered one did not match and the user did not
                   hit cancel. */
                initial_errtext = _("does not match - try again");
                goto next_try;
              }
          }
      }
    if (rc)
      {
        xfree (pi);
        return rc;
      }

    if (!*pi->pin)
      {
        xfree (pi);
        pi = NULL; /* User does not want a passphrase. */
      }
  }

  rc = gcry_pk_genkey (&s_key, s_keyparam );
  gcry_sexp_release (s_keyparam);
  if (rc)
    {
      log_error ("key generation failed: %s\n", gpg_strerror (rc));
      xfree (pi);
      return rc;
    }

  /* break out the parts */
  s_private = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!s_private)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_key);
      xfree (pi);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  s_public = gcry_sexp_find_token (s_key, "public-key", 0);
  if (!s_public)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_key);
      xfree (pi);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  gcry_sexp_release (s_key); s_key = NULL;

  /* store the secret key */
  if (DBG_CRYPTO)
    log_debug ("storing private key\n");
  rc = store_key (s_private, pi? pi->pin:NULL, 0);
  xfree (pi); pi = NULL;
  gcry_sexp_release (s_private);
  if (rc)
    {
      gcry_sexp_release (s_public);
      return rc;
    }

  /* return the public key */
  if (DBG_CRYPTO)
    log_debug ("returning public key\n");
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      gpg_error_t tmperr = out_of_core ();
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      return tmperr;
    }
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);
  put_membuf (outbuf, buf, len);
  gcry_sexp_release (s_public);
  xfree (buf);

  return 0;
}



/* Apply a new passpahrse to the key S_SKEY and store it. */
int
agent_protect_and_store (ctrl_t ctrl, gcry_sexp_t s_skey)
{
  struct pin_entry_info_s *pi, *pi2;
  int rc;

  {
    const char *text1 = _("Please enter the new passphrase");
    const char *text2 = _("Please re-enter this passphrase");
    const char *initial_errtext = NULL;

    pi = gcry_calloc_secure (2, sizeof (*pi) + 100);
    pi2 = pi + (sizeof *pi + 100);
    pi->max_length = 100;
    pi->max_tries = 3;
    pi->with_qualitybar = 1;
    pi2->max_length = 100;
    pi2->max_tries = 3;
    pi2->check_cb = reenter_compare_cb;
    pi2->check_cb_arg = pi->pin;

  next_try:
    rc = agent_askpin (ctrl, text1, NULL, initial_errtext, pi);
    initial_errtext = NULL;
    if (!rc)
      {
        if (check_passphrase_constraints (ctrl, pi->pin, 0))
          {
            pi->failed_tries = 0;
            pi2->failed_tries = 0;
            goto next_try;
          }
        /* Unless the passphrase is empty, ask to confirm it.  */
        if (pi->pin && *pi->pin)
          {
            rc = agent_askpin (ctrl, text2, NULL, NULL, pi2);
            if (rc == -1)
              { /* The re-entered one did not match and the user did not
                   hit cancel. */
                initial_errtext = _("does not match - try again");
                goto next_try;
              }
          }
      }
    if (rc)
      {
        xfree (pi);
        return rc;
      }

    if (!*pi->pin)
      {
        xfree (pi);
        pi = NULL; /* User does not want a passphrase. */
      }
  }

  rc = store_key (s_skey, pi? pi->pin:NULL, 1);
  xfree (pi);
  return rc;
}
