/* genkey.c - Generate a keypair
 * Copyright (C) 2002, 2003, 2004, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH.
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
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>

#include "agent.h"
#include "../common/i18n.h"
#include "../common/exechelp.h"
#include "../common/sysutils.h"

static int
store_key (gcry_sexp_t private, const char *passphrase, int force,
           unsigned long s2k_count, time_t timestamp)
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

      rc = agent_protect (buf, passphrase, &p, &len, s2k_count, -1);
      if (rc)
        {
          xfree (buf);
          return rc;
        }
      xfree (buf);
      buf = p;
    }

  rc = agent_write_private_key (grip, buf, len, force, timestamp,
                                NULL, NULL, NULL);
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
   these pattern.  If CHECK_CONSTRAINTS_NEW_SYMKEY is set in flags and
   --check-sym-passphrase-pattern has been configured, use the pattern
   file from that option.  */
static int
do_check_passphrase_pattern (ctrl_t ctrl, const char *pw, unsigned int flags)
{
  gpg_error_t err = 0;
  const char *pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CHECK_PATTERN);
  estream_t stream_to_check_pattern = NULL;
  const char *argv[10];
  pid_t pid;
  int result, i;
  const char *pattern;
  char *patternfname;

  (void)ctrl;

  pattern = opt.check_passphrase_pattern;
  if ((flags & CHECK_CONSTRAINTS_NEW_SYMKEY)
      && opt.check_sym_passphrase_pattern)
    pattern = opt.check_sym_passphrase_pattern;
  if (!pattern)
    return 1; /* Oops - Assume password should not be used  */

  if (strchr (pattern, '/') || strchr (pattern, '\\')
      || (*pattern == '~' && pattern[1] == '/'))
    patternfname = make_absfilename_try (pattern, NULL);
  else
    patternfname = make_filename_try (gnupg_sysconfdir (), pattern, NULL);
  if (!patternfname)
    {
      log_error ("error making filename from '%s': %s\n",
                 pattern, gpg_strerror (gpg_error_from_syserror ()));
      return 1; /* Do not pass the check.  */
    }

  /* Make debugging a broken config easier by printing a useful error
   * message.  */
  if (gnupg_access (patternfname, F_OK))
    {
      log_error ("error accessing '%s': %s\n",
                 patternfname, gpg_strerror (gpg_error_from_syserror ()));
      xfree (patternfname);
      return 1; /* Do not pass the check.  */
    }

  i = 0;
  argv[i++] = "--null";
  argv[i++] = "--",
  argv[i++] = patternfname,
  argv[i] = NULL;
  assert (i < sizeof argv);

  if (gnupg_spawn_process (pgmname, argv, NULL, NULL, 0,
                           &stream_to_check_pattern, NULL, NULL, &pid))
    result = 1; /* Execute error - assume password should no be used.  */
  else
    {
      es_set_binary (stream_to_check_pattern);
      if (es_fwrite (pw, strlen (pw), 1, stream_to_check_pattern) != 1)
        {
          err = gpg_error_from_syserror ();
          log_error (_("error writing to pipe: %s\n"), gpg_strerror (err));
          result = 1; /* Error - assume password should not be used.  */
        }
      else
        es_fflush (stream_to_check_pattern);
      es_fclose (stream_to_check_pattern);
      if (gnupg_wait_process (pgmname, pid, 1, NULL))
        result = 1; /* Helper returned an error - probably a match.  */
      else
        result = 0; /* Success; i.e. no match.  */
      gnupg_release_process (pid);
    }

  xfree (patternfname);
  return result;
}


static int
take_this_one_anyway2 (ctrl_t ctrl, const char *desc, const char *anyway_btn)
{
  gpg_error_t err;

  if (opt.enforce_passphrase_constraints)
    {
      err = agent_show_message (ctrl, desc, L_("Enter new passphrase"));
      if (!err)
        err = gpg_error (GPG_ERR_CANCELED);
    }
  else
    err = agent_get_confirmation (ctrl, desc,
                                  anyway_btn, L_("Enter new passphrase"), 0);
  return err;
}


static int
take_this_one_anyway (ctrl_t ctrl, const char *desc)
{
  return take_this_one_anyway2 (ctrl, desc, L_("Take this one anyway"));
}


/* Check whether the passphrase PW is suitable. Returns 0 if the
 * passphrase is suitable and true if it is not and the user should be
 * asked to provide a different one.  If FAILED_CONSTRAINT is set, a
 * message describing the problem is returned at FAILED_CONSTRAINT.
 * The FLAGS are:
 *   CHECK_CONSTRAINTS_NOT_EMPTY
 *       Do not allow an empty passphrase
 *   CHECK_CONSTRAINTS_NEW_SYMKEY
 *       Hint that the passphrase is used for a new symmetric key.
 */
int
check_passphrase_constraints (ctrl_t ctrl, const char *pw, unsigned int flags,
			      char **failed_constraint)
{
  gpg_error_t err = 0;
  unsigned int minlen = opt.min_passphrase_len;
  unsigned int minnonalpha = opt.min_passphrase_nonalpha;
  char *msg1 = NULL;
  char *msg2 = NULL;
  char *msg3 = NULL;
  int no_empty = !!(flags & CHECK_CONSTRAINTS_NOT_EMPTY);

  if (ctrl && ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
    return 0;

  if (!pw)
    pw = "";

  /* The first check is to warn about an empty passphrase. */
  if (!*pw)
    {
      const char *desc = (opt.enforce_passphrase_constraints || no_empty?
                          L_("You have not entered a passphrase!%0A"
                             "An empty passphrase is not allowed.") :
                          L_("You have not entered a passphrase - "
                             "this is in general a bad idea!%0A"
                             "Please confirm that you do not want to "
                             "have any protection on your key."));

      err = 1;
      if (failed_constraint)
	{
	  if (opt.enforce_passphrase_constraints || no_empty)
	    *failed_constraint = xstrdup (desc);
	  else
	    err = take_this_one_anyway2 (ctrl, desc,
					 L_("Yes, protection is not needed"));
	}

      goto leave;
    }

  /* Now check the constraints and collect the error messages unless
     in silent mode which returns immediately.  */
  if (utf8_charcount (pw, -1) < minlen )
    {
      if (!failed_constraint)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg1 = xtryasprintf
        ( ngettext ("A passphrase should be at least %u character long.",
                    "A passphrase should be at least %u characters long.",
                    minlen), minlen );
      if (!msg1)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (nonalpha_count (pw) < minnonalpha )
    {
      if (!failed_constraint)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg2 = xtryasprintf
        ( ngettext ("A passphrase should contain at least %u digit or%%0A"
                    "special character.",
                    "A passphrase should contain at least %u digits or%%0A"
                    "special characters.",
                    minnonalpha), minnonalpha );
      if (!msg2)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* If configured check the passphrase against a list of known words
     and pattern.  The actual test is done by an external program.
     The warning message is generic to give the user no hint on how to
     circumvent this list.  */
  if (*pw
      && (opt.check_passphrase_pattern || opt.check_sym_passphrase_pattern)
      && do_check_passphrase_pattern (ctrl, pw, flags))
    {
      if (!failed_constraint)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg3 = xtryasprintf
        (L_("A passphrase may not be a known term or match%%0A"
            "certain pattern."));
      if (!msg3)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (failed_constraint && (msg1 || msg2 || msg3))
    {
      char *msg;
      size_t n;

      msg = strconcat
        (L_("Warning: You have entered an insecure passphrase."),
         "%0A%0A",
         msg1? msg1 : "", msg1? "%0A" : "",
         msg2? msg2 : "", msg2? "%0A" : "",
         msg3? msg3 : "", msg3? "%0A" : "",
         NULL);
      if (!msg)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      /* Strip a trailing "%0A".  */
      n = strlen (msg);
      if (n > 3 && !strcmp (msg + n - 3, "%0A"))
        msg[n-3] = 0;

      err = 1;
      if (opt.enforce_passphrase_constraints)
	*failed_constraint = msg;
      else
	{
	  err = take_this_one_anyway (ctrl, msg);
	  xfree (msg);
	}
    }

 leave:
  xfree (msg1);
  xfree (msg2);
  xfree (msg3);
  return err;
}


/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static gpg_error_t
reenter_compare_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  return gpg_error (GPG_ERR_BAD_PASSPHRASE);
}


/* Ask the user for a new passphrase using PROMPT.  On success the
   function returns 0 and store the passphrase at R_PASSPHRASE; if the
   user opted not to use a passphrase NULL will be stored there.  The
   user needs to free the returned string.  In case of an error and
   error code is returned and NULL stored at R_PASSPHRASE.  */
gpg_error_t
agent_ask_new_passphrase (ctrl_t ctrl, const char *prompt,
                          char **r_passphrase)
{
  gpg_error_t err;
  const char *text1 = prompt;
  const char *text2 = L_("Please re-enter this passphrase");
  char *initial_errtext = NULL;
  struct pin_entry_info_s *pi, *pi2;

  *r_passphrase = NULL;

  if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
    {
	size_t size;
	unsigned char *buffer;

	err = pinentry_loopback (ctrl, "NEW_PASSPHRASE", &buffer, &size,
                                 MAX_PASSPHRASE_LEN);
	if (!err)
	  {
	    if (size)
	      {
		buffer[size] = 0;
		*r_passphrase = buffer;
	      }
	    else
	        *r_passphrase = NULL;
	  }
	return err;
    }

  pi = gcry_calloc_secure (1, sizeof (*pi) + MAX_PASSPHRASE_LEN + 1);
  if (!pi)
    return gpg_error_from_syserror ();
  pi2 = gcry_calloc_secure (1, sizeof (*pi2) + MAX_PASSPHRASE_LEN + 1);
  if (!pi2)
    {
      err = gpg_error_from_syserror ();
      xfree (pi);
      return err;
    }
  pi->max_length = MAX_PASSPHRASE_LEN + 1;
  pi->max_tries = 3;
  pi->with_qualitybar = 0;
  pi->with_repeat = 1;
  pi2->max_length = MAX_PASSPHRASE_LEN + 1;
  pi2->max_tries = 3;
  pi2->check_cb = reenter_compare_cb;
  pi2->check_cb_arg = pi->pin;

 next_try:
  err = agent_askpin (ctrl, text1, NULL, initial_errtext, pi, NULL, 0);
  xfree (initial_errtext);
  initial_errtext = NULL;
  if (!err)
    {
      if (check_passphrase_constraints (ctrl, pi->pin, 0, &initial_errtext))
        {
          pi->failed_tries = 0;
          pi2->failed_tries = 0;
          goto next_try;
        }
      /* Unless the passphrase is empty or the pinentry told us that
         it already did the repetition check, ask to confirm it.  */
      if (*pi->pin && !pi->repeat_okay)
        {
          err = agent_askpin (ctrl, text2, NULL, NULL, pi2, NULL, 0);
          if (gpg_err_code (err) == GPG_ERR_BAD_PASSPHRASE)
            { /* The re-entered one did not match and the user did not
                 hit cancel. */
              initial_errtext = xtrystrdup (L_("does not match - try again"));
              if (initial_errtext)
                goto next_try;
              err = gpg_error_from_syserror ();
            }
        }
    }

  if (!err && *pi->pin)
    {
      /* User wants a passphrase. */
      *r_passphrase = xtrystrdup (pi->pin);
      if (!*r_passphrase)
        err = gpg_error_from_syserror ();
    }

  xfree (initial_errtext);
  xfree (pi2);
  xfree (pi);
  return err;
}



/* Generate a new keypair according to the parameters given in
   KEYPARAM.  If CACHE_NONCE is given first try to lookup a passphrase
   using the cache nonce.  If NO_PROTECTION is true the key will not
   be protected by a passphrase.  If OVERRIDE_PASSPHRASE is true that
   passphrase will be used for the new key.  If TIMESTAMP is not zero
   it will be recorded as creation date of the key (unless extended
   format is disabled) . */
int
agent_genkey (ctrl_t ctrl, const char *cache_nonce, time_t timestamp,
              const char *keyparam, size_t keyparamlen, int no_protection,
              const char *override_passphrase, int preset, membuf_t *outbuf)
{
  gcry_sexp_t s_keyparam, s_key, s_private, s_public;
  char *passphrase_buffer = NULL;
  const char *passphrase;
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
  if (override_passphrase)
    passphrase = override_passphrase;
  else if (no_protection || !cache_nonce)
    passphrase = NULL;
  else
    {
      passphrase_buffer = agent_get_cache (ctrl, cache_nonce, CACHE_MODE_NONCE);
      passphrase = passphrase_buffer;
    }

  if (passphrase || no_protection)
    ;
  else
    {
      rc = agent_ask_new_passphrase (ctrl,
                                     L_("Please enter the passphrase to%0A"
                                        "protect your new key"),
                                     &passphrase_buffer);
      if (rc)
        return rc;
      passphrase = passphrase_buffer;
    }

  rc = gcry_pk_genkey (&s_key, s_keyparam );
  gcry_sexp_release (s_keyparam);
  if (rc)
    {
      log_error ("key generation failed: %s\n", gpg_strerror (rc));
      xfree (passphrase_buffer);
      return rc;
    }

  /* break out the parts */
  s_private = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!s_private)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_key);
      xfree (passphrase_buffer);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  s_public = gcry_sexp_find_token (s_key, "public-key", 0);
  if (!s_public)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_key);
      xfree (passphrase_buffer);
      return gpg_error (GPG_ERR_INV_DATA);
    }
  gcry_sexp_release (s_key); s_key = NULL;

  /* store the secret key */
  if (DBG_CRYPTO)
    log_debug ("storing private key\n");
  rc = store_key (s_private, passphrase, 0, ctrl->s2k_count, timestamp);
  if (!rc)
    {
      if (!cache_nonce)
        {
          char tmpbuf[12];
          gcry_create_nonce (tmpbuf, 12);
          cache_nonce = bin2hex (tmpbuf, 12, NULL);
        }
      if (cache_nonce
          && !no_protection
          && !agent_put_cache (ctrl, cache_nonce, CACHE_MODE_NONCE,
                               passphrase, ctrl->cache_ttl_opt_preset))
        agent_write_status (ctrl, "CACHE_NONCE", cache_nonce, NULL);
      if (preset && !no_protection)
	{
	  unsigned char grip[20];
	  char hexgrip[40+1];
	  if (gcry_pk_get_keygrip (s_private, grip))
	    {
	      bin2hex(grip, 20, hexgrip);
	      rc = agent_put_cache (ctrl, hexgrip, CACHE_MODE_ANY, passphrase,
                                    ctrl->cache_ttl_opt_preset);
	    }
	}
    }
  xfree (passphrase_buffer);
  passphrase_buffer = NULL;
  passphrase = NULL;
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



/* Apply a new passphrase to the key S_SKEY and store it.  If
   PASSPHRASE_ADDR and *PASSPHRASE_ADDR are not NULL, use that
   passphrase.  If PASSPHRASE_ADDR is not NULL store a newly entered
   passphrase at that address. */
gpg_error_t
agent_protect_and_store (ctrl_t ctrl, gcry_sexp_t s_skey,
                         char **passphrase_addr)
{
  gpg_error_t err;

  if (passphrase_addr && *passphrase_addr)
    {
      /* Take an empty string as request not to protect the key.  */
      err = store_key (s_skey, **passphrase_addr? *passphrase_addr:NULL, 1,
                       ctrl->s2k_count, 0);
    }
  else
    {
      char *pass = NULL;

      if (passphrase_addr)
        {
          xfree (*passphrase_addr);
          *passphrase_addr = NULL;
        }
      err = agent_ask_new_passphrase (ctrl,
                                      L_("Please enter the new passphrase"),
                                      &pass);
      if (!err)
        err = store_key (s_skey, pass, 1, ctrl->s2k_count, 0);
      if (!err && passphrase_addr)
        *passphrase_addr = pass;
      else
        xfree (pass);
    }

  return err;
}
