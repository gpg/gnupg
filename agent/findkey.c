/* findkey.c - Locate the secret key
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007,
 *               2010, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
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
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <npth.h> /* (we use pth_sleep) */

#include "agent.h"
#include "../common/i18n.h"
#include "../common/ssh-utils.h"
#include "../common/name-value.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* Helper to pass data to the check callback of the unprotect function. */
struct try_unprotect_arg_s
{
  ctrl_t ctrl;
  const unsigned char *protected_key;
  unsigned char *unprotected_key;
  int change_required; /* Set by the callback to indicate that the
                          user should change the passphrase.  */
};


/* Note: Ownership of FNAME and FP are moved to this function.  */
static gpg_error_t
write_extended_private_key (char *fname, estream_t fp, int update,
                            const void *buf, size_t len)
{
  gpg_error_t err;
  nvc_t pk = NULL;
  gcry_sexp_t key = NULL;
  int remove = 0;

  if (update)
    {
      int line;

      err = nvc_parse_private_key (&pk, &line, fp);
      if (err && gpg_err_code (err) != GPG_ERR_ENOENT)
        {
          log_error ("error parsing '%s' line %d: %s\n",
                     fname, line, gpg_strerror (err));
          goto leave;
        }
    }
  else
    {
      pk = nvc_new_private_key ();
      if (!pk)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  es_clearerr (fp);

  err = gcry_sexp_sscan (&key, NULL, buf, len);
  if (err)
    goto leave;

  err = nvc_set_private_key (pk, key);
  if (err)
    goto leave;

  err = es_fseek (fp, 0, SEEK_SET);
  if (err)
    goto leave;

  err = nvc_write (pk, fp);
  if (err)
    {
      log_error ("error writing '%s': %s\n", fname, gpg_strerror (err));
      remove = 1;
      goto leave;
    }

  if (ftruncate (es_fileno (fp), es_ftello (fp)))
    {
      err = gpg_error_from_syserror ();
      log_error ("error truncating '%s': %s\n", fname, gpg_strerror (err));
      remove = 1;
      goto leave;
    }

  if (es_fclose (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n", fname, gpg_strerror (err));
      remove = 1;
      goto leave;
    }
  else
    fp = NULL;

  bump_key_eventcounter ();

 leave:
  es_fclose (fp);
  if (remove)
    gnupg_remove (fname);
  xfree (fname);
  gcry_sexp_release (key);
  nvc_release (pk);
  return err;
}

/* Write an S-expression formatted key to our key storage.  With FORCE
   passed as true an existing key with the given GRIP will get
   overwritten.  */
int
agent_write_private_key (const unsigned char *grip,
                         const void *buffer, size_t length, int force)
{
  char *fname;
  estream_t fp;
  char hexgrip[40+4+1];

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (gnupg_homedir (), GNUPG_PRIVATE_KEYS_DIR,
                         hexgrip, NULL);

  /* FIXME: Write to a temp file first so that write failures during
     key updates won't lead to a key loss.  */

  if (!force && !access (fname, F_OK))
    {
      log_error ("secret key file '%s' already exists\n", fname);
      xfree (fname);
      return gpg_error (GPG_ERR_EEXIST);
    }

  fp = es_fopen (fname, force? "rb+,mode=-rw" : "wbx,mode=-rw");
  if (!fp)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();

      if (force && gpg_err_code (tmperr) == GPG_ERR_ENOENT)
        {
          fp = es_fopen (fname, "wbx,mode=-rw");
          if (!fp)
            tmperr = gpg_error_from_syserror ();
        }
      if (!fp)
        {
          log_error ("can't create '%s': %s\n", fname, gpg_strerror (tmperr));
          xfree (fname);
          return tmperr;
        }
    }
  else if (force)
    {
      gpg_error_t rc;
      char first;

      /* See if an existing key is in extended format.  */
      if (es_fread (&first, 1, 1, fp) != 1)
        {
          rc = gpg_error_from_syserror ();
          log_error ("error reading first byte from '%s': %s\n",
                     fname, strerror (errno));
          xfree (fname);
          es_fclose (fp);
          return rc;
        }

      rc = es_fseek (fp, 0, SEEK_SET);
      if (rc)
        {
          log_error ("error seeking in '%s': %s\n", fname, strerror (errno));
          xfree (fname);
          es_fclose (fp);
          return rc;
        }

      if (first != '(')
        {
          /* Key is already in the extended format.  */
          return write_extended_private_key (fname, fp, 1, buffer, length);
        }
      if (first == '(' && opt.enable_extended_key_format)
        {
          /* Key is in the old format - but we want the extended format.  */
          return write_extended_private_key (fname, fp, 0, buffer, length);
        }
    }

  if (opt.enable_extended_key_format)
    return write_extended_private_key (fname, fp, 0, buffer, length);

  if (es_fwrite (buffer, length, 1, fp) != 1)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      log_error ("error writing '%s': %s\n", fname, gpg_strerror (tmperr));
      es_fclose (fp);
      gnupg_remove (fname);
      xfree (fname);
      return tmperr;
    }

  /* When force is given, the file might have to be truncated.  */
  if (force && ftruncate (es_fileno (fp), es_ftello (fp)))
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      log_error ("error truncating '%s': %s\n", fname, gpg_strerror (tmperr));
      es_fclose (fp);
      gnupg_remove (fname);
      xfree (fname);
      return tmperr;
    }

  if (es_fclose (fp))
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      log_error ("error closing '%s': %s\n", fname, gpg_strerror (tmperr));
      gnupg_remove (fname);
      xfree (fname);
      return tmperr;
    }
  bump_key_eventcounter ();
  xfree (fname);
  return 0;
}


/* Callback function to try the unprotection from the passphrase query
   code. */
static gpg_error_t
try_unprotect_cb (struct pin_entry_info_s *pi)
{
  struct try_unprotect_arg_s *arg = pi->check_cb_arg;
  ctrl_t ctrl = arg->ctrl;
  size_t dummy;
  gpg_error_t err;
  gnupg_isotime_t now, protected_at, tmptime;
  char *desc = NULL;

  assert (!arg->unprotected_key);

  arg->change_required = 0;
  err = agent_unprotect (ctrl, arg->protected_key, pi->pin, protected_at,
                         &arg->unprotected_key, &dummy);
  if (err)
    return err;
  if (!opt.max_passphrase_days || ctrl->in_passwd)
    return 0;  /* No regular passphrase change required.  */

  if (!*protected_at)
    {
      /* No protection date known - must force passphrase change.  */
      desc = xtrystrdup (L_("Note: This passphrase has never been changed.%0A"
                            "Please change it now."));
      if (!desc)
        return gpg_error_from_syserror ();
    }
  else
    {
      gnupg_get_isotime (now);
      gnupg_copy_time (tmptime, protected_at);
      err = add_days_to_isotime (tmptime, opt.max_passphrase_days);
      if (err)
        return err;
      if (strcmp (now, tmptime) > 0 )
        {
          /* Passphrase "expired".  */
          desc = xtryasprintf
            (L_("This passphrase has not been changed%%0A"
                "since %.4s-%.2s-%.2s.  Please change it now."),
             protected_at, protected_at+4, protected_at+6);
          if (!desc)
            return gpg_error_from_syserror ();
        }
    }

  if (desc)
    {
      /* Change required.  */
      if (opt.enforce_passphrase_constraints)
        {
          err = agent_get_confirmation (ctrl, desc,
                                        L_("Change passphrase"), NULL, 0);
          if (!err)
            arg->change_required = 1;
        }
      else
        {
          err = agent_get_confirmation (ctrl, desc,
                                        L_("Change passphrase"),
                                        L_("I'll change it later"), 0);
          if (!err)
            arg->change_required = 1;
          else if (gpg_err_code (err) == GPG_ERR_CANCELED
                   || gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
            err = 0;
        }
      xfree (desc);
    }

  return err;
}


/* Modify a Key description, replacing certain special format
   characters.  List of currently supported replacements:

   %% - Replaced by a single %
   %c - Replaced by the content of COMMENT.
   %C - Same as %c but put into parentheses.
   %F - Replaced by an ssh style fingerprint computed from KEY.

   The functions returns 0 on success or an error code.  On success a
   newly allocated string is stored at the address of RESULT.
 */
gpg_error_t
agent_modify_description (const char *in, const char *comment,
                          const gcry_sexp_t key, char **result)
{
  size_t comment_length;
  size_t in_len;
  size_t out_len;
  char *out;
  size_t i;
  int special, pass;
  char *ssh_fpr = NULL;
  char *p;

  *result = NULL;

  if (!comment)
    comment = "";

  comment_length = strlen (comment);
  in_len  = strlen (in);

  /* First pass calculates the length, second pass does the actual
     copying.  */
  /* FIXME: This can be simplified by using es_fopenmem.  */
  out = NULL;
  out_len = 0;
  for (pass=0; pass < 2; pass++)
    {
      special = 0;
      for (i = 0; i < in_len; i++)
        {
          if (special)
            {
              special = 0;
              switch (in[i])
                {
                case '%':
                  if (out)
                    *out++ = '%';
                  else
                    out_len++;
                  break;

                case 'c': /* Comment.  */
                  if (out)
                    {
                      memcpy (out, comment, comment_length);
                      out += comment_length;
                    }
                  else
                    out_len += comment_length;
                  break;

                case 'C': /* Comment.  */
                  if (!comment_length)
                    ;
                  else if (out)
                    {
                      *out++ = '(';
                      memcpy (out, comment, comment_length);
                      out += comment_length;
                      *out++ = ')';
                    }
                  else
                    out_len += comment_length + 2;
                  break;

                case 'F': /* SSH style fingerprint.  */
                  if (!ssh_fpr && key)
                    ssh_get_fingerprint_string (key, &ssh_fpr);
                  if (ssh_fpr)
                    {
                      if (out)
                        out = stpcpy (out, ssh_fpr);
                      else
                        out_len += strlen (ssh_fpr);
                    }
                  break;

                default: /* Invalid special sequences are kept as they are. */
                  if (out)
                    {
                      *out++ = '%';
                      *out++ = in[i];
                    }
                  else
                    out_len+=2;
                  break;
                }
            }
          else if (in[i] == '%')
            special = 1;
          else
            {
              if (out)
                *out++ = in[i];
              else
                out_len++;
            }
        }

      if (!pass)
        {
          *result = out = xtrymalloc (out_len + 1);
          if (!out)
            {
              xfree (ssh_fpr);
              return gpg_error_from_syserror ();
            }
        }
    }

  *out = 0;
  log_assert (*result + out_len == out);
  xfree (ssh_fpr);

  /* The ssh prompt may sometimes end in
   *    "...%0A  ()"
   * The empty parentheses doesn't look very good.  We use this hack
   * here to remove them as well as the indentation spaces. */
  p = *result;
  i = strlen (p);
  if (i > 2 && !strcmp (p + i - 2, "()"))
    {
      p += i - 2;
      *p-- = 0;
      while (p > *result && spacep (p))
        *p-- = 0;
    }

  return 0;
}



/* Unprotect the canconical encoded S-expression key in KEYBUF.  GRIP
   should be the hex encoded keygrip of that key to be used with the
   caching mechanism. DESC_TEXT may be set to override the default
   description used for the pinentry.  If LOOKUP_TTL is given this
   function is used to lookup the default ttl.  If R_PASSPHRASE is not
   NULL, the function succeeded and the key was protected the used
   passphrase (entered or from the cache) is stored there; if not NULL
   will be stored.  The caller needs to free the returned
   passphrase. */
static int
unprotect (ctrl_t ctrl, const char *cache_nonce, const char *desc_text,
           unsigned char **keybuf, const unsigned char *grip,
           cache_mode_t cache_mode, lookup_ttl_t lookup_ttl,
           char **r_passphrase)
{
  struct pin_entry_info_s *pi;
  struct try_unprotect_arg_s arg;
  int rc;
  unsigned char *result;
  size_t resultlen;
  char hexgrip[40+1];

  if (r_passphrase)
    *r_passphrase = NULL;

  bin2hex (grip, 20, hexgrip);

  /* Initially try to get it using a cache nonce.  */
  if (cache_nonce)
    {
      char *pw;

      pw = agent_get_cache (cache_nonce, CACHE_MODE_NONCE);
      if (pw)
        {
          rc = agent_unprotect (ctrl, *keybuf, pw, NULL, &result, &resultlen);
          if (!rc)
            {
              if (r_passphrase)
                *r_passphrase = pw;
              else
                xfree (pw);
              xfree (*keybuf);
              *keybuf = result;
              return 0;
            }
          xfree (pw);
        }
    }

  /* First try to get it from the cache - if there is none or we can't
     unprotect it, we fall back to ask the user */
  if (cache_mode != CACHE_MODE_IGNORE)
    {
      char *pw;

    retry:
      pw = agent_get_cache (hexgrip, cache_mode);
      if (pw)
        {
          rc = agent_unprotect (ctrl, *keybuf, pw, NULL, &result, &resultlen);
          if (!rc)
            {
              if (cache_mode == CACHE_MODE_NORMAL)
                agent_store_cache_hit (hexgrip);
              if (r_passphrase)
                *r_passphrase = pw;
              else
                xfree (pw);
              xfree (*keybuf);
              *keybuf = result;
              return 0;
            }
          xfree (pw);
        }
      else if (cache_mode == CACHE_MODE_NORMAL)
        {
          /* The standard use of GPG keys is to have a signing and an
             encryption subkey.  Commonly both use the same
             passphrase.  We try to help the user to enter the
             passphrase only once by silently trying the last
             correctly entered passphrase.  Checking one additional
             passphrase should be acceptable; despite the S2K
             introduced delays. The assumed workflow is:

               1. Read encrypted message in a MUA and thus enter a
                  passphrase for the encryption subkey.

               2. Reply to that mail with an encrypted and signed
                  mail, thus entering the passphrase for the signing
                  subkey.

             We can often avoid the passphrase entry in the second
             step.  We do this only in normal mode, so not to
             interfere with unrelated cache entries.  */
          pw = agent_get_cache (NULL, cache_mode);
          if (pw)
            {
              rc = agent_unprotect (ctrl, *keybuf, pw, NULL,
                                    &result, &resultlen);
              if (!rc)
                {
                  if (r_passphrase)
                    *r_passphrase = pw;
                  else
                    xfree (pw);
                  xfree (*keybuf);
                  *keybuf = result;
                  return 0;
                }
              xfree (pw);
            }
        }

      /* If the pinentry is currently in use, we wait up to 60 seconds
         for it to close and check the cache again.  This solves a common
         situation where several requests for unprotecting a key have
         been made but the user is still entering the passphrase for
         the first request.  Because all requests to agent_askpin are
         serialized they would then pop up one after the other to
         request the passphrase - despite that the user has already
         entered it and is then available in the cache.  This
         implementation is not race free but in the worst case the
         user has to enter the passphrase only once more. */
      if (pinentry_active_p (ctrl, 0))
        {
          /* Active - wait */
          if (!pinentry_active_p (ctrl, 60))
            {
              /* We need to give the other thread a chance to actually put
                 it into the cache. */
              npth_sleep (1);
              goto retry;
            }
          /* Timeout - better call pinentry now the plain way. */
        }
    }

  pi = gcry_calloc_secure (1, sizeof (*pi) + MAX_PASSPHRASE_LEN + 1);
  if (!pi)
    return gpg_error_from_syserror ();
  pi->max_length = MAX_PASSPHRASE_LEN + 1;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 16;
  pi->max_tries = 3;
  pi->check_cb = try_unprotect_cb;
  arg.ctrl = ctrl;
  arg.protected_key = *keybuf;
  arg.unprotected_key = NULL;
  arg.change_required = 0;
  pi->check_cb_arg = &arg;

  rc = agent_askpin (ctrl, desc_text, NULL, NULL, pi, hexgrip, cache_mode);
  if (!rc)
    {
      assert (arg.unprotected_key);
      if (arg.change_required)
        {
          /* The callback told as that the user should change their
             passphrase.  Present the dialog to do.  */
          size_t canlen, erroff;
          gcry_sexp_t s_skey;

          assert (arg.unprotected_key);
          canlen = gcry_sexp_canon_len (arg.unprotected_key, 0, NULL, NULL);
          rc = gcry_sexp_sscan (&s_skey, &erroff,
                                (char*)arg.unprotected_key, canlen);
          if (rc)
            {
              log_error ("failed to build S-Exp (off=%u): %s\n",
                         (unsigned int)erroff, gpg_strerror (rc));
              wipememory (arg.unprotected_key, canlen);
              xfree (arg.unprotected_key);
              xfree (pi);
              return rc;
            }
          rc = agent_protect_and_store (ctrl, s_skey, NULL);
          gcry_sexp_release (s_skey);
          if (rc)
            {
              log_error ("changing the passphrase failed: %s\n",
                         gpg_strerror (rc));
              wipememory (arg.unprotected_key, canlen);
              xfree (arg.unprotected_key);
              xfree (pi);
              return rc;
            }
        }
      else
        {
          /* Passphrase is fine.  */
          agent_put_cache (hexgrip, cache_mode, pi->pin,
                           lookup_ttl? lookup_ttl (hexgrip) : 0);
          agent_store_cache_hit (hexgrip);
          if (r_passphrase && *pi->pin)
            *r_passphrase = xtrystrdup (pi->pin);
        }
      xfree (*keybuf);
      *keybuf = arg.unprotected_key;
    }
  xfree (pi);
  return rc;
}


/* Read the key identified by GRIP from the private key directory and
   return it as an gcrypt S-expression object in RESULT.  On failure
   returns an error code and stores NULL at RESULT. */
static gpg_error_t
read_key_file (const unsigned char *grip, gcry_sexp_t *result)
{
  int rc;
  char *fname;
  estream_t fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen, erroff;
  gcry_sexp_t s_skey;
  char hexgrip[40+4+1];
  char first;

  *result = NULL;

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (gnupg_homedir (), GNUPG_PRIVATE_KEYS_DIR,
                         hexgrip, NULL);
  fp = es_fopen (fname, "rb");
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      if (gpg_err_code (rc) != GPG_ERR_ENOENT)
        log_error ("can't open '%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return rc;
    }

  if (es_fread (&first, 1, 1, fp) != 1)
    {
      rc = gpg_error_from_syserror ();
      log_error ("error reading first byte from '%s': %s\n",
                 fname, strerror (errno));
      xfree (fname);
      es_fclose (fp);
      return rc;
    }

  rc = es_fseek (fp, 0, SEEK_SET);
  if (rc)
    {
      log_error ("error seeking in '%s': %s\n", fname, strerror (errno));
      xfree (fname);
      es_fclose (fp);
      return rc;
    }

  if (first != '(')
    {
      /* Key is in extended format.  */
      nvc_t pk;
      int line;

      rc = nvc_parse_private_key (&pk, &line, fp);
      es_fclose (fp);

      if (rc)
        log_error ("error parsing '%s' line %d: %s\n",
                   fname, line, gpg_strerror (rc));
      else
        {
          rc = nvc_get_private_key (pk, result);
          nvc_release (pk);
          if (rc)
            log_error ("error getting private key from '%s': %s\n",
                       fname, gpg_strerror (rc));
        }

      xfree (fname);
      return rc;
    }

  if (fstat (es_fileno (fp), &st))
    {
      rc = gpg_error_from_syserror ();
      log_error ("can't stat '%s': %s\n", fname, strerror (errno));
      xfree (fname);
      es_fclose (fp);
      return rc;
    }

  buflen = st.st_size;
  buf = xtrymalloc (buflen+1);
  if (!buf)
    {
      rc = gpg_error_from_syserror ();
      log_error ("error allocating %zu bytes for '%s': %s\n",
                 buflen, fname, strerror (errno));
      xfree (fname);
      es_fclose (fp);
      xfree (buf);
      return rc;

    }

  if (es_fread (buf, buflen, 1, fp) != 1)
    {
      rc = gpg_error_from_syserror ();
      log_error ("error reading %zu bytes from '%s': %s\n",
                 buflen, fname, strerror (errno));
      xfree (fname);
      es_fclose (fp);
      xfree (buf);
      return rc;
    }

  /* Convert the file into a gcrypt S-expression object.  */
  rc = gcry_sexp_sscan (&s_skey, &erroff, (char*)buf, buflen);
  xfree (fname);
  es_fclose (fp);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      return rc;
    }
  *result = s_skey;
  return 0;
}


/* Remove the key identified by GRIP from the private key directory.  */
static gpg_error_t
remove_key_file (const unsigned char *grip)
{
  gpg_error_t err = 0;
  char *fname;
  char hexgrip[40+4+1];

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");
  fname = make_filename (gnupg_homedir (), GNUPG_PRIVATE_KEYS_DIR,
                         hexgrip, NULL);
  if (gnupg_remove (fname))
    err = gpg_error_from_syserror ();
  xfree (fname);
  return err;
}


/* Return the secret key as an S-Exp in RESULT after locating it using
   the GRIP.  If the operation shall be diverted to a token, an
   allocated S-expression with the shadow_info part from the file is
   stored at SHADOW_INFO; if not NULL will be stored at SHADOW_INFO.
   CACHE_MODE defines now the cache shall be used.  DESC_TEXT may be
   set to present a custom description for the pinentry.  LOOKUP_TTL
   is an optional function to convey a TTL to the cache manager; we do
   not simply pass the TTL value because the value is only needed if
   an unprotect action was needed and looking up the TTL may have some
   overhead (e.g. scanning the sshcontrol file).  If a CACHE_NONCE is
   given that cache item is first tried to get a passphrase.  If
   R_PASSPHRASE is not NULL, the function succeeded and the key was
   protected the used passphrase (entered or from the cache) is stored
   there; if not NULL will be stored.  The caller needs to free the
   returned passphrase.   */
gpg_error_t
agent_key_from_file (ctrl_t ctrl, const char *cache_nonce,
                     const char *desc_text,
                     const unsigned char *grip, unsigned char **shadow_info,
                     cache_mode_t cache_mode, lookup_ttl_t lookup_ttl,
                     gcry_sexp_t *result, char **r_passphrase)
{
  int rc;
  unsigned char *buf;
  size_t len, buflen, erroff;
  gcry_sexp_t s_skey;

  *result = NULL;
  if (shadow_info)
    *shadow_info = NULL;
  if (r_passphrase)
    *r_passphrase = NULL;

  rc = read_key_file (grip, &s_skey);
  if (rc)
    {
      if (gpg_err_code (rc) == GPG_ERR_ENOENT)
        rc = gpg_error (GPG_ERR_NO_SECKEY);
      return rc;
    }

  /* For use with the protection functions we also need the key as an
     canonical encoded S-expression in a buffer.  Create this buffer
     now.  */
  rc = make_canon_sexp (s_skey, &buf, &len);
  if (rc)
    return rc;

  switch (agent_private_key_type (buf))
    {
    case PRIVATE_KEY_CLEAR:
      break; /* no unprotection needed */
    case PRIVATE_KEY_OPENPGP_NONE:
      {
        unsigned char *buf_new;
        size_t buf_newlen;

        rc = agent_unprotect (ctrl, buf, "", NULL, &buf_new, &buf_newlen);
        if (rc)
          log_error ("failed to convert unprotected openpgp key: %s\n",
                     gpg_strerror (rc));
        else
          {
            xfree (buf);
            buf = buf_new;
          }
      }
      break;
    case PRIVATE_KEY_PROTECTED:
      {
	char *desc_text_final;
	char *comment = NULL;

        /* Note, that we will take the comment as a C string for
           display purposes; i.e. all stuff beyond a Nul character is
           ignored.  */
        {
          gcry_sexp_t comment_sexp;

          comment_sexp = gcry_sexp_find_token (s_skey, "comment", 0);
          if (comment_sexp)
            comment = gcry_sexp_nth_string (comment_sexp, 1);
          gcry_sexp_release (comment_sexp);
        }

        desc_text_final = NULL;
	if (desc_text)
          rc = agent_modify_description (desc_text, comment, s_skey,
                                         &desc_text_final);
        gcry_free (comment);

	if (!rc)
	  {
	    rc = unprotect (ctrl, cache_nonce, desc_text_final, &buf, grip,
                            cache_mode, lookup_ttl, r_passphrase);
	    if (rc)
	      log_error ("failed to unprotect the secret key: %s\n",
			 gpg_strerror (rc));
	  }

	xfree (desc_text_final);
      }
      break;
    case PRIVATE_KEY_SHADOWED:
      if (shadow_info)
        {
          const unsigned char *s;
          size_t n;

          rc = agent_get_shadow_info (buf, &s);
          if (!rc)
            {
              n = gcry_sexp_canon_len (s, 0, NULL,NULL);
              assert (n);
              *shadow_info = xtrymalloc (n);
              if (!*shadow_info)
                rc = out_of_core ();
              else
                {
                  memcpy (*shadow_info, s, n);
                  rc = 0;
                }
            }
          if (rc)
            log_error ("get_shadow_info failed: %s\n", gpg_strerror (rc));
        }
      else
        rc = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      break;
    default:
      log_error ("invalid private key format\n");
      rc = gpg_error (GPG_ERR_BAD_SECKEY);
      break;
    }
  gcry_sexp_release (s_skey);
  s_skey = NULL;
  if (rc)
    {
      xfree (buf);
      if (r_passphrase)
        {
          xfree (*r_passphrase);
          *r_passphrase = NULL;
        }
      return rc;
    }

  buflen = gcry_sexp_canon_len (buf, 0, NULL, NULL);
  rc = gcry_sexp_sscan (&s_skey, &erroff, (char*)buf, buflen);
  wipememory (buf, buflen);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      if (r_passphrase)
        {
          xfree (*r_passphrase);
          *r_passphrase = NULL;
        }
      return rc;
    }

  *result = s_skey;
  return 0;
}


/* Return the string name from the S-expression S_KEY as well as a
   string describing the names of the parameters.  ALGONAMESIZE and
   ELEMSSIZE give the allocated size of the provided buffers.  The
   buffers may be NULL if not required.  If R_LIST is not NULL the top
   level list will be stored there; the caller needs to release it in
   this case.  */
static gpg_error_t
key_parms_from_sexp (gcry_sexp_t s_key, gcry_sexp_t *r_list,
                     char *r_algoname, size_t algonamesize,
                     char *r_elems, size_t elemssize)
{
  gcry_sexp_t list, l2;
  const char *name, *algoname, *elems;
  size_t n;

  if (r_list)
    *r_list = NULL;

  list = gcry_sexp_find_token (s_key, "shadowed-private-key", 0 );
  if (!list)
    list = gcry_sexp_find_token (s_key, "protected-private-key", 0 );
  if (!list)
    list = gcry_sexp_find_token (s_key, "private-key", 0 );
  if (!list)
    {
      log_error ("invalid private key format\n");
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  name = gcry_sexp_nth_data (list, 0, &n);
  if (n==3 && !memcmp (name, "rsa", 3))
    {
      algoname = "rsa";
      elems = "ne";
    }
  else if (n==3 && !memcmp (name, "dsa", 3))
    {
      algoname = "dsa";
      elems = "pqgy";
    }
  else if (n==3 && !memcmp (name, "ecc", 3))
    {
      algoname = "ecc";
      elems = "pabgnq";
    }
  else if (n==5 && !memcmp (name, "ecdsa", 5))
    {
      algoname = "ecdsa";
      elems = "pabgnq";
    }
  else if (n==4 && !memcmp (name, "ecdh", 4))
    {
      algoname = "ecdh";
      elems = "pabgnq";
    }
  else if (n==3 && !memcmp (name, "elg", 3))
    {
      algoname = "elg";
      elems = "pgy";
    }
  else
    {
      log_error ("unknown private key algorithm\n");
      gcry_sexp_release (list);
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  if (r_algoname)
    {
      if (strlen (algoname) >= algonamesize)
        return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
      strcpy (r_algoname, algoname);
    }
  if (r_elems)
    {
      if (strlen (elems) >= elemssize)
        return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
      strcpy (r_elems, elems);
    }

  if (r_list)
    *r_list = list;
  else
    gcry_sexp_release (list);

  return 0;
}


/* Return true if KEYPARMS holds an EdDSA key.  */
static int
is_eddsa (gcry_sexp_t keyparms)
{
  int result = 0;
  gcry_sexp_t list;
  const char *s;
  size_t n;
  int i;

  list = gcry_sexp_find_token (keyparms, "flags", 0);
  for (i = list ? gcry_sexp_length (list)-1 : 0; i > 0; i--)
    {
      s = gcry_sexp_nth_data (list, i, &n);
      if (!s)
        continue; /* Not a data element. */

      if (n == 5 && !memcmp (s, "eddsa", 5))
        {
          result = 1;
          break;
        }
    }
  gcry_sexp_release (list);
  return result;
}


/* Return the public key algorithm number if S_KEY is a DSA style key.
   If it is not a DSA style key, return 0.  */
int
agent_is_dsa_key (gcry_sexp_t s_key)
{
  int result;
  gcry_sexp_t list;
  char algoname[6];

  if (!s_key)
    return 0;

  if (key_parms_from_sexp (s_key, &list, algoname, sizeof algoname, NULL, 0))
    return 0; /* Error - assume it is not an DSA key.  */

  if (!strcmp (algoname, "dsa"))
    result = GCRY_PK_DSA;
  else if (!strcmp (algoname, "ecc"))
    {
      if (is_eddsa (list))
        result = 0;
      else
        result = GCRY_PK_ECDSA;
    }
  else if (!strcmp (algoname, "ecdsa"))
    result = GCRY_PK_ECDSA;
  else
    result = 0;

  gcry_sexp_release (list);
  return result;
}


/* Return true if S_KEY is an EdDSA key as used with curve Ed25519.  */
int
agent_is_eddsa_key (gcry_sexp_t s_key)
{
  int result;
  gcry_sexp_t list;
  char algoname[6];

  if (!s_key)
    return 0;

  if (key_parms_from_sexp (s_key, &list, algoname, sizeof algoname, NULL, 0))
    return 0; /* Error - assume it is not an EdDSA key.  */

  if (!strcmp (algoname, "ecc") && is_eddsa (list))
    result = 1;
  else if (!strcmp (algoname, "eddsa")) /* backward compatibility.  */
    result = 1;
  else
    result = 0;

  gcry_sexp_release (list);
  return result;
}


/* Return the key for the keygrip GRIP.  The result is stored at
   RESULT.  This function extracts the key from the private key
   database and returns it as an S-expression object as it is.  On
   failure an error code is returned and NULL stored at RESULT. */
gpg_error_t
agent_raw_key_from_file (ctrl_t ctrl, const unsigned char *grip,
                         gcry_sexp_t *result)
{
  gpg_error_t err;
  gcry_sexp_t s_skey;

  (void)ctrl;

  *result = NULL;

  err = read_key_file (grip, &s_skey);
  if (!err)
    *result = s_skey;
  return err;
}


/* Return the public key for the keygrip GRIP.  The result is stored
   at RESULT.  This function extracts the public key from the private
   key database.  On failure an error code is returned and NULL stored
   at RESULT. */
gpg_error_t
agent_public_key_from_file (ctrl_t ctrl,
                            const unsigned char *grip,
                            gcry_sexp_t *result)
{
  gpg_error_t err;
  int i, idx;
  gcry_sexp_t s_skey;
  const char *algoname, *elems;
  int npkey;
  gcry_mpi_t array[10];
  gcry_sexp_t curve = NULL;
  gcry_sexp_t flags = NULL;
  gcry_sexp_t uri_sexp, comment_sexp;
  const char *uri, *comment;
  size_t uri_length, comment_length;
  char *format, *p;
  void *args[2+7+2+2+1]; /* Size is 2 + max. # of elements + 2 for uri + 2
                            for comment + end-of-list.  */
  int argidx;
  gcry_sexp_t list = NULL;
  const char *s;

  (void)ctrl;

  *result = NULL;

  err = read_key_file (grip, &s_skey);
  if (err)
    return err;

  for (i=0; i < DIM (array); i++)
    array[i] = NULL;

  err = extract_private_key (s_skey, 0, &algoname, &npkey, NULL, &elems,
                             array, DIM (array), &curve, &flags);
  if (err)
    {
      gcry_sexp_release (s_skey);
      return err;
    }

  uri = NULL;
  uri_length = 0;
  uri_sexp = gcry_sexp_find_token (s_skey, "uri", 0);
  if (uri_sexp)
    uri = gcry_sexp_nth_data (uri_sexp, 1, &uri_length);

  comment = NULL;
  comment_length = 0;
  comment_sexp = gcry_sexp_find_token (s_skey, "comment", 0);
  if (comment_sexp)
    comment = gcry_sexp_nth_data (comment_sexp, 1, &comment_length);

  gcry_sexp_release (s_skey);
  s_skey = NULL;


  /* FIXME: The following thing is pretty ugly code; we should
     investigate how to make it cleaner.  Probably code to handle
     canonical S-expressions in a memory buffer is better suited for
     such a task.  After all that is what we do in protect.c.  Need
     to find common patterns and write a straightformward API to use
     them.  */
  assert (sizeof (size_t) <= sizeof (void*));

  format = xtrymalloc (15+4+7*npkey+10+15+1+1);
  if (!format)
    {
      err = gpg_error_from_syserror ();
      for (i=0; array[i]; i++)
        gcry_mpi_release (array[i]);
      gcry_sexp_release (curve);
      gcry_sexp_release (flags);
      gcry_sexp_release (uri_sexp);
      gcry_sexp_release (comment_sexp);
      return err;
    }

  argidx = 0;
  p = stpcpy (stpcpy (format, "(public-key("), algoname);
  p = stpcpy (p, "%S%S");       /* curve name and flags.  */
  args[argidx++] = &curve;
  args[argidx++] = &flags;
  for (idx=0, s=elems; idx < npkey; idx++)
    {
      *p++ = '(';
      *p++ = *s++;
      p = stpcpy (p, " %m)");
      assert (argidx < DIM (args));
      args[argidx++] = &array[idx];
    }
  *p++ = ')';
  if (uri)
    {
      p = stpcpy (p, "(uri %b)");
      assert (argidx+1 < DIM (args));
      args[argidx++] = (void *)&uri_length;
      args[argidx++] = (void *)&uri;
    }
  if (comment)
    {
      p = stpcpy (p, "(comment %b)");
      assert (argidx+1 < DIM (args));
      args[argidx++] = (void *)&comment_length;
      args[argidx++] = (void*)&comment;
    }
  *p++ = ')';
  *p = 0;
  assert (argidx < DIM (args));
  args[argidx] = NULL;

  err = gcry_sexp_build_array (&list, NULL, format, args);
  xfree (format);
  for (i=0; array[i]; i++)
    gcry_mpi_release (array[i]);
  gcry_sexp_release (curve);
  gcry_sexp_release (flags);
  gcry_sexp_release (uri_sexp);
  gcry_sexp_release (comment_sexp);

  if (!err)
    *result = list;
  return err;
}



/* Check whether the secret key identified by GRIP is available.
   Returns 0 is the key is available.  */
int
agent_key_available (const unsigned char *grip)
{
  int result;
  char *fname;
  char hexgrip[40+4+1];

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (gnupg_homedir (), GNUPG_PRIVATE_KEYS_DIR,
                         hexgrip, NULL);
  result = !access (fname, R_OK)? 0 : -1;
  xfree (fname);
  return result;
}



/* Return the information about the secret key specified by the binary
   keygrip GRIP.  If the key is a shadowed one the shadow information
   will be stored at the address R_SHADOW_INFO as an allocated
   S-expression.  */
gpg_error_t
agent_key_info_from_file (ctrl_t ctrl, const unsigned char *grip,
                          int *r_keytype, unsigned char **r_shadow_info)
{
  gpg_error_t err;
  unsigned char *buf;
  size_t len;
  int keytype;

  (void)ctrl;

  if (r_keytype)
    *r_keytype = PRIVATE_KEY_UNKNOWN;
  if (r_shadow_info)
    *r_shadow_info = NULL;

  {
    gcry_sexp_t sexp;

    err = read_key_file (grip, &sexp);
    if (err)
      {
        if (gpg_err_code (err) == GPG_ERR_ENOENT)
          return gpg_error (GPG_ERR_NOT_FOUND);
        else
          return err;
      }
    err = make_canon_sexp (sexp, &buf, &len);
    gcry_sexp_release (sexp);
    if (err)
      return err;
  }

  keytype = agent_private_key_type (buf);
  switch (keytype)
    {
    case PRIVATE_KEY_CLEAR:
    case PRIVATE_KEY_OPENPGP_NONE:
      break;
    case PRIVATE_KEY_PROTECTED:
      /* If we ever require it we could retrieve the comment fields
         from such a key. */
      break;
    case PRIVATE_KEY_SHADOWED:
      if (r_shadow_info)
        {
          const unsigned char *s;
          size_t n;

          err = agent_get_shadow_info (buf, &s);
          if (!err)
            {
              n = gcry_sexp_canon_len (s, 0, NULL, NULL);
              assert (n);
              *r_shadow_info = xtrymalloc (n);
              if (!*r_shadow_info)
                err = gpg_error_from_syserror ();
              else
                memcpy (*r_shadow_info, s, n);
            }
        }
      break;
    default:
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      break;
    }

  if (!err && r_keytype)
    *r_keytype = keytype;

  xfree (buf);
  return err;
}



/* Delete the key with GRIP from the disk after having asked for
 * confirmation using DESC_TEXT.  If FORCE is set the function won't
 * require a confirmation via Pinentry or warns if the key is also
 * used by ssh.  If ONLY_STUBS is set only stub keys (references to
 * smartcards) will be affected.
 *
 * Common error codes are:
 *   GPG_ERR_NO_SECKEY
 *   GPG_ERR_KEY_ON_CARD
 *   GPG_ERR_NOT_CONFIRMED
 *   GPG_ERR_FORBIDDEN     - Not a stub key and ONLY_STUBS requested.
 */
gpg_error_t
agent_delete_key (ctrl_t ctrl, const char *desc_text,
                  const unsigned char *grip, int force, int only_stubs)
{
  gpg_error_t err;
  gcry_sexp_t s_skey = NULL;
  unsigned char *buf = NULL;
  size_t len;
  char *desc_text_final = NULL;
  char *comment = NULL;
  ssh_control_file_t cf = NULL;
  char hexgrip[40+4+1];
  char *default_desc = NULL;
  int key_type;

  err = read_key_file (grip, &s_skey);
  if (gpg_err_code (err) == GPG_ERR_ENOENT)
    err = gpg_error (GPG_ERR_NO_SECKEY);
  if (err)
    goto leave;

  err = make_canon_sexp (s_skey, &buf, &len);
  if (err)
    goto leave;

  key_type = agent_private_key_type (buf);
  if (only_stubs && key_type != PRIVATE_KEY_SHADOWED)
    {
      err  = gpg_error (GPG_ERR_FORBIDDEN);
      goto leave;
    }

  switch (key_type)
    {
    case PRIVATE_KEY_CLEAR:
    case PRIVATE_KEY_OPENPGP_NONE:
    case PRIVATE_KEY_PROTECTED:
      bin2hex (grip, 20, hexgrip);
      if (!force)
        {
          if (!desc_text)
            {
              default_desc = xtryasprintf
          (L_("Do you really want to delete the key identified by keygrip%%0A"
              "  %s%%0A  %%C%%0A?"), hexgrip);
              desc_text = default_desc;
            }

          /* Note, that we will take the comment as a C string for
             display purposes; i.e. all stuff beyond a Nul character is
             ignored.  */
          {
            gcry_sexp_t comment_sexp;

            comment_sexp = gcry_sexp_find_token (s_skey, "comment", 0);
            if (comment_sexp)
              comment = gcry_sexp_nth_string (comment_sexp, 1);
            gcry_sexp_release (comment_sexp);
          }

          if (desc_text)
            err = agent_modify_description (desc_text, comment, s_skey,
                                            &desc_text_final);
          if (err)
            goto leave;

          err = agent_get_confirmation (ctrl, desc_text_final,
                                        L_("Delete key"), L_("No"), 0);
          if (err)
            goto leave;

          cf = ssh_open_control_file ();
          if (cf)
            {
              if (!ssh_search_control_file (cf, hexgrip, NULL, NULL, NULL))
                {
                  err = agent_get_confirmation
                    (ctrl,
                     L_("Warning: This key is also listed for use with SSH!\n"
                        "Deleting the key might remove your ability to "
                        "access remote machines."),
                     L_("Delete key"), L_("No"), 0);
                  if (err)
                    goto leave;
                }
            }
        }
      err = remove_key_file (grip);
      break;

    case PRIVATE_KEY_SHADOWED:
      err = remove_key_file (grip);
      break;

    default:
      log_error ("invalid private key format\n");
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      break;
    }

 leave:
  ssh_close_control_file (cf);
  gcry_free (comment);
  xfree (desc_text_final);
  xfree (default_desc);
  xfree (buf);
  gcry_sexp_release (s_skey);
  return err;
}


/* Write an S-expression formatted shadow key to our key storage.
   Shadow key is created by an S-expression public key in PKBUF and
   card's SERIALNO and the IDSTRING.  With FORCE passed as true an
   existing key with the given GRIP will get overwritten.  */
gpg_error_t
agent_write_shadow_key (const unsigned char *grip,
                        const char *serialno, const char *keyid,
                        const unsigned char *pkbuf, int force)
{
  gpg_error_t err;
  unsigned char *shadow_info;
  unsigned char *shdkey;
  size_t len;

  shadow_info = make_shadow_info (serialno, keyid);
  if (!shadow_info)
    return gpg_error_from_syserror ();

  err = agent_shadow_key (pkbuf, shadow_info, &shdkey);
  xfree (shadow_info);
  if (err)
    {
      log_error ("shadowing the key failed: %s\n", gpg_strerror (err));
      return err;
    }

  len = gcry_sexp_canon_len (shdkey, 0, NULL, NULL);
  err = agent_write_private_key (grip, shdkey, len, force);
  xfree (shdkey);
  if (err)
    log_error ("error writing key: %s\n", gpg_strerror (err));

  return err;
}
