/* findkey.c - Locate the secret key
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007,
 *               2010, 2011 Free Software Foundation, Inc.
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
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <pth.h> /* (we use pth_sleep) */

#include "agent.h"
#include "i18n.h"
#include "../common/ssh-utils.h"

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
                          user should chnage the passphrase.  */
};


/* Write an S-expression formatted key to our key storage.  With FORCE
   passed as true an existing key with the given GRIP will get
   overwritten.  */
int
agent_write_private_key (const unsigned char *grip,
                         const void *buffer, size_t length, int force)
{
  char *fname;
  FILE *fp;
  char hexgrip[40+4+1];
  int fd;

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);

  if (!force && !access (fname, F_OK))
    {
      log_error ("secret key file `%s' already exists\n", fname);
      xfree (fname);
      return gpg_error (GPG_ERR_GENERAL);
    }

  /* In FORCE mode we would like to create FNAME but only if it does
     not already exist.  We cannot make this guarantee just using
     POSIX (GNU provides the "x" opentype for fopen, however, this is
     not portable).  Thus, we use the more flexible open function and
     then use fdopen to obtain a stream. */
  fd = open (fname, force? (O_CREAT | O_TRUNC | O_WRONLY | O_BINARY)
                         : (O_CREAT | O_EXCL | O_WRONLY | O_BINARY),
             S_IRUSR | S_IWUSR
#ifndef HAVE_W32_SYSTEM
                 | S_IRGRP
#endif
                 );
  if (fd < 0)
    fp = NULL;
  else
    {
      fp = fdopen (fd, "wb");
      if (!fp)
        {
          int save_e = errno;
          close (fd);
          errno = save_e;
        }
    }

  if (!fp)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("can't create `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return tmperr;
    }

  if (fwrite (buffer, length, 1, fp) != 1)
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("error writing `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      remove (fname);
      xfree (fname);
      return tmperr;
    }
  if ( fclose (fp) )
    {
      gpg_error_t tmperr = gpg_error (gpg_err_code_from_errno (errno));
      log_error ("error closing `%s': %s\n", fname, strerror (errno));
      remove (fname);
      xfree (fname);
      return tmperr;
    }
  bump_key_eventcounter ();
  xfree (fname);
  return 0;
}


/* Callback function to try the unprotection from the passpharse query
   code. */
static int
try_unprotect_cb (struct pin_entry_info_s *pi)
{
  struct try_unprotect_arg_s *arg = pi->check_cb_arg;
  size_t dummy;
  gpg_error_t err;
  gnupg_isotime_t now, protected_at, tmptime;
  char *desc = NULL;

  assert (!arg->unprotected_key);

  arg->change_required = 0;
  err = agent_unprotect (arg->protected_key, pi->pin, protected_at,
                         &arg->unprotected_key, &dummy);
  if (err)
    return err;
  if (!opt.max_passphrase_days || arg->ctrl->in_passwd)
    return 0;  /* No regular passphrase change required.  */

  if (!*protected_at)
    {
      /* No protection date known - must force passphrase change.  */
      desc = xtrystrdup (_("Note: This passphrase has never been changed.%0A"
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
            (_("This passphrase has not been changed%%0A"
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
          err = agent_get_confirmation (arg->ctrl, desc,
                                        _("Change passphrase"), NULL, 0);
          if (!err)
            arg->change_required = 1;
        }
      else
        {
          err = agent_get_confirmation (arg->ctrl, desc,
                                        _("Change passphrase"),
                                        _("I'll change it later"), 0);
          if (!err)
            arg->change_required = 1;
          else if (gpg_err_code (err) == GPG_ERR_CANCELED)
            err = 0;
        }
      xfree (desc);
    }

  return 0;
}


/* Modify a Key description, replacing certain special format
   characters.  List of currently supported replacements:

   %% - Replaced by a single %
   %c - Replaced by the content of COMMENT.
   %F - Replaced by an ssh style fingerprint computed from KEY.

   The functions returns 0 on success or an error code.  On success a
   newly allocated string is stored at the address of RESULT.
 */
static gpg_error_t
modify_description (const char *in, const char *comment, const gcry_sexp_t key,
                    char **result)
{
  size_t comment_length;
  size_t in_len;
  size_t out_len;
  char *out;
  size_t i;
  int special, pass;
  char *ssh_fpr = NULL;

  comment_length = strlen (comment);
  in_len  = strlen (in);

  /* First pass calculates the length, second pass does the actual
     copying.  */
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
  assert (*result + out_len == out);
  xfree (ssh_fpr);
  return 0;
}



/* Unprotect the canconical encoded S-expression key in KEYBUF.  GRIP
   should be the hex encoded keygrip of that key to be used with the
   caching mechanism. DESC_TEXT may be set to override the default
   description used for the pinentry.  If LOOKUP_TTL is given this
   function is used to lookup the default ttl. */
static int
unprotect (ctrl_t ctrl, const char *desc_text,
           unsigned char **keybuf, const unsigned char *grip,
           cache_mode_t cache_mode, lookup_ttl_t lookup_ttl)
{
  struct pin_entry_info_s *pi;
  struct try_unprotect_arg_s arg;
  int rc;
  unsigned char *result;
  size_t resultlen;
  char hexgrip[40+1];

  bin2hex (grip, 20, hexgrip);

  /* First try to get it from the cache - if there is none or we can't
     unprotect it, we fall back to ask the user */
  if (cache_mode != CACHE_MODE_IGNORE)
    {
      void *cache_marker;
      const char *pw;

    retry:
      pw = agent_get_cache (hexgrip, cache_mode, &cache_marker);
      if (pw)
        {
          rc = agent_unprotect (*keybuf, pw, NULL, &result, &resultlen);
          agent_unlock_cache_entry (&cache_marker);
          if (!rc)
            {
              xfree (*keybuf);
              *keybuf = result;
              return 0;
            }
          rc  = 0;
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
              pth_sleep (1);
              goto retry;
            }
          /* Timeout - better call pinentry now the plain way. */
        }
    }

  pi = gcry_calloc_secure (1, sizeof (*pi) + 100);
  if (!pi)
    return gpg_error_from_syserror ();
  pi->max_length = 100;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 16;
  pi->max_tries = 3;
  pi->check_cb = try_unprotect_cb;
  arg.ctrl = ctrl;
  arg.protected_key = *keybuf;
  arg.unprotected_key = NULL;
  arg.change_required = 0;
  pi->check_cb_arg = &arg;

  rc = agent_askpin (ctrl, desc_text, NULL, NULL, pi);
  if (!rc)
    {
      assert (arg.unprotected_key);
      if (arg.change_required)
        {
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
          rc = agent_protect_and_store (ctrl, s_skey);
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
        agent_put_cache (hexgrip, cache_mode, pi->pin,
                         lookup_ttl? lookup_ttl (hexgrip) : 0);
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
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen, erroff;
  gcry_sexp_t s_skey;
  char hexgrip[40+4+1];

  *result = NULL;

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  fp = fopen (fname, "rb");
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      if (gpg_err_code (rc) != GPG_ERR_ENOENT)
        log_error ("can't open `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return rc;
    }

  if (fstat (fileno(fp), &st))
    {
      rc = gpg_error_from_syserror ();
      log_error ("can't stat `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      return rc;
    }

  buflen = st.st_size;
  buf = xtrymalloc (buflen+1);
  if (!buf || fread (buf, buflen, 1, fp) != 1)
    {
      rc = gpg_error_from_syserror ();
      log_error ("error reading `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      xfree (buf);
      return rc;
    }

  /* Convert the file into a gcrypt S-expression object.  */
  rc = gcry_sexp_sscan (&s_skey, &erroff, (char*)buf, buflen);
  xfree (fname);
  fclose (fp);
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


/* Return the secret key as an S-Exp in RESULT after locating it using
   the GRIP.  Stores NULL at RESULT if the operation shall be diverted
   to a token; in this case an allocated S-expression with the
   shadow_info part from the file is stored at SHADOW_INFO.
   CACHE_MODE defines now the cache shall be used.  DESC_TEXT may be
   set to present a custom description for the pinentry.  LOOKUP_TTL
   is an optional function to convey a TTL to the cache manager; we do
   not simply pass the TTL value because the value is only needed if an
   unprotect action was needed and looking up the TTL may have some
   overhead (e.g. scanning the sshcontrol file). */
gpg_error_t
agent_key_from_file (ctrl_t ctrl, const char *desc_text,
                     const unsigned char *grip, unsigned char **shadow_info,
                     cache_mode_t cache_mode, lookup_ttl_t lookup_ttl,
                     gcry_sexp_t *result)
{
  int rc;
  unsigned char *buf;
  size_t len, buflen, erroff;
  gcry_sexp_t s_skey;
  int got_shadow_info = 0;

  *result = NULL;
  if (shadow_info)
    *shadow_info = NULL;

  rc = read_key_file (grip, &s_skey);
  if (rc)
    return rc;

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
          rc = modify_description (desc_text, comment? comment:"", s_skey,
                                   &desc_text_final);
        gcry_free (comment);

	if (!rc)
	  {
	    rc = unprotect (ctrl, desc_text_final, &buf, grip,
                            cache_mode, lookup_ttl);
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
                  got_shadow_info = 1;
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
  if (rc || got_shadow_info)
    {
      xfree (buf);
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
      return rc;
    }

  *result = s_skey;
  return 0;
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
  int i, idx, rc;
  gcry_sexp_t s_skey;
  const char *algoname;
  gcry_sexp_t uri_sexp, comment_sexp;
  const char *uri, *comment;
  size_t uri_length, comment_length;
  char *format, *p;
  void *args[4+2+2+1]; /* Size is max. # of elements + 2 for uri + 2
                           for comment + end-of-list.  */
  int argidx;
  gcry_sexp_t list, l2;
  const char *name;
  const char *s;
  size_t n;
  const char *elems;
  gcry_mpi_t *array;

  (void)ctrl;

  *result = NULL;

  rc = read_key_file (grip, &s_skey);
  if (rc)
    return rc;

  list = gcry_sexp_find_token (s_skey, "shadowed-private-key", 0 );
  if (!list)
    list = gcry_sexp_find_token (s_skey, "protected-private-key", 0 );
  if (!list)
    list = gcry_sexp_find_token (s_skey, "private-key", 0 );
  if (!list)
    {
      log_error ("invalid private key format\n");
      gcry_sexp_release (s_skey);
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
  else if (n==3 && !memcmp (name, "elg", 3))
    {
      algoname = "elg";
      elems = "pgy";
    }
  else
    {
      log_error ("unknown private key algorithm\n");
      gcry_sexp_release (list);
      gcry_sexp_release (s_skey);
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }

  /* Allocate an array for the parameters and copy them out of the
     secret key.   FIXME: We should have a generic copy function. */
  array = xtrycalloc (strlen(elems) + 1, sizeof *array);
  if (!array)
    {
      rc = gpg_error_from_syserror ();
      gcry_sexp_release (list);
      gcry_sexp_release (s_skey);
      return rc;
    }

  for (idx=0, s=elems; *s; s++, idx++ )
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          /* Required parameter not found.  */
          for (i=0; i<idx; i++)
            gcry_mpi_release (array[i]);
          xfree (array);
          gcry_sexp_release (list);
          gcry_sexp_release (s_skey);
          return gpg_error (GPG_ERR_BAD_SECKEY);
	}
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx])
        {
          /* Required parameter is invalid. */
          for (i=0; i<idx; i++)
            gcry_mpi_release (array[i]);
          xfree (array);
          gcry_sexp_release (list);
          gcry_sexp_release (s_skey);
          return gpg_error (GPG_ERR_BAD_SECKEY);
	}
    }
  gcry_sexp_release (list);
  list = NULL;

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
     investigate how to make it cleaner. Probably code to handle
     canonical S-expressions in a memory buffer is better suioted for
     such a task.  After all that is what we do in protect.c.  Neeed
     to find common patterns and write a straightformward API to use
     them.  */
  assert (sizeof (size_t) <= sizeof (void*));

  format = xtrymalloc (15+7*strlen (elems)+10+15+1+1);
  if (!format)
    {
      rc = gpg_error_from_syserror ();
      for (i=0; array[i]; i++)
        gcry_mpi_release (array[i]);
      xfree (array);
      gcry_sexp_release (uri_sexp);
      gcry_sexp_release (comment_sexp);
      return rc;
    }

  argidx = 0;
  p = stpcpy (stpcpy (format, "(public-key("), algoname);
  for (idx=0, s=elems; *s; s++, idx++ )
    {
      *p++ = '(';
      *p++ = *s;
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

  rc = gcry_sexp_build_array (&list, NULL, format, args);
  xfree (format);
  for (i=0; array[i]; i++)
    gcry_mpi_release (array[i]);
  xfree (array);
  gcry_sexp_release (uri_sexp);
  gcry_sexp_release (comment_sexp);

  if (!rc)
    *result = list;
  return rc;
}



/* Return the secret key as an S-Exp after locating it using the grip.
   Returns NULL if key is not available. 0 = key is available */
int
agent_key_available (const unsigned char *grip)
{
  int result;
  char *fname;
  char hexgrip[40+4+1];

  bin2hex (grip, 20, hexgrip);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
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
