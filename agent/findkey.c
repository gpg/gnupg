/* findkey.c - locate the secret key
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

#include "agent.h"

/* Helper to pass data to the check callback of the unprotect function. */
struct try_unprotect_arg_s {
  const unsigned char *protected_key;
  unsigned char *unprotected_key;
};



int
agent_write_private_key (const unsigned char *grip,
                         const void *buffer, size_t length, int force)
{
  int i;
  char *fname;
  FILE *fp;
  char hexgrip[40+4+1];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  if (force)
    fp = fopen (fname, "wb");
  else
    {
      int fd;

      if (!access (fname, F_OK))
      {
        log_error ("secret key file `%s' already exists\n", fname);
        xfree (fname);
        return gpg_error (GPG_ERR_GENERAL);
      }

      /* We would like to create FNAME but only if it does not already
	 exist.  We cannot make this guarantee just using POSIX (GNU
	 provides the "x" opentype for fopen, however, this is not
	 portable).  Thus, we use the more flexible open function and
	 then use fdopen to obtain a stream.

	 The mode parameter to open is what fopen uses.  It will be
	 combined with the process' umask automatically.  */
      fd = open (fname, O_CREAT | O_EXCL | O_RDWR,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
      if (fd < 0)
	fp = 0;
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

  assert (!arg->unprotected_key);
  return agent_unprotect (arg->protected_key, pi->pin,
                          &arg->unprotected_key, &dummy);
}


/* Unprotect the canconical encoded S-expression key in KEYBUF.  GRIP
   should be the hex encoded keygrip of that key to be used with the
   caching mechanism. */
static int
unprotect (CTRL ctrl,
           unsigned char **keybuf, const unsigned char *grip, int ignore_cache)
{
  struct pin_entry_info_s *pi;
  struct try_unprotect_arg_s arg;
  int rc, i;
  unsigned char *result;
  size_t resultlen;
  char hexgrip[40+1];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  hexgrip[40] = 0;

  /* First try to get it from the cache - if there is none or we can't
     unprotect it, we fall back to ask the user */
  if (!ignore_cache)
    {
      void *cache_marker;
      const char *pw = agent_get_cache (hexgrip, &cache_marker);
      if (pw)
        {
          rc = agent_unprotect (*keybuf, pw, &result, &resultlen);
          agent_unlock_cache_entry (&cache_marker);
          if (!rc)
            {
              xfree (*keybuf);
              *keybuf = result;
              return 0;
            }
          rc  = 0;
        }
    }
  
  pi = gcry_calloc_secure (1, sizeof (*pi) + 100);
  pi->max_length = 100;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 8;
  pi->max_tries = 3;
  pi->check_cb = try_unprotect_cb;
  arg.protected_key = *keybuf;
  arg.unprotected_key = NULL;
  pi->check_cb_arg = &arg;

  rc = agent_askpin (ctrl, NULL, pi);
  if (!rc)
    {
      assert (arg.unprotected_key);
      agent_put_cache (hexgrip, pi->pin, 0);
      xfree (*keybuf);
      *keybuf = arg.unprotected_key;
    }
  xfree (pi);
  return rc;
}



/* Return the secret key as an S-Exp in RESULT after locating it using
   the grip.  Returns NULL in RESULT if the operation should be
   diverted to a token; SHADOW_INFO will point then to an allocated
   S-Expression with the shadow_info part from the file.  With
   IGNORE_CACHE passed as true the passphrase is not taken from the
   cache.*/
gpg_error_t
agent_key_from_file (CTRL ctrl,
                     const unsigned char *grip, unsigned char **shadow_info,
                     int ignore_cache, gcry_sexp_t *result)
{
  int i, rc;
  char *fname;
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t len, buflen, erroff;
  gcry_sexp_t s_skey;
  char hexgrip[40+4+1];
  int got_shadow_info = 0;
  
  *result = NULL;
  if (shadow_info)
      *shadow_info = NULL;

  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  fp = fopen (fname, "rb");
  if (!fp)
    {
      rc = gpg_error_from_errno (errno);
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return rc;
    }
  
  if (fstat (fileno(fp), &st))
    {
      rc = gpg_error_from_errno (errno);
      log_error ("can't stat `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      return rc;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      rc = gpg_error_from_errno (errno);
      log_error ("error reading `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      xfree (buf);
      return rc;
    }

  rc = gcry_sexp_sscan (&s_skey, &erroff, buf, buflen);
  xfree (fname);
  fclose (fp);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gpg_strerror (rc));
      return rc;
    }
  len = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      rc = out_of_core ();
      gcry_sexp_release (s_skey);
      return rc;
    }
  len = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);
  gcry_sexp_release (s_skey);

  switch (agent_private_key_type (buf))
    {
    case PRIVATE_KEY_CLEAR:
      break; /* no unprotection needed */
    case PRIVATE_KEY_PROTECTED:
      rc = unprotect (ctrl, &buf, grip, ignore_cache);
      if (rc)
        log_error ("failed to unprotect the secret key: %s\n",
                   gpg_strerror (rc));
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
  if (rc || got_shadow_info)
    {
      xfree (buf);
      return rc;
    }

  buflen = gcry_sexp_canon_len (buf, 0, NULL, NULL);
  rc = gcry_sexp_sscan (&s_skey, &erroff, buf, buflen);
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

/* Return the secret key as an S-Exp after locating it using the grip.
   Returns NULL if key is not available. 0 = key is available */
int
agent_key_available (const unsigned char *grip)
{
  int i;
  char *fname;
  char hexgrip[40+4+1];
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, GNUPG_PRIVATE_KEYS_DIR, hexgrip, NULL);
  i = !access (fname, R_OK)? 0 : -1;
  xfree (fname);
  return i;
}



