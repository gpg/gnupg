/* findkey.c - locate the secret key
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"


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

  fname = make_filename (opt.homedir, "private-keys-v1.d", hexgrip, NULL);
  if (force)
    fp = fopen (fname, "wb");
  else
    {
      if (!access (fname, F_OK))
      {
        log_error ("secret key file `%s' already exists\n", fname);
        xfree (fname);
        return seterr (General_Error);
      }
      fp = fopen (fname, "wbx");  /* FIXME: the x is a GNU extension - let
                                     configure check whether this actually
                                     works */
    }

  if (!fp) 
    { 
      log_error ("can't create `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return seterr (File_Create_Error);
    }

  if (fwrite (buffer, length, 1, fp) != 1)
    {
      log_error ("error writing `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      remove (fname);
      xfree (fname);
      return seterr (File_Create_Error);
    }
  if ( fclose (fp) )
    {
      log_error ("error closing `%s': %s\n", fname, strerror (errno));
      remove (fname);
      xfree (fname);
      return seterr (File_Create_Error);
    }

  xfree (fname);
  return 0;
}


static int
unprotect (unsigned char **keybuf, const unsigned char *grip)
{
  struct pin_entry_info_s *pi;
  int rc, i;
  unsigned char *result;
  size_t resultlen;
  int tries = 0;
  char hexgrip[40+1];
  const char *errtext;
  
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  hexgrip[40] = 0;

  /* first try to get it from the cache - if there is none or we can't
     unprotect it, we fall back to ask the user */
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

  errtext = NULL;
  do
    {
      rc = agent_askpin (NULL, errtext, pi);
      if (!rc)
        {
          rc = agent_unprotect (*keybuf, pi->pin, &result, &resultlen);
          if (!rc)
            {
              agent_put_cache (hexgrip, pi->pin, 0);
              xfree (*keybuf);
              *keybuf = result;
              xfree (pi);
              return 0;
            }
        }
      errtext = pi->min_digits? trans ("Bad PIN") : trans ("Bad Passphrase");
    }
  while ((rc == GNUPG_Bad_Passphrase || rc == GNUPG_Bad_PIN)
         && tries++ < 3);
  xfree (pi);
  return rc;
}



/* Return the secret key as an S-Exp after locating it using the grip.
   Returns NULL if key is not available or the operation should be
   diverted to a token.  In the latter case shadow_info will point to
   an allocated S-Expression with the shadow_info part from the
   file. */
GCRY_SEXP
agent_key_from_file (const unsigned char *grip, unsigned char **shadow_info)
{
  int i, rc;
  char *fname;
  FILE *fp;
  struct stat st;
  unsigned char *buf;
  size_t len, buflen, erroff;
  GCRY_SEXP s_skey;
  char hexgrip[40+4+1];
  
  if (shadow_info)
      *shadow_info = NULL;

  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  strcpy (hexgrip+40, ".key");

  fname = make_filename (opt.homedir, "private-keys-v1.d", hexgrip, NULL);
  fp = fopen (fname, "rb");
  if (!fp)
    {
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return NULL;
    }
  
  if (fstat (fileno(fp), &st))
    {
      log_error ("can't stat `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      log_error ("error reading `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      fclose (fp);
      xfree (buf);
      return NULL;
    }

  rc = gcry_sexp_sscan (&s_skey, &erroff, buf, buflen);
  xfree (fname);
  fclose (fp);
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gcry_strerror (rc));
      return NULL;
    }
  len = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      gcry_sexp_release (s_skey);
      return NULL;
    }
  len = gcry_sexp_sprint (s_skey, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);
  gcry_sexp_release (s_skey);

  switch (agent_private_key_type (buf))
    {
    case PRIVATE_KEY_CLEAR:
      break; /* no unprotection needed */
    case PRIVATE_KEY_PROTECTED:
      rc = unprotect (&buf, grip);
      if (rc)
        log_error ("failed to unprotect the secret key: %s\n",
                   gnupg_strerror (rc));
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
                rc = GNUPG_Out_Of_Core;
              else
                {
                  memcpy (*shadow_info, s, n);
                  rc = 0;
                }
            }
          if (rc)
            log_error ("get_shadow_info failed: %s\n", gnupg_strerror (rc));
        }
      rc = -1; /* ugly interface: we return an error but keep a value
                  in shadow_info.  */
      break;
    default:
      log_error ("invalid private key format\n");
      rc = GNUPG_Bad_Secret_Key;
      break;
    }
  if (rc)
    {
      xfree (buf);
      return NULL;
    }

  /* arggg FIXME: does scan support secure memory? */
  rc = gcry_sexp_sscan (&s_skey, &erroff,
                        buf, gcry_sexp_canon_len (buf, 0, NULL, NULL));
  xfree (buf);
  if (rc)
    {
      log_error ("failed to build S-Exp (off=%u): %s\n",
                 (unsigned int)erroff, gcry_strerror (rc));
      return NULL;
    }

  return s_skey;
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

  fname = make_filename (opt.homedir, "private-keys-v1.d", hexgrip, NULL);
  i = !access (fname, R_OK)? 0 : -1;
  xfree (fname);
  return i;
}



