/* pksign.c - Generate a keypair
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"

static int
store_key (GCRY_SEXP private)
{
  int i;
  char *fname;
  FILE *fp;
  char *buf;
  size_t len;
  unsigned char grip[20];
  char hexgrip[41];
  
  if ( !gcry_pk_get_keygrip (private, grip) )
    {
      log_error ("can't calculate keygrip\n");
      return seterr (General_Error);
    }
  for (i=0; i < 20; i++)
    sprintf (hexgrip+2*i, "%02X", grip[i]);
  hexgrip[40] = 0;

  fname = make_filename (opt.homedir, "private-keys-v1.d", hexgrip, NULL);
  if (!access (fname, F_OK))
    {
      log_error ("secret key file `%s' already exists - very strange\n",
                 fname);
      xfree (fname);
      return seterr (General_Error);
    }
  fp = fopen (fname, "wbx");
  if (!fp)
    {
      log_error ("can't create `%s': %s\n", fname, strerror (errno));
      xfree (fname);
      return seterr (File_Create_Error);
    }

  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = gcry_malloc_secure (len);
  if (!buf)
    {
      fclose (fp);
      remove (fname);
      xfree (fname);
      return seterr (Out_Of_Core);
    }
  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  if (fwrite (buf, len, 1, fp) != 1)
    {
      log_error ("error writing `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      remove (fname);
      xfree (fname);
      xfree (buf);
      return seterr (File_Create_Error);
    }
  if ( fclose (fp) )
    {
      log_error ("error closing `%s': %s\n", fname, strerror (errno));
      remove (fname);
      xfree (fname);
      xfree (buf);
      return seterr (File_Create_Error);
    }

  xfree (fname);
  xfree (buf);
  return 0;
}



/* Generate a new keypair according to the parameters given in
   KEYPARAM */
int
agent_genkey (CTRL ctrl, const char *keyparam, size_t keyparamlen,
              FILE *outfp) 
{
  GCRY_SEXP s_keyparam, s_key, s_private, s_public;
  int rc;
  size_t len;
  char *buf;

  rc = gcry_sexp_sscan (&s_keyparam, NULL, keyparam, keyparamlen);
  if (rc)
    {
      log_error ("failed to convert keyparam: %s\n", gcry_strerror (rc));
      return seterr (Invalid_Data);
    }

  /* fixme: Get the passphrase now, cause key generation may take a while */

  rc = gcry_pk_genkey (&s_key, s_keyparam );
  gcry_sexp_release (s_keyparam);
  if (rc)
    {
      log_error ("key generation failed: %s\n", gcry_strerror (rc));
      return map_gcry_err (rc);
    }

  /* break out the parts */
  s_private = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!s_private)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_key);
      return seterr (Invalid_Data);
    }
  s_public = gcry_sexp_find_token (s_key, "public-key", 0);
  if (!s_public)
    {
      log_error ("key generation failed: invalid return value\n");
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_key);
      return seterr (Invalid_Data);
    }
  gcry_sexp_release (s_key); s_key = NULL;
  
  /* store the secret key */
  log_debug ("storing private key\n");
  rc = store_key (s_private);
  gcry_sexp_release (s_private);
  if (rc)
    {
      gcry_sexp_release (s_public);
      return rc;
    }

  /* return the public key */
  log_debug ("returning public key\n");
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xmalloc (len);
  if (!buf)
    {
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      return seterr (Out_Of_Core);
    }
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);
  if (fwrite (buf, len, 1, outfp) != 1)
    {
      log_error ("error writing public key: %s\n", strerror (errno));
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      xfree (buf);
      return seterr (File_Create_Error);
    }
  gcry_sexp_release (s_public);
  xfree (buf);

  return 0;
}

