/* ssh-utils.c - Secure Shell helper functions
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "util.h"
#include "ssh-utils.h"



/* Return the Secure Shell type fingerprint for KEY.  The length of
   the fingerprint is returned at R_LEN and the fingerprint itself at
   R_FPR.  In case of a error code is returned and NULL stored at
   R_FPR.  This function is usually called via the ssh_get_fingerprint
   macro which makes sure to use the correct value for ERRSOURCE. */
static gpg_error_t
get_fingerprint (gcry_sexp_t key, void **r_fpr, size_t *r_len,
                 gpg_err_source_t errsource, int as_string)
{
  gpg_error_t err;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2 = NULL;
  const char *s;
  char *name = NULL;
  int idx;
  const char *elems;
  gcry_md_hd_t md = NULL;

  *r_fpr = NULL;
  *r_len = 0;

  /* Check that the first element is valid. */
  list = gcry_sexp_find_token (key, "public-key", 0);
  if (!list)
    list = gcry_sexp_find_token (key, "private-key", 0);
  if (!list)
    list = gcry_sexp_find_token (key, "protected-private-key", 0);
  if (!list)
    list = gcry_sexp_find_token (key, "shadowed-private-key", 0);
  if (!list)
    {
      err = gpg_err_make (errsource, GPG_ERR_UNKNOWN_SEXP);
      goto leave;
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  l2 = NULL;

  name = gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      err = gpg_err_make (errsource, GPG_ERR_INV_SEXP);
      goto leave;
    }

  err = gcry_md_open (&md, GCRY_MD_MD5, 0);
  if (err)
    goto leave;

  switch (gcry_pk_map_name (name))
    {
    case GCRY_PK_RSA:
      elems = "en";
      gcry_md_write (md, "\0\0\0\x07ssh-rsa", 11);
      break;
    case GCRY_PK_DSA:
      elems = "pqgy";
      gcry_md_write (md, "\0\0\0\x07ssh-dss", 11);
      break;
    default:
      elems = "";
      err = gpg_err_make (errsource, GPG_ERR_PUBKEY_ALGO);
      break;
    }
  if (err)
    goto leave;

  for (idx = 0, s = elems; *s; s++, idx++)
    {
      gcry_mpi_t a;
      unsigned char *buf;
      size_t buflen;

      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          err = gpg_err_make (errsource, GPG_ERR_INV_SEXP);
          goto leave;
        }
      a = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      l2 = NULL;
      if (!a)
        {
          err = gpg_err_make (errsource, GPG_ERR_INV_SEXP);
          goto leave;
        }

      err = gcry_mpi_aprint (GCRYMPI_FMT_SSH, &buf, &buflen, a);
      gcry_mpi_release (a);
      if (err)
        goto leave;
      gcry_md_write (md, buf, buflen);
      gcry_free (buf);
    }

  *r_fpr = gcry_malloc (as_string? 61:20);
  if (!*r_fpr)
    {
      err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
      goto leave;
    }

  if (as_string)
    {
      bin2hexcolon (gcry_md_read (md, GCRY_MD_MD5), 16, *r_fpr);
      *r_len = 3*16+1;
      strlwr (*r_fpr);
    }
  else
    {
      memcpy (*r_fpr, gcry_md_read (md, GCRY_MD_MD5), 16);
      *r_len = 16;
    }
  err = 0;

 leave:
  gcry_free (name);
  gcry_sexp_release (l2);
  gcry_md_close (md);
  gcry_sexp_release (list);
  return err;
}

/* Return the Secure Shell type fingerprint for KEY.  The length of
   the fingerprint is returned at R_LEN and the fingerprint itself at
   R_FPR.  In case of an error an error code is returned and NULL
   stored at R_FPR.  This function is usually called via the
   ssh_get_fingerprint macro which makes sure to use the correct value
   for ERRSOURCE. */
gpg_error_t
_ssh_get_fingerprint (gcry_sexp_t key, void **r_fpr, size_t *r_len,
                      gpg_err_source_t errsource)
{
  return get_fingerprint (key, r_fpr, r_len, errsource, 0);
}


/* Return the Secure Shell type fingerprint for KEY as a string.  The
   fingerprint is mallcoed and stored at R_FPRSTR.  In case of an
   error an error code is returned and NULL stored at R_FPRSTR.  This
   function is usually called via the ssh_get_fingerprint_string macro
   which makes sure to use the correct value for ERRSOURCE. */
gpg_error_t
_ssh_get_fingerprint_string (gcry_sexp_t key, char **r_fprstr,
                             gpg_err_source_t errsource)
{
  gpg_error_t err;
  size_t dummy;
  void *string;

  err = get_fingerprint (key, &string, &dummy, errsource, 1);
  *r_fprstr = string;
  return err;
}
