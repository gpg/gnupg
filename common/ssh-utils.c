/* ssh-utils.c - Secure Shell helper functions
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "util.h"
#include "ssh-utils.h"


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

/* Dummy functions for es_mopen.  */
static void *dummy_realloc (void *mem, size_t size) { (void) size; return mem; }
static void dummy_free (void *mem) { (void) mem; }

/* Return the Secure Shell type fingerprint for KEY using digest ALGO.
   The length of the fingerprint is returned at R_LEN and the
   fingerprint itself at R_FPR.  In case of a error code is returned
   and NULL stored at R_FPR.  */
static gpg_error_t
get_fingerprint (gcry_sexp_t key, int algo,
                 void **r_fpr, size_t *r_len, int as_string)
{
  gpg_error_t err;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2 = NULL;
  const char *s;
  char *name = NULL;
  int idx;
  const char *elems;
  gcry_md_hd_t md = NULL;
  int blobmode = 0;

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
      err = gpg_err_make (default_errsource, GPG_ERR_UNKNOWN_SEXP);
      goto leave;
    }

  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  l2 = NULL;

  name = gcry_sexp_nth_string (list, 0);
  if (!name)
    {
      err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
      goto leave;
    }

  err = gcry_md_open (&md, algo, 0);
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

    case GCRY_PK_ECC:
      if (is_eddsa (list))
        {
          elems = "q";
          blobmode = 1;
          /* For now there is just one curve, thus no need to switch
             on it.  */
          gcry_md_write (md, "\0\0\0\x0b" "ssh-ed25519", 15);
        }
      else
        {
          /* We only support the 3 standard curves for now.  It is
             just a quick hack.  */
          elems = "q";
          gcry_md_write (md, "\0\0\0\x13" "ecdsa-sha2-nistp", 20);
          l2 = gcry_sexp_find_token (list, "curve", 0);
          if (!l2)
            elems = "";
          else
            {
              gcry_free (name);
              name = gcry_sexp_nth_string (l2, 1);
              gcry_sexp_release (l2);
              l2 = NULL;
              if (!name)
                elems = "";
              else if (!strcmp (name, "NIST P-256")||!strcmp (name, "nistp256"))
                gcry_md_write (md, "256\0\0\0\x08nistp256", 15);
              else if (!strcmp (name, "NIST P-384")||!strcmp (name, "nistp384"))
                gcry_md_write (md, "384\0\0\0\x08nistp384", 15);
              else if (!strcmp (name, "NIST P-521")||!strcmp (name, "nistp521"))
                gcry_md_write (md, "521\0\0\0\x08nistp521", 15);
              else
                elems = "";
            }
          if (!*elems)
            err = gpg_err_make (default_errsource, GPG_ERR_UNKNOWN_CURVE);
        }
      break;

    default:
      elems = "";
      err = gpg_err_make (default_errsource, GPG_ERR_PUBKEY_ALGO);
      break;
    }
  if (err)
    goto leave;


  for (idx = 0, s = elems; *s; s++, idx++)
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
          goto leave;
        }
      if (blobmode)
        {
          const char *blob;
          size_t bloblen;
          unsigned char lenbuf[4];

          blob = gcry_sexp_nth_data (l2, 1, &bloblen);
          if (!blob)
            {
              err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
              goto leave;
            }
          blob++;
          bloblen--;
          lenbuf[0] = bloblen >> 24;
          lenbuf[1] = bloblen >> 16;
          lenbuf[2] = bloblen >>  8;
          lenbuf[3] = bloblen;
          gcry_md_write (md, lenbuf, 4);
          gcry_md_write (md, blob, bloblen);
        }
      else
        {
          gcry_mpi_t a;
          unsigned char *buf;
          size_t buflen;

          a = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
          gcry_sexp_release (l2);
          l2 = NULL;
          if (!a)
            {
              err = gpg_err_make (default_errsource, GPG_ERR_INV_SEXP);
              goto leave;
            }

          err = gcry_mpi_aprint (GCRYMPI_FMT_SSH, &buf, &buflen, a);
          gcry_mpi_release (a);
          if (err)
            goto leave;
          gcry_md_write (md, buf, buflen);
          gcry_free (buf);
        }
    }

  if (as_string)
    {
      const char *algo_name;
      char *fpr;

      /* Prefix string with the algorithm name and a colon.  */
      algo_name = gcry_md_algo_name (algo);
      *r_fpr = xtrymalloc (strlen (algo_name) + 1 + 3 * gcry_md_get_algo_dlen (algo) + 1);
      if (*r_fpr == NULL)
        {
          err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
          goto leave;
        }

      memcpy (*r_fpr, algo_name, strlen (algo_name));
      fpr = (char *) *r_fpr + strlen (algo_name);
      *fpr++ = ':';

      if (algo == GCRY_MD_MD5)
        {
          bin2hexcolon (gcry_md_read (md, algo), gcry_md_get_algo_dlen (algo), fpr);
          strlwr (fpr);
        }
      else
        {
          struct b64state b64s;
          estream_t stream;
          char *p;
          long int len;

          /* Write the base64-encoded hash to fpr.  */
          stream = es_mopen (fpr, 3 * gcry_md_get_algo_dlen (algo) + 1, 0,
                             0, dummy_realloc, dummy_free, "w");
          if (stream == NULL)
            {
              err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
              goto leave;
            }

          err = b64enc_start_es (&b64s, stream, "");
          if (err)
            {
              es_fclose (stream);
              goto leave;
            }

          err = b64enc_write (&b64s,
                              gcry_md_read (md, algo), gcry_md_get_algo_dlen (algo));
          if (err)
            {
              es_fclose (stream);
              goto leave;
            }

          /* Finish, get the length, and close the stream.  */
          err = b64enc_finish (&b64s);
          len = es_ftell (stream);
          es_fclose (stream);
          if (err)
            goto leave;

          /* Terminate.  */
          fpr[len] = 0;

          /* Strip the trailing padding characters.  */
          for (p = fpr + len - 1; p > fpr && *p == '='; p--)
            *p = 0;
        }

      *r_len = strlen (*r_fpr) + 1;
    }
  else
    {
      *r_len = gcry_md_get_algo_dlen (algo);
      *r_fpr = xtrymalloc (*r_len);
      if (!*r_fpr)
        {
          err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
          goto leave;
        }
      memcpy (*r_fpr, gcry_md_read (md, algo), *r_len);
    }
  err = 0;

 leave:
  gcry_free (name);
  gcry_sexp_release (l2);
  gcry_md_close (md);
  gcry_sexp_release (list);
  return err;
}

/* Return the Secure Shell type fingerprint for KEY using digest ALGO.
   The length of the fingerprint is returned at R_LEN and the
   fingerprint itself at R_FPR.  In case of an error an error code is
   returned and NULL stored at R_FPR.  */
gpg_error_t
ssh_get_fingerprint (gcry_sexp_t key, int algo,
                     void **r_fpr, size_t *r_len)
{
  return get_fingerprint (key, algo, r_fpr, r_len, 0);
}


/* Return the Secure Shell type fingerprint for KEY using digest ALGO
   as a string.  The fingerprint is mallcoed and stored at R_FPRSTR.
   In case of an error an error code is returned and NULL stored at
   R_FPRSTR.  */
gpg_error_t
ssh_get_fingerprint_string (gcry_sexp_t key, int algo, char **r_fprstr)
{
  gpg_error_t err;
  size_t dummy;
  void *string;

  err = get_fingerprint (key, algo, &string, &dummy, 1);
  *r_fprstr = string;
  return err;
}
