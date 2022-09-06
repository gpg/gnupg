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
#include "openpgpdefs.h"


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


/* Write the uint32 contained in UINT32 to STREAM.  */
static gpg_error_t
stream_write_uint32 (estream_t stream, u32 uint32)
{
  unsigned char buffer[4];
  gpg_error_t err;
  int ret;

  buffer[0] = uint32 >> 24;
  buffer[1] = uint32 >> 16;
  buffer[2] = uint32 >>  8;
  buffer[3] = uint32 >>  0;

  ret = es_write (stream, buffer, sizeof (buffer), NULL);
  if (ret)
    err = gpg_error_from_syserror ();
  else
    err = 0;

  return err;
}

/* Write SIZE bytes from BUFFER to STREAM.  */
static gpg_error_t
stream_write_data (estream_t stream, const unsigned char *buffer, size_t size)
{
  gpg_error_t err;
  int ret;

  ret = es_write (stream, buffer, size, NULL);
  if (ret)
    err = gpg_error_from_syserror ();
  else
    err = 0;

  return err;
}

/* Write a binary string from STRING of size STRING_N to STREAM.  */
static gpg_error_t
stream_write_string (estream_t stream,
                     const unsigned char *string, u32 string_n)
{
  gpg_error_t err;

  err = stream_write_uint32 (stream, string_n);
  if (err)
    goto out;

  err = stream_write_data (stream, string, string_n);

 out:

  return err;
}

/* Write a C-string from STRING to STREAM.  */
static gpg_error_t
stream_write_cstring (estream_t stream, const char *string)
{
  gpg_error_t err;

  err = stream_write_string (stream,
                             (const unsigned char *) string, strlen (string));

  return err;
}

/* Write the MPI contained in MPINT to STREAM.  */
static gpg_error_t
stream_write_mpi (estream_t stream, gcry_mpi_t mpint)
{
  unsigned char *mpi_buffer;
  size_t mpi_buffer_n;
  gpg_error_t err;

  mpi_buffer = NULL;

  err = gcry_mpi_aprint (GCRYMPI_FMT_STD, &mpi_buffer, &mpi_buffer_n, mpint);
  if (err)
    goto out;

  err = stream_write_string (stream, mpi_buffer, mpi_buffer_n);

 out:

  xfree (mpi_buffer);

  return err;
}


/* Encode a key in SEXP, in SSH format.  */
static gpg_error_t
sexp_to_sshblob (gcry_sexp_t sexp, const char *identifier, int is_eddsa_flag,
                 const char *curve, const char *elems,
                 void **r_blob, size_t *r_blob_size)
{
  gpg_error_t err = 0;
  gcry_sexp_t value_list = NULL;
  gcry_sexp_t value_pair = NULL;
  estream_t stream = NULL;
  const char *p_elems;
  const char *data;
  size_t datalen;

  *r_blob = NULL;
  *r_blob_size = 0;

  stream = es_fopenmem (0, "r+b");
  if (!stream)
    {
      err = gpg_error_from_syserror ();
      goto out;
    }

  /* Get key value list.  */
  value_list = gcry_sexp_cadr (sexp);
  if (!value_list)
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto out;
    }

  err = stream_write_cstring (stream, identifier);
  if (err)
    goto out;

  if (curve && !is_eddsa_flag)
    {
      /* ECDSA requires the curve name.  */
      err = stream_write_cstring (stream, curve);
      if (err)
        goto out;
    }

  /* Write the parameters.  */
  for (p_elems = elems; *p_elems; p_elems++)
    {
      gcry_sexp_release (value_pair);
      value_pair = gcry_sexp_find_token (value_list, p_elems, 1);
      if (!value_pair)
        {
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto out;
        }
      if (is_eddsa_flag)
        {
          data = gcry_sexp_nth_data (value_pair, 1, &datalen);
          if (!data)
            {
              err = gpg_error (GPG_ERR_INV_SEXP);
              goto out;
            }
          if ((datalen & 1) && *data == 0x40)
            { /* Remove the prefix 0x40.  */
              data++;
              datalen--;
            }
          err = stream_write_string (stream, data, datalen);
          if (err)
            goto out;
        }
      else
        {
          gcry_mpi_t mpi;

          /* Note that we need to use STD format; i.e. prepend a 0x00
             to indicate a positive number if the high bit is set.  */
          mpi = gcry_sexp_nth_mpi (value_pair, 1, GCRYMPI_FMT_STD);
          if (!mpi)
            {
              err = gpg_error (GPG_ERR_INV_SEXP);
              goto out;
            }
          err = stream_write_mpi (stream, mpi);
          gcry_mpi_release (mpi);
          if (err)
            goto out;
        }
    }

  if (es_fclose_snatch (stream, r_blob, r_blob_size))
    {
      err = gpg_error_from_syserror ();
      goto out;
    }
  stream = NULL;

 out:
  gcry_sexp_release (value_list);
  gcry_sexp_release (value_pair);
  es_fclose (stream);

  return err;
}

/* For KEY in S-expression, write it in SSH base64 format to STREAM,
   adding COMMENT.  */
gpg_error_t
ssh_public_key_in_base64 (gcry_sexp_t key, estream_t stream,
                          const char *comment)
{
  gpg_error_t err = 0;
  int algo;
  int is_eddsa_flag = 0;
  const char *curve = NULL;
  const char *pub_elements = NULL;
  const char *identifier = NULL;
  void *blob = NULL;
  size_t bloblen;
  struct b64state b64_state;

  algo = get_pk_algo_from_key (key);
  if (algo == 0)
    return gpg_error (GPG_ERR_PUBKEY_ALGO);

  if (algo == GCRY_PK_ECC || algo == GCRY_PK_EDDSA)
    {
      curve = gcry_pk_get_curve (key, 0, NULL);
      if (!curve)
        return gpg_error (GPG_ERR_INV_CURVE);
    }

  switch (algo)
    {
    case GCRY_PK_RSA:
      identifier = "ssh-rsa";
      pub_elements = "en";
      break;

    case GCRY_PK_ECC:
      if (!strcmp (curve, "NIST P-256"))
        identifier = "ecdsa-sha2-nistp256";
      else if (!strcmp (curve, "NIST P-384"))
        identifier = "ecdsa-sha2-nistp384";
      else if (!strcmp (curve, "NIST P-521"))
        identifier = "ecdsa-sha2-nistp521";
      else
        err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      pub_elements = "q";
      break;

    case GCRY_PK_EDDSA:
      is_eddsa_flag = 1;
      if (!strcmp (curve, "Ed25519"))
        identifier = "ssh-ed25519";
      else if (!strcmp (curve, "Ed448"))
        identifier = "ssh-ed448";
      else
        err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      pub_elements = "q";
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (err)
    return err;

  err = sexp_to_sshblob (key, identifier, is_eddsa_flag, curve, pub_elements,
                         &blob, &bloblen);
  if (err)
    return err;

  es_fprintf (stream, "%s ", identifier);

  err = b64enc_start_es (&b64_state, stream, "");
  if (err)
    {
      es_free (blob);
      return err;
    }

  err = b64enc_write (&b64_state, blob, bloblen);
  b64enc_finish (&b64_state);
  es_free (blob);
  if (err)
    return err;

  if (comment)
    es_fprintf (stream, " %s", comment);

  return err;
}
