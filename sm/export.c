/* export.c - Export certificates and private keys.
 * Copyright (C) 2002, 2003, 2004, 2007, 2009,
 *               2010 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/exechelp.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "minip12.h"

/* A table to store a fingerprint as used in a duplicates table.  We
   don't need to hash here because a fingerprint is already a perfect
   hash value.  This we use the most significant bits to index the
   table and then use a linked list for the overflow.  Possible
   enhancement for very large number of certificates:  Add a second
   level table and then resort to a linked list.  */
struct duptable_s
{
  struct duptable_s *next;

  /* Note that we only need to store 19 bytes because the first byte
     is implictly given by the table index (we require at least 8
     bits). */
  unsigned char fpr[19];
};
typedef struct duptable_s *duptable_t;
#define DUPTABLE_BITS 12
#define DUPTABLE_SIZE (1 << DUPTABLE_BITS)


static void print_short_info (ksba_cert_t cert, estream_t stream);
static gpg_error_t export_p12 (ctrl_t ctrl,
                               const unsigned char *certimg, size_t certimglen,
                               const char *prompt, const char *keygrip,
                               int rawmode,
                               void **r_result, size_t *r_resultlen);


/* Create a table used to indetify duplicated certificates. */
static duptable_t *
create_duptable (void)
{
  return xtrycalloc (DUPTABLE_SIZE, sizeof (duptable_t));
}

static void
destroy_duptable (duptable_t *table)
{
  int idx;
  duptable_t t, t2;

  if (table)
    {
      for (idx=0; idx < DUPTABLE_SIZE; idx++)
        for (t = table[idx]; t; t = t2)
          {
            t2 = t->next;
            xfree (t);
          }
      xfree (table);
    }
}

/* Insert the 20 byte fingerprint FPR into TABLE.  Sets EXITS to true
   if the fingerprint already exists in the table. */
static gpg_error_t
insert_duptable (duptable_t *table, unsigned char *fpr, int *exists)
{
  size_t idx;
  duptable_t t;

  *exists = 0;
  idx = fpr[0];
#if DUPTABLE_BITS > 16 || DUPTABLE_BITS < 8
#error cannot handle a table larger than 16 bits or smaller than 8 bits
#elif DUPTABLE_BITS > 8
  idx <<= (DUPTABLE_BITS - 8);
  idx |= (fpr[1] & ~(~0U << 4));
#endif

  for (t = table[idx]; t; t = t->next)
    if (!memcmp (t->fpr, fpr+1, 19))
      break;
  if (t)
    {
      *exists = 1;
      return 0;
    }
  /* Insert that fingerprint. */
  t = xtrymalloc (sizeof *t);
  if (!t)
    return gpg_error_from_syserror ();
  memcpy (t->fpr, fpr+1, 19);
  t->next = table[idx];
  table[idx] = t;
  return 0;
}


/* Export all certificates or just those given in NAMES.  The output
   is written to STREAM.  */
void
gpgsm_export (ctrl_t ctrl, strlist_t names, estream_t stream)
{
  KEYDB_HANDLE hd = NULL;
  KEYDB_SEARCH_DESC *desc = NULL;
  int ndesc;
  gnupg_ksba_io_t b64writer = NULL;
  ksba_writer_t writer;
  strlist_t sl;
  ksba_cert_t cert = NULL;
  int rc=0;
  int count = 0;
  int i;
  duptable_t *dtable;


  dtable = create_duptable ();
  if (!dtable)
    {
      log_error ("creating duplicates table failed: %s\n", strerror (errno));
      goto leave;
    }

  hd = keydb_new ();
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  if (!names)
    ndesc = 1;
  else
    {
      for (sl=names, ndesc=0; sl; sl = sl->next, ndesc++)
        ;
    }

  desc = xtrycalloc (ndesc, sizeof *desc);
  if (!ndesc)
    {
      log_error ("allocating memory for export failed: %s\n",
                 gpg_strerror (out_of_core ()));
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else
    {
      for (ndesc=0, sl=names; sl; sl = sl->next)
        {
          rc = classify_user_id (sl->d, desc+ndesc, 0);
          if (rc)
            {
              log_error ("key '%s' not found: %s\n",
                         sl->d, gpg_strerror (rc));
              rc = 0;
            }
          else
            ndesc++;
        }
    }

  /* If all specifications are done by fingerprint or keygrip, we
     switch to ephemeral mode so that _all_ currently available and
     matching certificates are exported.  */
  if (names && ndesc)
    {
      for (i=0; (i < ndesc
                 && (desc[i].mode == KEYDB_SEARCH_MODE_FPR
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR20
                     || desc[i].mode == KEYDB_SEARCH_MODE_FPR16
                     || desc[i].mode == KEYDB_SEARCH_MODE_KEYGRIP)); i++)
        ;
      if (i == ndesc)
        keydb_set_ephemeral (hd, 1);
    }

  while (!(rc = keydb_search (ctrl, hd, desc, ndesc)))
    {
      unsigned char fpr[20];
      int exists;

      if (!names)
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      rc = keydb_get_cert (hd, &cert);
      if (rc)
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      gpgsm_get_fingerprint (cert, 0, fpr, NULL);
      rc = insert_duptable (dtable, fpr, &exists);
      if (rc)
        {
          log_error ("inserting into duplicates table failed: %s\n",
                     gpg_strerror (rc));
          goto leave;
        }

      if (!exists && count && !ctrl->create_pem)
        {
          log_info ("exporting more than one certificate "
                    "is not possible in binary mode\n");
          log_info ("ignoring other certificates\n");
          break;
        }

      if (!exists)
        {
          const unsigned char *image;
          size_t imagelen;

          image = ksba_cert_get_image (cert, &imagelen);
          if (!image)
            {
              log_error ("ksba_cert_get_image failed\n");
              goto leave;
            }


          if (ctrl->create_pem)
            {
              if (count)
                es_putc ('\n', stream);
              print_short_info (cert, stream);
              es_putc ('\n', stream);
            }
          count++;

          if (!b64writer)
            {
              ctrl->pem_name = "CERTIFICATE";
              rc = gnupg_ksba_create_writer
                (&b64writer, ((ctrl->create_pem? GNUPG_KSBA_IO_PEM : 0)
                              | (ctrl->create_base64? GNUPG_KSBA_IO_BASE64 :0)),
                 ctrl->pem_name, stream, &writer);
              if (rc)
                {
                  log_error ("can't create writer: %s\n", gpg_strerror (rc));
                  goto leave;
                }
            }

          rc = ksba_writer_write (writer, image, imagelen);
          if (rc)
            {
              log_error ("write error: %s\n", gpg_strerror (rc));
              goto leave;
            }

          if (ctrl->create_pem)
            {
              /* We want one certificate per PEM block */
              rc = gnupg_ksba_finish_writer (b64writer);
              if (rc)
                {
                  log_error ("write failed: %s\n", gpg_strerror (rc));
                  goto leave;
                }
              gnupg_ksba_destroy_writer (b64writer);
              b64writer = NULL;
            }
        }

      ksba_cert_release (cert);
      cert = NULL;
    }
  if (rc && rc != -1)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));
  else if (b64writer)
    {
      rc = gnupg_ksba_finish_writer (b64writer);
      if (rc)
        {
          log_error ("write failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
    }

 leave:
  gnupg_ksba_destroy_writer (b64writer);
  ksba_cert_release (cert);
  xfree (desc);
  keydb_release (hd);
  destroy_duptable (dtable);
}


/* Export a certificate and its private key.  RAWMODE controls the
   actual output:
       0 - Private key and certifciate in PKCS#12 format
       1 - Only unencrypted private key in PKCS#8 format
       2 - Only unencrypted private key in PKCS#1 format
    */
void
gpgsm_p12_export (ctrl_t ctrl, const char *name, estream_t stream, int rawmode)
{
  gpg_error_t err = 0;
  KEYDB_HANDLE hd;
  KEYDB_SEARCH_DESC *desc = NULL;
  gnupg_ksba_io_t b64writer = NULL;
  ksba_writer_t writer;
  ksba_cert_t cert = NULL;
  const unsigned char *image;
  size_t imagelen;
  char *keygrip = NULL;
  char *prompt;
  void *data;
  size_t datalen;

  hd = keydb_new ();
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  desc = xtrycalloc (1, sizeof *desc);
  if (!desc)
    {
      log_error ("allocating memory for export failed: %s\n",
                 gpg_strerror (out_of_core ()));
      goto leave;
    }

  err = classify_user_id (name, desc, 0);
  if (err)
    {
      log_error ("key '%s' not found: %s\n",
                 name, gpg_strerror (err));
      goto leave;
    }

  /* Lookup the certificate and make sure that it is unique. */
  err = keydb_search (ctrl, hd, desc, 1);
  if (!err)
    {
      err = keydb_get_cert (hd, &cert);
      if (err)
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (err));
          goto leave;
        }

    next_ambiguous:
      err = keydb_search (ctrl, hd, desc, 1);
      if (!err)
        {
          ksba_cert_t cert2 = NULL;

          if (!keydb_get_cert (hd, &cert2))
            {
              if (gpgsm_certs_identical_p (cert, cert2))
                {
                  ksba_cert_release (cert2);
                  goto next_ambiguous;
                }
              ksba_cert_release (cert2);
            }
          err = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
        }
      else if (err == -1 || gpg_err_code (err) == GPG_ERR_EOF)
        err = 0;
      if (err)
        {
          log_error ("key '%s' not found: %s\n",
                     name, gpg_strerror (err));
          goto leave;
        }
    }

  keygrip = gpgsm_get_keygrip_hexstring (cert);
  if (!keygrip || gpgsm_agent_havekey (ctrl, keygrip))
    {
      /* Note, that the !keygrip case indicates a bad certificate. */
      err = gpg_error (GPG_ERR_NO_SECKEY);
      log_error ("can't export key '%s': %s\n", name, gpg_strerror (err));
      goto leave;
    }

  image = ksba_cert_get_image (cert, &imagelen);
  if (!image)
    {
      log_error ("ksba_cert_get_image failed\n");
      goto leave;
    }

  if (ctrl->create_pem)
    {
      print_short_info (cert, stream);
      es_putc ('\n', stream);
    }

  if (opt.p12_charset && ctrl->create_pem && !rawmode)
    {
      es_fprintf (stream, "The passphrase is %s encoded.\n\n",
                  opt.p12_charset);
    }

  if (rawmode == 0)
    ctrl->pem_name = "PKCS12";
  else if (rawmode == 1)
    ctrl->pem_name = "PRIVATE KEY";
  else
    ctrl->pem_name = "RSA PRIVATE KEY";
  err = gnupg_ksba_create_writer
    (&b64writer, ((ctrl->create_pem? GNUPG_KSBA_IO_PEM : 0)
                  | (ctrl->create_base64? GNUPG_KSBA_IO_BASE64 : 0)),
     ctrl->pem_name, stream, &writer);
  if (err)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (err));
      goto leave;
    }

  prompt = gpgsm_format_keydesc (cert);
  err = export_p12 (ctrl, image, imagelen, prompt, keygrip, rawmode,
                    &data, &datalen);
  xfree (prompt);
  if (err)
    goto leave;
  err = ksba_writer_write (writer, data, datalen);
  xfree (data);
  if (err)
    {
      log_error ("write failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (ctrl->create_pem)
    {
      /* We want one certificate per PEM block */
      err = gnupg_ksba_finish_writer (b64writer);
      if (err)
        {
          log_error ("write failed: %s\n", gpg_strerror (err));
          goto leave;
        }
      gnupg_ksba_destroy_writer (b64writer);
      b64writer = NULL;
    }

  ksba_cert_release (cert);
  cert = NULL;

 leave:
  gnupg_ksba_destroy_writer (b64writer);
  ksba_cert_release (cert);
  xfree (keygrip);
  xfree (desc);
  keydb_release (hd);
}


/* Print some info about the certifciate CERT to FP or STREAM */
static void
print_short_info (ksba_cert_t cert, estream_t stream)
{
  char *p;
  ksba_sexp_t sexp;
  int idx;

  for (idx=0; (p = ksba_cert_get_issuer (cert, idx)); idx++)
    {
      es_fputs ((!idx
                 ?   "Issuer ...: "
                 : "\n   aka ...: "), stream);
      gpgsm_es_print_name (stream, p);
      xfree (p);
    }
  es_putc ('\n', stream);

  es_fputs ("Serial ...: ", stream);
  sexp = ksba_cert_get_serial (cert);
  if (sexp)
    {
      int len;
      const unsigned char *s = sexp;

      if (*s == '(')
        {
          s++;
          for (len=0; *s && *s != ':' && digitp (s); s++)
            len = len*10 + atoi_1 (s);
          if (*s == ':')
            es_write_hexstring (stream, s+1, len, 0, NULL);
        }
      xfree (sexp);
    }
  es_putc ('\n', stream);

  for (idx=0; (p = ksba_cert_get_subject (cert, idx)); idx++)
    {
      es_fputs ((!idx
                 ?   "Subject ..: "
                 : "\n    aka ..: "), stream);
      gpgsm_es_print_name (stream, p);
      xfree (p);
    }
  es_putc ('\n', stream);

  p = gpgsm_get_keygrip_hexstring (cert);
  if (p)
    {
      es_fprintf (stream, "Keygrip ..: %s\n", p);
      xfree (p);
    }
}



/* Parse a private key S-expression and return a malloced array with
   the RSA parameters in pkcs#12 order.  The caller needs to
   deep-release this array.  */
static gcry_mpi_t *
sexp_to_kparms (gcry_sexp_t sexp)
{
  gcry_sexp_t list, l2;
  const char *name;
  const char *s;
  size_t n;
  int idx;
  const char *elems;
  gcry_mpi_t *array;

  list = gcry_sexp_find_token (sexp, "private-key", 0 );
  if(!list)
    return NULL;
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  name = gcry_sexp_nth_data (list, 0, &n);
  if(!name || n != 3 || memcmp (name, "rsa", 3))
    {
      gcry_sexp_release (list);
      return NULL;
    }

  /* Parameter names used with RSA in the pkcs#12 order. */
  elems = "nedqp--u";
  array = xtrycalloc (strlen(elems) + 1, sizeof *array);
  if (!array)
    {
      gcry_sexp_release (list);
      return NULL;
    }
  for (idx=0, s=elems; *s; s++, idx++ )
    {
      if (*s == '-')
        continue; /* Computed below  */
      l2 = gcry_sexp_find_token (list, s, 1);
      if (l2)
        {
          array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
          gcry_sexp_release (l2);
        }
      if (!array[idx]) /* Required parameter not found or invalid.  */
        {
          for (idx=0; array[idx]; idx++)
            gcry_mpi_release (array[idx]);
          xfree (array);
          gcry_sexp_release (list);
          return NULL;
        }
    }
  gcry_sexp_release (list);

  array[5] = gcry_mpi_snew (0);  /* compute d mod (q-1) */
  gcry_mpi_sub_ui (array[5], array[3], 1);
  gcry_mpi_mod (array[5], array[2], array[5]);

  array[6] = gcry_mpi_snew (0);  /* compute d mod (p-1) */
  gcry_mpi_sub_ui (array[6], array[4], 1);
  gcry_mpi_mod (array[6], array[2], array[6]);

  return array;
}


static gpg_error_t
export_p12 (ctrl_t ctrl, const unsigned char *certimg, size_t certimglen,
            const char *prompt, const char *keygrip, int rawmode,
            void **r_result, size_t *r_resultlen)
{
  gpg_error_t err = 0;
  void *kek = NULL;
  size_t keklen;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  gcry_cipher_hd_t cipherhd = NULL;
  gcry_sexp_t s_skey = NULL;
  gcry_mpi_t *kparms = NULL;
  unsigned char *key = NULL;
  size_t keylen;
  char *passphrase = NULL;
  unsigned char *result = NULL;
  size_t resultlen;
  int i;

  *r_result = NULL;

  /* Get the current KEK.  */
  err = gpgsm_agent_keywrap_key (ctrl, 1, &kek, &keklen);
  if (err)
    {
      log_error ("error getting the KEK: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Receive the wrapped key from the agent.  */
  err = gpgsm_agent_export_key (ctrl, keygrip, prompt,
                                &wrappedkey, &wrappedkeylen);
  if (err)
    goto leave;


  /* Unwrap the key.  */
  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    goto leave;
  err = gcry_cipher_setkey (cipherhd, kek, keklen);
  if (err)
    goto leave;
  xfree (kek);
  kek = NULL;

  if (wrappedkeylen < 24)
    {
      err = gpg_error (GPG_ERR_INV_LENGTH);
      goto leave;
    }
  keylen = wrappedkeylen - 8;
  key = xtrymalloc_secure (keylen);
  if (!key)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gcry_cipher_decrypt (cipherhd, key, keylen, wrappedkey, wrappedkeylen);
  if (err)
    goto leave;
  xfree (wrappedkey);
  wrappedkey = NULL;
  gcry_cipher_close (cipherhd);
  cipherhd = NULL;


  /* Convert to a gcrypt S-expression.  */
  err = gcry_sexp_create (&s_skey, key, keylen, 0, xfree_fnc);
  if (err)
    goto leave;
  key = NULL; /* Key is now owned by S_KEY.  */

  /* Get the parameters from the S-expression.  */
  kparms = sexp_to_kparms (s_skey);
  gcry_sexp_release (s_skey);
  s_skey = NULL;
  if (!kparms)
    {
      log_error ("error converting key parameters\n");
      err = GPG_ERR_BAD_SECKEY;
      goto leave;
    }

  if (rawmode)
    {
      /* Export in raw mode, that is only the pkcs#1/#8 private key. */
      result = p12_raw_build (kparms, rawmode, &resultlen);
      if (!result)
        err = gpg_error (GPG_ERR_GENERAL);
    }
  else
    {
      err = gpgsm_agent_ask_passphrase
        (ctrl,
         i18n_utf8 (N_("Please enter the passphrase to protect the "
                       "new PKCS#12 object.")),
         1, &passphrase);
      if (err)
        goto leave;

      result = p12_build (kparms, certimg, certimglen, passphrase,
                          opt.p12_charset, &resultlen);
      xfree (passphrase);
      passphrase = NULL;
      if (!result)
        err = gpg_error (GPG_ERR_GENERAL);
    }

 leave:
  xfree (key);
  gcry_sexp_release (s_skey);
  if (kparms)
    {
      for (i=0; kparms[i]; i++)
        gcry_mpi_release (kparms[i]);
      xfree (kparms);
    }
  gcry_cipher_close (cipherhd);
  xfree (wrappedkey);
  xfree (kek);

  if (gpg_err_code (err) == GPG_ERR_BAD_PASSPHRASE)
    {
      /* During export this is the passphrase used to unprotect the
         key and not the pkcs#12 thing as in export.  Therefore we can
         issue the regular passphrase status.  FIXME: replace the all
         zero keyid by a regular one. */
      gpgsm_status (ctrl, STATUS_BAD_PASSPHRASE, "0000000000000000");
    }

  if (err)
    {
      xfree (result);
    }
  else
    {
      *r_result = result;
      *r_resultlen = resultlen;
    }
  return err;
}
