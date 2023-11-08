/* sign.c - Sign a message
 * Copyright (C) 2001, 2002, 2003, 2008,
 *               2010 Free Software Foundation, Inc.
 * Copyright (C) 2003-2012, 2016-2017, 2019,
 *               2020, 2022-2023 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/i18n.h"
#include "../common/tlv.h"


/* Hash the data and return if something was hashed.  Return -1 on error.  */
static int
hash_data (int fd, gcry_md_hd_t md)
{
  estream_t fp;
  char buffer[4096];
  int nread;
  int rc = 0;

  fp = es_fdopen_nc (fd, "rb");
  if (!fp)
    {
      log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
      return -1;
    }

  do
    {
      nread = es_fread (buffer, 1, DIM(buffer), fp);
      gcry_md_write (md, buffer, nread);
    }
  while (nread);
  if (es_ferror (fp))
    {
      log_error ("read error on fd %d: %s\n", fd, strerror (errno));
      rc = -1;
    }
  es_fclose (fp);
  return rc;
}


static int
hash_and_copy_data (int fd, gcry_md_hd_t md, ksba_writer_t writer)
{
  gpg_error_t err;
  estream_t fp;
  char buffer[4096];
  int nread;
  int rc = 0;
  int any = 0;

  fp = es_fdopen_nc (fd, "rb");
  if (!fp)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
      return tmperr;
    }

  do
    {
      nread = es_fread (buffer, 1, DIM(buffer), fp);
      if (nread)
        {
          any = 1;
          gcry_md_write (md, buffer, nread);
          err = ksba_writer_write_octet_string (writer, buffer, nread, 0);
          if (err)
            {
              log_error ("write failed: %s\n", gpg_strerror (err));
              rc = err;
            }
        }
    }
  while (nread && !rc);
  if (es_ferror (fp))
    {
      rc = gpg_error_from_syserror ();
      log_error ("read error on fd %d: %s\n", fd, strerror (errno));
    }
  es_fclose (fp);
  if (!any)
    {
      /* We can't allow signing an empty message because it does not
         make much sense and more seriously, ksba_cms_build has
         already written the tag for data and now expects an octet
         string and an octet string of size 0 is illegal.  */
      log_error ("cannot sign an empty message\n");
      rc = gpg_error (GPG_ERR_NO_DATA);
    }
  if (!rc)
    {
      err = ksba_writer_write_octet_string (writer, NULL, 0, 1);
      if (err)
        {
          log_error ("write failed: %s\n", gpg_strerror (err));
          rc = err;
        }
    }

  return rc;
}


/* Get the default certificate which is defined as the first
   certificate capable of signing returned by the keyDB and has a
   secret key available. */
int
gpgsm_get_default_cert (ctrl_t ctrl, ksba_cert_t *r_cert)
{
  KEYDB_HANDLE hd;
  ksba_cert_t cert = NULL;
  int rc;
  char *p;

  hd = keydb_new (ctrl);
  if (!hd)
    return gpg_error (GPG_ERR_GENERAL);
  rc = keydb_search_first (ctrl, hd);
  if (rc)
    {
      keydb_release (hd);
      return rc;
    }

  do
    {
      rc = keydb_get_cert (hd, &cert);
      if (rc)
        {
          log_error ("keydb_get_cert failed: %s\n", gpg_strerror (rc));
          keydb_release (hd);
          return rc;
        }

      if (!gpgsm_cert_use_sign_p (cert, 1))
        {
          p = gpgsm_get_keygrip_hexstring (cert);
          if (p)
            {
              if (!gpgsm_agent_havekey (ctrl, p))
                {
                  xfree (p);
                  keydb_release (hd);
                  *r_cert = cert;
                  return 0; /* got it */
                }
              xfree (p);
            }
        }

      ksba_cert_release (cert);
      cert = NULL;
    }
  while (!(rc = keydb_search_next (ctrl, hd)));
  if (rc && rc != -1)
    log_error ("keydb_search_next failed: %s\n", gpg_strerror (rc));

  ksba_cert_release (cert);
  keydb_release (hd);
  return rc;
}


static ksba_cert_t
get_default_signer (ctrl_t ctrl)
{
  KEYDB_SEARCH_DESC desc;
  ksba_cert_t cert = NULL;
  KEYDB_HANDLE kh = NULL;
  int rc;

  if (!opt.local_user)
    {
      rc = gpgsm_get_default_cert (ctrl, &cert);
      if (rc)
        {
          if (rc != -1)
            log_debug ("failed to find default certificate: %s\n",
                       gpg_strerror (rc));
          return NULL;
        }
      return cert;
    }

  rc = classify_user_id (opt.local_user, &desc, 0);
  if (rc)
    {
      log_error ("failed to find default signer: %s\n", gpg_strerror (rc));
      return NULL;
    }

  kh = keydb_new (ctrl);
  if (!kh)
    return NULL;

  rc = keydb_search (ctrl, kh, &desc, 1);
  if (rc)
    {
      log_debug ("failed to find default certificate: rc=%d\n", rc);
    }
  else
    {
      rc = keydb_get_cert (kh, &cert);
      if (rc)
        {
          log_debug ("failed to get cert: rc=%d\n", rc);
        }
    }

  keydb_release (kh);
  return cert;
}

/* Depending on the options in CTRL add the certificate CERT as well as
   other certificate up in the chain to the Root-CA to the CMS
   object. */
static int
add_certificate_list (ctrl_t ctrl, ksba_cms_t cms, ksba_cert_t cert)
{
  gpg_error_t err;
  int rc = 0;
  ksba_cert_t next = NULL;
  int n;
  int not_root = 0;

  ksba_cert_ref (cert);

  n = ctrl->include_certs;
  if (n == -2)
    {
      not_root = 1;
      n = -1;
    }
  if (n < 0 || n > 50)
    n = 50; /* We better apply an upper bound */

  /* First add my own certificate unless we don't want any certificate
     included at all. */
  if (n)
    {
      if (not_root && gpgsm_is_root_cert (cert))
        err = 0;
      else
        err = ksba_cms_add_cert (cms, cert);
      if (err)
        goto ksba_failure;
      if (n>0)
        n--;
    }
  /* Walk the chain to include all other certificates.  Note that a -1
     used for N makes sure that there is no limit and all certs get
     included. */
  while ( n-- && !(rc = gpgsm_walk_cert_chain (ctrl, cert, &next)) )
    {
      if (not_root && gpgsm_is_root_cert (next))
        err = 0;
      else
        err = ksba_cms_add_cert (cms, next);
      ksba_cert_release (cert);
      cert = next; next = NULL;
      if (err)
        goto ksba_failure;
    }
  ksba_cert_release (cert);

  return gpg_err_code (rc) == GPG_ERR_NOT_FOUND? 0 : rc;

 ksba_failure:
  ksba_cert_release (cert);
  log_error ("ksba_cms_add_cert failed: %s\n", gpg_strerror (err));
  return err;
}


static gpg_error_t
add_signed_attribute (ksba_cms_t cms, const char *attrstr)
{
  gpg_error_t err;
  char **fields = NULL;
  const char *s;
  int i;
  unsigned char *der = NULL;
  size_t derlen;

  fields = strtokenize (attrstr, ":");
  if (!fields)
    {
      err = gpg_error_from_syserror ();
      log_error ("strtokenize failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  for (i=0; fields[i]; i++)
    ;
  if (i != 3)
    {
      err = gpg_error (GPG_ERR_SYNTAX);
      log_error ("invalid attribute specification '%s': %s\n",
                 attrstr, i < 3 ? "not enough fields":"too many fields");
      goto leave;
    }
  if (!ascii_strcasecmp (fields[1], "u"))
    {
      err = 0;
      goto leave; /* Skip unsigned attributes.  */
    }
  if (ascii_strcasecmp (fields[1], "s"))
    {
      err = gpg_error (GPG_ERR_SYNTAX);
      log_error ("invalid attribute specification '%s': %s\n",
                 attrstr, "type is not 's' or 'u'");
      goto leave;
    }
  /* Check that the OID is valid.  */
  err = ksba_oid_from_str (fields[0], &der, &derlen);
  if (err)
    {
      log_error ("invalid attribute specification '%s': %s\n",
                 attrstr, gpg_strerror (err));
      goto leave;
    }
  xfree (der);
  der = NULL;

  if (strchr (fields[2], '/'))
    {
      /* FIXME: read from file. */
    }
  else /* Directly given in hex.  */
    {
      for (i=0, s = fields[2]; hexdigitp (s); s++, i++)
        ;
      if (*s || !i || (i&1))
        {
          log_error ("invalid attribute specification '%s': %s\n",
                     attrstr, "invalid hex encoding of the data");
          err = gpg_error (GPG_ERR_SYNTAX);
          goto leave;
        }
      der = xtrystrdup (fields[2]);
      if (!der)
        {
          err = gpg_error_from_syserror ();
          log_error ("malloc failed: %s\n", gpg_strerror (err));
          goto leave;
        }
      for (s=fields[2], derlen=0; s[0] && s[1]; s += 2)
        der[derlen++] = xtoi_2 (s);
    }

  /* Store the data in the CMS object for all signers.  */
#if 0
  err = ksba_cms_add_attribute (cms, -1, fields[0], 0, der, derlen);
#else
  (void)cms;
  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
  if (err)
    {
      log_error ("invalid attribute specification '%s': %s\n",
                 attrstr, gpg_strerror (err));
      goto leave;
    }

 leave:
  xfree (der);
  xfree (fields);
  return err;
}



/* This function takes a binary detached signature in (BLOB,BLOBLEN)
 * and writes it to OUT_FP.  The core of the function is to replace
 * NDEF length sequences in the input to those with fixed inputs.
 * This helps certain other implementations to properly verify
 * detached signature.  Moreover, it allows our own trailing zero
 * stripping code - which we need for PDF signatures - to work
 * correctly.
 *
 * Example start of a detached signature as created by us:
 *   0 NDEF: SEQUENCE {      -- 1st sequence
 *   2    9:   OBJECT IDENTIFIER signedData (1 2 840 113549 1 7 2)
 *  13 NDEF:   [0] {         -- 2nd sequence
 *  15 NDEF:     SEQUENCE {  -- 3rd sequence
 *  17    1:       INTEGER 1 -- version
 *  20   15:       SET {     -- set of algorithms
 *  22   13:         SEQUENCE {
 *  24    9:           OBJECT IDENTIFIER sha-256 (2 16 840 1 101 3 4 2 1)
 *  35    0:           NULL
 *         :           }
 *         :         }
 *  37 NDEF:       SEQUENCE { -- 4th pretty short sequence
 *  39    9:         OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
 *         :         }
 *  52  869:       [0] {
 * Our goal is to replace the NDEF by fixed length tags.
 */
static gpg_error_t
write_detached_signature (ctrl_t ctrl, const void *blob, size_t bloblen,
                          estream_t out_fp)
{
  gpg_error_t err;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, cons, ndef;
  const unsigned char *p_ctoid, *p_version, *p_algoset, *p_dataoid;
  size_t               n_ctoid,  n_version,  n_algoset,  n_dataoid;
  const unsigned char *p_certset, *p_signerinfos;
  size_t               n_certset,  n_signerinfos;
  int i;
  ksba_der_t dbld;
  unsigned char *finalder = NULL;
  size_t finalderlen;

  (void)ctrl;

  p = blob;
  n = bloblen;
  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && cons))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No 1st sequence.  */

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_OBJECT_ID && !cons))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No signedData OID.  */
  if (objlen > n)
    return gpg_error (GPG_ERR_BAD_BER);     /* Object larger than data. */
  p_ctoid = p;
  n_ctoid = objlen;
  p += objlen;
  n -= objlen;

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_CONTEXT && tag == 0 && cons))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No 2nd sequence.  */

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && cons))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No 3rd sequence.  */

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_INTEGER))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No version.  */
  if (objlen > n)
    return gpg_error (GPG_ERR_BAD_BER);     /* Object larger than data. */
  p_version = p;
  n_version = objlen;
  p += objlen;
  n -= objlen;

  p_algoset = p;
  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SET && cons && !ndef))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No set of algorithms.  */
  if (objlen > n)
    return gpg_error (GPG_ERR_BAD_BER);     /* Object larger than data. */
  n_algoset = hdrlen + objlen;
  p += objlen;
  n -= objlen;

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && cons))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No 4th sequence.  */

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_OBJECT_ID && !cons))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No data OID.  */
  if (objlen > n)
    return gpg_error (GPG_ERR_BAD_BER);     /* Object larger than data. */
  p_dataoid = p;
  n_dataoid = objlen;
  p += objlen;
  n -= objlen;

  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (!(class == CLASS_UNIVERSAL && tag == TAG_NONE && !cons && !objlen))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No End tag.  */

  /* certificates [0] IMPLICIT CertificateSet OPTIONAL,
   * Note: We ignore the following
   *       crls [1] IMPLICIT CertificateRevocationLists OPTIONAL
   * because gpgsm does not create them.   */
  if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,&objlen,&hdrlen)))
    return err;
  if (class == CLASS_CONTEXT && tag == 0 && cons)
    {
      if (objlen > n)
        return gpg_error (GPG_ERR_BAD_BER);     /* Object larger than data. */
      p_certset = p;
      n_certset = objlen;
      p += objlen;
      n -= objlen;
      if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,
                                 &objlen,&hdrlen)))
        return err;
    }
  else
    {
      p_certset = NULL;
      n_certset = 0;
    }

  /*  SignerInfos ::= SET OF SignerInfo  */
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SET && cons && !ndef))
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No set of signerInfos.  */
  if (objlen > n)
    return gpg_error (GPG_ERR_BAD_BER);     /* Object larger than data. */
  p_signerinfos = p;
  n_signerinfos = objlen;
  p += objlen;
  n -= objlen;

  /* For the fun of it check the 3 end tags.  */
  for (i=0; i < 3; i++)
    {
      if ((err=parse_ber_header (&p,&n,&class,&tag,&cons,&ndef,
                                 &objlen,&hdrlen)))
        return err;
      if (!(class == CLASS_UNIVERSAL && tag == TAG_NONE && !cons && !objlen))
        return gpg_error (GPG_ERR_INV_CMS_OBJ); /* No End tag.  */
    }
  if (n)
    return gpg_error (GPG_ERR_INV_CMS_OBJ); /* Garbage */

  /*---- From here on we jump to leave on error.  ----*/

  /* Now create a new object from the collected data.  */
  dbld = ksba_der_builder_new (16);  /* (pre-allocate 16 items)  */
  if (!dbld)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ksba_der_add_tag (dbld, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_val ( dbld, 0, KSBA_TYPE_OBJECT_ID, p_ctoid, n_ctoid);
  ksba_der_add_tag ( dbld, KSBA_CLASS_CONTEXT, 0);
  ksba_der_add_tag (  dbld, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_val (   dbld, 0, KSBA_TYPE_INTEGER, p_version, n_version);
  ksba_der_add_der (   dbld, p_algoset, n_algoset);
  ksba_der_add_tag (   dbld, 0, KSBA_TYPE_SEQUENCE);
  ksba_der_add_val (    dbld, 0, KSBA_TYPE_OBJECT_ID, p_dataoid, n_dataoid);
  ksba_der_add_end (   dbld);
  if (p_certset)
    {
      ksba_der_add_tag (   dbld, KSBA_CLASS_CONTEXT, 0);
      ksba_der_add_der (    dbld, p_certset, n_certset);
      ksba_der_add_end (   dbld);
    }
  ksba_der_add_tag (   dbld, 0, KSBA_TYPE_SET);
  ksba_der_add_der (    dbld, p_signerinfos, n_signerinfos);
  ksba_der_add_end (   dbld);
  ksba_der_add_end (  dbld);
  ksba_der_add_end ( dbld);
  ksba_der_add_end (dbld);

  err = ksba_der_builder_get (dbld, &finalder, &finalderlen);
  if (err)
    goto leave;

  if (es_fwrite (finalder, finalderlen, 1, out_fp) != 1)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }


 leave:
  ksba_der_release (dbld);
  ksba_free (finalder);
  return err;
}



/* Perform a sign operation.

   Sign the data received on DATA-FD in embedded mode or in detached
   mode when DETACHED is true.  Write the signature to OUT_FP.  The
   keys used to sign are taken from SIGNERLIST or the default one will
   be used if the value of this argument is NULL. */
int
gpgsm_sign (ctrl_t ctrl, certlist_t signerlist,
            int data_fd, int detached, estream_t out_fp)
{
  gpg_error_t err;
  int i;
  gnupg_ksba_io_t b64writer = NULL;
  ksba_writer_t writer;
  estream_t sig_fp = NULL;  /* Used for detached signatures.  */
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  KEYDB_HANDLE kh = NULL;
  gcry_md_hd_t data_md = NULL;
  int signer;
  const char *algoid;
  int algo;
  ksba_isotime_t signed_at;
  certlist_t cl;
  int release_signerlist = 0;
  int binary_detached = detached && !ctrl->create_pem && !ctrl->create_base64;
  char *curve = NULL;

  audit_set_type (ctrl->audit, AUDIT_TYPE_SIGN);

  kh = keydb_new (ctrl);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (!gnupg_rng_is_compliant (opt.compliance))
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
      log_error (_("%s is not compliant with %s mode\n"),
                 "RNG",
                 gnupg_compliance_option_string (opt.compliance));
      gpgsm_status_with_error (ctrl, STATUS_ERROR,
                               "random-compliance", err);
      goto leave;
    }

  /* Note that in detached mode the b64 write is actually a binary
   * writer because we need to fixup the created signature later.
   * Note that we do this only for binary output because we have no
   * PEM writer interface outside of the ksba create writer code.  */
  ctrl->pem_name = "SIGNED MESSAGE";
  if (binary_detached)
    {
      sig_fp = es_fopenmem (0, "w+");
      err = sig_fp? 0 : gpg_error_from_syserror ();
      if (!err)
        err = gnupg_ksba_create_writer (&b64writer, 0, NULL, sig_fp, &writer);
    }
  else
    {
      err = gnupg_ksba_create_writer
        (&b64writer, ((ctrl->create_pem? GNUPG_KSBA_IO_PEM : 0)
                      | (ctrl->create_base64? GNUPG_KSBA_IO_BASE64 : 0)),
         ctrl->pem_name, out_fp, &writer);
    }
  if (err)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (err));
      goto leave;
    }

  gnupg_ksba_set_progress_cb (b64writer, gpgsm_progress_cb, ctrl);
  if (ctrl->input_size_hint)
    gnupg_ksba_set_total (b64writer, ctrl->input_size_hint);

  err = ksba_cms_new (&cms);
  if (err)
    goto leave;

  err = ksba_cms_set_reader_writer (cms, NULL, writer);
  if (err)
    {
      log_debug ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  /* We are going to create signed data with data as encap. content.
   * In authenticode mode we use spcIndirectDataContext instead.  */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_SIGNED_DATA);
  if (!err)
    err = ksba_cms_set_content_type
      (cms, 1,
       opt.authenticode? KSBA_CT_SPC_IND_DATA_CTX :
       KSBA_CT_DATA
       );
  if (err)
    {
      log_debug ("ksba_cms_set_content_type failed: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  /* If no list of signers is given, use the default certificate. */
  if (!signerlist)
    {
      ksba_cert_t cert = get_default_signer (ctrl);
      if (!cert)
        {
          log_error ("no default signer found\n");
          gpgsm_status2 (ctrl, STATUS_INV_SGNR,
                         get_inv_recpsgnr_code (GPG_ERR_NO_SECKEY), NULL);
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

      /* Although we don't check for ambiguous specification we will
         check that the signer's certificate is usable and valid.  */
      err = gpgsm_cert_use_sign_p (cert, 0);
      if (!err)
        err = gpgsm_validate_chain (ctrl, cert,
                                   GNUPG_ISOTIME_NONE, NULL, 0, NULL, 0, NULL);
      if (err)
        {
          char *tmpfpr;

          tmpfpr = gpgsm_get_fingerprint_hexstring (cert, 0);
          gpgsm_status2 (ctrl, STATUS_INV_SGNR,
                         get_inv_recpsgnr_code (err), tmpfpr, NULL);
          xfree (tmpfpr);
          goto leave;
        }

      /* That one is fine - create signerlist. */
      signerlist = xtrycalloc (1, sizeof *signerlist);
      if (!signerlist)
        {
          err = gpg_error_from_syserror ();
          ksba_cert_release (cert);
          goto leave;
        }
      signerlist->cert = cert;
      release_signerlist = 1;
    }


  /* Figure out the hash algorithm to use. We do not want to use the
     one for the certificate but if possible an OID for the plain
     algorithm.  */
  if (opt.forced_digest_algo && opt.verbose)
    log_info ("user requested hash algorithm %d\n", opt.forced_digest_algo);
  for (i=0, cl=signerlist; cl; cl = cl->next, i++)
    {
      const char *oid;
      unsigned int nbits;
      int pk_algo;

      xfree (curve);
      pk_algo = gpgsm_get_key_algo_info (cl->cert, &nbits, &curve);
      cl->pk_algo = pk_algo;

      if (opt.forced_digest_algo)
        {
          oid = NULL;
          cl->hash_algo = opt.forced_digest_algo;
        }
      else
        {
          if (pk_algo == GCRY_PK_ECC)
            {
              /* Map the Curve to a corresponding hash algo.  */
              if (nbits <= 256)
                oid = "2.16.840.1.101.3.4.2.1"; /* sha256 */
              else if (nbits <= 384)
                oid = "2.16.840.1.101.3.4.2.2"; /* sha384 */
              else
                oid = "2.16.840.1.101.3.4.2.3"; /* sha512 */
            }
          else
            {
              /* For RSA we reuse the hash algo used by the certificate.  */
              oid = ksba_cert_get_digest_algo (cl->cert);
            }
          cl->hash_algo = oid ? gcry_md_map_name (oid) : 0;
        }
      switch (cl->hash_algo)
        {
        case GCRY_MD_SHA1:   oid = "1.3.14.3.2.26"; break;
        case GCRY_MD_RMD160: oid = "1.3.36.3.2.1"; break;
        case GCRY_MD_SHA224: oid = "2.16.840.1.101.3.4.2.4"; break;
        case GCRY_MD_SHA256: oid = "2.16.840.1.101.3.4.2.1"; break;
        case GCRY_MD_SHA384: oid = "2.16.840.1.101.3.4.2.2"; break;
        case GCRY_MD_SHA512: oid = "2.16.840.1.101.3.4.2.3"; break;
/*         case GCRY_MD_WHIRLPOOL: oid = "No OID yet"; break; */

        case GCRY_MD_MD5:  /* We don't want to use MD5.  */
        case 0:            /* No algorithm found in cert.  */
        default:           /* Other algorithms.  */
          log_info (_("hash algorithm %d (%s) for signer %d not supported;"
                      " using %s\n"),
                    cl->hash_algo, oid? oid: "?", i,
                    gcry_md_algo_name (GCRY_MD_SHA1));
          cl->hash_algo = GCRY_MD_SHA1;
          oid = "1.3.14.3.2.26";
          break;
        }
      cl->hash_algo_oid = oid;

      /* Check compliance.  */
      if (! gnupg_digest_is_allowed (opt.compliance, 1, cl->hash_algo))
        {
          log_error (_("digest algorithm '%s' may not be used in %s mode\n"),
                     gcry_md_algo_name (cl->hash_algo),
                     gnupg_compliance_option_string (opt.compliance));
          err = gpg_error (GPG_ERR_DIGEST_ALGO);
          goto leave;
        }

      if (!gnupg_pk_is_allowed (opt.compliance, PK_USE_SIGNING, pk_algo,
                                PK_ALGO_FLAG_ECC18, NULL, nbits, curve))
        {
          char  kidstr[10+1];

          snprintf (kidstr, sizeof kidstr, "0x%08lX",
                    gpgsm_get_short_fingerprint (cl->cert, NULL));
          log_error (_("key %s may not be used for signing in %s mode\n"),
                     kidstr,
                     gnupg_compliance_option_string (opt.compliance));
          err = gpg_error (GPG_ERR_PUBKEY_ALGO);
          goto leave;
        }

    }

  if (opt.verbose > 1 || opt.debug)
    {
      for (i=0, cl=signerlist; cl; cl = cl->next, i++)
        log_info (_("hash algorithm used for signer %d: %s (%s)\n"),
                  i, gcry_md_algo_name (cl->hash_algo), cl->hash_algo_oid);
    }


  /* Gather certificates of signers and store them in the CMS object. */
  for (cl=signerlist; cl; cl = cl->next)
    {
      err = gpgsm_cert_use_sign_p (cl->cert, 0);
      if (err)
        goto leave;

      err = ksba_cms_add_signer (cms, cl->cert);
      if (err)
        {
          log_error ("ksba_cms_add_signer failed: %s\n", gpg_strerror (err));
          goto leave;
        }
      err = add_certificate_list (ctrl, cms, cl->cert);
      if (err)
        {
          log_error ("failed to store list of certificates: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      /* Set the hash algorithm we are going to use */
      err = ksba_cms_add_digest_algo (cms, cl->hash_algo_oid);
      if (err)
        {
          log_debug ("ksba_cms_add_digest_algo failed: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
    }


  /* Check whether one of the certificates is qualified.  Note that we
     already validated the certificate and thus the user data stored
     flag must be available. */
  if (!opt.no_chain_validation)
    {
      for (cl=signerlist; cl; cl = cl->next)
        {
          size_t buflen;
          char buffer[1];

          err = ksba_cert_get_user_data (cl->cert, "is_qualified",
                                         &buffer, sizeof (buffer), &buflen);
          if (err || !buflen)
            {
              log_error (_("checking for qualified certificate failed: %s\n"),
                         gpg_strerror (err));
              goto leave;
            }
          if (*buffer)
            err = gpgsm_qualified_consent (ctrl, cl->cert);
          else
            err = gpgsm_not_qualified_warning (ctrl, cl->cert);
          if (err)
            goto leave;
        }
    }

  /* Prepare hashing (actually we are figuring out what we have set
     above). */
  err = gcry_md_open (&data_md, 0, 0);
  if (err)
    {
      log_error ("md_open failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  if (DBG_HASHING)
    gcry_md_debug (data_md, "sign.data");

  for (i=0; (algoid=ksba_cms_get_digest_algo_list (cms, i)); i++)
    {
      algo = gcry_md_map_name (algoid);
      if (!algo)
        {
          log_error ("unknown hash algorithm '%s'\n", algoid? algoid:"?");
          err = gpg_error (GPG_ERR_BUG);
          goto leave;
        }
      gcry_md_enable (data_md, algo);
      audit_log_i (ctrl->audit, AUDIT_DATA_HASH_ALGO, algo);
    }

  audit_log (ctrl->audit, AUDIT_SETUP_READY);

  if (detached)
    { /* We hash the data right now so that we can store the message
         digest.  ksba_cms_build() takes this as an flag that detached
         data is expected. */
      unsigned char *digest;
      size_t digest_len;

      if (!hash_data (data_fd, data_md))
        audit_log (ctrl->audit, AUDIT_GOT_DATA);
      for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
        {
          digest = gcry_md_read (data_md, cl->hash_algo);
          digest_len = gcry_md_get_algo_dlen (cl->hash_algo);
          if ( !digest || !digest_len )
            {
              log_error ("problem getting the hash of the data\n");
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          err = ksba_cms_set_message_digest (cms, signer, digest, digest_len);
          if (err)
            {
              log_error ("ksba_cms_set_message_digest failed: %s\n",
                         gpg_strerror (err));
              goto leave;
            }
        }
    }

  gnupg_get_isotime (signed_at);
  for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
    {
      err = ksba_cms_set_signing_time (cms, signer, signed_at);
      if (err)
        {
          log_error ("ksba_cms_set_signing_time failed: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
    }

  {
    strlist_t sl;

    for (sl = opt.attributes; sl; sl = sl->next)
      if ((err = add_signed_attribute (cms, sl->d)))
        goto leave;
  }


  /* We need to write at least a minimal list of our capabilities to
   * try to convince some MUAs to use 3DES and not the crippled
   * RC2. Our list is:
   *
   *   aes256-CBC
   *   aes128-CBC
   *   des-EDE3-CBC
   */
  err = ksba_cms_add_smime_capability (cms, "2.16.840.1.101.3.4.1.42", NULL,0);
  if (!err)
    err = ksba_cms_add_smime_capability (cms, "2.16.840.1.101.3.4.1.2", NULL,0);
  if (!err)
    err = ksba_cms_add_smime_capability (cms, "1.2.840.113549.3.7", NULL, 0);
  if (err)
    {
      log_error ("ksba_cms_add_smime_capability failed: %s\n",
                 gpg_strerror (err));
      goto leave;
    }


  /* Main building loop. */
  do
    {
      err = ksba_cms_build (cms, &stopreason);
      if (err)
        {
          log_error ("creating CMS object failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (stopreason == KSBA_SR_BEGIN_DATA)
        {
          /* Hash the data and store the message digest. */
          unsigned char *digest;
          size_t digest_len;

          log_assert (!detached);

          err = hash_and_copy_data (data_fd, data_md, writer);
          if (err)
            goto leave;
          audit_log (ctrl->audit, AUDIT_GOT_DATA);
          for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
            {
              digest = gcry_md_read (data_md, cl->hash_algo);
              digest_len = gcry_md_get_algo_dlen (cl->hash_algo);
              if ( !digest || !digest_len )
                {
                  log_error ("problem getting the hash of the data\n");
                  err = gpg_error (GPG_ERR_BUG);
                  goto leave;
                }
              err = ksba_cms_set_message_digest (cms, signer,
                                                 digest, digest_len);
              if (err)
                {
                  log_error ("ksba_cms_set_message_digest failed: %s\n",
                             gpg_strerror (err));
                  goto leave;
                }
            }
        }
      else if (stopreason == KSBA_SR_NEED_SIG)
        {
          /* Compute the signature for all signers.  */
          gcry_md_hd_t md;

          err = gcry_md_open (&md, 0, 0);
          if (err)
            {
              log_error ("md_open failed: %s\n", gpg_strerror (err));
              goto leave;
            }
          if (DBG_HASHING)
            gcry_md_debug (md, "sign.attr");
          ksba_cms_set_hash_function (cms, HASH_FNC, md);
          for (cl=signerlist,signer=0; cl; cl = cl->next, signer++)
            {
              unsigned char *sigval = NULL;
              char *buf, *fpr;

              audit_log_i (ctrl->audit, AUDIT_NEW_SIG, signer);
              if (signer)
                gcry_md_reset (md);
              {
                certlist_t cl_tmp;

                for (cl_tmp=signerlist; cl_tmp; cl_tmp = cl_tmp->next)
                  {
                    gcry_md_enable (md, cl_tmp->hash_algo);
                    audit_log_i (ctrl->audit, AUDIT_ATTR_HASH_ALGO,
                                 cl_tmp->hash_algo);
                  }
              }

              err = ksba_cms_hash_signed_attrs (cms, signer);
              if (err)
                {
                  log_debug ("hashing signed attrs failed: %s\n",
                             gpg_strerror (err));
                  gcry_md_close (md);
                  goto leave;
                }

              err = gpgsm_create_cms_signature (ctrl, cl->cert,
                                                md, cl->hash_algo, &sigval);
              if (err)
                {
                  audit_log_cert (ctrl->audit, AUDIT_SIGNED_BY, cl->cert, err);
                  gcry_md_close (md);
                  goto leave;
                }

              err = ksba_cms_set_sig_val (cms, signer, sigval);
              xfree (sigval);
              if (err)
                {
                  audit_log_cert (ctrl->audit, AUDIT_SIGNED_BY, cl->cert, err);
                  log_error ("failed to store the signature: %s\n",
                             gpg_strerror (err));
                  gcry_md_close (md);
                  goto leave;
                }

              /* write a status message */
              fpr = gpgsm_get_fingerprint_hexstring (cl->cert, GCRY_MD_SHA1);
              if (!fpr)
                {
                  err = gpg_error (GPG_ERR_ENOMEM);
                  gcry_md_close (md);
                  goto leave;
                }
              if (opt.verbose)
                {
                  char *pkalgostr = gpgsm_pubkey_algo_string (cl->cert, NULL);
                  log_info (_("%s/%s signature using %s key %s\n"),
                            pubkey_algo_to_string (cl->pk_algo),
                            gcry_md_algo_name (cl->hash_algo),
                            pkalgostr, fpr);
                  xfree (pkalgostr);
                }
              buf = xtryasprintf ("%c %d %d 00 %s %s",
                                  detached? 'D':'S',
                                  cl->pk_algo,
                                  cl->hash_algo,
                                  signed_at,
                                  fpr);
              if (!buf)
                err = gpg_error_from_syserror ();
              xfree (fpr);
              if (err)
                {
                  gcry_md_close (md);
                  goto leave;
                }
              gpgsm_status (ctrl, STATUS_SIG_CREATED, buf);
              xfree (buf);
              audit_log_cert (ctrl->audit, AUDIT_SIGNED_BY, cl->cert, 0);
            }
          gcry_md_close (md);
        }
    }
  while (stopreason != KSBA_SR_READY);

  err = gnupg_ksba_finish_writer (b64writer);
  if (err)
    {
      log_error ("write failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (binary_detached)
    {
      void *blob = NULL;
      size_t bloblen;

      err = (es_fclose_snatch (sig_fp, &blob, &bloblen)?
             gpg_error_from_syserror () : 0);
      sig_fp = NULL;
      if (err)
        goto leave;
      err = write_detached_signature (ctrl, blob, bloblen, out_fp);
      xfree (blob);
      if (err)
        goto leave;
    }


  audit_log (ctrl->audit, AUDIT_SIGNING_DONE);
  log_info ("signature created\n");

 leave:
  if (err)
    log_error ("error creating signature: %s <%s>\n",
               gpg_strerror (err), gpg_strsource (err) );
  if (release_signerlist)
    gpgsm_release_certlist (signerlist);
  xfree (curve);
  ksba_cms_release (cms);
  gnupg_ksba_destroy_writer (b64writer);
  keydb_release (kh);
  gcry_md_close (data_md);
  es_fclose (sig_fp);
  return err;
}
