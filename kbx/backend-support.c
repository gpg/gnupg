/* backend-support.c - Supporting functions for the backend.
 * Copyright (C) 2019 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "keyboxd.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/tlv.h"
#include "backend.h"
#include "keybox-defs.h"


/* Common definition part of all backend handle.  All definitions of
 * this structure must start with these fields.  */
struct backend_handle_s
{
  enum database_types db_type;
  unsigned int backend_id;
};



/* Return a string with the name of the database type T.  */
const char *
strdbtype (enum database_types t)
{
  switch (t)
    {
    case DB_TYPE_NONE: return "none";
    case DB_TYPE_CACHE:return "cache";
    case DB_TYPE_KBX:  return "keybox";
    case DB_TYPE_SQLITE: return "sqlite";
    }
  return "?";
}


/* Return a new backend ID.  Backend IDs are used to identify backends
 * without using the actual object.  The number of backend resources
 * is limited because they are specified in the config file.  Thus an
 * overflow check is not required.  */
unsigned int
be_new_backend_id (void)
{
  static unsigned int last;

  return ++last;
}


/* Release the backend described by HD.  This is a generic function
 * which dispatches to the the actual backend.  */
void
be_generic_release_backend (ctrl_t ctrl, backend_handle_t hd)
{
  if (!hd)
    return;
  switch (hd->db_type)
    {
    case DB_TYPE_NONE:
      xfree (hd);
      break;
    case DB_TYPE_CACHE:
      be_cache_release_resource (ctrl, hd);
      break;
    case DB_TYPE_KBX:
      be_kbx_release_resource (ctrl, hd);
      break;
    case DB_TYPE_SQLITE:
      be_sqlite_release_resource (ctrl, hd);
      break;
    default:
      log_error ("%s: faulty backend handle of type %d given\n",
                 __func__, hd->db_type);
    }
}


/* Release the request object REQ.  */
void
be_release_request (db_request_t req)
{
  db_request_part_t part, partn;

  if (!req)
    return;

  for (part = req->part; part; part = partn)
    {
      partn = part->next;
      be_kbx_release_kbx_hd (part->kbx_hd);
      be_sqlite_release_local (part->besqlite);
      xfree (part);
    }
}


/* Given the backend handle BACKEND_HD and the REQUEST find or
 * allocate a request part for that backend and store it at R_PART.
 * On error R_PART is set to NULL and an error returned.  */
gpg_error_t
be_find_request_part (backend_handle_t backend_hd, db_request_t request,
                      db_request_part_t *r_part)
{
  gpg_error_t err;
  db_request_part_t part;

  for (part = request->part; part; part = part->next)
    if (part->backend_id == backend_hd->backend_id)
      break;
  if (!part)
    {
      part = xtrycalloc (1, sizeof *part);
      if (!part)
        return gpg_error_from_syserror ();
      part->backend_id = backend_hd->backend_id;
      if (backend_hd->db_type == DB_TYPE_KBX)
        {
          err = be_kbx_init_request_part (backend_hd, part);
          if (err)
            {
              xfree (part);
              return err;
            }
        }
      else if (backend_hd->db_type == DB_TYPE_SQLITE)
        {
          err = be_sqlite_init_local (backend_hd, part);
          if (err)
            {
              xfree (part);
              return err;
            }
        }
      part->next = request->part;
      request->part = part;
    }
  *r_part = part;
  return 0;
}


/* Return the public key (BUFFER,BUFLEN) which has the type
 * PUBKEY_TYPE to the caller.  */
gpg_error_t
be_return_pubkey (ctrl_t ctrl, const void *buffer, size_t buflen,
                  enum pubkey_types pubkey_type, const unsigned char *ubid,
                  int is_ephemeral, int is_revoked, int uid_no, int pk_no)
{
  gpg_error_t err;
  char hexubid[2*UBID_LEN+1];

  bin2hex (ubid, UBID_LEN, hexubid);
  err = kbxd_status_printf (ctrl, "PUBKEY_INFO", "%d %s %c%c %d %d",
                            pubkey_type, hexubid,
                            is_ephemeral? 'e':'-',
                            is_revoked?   'r':'-',
                            uid_no, pk_no);
  if (err)
    goto leave;

  if (ctrl->no_data_return)
    err = 0;
  else
    err = kbxd_write_data_line (ctrl, buffer, buflen);

 leave:
  return err;
}



/* Return true if (BLOB/BLOBLEN) seems to be an X509 certificate.  */
int
be_is_x509_blob (const unsigned char *blob, size_t bloblen)
{
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, cons, ndef;

  /* An X.509 certificate can be identified by this DER encoding:
   *
   *  30 82 05 B8 30 82 04 A0 A0 03 02 01 02 02 07 15 46 A0 BF 30 07 39
   *  ----------- +++++++++++ ----- ++++++++ --------------------------
   *  SEQUENCE    SEQUENCE    [0]   INTEGER  INTEGER
   *              (tbs)            (version) (s/n)
   *
   *  Note that v0 certificates don't have an explict version number.
   */

  p = blob;
  n = bloblen;
  if (parse_ber_header (&p, &n, &class, &tag, &cons, &ndef, &objlen, &hdrlen))
    return 0; /* Not a proper BER object.  */
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && cons))
    return 0; /* Does not start with a sequence.  */

  if (parse_ber_header (&p, &n, &class, &tag, &cons, &ndef, &objlen, &hdrlen))
    return 0; /* Not a proper BER object.  */
  if (!(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && cons))
    return 0; /* No TBS sequence.  */
  if (n < 7 || objlen < 7)
    return 0; /* Too short:  [0], version and min. s/n required.  */

  if (parse_ber_header (&p, &n, &class, &tag, &cons, &ndef, &objlen, &hdrlen))
    return 0; /* Not a proper BER object.  */
  if (!(class == CLASS_CONTEXT && tag == 0 && cons))
    {
      if (class == CLASS_UNIVERSAL && tag == TAG_INTEGER && !cons)
        return 1; /* Might be a X.509 v0 cert with implict version.  */
      return 0; /* No context tag.  */
    }

  if (parse_ber_header (&p, &n, &class, &tag, &cons, &ndef, &objlen, &hdrlen))
    return 0; /* Not a proper BER object.  */

  if (!(class == CLASS_UNIVERSAL && tag == TAG_INTEGER
        && !cons && objlen == 1 && n && (*p == 1 || *p == 2)))
    return 0; /* Unknown X.509 version.  */
  p++;  /* Skip version number.  */
  n--;

  if (parse_ber_header (&p, &n, &class, &tag, &cons, &ndef, &objlen, &hdrlen))
    return 0; /* Not a proper BER object.  */
  if (!(class == CLASS_UNIVERSAL && tag == TAG_INTEGER && !cons))
    return 0;  /* No s/n.  */

  return 1; /* Looks like an X.509 certificate. */
}


/* Return the public key type and the (primary) fingerprint for
 * (BLOB,BLOBLEN).  r_UBID must point to a buffer of at least UBID_LEN
 * bytes, on success it receives the UBID (primary fingerprint
 * truncated 20 octets). R_PKTYPE receives the public key type.  */
gpg_error_t
be_ubid_from_blob (const void *blob, size_t bloblen,
                   enum pubkey_types *r_pktype, char *r_ubid)
{
  gpg_error_t err;

  if (be_is_x509_blob (blob, bloblen))
    {
      /* Although libksba has a dedicated function to compute the
       * fingerprint we compute it here directly because we know that
       * we have the entire certificate here (we checked the start of
       * the blob and assume that the length is also okay).  */
      *r_pktype = PUBKEY_TYPE_X509;
      gcry_md_hash_buffer (GCRY_MD_SHA1, r_ubid, blob, bloblen);
      err = 0;
    }
  else
    {
      struct _keybox_openpgp_info info;

      err = _keybox_parse_openpgp (blob, bloblen, NULL, &info);
      if (err)
        {
          log_info ("error parsing OpenPGP blob: %s\n", gpg_strerror (err));
          err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);
        }
      else
        {
          *r_pktype = PUBKEY_TYPE_OPGP;
          log_assert (info.primary.fprlen >= 20);
          memcpy (r_ubid, info.primary.fpr, UBID_LEN);
          _keybox_destroy_openpgp_info (&info);
        }
    }

  return err;
}



/* Return a certificates serial number in hex encoding.  Caller must
 * free the returned string.  NULL is returned on error but ERRNO
 * might not be set if the certificate and thus Libksba is broken.  */
char *
be_get_x509_serial (ksba_cert_t cert)
{
  const char *p;
  unsigned long n;
  char *endp;

  p = (const char *)ksba_cert_get_serial (cert);
  if (!p)
    {
      log_debug ("oops: Libksba returned a certificate w/o a serial\n");
      return NULL;
    }

  if (*p != '(')
    {
      log_debug ("oops: Libksba returned an invalid s-expression\n");
      return NULL;
    }

  p++;
  n = strtoul (p, &endp, 10);
  p = endp;
  if (*p != ':')
    {
      log_debug ("oops: Libksba returned an invalid s-expression\n");
      return NULL;
    }
  p++;

  return bin2hex (p, n, NULL);
}


/* Return the keygrip for the X.509 certificate CERT.  The grip is
 * stored at KEYGRIP which must have been allocated by the caller
 * with a size of KEYGRIP_LEN.  */
gpg_error_t
be_get_x509_keygrip (ksba_cert_t cert, unsigned char *keygrip)
{
  gpg_error_t err;
  size_t n;
  ksba_sexp_t p;
  gcry_sexp_t s_pkey;

  p = ksba_cert_get_public_key (cert);
  if (!p)
    return gpg_error (GPG_ERR_NO_PUBKEY);
  n = gcry_sexp_canon_len (p, 0, NULL, NULL);
  if (!n)
    {
      ksba_free (p);
      return gpg_error (GPG_ERR_NO_PUBKEY);
    }
  err = gcry_sexp_sscan (&s_pkey, NULL, (char*)p, n);
  ksba_free (p);
  if (err)
    return err;

  if (!gcry_pk_get_keygrip (s_pkey, keygrip))
    err = gpg_error (GPG_ERR_PUBKEY_ALGO);
  gcry_sexp_release (s_pkey);
  return err;
}
