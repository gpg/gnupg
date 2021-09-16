/* backend-kbx.c - Keybox format backend for keyboxd
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "keyboxd.h"
#include "../common/i18n.h"
#include "backend.h"
#include "keybox.h"


/* Our definition of the backend handle.  */
struct backend_handle_s
{
  enum database_types db_type; /* Always DB_TYPE_KBX.  */
  unsigned int backend_id;     /* Always the id of the backend.  */

  void *token;  /* Used to create a new KEYBOX_HANDLE.  */
  char filename[1];
};


/* Check that the file FILENAME is a valid keybox file which can be
 * used here.  Common return codes:
 *
 * 0              := Valid keybox file
 * GPG_ERR_ENOENT := No such file
 * GPG_ERR_NO_OBJ := File exists with size zero.
 * GPG_ERR_INV_OBJ:= File exists but is not a keybox file.
 */
static gpg_error_t
check_kbx_file_magic (const char *filename)
{
  gpg_error_t err;
  u32 magic;
  unsigned char verbuf[4];
  estream_t fp;

  fp = es_fopen (filename, "rb");
  if (!fp)
    return gpg_error_from_syserror ();

  err = gpg_error (GPG_ERR_INV_OBJ);
  if (es_fread (&magic, 4, 1, fp) == 1 )
    {
      if (es_fread (&verbuf, 4, 1, fp) == 1
          && verbuf[0] == 1
          && es_fread (&magic, 4, 1, fp) == 1
          && !memcmp (&magic, "KBXf", 4))
        {
          err = 0;
        }
    }
  else /* Maybe empty: Let's create it. */
    err = gpg_error (GPG_ERR_NO_OBJ);

  es_fclose (fp);
  return err;
}


/* Create new keybox file.  This can also be used if the keybox
 * already exists but has a length of zero.  Do not use it in any
 * other cases.  */
static gpg_error_t
create_keybox (const char *filename)
{
  gpg_error_t err;
  dotlock_t lockhd = NULL;
  estream_t fp;

  /* To avoid races with other temporary instances of keyboxd trying
   * to create or update the keybox, we do the next stuff in a locked
   * state. */
  lockhd = dotlock_create (filename, 0);
  if (!lockhd)
    {
      err = gpg_error_from_syserror ();
      /* A reason for this to fail is that the directory is not
       * writable. However, this whole locking stuff does not make
       * sense if this is the case. An empty non-writable directory
       * with no keybox is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for '%s': %s\n",
                  filename, gpg_strerror (err));
      return err;
    }

  if ( dotlock_take (lockhd, -1) )
    {
      err = gpg_error_from_syserror ();
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock '%s': %s\n", filename, gpg_strerror (err));
      goto leave;
    }

  /* Make sure that at least one record is in a new keybox file, so
   * that the detection magic will work the next time it is used.
   * We always set the OpenPGP blobs maybe available flag.   */
  fp = es_fopen (filename, "w+b,mode=-rw-------");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating keybox '%s': %s\n"),
                 filename, gpg_strerror (err));
      goto leave;
    }
  err = _keybox_write_header_blob (fp, 1);
  es_fclose (fp);
  if (err)
    {
      log_error (_("error creating keybox '%s': %s\n"),
                 filename, gpg_strerror (err));
      goto leave;
    }

  if (!opt.quiet)
    log_info (_("keybox '%s' created\n"), filename);
  err = 0;

 leave:
  if (lockhd)
    {
      dotlock_release (lockhd);
      dotlock_destroy (lockhd);
    }
  return err;
}



/* Install a new resource and return a handle for that backend.  */
gpg_error_t
be_kbx_add_resource (ctrl_t ctrl, backend_handle_t *r_hd,
                     const char *filename, int readonly)
{
  gpg_error_t err;
  backend_handle_t hd;
  void *token;

  (void)ctrl;

  *r_hd = NULL;
  hd = xtrycalloc (1, sizeof *hd + strlen (filename));
  if (!hd)
    return gpg_error_from_syserror ();
  hd->db_type = DB_TYPE_KBX;
  strcpy (hd->filename, filename);

  err = check_kbx_file_magic (filename);
  switch (gpg_err_code (err))
    {
    case 0:
      break;
    case GPG_ERR_ENOENT:
    case GPG_ERR_NO_OBJ:
      if (readonly)
        {
          err = gpg_error (GPG_ERR_ENOENT);
          goto leave;
        }
      err = create_keybox (filename);
      if (err)
        goto leave;
      break;
    default:
      goto leave;
    }

  err = keybox_register_file (filename, 0, &token);
  if (err)
    goto leave;

  hd->backend_id = be_new_backend_id ();
  hd->token = token;

  *r_hd = hd;
  hd = NULL;

 leave:
  xfree (hd);
  return err;
}


/* Release the backend handle HD and all its resources.  HD is not
 * valid after a call to this function.  */
void
be_kbx_release_resource (ctrl_t ctrl, backend_handle_t hd)
{
  (void)ctrl;

  if (!hd)
    return;
  hd->db_type = DB_TYPE_NONE;

  xfree (hd);
}


void
be_kbx_release_kbx_hd (KEYBOX_HANDLE kbx_hd)
{
  keybox_release (kbx_hd);
}


/* Helper for be_find_request_part to initialize a kbx request part.  */
gpg_error_t
be_kbx_init_request_part (backend_handle_t backend_hd, db_request_part_t part)
{
  part->kbx_hd = keybox_new_openpgp (backend_hd->token, 0);
  if (!part->kbx_hd)
    return gpg_error_from_syserror ();
  return 0;
}


/* Search for the keys described by (DESC,NDESC) and return them to
 * the caller.  BACKEND_HD is the handle for this backend and REQUEST
 * is the current database request object.  */
gpg_error_t
be_kbx_search (ctrl_t ctrl, backend_handle_t backend_hd, db_request_t request,
               KEYDB_SEARCH_DESC *desc, unsigned int ndesc)
{
  gpg_error_t err;
  db_request_part_t part;
  size_t descindex;
  unsigned long skipped_long_blobs = 0;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_KBX);
  log_assert (request);

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;

  if (!desc)
    err = keybox_search_reset (part->kbx_hd);
  else
    err = keybox_search (part->kbx_hd, desc, ndesc, KEYBOX_BLOBTYPE_PGP,
                         &descindex, &skipped_long_blobs);
  if (err == -1)
    err = gpg_error (GPG_ERR_EOF);

  if (desc && !err)
    {
      /* Successful search operation.  */
      void *buffer;
      size_t buflen;
      enum pubkey_types pubkey_type;
      unsigned char ubid[UBID_LEN];

      err = keybox_get_data (part->kbx_hd, &buffer, &buflen,
                             &pubkey_type, ubid);
      if (err)
        goto leave;
      /* FIXME: Return the ephemeral flag.  */
      err = be_return_pubkey (ctrl, buffer, buflen, pubkey_type, ubid,
                              0, 0, 0, 0);
      if (!err)
        be_cache_pubkey (ctrl, ubid, buffer, buflen, pubkey_type);
      xfree (buffer);
    }

 leave:
  return err;
}


/* Seek in the keybox to the given UBID (if UBID is not NULL) or to
 * the primary fingerprint specified by (FPR,FPRLEN).  BACKEND_HD is
 * the handle for this backend and REQUEST is the current database
 * request object.  This does a dummy read so that the next search
 * operation starts right after that UBID. */
gpg_error_t
be_kbx_seek (ctrl_t ctrl, backend_handle_t backend_hd,
             db_request_t request, const unsigned char *ubid)
{
  gpg_error_t err;
  db_request_part_t part;
  size_t descindex;
  unsigned long skipped_long_blobs = 0;
  KEYDB_SEARCH_DESC desc;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_KBX);
  log_assert (request);

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_UBID;
  memcpy (desc.u.ubid, ubid, UBID_LEN);

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;

  err = keybox_search_reset (part->kbx_hd);
  if (!err)
    err = keybox_search (part->kbx_hd, &desc, 1, 0,
                         &descindex, &skipped_long_blobs);
  if (err == -1)
    err = gpg_error (GPG_ERR_EOF);

 leave:
  return err;
}


/* Insert (BLOB,BLOBLEN) into the keybox.  BACKEND_HD is the handle
 * for this backend and REQUEST is the current database request
 * object.  */
gpg_error_t
be_kbx_insert (ctrl_t ctrl, backend_handle_t backend_hd,
               db_request_t request, enum pubkey_types pktype,
               const void *blob, size_t bloblen)
{
  gpg_error_t err;
  db_request_part_t part;
  ksba_cert_t cert = NULL;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_KBX);
  log_assert (request);

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;

  if (pktype == PUBKEY_TYPE_OPGP)
    err = keybox_insert_keyblock (part->kbx_hd, blob, bloblen);
  else if (pktype == PUBKEY_TYPE_X509)
    {
      unsigned char sha1[20];

      err = ksba_cert_new (&cert);
      if (err)
        goto leave;
      err = ksba_cert_init_from_mem (cert, blob, bloblen);
      if (err)
        goto leave;
      gcry_md_hash_buffer (GCRY_MD_SHA1, sha1, blob, bloblen);

      err = keybox_insert_cert (part->kbx_hd, cert, sha1);
    }
  else
    err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);

 leave:
  ksba_cert_release (cert);
  return err;
}


/* Update (BLOB,BLOBLEN) in the keybox.  BACKEND_HD is the handle for
 * this backend and REQUEST is the current database request object.  */
gpg_error_t
be_kbx_update (ctrl_t ctrl, backend_handle_t backend_hd,
               db_request_t request, enum pubkey_types pktype,
               const void *blob, size_t bloblen)
{
  gpg_error_t err;
  db_request_part_t part;
  ksba_cert_t cert = NULL;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_KBX);
  log_assert (request);

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;

  /* FIXME: We make use of the fact that we know that the caller
   * already did a keybox search.  This needs to be made more
   * explicit.  */
  if (pktype == PUBKEY_TYPE_OPGP)
    {
      err = keybox_update_keyblock (part->kbx_hd, blob, bloblen);
    }
  else if (pktype == PUBKEY_TYPE_X509)
    {
      unsigned char sha1[20];

      err = ksba_cert_new (&cert);
      if (err)
        goto leave;
      err = ksba_cert_init_from_mem (cert, blob, bloblen);
      if (err)
        goto leave;
      gcry_md_hash_buffer (GCRY_MD_SHA1, sha1, blob, bloblen);

      err = keybox_update_cert (part->kbx_hd, cert, sha1);
    }
  else
    err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);

 leave:
  ksba_cert_release (cert);
  return err;
}


/* Delete the blob from the keybox.  BACKEND_HD is the handle for
 * this backend and REQUEST is the current database request object.  */
gpg_error_t
be_kbx_delete (ctrl_t ctrl, backend_handle_t backend_hd, db_request_t request)
{
  gpg_error_t err;
  db_request_part_t part;

  (void)ctrl;

  log_assert (backend_hd && backend_hd->db_type == DB_TYPE_KBX);
  log_assert (request);

  /* Find the specific request part or allocate it.  */
  err = be_find_request_part (backend_hd, request, &part);
  if (err)
    goto leave;

  /* FIXME: We make use of the fact that we know that the caller
   * already did a keybox search.  This needs to be made more
   * explicit.  */
  err = keybox_delete (part->kbx_hd);

 leave:
  return err;
}
