/* keybox-update.c - keybox update operations
 * Copyright (C) 2001, 2003, 2004, 2012 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "keybox-defs.h"
#include "../common/sysutils.h"
#include "../common/host2net.h"
#include "../common/utilproto.h"

#define EXTSEP_S "."

#define FILECOPY_INSERT 1
#define FILECOPY_DELETE 2
#define FILECOPY_UPDATE 3


#if !defined(HAVE_FSEEKO) && !defined(fseeko)

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifndef LONG_MAX
# define LONG_MAX ((long) ((unsigned long) -1 >> 1))
#endif
#ifndef LONG_MIN
# define LONG_MIN (-1 - LONG_MAX)
#endif

/****************
 * A substitute for fseeko, for hosts that don't have it.
 */
static int
fseeko (FILE * stream, off_t newpos, int whence)
{
  while (newpos != (long) newpos)
    {
      long pos = newpos < 0 ? LONG_MIN : LONG_MAX;
      if (fseek (stream, pos, whence) != 0)
	return -1;
      newpos -= pos;
      whence = SEEK_CUR;
    }
  return fseek (stream, (long) newpos, whence);
}
#endif /* !defined(HAVE_FSEEKO) && !defined(fseeko) */


static int
create_tmp_file (const char *template,
                 char **r_bakfname, char **r_tmpfname, estream_t *r_fp)
{
  gpg_error_t err;

  err = keybox_tmp_names (template, 0, r_bakfname, r_tmpfname);
  if (!err)
    {
      *r_fp = es_fopen (*r_tmpfname, "wb");
      if (!*r_fp)
        {
          err = gpg_error_from_syserror ();
          xfree (*r_tmpfname);
          *r_tmpfname = NULL;
          xfree (*r_bakfname);
          *r_bakfname = NULL;
        }
    }

  return err;
}


static int
rename_tmp_file (const char *bakfname, const char *tmpfname,
                 const char *fname, int secret )
{
  int rc=0;
  int block = 0;

  /* restrict the permissions for secret keyboxs */
#ifndef HAVE_DOSISH_SYSTEM
/*    if (secret && !opt.preserve_permissions) */
/*      { */
/*        if (chmod (tmpfname, S_IRUSR | S_IWUSR) )  */
/*          { */
/*            log_debug ("chmod of '%s' failed: %s\n", */
/*                       tmpfname, strerror(errno) ); */
/*            return KEYBOX_Write_File; */
/*  	} */
/*      } */
#endif

  /* fixme: invalidate close caches (not used with stdio)*/
/*    iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)tmpfname ); */
/*    iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)bakfname ); */
/*    iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname ); */

  /* First make a backup file except for secret keyboxes. */
  if (!secret)
    {
      block = 1;
      rc = gnupg_rename_file (fname, bakfname, &block);
      if (rc)
        goto leave;
    }

  /* Then rename the file. */
  rc = gnupg_rename_file (tmpfname, fname, NULL);
  if (block)
    {
      gnupg_unblock_all_signals ();
      block = 0;
    }
  /* if (rc) */
  /*   { */
  /*     if (secret) */
  /*       { */
  /*         log_info ("WARNING: 2 files with confidential" */
  /*                   " information exists.\n"); */
  /*         log_info ("%s is the unchanged one\n", fname ); */
  /*         log_info ("%s is the new one\n", tmpfname ); */
  /*         log_info ("Please fix this possible security flaw\n"); */
  /*       } */
  /*   } */

 leave:
  if (block)
    gnupg_unblock_all_signals ();
  return rc;
}



/* Perform insert/delete/update operation.  MODE is one of
   FILECOPY_INSERT, FILECOPY_DELETE, FILECOPY_UPDATE.  FOR_OPENPGP
   indicates that this is called due to an OpenPGP keyblock change.  */
static int
blob_filecopy (int mode, const char *fname, KEYBOXBLOB blob,
               int secret, int for_openpgp, off_t start_offset)
{
  gpg_err_code_t ec;
  estream_t fp, newfp;
  int rc = 0;
  char *bakfname = NULL;
  char *tmpfname = NULL;
  char buffer[4096];  /* (Must be at least 32 bytes) */
  int nread, nbytes;

  /* Open the source file. Because we do a rename, we have to check the
     permissions of the file */
  if ((ec = gnupg_access (fname, W_OK)))
    return gpg_error (ec);

  fp = es_fopen (fname, "rb");
  if (mode == FILECOPY_INSERT && !fp && errno == ENOENT)
    {
      /* Insert mode but file does not exist:
         Create a new keybox file. */
      newfp = es_fopen (fname, "wb");
      if (!newfp )
        return gpg_error_from_syserror ();

      rc = _keybox_write_header_blob (newfp, for_openpgp);
      if (rc)
        {
          es_fclose (newfp);
          return rc;
        }

      rc = _keybox_write_blob (blob, newfp, NULL);
      if (rc)
        {
          es_fclose (newfp);
          return rc;
        }

      if ( es_fclose (newfp) )
        return gpg_error_from_syserror ();

/*        if (chmod( fname, S_IRUSR | S_IWUSR )) */
/*          { */
/*            log_debug ("%s: chmod failed: %s\n", fname, strerror(errno) ); */
/*            return KEYBOX_File_Error; */
/*          } */
      return 0; /* Ready. */
    }

  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      goto leave;
    }

  /* Create the new file.  On success NEWFP is initialized.  */
  rc = create_tmp_file (fname, &bakfname, &tmpfname, &newfp);
  if (rc)
    {
      es_fclose (fp);
      goto leave;
    }

  /* prepare for insert */
  if (mode == FILECOPY_INSERT)
    {
      int first_record = 1;

      /* Copy everything to the new file.  If this is for OpenPGP, we
         make sure that the openpgp flag is set in the header.  (We
         failsafe the blob type.) */
      while ( (nread = es_fread (buffer, 1, DIM(buffer), fp)) > 0 )
        {
          if (first_record && for_openpgp
              && buffer[4] == KEYBOX_BLOBTYPE_HEADER)
            {
              first_record = 0;
              buffer[7] |= 0x02; /* OpenPGP data may be available.  */
            }

          if (es_fwrite (buffer, nread, 1, newfp) != 1)
            {
              rc = gpg_error_from_syserror ();
              es_fclose (fp);
              es_fclose (newfp);
              goto leave;
            }
        }
      if (es_ferror (fp))
        {
          rc = gpg_error_from_syserror ();
          es_fclose (fp);
          es_fclose (newfp);
          goto leave;
        }
    }

  /* Prepare for delete or update. */
  if ( mode == FILECOPY_DELETE || mode == FILECOPY_UPDATE )
    {
      off_t current = 0;

      /* Copy first part to the new file. */
      while ( current < start_offset )
        {
          nbytes = DIM(buffer);
          if (current + nbytes > start_offset)
              nbytes = start_offset - current;
          nread = es_fread (buffer, 1, nbytes, fp);
          if (!nread)
            break;
          current += nread;

          if (es_fwrite (buffer, nread, 1, newfp) != 1)
            {
              rc = gpg_error_from_syserror ();
              es_fclose (fp);
              es_fclose (newfp);
              goto leave;
            }
        }
      if (es_ferror (fp))
        {
          rc = gpg_error_from_syserror ();
          es_fclose (fp);
          es_fclose (newfp);
          goto leave;
        }

      /* Skip this blob. */
      rc = _keybox_read_blob (NULL, fp, NULL);
      if (rc)
        {
          es_fclose (fp);
          es_fclose (newfp);
          return rc;
        }
    }

  /* Do an insert or update. */
  if ( mode == FILECOPY_INSERT || mode == FILECOPY_UPDATE )
    {
      rc = _keybox_write_blob (blob, newfp, NULL);
      if (rc)
        {
          es_fclose (fp);
          es_fclose (newfp);
          return rc;
        }
    }

  /* Copy the rest of the packet for an delete or update. */
  if (mode == FILECOPY_DELETE || mode == FILECOPY_UPDATE)
    {
      while ( (nread = es_fread (buffer, 1, DIM(buffer), fp)) > 0 )
        {
          if (es_fwrite (buffer, nread, 1, newfp) != 1)
            {
              rc = gpg_error_from_syserror ();
              es_fclose (fp);
              es_fclose (newfp);
              goto leave;
            }
        }
      if (es_ferror (fp))
        {
          rc = gpg_error_from_syserror ();
          es_fclose (fp);
          es_fclose (newfp);
          goto leave;
        }
    }

  /* Close both files. */
  if (es_fclose(fp))
    {
      rc = gpg_error_from_syserror ();
      es_fclose (newfp);
      goto leave;
    }
  if (es_fclose(newfp))
    {
      rc = gpg_error_from_syserror ();
      goto leave;
    }

  rc = rename_tmp_file (bakfname, tmpfname, fname, secret);

 leave:
  xfree(bakfname);
  xfree(tmpfname);
  return rc;
}


/* Insert the OpenPGP keyblock {IMAGE,IMAGELEN} into HD. */
gpg_error_t
keybox_insert_keyblock (KEYBOX_HANDLE hd, const void *image, size_t imagelen)
{
  gpg_error_t err;
  const char *fname;
  KEYBOXBLOB blob;
  size_t nparsed;
  struct _keybox_openpgp_info info;

  if (!hd)
    return gpg_error (GPG_ERR_INV_HANDLE);
  if (!hd->kb)
    return gpg_error (GPG_ERR_INV_HANDLE);
  fname = hd->kb->fname;
  if (!fname)
    return gpg_error (GPG_ERR_INV_HANDLE);


  /* Close this one otherwise we will mess up the position for a next
     search.  Fixme: it would be better to adjust the position after
     the write operation.  */
  _keybox_close_file (hd);

  err = _keybox_parse_openpgp (image, imagelen, &nparsed, &info);
  if (err)
    return err;
  assert (nparsed <= imagelen);
  err = _keybox_create_openpgp_blob (&blob, &info, image, imagelen,
                                      hd->ephemeral);
  _keybox_destroy_openpgp_info (&info);
  if (!err)
    {
      err = blob_filecopy (FILECOPY_INSERT, fname, blob, hd->secret, 1, 0);
      _keybox_release_blob (blob);
      /*    if (!rc && !hd->secret && kb_offtbl) */
      /*      { */
      /*        update_offset_hash_table_from_kb (kb_offtbl, kb, 0); */
      /*      } */
    }
  return err;
}


/* Update the current key at HD with the given OpenPGP keyblock in
   {IMAGE,IMAGELEN}.  */
gpg_error_t
keybox_update_keyblock (KEYBOX_HANDLE hd, const void *image, size_t imagelen)
{
  gpg_error_t err;
  const char *fname;
  off_t off;
  KEYBOXBLOB blob;
  size_t nparsed;
  struct _keybox_openpgp_info info;

  if (!hd || !image || !imagelen)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);
  if (blob_get_type (hd->found.blob) != KEYBOX_BLOBTYPE_PGP)
    return gpg_error (GPG_ERR_WRONG_BLOB_TYPE);
  fname = hd->kb->fname;
  if (!fname)
    return gpg_error (GPG_ERR_INV_HANDLE);

  off = _keybox_get_blob_fileoffset (hd->found.blob);
  if (off == (off_t)-1)
    return gpg_error (GPG_ERR_GENERAL);

  /* Close the file so that we do no mess up the position for a
     next search.  */
  _keybox_close_file (hd);

  /* Build a new blob.  */
  err = _keybox_parse_openpgp (image, imagelen, &nparsed, &info);
  if (err)
    return err;
  assert (nparsed <= imagelen);
  err = _keybox_create_openpgp_blob (&blob, &info, image, imagelen,
                                     hd->ephemeral);
  _keybox_destroy_openpgp_info (&info);

  /* Update the keyblock.  */
  if (!err)
    {
      err = blob_filecopy (FILECOPY_UPDATE, fname, blob, hd->secret, 1, off);
      _keybox_release_blob (blob);
    }
  return err;
}



#ifdef KEYBOX_WITH_X509
int
keybox_insert_cert (KEYBOX_HANDLE hd, ksba_cert_t cert,
                    unsigned char *sha1_digest)
{
  int rc;
  const char *fname;
  KEYBOXBLOB blob;

  if (!hd)
    return gpg_error (GPG_ERR_INV_HANDLE);
  if (!hd->kb)
    return gpg_error (GPG_ERR_INV_HANDLE);
  fname = hd->kb->fname;
  if (!fname)
    return gpg_error (GPG_ERR_INV_HANDLE);

  /* Close this one otherwise we will mess up the position for a next
     search.  Fixme: it would be better to adjust the position after
     the write operation.  */
  _keybox_close_file (hd);

  rc = _keybox_create_x509_blob (&blob, cert, sha1_digest, hd->ephemeral);
  if (!rc)
    {
      rc = blob_filecopy (FILECOPY_INSERT, fname, blob, hd->secret, 0, 0);
      _keybox_release_blob (blob);
      /*    if (!rc && !hd->secret && kb_offtbl) */
      /*      { */
      /*        update_offset_hash_table_from_kb (kb_offtbl, kb, 0); */
      /*      } */
    }
  return rc;
}

int
keybox_update_cert (KEYBOX_HANDLE hd, ksba_cert_t cert,
                    unsigned char *sha1_digest)
{
  (void)hd;
  (void)cert;
  (void)sha1_digest;
  return -1;
}


#endif /*KEYBOX_WITH_X509*/

/* Note: We assume that the keybox has been locked before the current
   search was executed.  This is needed so that we can depend on the
   offset information of the flags. */
int
keybox_set_flags (KEYBOX_HANDLE hd, int what, int idx, unsigned int value)
{
  off_t off;
  const char *fname;
  estream_t fp;
  gpg_err_code_t ec;
  size_t flag_pos, flag_size;
  const unsigned char *buffer;
  size_t length;

  (void)idx;  /* Not yet used.  */

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);
  if (!hd->kb)
    return gpg_error (GPG_ERR_INV_HANDLE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);
  fname = hd->kb->fname;
  if (!fname)
    return gpg_error (GPG_ERR_INV_HANDLE);

  off = _keybox_get_blob_fileoffset (hd->found.blob);
  if (off == (off_t)-1)
    return gpg_error (GPG_ERR_GENERAL);

  buffer = _keybox_get_blob_image (hd->found.blob, &length);
  ec = _keybox_get_flag_location (buffer, length, what, &flag_pos, &flag_size);
  if (ec)
    return gpg_error (ec);

  off += flag_pos;

  _keybox_close_file (hd);
  fp = es_fopen (hd->kb->fname, "r+b");
  if (!fp)
    return gpg_error_from_syserror ();

  ec = 0;
  if (es_fseeko (fp, off, SEEK_SET))
    ec = gpg_err_code_from_syserror ();
  else
    {
      unsigned char tmp[4];

      tmp[0] = value >> 24;
      tmp[1] = value >> 16;
      tmp[2] = value >>  8;
      tmp[3] = value;

      switch (flag_size)
        {
        case 1:
        case 2:
        case 4:
          if (es_fwrite (tmp+4-flag_size, flag_size, 1, fp) != 1)
            ec = gpg_err_code_from_syserror ();
          break;
        default:
          ec = GPG_ERR_BUG;
          break;
        }
    }

  if (es_fclose (fp))
    {
      if (!ec)
        ec = gpg_err_code_from_syserror ();
    }

  return gpg_error (ec);
}



int
keybox_delete (KEYBOX_HANDLE hd)
{
  off_t off;
  const char *fname;
  estream_t fp;
  int rc;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!hd->found.blob)
    return gpg_error (GPG_ERR_NOTHING_FOUND);
  if (!hd->kb)
    return gpg_error (GPG_ERR_INV_HANDLE);
  fname = hd->kb->fname;
  if (!fname)
    return gpg_error (GPG_ERR_INV_HANDLE);

  off = _keybox_get_blob_fileoffset (hd->found.blob);
  if (off == (off_t)-1)
    return gpg_error (GPG_ERR_GENERAL);
  off += 4;

  _keybox_close_file (hd);
  fp = es_fopen (hd->kb->fname, "r+b");
  if (!fp)
    return gpg_error_from_syserror ();

  if (es_fseeko (fp, off, SEEK_SET))
    rc = gpg_error_from_syserror ();
  else if (es_fputc (0, fp) == EOF)
    rc = gpg_error_from_syserror ();
  else
    rc = 0;

  if (es_fclose (fp))
    {
      if (!rc)
        rc = gpg_error_from_syserror ();
    }

  return rc;
}


/* Compress the keybox file.  This should be run with the file
   locked. */
int
keybox_compress (KEYBOX_HANDLE hd)
{
  gpg_err_code_t ec;
  int read_rc, rc;
  const char *fname;
  estream_t fp, newfp;
  char *bakfname = NULL;
  char *tmpfname = NULL;
  int first_blob;
  KEYBOXBLOB blob = NULL;
  u32 cut_time;
  int any_changes = 0;
  int skipped_deleted;

  if (!hd)
    return gpg_error (GPG_ERR_INV_HANDLE);
  if (!hd->kb)
    return gpg_error (GPG_ERR_INV_HANDLE);
  if (hd->secret)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  fname = hd->kb->fname;
  if (!fname)
    return gpg_error (GPG_ERR_INV_HANDLE);

  _keybox_close_file (hd);

  /* Open the source file. Because we do a rename, we have to check the
     permissions of the file */
  if ((ec = gnupg_access (fname, W_OK)))
    return gpg_error (ec);

  fp = es_fopen (fname, "rb");
  if (!fp && errno == ENOENT)
    return 0; /* Ready. File has been deleted right after the access above. */
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      return rc;
    }

  /* A quick test to see if we need to compress the file at all.  We
     schedule a compress run after 3 hours. */
  if ( !_keybox_read_blob (&blob, fp, NULL) )
    {
      const unsigned char *buffer;
      size_t length;

      buffer = _keybox_get_blob_image (blob, &length);
      if (length > 4 && buffer[4] == KEYBOX_BLOBTYPE_HEADER)
        {
          u32 last_maint = buf32_to_u32 (buffer+20);

          if ( (last_maint + 3*3600) > make_timestamp () )
            {
              es_fclose (fp);
              _keybox_release_blob (blob);
              return 0; /* Compress run not yet needed. */
            }
        }
      _keybox_release_blob (blob);
      es_fseek (fp, 0, SEEK_SET);
      es_clearerr (fp);
    }

  /* Create the new file. */
  rc = create_tmp_file (fname, &bakfname, &tmpfname, &newfp);
  if (rc)
    {
      es_fclose (fp);
      return rc;;
    }


  /* Processing loop.  By reading using _keybox_read_blob we
     automagically skip any blobs flagged as deleted.  Thus what we
     only have to do is to check all ephemeral flagged blocks whether
     their time has come and write out all other blobs. */
  cut_time = make_timestamp () - 86400;
  first_blob = 1;
  skipped_deleted = 0;
  for (rc=0; !(read_rc = _keybox_read_blob (&blob, fp, &skipped_deleted));
       _keybox_release_blob (blob), blob = NULL )
    {
      unsigned int blobflags;
      const unsigned char *buffer;
      size_t length, pos, size;
      u32 created_at;

      if (skipped_deleted)
        any_changes = 1;
      buffer = _keybox_get_blob_image (blob, &length);
      if (first_blob)
        {
          first_blob = 0;
          if (length > 4 && buffer[4] == KEYBOX_BLOBTYPE_HEADER)
            {
              /* Write out the blob with an updated maintenance time
                 stamp and if needed (ie. used by gpg) set the openpgp
                 flag.  */
              _keybox_update_header_blob (blob, hd->for_openpgp);
              rc = _keybox_write_blob (blob, newfp, NULL);
              if (rc)
                break;
              continue;
            }

          /* The header blob is missing.  Insert it.  */
          rc = _keybox_write_header_blob (newfp, hd->for_openpgp);
          if (rc)
            break;
          any_changes = 1;
        }
      else if (length > 4 && buffer[4] == KEYBOX_BLOBTYPE_HEADER)
        {
          /* Oops: There is another header record - remove it. */
          any_changes = 1;
          continue;
        }

      if (_keybox_get_flag_location (buffer, length,
                                     KEYBOX_FLAG_BLOB, &pos, &size)
          || size != 2)
        {
          rc = gpg_error (GPG_ERR_BUG);
          break;
        }
      blobflags = buf16_to_uint (buffer+pos);
      if ((blobflags & KEYBOX_FLAG_BLOB_EPHEMERAL))
        {
          /* This is an ephemeral blob. */
          if (_keybox_get_flag_location (buffer, length,
                                         KEYBOX_FLAG_CREATED_AT, &pos, &size)
              || size != 4)
            created_at = 0; /* oops. */
          else
            created_at = buf32_to_u32 (buffer+pos);

          if (created_at && created_at < cut_time)
            {
              any_changes = 1;
              continue; /* Skip this blob. */
            }
        }

      rc = _keybox_write_blob (blob, newfp, NULL);
      if (rc)
        break;
    }
  if (skipped_deleted)
    any_changes = 1;
  _keybox_release_blob (blob); blob = NULL;
  if (!rc && read_rc == -1)
    rc = 0;
  else if (!rc)
    rc = read_rc;

  /* Close both files. */
  if (es_fclose(fp) && !rc)
    rc = gpg_error_from_syserror ();
  if (es_fclose(newfp) && !rc)
    rc = gpg_error_from_syserror ();

  /* Rename or remove the temporary file. */
  if (rc || !any_changes)
    gnupg_remove (tmpfname);
  else
    rc = rename_tmp_file (bakfname, tmpfname, fname, hd->secret);

  xfree(bakfname);
  xfree(tmpfname);
  return rc;
}
