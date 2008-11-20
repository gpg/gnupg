/* keybox-update.c - keybox update operations
 *	Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "keybox-defs.h"

#define EXTSEP_S "."


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
                 char **r_bakfname, char **r_tmpfname, FILE **r_fp)
{  
  char *bakfname, *tmpfname;
  
  *r_bakfname = NULL;
  *r_tmpfname = NULL;
  
# ifdef USE_ONLY_8DOT3
  /* Here is another Windoze bug?:
   * you cant rename("pubring.kbx.tmp", "pubring.kbx");
   * but	rename("pubring.kbx.tmp", "pubring.aaa");
   * works.  So we replace ".kbx" by ".kb_" or ".k__".  Note that we
   * can't use ".bak" and ".tmp", because these suffixes are used by
   * gpg and would lead to a sharing violation or data corruption.
   */
  if (strlen (template) > 4
      && !strcmp (template+strlen(template)-4, EXTSEP_S "kbx") )
    {
      bakfname = xtrymalloc (strlen (template) + 1);
      if (!bakfname)
        return gpg_error_from_syserror ();
      strcpy (bakfname, template);
      strcpy (bakfname+strlen(template)-4, EXTSEP_S "kb_");
      
      tmpfname = xtrymalloc (strlen (template) + 1);
      if (!tmpfname)
        {
          gpg_error_t tmperr = gpg_error_from_syserror ();
          xfree (bakfname);
          return tmperr;
        }
      strcpy (tmpfname,template);
      strcpy (tmpfname + strlen (template)-4, EXTSEP_S "k__");
    }
  else 
    { /* File does not end with kbx, thus we hope we are working on a
         modern file system and appending a suffix works. */
      bakfname = xtrymalloc ( strlen (template) + 5);
      if (!bakfname)
        return gpg_error_from_syserror ();
      strcpy (stpcpy (bakfname, template), EXTSEP_S "kb_");
      
      tmpfname = xtrymalloc ( strlen (template) + 5);
      if (!tmpfname)
        {
          gpg_error_t tmperr = gpg_error_from_syserror ();
          xfree (bakfname);
          return tmperr;
        }
      strcpy (stpcpy (tmpfname, template), EXTSEP_S "k__");
    }
# else /* Posix file names */
  bakfname = xtrymalloc (strlen (template) + 2);
  if (!bakfname)
    return gpg_error_from_syserror ();
  strcpy (stpcpy (bakfname,template),"~");
  
  tmpfname = xtrymalloc ( strlen (template) + 5);
  if (!tmpfname)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      xfree (bakfname);
      return tmperr;
    }
  strcpy (stpcpy (tmpfname,template), EXTSEP_S "tmp");
# endif /* Posix filename */

  *r_fp = fopen (tmpfname, "wb");
  if (!*r_fp)
    {
      gpg_error_t tmperr = gpg_error_from_syserror ();
      xfree (tmpfname);
      xfree (bakfname);
      return tmperr;
    }

  *r_bakfname = bakfname;
  *r_tmpfname = tmpfname;
  return 0;
}


static int
rename_tmp_file (const char *bakfname, const char *tmpfname,
                 const char *fname, int secret )
{
  int rc=0;

  /* restrict the permissions for secret keyboxs */
#ifndef HAVE_DOSISH_SYSTEM
/*    if (secret && !opt.preserve_permissions) */
/*      { */
/*        if (chmod (tmpfname, S_IRUSR | S_IWUSR) )  */
/*          { */
/*            log_debug ("chmod of `%s' failed: %s\n", */
/*                       tmpfname, strerror(errno) ); */
/*            return KEYBOX_Write_File; */
/*  	} */
/*      } */
#endif

  /* fixme: invalidate close caches (not used with stdio)*/
/*    iobuf_ioctl (NULL, 2, 0, (char*)tmpfname ); */
/*    iobuf_ioctl (NULL, 2, 0, (char*)bakfname ); */
/*    iobuf_ioctl (NULL, 2, 0, (char*)fname ); */

  /* First make a backup file except for secret keyboxes. */
  if (!secret)
    { 
#if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
      remove (bakfname);
#endif
      if (rename (fname, bakfname) )
        {
          return gpg_error_from_syserror ();
	}
    }
  
  /* Then rename the file. */
#if defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
  remove (fname);
#endif
  if (rename (tmpfname, fname) )
    {
      rc = gpg_error_from_syserror ();
      if (secret)
        {
/*            log_info ("WARNING: 2 files with confidential" */
/*                       " information exists.\n"); */
/*            log_info ("%s is the unchanged one\n", fname ); */
/*            log_info ("%s is the new one\n", tmpfname ); */
/*            log_info ("Please fix this possible security flaw\n"); */
	}
      return rc;
    }
  
  return 0;
}



/* Perform insert/delete/update operation.
    mode 1 = insert
 	 2 = delete
 	 3 = update
*/
static int
blob_filecopy (int mode, const char *fname, KEYBOXBLOB blob, 
               int secret, off_t start_offset)
{
  FILE *fp, *newfp;
  int rc=0;
  char *bakfname = NULL;
  char *tmpfname = NULL;
  char buffer[4096];
  int nread, nbytes;

  /* Open the source file. Because we do a rename, we have to check the 
     permissions of the file */
  if (access (fname, W_OK))
    return gpg_error_from_syserror ();

  fp = fopen (fname, "rb");
  if (mode == 1 && !fp && errno == ENOENT)
    { 
      /* Insert mode but file does not exist:
         Create a new keybox file. */
      newfp = fopen (fname, "wb");
      if (!newfp )
        return gpg_error_from_syserror ();

      rc = _keybox_write_header_blob (newfp);
      if (rc)
        return rc;

      rc = _keybox_write_blob (blob, newfp);
      if (rc)
        return rc;

      if ( fclose (newfp) )
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

  /* Create the new file. */
  rc = create_tmp_file (fname, &bakfname, &tmpfname, &newfp);
  if (rc)
    {
      fclose(fp);
      goto leave;
    }
  
  /* prepare for insert */
  if (mode == 1)
    { 
      /* Copy everything to the new file. */
      while ( (nread = fread (buffer, 1, DIM(buffer), fp)) > 0 )
        {
          if (fwrite (buffer, nread, 1, newfp) != 1)
            {
              rc = gpg_error_from_syserror ();
              goto leave;
            }
        }
      if (ferror (fp))
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
    }
  
  /* Prepare for delete or update. */
  if ( mode == 2 || mode == 3 ) 
    { 
      off_t current = 0;
      
      /* Copy first part to the new file. */
      while ( current < start_offset )
        {
          nbytes = DIM(buffer);
          if (current + nbytes > start_offset)
              nbytes = start_offset - current;
          nread = fread (buffer, 1, nbytes, fp);
          if (!nread)
            break;
          current += nread;
          
          if (fwrite (buffer, nread, 1, newfp) != 1)
            {
              rc = gpg_error_from_syserror ();
              goto leave;
            }
        }
      if (ferror (fp))
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
      
      /* Skip this blob. */
      rc = _keybox_read_blob (NULL, fp);
      if (rc)
        return rc;
    }
  
  /* Do an insert or update. */
  if ( mode == 1 || mode == 3 )
    { 
      rc = _keybox_write_blob (blob, newfp);
      if (rc)
          return rc;
    }
  
  /* Copy the rest of the packet for an delete or update. */
  if (mode == 2 || mode == 3)
    { 
      while ( (nread = fread (buffer, 1, DIM(buffer), fp)) > 0 )
        {
          if (fwrite (buffer, nread, 1, newfp) != 1)
            {
              rc = gpg_error_from_syserror ();
              goto leave;
            }
        }
      if (ferror (fp))
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }
    }
    
  /* Close both files. */
  if (fclose(fp))
    {
      rc = gpg_error_from_syserror ();
      fclose (newfp);
      goto leave;
    }
  if (fclose(newfp))
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
      rc = blob_filecopy (1, fname, blob, hd->secret, 0);
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
  FILE *fp;
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
  fp = fopen (hd->kb->fname, "r+b");
  if (!fp)
    return gpg_error_from_syserror ();

  ec = 0;
  if (fseeko (fp, off, SEEK_SET))
    ec = gpg_error_from_syserror ();
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
          if (fwrite (tmp+4-flag_size, flag_size, 1, fp) != 1)
            ec = gpg_err_code_from_syserror ();
          break;
        default:
          ec = GPG_ERR_BUG;
          break;
        }
    }

  if (fclose (fp))
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
  FILE *fp;
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
  fp = fopen (hd->kb->fname, "r+b");
  if (!fp)
    return gpg_error_from_syserror ();

  if (fseeko (fp, off, SEEK_SET))
    rc = gpg_error_from_syserror ();
  else if (putc (0, fp) == EOF)
    rc = gpg_error_from_syserror ();
  else
    rc = 0;

  if (fclose (fp))
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
  int read_rc, rc;
  const char *fname;
  FILE *fp, *newfp;
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
  if (access (fname, W_OK))
    return gpg_error_from_syserror ();

  fp = fopen (fname, "rb");
  if (!fp && errno == ENOENT)
    return 0; /* Ready. File has been deleted right after the access above. */
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      return rc;
    }

  /* A quick test to see if we need to compress the file at all.  We
     schedule a compress run after 3 hours. */
  if ( !_keybox_read_blob (&blob, fp) )
    {
      const unsigned char *buffer;
      size_t length;

      buffer = _keybox_get_blob_image (blob, &length);
      if (length > 4 && buffer[4] == BLOBTYPE_HEADER)
        {
          u32 last_maint = ((buffer[20] << 24) | (buffer[20+1] << 16)
                            | (buffer[20+2] << 8) | (buffer[20+3]));
          
          if ( (last_maint + 3*3600) > time (NULL) )
            {
              fclose (fp);
              _keybox_release_blob (blob);
              return 0; /* Compress run not yet needed. */
            }
        }
      _keybox_release_blob (blob);
      rewind (fp);
    }

  /* Create the new file. */
  rc = create_tmp_file (fname, &bakfname, &tmpfname, &newfp);
  if (rc)
    {
      fclose(fp);
      return rc;;
    }

  
  /* Processing loop.  By reading using _keybox_read_blob we
     automagically skip any blobs flagged as deleted.  Thus what we
     only have to do is to check all ephemeral flagged blocks whether
     their time has come and write out all other blobs. */
  cut_time = time(NULL) - 86400;
  first_blob = 1;
  skipped_deleted = 0;
  for (rc=0; !(read_rc = _keybox_read_blob2 (&blob, fp, &skipped_deleted));
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
          if (length > 4 && buffer[4] == BLOBTYPE_HEADER)
            {
              /* Write out the blob with an updated maintenance time stamp. */
              _keybox_update_header_blob (blob);
              rc = _keybox_write_blob (blob, newfp);
              if (rc)
                break;
              continue;
            }

          /* The header blob is missing.  Insert it.  */
          rc = _keybox_write_header_blob (newfp);
          if (rc)
            break;
          any_changes = 1;
        }
      else if (length > 4 && buffer[4] == BLOBTYPE_HEADER)
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
      blobflags = ((buffer[pos] << 8) | (buffer[pos+1]));
      if ((blobflags & KEYBOX_FLAG_BLOB_EPHEMERAL))
        {
          /* This is an ephemeral blob. */
          if (_keybox_get_flag_location (buffer, length, 
                                         KEYBOX_FLAG_CREATED_AT, &pos, &size)
              || size != 4)
            created_at = 0; /* oops. */
          else
            created_at = ((buffer[pos] << 24) | (buffer[pos+1] << 16)
                          | (buffer[pos+2] << 8) | (buffer[pos+3]));

          if (created_at && created_at < cut_time)
            {
              any_changes = 1;
              continue; /* Skip this blob. */
            }
        }

      rc = _keybox_write_blob (blob, newfp);
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
  if (fclose(fp) && !rc)
    rc = gpg_error_from_syserror ();
  if (fclose(newfp) && !rc)
    rc = gpg_error_from_syserror ();

  /* Rename or remove the temporary file. */
  if (rc || !any_changes)
    remove (tmpfname);
  else
    rc = rename_tmp_file (bakfname, tmpfname, fname, hd->secret);

  xfree(bakfname);
  xfree(tmpfname);
  return rc;
}

