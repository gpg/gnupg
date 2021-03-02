/* keybox-init.c - Initialization of the library
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <assert.h>

#include "keybox-defs.h"
#include "../common/sysutils.h"
#include "../common/mischelp.h"

static KB_NAME kb_names;


/* Register a filename for plain keybox files.  Returns 0 on success,
 * GPG_ERR_EEXIST if it has already been registered, or another error
 * code.  On success or with error code GPG_ERR_EEXIST a token usable
 * to access the keybox handle is stored at R_TOKEN, NULL is stored
 * for all other errors.  */
gpg_error_t
keybox_register_file (const char *fname, int secret, void **r_token)
{
  KB_NAME kr;

  *r_token = NULL;

  for (kr=kb_names; kr; kr = kr->next)
    {
      if (same_file_p (kr->fname, fname) )
        {
          *r_token = kr;
          return gpg_error (GPG_ERR_EEXIST); /* Already registered. */
        }
    }

  kr = xtrymalloc (sizeof *kr + strlen (fname));
  if (!kr)
    return gpg_error_from_syserror ();
  strcpy (kr->fname, fname);
  kr->secret = !!secret;

  kr->handle_table = NULL;
  kr->handle_table_size = 0;

  kr->lockhd = NULL;
  kr->is_locked = 0;
  kr->did_full_scan = 0;
  /* keep a list of all issued pointers */
  kr->next = kb_names;
  kb_names = kr;

  /* create the offset table the first time a function here is used */
/*      if (!kb_offtbl) */
/*        kb_offtbl = new_offset_hash_table (); */

  *r_token = kr;
  return 0;
}

int
keybox_is_writable (void *token)
{
  KB_NAME r = token;

  return r? !gnupg_access (r->fname, W_OK) : 0;
}



static KEYBOX_HANDLE
do_keybox_new (KB_NAME resource, int secret, int for_openpgp)
{
  KEYBOX_HANDLE hd;
  int idx;

  assert (resource && !resource->secret == !secret);
  hd = xtrycalloc (1, sizeof *hd);
  if (hd)
    {
      hd->kb = resource;
      hd->secret = !!secret;
      hd->for_openpgp = for_openpgp;
      if (!resource->handle_table)
        {
          resource->handle_table_size = 3;
          resource->handle_table = xtrycalloc (resource->handle_table_size,
                                               sizeof *resource->handle_table);
          if (!resource->handle_table)
            {
              resource->handle_table_size = 0;
              xfree (hd);
              return NULL;
            }
        }
      for (idx=0; idx < resource->handle_table_size; idx++)
        if (!resource->handle_table[idx])
          {
            resource->handle_table[idx] = hd;
            break;
          }
      if (!(idx < resource->handle_table_size))
        {
          KEYBOX_HANDLE *tmptbl;
          size_t newsize;

          newsize = resource->handle_table_size + 5;
          tmptbl = xtryrealloc (resource->handle_table,
                                newsize * sizeof (*tmptbl));
          if (!tmptbl)
            {
              xfree (hd);
              return NULL;
            }
          resource->handle_table = tmptbl;
          resource->handle_table_size = newsize;
          resource->handle_table[idx] = hd;
          for (idx++; idx < resource->handle_table_size; idx++)
            resource->handle_table[idx] = NULL;
        }
    }
  return hd;
}


/* Create a new handle for the resource associated with TOKEN.  SECRET
   is just a cross-check.  This is the OpenPGP version.  The returned
   handle must be released using keybox_release.  */
KEYBOX_HANDLE
keybox_new_openpgp (void *token, int secret)
{
  KB_NAME resource = token;

  return do_keybox_new (resource, secret, 1);
}

/* Create a new handle for the resource associated with TOKEN.  SECRET
   is just a cross-check.  This is the X.509 version.  The returned
   handle must be released using keybox_release.  */
KEYBOX_HANDLE
keybox_new_x509 (void *token, int secret)
{
  KB_NAME resource = token;

  return do_keybox_new (resource, secret, 0);
}


void
keybox_release (KEYBOX_HANDLE hd)
{
  if (!hd)
    return;
  if (hd->kb->handle_table)
    {
      int idx;
      for (idx=0; idx < hd->kb->handle_table_size; idx++)
        if (hd->kb->handle_table[idx] == hd)
          hd->kb->handle_table[idx] = NULL;
    }
  _keybox_release_blob (hd->found.blob);
  _keybox_release_blob (hd->saved_found.blob);
  if (hd->fp)
    {
      es_fclose (hd->fp);
      hd->fp = NULL;
    }
  xfree (hd->word_match.name);
  xfree (hd->word_match.pattern);
  xfree (hd);
}


/* Save the current found state in HD for later retrieval by
   keybox_restore_found_state.  Only one state may be saved.  */
void
keybox_push_found_state (KEYBOX_HANDLE hd)
{
  if (hd->saved_found.blob)
    {
      _keybox_release_blob (hd->saved_found.blob);
      hd->saved_found.blob = NULL;
    }
  hd->saved_found = hd->found;
  hd->found.blob = NULL;
}


/* Restore the saved found state in HD.  */
void
keybox_pop_found_state (KEYBOX_HANDLE hd)
{
  if (hd->found.blob)
    {
      _keybox_release_blob (hd->found.blob);
      hd->found.blob = NULL;
    }
  hd->found = hd->saved_found;
  hd->saved_found.blob = NULL;
}


const char *
keybox_get_resource_name (KEYBOX_HANDLE hd)
{
  if (!hd || !hd->kb)
    return NULL;
  return hd->kb->fname;
}

int
keybox_set_ephemeral (KEYBOX_HANDLE hd, int yes)
{
  if (!hd)
    return gpg_error (GPG_ERR_INV_HANDLE);
  hd->ephemeral = yes;
  return 0;
}


/* Close the file of the resource identified by HD.  For consistent
   results this function closes the files of all handles pointing to
   the resource identified by HD.  */
void
_keybox_close_file (KEYBOX_HANDLE hd)
{
  int idx;
  KEYBOX_HANDLE roverhd;

  if (!hd || !hd->kb || !hd->kb->handle_table)
    return;

  for (idx=0; idx < hd->kb->handle_table_size; idx++)
    if ((roverhd = hd->kb->handle_table[idx]))
      {
        if (roverhd->fp)
          {
            es_fclose (roverhd->fp);
            roverhd->fp = NULL;
          }
      }
  log_assert (!hd->fp);
}


/* Close all the files associated with the resource identified by TOKEN.  */
void
keybox_close_all_files (void *token)
{
  KB_NAME resource = token;
  KEYBOX_HANDLE roverhd;
  int idx;

  if (!resource)
    return;

  for (idx=0; idx < resource->handle_table_size; idx++)
    if ((roverhd = resource->handle_table[idx]) && roverhd->fp)
      {
        es_fclose (roverhd->fp);
        roverhd->fp = NULL;
      }
}


/*
 * Lock the keybox at handle HD, or unlock if YES is false.
 * Lock the keybox at handle HD, or unlock if YES is false.  TIMEOUT
 * is the value used for dotlock_take.  In general -1 should be used
 * when taking a lock; use 0 when releasing a lock.
 */
gpg_error_t
keybox_lock (KEYBOX_HANDLE hd, int yes, long timeout)
{
  gpg_error_t err = 0;
  KB_NAME kb = hd->kb;

  if (!keybox_is_writable (kb))
    return 0;

  /* Make sure the lock handle has been created.  */
  if (!kb->lockhd)
    {
      kb->lockhd = dotlock_create (kb->fname, 0);
      if (!kb->lockhd)
        {
          err = gpg_error_from_syserror ();
          log_info ("can't allocate lock for '%s'\n", kb->fname );
          return err;
        }
    }

  if (yes) /* Take the lock.  */
    {
      if (!kb->is_locked)
        {
#ifdef HAVE_W32_SYSTEM
          /* Under Windows we need to close the file before we try
           * to lock it.  This is because another process might have
           * taken the lock and is using keybox_file_rename to
           * rename the base file.  Now if our dotlock_take below is
           * waiting for the lock but we have the base file still
           * open, keybox_file_rename will never succeed as we are
           * in a deadlock.  */
          _keybox_close_file (hd);
#endif /*HAVE_W32_SYSTEM*/
          if (dotlock_take (kb->lockhd, timeout))
            {
              err = gpg_error_from_syserror ();
              if (!timeout && gpg_err_code (err) == GPG_ERR_EACCES)
                ; /* No diagnostic if we only tried to lock.  */
              else
                log_info ("can't lock '%s'\n", kb->fname );
            }
          else
            kb->is_locked = 1;
        }
    }
  else /* Release the lock.  */
    {
      if (kb->is_locked)
        {
          if (dotlock_release (kb->lockhd))
            {
              err = gpg_error_from_syserror ();
              log_info ("can't unlock '%s'\n", kb->fname );
            }
          else
            kb->is_locked = 0;
        }
   }

  return err;
}
