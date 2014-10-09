/* keybox-init.c - Initalization of the library
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "../common/mischelp.h"
#include "keybox-defs.h"

static KB_NAME kb_names;


/* Register a filename for plain keybox files.  Returns a pointer to
   be used to create a handles and so on.  Returns NULL to indicate
   that FNAME has already been registered.  */
void *
keybox_register_file (const char *fname, int secret)
{
  KB_NAME kr;

  for (kr=kb_names; kr; kr = kr->next)
    {
      if (same_file_p (kr->fname, fname) )
        return NULL; /* Already registered. */
    }

  kr = xtrymalloc (sizeof *kr + strlen (fname));
  if (!kr)
    return NULL;
  strcpy (kr->fname, fname);
  kr->secret = !!secret;

  kr->handle_table = NULL;
  kr->handle_table_size = 0;

  /* kr->lockhd = NULL;*/
  kr->is_locked = 0;
  kr->did_full_scan = 0;
  /* keep a list of all issued pointers */
  kr->next = kb_names;
  kb_names = kr;

  /* create the offset table the first time a function here is used */
/*      if (!kb_offtbl) */
/*        kb_offtbl = new_offset_hash_table (); */

  return kr;
}

int
keybox_is_writable (void *token)
{
  KB_NAME r = token;

  return r? !access (r->fname, W_OK) : 0;
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
      fclose (hd->fp);
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
   results this fucntion closes the files of all handles pointing to
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
            fclose (roverhd->fp);
            roverhd->fp = NULL;
          }
      }
  assert (!hd->fp);
}


/*
 * Lock the keybox at handle HD, or unlock if YES is false.  Note that
 * we currently ignore the handle and lock all registered keyboxes.
 */
int
keybox_lock (KEYBOX_HANDLE hd, int yes)
{
  /* FIXME: We need to implement it before we can use it with gpg.
     gpgsm does the locking in its local keydb.c driver; this should
     be changed as well.  */

  (void)hd;
  (void)yes;
  return 0;
}
