/* keybox-init.c - Initalization of the library 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "keybox-defs.h"

/* 
 * Register a filename for plain keybox files.  Returns a pointer to
 * be used to create a handles etc or NULL to indicate that it has
 * already been registered */
void *
keybox_register_file (const char *fname, int secret)
{
  return NULL;
#if 0
    KB_NAME kr;

    if (active_handles)
        BUG (); /* We don't allow that */

    for (kr=kb_names; kr; kr = kr->next) {
        if ( !compare_filenames (kr->fname, fname) )
            return NULL; /* already registered */
    }

    kr = m_alloc (sizeof *kr + strlen (fname));
    strcpy (kr->fname, fname);
    kr->secret = !!secret;
    kr->lockhd = NULL;
    kr->is_locked = 0;
    kr->did_full_scan = 0;
    /* keep a list of all issued pointers */
    kr->next = kb_names;
    kb_names = kr;

    /* create the offset table the first time a function here is used */
    if (!kb_offtbl)
      kb_offtbl = new_offset_hash_table ();

    return kr;
#endif
}

int
keybox_is_writable (void *token)
{
  KB_NAME r = token;

  return r? !access (r->fname, W_OK) : 0;
}
    
