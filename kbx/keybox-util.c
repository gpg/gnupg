/* keybox-util.c - Utility functions for Keybox
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
#ifdef  HAVE_DOSISH_SYSTEM
# define WIN32_LEAN_AND_MEAN  /* We only need the OS core stuff.  */
# include <windows.h>
#endif

#include "keybox-defs.h"
#include "../common/utilproto.h"


static void *(*alloc_func)(size_t n) = malloc;
static void *(*realloc_func)(void *p, size_t n) = realloc;
static void (*free_func)(void*) = free;



void
keybox_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                          void *(*new_realloc_func)(void *p, size_t n),
                          void (*new_free_func)(void*) )
{
  alloc_func	    = new_alloc_func;
  realloc_func      = new_realloc_func;
  free_func	    = new_free_func;
}

void *
_keybox_malloc (size_t n)
{
  return alloc_func (n);
}

void *
_keybox_realloc (void *a, size_t n)
{
  return realloc_func (a, n);
}

void *
_keybox_calloc (size_t n, size_t m)
{
  void *p = _keybox_malloc (n*m);
  if (p)
    memset (p, 0, n* m);
  return p;
}

void
_keybox_free (void *p)
{
  if (p)
    free_func (p);
}


/* Store the two malloced temporary file names used for keybox updates
   of file FILENAME at R_BAKNAME and R_TMPNAME.  On error an error
   code is returned and NULL stored at R_BAKNAME and R_TMPNAME.  If
   FOR_KEYRING is true the returned names match those used by GnuPG's
   keyring code.  */
gpg_error_t
keybox_tmp_names (const char *filename, int for_keyring,
                  char **r_bakname, char **r_tmpname)
{
  gpg_error_t err;
  char *bak_name, *tmp_name;

  *r_bakname = NULL;
  *r_tmpname = NULL;

# ifdef USE_ONLY_8DOT3
  /* Here is another Windoze bug?:
   * you can't rename("pubring.kbx.tmp", "pubring.kbx");
   * but	rename("pubring.kbx.tmp", "pubring.aaa");
   * works.  So we replace ".kbx" by ".kb_" or ".k__".  Note that we
   * can't use ".bak" and ".tmp", because these suffixes are used by
   * gpg's keyrings and would lead to a sharing violation or data
   * corruption.  If the name does not end in ".kbx" we assume working
   * on a modern file system and append the suffix.  */
  {
    const char *ext   = for_keyring? EXTSEP_S GPGEXT_GPG : EXTSEP_S "kbx";
    const char *b_ext = for_keyring? EXTSEP_S "bak"      : EXTSEP_S "kb_";
    const char *t_ext = for_keyring? EXTSEP_S "tmp"      : EXTSEP_S "k__";
    int repl;

    if (strlen (ext) != 4 || strlen (b_ext) != 4)
      BUG ();
    repl = (strlen (filename) > 4
            && !strcmp (filename + strlen (filename) - 4, ext));
    bak_name = xtrymalloc (strlen (filename) + (repl?0:4) + 1);
    if (!bak_name)
      return gpg_error_from_syserror ();
    strcpy (bak_name, filename);
    strcpy (bak_name + strlen (filename) - (repl?4:0), b_ext);

    tmp_name = xtrymalloc (strlen (filename) + (repl?0:4) + 1);
    if (!tmp_name)
      {
        err = gpg_error_from_syserror ();
        xfree (bak_name);
        return err;
      }
    strcpy (tmp_name, filename);
    strcpy (tmp_name + strlen (filename) - (repl?4:0), t_ext);
  }
# else /* Posix file names */
  (void)for_keyring;
  bak_name = xtrymalloc (strlen (filename) + 2);
  if (!bak_name)
    return gpg_error_from_syserror ();
  strcpy (stpcpy (bak_name, filename), "~");

  tmp_name = xtrymalloc (strlen (filename) + 5);
  if (!tmp_name)
    {
      err = gpg_error_from_syserror ();
      xfree (bak_name);
      return err;
    }
  strcpy (stpcpy (tmp_name,filename), EXTSEP_S "tmp");
# endif /* Posix filename */

  *r_bakname = bak_name;
  *r_tmpname = tmp_name;
  return 0;
}

gpg_error_t
keybox_file_rename (const char *oldname, const char *newname,
                    int *block_signals)
{
  return gnupg_rename_file (oldname, newname, block_signals);
}
