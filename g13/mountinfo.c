/* mountinfo.c - Track infos about mounts
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#include "g13.h"
#include "../common/i18n.h"
#include "mountinfo.h"

#include "keyblob.h"
#include "g13tuple.h"



/* The object to keep track of mount information.  */
struct mounttable_s
{
  int in_use;        /* The slot is in use.  */
  char *container;   /* Name of the container.  */
  char *mountpoint;  /* Name of the mounttype.  */
  int conttype;      /* Type of the container.  */
  unsigned int rid;  /* Identifier of the runner task.  */
  struct {
    unsigned int remove:1;  /* True if the mountpoint shall be removed
                               on umount.  */
  } flags;
};


/* The allocated table of mounts and its size.  */
static mtab_t mounttable;
size_t mounttable_size;



/* Add CONTAINER,MOUNTPOINT,CONTTYPE,RID to the mounttable.  */
gpg_error_t
mountinfo_add_mount (const char *container, const char *mountpoint,
                     int conttype, unsigned int rid, int remove_flag)
{
  size_t idx;
  mtab_t m;

  for (idx=0; idx < mounttable_size; idx++)
    if (!mounttable[idx].in_use)
      break;
  if (!(idx < mounttable_size))
    {
      size_t nslots = mounttable_size;

      mounttable_size += 10;
      m = xtrycalloc (mounttable_size, sizeof *mounttable);
      if (!m)
        return gpg_error_from_syserror ();
      if (mounttable)
        {
          for (idx=0; idx < nslots; idx++)
            m[idx] = mounttable[idx];
          xfree (mounttable);
        }
      mounttable = m;
      m = mounttable + nslots;
      assert (!m->in_use);
    }
  else
    m = mounttable + idx;

  m->container = xtrystrdup (container);
  if (!m->container)
    return gpg_error_from_syserror ();
  m->mountpoint = xtrystrdup (mountpoint);
  if (!m->mountpoint)
    {
      xfree (m->container);
      m->container = NULL;
      return gpg_error_from_syserror ();
    }
  m->conttype = conttype;
  m->rid = rid;
  m->flags.remove = !!remove_flag;
  m->in_use = 1;

  return 0;
}


/* Remove a mount info.  Either the CONTAINER, the MOUNTPOINT or the
   RID must be given.  The first argument given is used.  */
gpg_error_t
mountinfo_del_mount (const char *container, const char *mountpoint,
                     unsigned int rid)
{
  gpg_error_t err;
  size_t idx;
  mtab_t m;

  /* If a container or mountpint is givem search the RID via the
     standard find function.  */
  if (container || mountpoint)
    {
      err = mountinfo_find_mount (container, mountpoint, &rid);
      if (err)
        return err;
    }

  /* Find via RID and delete. */
  for (idx=0, m = mounttable; idx < mounttable_size; idx++, m++)
    if (m->in_use && m->rid == rid)
      {
        if (m->flags.remove && m->mountpoint)
          {
            /* FIXME: This does not always work because the umount may
               not have completed yet.  We should add the mountpoints
               to an idle queue and retry a remove.  */
            if (rmdir (m->mountpoint))
              log_error ("error removing mount point '%s': %s\n",
                         m->mountpoint,
                         gpg_strerror (gpg_error_from_syserror ()));
          }
        m->in_use = 0;
        xfree (m->container);
        m->container = NULL;
        xfree (m->mountpoint);
        m->mountpoint = NULL;
        return 0;
      }
  return gpg_error (GPG_ERR_NOT_FOUND);
}


/* Find a mount and return its rid at R_RID.  If CONTAINER is given,
   the search is done by the container name, if it is not given the
   search is done by MOUNTPOINT.  */
gpg_error_t
mountinfo_find_mount (const char *container, const char *mountpoint,
                      unsigned int *r_rid)
{
  size_t idx;
  mtab_t m;

  if (container)
    {
      for (idx=0, m = mounttable; idx < mounttable_size; idx++, m++)
        if (m->in_use && !strcmp (m->container, container))
          break;
    }
  else if (mountpoint)
    {
      for (idx=0, m = mounttable; idx < mounttable_size; idx++, m++)
        if (m->in_use && !strcmp (m->mountpoint, mountpoint))
          break;
    }
  else
    idx = mounttable_size;
  if (!(idx < mounttable_size))
    return gpg_error (GPG_ERR_NOT_FOUND);

  *r_rid = m->rid;
  return 0;
}


/* Dump all info to the log stream.  */
void
mountinfo_dump_all (void)
{
  size_t idx;
  mtab_t m;

  for (idx=0, m = mounttable; idx < mounttable_size; idx++, m++)
    if (m->in_use)
      log_info ("mtab[%d] %s on %s type %d rid %u%s\n",
                (int)idx, m->container, m->mountpoint, m->conttype, m->rid,
                m->flags.remove?" [remove]":"");
}
