/* keydb.c - key database dispatcher
 * Copyright (C) 2001-2013 Free Software Foundation, Inc.
 * Coyrright (C) 2001-2015 Werner Koch
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gpg.h"
#include "util.h"
#include "options.h"
#include "main.h" /*try_make_homedir ()*/
#include "packet.h"
#include "keyring.h"
#include "../kbx/keybox.h"
#include "keydb.h"
#include "i18n.h"

static int active_handles;

typedef enum
  {
    KEYDB_RESOURCE_TYPE_NONE = 0,
    KEYDB_RESOURCE_TYPE_KEYRING,
    KEYDB_RESOURCE_TYPE_KEYBOX
  } KeydbResourceType;
#define MAX_KEYDB_RESOURCES 40

struct resource_item
{
  KeydbResourceType type;
  union {
    KEYRING_HANDLE kr;
    KEYBOX_HANDLE kb;
  } u;
  void *token;
};

static struct resource_item all_resources[MAX_KEYDB_RESOURCES];
static int used_resources;
static void *primary_keyring=NULL;

struct keydb_handle
{
  int locked;
  int found;
  int saved_found;
  unsigned long skipped_long_blobs;
  int no_caching;
  int current;
  int used;   /* Number of items in ACTIVE. */
  struct resource_item active[MAX_KEYDB_RESOURCES];
};


/* This object is used to keep a list of keyids in a linked list.  */
typedef struct kid_list_s
{
  struct kid_list_s *next;
  u32 kid[2];
  int state;  /* True if found.  */
} *kid_list_t;

/* To avoid looking up a key by keyid where we know that it does not
   yet exist, we keep a table of keyids with search results.  This
   improves the --list-sigs and --check-sigs commands substantively.
   To avoid extra complexity we clear the entire table on any insert
   or update operation.  The array is indexed by the LSB of the keyid.
   KID_FOUND_TABLE_COUNT gives the number of keys in the table.  */
static kid_list_t kid_found_table[256];
static unsigned int kid_found_table_count;


/* This is a simple cache used to return the last result of a
   successful fingerprint search.  This works only for keybox resources
   because (due to lack of a copy_keyblock function) we need to store
   an image of the keyblock which is fortunately instantly available
   for keyboxes.  */
enum keyblock_cache_states {
  KEYBLOCK_CACHE_EMPTY,
  KEYBLOCK_CACHE_PREPARED,
  KEYBLOCK_CACHE_FILLED
};

struct {
  enum keyblock_cache_states state;
  byte fpr[MAX_FINGERPRINT_LEN];
  iobuf_t iobuf; /* Image of the keyblock.  */
  u32 *sigstatus;
  int pk_no;
  int uid_no;
} keyblock_cache;


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);


/* Checkwhether the keyid KID is in the table of found or not found
   keyids.

   Returns:
     0 - Keyid not in table
     1 - Keyid in table because not found in a previous search
     2 - Keyid in table because found in a previous search
 */
static int
kid_not_found_p (u32 *kid)
{
  kid_list_t k;

  for (k = kid_found_table[kid[0] % 256]; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      {
        if (DBG_CACHE)
          log_debug ("keydb: kid_not_found_p (%08lx%08lx) => %s\n",
                     (ulong)kid[0], (ulong)kid[1],
                     k->state? "false (found)": "true");
        return k->state? 2 : 1;
      }

  if (DBG_CACHE)
    log_debug ("keydb: kid_not_found_p (%08lx%08lx) => false\n",
               (ulong)kid[0], (ulong)kid[1]);
  return 0;
}


/* Put the keyid KID into the table of keyids with their find states of
   previous searches.  Note that there is no check whether the keyid
   is already in the table, thus kid_not_found_p() should be used prior.  */
static void
kid_not_found_insert (u32 *kid, int found)
{
  kid_list_t k;

  if (DBG_CACHE)
    log_debug ("keydb: kid_not_found_insert (%08lx%08lx, %d)\n",
               (ulong)kid[0], (ulong)kid[1], found);
  k = xmalloc (sizeof *k);
  k->kid[0] = kid[0];
  k->kid[1] = kid[1];
  k->state = found;
  k->next = kid_found_table[kid[0]%256];
  kid_found_table[kid[0]%256] = k;
  kid_found_table_count++;
}


/* Flush the entire table of keyids whche were not found in previous
   searches.  */
static void
kid_not_found_flush (void)
{
  kid_list_t k, knext;
  int i;

  if (DBG_CACHE)
    log_debug ("keydb: kid_not_found_flush\n");

  if (!kid_found_table_count)
    return;

  for (i=0; i < DIM(kid_found_table); i++)
    {
      for (k = kid_found_table[i]; k; k = knext)
        {
          knext = k->next;
          xfree (k);
        }
      kid_found_table[i] = NULL;
    }
  kid_found_table_count = 0;
}


static void
keyblock_cache_clear (void)
{
  keyblock_cache.state = KEYBLOCK_CACHE_EMPTY;
  xfree (keyblock_cache.sigstatus);
  keyblock_cache.sigstatus = NULL;
  iobuf_close (keyblock_cache.iobuf);
  keyblock_cache.iobuf = NULL;
}


/* Handle the creation of a keyring or a keybox if it does not yet
   exist.  Take into account that other processes might have the
   keyring/keybox already locked.  This lock check does not work if
   the directory itself is not yet available.  If is IS_BOX is true
   the filename is expected to be a keybox.  If FORCE_CREATE is true
   the keyring or keybox shall be created.  */
static int
maybe_create_keyring_or_box (char *filename, int is_box, int force_create)
{
  dotlock_t lockhd = NULL;
  IOBUF iobuf;
  int rc;
  mode_t oldmask;
  char *last_slash_in_filename;
  int save_slash;

  /* A quick test whether the filename already exists. */
  if (!access (filename, F_OK))
    return 0;

  /* If we don't want to create a new file at all, there is no need to
     go any further - bail out right here.  */
  if (!force_create)
    return gpg_error (GPG_ERR_ENOENT);

  /* First of all we try to create the home directory.  Note, that we
     don't do any locking here because any sane application of gpg
     would create the home directory by itself and not rely on gpg's
     tricky auto-creation which is anyway only done for certain home
     directory name pattern. */
  last_slash_in_filename = strrchr (filename, DIRSEP_C);
#if HAVE_W32_SYSTEM
  {
    /* Windows may either have a slash or a backslash.  Take care of it.  */
    char *p = strrchr (filename, '/');
    if (!last_slash_in_filename || p > last_slash_in_filename)
      last_slash_in_filename = p;
  }
#endif /*HAVE_W32_SYSTEM*/
  if (!last_slash_in_filename)
    return gpg_error (GPG_ERR_ENOENT);  /* No slash at all - should
                                           not happen though.  */
  save_slash = *last_slash_in_filename;
  *last_slash_in_filename = 0;
  if (access(filename, F_OK))
    {
      static int tried;

      if (!tried)
        {
          tried = 1;
          try_make_homedir (filename);
        }
      if (access (filename, F_OK))
        {
          rc = gpg_error_from_syserror ();
          *last_slash_in_filename = save_slash;
          goto leave;
        }
    }
  *last_slash_in_filename = save_slash;

  /* To avoid races with other instances of gpg trying to create or
     update the keyring (it is removed during an update for a short
     time), we do the next stuff in a locked state. */
  lockhd = dotlock_create (filename, 0);
  if (!lockhd)
    {
      rc = gpg_error_from_syserror ();
      /* A reason for this to fail is that the directory is not
         writable. However, this whole locking stuff does not make
         sense if this is the case. An empty non-writable directory
         with no keyring is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for '%s': %s\n",
                  filename, gpg_strerror (rc));

      if (!force_create)
        return gpg_error (GPG_ERR_ENOENT);  /* Won't happen.  */
      else
        return rc;
    }

  if ( dotlock_take (lockhd, -1) )
    {
      rc = gpg_error_from_syserror ();
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock '%s': %s\n", filename, gpg_strerror (rc));
      goto leave;
    }

  /* Now the real test while we are locked. */
  if (!access (filename, F_OK))
    {
      rc = 0;  /* Okay, we may access the file now.  */
      goto leave;
    }

  /* The file does not yet exist, create it now. */
  oldmask = umask (077);
  if (is_secured_filename (filename))
    {
      iobuf = NULL;
      gpg_err_set_errno (EPERM);
    }
  else
    iobuf = iobuf_create (filename, 0);
  umask (oldmask);
  if (!iobuf)
    {
      rc = gpg_error_from_syserror ();
      if (is_box)
        log_error (_("error creating keybox '%s': %s\n"),
                   filename, gpg_strerror (rc));
      else
        log_error (_("error creating keyring '%s': %s\n"),
                   filename, gpg_strerror (rc));
      goto leave;
    }

  iobuf_close (iobuf);
  /* Must invalidate that ugly cache */
  iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, filename);

  /* Make sure that at least one record is in a new keybox file, so
     that the detection magic will work the next time it is used.  */
  if (is_box)
    {
      FILE *fp = fopen (filename, "w");
      if (!fp)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = _keybox_write_header_blob (fp, 1);
          fclose (fp);
        }
      if (rc)
        {
          if (is_box)
            log_error (_("error creating keybox '%s': %s\n"),
                       filename, gpg_strerror (rc));
          else
            log_error (_("error creating keyring '%s': %s\n"),
                       filename, gpg_strerror (rc));
          goto leave;
        }
    }

  if (!opt.quiet)
    {
      if (is_box)
        log_info (_("keybox '%s' created\n"), filename);
      else
        log_info (_("keyring '%s' created\n"), filename);
    }

  rc = 0;

 leave:
  if (lockhd)
    {
      dotlock_release (lockhd);
      dotlock_destroy (lockhd);
    }
  return rc;
}


/* Helper for keydb_add_resource.  Opens FILENAME to figures out the
   resource type.  Returns the resource type and a flag at R_NOTFOUND
   indicating whether FILENAME could be opened at all.  If the openpgp
   flag is set in a keybox header, R_OPENPGP will be set to true.  */
static KeydbResourceType
rt_from_file (const char *filename, int *r_found, int *r_openpgp)
{
  u32 magic;
  unsigned char verbuf[4];
  FILE *fp;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;

  *r_found = *r_openpgp = 0;
  fp = fopen (filename, "rb");
  if (fp)
    {
      *r_found = 1;

      if (fread (&magic, 4, 1, fp) == 1 )
        {
          if (magic == 0x13579ace || magic == 0xce9a5713)
            ; /* GDBM magic - not anymore supported. */
          else if (fread (&verbuf, 4, 1, fp) == 1
                   && verbuf[0] == 1
                   && fread (&magic, 4, 1, fp) == 1
                   && !memcmp (&magic, "KBXf", 4))
            {
              if ((verbuf[3] & 0x02))
                *r_openpgp = 1;
              rt = KEYDB_RESOURCE_TYPE_KEYBOX;
            }
          else
            rt = KEYDB_RESOURCE_TYPE_KEYRING;
        }
      else /* Maybe empty: assume keyring. */
        rt = KEYDB_RESOURCE_TYPE_KEYRING;

      fclose (fp);
    }

  return rt;
}


/*
 * Register a resource (keyring or aeybox).  The first keyring or
 * keybox which is added by this function is created if it does not
 * exist.  FLAGS are a combination of the KEYDB_RESOURCE_FLAG_
 * constants as defined in keydb.h.
 */
gpg_error_t
keydb_add_resource (const char *url, unsigned int flags)
{
  static int any_registered;
  const char *resname = url;
  char *filename = NULL;
  int create;
  int read_only = !!(flags&KEYDB_RESOURCE_FLAG_READONLY);
  int is_default = !!(flags&KEYDB_RESOURCE_FLAG_DEFAULT);
  int rc = 0;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;
  void *token;

  /* Create the resource if it is the first registered one.  */
  create = (!read_only && !any_registered);

  /* Do we have an URL?
   *	gnupg-ring:filename  := this is a plain keyring.
   *	gnupg-kbx:filename   := this is a keybox file.
   *	filename := See what is is, but create as plain keyring.
   */
  if (strlen (resname) > 11 && !strncmp( resname, "gnupg-ring:", 11) )
    {
      rt = KEYDB_RESOURCE_TYPE_KEYRING;
      resname += 11;
    }
  else if (strlen (resname) > 10 && !strncmp (resname, "gnupg-kbx:", 10) )
    {
      rt = KEYDB_RESOURCE_TYPE_KEYBOX;
      resname += 10;
    }
#if !defined(HAVE_DRIVE_LETTERS) && !defined(__riscos__)
  else if (strchr (resname, ':'))
    {
      log_error ("invalid key resource URL '%s'\n", url );
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
#endif /* !HAVE_DRIVE_LETTERS && !__riscos__ */

  if (*resname != DIRSEP_C
#ifdef HAVE_W32_SYSTEM
      && *resname != '/'  /* Fixme: does not handle drive letters.  */
#endif
        )
    {
      /* Do tilde expansion etc. */
      if (strchr (resname, DIRSEP_C)
#ifdef HAVE_W32_SYSTEM
          || strchr (resname, '/')  /* Windows also accepts this.  */
#endif
          )
        filename = make_filename (resname, NULL);
      else
        filename = make_filename (opt.homedir, resname, NULL);
    }
  else
    filename = xstrdup (resname);

  /* See whether we can determine the filetype.  */
  if (rt == KEYDB_RESOURCE_TYPE_NONE)
    {
      int found, openpgp_flag;
      int pass = 0;
      size_t filenamelen;

    check_again:
      filenamelen = strlen (filename);
      rt = rt_from_file (filename, &found, &openpgp_flag);
      if (found)
        {
          /* The file exists and we have the resource type in RT.

             Now let us check whether in addition to the "pubring.gpg"
             a "pubring.kbx with openpgp keys exists.  This is so that
             GPG 2.1 will use an existing "pubring.kbx" by default iff
             that file has been created or used by 2.1.  This check is
             needed because after creation or use of the kbx file with
             2.1 an older version of gpg may have created a new
             pubring.gpg for its own use.  */
          if (!pass && is_default && rt == KEYDB_RESOURCE_TYPE_KEYRING
              && filenamelen > 4 && !strcmp (filename+filenamelen-4, ".gpg"))
            {
              strcpy (filename+filenamelen-4, ".kbx");
              if ((rt_from_file (filename, &found, &openpgp_flag)
                   == KEYDB_RESOURCE_TYPE_KEYBOX) && found && openpgp_flag)
                rt = KEYDB_RESOURCE_TYPE_KEYBOX;
              else /* Restore filename */
                strcpy (filename+filenamelen-4, ".gpg");
            }
	}
      else if (!pass
               && is_default && create
               && filenamelen > 4 && !strcmp (filename+filenamelen-4, ".gpg"))
        {
          /* The file does not exist, the default resource has been
             requested, the file shall be created, and the file has a
             ".gpg" suffix.  Change the suffix to ".kbx" and try once
             more.  This way we achieve that we open an existing
             ".gpg" keyring, but create a new keybox file with an
             ".kbx" suffix.  */
          strcpy (filename+filenamelen-4, ".kbx");
          pass++;
          goto check_again;
        }
      else /* No file yet: create keybox. */
        rt = KEYDB_RESOURCE_TYPE_KEYBOX;
    }

  switch (rt)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      log_error ("unknown type of key resource '%s'\n", url );
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;

    case KEYDB_RESOURCE_TYPE_KEYRING:
      rc = maybe_create_keyring_or_box (filename, 0, create);
      if (rc)
        goto leave;

      if (keyring_register_filename (filename, read_only, &token))
        {
          if (used_resources >= MAX_KEYDB_RESOURCES)
            rc = gpg_error (GPG_ERR_RESOURCE_LIMIT);
          else
            {
              if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY))
                primary_keyring = token;
              all_resources[used_resources].type = rt;
              all_resources[used_resources].u.kr = NULL; /* Not used here */
              all_resources[used_resources].token = token;
              used_resources++;
            }
        }
      else
        {
          /* This keyring was already registered, so ignore it.
             However, we can still mark it as primary even if it was
             already registered.  */
          if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY))
            primary_keyring = token;
        }
      break;

    case KEYDB_RESOURCE_TYPE_KEYBOX:
      {
        rc = maybe_create_keyring_or_box (filename, 1, create);
        if (rc)
          goto leave;

        /* FIXME: How do we register a read-only keybox?  */
        token = keybox_register_file (filename, 0);
        if (token)
          {
            if (used_resources >= MAX_KEYDB_RESOURCES)
              rc = gpg_error (GPG_ERR_RESOURCE_LIMIT);
            else
              {
                /* if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY)) */
                /*   primary_keyring = token; */
                all_resources[used_resources].type = rt;
                all_resources[used_resources].u.kb = NULL; /* Not used here */
                all_resources[used_resources].token = token;

                /* FIXME: Do a compress run if needed and no other
                   user is currently using the keybox. */

                used_resources++;
              }
          }
        else
          {
            /* Already registered.  We will mark it as the primary key
               if requested.  */
            /* FIXME: How to do that?  Change the keybox interface?  */
            /* if ((flags & KEYDB_RESOURCE_FLAG_PRIMARY)) */
            /*   primary_keyring = token; */
          }
      }
      break;

      default:
	log_error ("resource type of '%s' not supported\n", url);
	rc = gpg_error (GPG_ERR_GENERAL);
	goto leave;
    }

  /* fixme: check directory permissions and print a warning */

 leave:
  if (rc)
    log_error (_("keyblock resource '%s': %s\n"), filename, gpg_strerror (rc));
  else
    any_registered = 1;
  xfree (filename);
  return rc;
}


void
keydb_dump_stats (void)
{
  if (kid_found_table_count)
    log_info ("keydb: kid_not_found_table: total: %u\n", kid_found_table_count);
}


KEYDB_HANDLE
keydb_new (void)
{
  KEYDB_HANDLE hd;
  int i, j;

  if (DBG_CLOCK)
    log_clock ("keydb_new");

  hd = xmalloc_clear (sizeof *hd);
  hd->found = -1;
  hd->saved_found = -1;

  assert (used_resources <= MAX_KEYDB_RESOURCES);
  for (i=j=0; i < used_resources; i++)
    {
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].u.kr = keyring_new (all_resources[i].token);
          if (!hd->active[j].u.kr) {
            xfree (hd);
            return NULL; /* fixme: release all previously allocated handles*/
          }
          j++;
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].u.kb   = keybox_new_openpgp (all_resources[i].token, 0);
          if (!hd->active[j].u.kb)
            {
              xfree (hd);
              return NULL; /* fixme: release all previously allocated handles*/
            }
          j++;
          break;
        }
    }
  hd->used = j;

  active_handles++;
  return hd;
}


void
keydb_release (KEYDB_HANDLE hd)
{
  int i;

  if (!hd)
    return;
  assert (active_handles > 0);
  active_handles--;

  unlock_all (hd);
  for (i=0; i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          keyring_release (hd->active[i].u.kr);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_release (hd->active[i].u.kb);
          break;
        }
    }

  xfree (hd);
}


/* Set a flag on handle to not use cached results.  This is required
   for updating a keyring and for key listins.  Fixme: Using a new
   parameter for keydb_new might be a better solution.  */
void
keydb_disable_caching (KEYDB_HANDLE hd)
{
  if (hd)
    hd->no_caching = 1;
}


/*
 * Return the name of the current resource.  This is function first
 * looks for the last found found, then for the current search
 * position, and last returns the first available resource.  The
 * returned string is only valid as long as the handle exists.  This
 * function does only return NULL if no handle is specified, in all
 * other error cases an empty string is returned.
 */
const char *
keydb_get_resource_name (KEYDB_HANDLE hd)
{
  int idx;
  const char *s = NULL;

  if (!hd)
    return NULL;

  if ( hd->found >= 0 && hd->found < hd->used)
    idx = hd->found;
  else if ( hd->current >= 0 && hd->current < hd->used)
    idx = hd->current;
  else
    idx = 0;

  switch (hd->active[idx].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      s = NULL;
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      s = keyring_get_resource_name (hd->active[idx].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      s = keybox_get_resource_name (hd->active[idx].u.kb);
      break;
    }

  return s? s: "";
}



static int
lock_all (KEYDB_HANDLE hd)
{
  int i, rc = 0;

  /* Fixme: This locking scheme may lead to a deadlock if the resources
     are not added in the same order by all processes.  We are
     currently only allowing one resource so it is not a problem.
     [Oops: Who claimed the latter]

     To fix this we need to use a lock file to protect lock_all.  */

  for (i=0; !rc && i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_lock (hd->active[i].u.kr, 1);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_lock (hd->active[i].u.kb, 1);
          break;
        }
    }

  if (rc)
    {
      /* Revert the already taken locks.  */
      for (i--; i >= 0; i--)
        {
          switch (hd->active[i].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYRING:
              keyring_lock (hd->active[i].u.kr, 0);
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              rc = keybox_lock (hd->active[i].u.kb, 0);
              break;
            }
        }
    }
  else
    hd->locked = 1;

  return rc;
}


static void
unlock_all (KEYDB_HANDLE hd)
{
  int i;

  if (!hd->locked)
    return;

  for (i=hd->used-1; i >= 0; i--)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          keyring_lock (hd->active[i].u.kr, 0);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_lock (hd->active[i].u.kb, 0);
          break;
        }
    }
  hd->locked = 0;
}



/* Push the last found state if any.  */
void
keydb_push_found_state (KEYDB_HANDLE hd)
{
  if (!hd)
    return;

  if (hd->found < 0 || hd->found >= hd->used)
    {
      hd->saved_found = -1;
      return;
    }

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      keyring_push_found_state (hd->active[hd->found].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      keybox_push_found_state (hd->active[hd->found].u.kb);
      break;
    }

  hd->saved_found = hd->found;
  hd->found = -1;
}


/* Pop the last found state.  */
void
keydb_pop_found_state (KEYDB_HANDLE hd)
{
  if (!hd)
    return;

  hd->found = hd->saved_found;
  hd->saved_found = -1;
  if (hd->found < 0 || hd->found >= hd->used)
    return;

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      keyring_pop_found_state (hd->active[hd->found].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      keybox_pop_found_state (hd->active[hd->found].u.kb);
      break;
    }
}



static gpg_error_t
parse_keyblock_image (iobuf_t iobuf, int pk_no, int uid_no,
                      const u32 *sigstatus, kbnode_t *r_keyblock)
{
  gpg_error_t err;
  PACKET *pkt;
  kbnode_t keyblock = NULL;
  kbnode_t node, *tail;
  int in_cert, save_mode;
  u32 n_sigs;
  int pk_count, uid_count;

  *r_keyblock = NULL;

  pkt = xtrymalloc (sizeof *pkt);
  if (!pkt)
    return gpg_error_from_syserror ();
  init_packet (pkt);
  save_mode = set_packet_list_mode (0);
  in_cert = 0;
  n_sigs = 0;
  tail = NULL;
  pk_count = uid_count = 0;
  while ((err = parse_packet (iobuf, pkt)) != -1)
    {
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_PACKET)
        {
          free_packet (pkt);
          init_packet (pkt);
          continue;
	}
      if (err)
        {
          log_error ("parse_keyblock_image: read error: %s\n",
                     gpg_strerror (err));
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }

      /* Filter allowed packets.  */
      switch (pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_KEY:
        case PKT_SECRET_SUBKEY:
        case PKT_USER_ID:
        case PKT_ATTRIBUTE:
        case PKT_SIGNATURE:
          break; /* Allowed per RFC.  */

        default:
          /* Note that can't allow ring trust packets here and some of
             the other GPG specific packets don't make sense either.  */
          log_error ("skipped packet of type %d in keybox\n",
                     (int)pkt->pkttype);
          free_packet(pkt);
          init_packet(pkt);
          continue;
        }

      /* Other sanity checks.  */
      if (!in_cert && pkt->pkttype != PKT_PUBLIC_KEY)
        {
          log_error ("parse_keyblock_image: first packet in a keybox blob "
                     "is not a public key packet\n");
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }
      if (in_cert && (pkt->pkttype == PKT_PUBLIC_KEY
                      || pkt->pkttype == PKT_SECRET_KEY))
        {
          log_error ("parse_keyblock_image: "
                     "multiple keyblocks in a keybox blob\n");
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }
      in_cert = 1;

      if (pkt->pkttype == PKT_SIGNATURE && sigstatus)
        {
          PKT_signature *sig = pkt->pkt.signature;

          n_sigs++;
          if (n_sigs > sigstatus[0])
            {
              log_error ("parse_keyblock_image: "
                         "more signatures than found in the meta data\n");
              err = gpg_error (GPG_ERR_INV_KEYRING);
              break;

            }
          if (sigstatus[n_sigs])
            {
              sig->flags.checked = 1;
              if (sigstatus[n_sigs] == 1 )
                ; /* missing key */
              else if (sigstatus[n_sigs] == 2 )
                ; /* bad signature */
              else if (sigstatus[n_sigs] < 0x10000000)
                ; /* bad flag */
              else
                {
                  sig->flags.valid = 1;
                  /* Fixme: Shall we set the expired flag here?  */
                }
            }
        }

      node = new_kbnode (pkt);

      switch (pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_KEY:
        case PKT_SECRET_SUBKEY:
          if (++pk_count == pk_no)
            node->flag |= 1;
          break;

        case PKT_USER_ID:
          if (++uid_count == uid_no)
            node->flag |= 2;
          break;

        default:
          break;
        }

      if (!keyblock)
        keyblock = node;
      else
        *tail = node;
      tail = &node->next;
      pkt = xtrymalloc (sizeof *pkt);
      if (!pkt)
        {
          err = gpg_error_from_syserror ();
          break;
        }
      init_packet (pkt);
    }
  set_packet_list_mode (save_mode);

  if (err == -1 && keyblock)
    err = 0; /* Got the entire keyblock.  */

  if (!err && sigstatus && n_sigs != sigstatus[0])
    {
      log_error ("parse_keyblock_image: signature count does not match\n");
      err = gpg_error (GPG_ERR_INV_KEYRING);
    }

  if (err)
    release_kbnode (keyblock);
  else
    *r_keyblock = keyblock;
  free_packet (pkt);
  xfree (pkt);
  return err;
}


/*
 * Return the last found keyring.  Caller must free it.
 * The returned keyblock has the kbode flag bit 0 set for the node with
 * the public key used to locate the keyblock or flag bit 1 set for
 * the user ID node.
 */
gpg_error_t
keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb)
{
  gpg_error_t err = 0;

  *ret_kb = NULL;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (DBG_CLOCK)
    log_clock ("keydb_get_keybock enter");

  if (keyblock_cache.state == KEYBLOCK_CACHE_FILLED)
    {
      iobuf_seek (keyblock_cache.iobuf, 0);
      err = parse_keyblock_image (keyblock_cache.iobuf,
                                  keyblock_cache.pk_no,
                                  keyblock_cache.uid_no,
                                  keyblock_cache.sigstatus,
                                  ret_kb);
      if (err)
        keyblock_cache_clear ();
      if (DBG_CLOCK)
        log_clock (err? "keydb_get_keyblock leave (cached, failed)"
                      : "keydb_get_keyblock leave (cached)");
      return err;
    }

  if (hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_VALUE_NOT_FOUND);

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = keyring_get_keyblock (hd->active[hd->found].u.kr, ret_kb);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      {
        iobuf_t iobuf;
        u32 *sigstatus;
        int pk_no, uid_no;

        err = keybox_get_keyblock (hd->active[hd->found].u.kb,
                                   &iobuf, &pk_no, &uid_no, &sigstatus);
        if (!err)
          {
            err = parse_keyblock_image (iobuf, pk_no, uid_no, sigstatus,
                                        ret_kb);
            if (!err && keyblock_cache.state == KEYBLOCK_CACHE_PREPARED)
              {
                keyblock_cache.state     = KEYBLOCK_CACHE_FILLED;
                keyblock_cache.sigstatus = sigstatus;
                keyblock_cache.iobuf     = iobuf;
                keyblock_cache.pk_no     = pk_no;
                keyblock_cache.uid_no    = uid_no;
              }
            else
              {
                xfree (sigstatus);
                iobuf_close (iobuf);
              }
          }
      }
      break;
    }

  if (keyblock_cache.state != KEYBLOCK_CACHE_FILLED)
    keyblock_cache_clear ();

  if (DBG_CLOCK)
    log_clock (err? "keydb_get_keyblock leave (failed)"
               : "keydb_get_keyblock leave");
  return err;
}


/* Build a keyblock image from KEYBLOCK.  Returns 0 on success and
   only then stores a new iobuf object at R_IOBUF and a signature
   status vecotor at R_SIGSTATUS.  */
static gpg_error_t
build_keyblock_image (kbnode_t keyblock, iobuf_t *r_iobuf, u32 **r_sigstatus)
{
  gpg_error_t err;
  iobuf_t iobuf;
  kbnode_t kbctx, node;
  u32 n_sigs;
  u32 *sigstatus;

  *r_iobuf = NULL;
  if (r_sigstatus)
    *r_sigstatus = NULL;

  /* Allocate a vector for the signature cache.  This is an array of
     u32 values with the first value giving the number of elements to
     follow and each element descriping the cache status of the
     signature.  */
  if (r_sigstatus)
    {
      for (kbctx=NULL, n_sigs=0; (node = walk_kbnode (keyblock, &kbctx, 0));)
        if (node->pkt->pkttype == PKT_SIGNATURE)
          n_sigs++;
      sigstatus = xtrycalloc (1+n_sigs, sizeof *sigstatus);
      if (!sigstatus)
        return gpg_error_from_syserror ();
    }
  else
    sigstatus = NULL;

  iobuf = iobuf_temp ();
  for (kbctx = NULL, n_sigs = 0; (node = walk_kbnode (keyblock, &kbctx, 0));)
    {
      /* Make sure to use only packets valid on a keyblock.  */
      switch (node->pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SIGNATURE:
        case PKT_USER_ID:
        case PKT_ATTRIBUTE:
          /* Note that we don't want the ring trust packets.  They are
             not useful. */
          break;
        default:
          continue;
        }

      err = build_packet (iobuf, node->pkt);
      if (err)
        {
          iobuf_close (iobuf);
          return err;
        }

      /* Build signature status vector.  */
      if (node->pkt->pkttype == PKT_SIGNATURE)
        {
          PKT_signature *sig = node->pkt->pkt.signature;

          n_sigs++;
          /* Fixme: Detect the "missing key" status.  */
          if (sig->flags.checked && sigstatus)
            {
              if (sig->flags.valid)
                {
                  if (!sig->expiredate)
                    sigstatus[n_sigs] = 0xffffffff;
                  else if (sig->expiredate < 0x1000000)
                    sigstatus[n_sigs] = 0x10000000;
                  else
                    sigstatus[n_sigs] = sig->expiredate;
                }
              else
                sigstatus[n_sigs] = 0x00000002; /* Bad signature.  */
            }
        }
    }
  if (sigstatus)
    sigstatus[0] = n_sigs;

  *r_iobuf = iobuf;
  if (r_sigstatus)
    *r_sigstatus = sigstatus;
  return 0;
}


/*
 * Update the current keyblock with the keyblock KB
 */
gpg_error_t
keydb_update_keyblock (KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  kid_not_found_flush ();
  keyblock_cache_clear ();

  if (hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_VALUE_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  err = lock_all (hd);
  if (err)
    return err;

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = keyring_update_keyblock (hd->active[hd->found].u.kr, kb);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      {
        iobuf_t iobuf;

        err = build_keyblock_image (kb, &iobuf, NULL);
        if (!err)
          {
            err = keybox_update_keyblock (hd->active[hd->found].u.kb,
                                          iobuf_get_temp_buffer (iobuf),
                                          iobuf_get_temp_length (iobuf));
            iobuf_close (iobuf);
          }
      }
      break;
    }

  unlock_all (hd);
  return err;
}


/*
 * Insert a new KB into one of the resources.
 */
gpg_error_t
keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;
  int idx;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  kid_not_found_flush ();
  keyblock_cache_clear ();

  if (opt.dry_run)
    return 0;

  if (hd->found >= 0 && hd->found < hd->used)
    idx = hd->found;
  else if (hd->current >= 0 && hd->current < hd->used)
    idx = hd->current;
  else
    return gpg_error (GPG_ERR_GENERAL);

  err = lock_all (hd);
  if (err)
    return err;

  switch (hd->active[idx].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      err = keyring_insert_keyblock (hd->active[idx].u.kr, kb);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      { /* We need to turn our kbnode_t list of packets into a proper
           keyblock first.  This is required by the OpenPGP key parser
           included in the keybox code.  Eventually we can change this
           kludge to have the caller pass the image.  */
        iobuf_t iobuf;
        u32 *sigstatus;

        err = build_keyblock_image (kb, &iobuf, &sigstatus);
        if (!err)
          {
            err = keybox_insert_keyblock (hd->active[idx].u.kb,
                                          iobuf_get_temp_buffer (iobuf),
                                          iobuf_get_temp_length (iobuf),
                                          sigstatus);
            xfree (sigstatus);
            iobuf_close (iobuf);
          }
      }
      break;
    }

  unlock_all (hd);
  return err;
}


/*
 * Delete the current keyblock.
 */
gpg_error_t
keydb_delete_keyblock (KEYDB_HANDLE hd)
{
  gpg_error_t rc;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  kid_not_found_flush ();
  keyblock_cache_clear ();

  if (hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_VALUE_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  rc = lock_all (hd);
  if (rc)
    return rc;

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = gpg_error (GPG_ERR_GENERAL);
      break;
    case KEYDB_RESOURCE_TYPE_KEYRING:
      rc = keyring_delete_keyblock (hd->active[hd->found].u.kr);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_delete (hd->active[hd->found].u.kb);
      break;
    }

  unlock_all (hd);
  return rc;
}



/*
 * Locate the default writable key resource, so that the next
 * operation (which is only relevant for inserts) will be done on this
 * resource.
 */
gpg_error_t
keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved)
{
  gpg_error_t rc;

  (void)reserved;

  if (!hd)
    return GPG_ERR_INV_ARG;

  rc = keydb_search_reset (hd); /* this does reset hd->current */
  if (rc)
    return rc;

  /* If we have a primary set, try that one first */
  if (primary_keyring)
    {
      for ( ; hd->current >= 0 && hd->current < hd->used; hd->current++)
	{
	  if(hd->active[hd->current].token==primary_keyring)
	    {
	      if(keyring_is_writable (hd->active[hd->current].token))
		return 0;
	      else
		break;
	    }
	}

      rc = keydb_search_reset (hd); /* this does reset hd->current */
      if (rc)
	return rc;
    }

  for ( ; hd->current >= 0 && hd->current < hd->used; hd->current++)
    {
      switch (hd->active[hd->current].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG();
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          if (keyring_is_writable (hd->active[hd->current].token))
            return 0; /* found (hd->current is set to it) */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          if (keybox_is_writable (hd->active[hd->current].token))
            return 0; /* found (hd->current is set to it) */
          break;
        }
    }

  return gpg_error (GPG_ERR_NOT_FOUND);
}

/*
 * Rebuild the caches of all key resources.
 */
void
keydb_rebuild_caches (int noisy)
{
  int i, rc;

  keyblock_cache_clear ();

  for (i=0; i < used_resources; i++)
    {
      if (!keyring_is_writable (all_resources[i].token))
        continue;
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_rebuild_cache (all_resources[i].token,noisy);
          if (rc)
            log_error (_("failed to rebuild keyring cache: %s\n"),
                       gpg_strerror (rc));
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          /* N/A.  */
          break;
        }
    }
}


/* Return the number of skipped blocks since the last search reset.  */
unsigned long
keydb_get_skipped_counter (KEYDB_HANDLE hd)
{
  return hd ? hd->skipped_long_blobs : 0;
}


/*
 * Start the next search on this handle right at the beginning
 */
gpg_error_t
keydb_search_reset (KEYDB_HANDLE hd)
{
  gpg_error_t rc = 0;
  int i;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  keyblock_cache_clear ();

  if (DBG_CLOCK)
    log_clock ("keydb_search_reset");

  if (DBG_CACHE)
    log_debug ("keydb_search: reset  (hd=%p)", hd);

  hd->skipped_long_blobs = 0;
  hd->current = 0;
  hd->found = -1;
  /* Now reset all resources.  */
  for (i=0; !rc && i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_search_reset (hd->active[i].u.kr);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_search_reset (hd->active[i].u.kb);
          break;
        }
    }
  return rc;
}


static void
dump_search_desc (KEYDB_HANDLE hd, const char *text,
                  KEYDB_SEARCH_DESC *desc, size_t ndesc)
{
  int n;
  const char *s;

  for (n=0; n < ndesc; n++)
    {
      switch (desc[n].mode)
        {
        case KEYDB_SEARCH_MODE_NONE:      s = "none";      break;
        case KEYDB_SEARCH_MODE_EXACT:     s = "exact";     break;
        case KEYDB_SEARCH_MODE_SUBSTR:    s = "substr";    break;
        case KEYDB_SEARCH_MODE_MAIL:      s = "mail";      break;
        case KEYDB_SEARCH_MODE_MAILSUB:   s = "mailsub";   break;
        case KEYDB_SEARCH_MODE_MAILEND:   s = "mailend";   break;
        case KEYDB_SEARCH_MODE_WORDS:     s = "words";     break;
        case KEYDB_SEARCH_MODE_SHORT_KID: s = "short_kid"; break;
        case KEYDB_SEARCH_MODE_LONG_KID:  s = "long_kid";  break;
        case KEYDB_SEARCH_MODE_FPR16:     s = "fpr16";     break;
        case KEYDB_SEARCH_MODE_FPR20:     s = "fpr20";     break;
        case KEYDB_SEARCH_MODE_FPR:       s = "fpr";       break;
        case KEYDB_SEARCH_MODE_ISSUER:    s = "issuer";    break;
        case KEYDB_SEARCH_MODE_ISSUER_SN: s = "issuer_sn"; break;
        case KEYDB_SEARCH_MODE_SN:        s = "sn";        break;
        case KEYDB_SEARCH_MODE_SUBJECT:   s = "subject";   break;
        case KEYDB_SEARCH_MODE_KEYGRIP:   s = "keygrip";   break;
        case KEYDB_SEARCH_MODE_FIRST:     s = "first";     break;
        case KEYDB_SEARCH_MODE_NEXT:      s = "next";      break;
        default:                          s = "?";         break;
        }
      if (!n)
        log_debug ("%s: mode=%s  (hd=%p)", text, s, hd);
      else
        log_debug ("%*s  mode=%s", (int)strlen (text), "", s);
      if (desc[n].mode == KEYDB_SEARCH_MODE_LONG_KID)
        log_printf (" %08lX%08lX", (unsigned long)desc[n].u.kid[0],
                    (unsigned long)desc[n].u.kid[1]);
      else if (desc[n].mode == KEYDB_SEARCH_MODE_SHORT_KID)
        log_printf (" %08lX", (unsigned long)desc[n].u.kid[1]);
      else if (desc[n].mode == KEYDB_SEARCH_MODE_SUBSTR)
        log_printf (" '%s'", desc[n].u.name);
    }
}


/*
 * Search through all keydb resources, starting at the current
 * position, for a keyblock which contains one of the keys described
 * in the DESC array.  Returns GPG_ERR_NOT_FOUND if no matching
 * keyring was found.
 */
gpg_error_t
keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
              size_t ndesc, size_t *descindex)
{
  gpg_error_t rc;
  int once_found = 0;

  if (descindex)
    *descindex = 0; /* Make sure it is always set on return.  */

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (DBG_CLOCK)
    log_clock ("keydb_search enter");

  if (DBG_CACHE)
    dump_search_desc (hd, "keydb_search", desc, ndesc);


  /* Note that we track the found state in the table to cope with the
     case that a initial search found the key and the next search
     (without a reset) did not found the key.  Without keeping the
     found state we would falsely claim that the key has not been
     found.  Actually this is quite common because we need to check
     for ambgious keyids.  */
  if (ndesc == 1 && desc[0].mode == KEYDB_SEARCH_MODE_LONG_KID
      && (once_found = kid_not_found_p (desc[0].u.kid)) == 1 )
    {
      if (DBG_CLOCK)
        log_clock ("keydb_search leave (not found, cached)");
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  /* NB: If one of the exact search modes below is used in a loop to
     walk over all keys (with the same fingerprint) the caching must
     have been disabled for the handle.  */
  if (!hd->no_caching
      && ndesc == 1
      && (desc[0].mode == KEYDB_SEARCH_MODE_FPR20
          || desc[0].mode == KEYDB_SEARCH_MODE_FPR)
      && keyblock_cache.state  == KEYBLOCK_CACHE_FILLED
      && !memcmp (keyblock_cache.fpr, desc[0].u.fpr, 20))
    {
      /* (DESCINDEX is already set).  */
      if (DBG_CLOCK)
        log_clock ("keydb_search leave (cached)");
      return 0;
    }

  rc = -1;
  while ((rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
         && hd->current >= 0 && hd->current < hd->used)
    {
      switch (hd->active[hd->current].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG(); /* we should never see it here */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_search (hd->active[hd->current].u.kr, desc,
                               ndesc, descindex);
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_search (hd->active[hd->current].u.kb, desc,
                              ndesc, KEYBOX_BLOBTYPE_PGP,
                              descindex, &hd->skipped_long_blobs);
          break;
        }
      if (rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
        {
          /* EOF -> switch to next resource */
          hd->current++;
        }
      else if (!rc)
        hd->found = hd->current;
    }

  rc = ((rc == -1 || gpg_err_code (rc) == GPG_ERR_EOF)
        ? gpg_error (GPG_ERR_NOT_FOUND)
        : rc);

  keyblock_cache_clear ();
  if (!hd->no_caching
      && !rc
      && ndesc == 1 && (desc[0].mode == KEYDB_SEARCH_MODE_FPR20
                        || desc[0].mode == KEYDB_SEARCH_MODE_FPR))
    {
      keyblock_cache.state = KEYBLOCK_CACHE_PREPARED;
      memcpy (keyblock_cache.fpr, desc[0].u.fpr, 20);
    }

  if ((!rc || gpg_err_code (rc) == GPG_ERR_NOT_FOUND)
      && ndesc == 1 && desc[0].mode == KEYDB_SEARCH_MODE_LONG_KID
      && !once_found)
    {
      kid_not_found_insert (desc[0].u.kid, !rc);
    }

  if (DBG_CLOCK)
    log_clock (rc? "keydb_search leave (not found)"
                 : "keydb_search leave (found)");
  return rc;
}


/* Note that in contrast to using keydb_search in search first mode,
   this function skips legacy keys.  */
gpg_error_t
keydb_search_first (KEYDB_HANDLE hd)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  err = keydb_search (hd, &desc, 1, NULL);
  if (gpg_err_code (err) == GPG_ERR_LEGACY_KEY)
    err = keydb_search_next (hd);
  return err;
}


/* Note that in contrast to using keydb_search in search next mode,
   this fucntion skips legacy keys.  */
gpg_error_t
keydb_search_next (KEYDB_HANDLE hd)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;

  do
    {
      memset (&desc, 0, sizeof desc);
      desc.mode = KEYDB_SEARCH_MODE_NEXT;
      err = keydb_search (hd, &desc, 1, NULL);
    }
  while (gpg_err_code (err) == GPG_ERR_LEGACY_KEY);

  return err;
}

gpg_error_t
keydb_search_kid (KEYDB_HANDLE hd, u32 *kid)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0] = kid[0];
  desc.u.kid[1] = kid[1];
  return keydb_search (hd, &desc, 1, NULL);
}

gpg_error_t
keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FPR;
  memcpy (desc.u.fpr, fpr, MAX_FINGERPRINT_LEN);
  return keydb_search (hd, &desc, 1, NULL);
}
