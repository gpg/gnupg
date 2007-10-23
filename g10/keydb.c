/* keydb.c - key database dispatcher
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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

#include "util.h"
#include "options.h"
#include "main.h" /*try_make_homedir ()*/
#include "packet.h"
#include "keyring.h"
#include "keydb.h" 
#include "i18n.h"

static int active_handles;

typedef enum {
    KEYDB_RESOURCE_TYPE_NONE = 0,
    KEYDB_RESOURCE_TYPE_KEYRING
} KeydbResourceType;
#define MAX_KEYDB_RESOURCES 40

struct resource_item {
  KeydbResourceType type;
  union {
    KEYRING_HANDLE kr;
  } u;
  void *token;
  int secret;
};

static struct resource_item all_resources[MAX_KEYDB_RESOURCES];
static int used_resources;
static void *primary_keyring=NULL;

struct keydb_handle {
  int locked;
  int found;
  int current;
  int used; /* items in active */
  struct resource_item active[MAX_KEYDB_RESOURCES];
};


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);


/* Handle the creation of a keyring if it does not yet exist.  Take
   into acount that other processes might have the keyring already
   locked.  This lock check does not work if the directory itself is
   not yet available. */
static int
maybe_create_keyring (char *filename, int force)
{
  DOTLOCK lockhd = NULL;
  IOBUF iobuf;
  int rc;
  mode_t oldmask;
  char *last_slash_in_filename;

  /* A quick test whether the filename already exists. */
  if (!access (filename, F_OK))
    return 0;

  /* If we don't want to create a new file at all, there is no need to
     go any further - bail out right here.  */
  if (!force) 
    return G10ERR_OPEN_FILE;

  /* First of all we try to create the home directory.  Note, that we
     don't do any locking here because any sane application of gpg
     would create the home directory by itself and not rely on gpg's
     tricky auto-creation which is anyway only done for some home
     directory name patterns. */
  last_slash_in_filename = strrchr (filename, DIRSEP_C);
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
          rc = G10ERR_OPEN_FILE;
          *last_slash_in_filename = DIRSEP_C;
          goto leave;
        }
    }
  *last_slash_in_filename = DIRSEP_C;


  /* To avoid races with other instances of gpg trying to create or
     update the keyring (it is removed during an update for a short
     time), we do the next stuff in a locked state. */
  lockhd = create_dotlock (filename);
  if (!lockhd)
    {
      /* A reason for this to fail is that the directory is not
         writable. However, this whole locking stuff does not make
         sense if this is the case. An empty non-writable directory
         with no keyring is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for `%s'\n", filename );

      if (!force) 
        return G10ERR_OPEN_FILE; 
      else
        return G10ERR_GENERAL;
    }

  if ( make_dotlock (lockhd, -1) )
    {
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock `%s'\n", filename );
      rc = G10ERR_GENERAL;
      goto leave;
    }

  /* Now the real test while we are locked. */
  if (!access(filename, F_OK))
    {
      rc = 0;  /* Okay, we may access the file now.  */
      goto leave;
    }

  /* The file does not yet exist, create it now. */
  oldmask = umask (077);
  if (is_secured_filename (filename))
    {
      iobuf = NULL;
      errno = EPERM;
    }
  else
    iobuf = iobuf_create (filename);
  umask (oldmask);
  if (!iobuf) 
    {
      log_error ( _("error creating keyring `%s': %s\n"),
                  filename, strerror(errno));
      rc = G10ERR_OPEN_FILE;
      goto leave;
    }

  if (!opt.quiet)
    log_info (_("keyring `%s' created\n"), filename);

  iobuf_close (iobuf);
  /* Must invalidate that ugly cache */
  iobuf_ioctl (NULL, 2, 0, filename);
  rc = 0;

 leave:
  if (lockhd)
    {
      release_dotlock (lockhd);
      destroy_dotlock (lockhd);
    }
  return rc;
}


/*
 * Register a resource (which currently may only be a keyring file).
 * The first keyring which is added by this function is
 * created if it does not exist.
 * Note: this function may be called before secure memory is
 * available.
 * Flag 1 == force
 * Flag 2 == mark resource as primary
 * Flag 4 == This is a default resources
 */
int
keydb_add_resource (const char *url, int flags, int secret)
{
    static int any_secret, any_public;
    const char *resname = url;
    char *filename = NULL;
    int force=(flags&1);
    int rc = 0;
    KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;
    void *token;

    /* Do we have an URL?
     *	gnupg-ring:filename  := this is a plain keyring
     *	filename := See what is is, but create as plain keyring.
     */
    if (strlen (resname) > 11) {
	if (!strncmp( resname, "gnupg-ring:", 11) ) {
	    rt = KEYDB_RESOURCE_TYPE_KEYRING;
	    resname += 11;
	}
#if !defined(HAVE_DRIVE_LETTERS) && !defined(__riscos__)
	else if (strchr (resname, ':')) {
	    log_error ("invalid key resource URL `%s'\n", url );
	    rc = G10ERR_GENERAL;
	    goto leave;
	}
#endif /* !HAVE_DRIVE_LETTERS && !__riscos__ */
    }

    if (*resname != DIRSEP_C ) { /* do tilde expansion etc */
	if (strchr(resname, DIRSEP_C) )
	    filename = make_filename (resname, NULL);
	else
	    filename = make_filename (opt.homedir, resname, NULL);
    }
    else
	filename = xstrdup (resname);

    if (!force)
	force = secret? !any_secret : !any_public;

    /* see whether we can determine the filetype */
    if (rt == KEYDB_RESOURCE_TYPE_NONE) {
	FILE *fp = fopen( filename, "rb" );

	if (fp) {
	    u32 magic;

	    if (fread( &magic, 4, 1, fp) == 1 ) {
		if (magic == 0x13579ace || magic == 0xce9a5713)
		    ; /* GDBM magic - no more support */
		else
		    rt = KEYDB_RESOURCE_TYPE_KEYRING;
	    }
	    else /* maybe empty: assume ring */
		rt = KEYDB_RESOURCE_TYPE_KEYRING;
	    fclose( fp );
	}
	else /* no file yet: create ring */
	    rt = KEYDB_RESOURCE_TYPE_KEYRING;
    }

    switch (rt) {
      case KEYDB_RESOURCE_TYPE_NONE:
	log_error ("unknown type of key resource `%s'\n", url );
	rc = G10ERR_GENERAL;
	goto leave;

      case KEYDB_RESOURCE_TYPE_KEYRING:
        rc = maybe_create_keyring (filename, force);
        if (rc)
          goto leave;

        if(keyring_register_filename (filename, secret, &token))
	  {
	    if (used_resources >= MAX_KEYDB_RESOURCES)
	      rc = G10ERR_RESOURCE_LIMIT;
	    else 
	      {
		if(flags&2)
		  primary_keyring=token;
		all_resources[used_resources].type = rt;
		all_resources[used_resources].u.kr = NULL; /* Not used here */
		all_resources[used_resources].token = token;
		all_resources[used_resources].secret = secret;
		used_resources++;
	      }
	  }
	else
	  {
	    /* This keyring was already registered, so ignore it.
	       However, we can still mark it as primary even if it was
	       already registered. */
	    if(flags&2)
	      primary_keyring=token;
	  }
	break;

      default:
	log_error ("resource type of `%s' not supported\n", url);
	rc = G10ERR_GENERAL;
	goto leave;
    }

    /* fixme: check directory permissions and print a warning */

  leave:
    if (rc)
      {
        /* Secret keyrings are not required in all cases.  To avoid
           having gpg return failure we use log_info here if the
           rewsource is a secret one and marked as default
           resource.  */
        if ((flags&4) && secret)
          log_info (_("keyblock resource `%s': %s\n"),
                    filename, g10_errstr(rc));
        else
          log_error (_("keyblock resource `%s': %s\n"),
                     filename, g10_errstr(rc));
      }
    else if (secret)
	any_secret = 1;
    else
	any_public = 1;
    xfree (filename);
    return rc;
}




KEYDB_HANDLE
keydb_new (int secret)
{
  KEYDB_HANDLE hd;
  int i, j;
  
  hd = xmalloc_clear (sizeof *hd);
  hd->found = -1;
  
  assert (used_resources <= MAX_KEYDB_RESOURCES);
  for (i=j=0; i < used_resources; i++)
    {
      if (!all_resources[i].secret != !secret)
        continue;
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].secret = all_resources[i].secret;
          hd->active[j].u.kr = keyring_new (all_resources[i].token, secret);
          if (!hd->active[j].u.kr) {
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
    for (i=0; i < hd->used; i++) {
        switch (hd->active[i].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            keyring_release (hd->active[i].u.kr);
            break;
        }
    }

    xfree (hd);
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

    switch (hd->active[idx].type) {
      case KEYDB_RESOURCE_TYPE_NONE:
        s = NULL; 
        break;
      case KEYDB_RESOURCE_TYPE_KEYRING:
        s = keyring_get_resource_name (hd->active[idx].u.kr);
        break;
    }

    return s? s: "";
}



static int 
lock_all (KEYDB_HANDLE hd)
{
    int i, rc = 0;

    for (i=0; !rc && i < hd->used; i++) {
        switch (hd->active[i].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            rc = keyring_lock (hd->active[i].u.kr, 1);
            break;
        }
    }

    if (rc) {
        /* revert the already set locks */
        for (i--; i >= 0; i--) {
            switch (hd->active[i].type) {
              case KEYDB_RESOURCE_TYPE_NONE:
                break;
              case KEYDB_RESOURCE_TYPE_KEYRING:
                keyring_lock (hd->active[i].u.kr, 0);
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

    for (i=hd->used-1; i >= 0; i--) {
        switch (hd->active[i].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            keyring_lock (hd->active[i].u.kr, 0);
            break;
        }
    }
    hd->locked = 0;
}


/*
 * Return the last found keyring.  Caller must free it.
 * The returned keyblock has the kbode flag bit 0 set for the node with
 * the public key used to locate the keyblock or flag bit 1 set for 
 * the user ID node.
 */
int
keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb)
{
    int rc = 0;

    if (!hd)
        return G10ERR_INV_ARG;

    if ( hd->found < 0 || hd->found >= hd->used) 
        return -1; /* nothing found */

    switch (hd->active[hd->found].type) {
      case KEYDB_RESOURCE_TYPE_NONE:
        rc = G10ERR_GENERAL; /* oops */
        break;
      case KEYDB_RESOURCE_TYPE_KEYRING:
        rc = keyring_get_keyblock (hd->active[hd->found].u.kr, ret_kb);
        break;
    }

    return rc;
}

/* 
 * update the current keyblock with KB
 */
int
keydb_update_keyblock (KEYDB_HANDLE hd, KBNODE kb)
{
    int rc = 0;

    if (!hd)
        return G10ERR_INV_ARG;

    if ( hd->found < 0 || hd->found >= hd->used) 
        return -1; /* nothing found */

    if( opt.dry_run )
	return 0;

    rc = lock_all (hd);
    if (rc)
        return rc;

    switch (hd->active[hd->found].type) {
      case KEYDB_RESOURCE_TYPE_NONE:
        rc = G10ERR_GENERAL; /* oops */
        break;
      case KEYDB_RESOURCE_TYPE_KEYRING:
        rc = keyring_update_keyblock (hd->active[hd->found].u.kr, kb);
        break;
    }

    unlock_all (hd);
    return rc;
}


/* 
 * Insert a new KB into one of the resources. 
 */
int
keydb_insert_keyblock (KEYDB_HANDLE hd, KBNODE kb)
{
    int rc = -1;
    int idx;

    if (!hd) 
        return G10ERR_INV_ARG;

    if( opt.dry_run )
	return 0;

    if ( hd->found >= 0 && hd->found < hd->used) 
        idx = hd->found;
    else if ( hd->current >= 0 && hd->current < hd->used) 
        idx = hd->current;
    else
        return G10ERR_GENERAL;

    rc = lock_all (hd);
    if (rc)
        return rc;

    switch (hd->active[idx].type) {
      case KEYDB_RESOURCE_TYPE_NONE:
        rc = G10ERR_GENERAL; /* oops */
        break;
      case KEYDB_RESOURCE_TYPE_KEYRING:
        rc = keyring_insert_keyblock (hd->active[idx].u.kr, kb);
        break;
    }

    unlock_all (hd);
    return rc;
}


/* 
 * The current keyblock will be deleted.
 */
int
keydb_delete_keyblock (KEYDB_HANDLE hd)
{
    int rc = -1;

    if (!hd)
        return G10ERR_INV_ARG;

    if ( hd->found < 0 || hd->found >= hd->used) 
        return -1; /* nothing found */

    if( opt.dry_run )
	return 0;

    rc = lock_all (hd);
    if (rc)
        return rc;

    switch (hd->active[hd->found].type) {
      case KEYDB_RESOURCE_TYPE_NONE:
        rc = G10ERR_GENERAL; /* oops */
        break;
      case KEYDB_RESOURCE_TYPE_KEYRING:
        rc = keyring_delete_keyblock (hd->active[hd->found].u.kr);
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
int
keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved)
{
  int rc;
  
  if (!hd)
    return G10ERR_INV_ARG;
  
  rc = keydb_search_reset (hd); /* this does reset hd->current */
  if (rc)
    return rc;

  /* If we have a primary set, try that one first */
  if(primary_keyring)
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
        }
    }
  
  return -1;
}

/*
 * Rebuild the caches of all key resources.
 */
void
keydb_rebuild_caches (int noisy)
{
  int i, rc;
  
  for (i=0; i < used_resources; i++)
    {
      if (all_resources[i].secret)
        continue;
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYRING:
          rc = keyring_rebuild_cache (all_resources[i].token,noisy);
          if (rc)
            log_error (_("failed to rebuild keyring cache: %s\n"),
                       g10_errstr (rc));
          break;
        }
    }
}



/* 
 * Start the next search on this handle right at the beginning
 */
int 
keydb_search_reset (KEYDB_HANDLE hd)
{
    int i, rc = 0;

    if (!hd)
        return G10ERR_INV_ARG;

    hd->current = 0; 
    hd->found = -1;
    /* and reset all resources */
    for (i=0; !rc && i < hd->used; i++) {
        switch (hd->active[i].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            rc = keyring_search_reset (hd->active[i].u.kr);
            break;
        }
    }
    return rc; 
}


/* 
 * Search through all keydb resources, starting at the current position,
 * for a keyblock which contains one of the keys described in the DESC array.
 */
int 
keydb_search2 (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
	       size_t ndesc, size_t *descindex)
{
    int rc = -1;

    if (!hd)
        return G10ERR_INV_ARG;

    while (rc == -1 && hd->current >= 0 && hd->current < hd->used) {
        switch (hd->active[hd->current].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            BUG(); /* we should never see it here */
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            rc = keyring_search (hd->active[hd->current].u.kr, desc,
				 ndesc, descindex);
            break;
        }
        if (rc == -1) /* EOF -> switch to next resource */
            hd->current++; 
        else if (!rc)
            hd->found = hd->current;
    }

    return rc; 
}

int
keydb_search_first (KEYDB_HANDLE hd)
{
    KEYDB_SEARCH_DESC desc;

    memset (&desc, 0, sizeof desc);
    desc.mode = KEYDB_SEARCH_MODE_FIRST;
    return keydb_search (hd, &desc, 1);
}

int
keydb_search_next (KEYDB_HANDLE hd)
{
    KEYDB_SEARCH_DESC desc;

    memset (&desc, 0, sizeof desc);
    desc.mode = KEYDB_SEARCH_MODE_NEXT;
    return keydb_search (hd, &desc, 1);
}

int
keydb_search_kid (KEYDB_HANDLE hd, u32 *kid)
{
    KEYDB_SEARCH_DESC desc;

    memset (&desc, 0, sizeof desc);
    desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
    desc.u.kid[0] = kid[0];
    desc.u.kid[1] = kid[1];
    return keydb_search (hd, &desc, 1);
}

int
keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr)
{
    KEYDB_SEARCH_DESC desc;

    memset (&desc, 0, sizeof desc);
    desc.mode = KEYDB_SEARCH_MODE_FPR;
    memcpy (desc.u.fpr, fpr, MAX_FINGERPRINT_LEN);
    return keydb_search (hd, &desc, 1);
}
