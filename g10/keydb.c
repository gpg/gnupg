/* keydb.c - key database dispatcher
 * Copyright (C) 2001 Free Software Foundation, Inc.
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
#define MAX_KEYDB_RESOURCES 1

struct resource_item {
    KeydbResourceType type;
    union {
        KEYRING_HANDLE kr;
    } u;
};


struct keydb_handle {
    int locked;
    int found;
    int current;
    struct resource_item active[MAX_KEYDB_RESOURCES];
};


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);


/*
 * Register a resource (which currently may only be a keyring file).
 * The first keyring which is added by this function is
 * created if it does not exist.
 * Note: this function may be called before secure memory is
 * available.
 */
int
keydb_add_resource (const char *url, int force, int secret)
{
    static int any_secret, any_public;
    const char *resname = url;
    IOBUF iobuf = NULL;
    char *filename = NULL;
    int rc = 0;
    KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;
    const char *created_fname = NULL;

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
	filename = m_strdup (resname);

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
	iobuf = iobuf_open (filename);
	if (!iobuf && !force) {
	    rc = G10ERR_OPEN_FILE;
	    goto leave;
	}

	if (!iobuf) {
	    char *last_slash_in_filename;

	    last_slash_in_filename = strrchr (filename, DIRSEP_C);
	    *last_slash_in_filename = 0;

	    if (access(filename, F_OK)) {
		/* on the first time we try to create the default homedir and
		 * in this case the process will be terminated, so that on the
		 * next invocation it can read the options file in on startup
		 */
		try_make_homedir (filename);
		rc = G10ERR_OPEN_FILE;
        	*last_slash_in_filename = DIRSEP_C;
		goto leave;
	    }

	    *last_slash_in_filename = DIRSEP_C;

	    iobuf = iobuf_create (filename);
	    if (!iobuf) {
		log_error ( _("error creating keyring `%s': %s\n"),
                            filename, strerror(errno));
		rc = G10ERR_OPEN_FILE;
		goto leave;
	    }
	    else {
	      #ifndef HAVE_DOSISH_SYSTEM
		if (secret && !opt.preserve_permissions) {
		    if (chmod (filename, S_IRUSR | S_IWUSR) ) {
			log_error (_("changing permission of "
                                     " `%s' failed: %s\n"),
                                   filename, strerror(errno) );
			rc = G10ERR_WRITE_FILE;
			goto leave;
		    }
		}
	      #endif
		if (!opt.quiet)
                    log_info (_("keyring `%s' created\n"), filename);
                created_fname = filename;
	    }
	}
	iobuf_close (iobuf);
	iobuf = NULL;
        if (created_fname) /* must invalidate that ugly cache */
            iobuf_ioctl (NULL, 2, 0, (char*)created_fname);
        keyring_register_filename (filename, secret);
	break;

      default:
	log_error ("resource type of `%s' not supported\n", url);
	rc = G10ERR_GENERAL;
	goto leave;
    }

    /* fixme: check directory permissions and print a warning */

  leave:
    if (rc)
	log_error ("keyblock resource `%s': %s\n", filename, g10_errstr(rc));
    else if (secret)
	any_secret = 1;
    else
	any_public = 1;
    m_free (filename);
    return rc;
}




KEYDB_HANDLE
keydb_new (int secret)
{
    KEYDB_HANDLE hd;
    int i=0;

    hd = m_alloc_clear (sizeof *hd);
    hd->found = -1;

    hd->active[i].type = KEYDB_RESOURCE_TYPE_KEYRING;
    hd->active[i].u.kr = keyring_new (secret);
    if (!hd->active[i].u.kr) {
        m_free (hd);
        return NULL;
    }
    i++;


    assert (i <= MAX_KEYDB_RESOURCES);
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
    for (i=0; i < MAX_KEYDB_RESOURCES; i++) {
        switch (hd->active[i].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            keyring_release (hd->active[i].u.kr);
            break;
        }
    }

    m_free (hd);
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

    if ( hd->found >= 0 && hd->found < MAX_KEYDB_RESOURCES) 
        idx = hd->found;
    else if ( hd->current >= 0 && hd->current < MAX_KEYDB_RESOURCES) 
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

    for (i=0; !rc && i < MAX_KEYDB_RESOURCES; i++) {
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

    for (i=MAX_KEYDB_RESOURCES-1; i >= 0; i--) {
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

    if ( hd->found < 0 || hd->found >= MAX_KEYDB_RESOURCES) 
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

    if ( hd->found < 0 || hd->found >= MAX_KEYDB_RESOURCES) 
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

    if ( hd->found >= 0 && hd->found < MAX_KEYDB_RESOURCES) 
        idx = hd->found;
    else if ( hd->current >= 0 && hd->current < MAX_KEYDB_RESOURCES) 
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

    if ( hd->found < 0 || hd->found >= MAX_KEYDB_RESOURCES) 
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

    rc = keydb_search_reset (hd);
    if (!rc) {
        /* fixme: set forward to a writable one */
    }
    return rc;
}

/*
 * Rebuild the caches of all key resources.
 */
void
keydb_rebuild_caches (void)
{
  int rc;
  
  rc = keyring_rebuild_cache ();
  if (rc)
    log_error (_("failed to rebuild all keyring caches: %s\n"),
               g10_errstr (rc));
  /* add other types here */
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
    for (i=0; !rc && i < MAX_KEYDB_RESOURCES; i++) {
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
keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc, size_t ndesc)
{
    int rc = -1;

    if (!hd)
        return G10ERR_INV_ARG;

    while (rc == -1 && hd->current >= 0 && hd->current < MAX_KEYDB_RESOURCES) {
        switch (hd->active[hd->current].type) {
          case KEYDB_RESOURCE_TYPE_NONE:
            rc = -1; /* no resource = eof */
            break;
          case KEYDB_RESOURCE_TYPE_KEYRING:
            rc = keyring_search (hd->active[hd->current].u.kr, desc, ndesc);
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



