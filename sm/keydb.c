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

#include "gpgsm.h"
#include "../kbx/keybox.h"
#include "keydb.h" 
#include "i18n.h"

#define DIRSEP_C '/'

static int active_handles;

typedef enum {
    KEYDB_RESOURCE_TYPE_NONE = 0,
    KEYDB_RESOURCE_TYPE_KEYBOX
} KeydbResourceType;
#define MAX_KEYDB_RESOURCES 20

struct resource_item {
  KeydbResourceType type;
  union {
    KEYBOX_HANDLE kr;
  } u;
  void *token;
  int secret;
};

static struct resource_item all_resources[MAX_KEYDB_RESOURCES];
static int used_resources;

struct keydb_handle {
  int locked;
  int found;
  int current;
  int used; /* items in active */
  struct resource_item active[MAX_KEYDB_RESOURCES];
};


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);


/*
 * Register a resource (which currently may only be a keybox file).
 * The first keybox which is added by this function is
 * created if it does not exist.
 * Note: this function may be called before secure memory is
 * available.
 */
int
keydb_add_resource (const char *url, int force, int secret)
{
  static int any_secret, any_public;
  const char *resname = url;
  char *filename = NULL;
  int rc = 0; 
  FILE *fp;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;
  const char *created_fname = NULL;

  /* Do we have an URL?
     gnupg-kbx:filename := this is a plain keybox
     filename := See what is is, but create as plain keybox.
  */
  if (strlen (resname) > 10) 
    {
      if (!strncmp (resname, "gnupg-kbx:", 10) )
        {
          rt = KEYDB_RESOURCE_TYPE_KEYBOX;
          resname += 10;
	}
#if !defined(HAVE_DRIVE_LETTERS) && !defined(__riscos__)
      else if (strchr (resname, ':'))
        {
          log_error ("invalid key resource URL `%s'\n", url );
          rc = GNUPG_General_Error;
          goto leave;
	}
#endif /* !HAVE_DRIVE_LETTERS && !__riscos__ */
    }

  if (*resname != DIRSEP_C )
    { /* do tilde expansion etc */
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
  if (rt == KEYDB_RESOURCE_TYPE_NONE)
    {
      FILE *fp2 = fopen( filename, "rb" );
      
      if (fp2) {
        u32 magic;
        
        /* FIXME: check for the keybox magic */
        if (fread( &magic, 4, 1, fp2) == 1 ) 
          {
            if (magic == 0x13579ace || magic == 0xce9a5713)
              ; /* GDBM magic - no more support */
            else
              rt = KEYDB_RESOURCE_TYPE_KEYBOX;
          }
        else /* maybe empty: assume ring */
          rt = KEYDB_RESOURCE_TYPE_KEYBOX;
        fclose (fp2);
      }
      else /* no file yet: create ring */
        rt = KEYDB_RESOURCE_TYPE_KEYBOX;
    }
    
  switch (rt)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      log_error ("unknown type of key resource `%s'\n", url );
      rc = GNUPG_General_Error;
      goto leave;
      
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      fp = fopen (filename, "rb");
      if (!fp && !force)
        {
          rc = GNUPG_File_Open_Error;
          goto leave;
        }
      
      if (!fp)
        { /* no file */
#if 0 /* no autocreate of the homedirectory yet */
          {
            char *last_slash_in_filename;
            
            last_slash_in_filename = strrchr (filename, DIRSEP_C);
            *last_slash_in_filename = 0;
            if (access (filename, F_OK))
              { /* on the first time we try to create the default
                   homedir and in this case the process will be
                   terminated, so that on the next invocation can
                   read the options file in on startup */
                try_make_homedir (filename);
                rc = GNUPG_File_Open_Error;
                *last_slash_in_filename = DIRSEP_C;
                goto leave;
              }
            *last_slash_in_filename = DIRSEP_C;
          }
#endif
          fp = fopen (filename, "w");
          if (!fp)
            {
              log_error (_("error creating keybox `%s': %s\n"),
                         filename, strerror(errno));
              rc = GNUPG_File_Create_Error;
              goto leave;
	    }

          if (!opt.quiet)
            log_info (_("keybox `%s' created\n"), filename);
          created_fname = filename;
	}
	fclose (fp);
	fp = NULL;
        /* now regsiter the file */
        {
          void *token = keybox_register_file (filename, secret);
          if (!token)
            ; /* already registered - ignore it */
          else if (used_resources >= MAX_KEYDB_RESOURCES)
            rc = GNUPG_Resource_Limit;
          else 
            {
              all_resources[used_resources].type = rt;
              all_resources[used_resources].u.kr = NULL; /* Not used here */
              all_resources[used_resources].token = token;
              all_resources[used_resources].secret = secret;
              used_resources++;
            }
        }
	break;
    default:
      log_error ("resource type of `%s' not supported\n", url);
      rc = GNUPG_Not_Supported;
      goto leave;
    }

  /* fixme: check directory permissions and print a warning */

 leave:
  if (rc)
    log_error ("keyblock resource `%s': %s\n", filename, gnupg_strerror(rc));
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
  
  hd = xcalloc (1, sizeof *hd);
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
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          hd->active[j].type   = all_resources[i].type;
          hd->active[j].token  = all_resources[i].token;
          hd->active[j].secret = all_resources[i].secret;
          hd->active[j].u.kr = keybox_new (all_resources[i].token, secret);
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
  for (i=0; i < hd->used; i++)
    {
      switch (hd->active[i].type) 
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_release (hd->active[i].u.kr);
          break;
        }
    }

    xfree (hd);
}


/* Return the name of the current resource.  This is function first
   looks for the last found found, then for the current search
   position, and last returns the first available resource.  The
   returned string is only valid as long as the handle exists.  This
   function does only return NULL if no handle is specified, in all
   other error cases an empty string is returned.  */
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
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      s = keybox_get_resource_name (hd->active[idx].u.kr);
      break;
    }
  
  return s? s: "";
}



static int 
lock_all (KEYDB_HANDLE hd)
{
  int i, rc = 0;

  for (i=0; !rc && i < hd->used; i++) 
    {
      switch (hd->active[i].type) 
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          /* FIXME  rc = keybox_lock (hd->active[i].u.kr, 1);*/
          break;
        }
    }

    if (rc) 
      {
        /* revert the already set locks */
        for (i--; i >= 0; i--) 
          {
            switch (hd->active[i].type) 
              {
              case KEYDB_RESOURCE_TYPE_NONE:
                break;
              case KEYDB_RESOURCE_TYPE_KEYBOX:
                /* Fixme: keybox_lock (hd->active[i].u.kr, 0);*/
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
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          /* fixme: keybox_lock (hd->active[i].u.kr, 0);*/
          break;
        }
    }
  hd->locked = 0;
}


#if 0
/*
 * Return the last found keybox.  Caller must free it.
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
      case KEYDB_RESOURCE_TYPE_KEYBOX:
        rc = keybox_get_keyblock (hd->active[hd->found].u.kr, ret_kb);
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
      case KEYDB_RESOURCE_TYPE_KEYBOX:
        rc = keybox_update_keyblock (hd->active[hd->found].u.kr, kb);
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
      case KEYDB_RESOURCE_TYPE_KEYBOX:
        rc = keybox_insert_keyblock (hd->active[idx].u.kr, kb);
        break;
    }

    unlock_all (hd);
    return rc;
}

#endif /*disabled code*/



/*
  Return the last found keybox.  Caller must free it.  The returned
  keyblock has the kbode flag bit 0 set for the node with the public
  key used to locate the keyblock or flag bit 1 set for the user ID
  node.  */
int
keydb_get_cert (KEYDB_HANDLE hd, KsbaCert *r_cert)
{
  int rc = 0;

  if (!hd)
    return GNUPG_Invalid_Value;
  
  if ( hd->found < 0 || hd->found >= hd->used) 
    return -1; /* nothing found */
  
  switch (hd->active[hd->found].type) 
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = GNUPG_General_Error; /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_get_cert (hd->active[hd->found].u.kr, r_cert);
      break;
    }
  
  return rc;
}

/* 
 * Insert a new Certificate into one of the resources. 
 */
int
keydb_insert_cert (KEYDB_HANDLE hd, KsbaCert cert)
{
  int rc = -1;
  int idx;
  char digest[20];
  
  if (!hd) 
    return GNUPG_Invalid_Value;

  if (opt.dry_run)
    return 0;
  
  if ( hd->found >= 0 && hd->found < hd->used) 
    idx = hd->found;
  else if ( hd->current >= 0 && hd->current < hd->used) 
    idx = hd->current;
  else
    return GNUPG_General_Error;

  rc = lock_all (hd);
  if (rc)
    return rc;

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL); /* kludge*/

  switch (hd->active[idx].type) 
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = GNUPG_General_Error;
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_insert_cert (hd->active[idx].u.kr, cert, digest);
      break;
    }
  
  unlock_all (hd);
  return rc;
}



/* update the current keyblock with KB */
int
keydb_update_cert (KEYDB_HANDLE hd, KsbaCert cert)
{
  int rc = 0;
  char digest[20];
  
  if (!hd)
    return GNUPG_Invalid_Value;

  if ( hd->found < 0 || hd->found >= hd->used) 
    return -1; /* nothing found */

  if (opt.dry_run)
    return 0;

  rc = lock_all (hd);
  if (rc)
    return rc;

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL); /* kludge*/

  switch (hd->active[hd->found].type) 
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = GNUPG_General_Error; /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_update_cert (hd->active[hd->found].u.kr, cert, digest);
      break;
    }

  unlock_all (hd);
  return rc;
}


/* 
 * The current keyblock or cert will be deleted.
 */
int
keydb_delete (KEYDB_HANDLE hd)
{
  int rc = -1;
  
  if (!hd)
    return GNUPG_Invalid_Value;

  if ( hd->found < 0 || hd->found >= hd->used) 
    return -1; /* nothing found */

  if( opt.dry_run )
    return 0;

  rc = lock_all (hd);
  if (rc)
    return rc;

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      rc = GNUPG_General_Error;
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      rc = keybox_delete (hd->active[hd->found].u.kr);
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
    return GNUPG_Invalid_Value;
  
  rc = keydb_search_reset (hd); /* this does reset hd->current */
  if (rc)
    return rc;
  
  for ( ; hd->current >= 0 && hd->current < hd->used; hd->current++) 
    {
      switch (hd->active[hd->current].type) 
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG();
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          if (keybox_is_writable (hd->active[hd->current].token))
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
keydb_rebuild_caches (void)
{
  int i;
  
  for (i=0; i < used_resources; i++)
    {
      if (all_resources[i].secret)
        continue;
      switch (all_resources[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
/*            rc = keybox_rebuild_cache (all_resources[i].token); */
/*            if (rc) */
/*              log_error (_("failed to rebuild keybox cache: %s\n"), */
/*                         g10_errstr (rc)); */
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
    return GNUPG_Invalid_Value;

  hd->current = 0; 
  hd->found = -1;
  /* and reset all resources */
  for (i=0; !rc && i < hd->used; i++) 
    {
      switch (hd->active[i].type) 
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_search_reset (hd->active[i].u.kr);
          break;
        }
    }
  return rc; /* fixme: we need to map error codes or share them with
                all modules*/
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
    return GNUPG_Invalid_Value;

  while (rc == -1 && hd->current >= 0 && hd->current < hd->used) 
    {
      switch (hd->active[hd->current].type) 
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          BUG(); /* we should never see it here */
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_search (hd->active[hd->current].u.kr, desc, ndesc);
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
/*    desc.u.kid[0] = kid[0]; */
/*    desc.u.kid[1] = kid[1]; */
  return keydb_search (hd, &desc, 1);
}

int
keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr)
{
  KEYDB_SEARCH_DESC desc;
  
  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FPR;
  memcpy (desc.u.fpr, fpr, 20);
  return keydb_search (hd, &desc, 1);
}

int
keydb_search_issuer (KEYDB_HANDLE hd, const char *issuer)
{
  KEYDB_SEARCH_DESC desc;
  int rc;
  
  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_ISSUER;
  desc.u.name = issuer;
  rc = keydb_search (hd, &desc, 1);
  return rc;
}

int
keydb_search_issuer_sn (KEYDB_HANDLE hd,
                        const char *issuer, KsbaConstSexp serial)
{
  KEYDB_SEARCH_DESC desc;
  int rc;
  const unsigned char *s;
  
  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_ISSUER_SN;
  s = serial;
  if (*s !='(')
    return GNUPG_Invalid_Value;
  s++;
  for (desc.snlen = 0; digitp (s); s++)
    desc.snlen = 10*desc.snlen + atoi_1 (s);
  if (*s !=':')
    return GNUPG_Invalid_Value;
  desc.sn = s+1;
  desc.u.name = issuer;
  rc = keydb_search (hd, &desc, 1);
  return rc;
}

int
keydb_search_subject (KEYDB_HANDLE hd, const char *name)
{
  KEYDB_SEARCH_DESC desc;
  int rc;
  
  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_SUBJECT;
  desc.u.name = name;
  rc = keydb_search (hd, &desc, 1);
  return rc;
}


static int
hextobyte (const unsigned char *s)
{
  int c;

  if( *s >= '0' && *s <= '9' )
    c = 16 * (*s - '0');
  else if ( *s >= 'A' && *s <= 'F' )
    c = 16 * (10 + *s - 'A');
  else if ( *s >= 'a' && *s <= 'f' )
    c = 16 * (10 + *s - 'a');
  else
    return -1;
  s++;
  if ( *s >= '0' && *s <= '9' )
    c += *s - '0';
  else if ( *s >= 'A' && *s <= 'F' )
    c += 10 + *s - 'A';
  else if ( *s >= 'a' && *s <= 'f' )
    c += 10 + *s - 'a';
  else
    return -1;
  return c;
}


static int
classify_user_id (const char *name, 
                  KEYDB_SEARCH_DESC *desc,
                  int *force_exact )
{
  const char *s;
  int hexprefix = 0;
  int hexlength;
  int mode = 0;   
    
  /* clear the structure so that the mode field is set to zero unless
   * we set it to the correct value right at the end of this function */
  memset (desc, 0, sizeof *desc);
  *force_exact = 0;
  /* skip leading spaces.  Fixme: what about trailing white space? */
  for(s = name; *s && spacep (s); s++ )
    ;

  switch (*s) 
    {
    case 0:  /* empty string is an error */
      return 0;

    case '.': /* an email address, compare from end */
      mode = KEYDB_SEARCH_MODE_MAILEND;
      s++;
      desc->u.name = s;
      break;

    case '<': /* an email address */
      mode = KEYDB_SEARCH_MODE_MAIL;
      s++;
      desc->u.name = s;
      break;

    case '@':  /* part of an email address */
      mode = KEYDB_SEARCH_MODE_MAILSUB;
      s++;
      desc->u.name = s;
      break;

    case '=':  /* exact compare */
      mode = KEYDB_SEARCH_MODE_EXACT;
      s++;
      desc->u.name = s;
      break;

    case '*':  /* case insensitive substring search */
      mode = KEYDB_SEARCH_MODE_SUBSTR;
      s++;
      desc->u.name = s;
      break;

    case '+':  /* compare individual words */
      mode = KEYDB_SEARCH_MODE_WORDS;
      s++;
      desc->u.name = s;
      break;

    case '/': /* subject's DN */
      s++;
      if (!*s || spacep (s))
        return 0; /* no DN or prefixed with a space */
      desc->u.name = s;
      mode = KEYDB_SEARCH_MODE_SUBJECT;
      break;

    case '#':
      { 
        const char *si;
        
        s++;
        if ( *s == '/')
          { /* "#/" indicates an issuer's DN */
            s++;
            if (!*s || spacep (s))
              return 0; /* no DN or prefixed with a space */
            desc->u.name = s;
            mode = KEYDB_SEARCH_MODE_ISSUER;
          }
        else 
          { /* serialnumber + optional issuer ID */
            for (si=s; *si && *si != '/'; si++)
              {
                if (!strchr("01234567890abcdefABCDEF", *si))
                  return 0; /* invalid digit in serial number*/
              }
            desc->sn = s;
            desc->snlen = -1;
            if (!*si)
              mode = KEYDB_SEARCH_MODE_SN;
            else
              {
                s = si+1;
                if (!*s || spacep (s))
                  return 0; /* no DN or prefixed with a space */
                desc->u.name = s;
                mode = KEYDB_SEARCH_MODE_ISSUER_SN;
              }
          }
      }
      break;

    case ':': /*Unified fingerprint */
      {  
        const char *se, *si;
        int i;
        
        se = strchr (++s,':');
        if (!se)
          return 0;
        for (i=0,si=s; si < se; si++, i++ )
          {
            if (!strchr("01234567890abcdefABCDEF", *si))
              return 0; /* invalid digit */
          }
        if (i != 32 && i != 40)
          return 0; /* invalid length of fpr*/
        for (i=0,si=s; si < se; i++, si +=2) 
          desc->u.fpr[i] = hextobyte(si);
        for (; i < 20; i++)
          desc->u.fpr[i]= 0;
        s = se + 1;
        mode = KEYDB_SEARCH_MODE_FPR;
      } 
      break;
           
    default:
      if (s[0] == '0' && s[1] == 'x')
        {
          hexprefix = 1;
          s += 2;
        }

      hexlength = strspn(s, "0123456789abcdefABCDEF");
      if (hexlength >= 8 && s[hexlength] =='!')
        {
          *force_exact = 1;
          hexlength++; /* just for the following check */
        }
      
      /* check if a hexadecimal number is terminated by EOS or blank */
      if (hexlength && s[hexlength] && !spacep (s+hexlength)) 
        {
          if (hexprefix) /* a "0x" prefix without correct */
            return 0;	 /* termination is an error */
          /* The first chars looked like a hex number, but really is
             not */
          hexlength = 0;  
        }
      
      if (*force_exact)
        hexlength--; /* remove the bang */

      if (hexlength == 8
          || (!hexprefix && hexlength == 9 && *s == '0'))
        { /* short keyid */
          unsigned long kid;
          if (hexlength == 9)
            s++;
          kid = strtoul( s, NULL, 16 );
          desc->u.kid[4] = kid >> 24; 
          desc->u.kid[5] = kid >> 16; 
          desc->u.kid[6] = kid >>  8; 
          desc->u.kid[7] = kid; 
          mode = KEYDB_SEARCH_MODE_SHORT_KID;
        }
      else if (hexlength == 16
               || (!hexprefix && hexlength == 17 && *s == '0'))
        { /* complete keyid */
          unsigned long kid0, kid1;
          char buf[9];
          if (hexlength == 17)
            s++;
          mem2str(buf, s, 9 );
          kid0 = strtoul (buf, NULL, 16);
          kid1 = strtoul (s+8, NULL, 16);
          desc->u.kid[0] = kid0 >> 24; 
          desc->u.kid[1] = kid0 >> 16; 
          desc->u.kid[2] = kid0 >>  8; 
          desc->u.kid[3] = kid0; 
          desc->u.kid[4] = kid1 >> 24; 
          desc->u.kid[5] = kid1 >> 16; 
          desc->u.kid[6] = kid1 >>  8; 
          desc->u.kid[7] = kid1; 
          mode = KEYDB_SEARCH_MODE_LONG_KID;
        }
      else if (hexlength == 32
               || (!hexprefix && hexlength == 33 && *s == '0'))
        { /* md5 fingerprint */
          int i;
          if (hexlength == 33)
            s++;
          memset(desc->u.fpr+16, 0, 4); 
          for (i=0; i < 16; i++, s+=2) 
            {
              int c = hextobyte(s);
              if (c == -1)
                return 0;
              desc->u.fpr[i] = c;
            }
          mode = KEYDB_SEARCH_MODE_FPR16;
        }
      else if (hexlength == 40
               || (!hexprefix && hexlength == 41 && *s == '0'))
        { /* sha1/rmd160 fingerprint */
          int i;
          if (hexlength == 41)
            s++;
          for (i=0; i < 20; i++, s+=2) 
            {
              int c = hextobyte(s);
              if (c == -1)
                return 0;
              desc->u.fpr[i] = c;
            }
          mode = KEYDB_SEARCH_MODE_FPR20;
        }
      else if (!hexprefix)
        { /* default is substring search */
          *force_exact = 0;
          desc->u.name = s;
          mode = KEYDB_SEARCH_MODE_SUBSTR; 
        }
      else
	{ /* hex number with a prefix but a wrong length */
          return 0;
        }
    }
  
  desc->mode = mode;
  return mode;
}


int
keydb_classify_name (const char *name, KEYDB_SEARCH_DESC *desc)
{
  int dummy;
  KEYDB_SEARCH_DESC dummy_desc;

  if (!desc)
    desc = &dummy_desc;

  if (!classify_user_id (name, desc, &dummy))
    return GNUPG_Invalid_Name;
  return 0;
}

