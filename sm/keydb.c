/* keydb.c - key database dispatcher
 * Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
 * Copyright (C) 2014, 2020 g10 Code GmbH
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gpgsm.h"
#include <assuan.h>
#include "../kbx/keybox.h"
#include "keydb.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/comopt.h"
#include "../kbx/kbx-client-util.h"


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
};


/* Data used to keep track of keybox daemon sessions.  This allows us
 * to use several sessions with the keyboxd and also to re-use already
 * established sessions.  Note that gpgdm.h defines the type
 * keydb_local_t for this structure.  */
struct keydb_local_s
{
  /* Link to other keyboxd contexts which are used simultaneously.  */
  struct keydb_local_s *next;

  /* The active Assuan context. */
  assuan_context_t ctx;

  /* The client data helper context.  */
  kbx_client_data_t kcd;

  /* I/O buffer with the last search result or NULL.  Used if
   * D-lines are used to convey the keyblocks. */
  struct {
    char *buf;
    size_t len;
  } search_result;
  /* The "stack" used by keydb_push_found_state.  */
  struct {
    char *buf;
    size_t len;
  } saved_search_result;

  /* This flag set while an operation is running on this context.  */
  unsigned int is_active : 1;

  /* Flag indicating that a search reset is required.  */
  unsigned int need_search_reset : 1;
};


static struct resource_item all_resources[MAX_KEYDB_RESOURCES];
static int used_resources;

/* Whether we have successfully registered any resource.  */
static int any_registered;

/* Number of active handles.  */
static int active_handles;



struct keydb_handle {

  /* CTRL object passed to keydb_new.  */
  ctrl_t ctrl;

  /* If set the keyboxdd is used instead of the local files.  */
  int use_keyboxd;

  /* BEGIN USE_KEYBOXD */
  /* (These fields are only valid if USE_KEYBOXD is set.) */

  /* Connection info which also keeps the local state.  (This points
   * into the CTRL->keybox_local list.) */
  keydb_local_t kbl;

  /* Various flags.  */
  unsigned int last_ubid_valid:1;
  unsigned int last_is_ephemeral;  /* Last found key is ephemeral.  */

  /* The UBID of the last returned keyblock.  */
  unsigned char last_ubid[UBID_LEN];

  /* END USE_KEYBOXD */

  /* BEGIN !USE_KEYBOXD */
  /* (The remaining fields are only valid if USE_KEYBOXD is cleared.)  */

  /* If this flag is set the resources is locked.  */
  int locked;

  /* If this flag is set a lock will only be released by
   * keydb_release.  */
  int keep_lock;

  int found;
  int saved_found;
  int current;
  int is_ephemeral;
  int used; /* items in active */
  struct resource_item active[MAX_KEYDB_RESOURCES];

  /* END !USE_KEYBOXD */
};


static int lock_all (KEYDB_HANDLE hd);
static void unlock_all (KEYDB_HANDLE hd);



/* Deinitialize all session resources pertaining to the keyboxd.  */
void
gpgsm_keydb_deinit_session_data (ctrl_t ctrl)
{
  keydb_local_t kbl;

  while ((kbl = ctrl->keydb_local))
    {
      ctrl->keydb_local = kbl->next;
      if (kbl->is_active)
        log_error ("oops: trying to cleanup an active keydb context\n");
      else
        {
          kbx_client_data_release (kbl->kcd);
          kbl->kcd = NULL;
          assuan_release (kbl->ctx);
          kbl->ctx = NULL;
        }
      xfree (kbl);
    }
}


static void
try_make_homedir (const char *fname)
{
  if ( opt.dry_run || opt.no_homedir_creation )
    return;

  gnupg_maybe_make_homedir (fname, opt.quiet);
}


/* Handle the creation of a keybox if it does not yet exist.  Take
   into account that other processes might have the keybox already
   locked.  This lock check does not work if the directory itself is
   not yet available.  If R_CREATED is not NULL it will be set to true
   if the function created a new keybox.  */
static gpg_error_t
maybe_create_keybox (char *filename, int force, int *r_created)
{
  gpg_err_code_t ec;
  dotlock_t lockhd = NULL;
  estream_t fp;
  int rc;
  mode_t oldmask;
  char *last_slash_in_filename;
  int save_slash;

  if (r_created)
    *r_created = 0;

  /* A quick test whether the filename already exists. */
  if (!gnupg_access (filename, F_OK))
    return !gnupg_access (filename, R_OK)? 0 : gpg_error (GPG_ERR_EACCES);

  /* If we don't want to create a new file at all, there is no need to
     go any further - bail out right here.  */
  if (!force)
    return gpg_error (GPG_ERR_ENOENT);

  /* First of all we try to create the home directory.  Note, that we
     don't do any locking here because any sane application of gpg
     would create the home directory by itself and not rely on gpg's
     tricky auto-creation which is anyway only done for some home
     directory name patterns. */
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
  if (gnupg_access(filename, F_OK))
    {
      static int tried;

      if (!tried)
        {
          tried = 1;
          try_make_homedir (filename);
        }
      if ((ec = gnupg_access (filename, F_OK)))
        {
          rc = gpg_error (ec);
          *last_slash_in_filename = save_slash;
          goto leave;
        }
      *last_slash_in_filename = save_slash;

      if (!opt.use_keyboxd
          && !parse_comopt (GNUPG_MODULE_NAME_GPG, 0)
          && comopt.use_keyboxd)
        {
          /* The above try_make_homedir created a new default hoemdir
           * and also wrote a new common.conf.  Thus we now see that
           * use-keyboxd has been set.  Let's set this option and
           * return a dedicated error code.  */
          opt.use_keyboxd = comopt.use_keyboxd;
          rc = gpg_error (GPG_ERR_TRUE);
          goto leave;
        }
    }
  else
    *last_slash_in_filename = save_slash;

  /* To avoid races with other instances of gpg trying to create or
     update the keybox (it is removed during an update for a short
     time), we do the next stuff in a locked state. */
  lockhd = dotlock_create (filename, 0);
  if (!lockhd)
    {
      /* A reason for this to fail is that the directory is not
         writable. However, this whole locking stuff does not make
         sense if this is the case. An empty non-writable directory
         with no keyring is not really useful at all. */
      if (opt.verbose)
        log_info ("can't allocate lock for '%s'\n", filename );

      if (!force)
        return gpg_error (GPG_ERR_ENOENT);
      else
        return gpg_error (GPG_ERR_GENERAL);
    }

  if ( dotlock_take (lockhd, -1) )
    {
      /* This is something bad.  Probably a stale lockfile.  */
      log_info ("can't lock '%s'\n", filename);
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Now the real test while we are locked. */
  if (!gnupg_access(filename, F_OK))
    {
      rc = 0;  /* Okay, we may access the file now.  */
      goto leave;
    }

  /* The file does not yet exist, create it now. */
  oldmask = umask (077);
  fp = es_fopen (filename, "wb");
  if (!fp)
    {
      rc = gpg_error_from_syserror ();
      umask (oldmask);
      log_error (_("error creating keybox '%s': %s\n"),
                 filename, gpg_strerror (rc));
      goto leave;
    }
  umask (oldmask);

  /* Make sure that at least one record is in a new keybox file, so
     that the detection magic for OpenPGP keyboxes works the next time
     it is used.  */
  rc = _keybox_write_header_blob (fp, 0);
  if (rc)
    {
      es_fclose (fp);
      log_error (_("error creating keybox '%s': %s\n"),
                 filename, gpg_strerror (rc));
      goto leave;
    }

  if (!opt.quiet)
    log_info (_("keybox '%s' created\n"), filename);
  if (r_created)
    *r_created = 1;

  es_fclose (fp);
  rc = 0;

 leave:
  if (lockhd)
    {
      dotlock_release (lockhd);
      dotlock_destroy (lockhd);
    }
  return rc;
}


/*
 * Register a resource (which currently may only be a keybox file).
 * The first keybox which is added by this function is created if it
 * does not exist.  If AUTO_CREATED is not NULL it will be set to true
 * if the function has created a new keybox.
 */
gpg_error_t
keydb_add_resource (ctrl_t ctrl, const char *url, int force, int *auto_created)
{
  const char *resname = url;
  char *filename = NULL;
  gpg_error_t err = 0;
  KeydbResourceType rt = KEYDB_RESOURCE_TYPE_NONE;

  if (auto_created)
    *auto_created = 0;

  /* Do we have an URL?
     gnupg-kbx:filename := this is a plain keybox
     filename := See what it is, but create as plain keybox.
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
          log_error ("invalid key resource URL '%s'\n", url );
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
	}
#endif /* !HAVE_DRIVE_LETTERS && !__riscos__ */
    }

  if (*resname != DIRSEP_C )
    { /* do tilde expansion etc */
      if (strchr(resname, DIRSEP_C) )
        filename = make_filename (resname, NULL);
      else
        filename = make_filename (gnupg_homedir (), resname, NULL);
    }
  else
    filename = xstrdup (resname);

  if (!force)
    force = !any_registered;

  /* see whether we can determine the filetype */
  if (rt == KEYDB_RESOURCE_TYPE_NONE)
    {
      estream_t fp;

      fp = es_fopen( filename, "rb" );
      if (fp)
        {
          u32 magic;

          /* FIXME: check for the keybox magic */
          if (es_fread (&magic, 4, 1, fp) == 1 )
            {
              if (magic == 0x13579ace || magic == 0xce9a5713)
                ; /* GDBM magic - no more support */
              else
                rt = KEYDB_RESOURCE_TYPE_KEYBOX;
            }
          else /* maybe empty: assume keybox */
            rt = KEYDB_RESOURCE_TYPE_KEYBOX;

          es_fclose (fp);
        }
      else /* no file yet: create keybox */
        rt = KEYDB_RESOURCE_TYPE_KEYBOX;
    }

  switch (rt)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      log_error ("unknown type of key resource '%s'\n", url );
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;

    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = maybe_create_keybox (filename, force, auto_created);
      if (err)
        goto leave;
      /* Now register the file */
      {
        void *token;

        err = keybox_register_file (filename, 0, &token);
        if (gpg_err_code (err) == GPG_ERR_EEXIST)
          ; /* Already registered - ignore.  */
        else if (err)
          ; /* Other error.  */
        else if (used_resources >= MAX_KEYDB_RESOURCES)
          err = gpg_error (GPG_ERR_RESOURCE_LIMIT);
        else
          {
            KEYBOX_HANDLE kbxhd;

            all_resources[used_resources].type = rt;
            all_resources[used_resources].u.kr = NULL; /* Not used here */
            all_resources[used_resources].token = token;

            /* Do a compress run if needed and the keybox is not locked. */
            kbxhd = keybox_new_x509 (token, 0);
            if (kbxhd)
              {
                if (!keybox_lock (kbxhd, 1, 0))
                  {
                    keybox_compress (kbxhd);
                    keybox_lock (kbxhd, 0, 0);
                  }

                keybox_release (kbxhd);
              }

            used_resources++;
          }
      }
      break;

    default:
      log_error ("resource type of '%s' not supported\n", url);
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  /* fixme: check directory permissions and print a warning */

 leave:
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_TRUE)
        {
          log_error ("keyblock resource '%s': %s\n",
                     filename, gpg_strerror (err));
          gpgsm_status_with_error (ctrl, STATUS_ERROR,
                                   "add_keyblock_resource", err);
        }
    }
  else
    any_registered = 1;
  xfree (filename);
  return err;
}


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (ctrl_t ctrl, assuan_context_t ctx,
                       const char *servername)
{
  return warn_server_version_mismatch (ctx, servername, 0,
                                       gpgsm_status2, ctrl,
                                       !opt.quiet);
}


/* Connect to the keybox daemon and launch it if necessary.  Handle
 * the server's initial greeting and set global options.  Returns a
 * new assuan context or an error.  */
static gpg_error_t
create_new_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;

  err = start_new_keyboxd (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           opt.keyboxd_program,
                           opt.autostart, opt.verbose, DBG_IPC,
                           NULL, ctrl);
  if (!opt.autostart && gpg_err_code (err) == GPG_ERR_NO_KEYBOXD)
    {
      static int shown;

      if (!shown)
        {
          shown = 1;
          log_info (_("no keyboxd running in this session\n"));
        }
    }
  else if (!err && !(err = warn_version_mismatch (ctrl, ctx, KEYBOXD_NAME)))
    {
      /* Place to emit global options.  */
    }

  if (err)
    assuan_release (ctx);
  else
    *r_ctx = ctx;

  return err;
}


/* Get a context for accessing keyboxd.  If no context is available a
 * new one is created and if necessary keyboxd is started.  R_KBL
 * receives a pointer to the local context object.  */
static gpg_error_t
open_context (ctrl_t ctrl, keydb_local_t *r_kbl)
{
  gpg_error_t err;
  keydb_local_t kbl;

  *r_kbl = NULL;
  for (;;)
    {
      for (kbl = ctrl->keydb_local; kbl && kbl->is_active; kbl = kbl->next)
        ;
      if (kbl)
        {
          /* Found an inactive keyboxd session - return that.  */
          log_assert (!kbl->is_active);

          kbl->is_active = 1;
          kbl->need_search_reset = 1;

          *r_kbl = kbl;
          return 0;
        }

      /* None found.  Create a new session and retry.  */
      kbl = xtrycalloc (1, sizeof *kbl);
      if (!kbl)
        return gpg_error_from_syserror ();

      err = create_new_context (ctrl, &kbl->ctx);
      if (err)
        {
          xfree (kbl);
          return err;
        }

      err = kbx_client_data_new (&kbl->kcd, kbl->ctx, 1);
      if (err)
        {
          assuan_release (kbl->ctx);
          xfree (kbl);
          return err;
        }

      /* For thread-saftey we add it to the list and retry; this is
       * easier than to employ a lock.  */
      kbl->next = ctrl->keydb_local;
      ctrl->keydb_local = kbl;
    }
  /*NOTREACHED*/
}


KEYDB_HANDLE
keydb_new (ctrl_t ctrl)
{
  gpg_error_t err;
  KEYDB_HANDLE hd;
  int rc, i, j;

  if (DBG_CLOCK)
    log_clock ("%s: enter\n", __func__);

  hd = xcalloc (1, sizeof *hd);
  hd->found = -1;
  hd->saved_found = -1;
  hd->use_keyboxd = opt.use_keyboxd;
  hd->ctrl = ctrl;
  if (hd->use_keyboxd)
    {
      err = open_context (ctrl, &hd->kbl);
      if (err)
        {
          log_error (_("error opening key DB: %s\n"), gpg_strerror (err));
          xfree (hd);
          hd = NULL;
          if (!(rc = gpg_err_code_to_errno (err)))
            rc = gpg_err_code_to_errno (GPG_ERR_EIO);
          gpg_err_set_errno (rc);
          goto leave;
        }
    }
  else /* Use the local keybox.  */
    {
      log_assert (used_resources <= MAX_KEYDB_RESOURCES);
      for (i=j=0; i < used_resources; i++)
        {
          switch (all_resources[i].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE: /* ignore */
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              hd->active[j].type   = all_resources[i].type;
              hd->active[j].token  = all_resources[i].token;
              hd->active[j].u.kr = keybox_new_x509 (all_resources[i].token, 0);
              if (!hd->active[j].u.kr)
                {
                  xfree (hd);
                  return NULL; /* fixme: free all previously allocated handles*/
                }
              j++;
              break;
            }
        }
      hd->used = j;
    }

  active_handles++;

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (hd=%p)\n", __func__, hd);
  return hd;
}

void
keydb_release (KEYDB_HANDLE hd)
{
  keydb_local_t kbl;
  int i;

  if (!hd)
    return;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  log_assert (active_handles > 0);
  active_handles--;

  if (hd->use_keyboxd)
    {
      kbl = hd->kbl;
      if (DBG_CLOCK)
        log_clock ("close_context (found)");
      if (!kbl->is_active)
        log_fatal ("closing inactive keyboxd context %p\n", kbl);
      kbl->is_active = 0;
      hd->kbl = NULL;
    }
  else
    {
      hd->keep_lock = 0;
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
    }

  xfree (hd);
  if (DBG_CLOCK)
    log_clock ("%s: leave\n", __func__);
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

  if (hd->use_keyboxd)
    return "[keyboxd]";

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

/* Switch the handle into ephemeral mode and return the original value. */
int
keydb_set_ephemeral (KEYDB_HANDLE hd, int yes)
{
  int i;

  if (!hd)
    return 0;

  if (hd->use_keyboxd)
    return 0; /* FIXME: No support yet.  */


  yes = !!yes;
  if (hd->is_ephemeral != yes)
    {
      for (i=0; i < hd->used; i++)
        {
          switch (hd->active[i].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              keybox_set_ephemeral (hd->active[i].u.kr, yes);
              break;
            }
        }
    }

  i = hd->is_ephemeral;
  hd->is_ephemeral = yes;
  return i;
}


/* If the keyring has not yet been locked, lock it now.  This
 * operation is required before any update operation; it is optional
 * for an insert operation.  The lock is kept until a keydb_release so
 * that internal unlock_all calls have no effect.  */
gpg_error_t
keydb_lock (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_HANDLE);
  if (hd->use_keyboxd)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);
  err = lock_all (hd);
  if (!err)
    hd->keep_lock = 1;

  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}



static int
lock_all (KEYDB_HANDLE hd)
{
  int i, rc = 0;

  if (hd->use_keyboxd)
    return 0;

  /* Fixme: This locking scheme may lead to deadlock if the resources
     are not added in the same order by all processes.  We are
     currently only allowing one resource so it is not a problem. */
  for (i=0; i < hd->used; i++)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          rc = keybox_lock (hd->active[i].u.kr, 1, -1);
          break;
        }
      if (rc)
        break;
    }

    if (rc)
      {
        /* Revert the already set locks.  */
        for (i--; i >= 0; i--)
          {
            switch (hd->active[i].type)
              {
              case KEYDB_RESOURCE_TYPE_NONE:
                break;
              case KEYDB_RESOURCE_TYPE_KEYBOX:
                keybox_lock (hd->active[i].u.kr, 0, 0);
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

  if (hd->use_keyboxd)
    return;

  if (!hd->locked || hd->keep_lock)
    return;

  for (i=hd->used-1; i >= 0; i--)
    {
      switch (hd->active[i].type)
        {
        case KEYDB_RESOURCE_TYPE_NONE:
          break;
        case KEYDB_RESOURCE_TYPE_KEYBOX:
          keybox_lock (hd->active[i].u.kr, 0, 0);
          break;
        }
    }
  hd->locked = 0;
}



/* Push the last found state if any.   Only one state is saved.  */
void
keydb_push_found_state (KEYDB_HANDLE hd)
{
  if (!hd)
    return;

  if (hd->use_keyboxd)
    {
      xfree (hd->kbl->saved_search_result.buf);
      hd->kbl->saved_search_result.buf = hd->kbl->search_result.buf;
      hd->kbl->saved_search_result.len = hd->kbl->search_result.len;
      hd->kbl->search_result.buf = NULL;
      hd->kbl->search_result.len = 0;
    }
  else
    {
      if (hd->found < 0 || hd->found >= hd->used)
        hd->saved_found = -1;
      else
        {
          switch (hd->active[hd->found].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              keybox_push_found_state (hd->active[hd->found].u.kr);
              break;
            }

          hd->saved_found = hd->found;
          hd->found = -1;
        }
    }

  if (DBG_CLOCK)
    log_clock ("%s: done (hd=%p)\n", __func__, hd);
}


/* Pop the last found state.  */
void
keydb_pop_found_state (KEYDB_HANDLE hd)
{
  if (!hd)
    return;

  if (hd->use_keyboxd)
    {
      xfree (hd->kbl->search_result.buf);
      hd->kbl->search_result.buf = hd->kbl->saved_search_result.buf;
      hd->kbl->search_result.len = hd->kbl->saved_search_result.len;
      hd->kbl->saved_search_result.buf = NULL;
      hd->kbl->saved_search_result.len = 0;
    }
  else
    {
      hd->found = hd->saved_found;
      hd->saved_found = -1;
      if (hd->found < 0 || hd->found >= hd->used)
        ;
      else
        {
          switch (hd->active[hd->found].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              keybox_pop_found_state (hd->active[hd->found].u.kr);
              break;
            }
        }
    }

  if (DBG_CLOCK)
    log_clock ("%s: done (hd=%p)\n", __func__, hd);
}



/* Return the last found certificate.  Caller must free it.  */
int
keydb_get_cert (KEYDB_HANDLE hd, ksba_cert_t *r_cert)
{
  int err = 0;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (hd->use_keyboxd)
    {
      ksba_cert_t cert;

      /* Fixme: We should clear that also in non-keyboxd mode but we
       * did not in the past and thus all code should be checked
       * whether this is okay.  If we run into error in keyboxd mode,
       * this is a not as severe because keyboxd is currently
       * experimental.  */
      *r_cert = NULL;

      if (!hd->kbl->search_result.buf || !hd->kbl->search_result.len)
        {
          err = gpg_error (GPG_ERR_VALUE_NOT_FOUND);
          goto leave;
        }
      err = ksba_cert_new (&cert);
      if (err)
        goto leave;
      err = ksba_cert_init_from_mem (cert,
                                     hd->kbl->search_result.buf,
                                     hd->kbl->search_result.len);
      if (err)
        {
          ksba_cert_release (cert);
          goto leave;
        }
      *r_cert = cert;
      goto leave;
    }

  if ( hd->found < 0 || hd->found >= hd->used)
    {
      /* Fixme: It would be better to use GPG_ERR_VALUE_NOT_FOUND here
       * but for now we use NOT_FOUND because that is our standard
       * replacement for the formerly used (-1).  */
      err = gpg_error (GPG_ERR_NOT_FOUND); /* nothing found */
      goto leave;
    }

  err = GPG_ERR_BUG;
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_get_cert (hd->active[hd->found].u.kr, r_cert);
      break;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (rc=%d)\n", __func__, err);
  return err;
}


/* Return a flag of the last found object. WHICH is the flag requested;
   it should be one of the KEYBOX_FLAG_ values.  If the operation is
   successful, the flag value will be stored at the address given by
   VALUE.  Return 0 on success or an error code. */
gpg_error_t
keydb_get_flags (KEYDB_HANDLE hd, int which, int idx, unsigned int *value)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (hd->use_keyboxd)
    {
      /* FIXME */
      *value = 0;
      err = 0;
      goto leave;
    }

  if ( hd->found < 0 || hd->found >= hd->used)
    {
      err = gpg_error (GPG_ERR_NOTHING_FOUND);
      goto leave;
    }

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_get_flags (hd->active[hd->found].u.kr, which, idx, value);
      break;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}


/* Set a flag of the last found object. WHICH is the flag to be set; it
   should be one of the KEYBOX_FLAG_ values.  If the operation is
   successful, the flag value will be stored in the keybox.  Note,
   that some flag values can't be updated and thus may return an
   error, some other flag values may be masked out before an update.
   Returns 0 on success or an error code. */
gpg_error_t
keydb_set_flags (KEYDB_HANDLE hd, int which, int idx, unsigned int value)
{
  gpg_error_t err = 0;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (hd->use_keyboxd)
    {
      /* FIXME */
      goto leave;
    }

  if ( hd->found < 0 || hd->found >= hd->used)
    {
      err = gpg_error (GPG_ERR_NOTHING_FOUND);
      goto leave;
    }

  if (!hd->locked)
    {
      err = gpg_error (GPG_ERR_NOT_LOCKED);
      goto leave;
    }

  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_set_flags (hd->active[hd->found].u.kr, which, idx, value);
      break;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}


/* Default status callback used to show diagnostics from the keyboxd  */
static gpg_error_t
keydb_default_status_cb (void *opaque, const char *line)
{
  const char *s;

  (void)opaque;

  if ((s = has_leading_keyword (line, "NOTE")))
    log_info (_("Note: %s\n"), s);
  else if ((s = has_leading_keyword (line, "WARNING")))
    log_info (_("WARNING: %s\n"), s);

  return 0;
}



/* Communication object for Keyboxd STORE commands.  */
struct store_parm_s
{
  assuan_context_t ctx;
  const void *data;   /* The certificate in X.509 binary format.  */
  size_t datalen;     /* The length of DATA.  */
};


/* Handle the inquiries from the STORE command.  */
static gpg_error_t
store_inq_cb (void *opaque, const char *line)
{
  struct store_parm_s *parm = opaque;
  gpg_error_t err = 0;

  if (has_leading_keyword (line, "BLOB"))
    {
      if (parm->data)
        err = assuan_send_data (parm->ctx, parm->data, parm->datalen);
    }
  else
    return gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);

  return err;
}


/*
 * Insert a new Certificate into one of the resources.
 */
gpg_error_t
keydb_insert_cert (KEYDB_HANDLE hd, ksba_cert_t cert)
{
  gpg_error_t err;
  int idx;
  unsigned char digest[20];

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (opt.dry_run)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (hd->use_keyboxd)
    {
      struct store_parm_s parm;

      parm.ctx = hd->kbl->ctx;
      parm.data = ksba_cert_get_image (cert, &parm.datalen);
      if (!parm.data)
        {
          log_debug ("broken ksba cert object\n");
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
      err = assuan_transact (hd->kbl->ctx, "STORE --insert",
                             NULL, NULL,
                             store_inq_cb, &parm,
                             keydb_default_status_cb, hd);
      goto leave;
    }

  if ( hd->found >= 0 && hd->found < hd->used)
    idx = hd->found;
  else if ( hd->current >= 0 && hd->current < hd->used)
    idx = hd->current;
  else
    {
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (!hd->locked)
    {
      err = gpg_error (GPG_ERR_NOT_LOCKED);
      goto leave;
    }

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL); /* kludge*/

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[idx].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_insert_cert (hd->active[idx].u.kr, cert, digest);
      break;
    }

  unlock_all (hd);

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}



/* Update the current keyblock with KB.  */
/* Note: This function is currently not called.  */
gpg_error_t
keydb_update_cert (KEYDB_HANDLE hd, ksba_cert_t cert)
{
  (void)hd;
  (void)cert;
  return GPG_ERR_BUG;
#if 0
  gpg_error_t err;
  unsigned char digest[20];

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if ( hd->found < 0 || hd->found >= hd->used)
    return gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (hd->use_keyboxd)
    {
      /* FIXME */
      goto leave;
    }

  err = lock_all (hd);
  if (err)
    goto leave;

  gpgsm_get_fingerprint (cert, GCRY_MD_SHA1, digest, NULL); /* kludge*/

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL); /* oops */
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_update_cert (hd->active[hd->found].u.kr, cert, digest);
      break;
    }

  unlock_all (hd);
 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
#endif /*0*/
}


/*
 * The current keyblock or cert will be deleted.
 */
gpg_error_t
keydb_delete (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!hd->use_keyboxd && (hd->found < 0 || hd->found >= hd->used))
    return gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.dry_run)
    return 0;

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (hd->use_keyboxd)
    {
      unsigned char hexubid[UBID_LEN * 2 + 1];
      char line[ASSUAN_LINELENGTH];

      if (!hd->last_ubid_valid)
        {
          err = gpg_error (GPG_ERR_VALUE_NOT_FOUND);
          goto leave;
        }

      bin2hex (hd->last_ubid, UBID_LEN, hexubid);
      snprintf (line, sizeof line, "DELETE %s", hexubid);
      err = assuan_transact (hd->kbl->ctx, line,
                             NULL, NULL,
                             NULL, NULL,
                             keydb_default_status_cb, hd);
      goto leave;
    }

  if (!hd->locked)
    {
      err = gpg_error (GPG_ERR_NOT_LOCKED);
      goto leave;
    }

  err = gpg_error (GPG_ERR_BUG);
  switch (hd->active[hd->found].type)
    {
    case KEYDB_RESOURCE_TYPE_NONE:
      err = gpg_error (GPG_ERR_GENERAL);
      break;
    case KEYDB_RESOURCE_TYPE_KEYBOX:
      err = keybox_delete (hd->active[hd->found].u.kr);
      break;
    }

  unlock_all (hd);

 leave:
  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}



/*
 * Locate the default writable key resource, so that the next
 * operation (which is only relevant for inserts) will be done on this
 * resource.
 */
static gpg_error_t
keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved)
{
  int rc;

  (void)reserved;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (hd->use_keyboxd)
    return 0;  /* Not required.  */

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

  return gpg_error (GPG_ERR_NOT_FOUND);
}

/*
 * Rebuild the caches of all key resources.
 */
void
keydb_rebuild_caches (void)
{
  int i;

  /* This function does nothing and thus we don't need to handle keyboxd in a
   * special way.  */

  for (i=0; i < used_resources; i++)
    {
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
gpg_error_t
keydb_search_reset (KEYDB_HANDLE hd)
{
  gpg_error_t err = 0;
  int i;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  hd->current = 0;
  hd->found = -1;
  if (hd->use_keyboxd)
    {
      /* All we need is to tell search that a reset is pending.  Note that
       * keydb_new sets this flag as well.  To comply with the
       * specification of keydb_delete_keyblock we also need to clear the
       * ubid flag so that after a reset a delete can't be performed.  */
      hd->kbl->need_search_reset = 1;
      hd->last_ubid_valid = 0;
   }
  else
    {
      /* Reset all resources */
      for (i=0; !err && i < hd->used; i++)
        {
          switch (hd->active[i].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              err = keybox_search_reset (hd->active[i].u.kr);
              break;
            }
        }
    }

  if (DBG_CLOCK)
    log_clock ("%s: leave (err=%s)\n", __func__, gpg_strerror (err));
  return err;
}


char *
keydb_search_desc_dump (struct keydb_search_desc *desc)
{
  char *fpr;
  char *result;

  switch (desc->mode)
    {
    case KEYDB_SEARCH_MODE_EXACT:
      return xasprintf ("EXACT: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_SUBSTR:
      return xasprintf ("SUBSTR: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_MAIL:
      return xasprintf ("MAIL: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_MAILSUB:
      return xasprintf ("MAILSUB: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_MAILEND:
      return xasprintf ("MAILEND: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_WORDS:
      return xasprintf ("WORDS: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_SHORT_KID:
      return xasprintf ("SHORT_KID: '%08lX'", (ulong)desc->u.kid[1]);
    case KEYDB_SEARCH_MODE_LONG_KID:
      return xasprintf ("LONG_KID: '%08lX%08lX'",
                        (ulong)desc->u.kid[0], (ulong)desc->u.kid[1]);
    case KEYDB_SEARCH_MODE_FPR:
      fpr = bin2hexcolon (desc->u.fpr, desc->fprlen, NULL);
      result = xasprintf ("FPR%02d: '%s'", desc->fprlen, fpr);
      xfree (fpr);
      return result;
    case KEYDB_SEARCH_MODE_ISSUER:
      return xasprintf ("ISSUER: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_ISSUER_SN:
      return xasprintf ("ISSUER_SN: '#%.*s/%s'",
                        (int)desc->snlen,desc->sn, desc->u.name);
    case KEYDB_SEARCH_MODE_SN:
      return xasprintf ("SN: '%.*s'",
                        (int)desc->snlen, desc->sn);
    case KEYDB_SEARCH_MODE_SUBJECT:
      return xasprintf ("SUBJECT: '%s'", desc->u.name);
    case KEYDB_SEARCH_MODE_KEYGRIP:
      return xasprintf ("KEYGRIP: %s", desc->u.grip);
    case KEYDB_SEARCH_MODE_FIRST:
      return xasprintf ("FIRST");
    case KEYDB_SEARCH_MODE_NEXT:
      return xasprintf ("NEXT");
    default:
      return xasprintf ("Bad search mode (%d)", desc->mode);
    }
}



/* Status callback for SEARCH and NEXT operaions.  */
static gpg_error_t
search_status_cb (void *opaque, const char *line)
{
  KEYDB_HANDLE hd = opaque;
  gpg_error_t err = 0;
  const char *s;
  unsigned int n;

  if ((s = has_leading_keyword (line, "PUBKEY_INFO")))
    {
      if (atoi (s) != PUBKEY_TYPE_X509)
        err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);
      else
        {
          hd->last_ubid_valid = 0;
          while (*s && !spacep (s))
            s++;
          if (!(n=hex2fixedbuf (s, hd->last_ubid, sizeof hd->last_ubid)))
            err = gpg_error (GPG_ERR_INV_VALUE);
          else
            {
              hd->last_ubid_valid = 1;
              s += n;
              hd->last_is_ephemeral = (*s == 'e');
            }
        }
    }
  else
    err = keydb_default_status_cb (opaque, line);

  return err;
}

/* Search through all keydb resources, starting at the current
 * position, for a keyblock which contains one of the keys described
 * in the DESC array.  In keyboxd mode the search is instead delegated
 * to the keyboxd.
 *
 * DESC is an array of search terms with NDESC entries.  The search
 * terms are or'd together.  That is, the next entry in the DB that
 * matches any of the descriptions will be returned.
 *
 * Note: this function resumes searching where the last search left
 * off (i.e., at the current file position).  If you want to search
 * from the start of the database, then you need to first call
 * keydb_search_reset().
 *
 * If no key matches the search description, the error code
 * GPG_ERR_NOT_FOUND is retruned.  If there was a match, 0 is
 * returned.  If an error occurred, that error code is returned.
 *
 * The returned key is considered to be selected and the certificate
 * can be detched via keydb_get_cert.  */
gpg_error_t
keydb_search (ctrl_t ctrl, KEYDB_HANDLE hd,
              KEYDB_SEARCH_DESC *desc, size_t ndesc)
{
  gpg_error_t err = gpg_error (GPG_ERR_EOF);
  unsigned long skipped;
  int i;

  if (!hd)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!any_registered && !hd->use_keyboxd)
    {
      gpgsm_status_with_error (ctrl, STATUS_ERROR, "keydb_search",
                               gpg_error (GPG_ERR_KEYRING_OPEN));
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  if (DBG_CLOCK)
    log_clock ("%s: enter (hd=%p)\n", __func__, hd);

  if (DBG_LOOKUP)
    {
      log_debug ("%s: %zd search description(s):\n", __func__, ndesc);
      for (i = 0; i < ndesc; i ++)
        {
          char *t = keydb_search_desc_dump (&desc[i]);
          log_debug ("%s:   %d: %s\n", __func__, i, t);
          xfree (t);
        }
    }

  if (hd->use_keyboxd)
    {
      char line[ASSUAN_LINELENGTH];

      /* Clear the result objects.  */
      if (hd->kbl->search_result.buf)
        {
          xfree (hd->kbl->search_result.buf);
          hd->kbl->search_result.buf = NULL;
          hd->kbl->search_result.len = 0;
        }

      /* Check whether this is a NEXT search.  */
      if (!hd->kbl->need_search_reset)
        {
          /* A reset was not requested thus continue the search.  The
           * keyboxd keeps the context of the search and thus the NEXT
           * operates on the last search pattern.  This is the way how
           * we always used the keydb functions.  In theory we were
           * able to modify the search pattern between searches but
           * that is not anymore supported by keyboxd and a cursory
           * check does not show that we actually made use of that
           * misfeature.  */
          snprintf (line, sizeof line, "NEXT --x509");
          goto do_search;
        }

      hd->kbl->need_search_reset = 0;

      if (!ndesc)
        {
          err = gpg_error (GPG_ERR_INV_ARG);
          goto leave;
        }

      /* FIXME: Implement --multi */
      switch (desc->mode)
        {
        case KEYDB_SEARCH_MODE_EXACT:
          snprintf (line, sizeof line, "SEARCH --x509 =%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_SUBSTR:
          snprintf (line, sizeof line, "SEARCH --x509 *%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_MAIL:
          snprintf (line, sizeof line, "SEARCH --x509 <%s",
                    desc[0].u.name + (desc[0].u.name[0] == '<'));
          break;

        case KEYDB_SEARCH_MODE_MAILSUB:
          snprintf (line, sizeof line, "SEARCH --x509 @%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_MAILEND:
          snprintf (line, sizeof line, "SEARCH --x509 .%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_WORDS:
          snprintf (line, sizeof line, "SEARCH --x509 +%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_SHORT_KID:
          snprintf (line, sizeof line, "SEARCH --x509 0x%08lX",
                    (ulong)desc->u.kid[1]);
          break;

        case KEYDB_SEARCH_MODE_LONG_KID:
          snprintf (line, sizeof line, "SEARCH --x509 0x%08lX%08lX",
                    (ulong)desc->u.kid[0], (ulong)desc->u.kid[1]);
          break;

        case KEYDB_SEARCH_MODE_FPR:
          {
            unsigned char hexfpr[MAX_FINGERPRINT_LEN * 2 + 1];
            log_assert (desc[0].fprlen <= MAX_FINGERPRINT_LEN);
            bin2hex (desc[0].u.fpr, desc[0].fprlen, hexfpr);
            snprintf (line, sizeof line, "SEARCH --x509 0x%s", hexfpr);
          }
          break;

        case KEYDB_SEARCH_MODE_ISSUER:
          snprintf (line, sizeof line, "SEARCH --x509 #/%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_ISSUER_SN:
          if (desc[0].snhex)
            snprintf (line, sizeof line, "SEARCH --x509 #%.*s/%s",
                      (int)desc[0].snlen, desc[0].sn, desc[0].u.name);
          else
            {
              char *hexsn = bin2hex (desc[0].sn, desc[0].snlen, NULL);
              if (!hexsn)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }
              snprintf (line, sizeof line, "SEARCH --x509 #%s/%s",
                        hexsn, desc[0].u.name);
              xfree (hexsn);
            }
          break;

        case KEYDB_SEARCH_MODE_SN:
          snprintf (line, sizeof line, "SEARCH --x509 #%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_SUBJECT:
          snprintf (line, sizeof line, "SEARCH --x509 /%s", desc[0].u.name);
          break;

        case KEYDB_SEARCH_MODE_KEYGRIP:
          {
            unsigned char hexgrip[KEYGRIP_LEN * 2 + 1];
            bin2hex (desc[0].u.grip, KEYGRIP_LEN, hexgrip);
            snprintf (line, sizeof line, "SEARCH --x509 &%s", hexgrip);
          }
          break;

        case KEYDB_SEARCH_MODE_UBID:
          {
            unsigned char hexubid[UBID_LEN * 2 + 1];
            bin2hex (desc[0].u.ubid, UBID_LEN, hexubid);
            snprintf (line, sizeof line, "SEARCH --x509 ^%s", hexubid);
          }
          break;

        case KEYDB_SEARCH_MODE_FIRST:
          snprintf (line, sizeof line, "SEARCH --x509");
          break;

        case KEYDB_SEARCH_MODE_NEXT:
          log_debug ("%s: mode next - we should not get to here!\n", __func__);
          snprintf (line, sizeof line, "NEXT --x509");
          break;

        default:
          err = gpg_error (GPG_ERR_INV_ARG);
          goto leave;
        }

    do_search:
      hd->last_ubid_valid = 0;
      /* To avoid silent truncation we error out on a too long line.  */
      if (strlen (line) + 5 >= sizeof line)
        err = gpg_error (GPG_ERR_ASS_LINE_TOO_LONG);
      else
        err = kbx_client_data_cmd (hd->kbl->kcd, line, search_status_cb, hd);
      if (!err && !(err = kbx_client_data_wait (hd->kbl->kcd,
                                                &hd->kbl->search_result.buf,
                                                &hd->kbl->search_result.len)))
        {
          /* if (hd->last_ubid_valid) */
          /*   log_printhex (hd->last_ubid, 20, "found UBID%s:", */
          /*                 hd->last_is_ephemeral? "(ephemeral)":""); */
        }

    }
  else /* Local keyring search.  */
    {
      while (gpg_err_code (err) == GPG_ERR_EOF
             && hd->current >= 0 && hd->current < hd->used)
        {
          switch (hd->active[hd->current].type)
            {
            case KEYDB_RESOURCE_TYPE_NONE:
              BUG(); /* we should never see it here */
              break;
            case KEYDB_RESOURCE_TYPE_KEYBOX:
              err = keybox_search (hd->active[hd->current].u.kr, desc, ndesc,
                                   KEYBOX_BLOBTYPE_X509,
                                   NULL, &skipped);
              if (err == -1) /* Map legacy code.  */
                err = gpg_error (GPG_ERR_EOF);
              break;
            }

          if (DBG_LOOKUP)
            log_debug ("%s: searched %s (resource %d of %d) => %s\n",
                       __func__,
                       hd->active[hd->current].type==KEYDB_RESOURCE_TYPE_KEYBOX
                       ? "keybox" : "unknown type",
                       hd->current, hd->used, gpg_strerror (err));

          if (gpg_err_code (err) == GPG_ERR_EOF)
            { /* EOF -> switch to next resource */
              hd->current++;
            }
          else if (!err)
            hd->found = hd->current;
        }
    }

 leave:
  /* The NOTHING_FOUND error is triggered by a NEXT command.  */
  if (gpg_err_code (err) == GPG_ERR_EOF
      || gpg_err_code (err) == GPG_ERR_NOTHING_FOUND)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  if (DBG_CLOCK)
    log_clock ("%s: leave (%s)\n", __func__, gpg_strerror (err));
  return err;
}


int
keydb_search_first (ctrl_t ctrl, KEYDB_HANDLE hd)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_next (ctrl_t ctrl, KEYDB_HANDLE hd)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_NEXT;
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_kid (ctrl_t ctrl, KEYDB_HANDLE hd, u32 *kid)
{
  KEYDB_SEARCH_DESC desc;

  (void)kid;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0] = kid[0];
  desc.u.kid[1] = kid[1];
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_fpr (ctrl_t ctrl, KEYDB_HANDLE hd, const byte *fpr)
{
  KEYDB_SEARCH_DESC desc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FPR;
  memcpy (desc.u.fpr, fpr, 20);
  desc.fprlen = 20;
  return keydb_search (ctrl, hd, &desc, 1);
}

int
keydb_search_issuer (ctrl_t ctrl, KEYDB_HANDLE hd, const char *issuer)
{
  KEYDB_SEARCH_DESC desc;
  int rc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_ISSUER;
  desc.u.name = issuer;
  rc = keydb_search (ctrl, hd, &desc, 1);
  return rc;
}

int
keydb_search_issuer_sn (ctrl_t ctrl, KEYDB_HANDLE hd,
                        const char *issuer, ksba_const_sexp_t serial)
{
  KEYDB_SEARCH_DESC desc;
  int rc;
  const unsigned char *s;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_ISSUER_SN;
  s = serial;
  if (*s !='(')
    return gpg_error (GPG_ERR_INV_VALUE);
  s++;
  for (desc.snlen = 0; digitp (s); s++)
    desc.snlen = 10*desc.snlen + atoi_1 (s);
  if (*s !=':')
    return gpg_error (GPG_ERR_INV_VALUE);
  desc.sn = s+1;
  desc.u.name = issuer;
  rc = keydb_search (ctrl, hd, &desc, 1);
  return rc;
}

int
keydb_search_subject (ctrl_t ctrl, KEYDB_HANDLE hd, const char *name)
{
  KEYDB_SEARCH_DESC desc;
  int rc;

  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_SUBJECT;
  desc.u.name = name;
  rc = keydb_search (ctrl, hd, &desc, 1);
  return rc;
}



/* Store the certificate in the key DB but make sure that it does not
   already exists.  We do this simply by comparing the fingerprint.
   If EXISTED is not NULL it will be set to true if the certificate
   was already in the DB. */
int
keydb_store_cert (ctrl_t ctrl, ksba_cert_t cert, int ephemeral, int *existed)
{
  KEYDB_HANDLE kh;
  int rc;
  unsigned char fpr[20];

  if (existed)
    *existed = 0;

  if (!gpgsm_get_fingerprint (cert, 0, fpr, NULL))
    {
      log_error (_("failed to get the fingerprint\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  kh = keydb_new (ctrl);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      return gpg_error (GPG_ERR_ENOMEM);;
    }

  /* Set the ephemeral flag so that the search looks at all
     records.  */
  keydb_set_ephemeral (kh, 1);

  if (!kh->use_keyboxd)
    {
      rc = lock_all (kh);
      if (rc)
        return rc;
    }

  rc = keydb_search_fpr (ctrl, kh, fpr);
  if (gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
    {
      keydb_release (kh);
      if (!rc)
        {
          if (existed)
            *existed = 1;
          if (!ephemeral)
            {
              /* Remove ephemeral flags from existing certificate to "store"
                 it permanently. */
              rc = keydb_set_cert_flags (ctrl, cert, 1, KEYBOX_FLAG_BLOB, 0,
                                         KEYBOX_FLAG_BLOB_EPHEMERAL, 0);
              if (rc)
                {
                  log_error ("clearing ephemeral flag failed: %s\n",
                             gpg_strerror (rc));
                  return rc;
                }
            }
          return 0; /* okay */
        }
      log_error (_("problem looking for existing certificate: %s\n"),
                 gpg_strerror (rc));
      return rc;
    }

  /* Reset the ephemeral flag if not requested.  */
  if (!ephemeral)
    keydb_set_ephemeral (kh, 0);

  rc = keydb_locate_writable (kh, 0);
  if (rc)
    {
      log_error (_("error finding writable keyDB: %s\n"), gpg_strerror (rc));
      keydb_release (kh);
      return rc;
    }

  rc = keydb_insert_cert (kh, cert);
  if (rc)
    {
      log_error (_("error storing certificate: %s\n"), gpg_strerror (rc));
      keydb_release (kh);
      return rc;
    }
  keydb_release (kh);
  return 0;
}


/* This is basically keydb_set_flags but it implements a complete
   transaction by locating the certificate in the DB and updating the
   flags. */
gpg_error_t
keydb_set_cert_flags (ctrl_t ctrl, ksba_cert_t cert, int ephemeral,
                      int which, int idx,
                      unsigned int mask, unsigned int value)
{
  KEYDB_HANDLE kh;
  gpg_error_t err;
  unsigned char fpr[20];
  unsigned int old_value;

  if (!gpgsm_get_fingerprint (cert, 0, fpr, NULL))
    {
      log_error (_("failed to get the fingerprint\n"));
      return gpg_error (GPG_ERR_GENERAL);
    }

  kh = keydb_new (ctrl);
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      return gpg_error (GPG_ERR_ENOMEM);;
    }

  if (ephemeral)
    keydb_set_ephemeral (kh, 1);

  if (!kh->use_keyboxd)
    {
      err = keydb_lock (kh);
      if (err)
        {
          log_error (_("error locking keybox: %s\n"), gpg_strerror (err));
          keydb_release (kh);
          return err;
        }
    }

  err = keydb_search_fpr (ctrl, kh, fpr);
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
        log_error (_("problem re-searching certificate: %s\n"),
                   gpg_strerror (err));
      keydb_release (kh);
      return err;
    }

  err = keydb_get_flags (kh, which, idx, &old_value);
  if (err)
    {
      log_error (_("error getting stored flags: %s\n"), gpg_strerror (err));
      keydb_release (kh);
      return err;
    }

  value = ((old_value & ~mask) | (value & mask));

  if (value != old_value)
    {
      err = keydb_set_flags (kh, which, idx, value);
      if (err)
        {
          log_error (_("error storing flags: %s\n"), gpg_strerror (err));
          keydb_release (kh);
          return err;
        }
    }

  keydb_release (kh);
  return 0;
}


/* Reset all the certificate flags we have stored with the certificates
   for performance reasons. */
void
keydb_clear_some_cert_flags (ctrl_t ctrl, strlist_t names)
{
  gpg_error_t err;
  KEYDB_HANDLE hd = NULL;
  KEYDB_SEARCH_DESC *desc = NULL;
  int ndesc;
  strlist_t sl;
  int rc=0;
  unsigned int old_value, value;

  (void)ctrl;

  hd = keydb_new (ctrl);
  if (!hd)
    {
      log_error ("keydb_new failed\n");
      goto leave;
    }

  if (!names)
    ndesc = 1;
  else
    {
      for (sl=names, ndesc=0; sl; sl = sl->next, ndesc++)
        ;
    }

  desc = xtrycalloc (ndesc, sizeof *desc);
  if (!ndesc)
    {
      log_error ("allocating memory failed: %s\n",
                 gpg_strerror (out_of_core ()));
      goto leave;
    }

  if (!names)
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  else
    {
      for (ndesc=0, sl=names; sl; sl = sl->next)
        {
          rc = classify_user_id (sl->d, desc+ndesc, 0);
          if (rc)
            log_error ("key '%s' not found: %s\n", sl->d, gpg_strerror (rc));
          else
            ndesc++;
        }
    }

  if (!hd->use_keyboxd)
    {
      err = keydb_lock (hd);
      if (err)
        {
          log_error (_("error locking keybox: %s\n"), gpg_strerror (err));
          goto leave;
        }
    }

  while (!(rc = keydb_search (ctrl, hd, desc, ndesc)))
    {
      if (!names)
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      err = keydb_get_flags (hd, KEYBOX_FLAG_VALIDITY, 0, &old_value);
      if (err)
        {
          log_error (_("error getting stored flags: %s\n"),
                     gpg_strerror (err));
          goto leave;
        }

      value = (old_value & ~VALIDITY_REVOKED);
      if (value != old_value)
        {
          err = keydb_set_flags (hd, KEYBOX_FLAG_VALIDITY, 0, value);
          if (err)
            {
              log_error (_("error storing flags: %s\n"), gpg_strerror (err));
              goto leave;
            }
        }
    }
  if (rc && gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
    log_error ("keydb_search failed: %s\n", gpg_strerror (rc));

 leave:
  xfree (desc);
  keydb_release (hd);
}
