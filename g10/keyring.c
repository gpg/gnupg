/* keyring.c - keyring file handling
 * Copyright (C) 1998-2010 Free Software Foundation, Inc.
 * Copyright (C) 1997-2015 Werner Koch
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
#include <sys/types.h>
#include <sys/stat.h>

#include "gpg.h"
#include "../common/util.h"
#include "keyring.h"
#include "packet.h"
#include "keydb.h"
#include "options.h"
#include "main.h" /*for check_key_signature()*/
#include "../common/i18n.h"
#include "../kbx/keybox.h"


typedef struct keyring_resource *KR_RESOURCE;
struct keyring_resource
{
  struct keyring_resource *next;
  int read_only;
  dotlock_t lockhd;
  int is_locked;
  int did_full_scan;
  char fname[1];
};
typedef struct keyring_resource const * CONST_KR_RESOURCE;

static KR_RESOURCE kr_resources;

struct keyring_handle
{
  CONST_KR_RESOURCE resource;
  struct {
    CONST_KR_RESOURCE kr;
    IOBUF iobuf;
    int eof;
    int error;
  } current;
  struct {
    CONST_KR_RESOURCE kr;
    off_t offset;
    size_t pk_no;
    size_t uid_no;
    unsigned int n_packets; /*used for delete and update*/
  } found, saved_found;
  struct {
    char *name;
    char *pattern;
  } word_match;
};

/* The number of extant handles.  */
static int active_handles;

static int do_copy (int mode, const char *fname, KBNODE root,
                    off_t start_offset, unsigned int n_packets );



/* We keep a cache of entries that we have entered in the DB.  This
   includes not only public keys, but also subkeys.

   Note: we'd like to keep the offset of the items that are present,
   however, this doesn't work, because another concurrent GnuPG
   process could modify the keyring.  */
struct key_present {
  struct key_present *next;
  u32 kid[2];
};

/* For the hash table, we use separate chaining with linked lists.
   This means that we have an array of N linked lists (buckets), which
   is indexed by KEYID[1] mod N.  Elements present in the keyring will
   be on the list; elements not present in the keyring will not be on
   the list.

   Note: since the hash table stores both present and not present
   information, it cannot be used until we complete a full scan of the
   keyring.  This is indicated by key_present_hash_ready.  */
typedef struct key_present **key_present_hash_t;
static key_present_hash_t key_present_hash;
static int key_present_hash_ready;

#define KEY_PRESENT_HASH_BUCKETS 2048

/* Allocate a new value for a key present hash table.  */
static struct key_present *
key_present_value_new (void)
{
  struct key_present *k;

  k = xmalloc_clear (sizeof *k);
  return k;
}

/* Allocate a new key present hash table.  */
static key_present_hash_t
key_present_hash_new (void)
{
  struct key_present **tbl;

  tbl = xmalloc_clear (KEY_PRESENT_HASH_BUCKETS * sizeof *tbl);
  return tbl;
}

/* Return whether the value described by KID if it is in the hash
   table.  Otherwise, return NULL.  */
static struct key_present *
key_present_hash_lookup (key_present_hash_t tbl, u32 *kid)
{
  struct key_present *k;

  for (k = tbl[(kid[1] % (KEY_PRESENT_HASH_BUCKETS - 1))]; k; k = k->next)
    if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
      return k;
  return NULL;
}

/* Add the key to the hash table TBL if it is not already present.  */
static void
key_present_hash_update (key_present_hash_t tbl, u32 *kid)
{
  struct key_present *k;

  for (k = tbl[(kid[1] % (KEY_PRESENT_HASH_BUCKETS - 1))]; k; k = k->next)
    {
      if (k->kid[0] == kid[0] && k->kid[1] == kid[1])
        return;
    }

  k = key_present_value_new ();
  k->kid[0] = kid[0];
  k->kid[1] = kid[1];
  k->next = tbl[(kid[1] % (KEY_PRESENT_HASH_BUCKETS - 1))];
  tbl[(kid[1] % (KEY_PRESENT_HASH_BUCKETS - 1))] = k;
}

/* Add all the keys (public and subkeys) present in the keyblock to
   the hash TBL.  */
static void
key_present_hash_update_from_kb (key_present_hash_t tbl, KBNODE node)
{
  for (; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          u32 aki[2];
          keyid_from_pk (node->pkt->pkt.public_key, aki);
          key_present_hash_update (tbl, aki);
        }
    }
}

/*
 * Register a filename for plain keyring files.  ptr is set to a
 * pointer to be used to create a handles etc, or the already-issued
 * pointer if it has already been registered.  The function returns 1
 * if a new keyring was registered.
*/
int
keyring_register_filename (const char *fname, int read_only, void **ptr)
{
    KR_RESOURCE kr;

    if (active_handles)
      /* There are open handles.  */
      BUG ();

    for (kr=kr_resources; kr; kr = kr->next)
      {
        if (same_file_p (kr->fname, fname))
	  {
            /* Already registered. */
            if (read_only)
              kr->read_only = 1;
            *ptr=kr;
	    return 0;
	  }
      }

    kr = xmalloc (sizeof *kr + strlen (fname));
    strcpy (kr->fname, fname);
    kr->read_only = read_only;
    kr->lockhd = NULL;
    kr->is_locked = 0;
    kr->did_full_scan = 0;
    /* keep a list of all issued pointers */
    kr->next = kr_resources;
    kr_resources = kr;

    /* create the offset table the first time a function here is used */
    if (!key_present_hash)
      key_present_hash = key_present_hash_new ();

    *ptr=kr;

    return 1;
}

int
keyring_is_writable (void *token)
{
  KR_RESOURCE r = token;

  return r? (r->read_only || !gnupg_access (r->fname, W_OK)) : 0;
}



/* Create a new handle for the resource associated with TOKEN.
   On error NULL is returned and ERRNO is set.
   The returned handle must be released using keyring_release (). */
KEYRING_HANDLE
keyring_new (void *token)
{
  KEYRING_HANDLE hd;
  KR_RESOURCE resource = token;

  log_assert (resource);

  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return hd;
  hd->resource = resource;
  active_handles++;
  return hd;
}

void
keyring_release (KEYRING_HANDLE hd)
{
    if (!hd)
        return;
    log_assert (active_handles > 0);
    active_handles--;
    xfree (hd->word_match.name);
    xfree (hd->word_match.pattern);
    iobuf_close (hd->current.iobuf);
    xfree (hd);
}


/* Save the current found state in HD for later retrieval by
   keybox_pop_found_state.  Only one state may be saved.  */
void
keyring_push_found_state (KEYRING_HANDLE hd)
{
  hd->saved_found = hd->found;
  hd->found.kr = NULL;
}


/* Restore the saved found state in HD.  */
void
keyring_pop_found_state (KEYRING_HANDLE hd)
{
  hd->found = hd->saved_found;
  hd->saved_found.kr = NULL;
}


const char *
keyring_get_resource_name (KEYRING_HANDLE hd)
{
    if (!hd || !hd->resource)
      return NULL;
    return hd->resource->fname;
}


/*
 * Lock the keyring with the given handle, or unlock if YES is false.
 * We ignore the handle and lock all registered files.
 */
int
keyring_lock (KEYRING_HANDLE hd, int yes)
{
    KR_RESOURCE kr;
    int rc = 0;

    (void)hd;

    if (yes) {
        /* first make sure the lock handles are created */
        for (kr=kr_resources; kr; kr = kr->next) {
            if (!keyring_is_writable(kr))
                continue;
            if (!kr->lockhd) {
                kr->lockhd = dotlock_create (kr->fname, 0);
                if (!kr->lockhd) {
                    log_info ("can't allocate lock for '%s'\n", kr->fname );
                    rc = GPG_ERR_GENERAL;
                }
            }
        }
        if (rc)
            return rc;

        /* and now set the locks */
        for (kr=kr_resources; kr; kr = kr->next) {
            if (!keyring_is_writable(kr))
                continue;
            if (kr->is_locked)
                continue;

#ifdef HAVE_W32_SYSTEM
            /* Under Windows we need to CloseHandle the file before we
             * try to lock it.  This is because another process might
             * have taken the lock and is using keybox_file_rename to
             * rename the base file.  How if our dotlock_take below is
             * waiting for the lock but we have the base file still
             * open, keybox_file_rename will never succeed as we are
             * in a deadlock.  */
            iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0,
                         (char*)kr->fname);
#endif /*HAVE_W32_SYSTEM*/
            if (dotlock_take (kr->lockhd, -1) ) {
                log_info ("can't lock '%s'\n", kr->fname );
                rc = GPG_ERR_GENERAL;
            }
            else
                kr->is_locked = 1;
        }
    }

    if (rc || !yes) {
        for (kr=kr_resources; kr; kr = kr->next) {
            if (!keyring_is_writable(kr))
                continue;
            if (!kr->is_locked)
                continue;

            if (dotlock_release (kr->lockhd))
                log_info ("can't unlock '%s'\n", kr->fname );
            else
                kr->is_locked = 0;
        }
    }

    return rc;
}



/*
 * Return the last found keyblock.  Caller must free it.
 * The returned keyblock has the kbode flag bit 0 set for the node with
 * the public key used to locate the keyblock or flag bit 1 set for
 * the user ID node.
 */
int
keyring_get_keyblock (KEYRING_HANDLE hd, KBNODE *ret_kb)
{
    PACKET *pkt;
    struct parse_packet_ctx_s parsectx;
    int rc;
    KBNODE keyblock = NULL, node, lastnode;
    IOBUF a;
    int in_cert = 0;
    int pk_no = 0;
    int uid_no = 0;
    int save_mode;

    if (ret_kb)
        *ret_kb = NULL;

    if (!hd->found.kr)
        return -1; /* no successful search */

    a = iobuf_open (hd->found.kr->fname);
    if (!a)
      {
	log_error(_("can't open '%s'\n"), hd->found.kr->fname);
	return GPG_ERR_KEYRING_OPEN;
      }

    if (iobuf_seek (a, hd->found.offset) ) {
        log_error ("can't seek '%s'\n", hd->found.kr->fname);
	iobuf_close(a);
	return GPG_ERR_KEYRING_OPEN;
    }

    pkt = xmalloc (sizeof *pkt);
    init_packet (pkt);
    init_parse_packet (&parsectx, a);
    hd->found.n_packets = 0;
    lastnode = NULL;
    save_mode = set_packet_list_mode(0);
    while ((rc=parse_packet (&parsectx, pkt)) != -1) {
        hd->found.n_packets = parsectx.n_parsed_packets;
        if (gpg_err_code (rc) == GPG_ERR_UNKNOWN_PACKET) {
	    free_packet (pkt, &parsectx);
	    init_packet (pkt);
	    continue;
	}
        if (gpg_err_code (rc) == GPG_ERR_LEGACY_KEY)
          {
            if (in_cert)
              /* It is not this key that is problematic, but the
                 following key.  */
              {
                rc = 0;
                hd->found.n_packets --;
              }
            else
              /* Upper layer needs to handle this.  */
              {
              }
            break;
          }
	if (rc) {
            log_error ("keyring_get_keyblock: read error: %s\n",
                       gpg_strerror (rc) );
            rc = GPG_ERR_INV_KEYRING;
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
          case PKT_RING_TRUST:
          case PKT_OLD_COMMENT:
          case PKT_COMMENT:
          case PKT_GPG_CONTROL:
            break; /* Allowed by us.  */

          default:
	    log_info ("skipped packet of type %d in keyring\n",
                      (int)pkt->pkttype);
	    free_packet(pkt, &parsectx);
	    init_packet(pkt);
	    continue;
          }

        if (in_cert && (pkt->pkttype == PKT_PUBLIC_KEY
                        || pkt->pkttype == PKT_SECRET_KEY)) {
            hd->found.n_packets--; /* fix counter */
            break; /* ready */
        }

        in_cert = 1;
        node = new_kbnode (pkt);
        if (!keyblock)
          keyblock = lastnode = node;
        else
          {
            lastnode->next = node;
            lastnode = node;
          }
        switch (pkt->pkttype)
          {
          case PKT_PUBLIC_KEY:
          case PKT_PUBLIC_SUBKEY:
          case PKT_SECRET_KEY:
          case PKT_SECRET_SUBKEY:
            if (++pk_no == hd->found.pk_no)
              node->flag |= 1;
            break;

          case PKT_USER_ID:
            if (++uid_no == hd->found.uid_no)
              node->flag |= 2;
            break;

          default:
            break;
          }

        pkt = xmalloc (sizeof *pkt);
        init_packet(pkt);
    }
    set_packet_list_mode(save_mode);

    if (rc == -1 && keyblock)
	rc = 0; /* got the entire keyblock */

    if (rc || !ret_kb)
	release_kbnode (keyblock);
    else {
        *ret_kb = keyblock;
    }
    free_packet (pkt, &parsectx);
    deinit_parse_packet (&parsectx);
    xfree (pkt);
    iobuf_close(a);

    /* Make sure that future search operations fail immediately when
     * we know that we are working on a invalid keyring
     */
    if (gpg_err_code (rc) == GPG_ERR_INV_KEYRING)
        hd->current.error = rc;

    return rc;
}

int
keyring_update_keyblock (KEYRING_HANDLE hd, KBNODE kb)
{
    int rc;

    if (!hd->found.kr)
        return -1; /* no successful prior search */

    if (hd->found.kr->read_only)
      return gpg_error (GPG_ERR_EACCES);

    if (!hd->found.n_packets) {
        /* need to know the number of packets - do a dummy get_keyblock*/
        rc = keyring_get_keyblock (hd, NULL);
        if (rc) {
            log_error ("re-reading keyblock failed: %s\n", gpg_strerror (rc));
            return rc;
        }
        if (!hd->found.n_packets)
            BUG ();
    }

    /* The open iobuf isn't needed anymore and in fact is a problem when
       it comes to renaming the keyring files on some operating systems,
       so close it here */
    iobuf_close(hd->current.iobuf);
    hd->current.iobuf = NULL;

    /* do the update */
    rc = do_copy (3, hd->found.kr->fname, kb,
                  hd->found.offset, hd->found.n_packets );
    if (!rc) {
      if (key_present_hash)
        {
          key_present_hash_update_from_kb (key_present_hash, kb);
        }
      /* better reset the found info */
      hd->found.kr = NULL;
      hd->found.offset = 0;
    }
    return rc;
}

int
keyring_insert_keyblock (KEYRING_HANDLE hd, KBNODE kb)
{
    int rc;
    const char *fname;

    if (!hd)
        fname = NULL;
    else if (hd->found.kr)
      {
        fname = hd->found.kr->fname;
        if (hd->found.kr->read_only)
          return gpg_error (GPG_ERR_EACCES);
      }
    else if (hd->current.kr)
      {
        fname = hd->current.kr->fname;
        if (hd->current.kr->read_only)
          return gpg_error (GPG_ERR_EACCES);
      }
    else
        fname = hd->resource? hd->resource->fname:NULL;

    if (!fname)
        return GPG_ERR_GENERAL;

    /* Close this one otherwise we will lose the position for
     * a next search.  Fixme: it would be better to adjust the position
     * after the write operations.
     */
    iobuf_close (hd->current.iobuf);
    hd->current.iobuf = NULL;

    /* do the insert */
    rc = do_copy (1, fname, kb, 0, 0 );
    if (!rc && key_present_hash)
      {
        key_present_hash_update_from_kb (key_present_hash, kb);
      }

    return rc;
}


int
keyring_delete_keyblock (KEYRING_HANDLE hd)
{
    int rc;

    if (!hd->found.kr)
        return -1; /* no successful prior search */

    if (hd->found.kr->read_only)
      return gpg_error (GPG_ERR_EACCES);

    if (!hd->found.n_packets) {
        /* need to know the number of packets - do a dummy get_keyblock*/
        rc = keyring_get_keyblock (hd, NULL);
        if (rc) {
            log_error ("re-reading keyblock failed: %s\n", gpg_strerror (rc));
            return rc;
        }
        if (!hd->found.n_packets)
            BUG ();
    }

    /* close this one otherwise we will lose the position for
     * a next search.  Fixme: it would be better to adjust the position
     * after the write operations.
     */
    iobuf_close (hd->current.iobuf);
    hd->current.iobuf = NULL;

    /* do the delete */
    rc = do_copy (2, hd->found.kr->fname, NULL,
                  hd->found.offset, hd->found.n_packets );
    if (!rc) {
        /* better reset the found info */
        hd->found.kr = NULL;
        hd->found.offset = 0;
        /* Delete is a rare operations, so we don't remove the keys
         * from the offset table */
    }
    return rc;
}



/*
 * Start the next search on this handle right at the beginning
 */
int
keyring_search_reset (KEYRING_HANDLE hd)
{
    log_assert (hd);

    iobuf_close (hd->current.iobuf);
    hd->current.iobuf = NULL;
    hd->current.eof = 0;
    hd->current.error = 0;

    hd->found.kr = NULL;
    hd->found.offset = 0;

    if (hd->current.kr)
      iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0,
                   (char*)hd->current.kr->fname);
    hd->current.kr = NULL;

    return 0;
}


static int
prepare_search (KEYRING_HANDLE hd)
{
    if (hd->current.error) {
        /* If the last key was a legacy key, we simply ignore the error so that
           we can easily use search_next.  */
        if (gpg_err_code (hd->current.error) == GPG_ERR_LEGACY_KEY)
          {
            if (DBG_LOOKUP)
              log_debug ("%s: last error was GPG_ERR_LEGACY_KEY, clearing\n",
                         __func__);
            hd->current.error = 0;
          }
        else
          {
            if (DBG_LOOKUP)
              log_debug ("%s: returning last error: %s\n",
                         __func__, gpg_strerror (hd->current.error));
            return hd->current.error; /* still in error state */
          }
    }

    if (hd->current.kr && !hd->current.eof) {
        if ( !hd->current.iobuf )
          {
            if (DBG_LOOKUP)
              log_debug ("%s: missing iobuf!\n", __func__);
            return GPG_ERR_GENERAL; /* Position invalid after a modify.  */
          }
        return 0; /* okay */
    }

    if (!hd->current.kr && hd->current.eof)
      {
        if (DBG_LOOKUP)
          log_debug ("%s: EOF!\n", __func__);
        return -1; /* still EOF */
      }

    if (!hd->current.kr) { /* start search with first keyring */
        hd->current.kr = hd->resource;
        if (!hd->current.kr) {
          if (DBG_LOOKUP)
            log_debug ("%s: keyring not available!\n", __func__);
          hd->current.eof = 1;
          return -1; /* keyring not available */
        }
        log_assert (!hd->current.iobuf);
    }
    else { /* EOF */
        if (DBG_LOOKUP)
          log_debug ("%s: EOF\n", __func__);
        iobuf_close (hd->current.iobuf);
        hd->current.iobuf = NULL;
        hd->current.kr = NULL;
        hd->current.eof = 1;
        return -1;
    }

    hd->current.eof = 0;
    hd->current.iobuf = iobuf_open (hd->current.kr->fname);
    if (!hd->current.iobuf)
      {
        hd->current.error = gpg_error_from_syserror ();
        log_error(_("can't open '%s'\n"), hd->current.kr->fname );
        return hd->current.error;
      }

    return 0;
}


/* A map of the all characters valid used for word_match()
 * Valid characters are in this table converted to uppercase.
 * because the upper 128 bytes have special meaning, we assume
 * that they are all valid.
 * Note: We must use numerical values here in case that this program
 * will be converted to those little blue HAL9000s with their strange
 * EBCDIC character set (user ids are UTF-8).
 * wk 2000-04-13: Hmmm, does this really make sense, given the fact that
 * we can run gpg now on a S/390 running GNU/Linux, where the code
 * translation is done by the device drivers?
 */
static const byte word_match_chars[256] = {
  /* 00 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 08 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 10 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 18 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 20 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 28 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 30 */  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  /* 38 */  0x38, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 40 */  0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  /* 48 */  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
  /* 50 */  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  /* 58 */  0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 60 */  0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  /* 68 */  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
  /* 70 */  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  /* 78 */  0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00,
  /* 80 */  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  /* 88 */  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  /* 90 */  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  /* 98 */  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  /* a0 */  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  /* a8 */  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  /* b0 */  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
  /* b8 */  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  /* c0 */  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  /* c8 */  0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
  /* d0 */  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
  /* d8 */  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
  /* e0 */  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  /* e8 */  0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  /* f0 */  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  /* f8 */  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/****************
 * Do a word match (original user id starts with a '+').
 * The pattern is already tokenized to a more suitable format:
 * There are only the real words in it delimited by one space
 * and all converted to uppercase.
 *
 * Returns: 0 if all words match.
 *
 * Note: This algorithm is a straightforward one and not very
 *	 fast.	It works for UTF-8 strings.  The uidlen should
 *	 be removed but due to the fact that old versions of
 *	 pgp don't use UTF-8 we still use the length; this should
 *	 be fixed in parse-packet (and replace \0 by some special
 *	 UTF-8 encoding)
 */
static int
word_match( const byte *uid, size_t uidlen, const byte *pattern )
{
    size_t wlen, n;
    const byte *p;
    const byte *s;

    for( s=pattern; *s; ) {
	do {
	    /* skip leading delimiters */
	    while( uidlen && !word_match_chars[*uid] )
		uid++, uidlen--;
	    /* get length of the word */
	    n = uidlen; p = uid;
	    while( n && word_match_chars[*p] )
		p++, n--;
	    wlen = p - uid;
	    /* and compare against the current word from pattern */
	    for(n=0, p=uid; n < wlen && s[n] != ' ' && s[n] ; n++, p++ ) {
		if( word_match_chars[*p] != s[n] )
		    break;
	    }
	    if( n == wlen && (s[n] == ' ' || !s[n]) )
		break; /* found */
	    uid += wlen;
	    uidlen -= wlen;
	} while( uidlen );
	if( !uidlen )
	    return -1; /* not found */

	/* advance to next word in pattern */
	for(; *s != ' ' && *s ; s++ )
	    ;
	if( *s )
	    s++ ;
    }
    return 0; /* found */
}

/****************
 * prepare word word_match; that is parse the name and
 * build the pattern.
 * caller has to free the returned pattern
 */
static char*
prepare_word_match (const byte *name)
{
    byte *pattern, *p;
    int c;

    /* the original length is always enough for the pattern */
    p = pattern = xmalloc(strlen(name)+1);
    do {
	/* skip leading delimiters */
	while( *name && !word_match_chars[*name] )
	    name++;
	/* copy as long as we don't have a delimiter and convert
	 * to uppercase.
	 * fixme: how can we handle utf8 uppercasing */
	for( ; *name &&  (c=word_match_chars[*name]); name++ )
	    *p++ = c;
	*p++ = ' '; /* append pattern delimiter */
    } while( *name );
    p[-1] = 0; /* replace last pattern delimiter by EOS */

    return pattern;
}




static int
compare_name (int mode, const char *name, const char *uid, size_t uidlen)
{
    int i;
    const char *s, *se;

    if (mode == KEYDB_SEARCH_MODE_EXACT) {
	for (i=0; name[i] && uidlen; i++, uidlen--)
	    if (uid[i] != name[i])
		break;
	if (!uidlen && !name[i])
	    return 0; /* found */
    }
    else if (mode == KEYDB_SEARCH_MODE_SUBSTR) {
	if (ascii_memistr( uid, uidlen, name ))
	    return 0;
    }
    else if (   mode == KEYDB_SEARCH_MODE_MAIL
             || mode == KEYDB_SEARCH_MODE_MAILSUB
             || mode == KEYDB_SEARCH_MODE_MAILEND) {
        int have_angles = 1;
	for (i=0, s= uid; i < uidlen && *s != '<'; s++, i++)
	    ;
	if (i == uidlen)
	  {
	    /* The UID is a plain addr-spec (cf. RFC2822 section 4.3).  */
	    have_angles = 0;
	    s = uid;
	    i = 0;
	  }
	if (i < uidlen)  {
	    if (have_angles)
	      {
		/* skip opening delim and one char and look for the closing one*/
		s++; i++;
		for (se=s+1, i++; i < uidlen && *se != '>'; se++, i++)
		  ;
	      }
	    else
	      se = s + uidlen;

	    if (i < uidlen) {
		i = se - s;
		if (mode == KEYDB_SEARCH_MODE_MAIL) {
		    if( strlen(name)-2 == i
                        && !ascii_memcasecmp( s, name+1, i) )
			return 0;
		}
		else if (mode == KEYDB_SEARCH_MODE_MAILSUB) {
		    if( ascii_memistr( s, i, name ) )
			return 0;
		}
		else { /* email from end */
		    /* nyi */
		}
	    }
	}
    }
    else if (mode == KEYDB_SEARCH_MODE_WORDS)
	return word_match (uid, uidlen, name);
    else
	BUG();

    return -1; /* not found */
}


/*
 * Search through the keyring(s), starting at the current position,
 * for a keyblock which contains one of the keys described in the DESC array.
 */
int
keyring_search (KEYRING_HANDLE hd, KEYDB_SEARCH_DESC *desc,
		size_t ndesc, size_t *descindex, int ignore_legacy)
{
  int rc;
  PACKET pkt;
  struct parse_packet_ctx_s parsectx;
  int save_mode;
  off_t offset, main_offset;
  size_t n;
  int need_uid, need_words, need_keyid, need_fpr, any_skip, need_grip;
  int pk_no, uid_no;
  int initial_skip;
  int scanned_from_start;
  int use_key_present_hash;
  PKT_user_id *uid = NULL;
  PKT_public_key *pk = NULL;
  u32 aki[2];
  unsigned char grip[KEYGRIP_LEN];

  /* figure out what information we need */
  need_uid = need_words = need_keyid = need_fpr = any_skip = need_grip = 0;
  for (n=0; n < ndesc; n++)
    {
      switch (desc[n].mode)
        {
        case KEYDB_SEARCH_MODE_EXACT:
        case KEYDB_SEARCH_MODE_SUBSTR:
        case KEYDB_SEARCH_MODE_MAIL:
        case KEYDB_SEARCH_MODE_MAILSUB:
        case KEYDB_SEARCH_MODE_MAILEND:
          need_uid = 1;
          break;
        case KEYDB_SEARCH_MODE_WORDS:
          need_uid = 1;
          need_words = 1;
          break;
        case KEYDB_SEARCH_MODE_SHORT_KID:
        case KEYDB_SEARCH_MODE_LONG_KID:
          need_keyid = 1;
          break;
        case KEYDB_SEARCH_MODE_FPR:
          need_fpr = 1;
          break;
        case KEYDB_SEARCH_MODE_FIRST:
          /* always restart the search in this mode */
          keyring_search_reset (hd);
          break;
        case KEYDB_SEARCH_MODE_KEYGRIP:
          need_grip = 1;
          break;
        default: break;
        }
      if (desc[n].skipfnc)
        {
          any_skip = 1;
          need_keyid = 1;
        }
    }

  if (DBG_LOOKUP)
    log_debug ("%s: need_uid = %d; need_words = %d; need_keyid = %d; need_fpr = %d; any_skip = %d\n",
               __func__, need_uid, need_words, need_keyid, need_fpr, any_skip);

  rc = prepare_search (hd);
  if (rc)
    {
      if (DBG_LOOKUP)
        log_debug ("%s: prepare_search failed: %s (%d)\n",
                   __func__, gpg_strerror (rc), gpg_err_code (rc));
      return rc;
    }

  use_key_present_hash = !!key_present_hash;
  if (!use_key_present_hash)
    {
      if (DBG_LOOKUP)
        log_debug ("%s: no offset table.\n", __func__);
    }
  else if (!key_present_hash_ready)
    {
      if (DBG_LOOKUP)
        log_debug ("%s: initializing offset table. (need_keyid: %d => 1)\n",
                   __func__, need_keyid);
      need_keyid = 1;
    }
  else if (ndesc == 1 && desc[0].mode == KEYDB_SEARCH_MODE_LONG_KID)
    {
      struct key_present *oi;

      if (DBG_LOOKUP)
        log_debug ("%s: look up by long key id, checking cache\n", __func__);

      oi = key_present_hash_lookup (key_present_hash, desc[0].u.kid);
      if (!oi)
        { /* We know that we don't have this key */
          if (DBG_LOOKUP)
            log_debug ("%s: cache says not present\n", __func__);
          hd->found.kr = NULL;
          hd->current.eof = 1;
          return -1;
        }
      /* We could now create a positive search status and return.
       * However the problem is that another instance of gpg may
       * have changed the keyring so that the offsets are not valid
       * anymore - therefore we don't do it
       */
    }

  if (need_words)
    {
      const char *name = NULL;

      log_debug ("word search mode does not yet work\n");
      /* FIXME: here is a long standing bug in our function and in addition we
         just use the first search description */
      for (n=0; n < ndesc && !name; n++)
        {
          if (desc[n].mode == KEYDB_SEARCH_MODE_WORDS)
            name = desc[n].u.name;
        }
      log_assert (name);
      if ( !hd->word_match.name || strcmp (hd->word_match.name, name) )
        {
          /* name changed */
          xfree (hd->word_match.name);
          xfree (hd->word_match.pattern);
          hd->word_match.name = xstrdup (name);
          hd->word_match.pattern = prepare_word_match (name);
        }
      /*  name = hd->word_match.pattern; */
    }

  init_packet(&pkt);
  save_mode = set_packet_list_mode(0);

  hd->found.kr = NULL;
  main_offset = 0;
  pk_no = uid_no = 0;
  initial_skip = 1; /* skip until we see the start of a keyblock */
  scanned_from_start = iobuf_tell (hd->current.iobuf) == 0;
  if (DBG_LOOKUP)
    log_debug ("%s: %ssearching from start of resource.\n",
               __func__, scanned_from_start ? "" : "not ");
  init_parse_packet (&parsectx, hd->current.iobuf);
  while (1)
    {
      byte afp[MAX_FINGERPRINT_LEN];
      size_t an;

      rc = search_packet (&parsectx, &pkt, &offset, need_uid);
      if (ignore_legacy && gpg_err_code (rc) == GPG_ERR_LEGACY_KEY)
        {
          free_packet (&pkt, &parsectx);
          continue;
        }
      if (rc)
        break;

      if (pkt.pkttype == PKT_PUBLIC_KEY  || pkt.pkttype == PKT_SECRET_KEY)
        {
          main_offset = offset;
          pk_no = uid_no = 0;
          initial_skip = 0;
        }
      if (initial_skip)
        {
          free_packet (&pkt, &parsectx);
          continue;
        }

      pk = NULL;
      uid = NULL;
      if (   pkt.pkttype == PKT_PUBLIC_KEY
             || pkt.pkttype == PKT_PUBLIC_SUBKEY
             || pkt.pkttype == PKT_SECRET_KEY
             || pkt.pkttype == PKT_SECRET_SUBKEY)
        {
          pk = pkt.pkt.public_key;
          ++pk_no;

          if (need_fpr)
            {
              fingerprint_from_pk (pk, afp, &an);
              while (an < 32) /* fill up to 32 bytes */
                afp[an++] = 0;
            }
          if (need_keyid)
            keyid_from_pk (pk, aki);
          if (need_grip)
            keygrip_from_pk (pk, grip);

          if (use_key_present_hash
              && !key_present_hash_ready
              && scanned_from_start)
            key_present_hash_update (key_present_hash, aki);
        }
      else if (pkt.pkttype == PKT_USER_ID)
        {
          uid = pkt.pkt.user_id;
          ++uid_no;
        }

      for (n=0; n < ndesc; n++)
        {
          switch (desc[n].mode) {
          case KEYDB_SEARCH_MODE_NONE:
            BUG ();
            break;
          case KEYDB_SEARCH_MODE_EXACT:
          case KEYDB_SEARCH_MODE_SUBSTR:
          case KEYDB_SEARCH_MODE_MAIL:
          case KEYDB_SEARCH_MODE_MAILSUB:
          case KEYDB_SEARCH_MODE_MAILEND:
          case KEYDB_SEARCH_MODE_WORDS:
            if ( uid && !compare_name (desc[n].mode,
                                       desc[n].u.name,
                                       uid->name, uid->len))
              goto found;
            break;

          case KEYDB_SEARCH_MODE_SHORT_KID:
            if (pk
               && ((pk->fprlen == 32 && desc[n].u.kid[1] == aki[0])
                   || (pk->fprlen != 32 && desc[n].u.kid[1] == aki[1])))
                goto found;
            break;
          case KEYDB_SEARCH_MODE_LONG_KID:
            if (pk && desc[n].u.kid[0] == aki[0]
                && desc[n].u.kid[1] == aki[1])
              goto found;
            break;
          case KEYDB_SEARCH_MODE_FPR:
            if (pk && desc[n].fprlen >= 16 && desc[n].fprlen <= 32
                && !memcmp (desc[n].u.fpr, afp, desc[n].fprlen))
              goto found;
            break;
          case KEYDB_SEARCH_MODE_FIRST:
            if (pk)
              goto found;
            break;
          case KEYDB_SEARCH_MODE_NEXT:
            if (pk)
              goto found;
            break;
          case KEYDB_SEARCH_MODE_KEYGRIP:
            if (pk && !memcmp (desc[n].u.grip, grip, KEYGRIP_LEN))
              goto found;
            break;
          default:
            rc = GPG_ERR_INV_ARG;
            goto found;
          }
	}
      free_packet (&pkt, &parsectx);
      continue;
    found:
      if (rc)
        goto real_found;

      if (DBG_LOOKUP)
        log_debug ("%s: packet starting at offset %lld matched descriptor %zu\n"
                   , __func__, (long long)offset, n);

      /* Record which desc we matched on.  Note this value is only
	 meaningful if this function returns with no errors. */
      if(descindex)
	*descindex=n;
      for (n=any_skip?0:ndesc; n < ndesc; n++)
        {
          if (desc[n].skipfnc
              && desc[n].skipfnc (desc[n].skipfncvalue, aki, uid_no))
            {
              if (DBG_LOOKUP)
                log_debug ("%s: skipping match: desc %zd's skip function returned TRUE\n",
                           __func__, n);
              break;
            }
        }
      if (n == ndesc)
        goto real_found;
      free_packet (&pkt, &parsectx);
    }
 real_found:
  if (!rc)
    {
      if (DBG_LOOKUP)
        log_debug ("%s: returning success\n", __func__);
      hd->found.offset = main_offset;
      hd->found.kr = hd->current.kr;
      hd->found.pk_no = pk? pk_no : 0;
      hd->found.uid_no = uid? uid_no : 0;
    }
  else if (rc == -1)
    {
      if (DBG_LOOKUP)
        log_debug ("%s: no matches (EOF)\n", __func__);

      hd->current.eof = 1;
      /* if we scanned all keyrings, we are sure that
       * all known key IDs are in our offtbl, mark that. */
      if (use_key_present_hash
          && !key_present_hash_ready
          && scanned_from_start)
        {
          KR_RESOURCE kr;

          /* First set the did_full_scan flag for this keyring.  */
          for (kr=kr_resources; kr; kr = kr->next)
            {
              if (hd->resource == kr)
                {
                  kr->did_full_scan = 1;
                  break;
                }
            }
          /* Then check whether all flags are set and if so, mark the
             offtbl ready */
          for (kr=kr_resources; kr; kr = kr->next)
            {
              if (!kr->did_full_scan)
                break;
            }
          if (!kr)
            key_present_hash_ready = 1;
        }
    }
  else
    {
      if (DBG_LOOKUP)
        log_debug ("%s: error encountered during search: %s (%d)\n",
                   __func__, gpg_strerror (rc), rc);
      hd->current.error = rc;
    }

  free_packet (&pkt, &parsectx);
  deinit_parse_packet (&parsectx);
  set_packet_list_mode(save_mode);
  return rc;
}


static int
create_tmp_file (const char *template,
                 char **r_bakfname, char **r_tmpfname, IOBUF *r_fp)
{
  gpg_error_t err;
  mode_t oldmask;

  err = keybox_tmp_names (template, 1, r_bakfname, r_tmpfname);
  if (err)
    return err;

  /* Create the temp file with limited access.  Note that the umask
     call is not anymore needed because iobuf_create now takes care of
     it.  However, it does not harm and thus we keep it.  */
  oldmask = umask (077);
  if (is_secured_filename (*r_tmpfname))
    {
      *r_fp = NULL;
      gpg_err_set_errno (EPERM);
    }
  else
    *r_fp = iobuf_create (*r_tmpfname, 1);
  umask (oldmask);
  if (!*r_fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't create '%s': %s\n"), *r_tmpfname, gpg_strerror (err));
      xfree (*r_tmpfname);
      *r_tmpfname = NULL;
      xfree (*r_bakfname);
      *r_bakfname = NULL;
    }

  return err;
}


static int
rename_tmp_file (const char *bakfname, const char *tmpfname, const char *fname)
{
  int rc = 0;
  int block = 0;

  /* Invalidate close caches.  */
  if (iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)tmpfname ))
    {
      rc = gpg_error_from_syserror ();
      goto fail;
    }
  iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)bakfname );
  iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname );

  /* First make a backup file. */
  block = 1;
  rc = gnupg_rename_file (fname, bakfname, &block);
  if (rc)
    goto fail;

  /* then rename the file */
  rc = gnupg_rename_file (tmpfname, fname, NULL);
  if (block)
    {
      gnupg_unblock_all_signals ();
      block = 0;
    }
  if (rc)
    {
      register_secured_file (fname);
      goto fail;
    }

  /* Now make sure the file has the same permissions as the original */
#ifndef HAVE_DOSISH_SYSTEM
  {
    struct stat statbuf;

    statbuf.st_mode=S_IRUSR | S_IWUSR;

    if (!gnupg_stat (bakfname, &statbuf) && !chmod (fname, statbuf.st_mode))
      ;
    else
      log_error ("WARNING: unable to restore permissions to '%s': %s",
                 fname, strerror(errno));
  }
#endif

  return 0;

 fail:
  if (block)
    gnupg_unblock_all_signals ();
  return rc;
}


static int
write_keyblock (IOBUF fp, KBNODE keyblock)
{
  KBNODE kbctx = NULL, node;
  int rc;

  while ( (node = walk_kbnode (keyblock, &kbctx, 0)) )
    {
      if ( (rc = build_packet_and_meta (fp, node->pkt) ))
        {
          log_error ("build_packet(%d) failed: %s\n",
                     node->pkt->pkttype, gpg_strerror (rc) );
          return rc;
        }
    }
  return 0;
}

/*
 * Walk over all public keyrings, check the signatures and replace the
 * keyring with a new one where the signature cache is then updated.
 * This is only done for the public keyrings.
 */
int
keyring_rebuild_cache (ctrl_t ctrl, void *token, int noisy)
{
  KEYRING_HANDLE hd;
  KEYDB_SEARCH_DESC desc;
  KBNODE keyblock = NULL, node;
  const char *lastresname = NULL, *resname;
  IOBUF tmpfp = NULL;
  char *tmpfilename = NULL;
  char *bakfilename = NULL;
  int rc;
  ulong count = 0, sigcount = 0;

  hd = keyring_new (token);
  if (!hd)
    return gpg_error_from_syserror ();
  memset (&desc, 0, sizeof desc);
  desc.mode = KEYDB_SEARCH_MODE_FIRST;

  rc=keyring_lock (hd, 1);
  if(rc)
    goto leave;

  for (;;)
    {
      rc = keyring_search (hd, &desc, 1, NULL, 1 /* ignore_legacy */);
      if (rc)
        break;  /* ready.  */

      desc.mode = KEYDB_SEARCH_MODE_NEXT;
      resname = keyring_get_resource_name (hd);
      if (lastresname != resname )
        { /* we have switched to a new keyring - commit changes */
          if (tmpfp)
            {
              if (iobuf_close (tmpfp))
                {
                  rc = gpg_error_from_syserror ();
                  log_error ("error closing '%s': %s\n",
                             tmpfilename, strerror (errno));
                  goto leave;
                }
              /* because we have switched resources, we can be sure that
               * the original file is closed */
              tmpfp = NULL;
            }
          /* Static analyzer note: BAKFILENAME is never NULL here
             because it is controlled by LASTRESNAME.  */
          rc = lastresname? rename_tmp_file (bakfilename, tmpfilename,
                                             lastresname) : 0;
          xfree (tmpfilename);  tmpfilename = NULL;
          xfree (bakfilename);  bakfilename = NULL;
          if (rc)
            goto leave;
          lastresname = resname;
          if (noisy && !opt.quiet)
            log_info (_("caching keyring '%s'\n"), resname);
          rc = create_tmp_file (resname, &bakfilename, &tmpfilename, &tmpfp);
          if (rc)
            goto leave;
        }

      release_kbnode (keyblock);
      rc = keyring_get_keyblock (hd, &keyblock);
      if (rc)
        {
          if (gpg_err_code (rc) == GPG_ERR_LEGACY_KEY)
            continue;  /* Skip legacy keys.  */
          log_error ("keyring_get_keyblock failed: %s\n", gpg_strerror (rc));
          goto leave;
        }
      if ( keyblock->pkt->pkttype != PKT_PUBLIC_KEY)
        {
          /* We had a few reports about corrupted keyrings; if we have
             been called directly from the command line we delete such
             a keyblock instead of bailing out.  */
          log_error ("unexpected keyblock found (pkttype=%d)%s\n",
                     keyblock->pkt->pkttype, noisy? " - deleted":"");
          if (noisy)
            continue;
          log_info ("Hint: backup your keys and try running '%s'\n",
                    "gpg --rebuild-keydb-caches");
          rc = gpg_error (GPG_ERR_INV_KEYRING);
          goto leave;
        }

      if (keyblock->pkt->pkt.public_key->version < 4)
        {
          /* We do not copy/cache v3 keys or any other unknown
             packets.  It is better to remove them from the keyring.
             The code required to keep them in the keyring would be
             too complicated.  Given that we do not touch the old
             secring.gpg a suitable backup for decryption of v3 stuff
             using an older gpg version will always be available.
             Note: This test is actually superfluous because we
             already acted upon GPG_ERR_LEGACY_KEY.      */
        }
      else
        {
          /* Check all signature to set the signature's cache flags. */
          for (node=keyblock; node; node=node->next)
            {
              /* Note that this doesn't cache the result of a
                 revocation issued by a designated revoker.  This is
                 because the pk in question does not carry the revkeys
                 as we haven't merged the key and selfsigs.  It is
                 questionable whether this matters very much since
                 there are very very few designated revoker revocation
                 packets out there. */
              if (node->pkt->pkttype == PKT_SIGNATURE)
                {
                  PKT_signature *sig=node->pkt->pkt.signature;

                  if(!opt.no_sig_cache && sig->flags.checked && sig->flags.valid
                     && (openpgp_md_test_algo(sig->digest_algo)
                         || openpgp_pk_test_algo(sig->pubkey_algo)))
                    sig->flags.checked=sig->flags.valid=0;
                  else
                    check_key_signature (ctrl, keyblock, node, NULL);

                  sigcount++;
                }
            }

          /* Write the keyblock to the temporary file.  */
          rc = write_keyblock (tmpfp, keyblock);
          if (rc)
            goto leave;

          if ( !(++count % 50) && noisy && !opt.quiet)
            log_info (ngettext("%lu keys cached so far (%lu signature)\n",
                               "%lu keys cached so far (%lu signatures)\n",
                               sigcount),
                      count, sigcount);
        }
    } /* end main loop */
  if (rc == -1)
    rc = 0;
  if (rc)
    {
      log_error ("keyring_search failed: %s\n", gpg_strerror (rc));
      goto leave;
    }

  if (noisy || opt.verbose)
    {
      log_info (ngettext("%lu key cached",
                         "%lu keys cached", count), count);
      log_printf (ngettext(" (%lu signature)\n",
                           " (%lu signatures)\n", sigcount), sigcount);
    }

  if (tmpfp)
    {
      if (iobuf_close (tmpfp))
        {
          rc = gpg_error_from_syserror ();
          log_error ("error closing '%s': %s\n",
                     tmpfilename, strerror (errno));
          goto leave;
        }
      /* because we have switched resources, we can be sure that
       * the original file is closed */
      tmpfp = NULL;
    }
  rc = lastresname? rename_tmp_file (bakfilename, tmpfilename,
                                     lastresname) : 0;
  xfree (tmpfilename);  tmpfilename = NULL;
  xfree (bakfilename);  bakfilename = NULL;

 leave:
  if (tmpfp)
    iobuf_cancel (tmpfp);
  xfree (tmpfilename);
  xfree (bakfilename);
  release_kbnode (keyblock);
  keyring_lock (hd, 0);
  keyring_release (hd);
  return rc;
}



/****************
 * Perform insert/delete/update operation.
 * mode 1 = insert
 *	2 = delete
 *	3 = update
 */
static int
do_copy (int mode, const char *fname, KBNODE root,
         off_t start_offset, unsigned int n_packets )
{
    gpg_err_code_t ec;
    IOBUF fp, newfp;
    int rc=0;
    char *bakfname = NULL;
    char *tmpfname = NULL;

    /* Open the source file. Because we do a rename, we have to check the
       permissions of the file */
    if ((ec = gnupg_access (fname, W_OK)))
      return gpg_error (ec);

    fp = iobuf_open (fname);
    if (mode == 1 && !fp && errno == ENOENT) {
	/* insert mode but file does not exist: create a new file */
	KBNODE kbctx, node;
	mode_t oldmask;

	oldmask=umask(077);
        if (is_secured_filename (fname)) {
            newfp = NULL;
            gpg_err_set_errno (EPERM);
        }
        else
            newfp = iobuf_create (fname, 1);
	umask(oldmask);
	if( !newfp )
	  {
            rc = gpg_error_from_syserror ();
	    log_error (_("can't create '%s': %s\n"), fname, strerror(errno));
	    return rc;
	  }
	if( !opt.quiet )
	    log_info(_("%s: keyring created\n"), fname );

	kbctx=NULL;
	while ( (node = walk_kbnode( root, &kbctx, 0 )) ) {
	    if( (rc = build_packet( newfp, node->pkt )) ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, gpg_strerror (rc) );
		iobuf_cancel(newfp);
		return rc;
	    }
	}
	if( iobuf_close(newfp) ) {
            rc = gpg_error_from_syserror ();
	    log_error ("%s: close failed: %s\n", fname, strerror(errno));
	    return rc;
	}
	return 0; /* ready */
    }

    if( !fp )
      {
        rc = gpg_error_from_syserror ();
	log_error(_("can't open '%s': %s\n"), fname, strerror(errno) );
	goto leave;
      }

    /* Create the new file.  */
    rc = create_tmp_file (fname, &bakfname, &tmpfname, &newfp);
    if (rc) {
	iobuf_close(fp);
	goto leave;
    }

    if( mode == 1 ) { /* insert */
	/* copy everything to the new file */
	rc = copy_all_packets (fp, newfp);
	if( rc != -1 ) {
	    log_error("%s: copy to '%s' failed: %s\n",
		      fname, tmpfname, gpg_strerror (rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
    }

    if( mode == 2 || mode == 3 ) { /* delete or update */
	/* copy first part to the new file */
	rc = copy_some_packets( fp, newfp, start_offset );
	if( rc ) { /* should never get EOF here */
	    log_error ("%s: copy to '%s' failed: %s\n",
                       fname, tmpfname, gpg_strerror (rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
	/* skip this keyblock */
	log_assert( n_packets );
	rc = skip_some_packets( fp, n_packets );
	if( rc ) {
	    log_error("%s: skipping %u packets failed: %s\n",
			    fname, n_packets, gpg_strerror (rc));
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
    }

    if( mode == 1 || mode == 3 ) { /* insert or update */
        rc = write_keyblock (newfp, root);
        if (rc) {
          iobuf_close(fp);
          iobuf_cancel(newfp);
          goto leave;
        }
    }

    if( mode == 2 || mode == 3 ) { /* delete or update */
	/* copy the rest */
	rc = copy_all_packets( fp, newfp );
	if( rc != -1 ) {
	    log_error("%s: copy to '%s' failed: %s\n",
		      fname, tmpfname, gpg_strerror (rc) );
	    iobuf_close(fp);
	    iobuf_cancel(newfp);
	    goto leave;
	}
    }

    /* close both files */
    if( iobuf_close(fp) ) {
        rc = gpg_error_from_syserror ();
	log_error("%s: close failed: %s\n", fname, strerror(errno) );
	goto leave;
    }
    if( iobuf_close(newfp) ) {
        rc = gpg_error_from_syserror ();
	log_error("%s: close failed: %s\n", tmpfname, strerror(errno) );
	goto leave;
    }

    rc = rename_tmp_file (bakfname, tmpfname, fname);

  leave:
    xfree(bakfname);
    xfree(tmpfname);
    return rc;
}
