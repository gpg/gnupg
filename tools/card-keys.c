/* card-keys.c - OpenPGP and CMS related functions for gpg-card
 * Copyright (C) 2019 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/ccparray.h"
#include "../common/exectool.h"
#include "../common/openpgpdefs.h"
#include "gpg-card.h"


/* It is quite common that all keys of an OpenPGP card belong to the
 * the same OpenPGP keyblock.  To avoid running several queries
 * despite that we already got the information with the previous
 * keyblock, we keep a small cache of of previous done queries.  */
static struct
{
  unsigned int lru;
  keyblock_t keyblock;
} keyblock_cache[5];



/* Helper for release_keyblock.  */
static void
do_release_keyblock (keyblock_t keyblock)
{
  pubkey_t pubkey;
  userid_t uid;

  while (keyblock)
    {
      keyblock_t keyblocknext = keyblock->next;
      pubkey = keyblock->keys;
      while (pubkey)
        {
          pubkey_t pubkeynext = pubkey->next;
          xfree (pubkey);
          pubkey = pubkeynext;
        }
      uid = keyblock->uids;
      while (uid)
        {
          userid_t uidnext = uid->next;
          xfree (uid->value);
          xfree (uid);
          uid = uidnext;
        }
      xfree (keyblock);
      keyblock = keyblocknext;
    }
}


/* Release a keyblock object.  */
void
release_keyblock (keyblock_t keyblock)
{
  static unsigned int lru_counter;
  unsigned int lru;
  int i, lru_idx;

  if (!keyblock)
    return;

  lru = (unsigned int)(-1);
  lru_idx = 0;
  for (i=0; i < DIM (keyblock_cache); i++)
    {
      if (!keyblock_cache[i].keyblock)
        {
          keyblock_cache[i].keyblock = keyblock;
          keyblock_cache[i].lru = ++lru_counter;
          goto leave;
        }
      if (keyblock_cache[i].lru < lru)
        {
          lru = keyblock_cache[i].lru;
          lru_idx = i;
        }
    }

  /* No free slot.  Replace one. */
  do_release_keyblock (keyblock_cache[lru_idx].keyblock);
  keyblock_cache[lru_idx].keyblock = keyblock;
  keyblock_cache[lru_idx].lru = ++lru_counter;

 leave:
  if (!lru_counter)
    {
      /* Wrapped around.  We simply clear the entire cache. */
      flush_keyblock_cache ();
    }
}


/* Flush the enire keyblock cache.  */
void
flush_keyblock_cache (void)
{
  int i;

  for (i=0; i < DIM (keyblock_cache); i++)
    {
      do_release_keyblock (keyblock_cache[i].keyblock);
      keyblock_cache[i].keyblock = NULL;
    }
}



/* Object to communicate with the status_cb. */
struct status_cb_s
{
  const char *pgm; /* Name of the program for debug purposes. */
  int no_pubkey;   /* Result flag.  */
};


/* Status callback helper for the exec functions.  */
static void
status_cb (void *opaque, const char *keyword, char *args)
{
  struct status_cb_s *c = opaque;
  const char *s;

  if (DBG_EXTPROG)
    log_debug ("%s: status: %s %s\n", c->pgm, keyword, args);

  if (!strcmp (keyword, "ERROR")
      && (s=has_leading_keyword (args, "keylist.getkey"))
      && gpg_err_code (atoi (s)) == GPG_ERR_NO_PUBKEY)
    {
      /* No public key was found.  gpg terminates with an error in
       * this case and we can't change that behaviour.  Instead we
       * detect this status and carry that error forward. */
      c->no_pubkey = 1;
    }

}


/* Helper for get_matching_keys to parse "pub" style records.  */
static gpg_error_t
parse_key_record (char **fields, int nfields, pubkey_t *r_pubkey)
{
  pubkey_t pubkey;

  (void)fields; /* Not yet used.  */
  (void)nfields;

  pubkey = xtrycalloc (1, sizeof *pubkey);
  if (!pubkey)
    return gpg_error_from_syserror ();

  if (nfields > 5)
    pubkey->created = parse_timestamp (fields[5], NULL);

  *r_pubkey = pubkey;
  return 0;
}


/* Run gpg or gpgsm to get a list of all keys matching the 20 byte
 * KEYGRIP.  PROTOCOL is one of or a combination of
 * GNUPG_PROTOCOL_OPENPGP and GNUPG_PROTOCOL_CMS.  On success a new
 * keyblock is stored at R_KEYBLOCK; on error NULL is stored there. */
gpg_error_t
get_matching_keys (const unsigned char *keygrip, int protocol,
                   keyblock_t *r_keyblock)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv;
  estream_t listing;
  char hexgrip[1 + (2*KEYGRIP_LEN) + 1];
  char *line = NULL;
  size_t length_of_line = 0;
  size_t maxlen;
  ssize_t len;
  char **fields = NULL;
  int nfields;
  int first_seen;
  int i;
  keyblock_t keyblock_head, *keyblock_tail, kb;
  pubkey_t pubkey, pk;
  size_t n;
  struct status_cb_s status_cb_parm;

  *r_keyblock = NULL;

  keyblock_head = NULL;
  keyblock_tail = &keyblock_head;
  kb = NULL;

  /* Shortcut to run a listing on both protocols.  */
  if ((protocol & GNUPG_PROTOCOL_OPENPGP) && (protocol & GNUPG_PROTOCOL_CMS))
    {
      err = get_matching_keys (keygrip, GNUPG_PROTOCOL_OPENPGP, &kb);
      if (!err || gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
        {
          if (!err)
            {
              *keyblock_tail = kb;
              keyblock_tail = &kb->next;
              kb = NULL;
            }
          err = get_matching_keys (keygrip, GNUPG_PROTOCOL_CMS, &kb);
          if (!err)
            {
              *keyblock_tail = kb;
              keyblock_tail = &kb->next;
              kb = NULL;
            }
          else if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
            err = 0;
        }
      if (err)
        release_keyblock (keyblock_head);
      else
        *r_keyblock = keyblock_head;
      return err;
    }

  /* Check that we have only one protocol.  */
  if (protocol != GNUPG_PROTOCOL_OPENPGP && protocol != GNUPG_PROTOCOL_CMS)
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  /* Try to get it from our cache. */
  for (i=0; i < DIM (keyblock_cache); i++)
    for (kb = keyblock_cache[i].keyblock; kb; kb = kb->next)
      if (kb->protocol == protocol)
        for (pk = kb->keys; pk; pk = pk->next)
          if (pk->grip_valid && !memcmp (pk->grip, keygrip, KEYGRIP_LEN))
            {
              *r_keyblock = keyblock_cache[i].keyblock;
              keyblock_cache[i].keyblock = NULL;
              return 0;
            }

  /* Open a memory stream.  */
  listing = es_fopenmem (0, "w+b");
  if (!listing)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      return err;
    }

  status_cb_parm.pgm = protocol == GNUPG_PROTOCOL_OPENPGP? "gpg":"gpgsm";
  status_cb_parm.no_pubkey = 0;

  hexgrip[0] = '&';
  bin2hex (keygrip, KEYGRIP_LEN, hexgrip+1);

  ccparray_init (&ccp, 0);

  if (opt.verbose > 1 || DBG_EXTPROG)
    ccparray_put (&ccp, "--verbose");
  else
    ccparray_put (&ccp, "--quiet");
  ccparray_put (&ccp, "--no-options");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--with-colons");
  ccparray_put (&ccp, "--with-keygrip");
  ccparray_put (&ccp, "--list-keys");
  ccparray_put (&ccp, hexgrip);

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_exec_tool_stream (protocol == GNUPG_PROTOCOL_OPENPGP?
                                opt.gpg_program : opt.gpgsm_program,
                                argv, NULL, NULL, listing, status_cb,
                                &status_cb_parm);
  if (err)
    {
      if (status_cb_parm.no_pubkey)
        err = gpg_error (GPG_ERR_NO_PUBKEY);
      else if (gpg_err_code (err) != GPG_ERR_GENERAL)
        log_error ("key listing failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  es_rewind (listing);
  first_seen = 0;
  maxlen = 8192; /* Set limit large enough for all escaped UIDs.  */
  while ((len = es_read_line (listing, &line, &length_of_line, &maxlen)) > 0)
    {
      if (!maxlen)
        {
          log_error ("received line too long\n");
          err = gpg_error (GPG_ERR_LINE_TOO_LONG);
          goto leave;
        }
      /* Strip newline and carriage return, if present.  */
      while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	line[--len] = '\0';

      xfree (fields);
      fields = strtokenize (line, ":");
      if (!fields)
        {
          err = gpg_error_from_syserror ();
          log_error ("strtokenize failed: %s\n", gpg_strerror (err));
          goto leave;
        }
      for (nfields = 0; fields[nfields]; nfields++)
        ;
      if (!nfields)
        {
          err = gpg_error (GPG_ERR_INV_ENGINE);
          goto leave;
        }

      /* Skip over all records until we reach a pub or sec.  */
      if (!first_seen
          && (!strcmp (fields[0], "pub") || !strcmp (fields[0], "sec")
              || !strcmp (fields[0], "crt") || !strcmp (fields[0], "crs")))
        first_seen = 1;
      if (!first_seen)
        continue;

      if (!strcmp (fields[0], "pub") || !strcmp (fields[0], "sec")
          || !strcmp (fields[0], "crt") || !strcmp (fields[0], "crs"))
        {
          if (kb)  /* Finish the current keyblock.  */
            {
              *keyblock_tail = kb;
              keyblock_tail = &kb->next;
            }
          kb = xtrycalloc (1, sizeof *kb);
          if (!kb)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          kb->protocol = protocol;
          err = parse_key_record (fields, nfields, &pubkey);
          if (err)
            goto leave;
          kb->keys = pubkey;
          pubkey = NULL;
        }
      else if (!strcmp (fields[0], "sub") || !strcmp (fields[0], "ssb"))
        {
          log_assert (kb && kb->keys);
          err = parse_key_record (fields, nfields, &pubkey);
          if (err)
            goto leave;
          for (pk = kb->keys; pk->next; pk = pk->next)
                ;
          pk->next = pubkey;
          pubkey = NULL;
        }
      else if (!strcmp (fields[0], "fpr") && nfields > 9)
        {
          log_assert (kb && kb->keys);
          n = strlen (fields[9]);
          if (n != 64 && n != 40 && n != 32)
            {
              log_debug ("bad length (%zu) in fpr record\n", n);
              err = gpg_error (GPG_ERR_INV_ENGINE);
              goto leave;
            }
          n /= 2;

          for (pk = kb->keys; pk->next; pk = pk->next)
            ;
          if (pk->fprlen)
            {
              log_debug ("too many fpr records\n");
              err = gpg_error (GPG_ERR_INV_ENGINE);
              goto leave;
            }
          log_assert (n <= sizeof pk->fpr);
          pk->fprlen = n;
          if (hex2bin (fields[9], pk->fpr, n) < 0)
            {
              log_debug ("bad chars in fpr record\n");
              err = gpg_error (GPG_ERR_INV_ENGINE);
              goto leave;
            }
        }
      else if (!strcmp (fields[0], "grp") && nfields > 9)
        {
          log_assert (kb && kb->keys);
          n = strlen (fields[9]);
          if (n != 2*KEYGRIP_LEN)
            {
              log_debug ("bad length (%zu) in grp record\n", n);
              err = gpg_error (GPG_ERR_INV_ENGINE);
              goto leave;
            }
          n /= 2;

          for (pk = kb->keys; pk->next; pk = pk->next)
            ;
          if (pk->grip_valid)
            {
              log_debug ("too many grp records\n");
              err = gpg_error (GPG_ERR_INV_ENGINE);
              goto leave;
            }
          if (hex2bin (fields[9], pk->grip, KEYGRIP_LEN) < 0)
            {
              log_debug ("bad chars in fpr record\n");
              err = gpg_error (GPG_ERR_INV_ENGINE);
              goto leave;
            }
          pk->grip_valid = 1;
          if (!memcmp (pk->grip, keygrip, KEYGRIP_LEN))
            pk->requested = 1;
        }
      else if (!strcmp (fields[0], "uid") && nfields > 9)
        {
          userid_t uid, u;

          uid = xtrycalloc (1, sizeof *uid);
          if (!uid)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          uid->value = decode_c_string (fields[9]);
          if (!uid->value)
            {
              err = gpg_error_from_syserror ();
              xfree (uid);
              goto leave;
            }
          if (!kb->uids)
            kb->uids = uid;
          else
            {
              for (u = kb->uids; u->next; u = u->next)
                ;
              u->next = uid;
            }
        }
    }
  if (len < 0 || es_ferror (listing))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading memory stream\n");
      goto leave;
    }

  if (kb) /* Finish the current keyblock.  */
    {
      *keyblock_tail = kb;
      keyblock_tail = &kb->next;
      kb = NULL;
    }

  if (!keyblock_head)
    err = gpg_error (GPG_ERR_NO_PUBKEY);

 leave:
  if (err)
    release_keyblock (keyblock_head);
  else
    *r_keyblock = keyblock_head;
  xfree (kb);
  xfree (fields);
  es_free (line);
  xfree (argv);
  es_fclose (listing);
  return err;
}


void
dump_keyblock (keyblock_t keyblock)
{
  keyblock_t kb;
  pubkey_t pubkey;
  userid_t uid;

  for (kb = keyblock; kb; kb = kb->next)
    {
      log_info ("%s key:\n",
                 kb->protocol == GNUPG_PROTOCOL_OPENPGP? "OpenPGP":"X.509");
      for (pubkey = kb->keys; pubkey; pubkey = pubkey->next)
        {
          log_info ("  grip: ");
          if (pubkey->grip_valid)
            log_printhex (pubkey->grip, KEYGRIP_LEN, NULL);
          log_printf ("%s\n", pubkey->requested? " (*)":"");

          log_info ("   fpr: ");
          log_printhex (pubkey->fpr, pubkey->fprlen, "");
        }
      for (uid = kb->uids; uid; uid = uid->next)
        {
          log_info ("   uid: %s\n", uid->value);
        }
    }
}



gpg_error_t
test_get_matching_keys (const char *hexgrip)
{
  gpg_error_t err;
  unsigned char grip[KEYGRIP_LEN];
  keyblock_t keyblock;

  if (strlen (hexgrip) != 40)
    {
      log_error ("error: invalid keygrip\n");
      return 0;
    }
  if (hex2bin (hexgrip, grip, sizeof grip) < 0)
    {
      log_error ("error: bad kegrip\n");
      return 0;
    }
  err = get_matching_keys (grip,
                           (GNUPG_PROTOCOL_OPENPGP | GNUPG_PROTOCOL_CMS),
                           &keyblock);
  if (err)
    {
      log_error ("get_matching_keys failed: %s\n", gpg_strerror (err));
      return err;
    }

  dump_keyblock (keyblock);
  release_keyblock (keyblock);
  return 0;
}




struct export_key_status_parm_s
{
  const char *fpr;
  int found;
  int count;
};


static void
export_key_status_cb (void *opaque, const char *keyword, char *args)
{
  struct export_key_status_parm_s *parm = opaque;

  if (!strcmp (keyword, "EXPORTED"))
    {
      parm->count++;
      if (!ascii_strcasecmp (args, parm->fpr))
        parm->found = 1;
    }
}


/* Get a key by fingerprint from gpg's keyring.  The binary key is
 * returned as a new memory stream at R_KEY.  */
gpg_error_t
get_minimal_openpgp_key (estream_t *r_key, const char *fingerprint)
{
  gpg_error_t err;
  ccparray_t ccp;
  const char **argv = NULL;
  estream_t key = NULL;
  struct export_key_status_parm_s parm = { NULL };

  *r_key = NULL;

  key = es_fopenmem (0, "w+b");
  if (!key)
    {
      err = gpg_error_from_syserror ();
      log_error ("error allocating memory buffer: %s\n", gpg_strerror (err));
      goto leave;
    }

  ccparray_init (&ccp, 0);

  ccparray_put (&ccp, "--no-options");
  if (!opt.verbose)
    ccparray_put (&ccp, "--quiet");
  else if (opt.verbose > 1)
    ccparray_put (&ccp, "--verbose");
  ccparray_put (&ccp, "--batch");
  ccparray_put (&ccp, "--status-fd=2");
  ccparray_put (&ccp, "--always-trust");
  ccparray_put (&ccp, "--no-armor");
  ccparray_put (&ccp, "--export-options=export-minimal");
  ccparray_put (&ccp, "--export");
  ccparray_put (&ccp, "--");
  ccparray_put (&ccp, fingerprint);

  ccparray_put (&ccp, NULL);
  argv = ccparray_get (&ccp, NULL);
  if (!argv)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  parm.fpr = fingerprint;
  err = gnupg_exec_tool_stream (opt.gpg_program, argv, NULL,
                                NULL, key,
                                export_key_status_cb, &parm);
  if (!err && parm.count > 1)
    err = gpg_error (GPG_ERR_TOO_MANY);
  else if (!err && !parm.found)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  if (err)
    {
      log_error ("export failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  es_rewind (key);
  *r_key = key;
  key = NULL;

 leave:
  es_fclose (key);
  xfree (argv);
  return err;
}
