/* mailing-list.c - Create a mailing list.
 * Copyright (C) 2015 Neal H. Walfield <neal@walfield.org>
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
#include <ctype.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "iobuf.h"
#include "keydb.h"
#include "util.h"
#include "main.h"
#include "ttyio.h"
#include "status.h"
#include "i18n.h"
#include "mailing-list.h"

void
kbnode_dump (KBNODE kb)
{
  for (; kb; kb = kb->next)
    {
      switch (kb->pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
          log_debug ("  public key: %s%s\n",
                     keystr (kb->pkt->pkt.public_key->keyid),
                     kb->pkt->pkt.public_key->has_expired ? " (expired)" : "");
          break;
        case PKT_PUBLIC_SUBKEY:
          log_debug ("  subkey: %s%s\n",
                     keystr (kb->pkt->pkt.public_key->keyid),
                     kb->pkt->pkt.public_key->has_expired ? " (expired)" : "");
          break;
        case PKT_USER_ID:
          log_debug ("  user id: %s\n",
                     kb->pkt->pkt.user_id->name);
          break;
        case PKT_SIGNATURE:
          {
            PKT_signature *sig = kb->pkt->pkt.signature;
            struct notation *notations = sig_to_notation (sig);

            log_debug ("    sig by %s: class %x\n",
                       keystr (sig->keyid), sig->sig_class);

            if (notations)
              {
                struct notation *niter;

                log_debug ("      Notations:\n");

                for (niter = notations; niter; niter = niter->next)
                  {
                    log_debug ("        %s=%s\n",
                               niter->name, niter->value);
                  }

                free_notation (notations);
              }
          }
          break;
        default:
          log_debug ("  unknown packet: %d\n", kb->pkt->pkttype);
          break;
        }
    }
}

/* Get a copy of all the session keys and store them in *DEKS and the
   total count in *NDEKS.  On success, the caller must xfree
   deksp.  */
gpg_error_t
mailing_list_get_subscriber_list_session_keys (ctrl_t ctrl, KBNODE kb,
                                               DEK **deksp, int *ndeksp)
{
  gpg_error_t err;

  PKT_public_key *pk = kb->pkt->pkt.public_key;
  KBNODE n;
  PKT_public_key *sk = NULL;

  /* We need to collect all of the keys before we can decrypt (in
     order to access key_i, we need key_{i-1} and we aren't guaranteed
     to read the keys in order).  Thus, we save the raw key data in
     this structure.  */
  struct keydata
  {
    byte *data;
    size_t blen;
  };
  /* We grow this dynamically.  */
  struct keydata *keydata = NULL;
  int nkeydata = 0;
  iobuf_t keydata_initial = iobuf_temp ();

  DEK *deks = NULL;

  int i;
  int last = -1;

  for (n = kb; n; n = n->next)
    if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      {
        sk = n->pkt->pkt.public_key;
        if (DBG_PACKET)
          log_debug ("%s: Processing signatures for %s\n",
                     __func__, keystr (sk->keyid));
      }
    else if (n->pkt->pkttype == PKT_SIGNATURE)
      {
        PKT_signature *sig = n->pkt->pkt.signature;
        struct notation *notations;
        struct notation *niter;
        struct keydata k = { 0, 0 };
        /* The session key that this key was encrypted with.  */
        int encrypted_with = -2;

        if (! sig->flags.notation)
          /* Nothing to do.  */
          continue;

        notations = sig_to_notation (sig);
        for (niter = notations; niter; niter = niter->next)
          {
            if (strcmp ("subscriber-list-session-key@gnupg.org",
                        niter->name) == 0)
              {
                k.data = xmalloc (niter->blen);
                memcpy (k.data, niter->bdat, niter->blen);
                k.blen = niter->blen;
              }
            else if (strcmp ("subscriber-list-session-key-encrypted-with@gnupg.org",
                             niter->name) == 0)
              {
                encrypted_with = atoi (niter->value);
              }
            else if (strcmp ("mailing-list@gnupg.org", niter->name) == 0)
              {
                encrypted_with = -1;
              }
            else if (strcmp ("subscriber-list-key@gnupg.org",
                             niter->name) == 0)
              /* An encrypted initial session key.  Just append it to
                 KEYDATA_INITIAL.  */
              {
                if (DBG_PACKET)
                  log_debug ("%s: Adding subscriber-list-key for %s\n",
                             __func__, keystr (sk->keyid));

                iobuf_write (keydata_initial, niter->bdat, niter->blen);
              }
          }

        if (k.blen)
          {
            /* ENCRYPTED_WITH is the index of the key that this key
               was encrypted with.  Thus, this key is index
               ENCRYPTED_WITH+1.  */
            int session_key_index = encrypted_with + 1;
            if (session_key_index < 0)
              log_bug ("Have subscriber-list-session-key, but no subscriber-list-session-key-encrypted-with notation!\n");

            if (DBG_PACKET)
              log_debug ("%s: Got subscriber-list-session-key %d\n",
                         __func__, session_key_index);

            if (session_key_index >= nkeydata)
              {
                int o = nkeydata;
                nkeydata = 2 * (1 + nkeydata);
                keydata = xrealloc (keydata, nkeydata * sizeof (*keydata));
                memset (&keydata[o], 0, (nkeydata - o) * sizeof (*keydata));
              }

            if (last < session_key_index)
              last = session_key_index;

            if (keydata[session_key_index].blen)
              log_bug ("Have multiple session keys with index %d?!?\n",
                       session_key_index);

            keydata[session_key_index] = k;

            if (session_key_index == 0)
              /* Add the initial key to the keydata_initial set.  */
              iobuf_write (keydata_initial, k.data, k.blen);
          }

        free_notation (notations);
      }

  if (! nkeydata)
    {
      log_error ("Malformed mailing list key: did not find any subscriber-list-session-key notations.\n");
      return gpg_error (GPG_ERR_INTERNAL);
    }

  nkeydata = last + 1;

  if (DBG_PACKET)
    log_debug ("%s: Found %d subscriber-list-session keys.\n",
               __func__, nkeydata);

  deks = xmalloc_clear (nkeydata * sizeof (*deks));

  last = -1;
  for (i = 0; i < nkeydata; i ++)
    if (keydata[i].blen)
      {
        iobuf_t input;

        if (last + 1 != i)
          {
            log_error ("Malformed mailing list key: missing subscriber-list-session-keys %d-%d\n",
                       last + 1, i - 1);
            return gpg_error (GPG_ERR_INTERNAL);
          }
        last = i;

        if (DBG_PACKET)
          log_debug ("%s: mailing list key %s: session key %d is %zd bytes\n",
                     __func__, keystr (pk->keyid), i, keydata[i].blen);

        if (i == 0)
          {
            input =
              iobuf_temp_with_content (iobuf_get_temp_buffer (keydata_initial),
                                       iobuf_get_temp_length (keydata_initial));
            iobuf_close (keydata_initial);
            keydata_initial = NULL;

            err = proc_pubkey_packet (ctrl, input, &deks[i]);
            if (err)
              log_error ("unable to extract mailing list decryption key: %s.  Try adding the key subscribed to the mailing list to --try-secret-key KEYID.\n",
                         gpg_strerror (err));
          }
        else
          {
            input = iobuf_temp_with_content (keydata[i].data, keydata[i].blen);
            if (! input)
              log_bug ("Failed to create iobuf");

            /* The encryption function (s2k) needs an ASCII password.
               We just hex encode the session key and use that.  */
            set_next_passphrase (bin2hex (deks[i - 1].key, deks[i - 1].keylen,
                                          NULL));
            err = proc_symkey_packet (ctrl, input, &deks[i]);

            if (err)
              log_error ("Failed to extract session key %d from subscriber-list-session-key notation: %s\n",
                         i, gpg_strerror (err));
          }

        if (err)
          break;
      }

  for (i = 0; i < nkeydata; i ++)
    xfree (keydata[i].data);
  xfree (keydata);
  if (keydata_initial)
    iobuf_close (keydata_initial);

  if (err)
    xfree (deks);
  else
    {
      *deksp = deks;
      *ndeksp = last + 1;
    }

  return err;
}

gpg_error_t
mailing_list_add_subscriber (ctrl_t ctrl, KBNODE ml_kb, const char *sub)
{
  gpg_error_t err;

  /* The mailing list's primary key.  */
  PKT_public_key *ml_pk = ml_kb->pkt->pkt.public_key;
  /* The subscriber's keyblock.  */
  KBNODE sub_kb = NULL;
  /* The subscriber's primary key.  */
  PKT_public_key *sub_pk = NULL;
  /* The subscriber's encryption key.  */
  PKT_public_key *sub_ek = NULL;
  /* The modified copy of SUB_EK that we add to the mailing list's
     keyblock.  */
  PKT_public_key *ml_ek = NULL;

  /* The first session key.  */
  DEK session_key_initial;
  /* The current session key.  */
  DEK session_key;
  /* The index of the current session key.  */
  int session_key_i;

  struct notation *notations = NULL;

  err = get_pubkey_byname (NULL, NULL, NULL, sub, &sub_kb, NULL, 0, 0);
  if (err)
    {
      log_error (_("Looking up key '%s': %s\n"),
                 sub, gpg_strerror (err));
      goto out;
    }

  sub_pk = sub_kb->pkt->pkt.public_key;

  {
    char keyid_str[20];
    char subkeyid_str[20];

    format_keyid (ml_pk->keyid, KF_DEFAULT, keyid_str, sizeof (keyid_str));
    format_keyid (sub_pk->keyid, KF_DEFAULT,
                  subkeyid_str, sizeof (subkeyid_str));

    if (DBG_PACKET)
      log_debug ("%s: addsub %s %s\n", __func__, keyid_str, subkeyid_str);
  }

  /* Find the encryption key to add and save it in SUB_EK.  */
  {
    KBNODE n;
    for (n = sub_kb; n; n = n->next)
      if (n->pkt->pkttype == PKT_PUBLIC_KEY
          || n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          PKT_public_key *ek = n->pkt->pkt.public_key;

          /* Ignore invalid keys.  */
          if (! (ek->pubkey_usage & PUBKEY_USAGE_ENC))
            {
              if (DBG_PACKET)
                log_debug ("%s: Ignoring subkey %s: no encryption capability.\n",
                           __func__, keystr (ek->keyid));
              continue;
            }

          if (ek->flags.revoked)
            {
              if (DBG_PACKET)
                log_debug ("%s: Ignoring subkey %s: revoked.\n",
                           __func__, keystr (ek->keyid));
              continue;
            }

          if (ek->has_expired)
            {
              if (DBG_PACKET)
                log_debug ("%s: Ignoring subkey %s: expired.\n",
                           __func__, keystr (ek->keyid));
              continue;
            }

          if(ek->flags.maybe_revoked && !ek->flags.revoked)
            log_info(_("WARNING: this key might be revoked (revocation key"
                       " not present)\n"));

          if (DBG_PACKET)
            log_debug ("%s: subkey %s is a candidate.\n",
                       __func__, keystr (ek->keyid));

          if (! sub_ek)
            {
              sub_ek = ek;
              continue;
            }
          else
            /* If there are multiple valid keys, then prefer the
               newest one.  */
            {
              if (ek->timestamp > sub_ek->timestamp)
                sub_ek = ek;

              if (DBG_PACKET)
                log_debug ("%s: Preferring subkey %s (it is newer).\n",
                           __func__, keystr (sub_ek->keyid));
            }
        }

    if (! sub_ek)
      {
        if (DBG_PACKET)
          log_debug ("%s: Key does support encryption.\n", __func__);
        err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
        goto out;
      }
    /* SUB_EK now holds the selected encryption key.  */
  }

  /* Make sure we haven't already added this encryption key.  Or, if
     we have and it is unsubscriber, resubscribe it.  */
  {
    KBNODE n;
    char sub_ek_fp[MAX_FINGERPRINT_LEN];
    size_t sub_ek_fplen;

    fingerprint_from_pk (sub_ek, sub_ek_fp, &sub_ek_fplen);

    for (n = ml_kb; n; n = n->next)
      {
        char fp[MAX_FINGERPRINT_LEN];
        size_t fplen;

        if (n->pkt->pkttype != PKT_PUBLIC_SUBKEY)
          continue;

        fingerprint_from_pk (n->pkt->pkt.public_key, fp, &fplen);
        if (sub_ek_fplen == fplen && memcmp (sub_ek_fp, fp, fplen) == 0)
          /* Got a match!  */
          break;
      }

    if (n)
      {
        /* XXX: If SUB was a subscriber, but is currently
           unsubscriber, readd.  */
        log_error ("%s is already a subscriber.\n", sub);
        goto out;
      }
  }


  /* Get the initial session key (we need to grant the new subscriber
     access to it) and the current session key (we need to encrypt the
     new subscriber's parameters with it).  */
  {
    DEK *deks = NULL;
    int ndeks;
    err = mailing_list_get_subscriber_list_session_keys (ctrl, ml_kb,
                                                         &deks, &ndeks);
    if (err)
      {
        log_error ("Failed to get session keys for mailing list: %s\n",
                   gpg_strerror (err));
        xfree (deks);
        goto out;
      }

    session_key_initial = deks[0];

    session_key_i = ndeks - 1;
    session_key = deks[session_key_i];

    xfree (deks);
  }

  /* Make a new subkey using the new subscriber's selected encryption
     key.  */
  {
    PACKET *pkt;

    if (DBG_PACKET)
      {
        log_debug("%s: keyblock pre:\n", __func__);
        kbnode_dump (ml_kb);
      }

    pkt = xmalloc_clear (sizeof (*pkt));
    pkt->pkttype = PKT_PUBLIC_SUBKEY;
    ml_ek = xmalloc_clear (sizeof (*ml_ek));
    pkt->pkt.public_key = ml_ek;
    add_kbnode (ml_kb, new_kbnode (pkt));

    /* First copy everything and then clear what we don't need.  */
    /* XXX: It would be better to just copy the fields that we actually
       need.  */
    *ml_ek = *sub_ek;
    ml_ek->main_keyid[0] = ml_pk->keyid[0];
    ml_ek->main_keyid[1] = ml_pk->keyid[1];
    ml_ek->pubkey_usage = PUBKEY_USAGE_ENC;
    ml_ek->expiredate = 0;
    ml_ek->max_expiredate = 0;
    ml_ek->prefs = NULL;
    ml_ek->user_id = NULL;
    ml_ek->revkey = NULL;
    ml_ek->numrevkeys = 0;
    ml_ek->trust_regexp = NULL;
    ml_ek->serialno = NULL;
    ml_ek->seckey_info = NULL;
  }

  /* Encrypt the parameters and the current time using the current
     session key.  */
  {
    int i;
    int n = pubkey_get_npkey (ml_ek->pubkey_algo);

    for (i = 0; i < n; i ++)
      {
        /* XXX: Finish me: actually encrypt the keys; don't just copy
           them.  */
        (void) session_key;

        ml_ek->pkey[i] = gcry_mpi_copy (ml_ek->pkey[i]);
      }

    /* XXX: Encrypt the creation time.  */

    /* Recompute ml_ek->keyid.  */
    {
      char fp[MAX_FINGERPRINT_LEN];
      size_t fplen;
      u32 keyid[2];

      fingerprint_from_pk (ml_ek, fp, &fplen);
      keyid_from_fingerprint (fp, fplen, keyid);
      ml_ek->keyid[0] = keyid[0];
      ml_ek->keyid[1] = keyid[1];
    }
  }

  /* Add the public-key-encrypted-with notation.  */
  {
    char *notation;
    struct notation *notation_blob;

    /* The session key used to encrypt the public key parameters.  */
    notation = xasprintf ("public-key-encrypted-with@gnupg.org=%d",
                          session_key_i);
    notation_blob = string_to_notation (notation, 0);
    if (! notation_blob)
      {
        log_bug ("Failed to create notation: %s\n", notation);
        xfree (notation);
        err = gpg_error (GPG_ERR_INTERNAL);
        goto out;
      }
    xfree (notation);

    notation_blob->next = notations;
    notations = notation_blob;
  }

  /* Add the subscriber-list-key notation.  */
  {
    char *notation;
    struct notation *notation_blob;

    struct pk_list pk_list;
    /* The public key encrypted session key as a packet.  */
    iobuf_t pk_esk;
    char *buffer;
    size_t len;


    /* The initial session key encrypted with the new subscriber's
       public key.  */
    /* Initialize PK_LIST with just the encryption key.  */
    pk_list.next = NULL;
    pk_list.pk = sub_ek;
    /* Throw the key id.  */
    pk_list.flags = 1;

    pk_esk = iobuf_temp ();
    if (! pk_esk)
      {
        log_bug ("Out of memory allocating pk_esk\n");
        err = gpg_error (GPG_ERR_INTERNAL);
        goto out;
      }

    err = write_pubkey_enc_from_list (ctrl, &pk_list,
                                      &session_key_initial, pk_esk);
    if (err)
      {
        log_bug ("Failed to generate PK-ESK packet: %s\n",
                 gpg_strerror (err));
        iobuf_close (pk_esk);
        goto out;
      }

    buffer = iobuf_get_temp_buffer (pk_esk);
    len = iobuf_get_temp_length (pk_esk);

    /* XXX */
    if (DBG_PACKET)
      {
        char *fn = xasprintf ("/tmp/subscriber-list-key-%s",
                              keystr (sub_ek->keyid));
        FILE *fp = fopen (fn, "w");
        if (fp)
          {
            log_debug ("Writing subscriber-list-key to %s\n", fn);
            fwrite (buffer, len, 1, fp);
            fclose (fp);
          }
        xfree (fn);
      }

    notation = "subscriber-list-key@gnupg.org";
    notation_blob = blob_to_notation (notation, buffer, len);
    iobuf_close (pk_esk);
    if (! notation_blob)
      {
        log_bug ("Failed to create notation: %s=<SE-ESK packet, %zd bytes>\n",
                 notation, len);
        err = gpg_error (GPG_ERR_INTERNAL);
        goto out;
      }

    notation_blob->next = notations;
    notations = notation_blob;
  }

  /* Write the binding signature.  */
  err = write_keybinding (ml_kb, ml_pk, NULL, ml_ek->pubkey_usage,
                          make_timestamp(), NULL, notations);
  if (err)
    {
      log_error ("Error creating key binding: %s\n", gpg_strerror (err));
      goto out;
    }

  if (DBG_PACKET)
    {
      log_debug("%s: keyblock after adding self-sig:\n", __func__);
      kbnode_dump (ml_kb);
    }


  /* Save the updated keyblock.  */
  {
    KEYDB_HANDLE hd = keydb_new ();
    err = keydb_update_keyblock (hd, ml_kb);
    keydb_release (hd);
    if (err)
      {
        log_error ("Error saving %s's keyblock.\n",
                   keystr (ml_pk->keyid));
        goto out;
      }
  }

 out:
  free_notation (notations);

  if (sub_kb)
    release_kbnode (sub_kb);

  if (err)
    log_error (_("Key generation failed: %s\n"), gpg_strerror (err) );

  return err;
}

gpg_error_t
mailing_list_rm_subscriber (ctrl_t ctrl, KBNODE ml_kb, const char *sub_orig)
{
  gpg_error_t err;

  /* The mailing list's primary key.  */
  PKT_public_key *ml_pk = ml_kb->pkt->pkt.public_key;

  DEK *deks = NULL;
  int ndeks = 0;

  char *sub;
  int i, j;

  PKT_public_key *ek;
  struct notation *notations = NULL;

  /* Skip leading white space.  */
  while (*sub_orig == ' ')
    sub_orig ++;
  /* Kill the leading 0x (if any).  */
  if (sub_orig[0] == '0' && sub_orig[0] == 'x')
    sub_orig += 2;
  sub = xstrdup (sub_orig);

  if (DBG_PACKET)
    log_debug ("%s: sub: '%s'\n", __func__, sub);
  /* Remove any spaces and upcase the rest.  */
  for (i = j = 0; sub[i]; i ++, j ++)
    {
      while (sub[i] == ' ')
        i ++;

      if (i != j)
        sub[j] = toupper (sub[i]);
    }
  sub[j] = 0;
  if (DBG_PACKET && strcmp (sub_orig, sub) != 0)
    log_debug ("%s: sub postprocessed: '%s'\n", __func__, sub);

  /* Make sure it is in the form of a keyid (short or long) or a
     fingerprint.  */
  if (strspn (sub, "0123456789ABCDEF") != strlen (sub)
      || !(strlen (sub) == 8 || strlen (sub) != 16 || strlen (sub) != 40))
    {
      log_error ("'%s' is not a valid key id or fingerprint.\n", sub_orig);
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto out;
    }

  err = mailing_list_get_subscriber_list_session_keys (ctrl, ml_kb,
                                                       &deks, &ndeks);
  if (err)
    {
      log_error ("Failed to get session keys: %s\n", gpg_strerror (err));
      goto out;
    }

  /* Iterate and decrypt all of the keys to get their real key ids.  */
  {
    KBNODE n;

    for (n = ml_kb; n; n = n->next)
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          char id[41];
          int match = 0;

          ek = n->pkt->pkt.public_key;

          if (DBG_PACKET)
            log_debug ("%s: considering subkey %s.\n",
                       __func__, keystr (ek->keyid));

          switch (strlen (sub))
            {
            case 8:
              match = strcmp (format_keyid (ek->keyid, KF_SHORT,
                                            id, sizeof (id)),
                              sub) == 0;
              break;
            case 16:
              match = strcmp (format_keyid (ek->keyid, KF_LONG,
                                            id, sizeof (id)),
                              sub) == 0;
              break;
            case 40:
              match = strcmp (fingerprint_from_pk (ek, id, NULL), sub) == 0;
              break;
            default:
              assert (! "Unhandled case.");
            }

          if (match)
            break;
        }

    if (! n)
      {
        log_error ("No subkey matches %s\n", sub_orig);
        err = gpg_error (GPG_ERR_NOT_FOUND);
        goto out;
      }

    if (DBG_PACKET)
      log_debug ("%s: subkey %s matched.\n",
                 __func__, keystr (ek->keyid));

    if (ek->has_expired)
      {
        log_error ("Subscriber %s was already removed.\n", sub_orig);
        err = 0;
        goto out;
      }

    /* We need to generate a new session key.  */
    {
      const char *notation = "subscriber-list-session-key@gnupg.org";
      struct notation *notation_blob;

      STRING2KEY *symkey_s2k = NULL;
      DEK *symkey_dek = NULL;

      DEK dek;
      /* The symmetrically encrypted session key as a packet.  */
      iobuf_t sk_esk;

      char *buffer;
      size_t len;

      /* setup_symkey needs a passphrase.  We have a static passphrase.
         To communicate this to setup_symkey, we use the
         set_next_passphrase function, which preloads the passphrase and
         causes setup_symkey to not ask the user, which is exactly what
         we want.  */
      set_next_passphrase (bin2hex (deks[ndeks - 1].key, deks[ndeks - 1].keylen,
                                    NULL));
      err = setup_symkey (&symkey_s2k, &symkey_dek);
      if (err)
        {
          log_bug ("Failed to initialize s2k and dek buffers: %s\n",
                   gpg_strerror (err));
          return err;
        }

      memset (&dek, 0, sizeof (dek));
      dek.algo = default_cipher_algo ();
      make_session_key (&dek);

      sk_esk = iobuf_temp ();
      if (! sk_esk)
        {
          log_bug ("Out of memory allocating sk_esk\n");
          return gpg_error (GPG_ERR_INTERNAL);
        }

      err = write_symkey_enc (symkey_s2k, symkey_dek, &dek, sk_esk);
      if (err)
        {
          log_bug ("Failed to generate a symmetric key: %s\n",
                   gpg_strerror (err));
          return err;
        }

      buffer = iobuf_get_temp_buffer (sk_esk);
      len = iobuf_get_temp_length (sk_esk);

      notation_blob =
        blob_to_notation (notation, buffer, len);
      if (! notation_blob)
        {
          log_bug ("Failed to create notation: %s=<SE-ESK packet, %zd bytes>\n",
                   notation, len);
          return gpg_error (GPG_ERR_INTERNAL);
        }

      {
        char *fn = xasprintf ("/tmp/subscriber-list-session-key-%d", ndeks);
        FILE *fp = fopen (fn, "w");
        xfree (fn);
        fwrite (buffer, len, 1, fp);
        fclose (fp);
      }

      notation_blob->next = notations;
      notations = notation_blob;
    }

    /* Record the key that the notation was encrypted with.  */
    {
      char *notation
        = xasprintf ("subscriber-list-session-key-encrypted-with@gnupg.org=%d",
                     ndeks - 1);
      struct notation *notation_blob;

      notation_blob = string_to_notation (notation, 0);
      if (! notation_blob)
        {
          log_bug ("Failed to create notation: %s\n", notation);
          return gpg_error (GPG_ERR_INTERNAL);
        }

      notation_blob->next = notations;
      notations = notation_blob;
    }

    /* Add the notations and update the expiration time.  */
    for (n = n->next; n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
      {
        PKT_signature *sig = n->pkt->pkt.signature;

        if (DBG_PACKET)
          log_debug ("%s: sig: keyid: %s; class: %x; chosen: %d\n",
                     __func__, keystr (sig->keyid), sig->sig_class,
                     sig->flags.chosen_selfsig);

        if (ml_pk->keyid[0] == sig->keyid[0] && ml_pk->keyid[1] == sig->keyid[1]
            && sig->sig_class == 0x18
            && sig->flags.chosen_selfsig)
          break;
      }

    if (!n || n->pkt->pkttype != PKT_SIGNATURE)
      {
        log_error ("subkey %s missing key binding signature!\n", sub_orig);
        err = gpg_error (GPG_ERR_INV_DATA);
        goto out;
      }

    /* Modify the signature.  */
    {
      PKT_signature *sig = n->pkt->pkt.signature;
      PKT_signature *newsig;
      PACKET *newpkt;
      KBNODE n2;

      ek->expiredate = make_timestamp();

      err = update_keysig_packet (&newsig, sig, ml_pk, NULL, ek,
                                  ml_pk, notations,
                                  keygen_add_key_expire, ek);
      if (err)
        {
          log_error ("make_keysig_packet failed: %s\n",
                     gpg_strerror (err));
          return 0;
        }

      newpkt = xmalloc_clear (sizeof *newpkt);
      newpkt->pkttype = PKT_SIGNATURE;
      newpkt->pkt.signature = newsig;

      /* Add the packet.  */
      n2 = new_kbnode (newpkt);
      n2->next = n->next;
      n->next = n2;
    }
  }

  if (DBG_PACKET)
    {
      log_debug ("%s: Keyblock after adding new signature marking %s expired:\n",
                 __func__, keystr (ek->keyid));
      kbnode_dump (ml_kb);
    }

  {
    KEYDB_HANDLE hd = keydb_new ();
    err = keydb_update_keyblock (hd, ml_kb);
    keydb_release (hd);
    if (err)
      log_error ("Error saving %s's keyblock.\n",
                 keystr (ml_pk->keyid));
  }


 out:
  free_notation (notations);
  xfree (deks);
  xfree (sub);

  return err;
}

gpg_error_t
mailing_list_subscribers (ctrl_t ctrl, KBNODE kb, PK_LIST *pklistp)
{
  gpg_error_t err;

  DEK *deks = NULL;
  int ndeks;

  PK_LIST pklist = NULL;
  KBNODE n;
  PKT_public_key *pk = NULL;

  err = mailing_list_get_subscriber_list_session_keys (ctrl, kb,
                                                       &deks, &ndeks);

  for (n = kb; n; n = n->next)
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          pk = n->pkt->pkt.public_key;
          if (pk->has_expired)
            /* The subscriber was removed.  */
            {
              if (DBG_PACKET)
                log_debug ("%s: Skipping subscriber %s who was unsubscribed.\n",
                           __func__, keystr (pk->keyid));
              pk = NULL;
            }
        }
      else if (pk && n->pkt->pkttype == PKT_SIGNATURE)
        {
          PKT_signature *sig = n->pkt->pkt.signature;
          struct notation *notations;
          struct notation *x;

          notations = sig_to_notation (sig);
          if (! notations)
            continue;

          for (x = notations; x; x = x->next)
            /* If the public key is encrypted, then this is a subscriber.  */
            if (strcmp (x->name, "public-key-encrypted-with@gnupg.org") == 0)
              {
                PK_LIST r = xmalloc_clear (sizeof *r);
                int i = atoi (x->value);

                if (i >= ndeks)
                  {
                    log_error ("Unable to decrypt subkey %s: session key %d not available.\n",
                               keystr (pk->keyid), i);
                    goto out;
                  }

                /* XXX: Decrypt the public key parameters using the
                   session key.  */
                (void) i;

                r->pk = copy_public_key (NULL, pk);
                r->next = pklist;
                pklist = r;
              }

          free_notation (notations);
        }
      else
        {
          if (pk)
            {
              log_info ("Warning: %s is not a valid subscriber (missing notations)\n",
                        keystr (pk->keyid));
              pk = NULL;
            }
        }
    }

 out:
  xfree (deks);

  if (err)
    release_pk_list (pklist);
  else
    *pklistp = pklist;

  return err;
}
