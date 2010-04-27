/* pubkey-enc.c - Process a public key encoded packet.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2006, 2009,
 *               2010 Free Software Foundation, Inc.
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
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "packet.h"
#include "keydb.h"
#include "trustdb.h"
#include "cipher.h"
#include "status.h"
#include "options.h"
#include "main.h"
#include "i18n.h"
#include "pkglue.h"
#include "call-agent.h"


static gpg_error_t get_it (PKT_pubkey_enc *k,
                           DEK *dek, PKT_public_key *sk, u32 *keyid);


/* Check that the given algo is mentioned in one of the valid user-ids. */
static int
is_algo_in_prefs (kbnode_t keyblock, preftype_t type, int algo)
{
  kbnode_t k;

  for (k = keyblock; k; k = k->next)
    {
      if (k->pkt->pkttype == PKT_USER_ID)
        {
          PKT_user_id *uid = k->pkt->pkt.user_id;
          prefitem_t *prefs = uid->prefs;

          if (uid->created && prefs && !uid->is_revoked && !uid->is_expired)
            {
              for (; prefs->type; prefs++)
                if (prefs->type == type && prefs->value == algo)
                  return 1;
            }
        }
    }
  return 0;
}


/*
 * Get the session key from a pubkey enc packet and return it in DEK,
 * which should have been allocated in secure memory by the caller.
 */
gpg_error_t
get_session_key (PKT_pubkey_enc * k, DEK * dek)
{
  PKT_public_key *sk = NULL;
  int rc;

  rc = openpgp_pk_test_algo2 (k->pubkey_algo, PUBKEY_USAGE_ENC);
  if (rc)
    goto leave;

  if ((k->keyid[0] || k->keyid[1]) && !opt.try_all_secrets)
    {
      sk = xmalloc_clear (sizeof *sk);
      sk->pubkey_algo = k->pubkey_algo; /* We want a pubkey with this algo.  */
      if (!(rc = get_seckey (sk, k->keyid)))
        rc = get_it (k, dek, sk, k->keyid);
    }
  else if (opt.skip_hidden_recipients)
    rc = gpg_error (GPG_ERR_NO_SECKEY);
  else  /* Anonymous receiver: Try all available secret keys.  */
    {
      void *enum_context = NULL;
      u32 keyid[2];
      char *p;

      for (;;)
        {
          if (sk)
            free_public_key (sk);
          sk = xmalloc_clear (sizeof *sk);
          rc = -1; /* FIXME:enum_secret_keys (&enum_context, sk, 1, 0);*/
          if (rc)
            {
              rc = G10ERR_NO_SECKEY;
              break;
            }
          if (sk->pubkey_algo != k->pubkey_algo)
            continue;
          keyid_from_pk (sk, keyid);
          log_info (_("anonymous recipient; trying secret key %s ...\n"),
                    keystr (keyid));

          if (!opt.try_all_secrets && !is_status_enabled ())
            {
              p = get_last_passphrase ();
              set_next_passphrase (p);
              xfree (p);
            }

          /* rc = check_secret_key( sk, opt.try_all_secrets?1:-1 ); /\* ask */
          /*                                                        only */
          /*                                                        once *\/ */
          /* if( !rc ) */
          {
            rc = get_it (k, dek, sk, keyid);
            /* Successfully checked the secret key (either it was a
               card, had no passphrase, or had the right passphrase)
               but couldn't decrypt the session key, so thus that key
               is not the anonymous recipient.  Move the next
               passphrase into last for the next round.  We only do
               this if the secret key was successfully checked as in
               the normal case, check_secret_key handles this for us
               via passphrase_to_dek.  */
            if (rc)
              next_to_last_passphrase ();
          }

          if (!rc)
            {
              log_info (_("okay, we are the anonymous recipient.\n"));
              break;
            }
        }
      enum_secret_keys (&enum_context, NULL, 0, 0);     /* free context */
    }

leave:
  if (sk)
    free_public_key (sk);
  return rc;
}


static gpg_error_t
get_it (PKT_pubkey_enc *enc, DEK *dek, PKT_public_key *sk, u32 *keyid)
{
  gpg_error_t err;
  byte *frame = NULL;
  unsigned int n;
  size_t nframe;
  u16 csum, csum2;
  int card = 0;
  gcry_sexp_t s_data;
  char *desc;
  char *keygrip;

  /* Get the keygrip.  */
  err = hexkeygrip_from_pk (sk, &keygrip);
  if (err)
    goto leave;

  /* Convert the data to an S-expression.  */
  if (sk->pubkey_algo == GCRY_PK_ELG || sk->pubkey_algo == GCRY_PK_ELG_E)
    {
      if (!enc->data[0] || !enc->data[1])
        err = gpg_error (GPG_ERR_BAD_MPI);
      else
        err = gcry_sexp_build (&s_data, NULL, "(enc-val(elg(a%m)(b%m)))", 
                               enc->data[0], enc->data[1]);
    }
  else if (sk->pubkey_algo == GCRY_PK_RSA || sk->pubkey_algo == GCRY_PK_RSA_E)
    {
      if (!enc->data[0])
        err = gpg_error (GPG_ERR_BAD_MPI);
      else
        err = gcry_sexp_build (&s_data, NULL, "(enc-val(rsa(a%m)))",
                               enc->data[0]);
    }
  else
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    goto leave;

  /* Decrypt. */
  desc = gpg_format_keydesc (sk, 1);
  err = agent_pkdecrypt (NULL, keygrip, desc, s_data, &frame, &nframe);
  xfree (desc);
  gcry_sexp_release (s_data);
  if (err)
    goto leave;

  /* Now get the DEK (data encryption key) from the frame
   *
   * Old versions encode the DEK in in this format (msb is left):
   *
   *     0  1  DEK(16 bytes)  CSUM(2 bytes)  0  RND(n bytes) 2
   *
   * Later versions encode the DEK like this:
   *
   *     0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
   *
   * (mpi_get_buffer already removed the leading zero).
   *
   * RND are non-zero randow bytes.
   * A   is the cipher algorithm
   * DEK is the encryption key (session key) with length k
   * CSUM
   */
  if (DBG_CIPHER)
    log_printhex ("DEK frame:", frame, nframe);
  n = 0;
  if (!card)
    {
      if (n + 7 > nframe)
        {
          err = gpg_error (G10ERR_WRONG_SECKEY);
          goto leave;
        }
      if (frame[n] == 1 && frame[nframe - 1] == 2)
        {
          log_info (_("old encoding of the DEK is not supported\n"));
          err = gpg_error (G10ERR_CIPHER_ALGO);
          goto leave;
        }
      if (frame[n] != 2) /* Something went wrong.  */
        {
          err = gpg_error (G10ERR_WRONG_SECKEY);
          goto leave;
        }
      for (n++; n < nframe && frame[n]; n++) /* Skip the random bytes.  */
        ;
      n++; /* Skip the zero byte.  */
    }

  if (n + 4 > nframe)
    {
      err = gpg_error (G10ERR_WRONG_SECKEY);
      goto leave;
    }

  dek->keylen = nframe - (n + 1) - 2;
  dek->algo = frame[n++];
  if (dek->algo == CIPHER_ALGO_IDEA)
    write_status (STATUS_RSA_OR_IDEA);
  err = openpgp_cipher_test_algo (dek->algo);
  if (err)
    {
      if (!opt.quiet && gpg_err_code (err) == GPG_ERR_CIPHER_ALGO)
        {
          log_info (_("cipher algorithm %d%s is unknown or disabled\n"),
                    dek->algo,
                    dek->algo == CIPHER_ALGO_IDEA ? " (IDEA)" : "");
          if (dek->algo == CIPHER_ALGO_IDEA)
            idea_cipher_warn (0);
        }
      dek->algo = 0;
      goto leave;
    }
  if (dek->keylen != openpgp_cipher_get_algo_keylen (dek->algo))
    {
      err = gpg_error (GPG_ERR_WRONG_SECKEY);
      goto leave;
    }

  /* Copy the key to DEK and compare the checksum.  */
  csum = frame[nframe - 2] << 8;
  csum |= frame[nframe - 1];
  memcpy (dek->key, frame + n, dek->keylen);
  for (csum2 = 0, n = 0; n < dek->keylen; n++)
    csum2 += dek->key[n];
  if (csum != csum2)
    {
      err = gpg_error (GPG_ERR_WRONG_SECKEY);
      goto leave;
    }
  if (DBG_CIPHER)
    log_printhex ("DEK is:", dek->key, dek->keylen);

  /* Check that the algo is in the preferences and whether it has expired.  */
  {
    PKT_public_key *pk = NULL;
    KBNODE pkb = get_pubkeyblock (keyid);

    if (!pkb)
      {
        err = -1;
        log_error ("oops: public key not found for preference check\n");
      }
    else if (pkb->pkt->pkt.public_key->selfsigversion > 3
             && dek->algo != CIPHER_ALGO_3DES
             && !opt.quiet
             && !is_algo_in_prefs (pkb, PREFTYPE_SYM, dek->algo))
      log_info (_("WARNING: cipher algorithm %s not found in recipient"
                  " preferences\n"), openpgp_cipher_algo_name (dek->algo));
    if (!err)
      {
        KBNODE k;

        for (k = pkb; k; k = k->next)
          {
            if (k->pkt->pkttype == PKT_PUBLIC_KEY
                || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
              {
                u32 aki[2];
                keyid_from_pk (k->pkt->pkt.public_key, aki);

                if (aki[0] == keyid[0] && aki[1] == keyid[1])
                  {
                    pk = k->pkt->pkt.public_key;
                    break;
                  }
              }
          }
        if (!pk)
          BUG ();
        if (pk->expiredate && pk->expiredate <= make_timestamp ())
          {
            log_info (_("NOTE: secret key %s expired at %s\n"),
                      keystr (keyid), asctimestamp (pk->expiredate));
          }
      }

    if (pk && pk->is_revoked)
      {
        log_info (_("NOTE: key has been revoked"));
        log_printf ("\n");
        show_revocation_reason (pk, 1);
      }

    release_kbnode (pkb);
    err = 0;
  }

 leave:
  xfree (frame);
  xfree (keygrip);
  return err;
}


/*
 * Get the session key from the given string.
 * String is supposed to be formatted as this:
 *  <algo-id>:<even-number-of-hex-digits>
 */
gpg_error_t
get_override_session_key (DEK *dek, const char *string)
{
  const char *s;
  int i;

  if (!string)
    return G10ERR_BAD_KEY;
  dek->algo = atoi (string);
  if (dek->algo < 1)
    return G10ERR_BAD_KEY;
  if (!(s = strchr (string, ':')))
    return G10ERR_BAD_KEY;
  s++;
  for (i = 0; i < DIM (dek->key) && *s; i++, s += 2)
    {
      int c = hextobyte (s);
      if (c == -1)
        return G10ERR_BAD_KEY;
      dek->key[i] = c;
    }
  if (*s)
    return G10ERR_BAD_KEY;
  dek->keylen = i;
  return 0;
}
