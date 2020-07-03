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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "keydb.h"
#include "trustdb.h"
#include "../common/status.h"
#include "options.h"
#include "main.h"
#include "../common/i18n.h"
#include "pkglue.h"
#include "call-agent.h"
#include "../common/host2net.h"
#include "../common/compliance.h"


static gpg_error_t get_it (ctrl_t ctrl, PKT_pubkey_enc *k,
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

          if (uid->created && prefs && !uid->flags.revoked && !uid->flags.expired)
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
get_session_key (ctrl_t ctrl, PKT_pubkey_enc * k, DEK * dek)
{
  PKT_public_key *sk = NULL;
  int rc;

  if (DBG_CLOCK)
    log_clock ("get_session_key enter");

  rc = openpgp_pk_test_algo2 (k->pubkey_algo, PUBKEY_USAGE_ENC);
  if (rc)
    goto leave;

  if ((k->keyid[0] || k->keyid[1]) && !opt.try_all_secrets)
    {
      sk = xmalloc_clear (sizeof *sk);
      sk->pubkey_algo = k->pubkey_algo; /* We want a pubkey with this algo.  */
      if (!(rc = get_seckey (ctrl, sk, k->keyid)))
        {
          /* Check compliance.  */
          if (! gnupg_pk_is_allowed (opt.compliance, PK_USE_DECRYPTION,
                                     sk->pubkey_algo, 0,
                                     sk->pkey, nbits_from_pk (sk), NULL))
            {
              log_info (_("key %s is not suitable for decryption"
                          " in %s mode\n"),
                        keystr_from_pk (sk),
                        gnupg_compliance_option_string (opt.compliance));
              rc = gpg_error (GPG_ERR_PUBKEY_ALGO);
            }
          else
            rc = get_it (ctrl, k, dek, sk, k->keyid);
        }
    }
  else if (opt.skip_hidden_recipients)
    rc = gpg_error (GPG_ERR_NO_SECKEY);
  else  /* Anonymous receiver: Try all available secret keys.  */
    {
      void *enum_context = NULL;
      u32 keyid[2];

      for (;;)
        {
          sk = xmalloc_clear (sizeof *sk);
          rc = enum_secret_keys (ctrl, &enum_context, sk);
          if (rc)
            {
              sk = NULL;  /* enum_secret_keys turns SK into a shallow copy! */
              rc = GPG_ERR_NO_SECKEY;
              break;
            }
          if (sk->pubkey_algo != k->pubkey_algo)
            continue;
          if (!(sk->pubkey_usage & PUBKEY_USAGE_ENC))
            continue;
          keyid_from_pk (sk, keyid);
          if (!opt.quiet)
            log_info (_("anonymous recipient; trying secret key %s ...\n"),
                      keystr (keyid));

          /* Check compliance.  */
          if (! gnupg_pk_is_allowed (opt.compliance, PK_USE_DECRYPTION,
                                     sk->pubkey_algo, 0,
                                     sk->pkey, nbits_from_pk (sk), NULL))
            {
              log_info (_("key %s is not suitable for decryption"
                          " in %s mode\n"),
                          keystr_from_pk (sk),
                          gnupg_compliance_option_string (opt.compliance));
              continue;
            }

          rc = get_it (ctrl, k, dek, sk, keyid);
          if (!rc)
            {
              if (!opt.quiet)
                log_info (_("okay, we are the anonymous recipient.\n"));
              sk = NULL;
              break;
            }
          else if (gpg_err_code (rc) == GPG_ERR_FULLY_CANCELED)
            {
              sk = NULL;
              break; /* Don't try any more secret keys.  */
            }
        }
      enum_secret_keys (ctrl, &enum_context, NULL);  /* free context */
    }

 leave:
  free_public_key (sk);
  if (DBG_CLOCK)
    log_clock ("get_session_key leave");
  return rc;
}


static gpg_error_t
get_it (ctrl_t ctrl,
        PKT_pubkey_enc *enc, DEK *dek, PKT_public_key *sk, u32 *keyid)
{
  gpg_error_t err;
  byte *frame = NULL;
  unsigned int n;
  size_t nframe;
  u16 csum, csum2;
  int padding;
  gcry_sexp_t s_data;
  char *desc;
  char *keygrip;
  byte fp[MAX_FINGERPRINT_LEN];
  size_t fpn;

  if (DBG_CLOCK)
    log_clock ("decryption start");

  /* Get the keygrip.  */
  err = hexkeygrip_from_pk (sk, &keygrip);
  if (err)
    goto leave;

  /* Convert the data to an S-expression.  */
  if (sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL
      || sk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E)
    {
      if (!enc->data[0] || !enc->data[1])
        err = gpg_error (GPG_ERR_BAD_MPI);
      else
        err = gcry_sexp_build (&s_data, NULL, "(enc-val(elg(a%m)(b%m)))",
                               enc->data[0], enc->data[1]);
    }
  else if (sk->pubkey_algo == PUBKEY_ALGO_RSA
           || sk->pubkey_algo == PUBKEY_ALGO_RSA_E)
    {
      if (!enc->data[0])
        err = gpg_error (GPG_ERR_BAD_MPI);
      else
        err = gcry_sexp_build (&s_data, NULL, "(enc-val(rsa(a%m)))",
                               enc->data[0]);
    }
  else if (sk->pubkey_algo == PUBKEY_ALGO_ECDH)
    {
      if (!enc->data[0] || !enc->data[1])
        err = gpg_error (GPG_ERR_BAD_MPI);
      else
        err = gcry_sexp_build (&s_data, NULL, "(enc-val(ecdh(s%m)(e%m)))",
                               enc->data[1], enc->data[0]);
    }
  else
    err = gpg_error (GPG_ERR_BUG);

  if (err)
    goto leave;

  if (sk->pubkey_algo == PUBKEY_ALGO_ECDH)
    {
      fingerprint_from_pk (sk, fp, &fpn);
      log_assert (fpn == 20);
    }

  /* Decrypt. */
  desc = gpg_format_keydesc (ctrl, sk, FORMAT_KEYDESC_NORMAL, 1);
  err = agent_pkdecrypt (NULL, keygrip,
                         desc, sk->keyid, sk->main_keyid, sk->pubkey_algo,
                         s_data, &frame, &nframe, &padding);
  xfree (desc);
  gcry_sexp_release (s_data);
  if (err)
    goto leave;

  /* Now get the DEK (data encryption key) from the frame
   *
   * Old versions encode the DEK in this format (msb is left):
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
  if (DBG_CRYPTO)
    log_printhex (frame, nframe, "DEK frame:");
  n = 0;

  if (sk->pubkey_algo == PUBKEY_ALGO_ECDH)
    {
      gcry_mpi_t shared_mpi;
      gcry_mpi_t decoded;

      /* At the beginning the frame are the bytes of shared point MPI.  */
      err = gcry_mpi_scan (&shared_mpi, GCRYMPI_FMT_USG, frame, nframe, NULL);
      if (err)
        {
          err = gpg_error (GPG_ERR_WRONG_SECKEY);
          goto leave;
        }

      err = pk_ecdh_decrypt (&decoded, fp, enc->data[1]/*encr data as an MPI*/,
                             shared_mpi, sk->pkey);
      mpi_release (shared_mpi);
      if(err)
        goto leave;

      xfree (frame);
      err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &frame, &nframe, decoded);
      mpi_release (decoded);
      if (err)
        goto leave;

      /* Now the frame are the bytes decrypted but padded session key.  */
      if (!nframe || nframe <= 8
          || frame[nframe-1] > nframe)
        {
          err = gpg_error (GPG_ERR_WRONG_SECKEY);
          goto leave;
        }
      nframe -= frame[nframe-1]; /* Remove padding.  */
      log_assert (!n); /* (used just below) */
    }
  else
    {
      if (padding)
        {
          if (n + 7 > nframe)
            {
              err = gpg_error (GPG_ERR_WRONG_SECKEY);
              goto leave;
            }

          /* FIXME: Actually the leading zero is required but due to
           * the way we encode the output in libgcrypt as an MPI we
           * are not able to encode that leading zero.  However, when
           * using a Smartcard we are doing it the right way and
           * therefore we have to skip the zero.  This should be fixed
           * in gpg-agent of course. */
          if (!frame[n])
            n++;

          if (frame[n] == 1 && frame[nframe - 1] == 2)
            {
              log_info (_("old encoding of the DEK is not supported\n"));
              err = gpg_error (GPG_ERR_CIPHER_ALGO);
              goto leave;
            }
          if (frame[n] != 2) /* Something went wrong.  */
            {
              err = gpg_error (GPG_ERR_WRONG_SECKEY);
              goto leave;
            }
          for (n++; n < nframe && frame[n]; n++) /* Skip the random bytes.  */
            ;
          n++; /* Skip the zero byte.  */
        }
    }

  if (n + 4 > nframe)
    {
      err = gpg_error (GPG_ERR_WRONG_SECKEY);
      goto leave;
    }

  dek->keylen = nframe - (n + 1) - 2;
  dek->algo = frame[n++];
  err = openpgp_cipher_test_algo (dek->algo);
  if (err)
    {
      if (!opt.quiet && gpg_err_code (err) == GPG_ERR_CIPHER_ALGO)
        {
          log_info (_("cipher algorithm %d%s is unknown or disabled\n"),
                    dek->algo,
                    dek->algo == CIPHER_ALGO_IDEA ? " (IDEA)" : "");
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
  csum = buf16_to_u16 (frame+nframe-2);
  memcpy (dek->key, frame + n, dek->keylen);
  for (csum2 = 0, n = 0; n < dek->keylen; n++)
    csum2 += dek->key[n];
  if (csum != csum2)
    {
      err = gpg_error (GPG_ERR_WRONG_SECKEY);
      goto leave;
    }
  if (DBG_CLOCK)
    log_clock ("decryption ready");
  if (DBG_CRYPTO)
    log_printhex (dek->key, dek->keylen, "DEK is:");

  /* Check that the algo is in the preferences and whether it has
   * expired.  Also print a status line with the key's fingerprint.  */
  {
    PKT_public_key *pk = NULL;
    PKT_public_key *mainpk = NULL;
    KBNODE pkb = get_pubkeyblock (ctrl, keyid);

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
        kbnode_t k;
        int first = 1;

        for (k = pkb; k; k = k->next)
          {
            if (k->pkt->pkttype == PKT_PUBLIC_KEY
                || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
              {
                u32 aki[2];

                if (first)
                  {
                    first = 0;
                    mainpk = k->pkt->pkt.public_key;
                  }

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
            log_info (_("Note: secret key %s expired at %s\n"),
                      keystr (keyid), asctimestamp (pk->expiredate));
          }
      }

    if (pk && pk->flags.revoked)
      {
        log_info (_("Note: key has been revoked"));
        log_printf ("\n");
        show_revocation_reason (ctrl, pk, 1);
      }

    if (is_status_enabled () && pk && mainpk)
      {
        char pkhex[MAX_FINGERPRINT_LEN*2+1];
        char mainpkhex[MAX_FINGERPRINT_LEN*2+1];

        hexfingerprint (pk, pkhex, sizeof pkhex);
        hexfingerprint (mainpk, mainpkhex, sizeof mainpkhex);

        /* Note that we do not want to create a trustdb just for
         * getting the ownertrust: If there is no trustdb there can't
         * be ulitmately trusted key anyway and thus the ownertrust
         * value is irrelevant.  */
        write_status_printf (STATUS_DECRYPTION_KEY, "%s %s %c",
                             pkhex, mainpkhex,
                             get_ownertrust_info (ctrl, mainpk, 1));

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
    return GPG_ERR_BAD_KEY;
  dek->algo = atoi (string);
  if (dek->algo < 1)
    return GPG_ERR_BAD_KEY;
  if (!(s = strchr (string, ':')))
    return GPG_ERR_BAD_KEY;
  s++;
  for (i = 0; i < DIM (dek->key) && *s; i++, s += 2)
    {
      int c = hextobyte (s);
      if (c == -1)
        return GPG_ERR_BAD_KEY;
      dek->key[i] = c;
    }
  if (*s)
    return GPG_ERR_BAD_KEY;
  dek->keylen = i;
  return 0;
}
