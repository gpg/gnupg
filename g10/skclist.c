/* skclist.c - Build a list of secret keys
 * Copyright (C) 1998, 1999, 2000, 2001, 2006,
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
#include <errno.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "../common/status.h"
#include "keydb.h"
#include "../common/util.h"
#include "../common/i18n.h"
#include "keyserver-internal.h"
#include "call-agent.h"


/* Return true if Libgcrypt's RNG is in faked mode.  */
int
random_is_faked (void)
{
  return !!gcry_control (GCRYCTL_FAKED_RANDOM_P, 0);
}


void
release_sk_list (SK_LIST sk_list)
{
  SK_LIST sk_rover;

  for (; sk_list; sk_list = sk_rover)
    {
      sk_rover = sk_list->next;
      free_public_key (sk_list->pk);
      xfree (sk_list);
    }
}


/* Check that we are only using keys which don't have
 * the string "(insecure!)" or "not secure" or "do not use"
 * in one of the user ids.  */
static int
is_insecure (ctrl_t ctrl, PKT_public_key *pk)
{
  u32 keyid[2];
  KBNODE node = NULL, u;
  int insecure = 0;

  keyid_from_pk (pk, keyid);
  node = get_pubkeyblock (ctrl, keyid);
  for (u = node; u; u = u->next)
    {
      if (u->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *id = u->pkt->pkt.user_id;
	  if (id->attrib_data)
	    continue;		/* skip attribute packets */
	  if (strstr (id->name, "(insecure!)")
	      || strstr (id->name, "not secure")
	      || strstr (id->name, "do not use")
	      || strstr (id->name, "(INSECURE!)"))
	    {
	      insecure = 1;
	      break;
	    }
	}
    }
  release_kbnode (node);

  return insecure;
}

static int
key_present_in_sk_list (SK_LIST sk_list, PKT_public_key *pk)
{
  for (; sk_list; sk_list = sk_list->next)
    {
      if (!cmp_public_keys (sk_list->pk, pk))
	return 0;
    }
  return -1;
}

static int
is_duplicated_entry (strlist_t list, strlist_t item)
{
  for (; list && list != item; list = list->next)
    {
      if (!strcmp (list->d, item->d))
	return 1;
    }
  return 0;
}


gpg_error_t
build_sk_list (ctrl_t ctrl,
               strlist_t locusr, SK_LIST *ret_sk_list, unsigned int use)
{
  gpg_error_t err;
  SK_LIST sk_list = NULL;

  /* XXX: Change this function to use get_pubkeys instead of
     getkey_byname to detect ambiguous key specifications and warn
     about duplicate keyblocks.  For ambiguous key specifications on
     the command line or provided interactively, prompt the user to
     select the best key.  If a key specification is ambiguous and we
     are in batch mode, die.  */

  if (!locusr) /* No user ids given - use the card key or the default key.  */
    {
      struct agent_card_info_s info;
      PKT_public_key *pk;

      memset (&info, 0, sizeof(info));
      pk = xmalloc_clear (sizeof *pk);
      pk->req_usage = use;

      /* Check if a card is available.  If any, use the key as a hint.  */
      err = agent_scd_serialno (NULL, NULL);
      if (!err)
        {
          err = agent_scd_getattr ("KEY-FPR", &info);
          if (err)
            log_error ("error retrieving key fingerprint from card: %s\n",
                       gpg_strerror (err));
        }

      err = get_seckey_default_or_card (ctrl, pk,
                                        info.fpr1len? info.fpr1 : NULL,
                                        info.fpr1len);
      if (err)
	{
	  free_public_key (pk);
	  pk = NULL;
	  log_error ("no default secret key: %s\n", gpg_strerror (err));
	  write_status_text (STATUS_INV_SGNR, get_inv_recpsgnr_code (err));
	}
      else if ((err = openpgp_pk_test_algo2 (pk->pubkey_algo, use)))
	{
	  free_public_key (pk);
	  pk = NULL;
	  log_error ("invalid default secret key: %s\n", gpg_strerror (err));
	  write_status_text (STATUS_INV_SGNR, get_inv_recpsgnr_code (err));
	}
      else
	{
	  SK_LIST r;

	  if (random_is_faked () && !is_insecure (ctrl, pk))
	    {
	      log_info (_("key is not flagged as insecure - "
			  "can't use it with the faked RNG!\n"));
	      free_public_key (pk);
	      pk = NULL;
	      write_status_text (STATUS_INV_SGNR,
				 get_inv_recpsgnr_code (GPG_ERR_NOT_TRUSTED));
	    }
	  else
	    {
	      r = xmalloc (sizeof *r);
	      r->pk = pk;
	      pk = NULL;
	      r->next = sk_list;
	      r->mark = 0;
	      sk_list = r;
	    }
	}
    }
  else /* Check the given user ids.  */
    {
      strlist_t locusr_orig = locusr;

      for (; locusr; locusr = locusr->next)
	{
	  PKT_public_key *pk;

	  err = 0;
	  /* Do an early check against duplicated entries.  However
	   * this won't catch all duplicates because the user IDs may
	   * be specified in different ways.  */
	  if (is_duplicated_entry (locusr_orig, locusr))
	    {
	      log_info (_("skipped \"%s\": duplicated\n"), locusr->d);
	      continue;
	    }
	  pk = xmalloc_clear (sizeof *pk);
	  pk->req_usage = use;
          if ((err = getkey_byname (ctrl, NULL, pk, locusr->d, 1, NULL)))
	    {
	      free_public_key (pk);
	      pk = NULL;
	      log_error (_("skipped \"%s\": %s\n"),
			 locusr->d, gpg_strerror (err));
	      write_status_text_and_buffer
		(STATUS_INV_SGNR, get_inv_recpsgnr_code (err),
		 locusr->d, strlen (locusr->d), -1);
	    }
	  else if (!key_present_in_sk_list (sk_list, pk))
	    {
	      free_public_key (pk);
	      pk = NULL;
	      log_info (_("skipped: secret key already present\n"));
	    }
	  else if ((err = openpgp_pk_test_algo2 (pk->pubkey_algo, use)))
	    {
	      free_public_key (pk);
	      pk = NULL;
	      log_error ("skipped \"%s\": %s\n", locusr->d, gpg_strerror (err));
	      write_status_text_and_buffer
		(STATUS_INV_SGNR, get_inv_recpsgnr_code (err),
		 locusr->d, strlen (locusr->d), -1);
	    }
	  else
	    {
	      SK_LIST r;

	      if (pk->version == 4 && (use & PUBKEY_USAGE_SIG)
		  && pk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E)
		{
		  log_info (_("skipped \"%s\": %s\n"), locusr->d,
			    _("this is a PGP generated Elgamal key which"
			      " is not secure for signatures!"));
		  free_public_key (pk);
		  pk = NULL;
		  write_status_text_and_buffer
		    (STATUS_INV_SGNR,
		     get_inv_recpsgnr_code (GPG_ERR_WRONG_KEY_USAGE),
		     locusr->d, strlen (locusr->d), -1);
		}
	      else if (random_is_faked () && !is_insecure (ctrl, pk))
		{
		  log_info (_("key is not flagged as insecure - "
			      "can't use it with the faked RNG!\n"));
		  free_public_key (pk);
		  pk = NULL;
		  write_status_text_and_buffer
		    (STATUS_INV_SGNR,
		     get_inv_recpsgnr_code (GPG_ERR_NOT_TRUSTED),
		     locusr->d, strlen (locusr->d), -1);
		}
	      else
		{
		  r = xmalloc (sizeof *r);
		  r->pk = pk;
		  pk = NULL;
		  r->next = sk_list;
		  r->mark = 0;
		  sk_list = r;
		}
	    }
	}
    }

  if (!err && !sk_list)
    {
      log_error ("no valid signators\n");
      write_status_text (STATUS_NO_SGNR, "0");
      err = gpg_error (GPG_ERR_NO_USER_ID);
    }

  if (err)
    release_sk_list (sk_list);
  else
    *ret_sk_list = sk_list;
  return err;
}


/* Enumerate some secret keys (specifically, those specified with
 * --default-key and --try-secret-key).  Use the following procedure:
 *
 *  1) Initialize a void pointer to NULL
 *  2) Pass a reference to this pointer to this function (context)
 *     and provide space for the secret key (sk)
 *  3) Call this function as long as it does not return an error (or
 *     until you are done).  The error code GPG_ERR_EOF indicates the
 *     end of the listing.
 *  4) Call this function a last time with SK set to NULL,
 *     so that can free it's context.
 *
 * In pseudo-code:
 *
 *   void *ctx = NULL;
 *   PKT_public_key *sk = xmalloc_clear (sizeof (*sk));
 *
 *   while ((err = enum_secret_keys (&ctx, sk)))
 *     { // Process SK.
 *       if (done)
 *         break;
 *       sk = xmalloc_clear (sizeof (*sk));
 *     }
 *
 *   // Release any resources used by CTX.
 *   enum_secret_keys (&ctx, NULL);
 *
 *   if (gpg_err_code (err) != GPG_ERR_EOF)
 *     ; // An error occurred.
 */
gpg_error_t
enum_secret_keys (ctrl_t ctrl, void **context, PKT_public_key *sk)
{
  gpg_error_t err = 0;
  const char *name;
  int cardkey;
  kbnode_t keyblock;
  struct
  {
    int eof;
    int state;
    int cardkey_done;
    strlist_t sl;
    keypair_info_t card_keyinfo;
    keypair_info_t card_keyinfo_list;
    char fpr2[2 * MAX_FINGERPRINT_LEN + 2 ];
    kbnode_t keyblock;
    kbnode_t node;
    getkey_ctx_t ctx;
    SK_LIST results;
  } *c = *context;

#if MAX_FINGERPRINT_LEN < KEYGRIP_LEN
# error buffer too short for this configuration
#endif

  if (!c)
    {
      /* Make a new context.  */
      c = xtrycalloc (1, sizeof *c);
      if (!c)
        {
          err = gpg_error_from_syserror ();
          free_public_key (sk);
          return err;
        }
      *context = c;
    }

  if (!sk)
    {
      /* Free the context.  */
      free_keypair_info (c->card_keyinfo_list);
      release_sk_list (c->results);
      release_kbnode (c->keyblock);
      getkey_end (ctrl, c->ctx);
      xfree (c);
      *context = NULL;
      return 0;
    }

  if (c->eof)
    {
      free_public_key (sk);
      return gpg_error (GPG_ERR_EOF);
    }

  for (;;)
    {
      /* Loop until we have a keyblock.  */
      while (!c->keyblock)
        {
          /* Loop over the list of secret keys.  */
          do
            {
              name = NULL;
              cardkey = 0;
              keyblock = NULL;
              switch (c->state)
                {
                case 0: /* First try to use the --default-key.  */
                  name = parse_def_secret_key (ctrl);
                  c->state = 1;
                  break;

                case 1: /* Init list of keys to try.  */
                  c->sl = opt.secret_keys_to_try;
                  c->state++;
                  break;

                case 2: /* Get next item from list.  */
                  if (c->sl)
                    {
                      name = c->sl->d;
                      c->sl = c->sl->next;
                    }
                  else
                    c->state++;
                  break;

                case 3: /* Init list of card keys to try.  */
                  c->card_keyinfo_list = NULL;
                  err = agent_scd_serialno (NULL, NULL);
                  if (!err)
                    {
                      err = agent_scd_keyinfo (NULL, GCRY_PK_USAGE_ENCR,
                                               &c->card_keyinfo_list);
                    }
                  c->card_keyinfo = c->card_keyinfo_list;
                  c->state++;
                  break;

                case 4: /* Get next item from card keyinfo.  */
                  if (c->card_keyinfo)
                    {
                      const char *s;
                      int i;

                      /* Get the key using the keygrip.  */
                      c->fpr2[0] = '&';
                      for (i=1, s = c->card_keyinfo->keygrip;
                           (*s && *s != ' '
                            && i < sizeof c->fpr2 - 2);
                           s++, i++)
                        c->fpr2[i] = *s;
                      c->fpr2[i] = 0;
                      name = c->fpr2;
                      cardkey = 1;

                      c->card_keyinfo = c->card_keyinfo->next;
                    }
                  else
                    c->state++;
                  break;

                case 5: /* Init search context to enum all secret keys.  */
                  err = getkey_bynames (ctrl, &c->ctx, NULL, NULL, 1,
                                        &keyblock);
                  if (err)
                    {
                      release_kbnode (keyblock);
                      keyblock = NULL;
                      getkey_end (ctrl, c->ctx);
                      c->ctx = NULL;
                    }
                  c->state++;
                  break;

                case 6: /* Get next item from the context.  */
                  if (c->ctx)
                    {
                      err = getkey_next (ctrl, c->ctx, NULL, &keyblock);
                      if (err)
                        {
                          release_kbnode (keyblock);
                          keyblock = NULL;
                          getkey_end (ctrl, c->ctx);
                          c->ctx = NULL;
                        }
                    }
                  else
                    c->state++;
                  break;

                default: /* No more names to check - stop.  */
                  c->eof = 1;
                  free_public_key (sk);
                  return gpg_error (GPG_ERR_EOF);
                }
            }
          while ((!name || !*name) && !keyblock);

          if (keyblock)
            c->node = c->keyblock = keyblock;
          else
            {
              err = getkey_byname (ctrl, NULL, NULL, name, 1, &c->keyblock);
              if (err)
                {
                  struct agent_card_info_s cinfo = { 0 };

                  /* getkey_byname might return a keyblock even in the
                     error case - I have not checked.  Thus better release
                     it.  */
                  release_kbnode (c->keyblock);
                  c->keyblock = NULL;
                  /* If this was a card key we might not yet have the
                   * public key for it.  Thus check whether the card
                   * can return the fingerprint of the encryption key
                   * and we can then find the public key via LDAP.  */
                  if (cardkey && !c->cardkey_done
                      && gpg_err_code (err) == GPG_ERR_NO_SECKEY
                      && !agent_scd_getattr ("KEY-FPR", &cinfo)
                      && cinfo.fpr2len)
                    {
                      /* Note that this code does not handle the case
                       * for two readers having both openpgp
                       * encryption keys. only one will be tried.  */
                      c->cardkey_done = 1;
                      if (opt.debug)
                        log_debug ("using LDAP to find public key"
                                   " for current card\n");
                      if (!keyserver_import_fprint
                          (ctrl, cinfo.fpr2, cinfo.fpr2len, opt.keyserver,
                           KEYSERVER_IMPORT_FLAG_LDAP))
                        {
                          char fpr_string[MAX_FINGERPRINT_LEN * 2 + 1];

                          bin2hex (cinfo.fpr2, cinfo.fpr2len, fpr_string);
                          err = getkey_byname (ctrl, NULL, NULL, fpr_string, 1,
                                               &c->keyblock);
                          if (err)
                            {
                              release_kbnode (c->keyblock);
                              c->keyblock = NULL;
                            }
                          else
                            c->node = c->keyblock;
                        }
                    }
                }
              else
                c->node = c->keyblock;
            }
        }

      /* Get the next key from the current keyblock.  */
      for (; c->node; c->node = c->node->next)
        {
          if (c->node->pkt->pkttype == PKT_PUBLIC_KEY
              || c->node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
            {
              SK_LIST r;

              /* Skip this candidate if it's already enumerated.  */
              for (r = c->results; r; r = r->next)
                if (!cmp_public_keys (r->pk, c->node->pkt->pkt.public_key))
                  break;
              if (r)
                continue;

              copy_public_key (sk, c->node->pkt->pkt.public_key);
              c->node = c->node->next;

              r = xtrycalloc (1, sizeof (*r));
              if (!r)
                {
                  err = gpg_error_from_syserror ();
                  free_public_key (sk);
                  return err;
                }

              r->pk = sk;
              r->next = c->results;
              c->results = r;

              return 0; /* Found.  */
            }
        }

      /* Dispose the keyblock and continue.  */
      release_kbnode (c->keyblock);
      c->keyblock = NULL;
    }
}
