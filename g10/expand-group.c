/* expand-group.c - expand GPG group definitions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010 Free Software Foundation, Inc.
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

#include "gpg.h"
#include "options.h"
#include "keydb.h"

int
expand_id (const char *id, strlist_t *into, unsigned int flags)
{
  struct groupitem *groups;
  int count=0;

  for (groups = opt.grouplist; groups; groups=groups->next)
    {
      /* need strcasecmp() here, as this should be localized */
      if (strcasecmp (groups->name,id) == 0)
	 {
	   strlist_t each,sl;

	   /* This maintains the current utf8-ness */
	   for (each = groups->values; each; each=each->next)
	     {
	       sl = add_to_strlist (into, each->d);
	       sl->flags = flags;
	       count++;
	     }

	   break;
	 }
    }

  return count;
}

/* For simplicity, and to avoid potential loops, we only expand once -
 * you can't make an alias that points to an alias.  If PREPEND_INPUT
 * is true each item from INPUT is prepended to the new list; if it is
 * false the original item from INPUT is only added if no group
 * existed for it. */
strlist_t
expand_group (strlist_t input, int prepend_input)
{
  strlist_t output = NULL;
  strlist_t sl, rover;

  for (rover = input; rover; rover = rover->next)
    {
      if ((rover->flags & PK_LIST_FROM_FILE))
        continue;
      if (!expand_id (rover->d, &output, rover->flags))
        {
          /* Didn't find any groups, so use the existing string unless
           * we will anyway add it due to the prepend flag.  */
          if (!prepend_input)
            {
              sl = add_to_strlist (&output, rover->d);
              sl->flags = rover->flags;
            }
        }
      if (prepend_input)
        {
          sl = add_to_strlist (&output, rover->d);
          sl->flags = rover->flags;
        }
    }

  return output;
}


/* Extract all fingerprints from a party notation and return them in a strlist_t.
 * Caller needs to free the strlist. */
strlist_t
extract_members (notation_t party_notation)
{
  strlist_t output = NULL;
  byte *buf;
  size_t blen;
  size_t off = 0;

  /* No notation. */
  if (!party_notation)
    return NULL;

  /* Not a party notation. */
  if (memcmp (party_notation->name, "party@gnupg.org", strlen ("party@gnupg.org")))
    return NULL;

  buf = party_notation->bdat;
  blen = party_notation->blen;

  /* Empty member key. */
  if (blen == 1
      && !memcmp (buf, "-", strlen ("-")))
    return NULL;

  while (off < blen)
    {
      byte fprlen = 0;
      char *hexfpr = NULL;
      char *version = NULL;

      if (*buf == 4)
        fprlen = 20;
      else if (*buf == 5 || *buf == 6)
        fprlen = 32;
      else
        log_error ("invalid fingerprint length\n");

      /* Version.*/
      version = bin2hex (buf, 1, version);
      off++;
      buf++;

      /* Fingerprint. */
      hexfpr = bin2hex (buf, fprlen, hexfpr);
      off += fprlen;
      buf += fprlen;

      /* Add fpr to output. */
      output = add_to_strlist2 (&output, hexfpr, 0);
    }

  if (off != blen)
    {
      log_error ("extracting party members from notation failed.\n");
      return NULL;
    }

  return output;
}


/* Check INPUT for party keys. If a party key is found, extract
 * fingerprints of all party members from the party notation
 * and append them to the output list. Expand for the entire input.
 * If INCLUDE_PARTYKEY is set then the party key is also returned.
 * We dont want to include the party key for the recipients list when
 * encrypting but want to include it when exporting a party key and all members. */
strlist_t
expand_partykey (ctrl_t ctrl, strlist_t input, int include_partykey)
{
  int rc = 0;
  strlist_t output = NULL;
  strlist_t rcp = NULL;  /* recipient */

  const char* username = NULL;
  KEYDB_HANDLE hd = NULL;
  KEYDB_SEARCH_DESC desc;
  kbnode_t keyblock = NULL;
  kbnode_t node = NULL;

  strlist_t lastnode = NULL;
  int is_partykey = 0;



  if (!input)
    return NULL;

  for (rcp = input; rcp; rcp = rcp->next)
    {
      PKT_public_key *pk = NULL;
      u32 keyid[2];
      PKT_user_id *uid = NULL;
      int uid_count = 0;
      notation_t pnotation = NULL;
      strlist_t new_recipients = NULL;

      /* Maybe move this in front of the rcp loop. */
      keydb_release (hd);
      hd = keydb_new (ctrl);
      if (!hd)
        {
          rc = gpg_error_from_syserror ();
          log_error ("expanding party key failed: %s\n", gpg_strerror (rc));
          goto next;
        }

      username = rcp->d;
      rc = classify_user_id (username, &desc, 1);
      if (rc)
        goto next;

      rc = keydb_lock (hd);
      if (rc)
        goto next;

      rc = keydb_search (hd, &desc, 1, NULL);
      if (rc)
        {
          log_info ("key not found.\n");
          goto next;
        }

      release_kbnode (keyblock);
      rc = keydb_get_keyblock (hd, &keyblock);
      if (rc)
        {
          log_info ("failed to get the keyblock\n");
          goto next;
        }

      /* We need pubkey_usage later. */
      merge_keys_and_selfsig (ctrl, keyblock);

      /* First count user IDs and check for subkeys.
       * We allow exactly one user ID and no subkeys. */
      for (node = keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
                {
                  log_info ("skipping %s: not a party key.\n", username);
                  goto next;
                }

          if (node->pkt->pkttype == PKT_PUBLIC_KEY)
            {
              pk = node->pkt->pkt.public_key;

              if (!(pk->pubkey_usage & PUBKEY_USAGE_CERT)
                  || !(pk->pubkey_usage & PUBKEY_USAGE_PARTY))
                {
                  log_info ("skipping %s: not a party key.\n", username);
                  goto next;
                }

              keyid_from_pk (pk, keyid);
            }
          else if (node->pkt->pkttype == PKT_USER_ID)
            {
              if (uid_count)
                {
                  log_info ("skipping %s: not a party key "
                            "(multiple user IDs).\n", username);
                  goto next;
                }
              uid = node->pkt->pkt.user_id;
              uid_count++;
            }
        }

      if (!(pk && uid))
        {
          log_info ("skipping %s: invalid key\n", username);
          goto next;
        }

      for (node = keyblock; node; node = node->next)
        {
          is_partykey = 0;

          if (node->pkt->pkttype == PKT_SIGNATURE)
            {
              PKT_signature *sig = node->pkt->pkt.signature;
              /* User ID self-sig? */
              if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
                  && (uid && IS_UID_SIG (sig)))
                {
                  notation_t notation = NULL;
                  notation_t n;
                  int pn_count = 0;

                  notation = sig_to_notation (sig);

                  for (n = notation; n; n = n->next)
                    {
                      if (!strcmp (n->name, "party@gnupg.org"))
                            {
                              if (pn_count)
                                {
                                  log_error ("exactly party notation allowed.\n");
                                  goto next;
                                }
                              pn_count++;
                            }
                    }

                  if (pn_count != 1)
                    {
                      log_error ("exactly party notation allowed.\n");
                      goto next;
                    }

                  for (n = notation; n; n = n->next)
                    {
                      if (!strcmp (n->name, "party@gnupg.org"))
                        {
                          free_notation (pnotation);
                          pnotation = n;
                        }
                    }
                  /* We have a party key and found the notation. */
                  if (pnotation)
                    {
                      /* Only do this check if we expand_party for encryption.
                       * For encryption include_partykey is not set. */
                      if (!include_partykey)
                        {
                          pk_list_t dummy_pk_list = NULL;

                          is_partykey = 1;

                          /* We don't actually want to build a pk_list.
                           * We only want to check if the key is valid. */
                          rc = find_and_check_key (ctrl, username,
                                                   PUBKEY_USAGE_CERT
                                                   | PUBKEY_USAGE_PARTY,
                                                   0,
                                                   0,
                                                   &dummy_pk_list);
                          if (rc)
                            {
                              log_info ("skipping %s: invalid party key: %s\n",
                                        username, gpg_strerror (rc));

                              is_partykey = 0; /* not a valid partykey. */
                              goto next;
                            }
                        }
                      free_strlist (new_recipients);
                      new_recipients = extract_members (pnotation);
                      if (!new_recipients)
                        {
                          log_info ("party has no members.\n");
                          goto next;
                        }
                      else
                        {
                          strlist_t s;

                          /* new_recipients should inherit strlist_t flags
                           * from the partykey. */
                          for (s = new_recipients; s; s = s->next)
                            s->flags = rcp->flags;

                          /* Append new_recipients (party members) to output
                           * (all recipients). */
                          lastnode = strlist_last (output);
                          if (lastnode)
                            {
                              lastnode->next = strlist_copy (new_recipients);
                              lastnode = NULL;
                            }
                          else
                            output = strlist_copy (new_recipients);
                        }
                    }
                }
            }
        }


    next:
      /* We do it this way to keep strlist_t flags */
      if (!is_partykey || (is_partykey && include_partykey))
        {
          strlist_t tmp;

          lastnode = strlist_last (output);
          /* Append the current recipient to output. */
          tmp = strlist_copy (rcp);
          tmp->next = NULL;

          if (lastnode)
            lastnode->next = tmp;
          else /* Output was empty. */
          output = strlist_copy (tmp);
      }

      free_strlist (new_recipients);
      new_recipients = NULL;
      pk = NULL;
      uid = NULL;
      free_notation (pnotation);
      pnotation = NULL;
      uid_count = 0;
    }

  keydb_release (hd);
  hd = NULL;
  release_kbnode (keyblock);
  keyblock = NULL;

  return output;
}
