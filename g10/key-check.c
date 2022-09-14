/* key-check.c - Detect and fix various problems with keys
 * Copyright (C) 1998-2010 Free Software Foundation, Inc.
 * Copyright (C) 1998-2017 Werner Koch
 * Copyright (C) 2015-2018 g10 Code GmbH
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
#include "packet.h"
#include "keydb.h"
#include "main.h"
#include "../common/ttyio.h"
#include "../common/i18n.h"
#include "keyedit.h"

#include "key-check.h"


/* Print PREFIX followed by TEXT.  With mode > 0 use log_info, with
 * mode < 0 use ttyio, else print to stdout.  If TEXT is not NULL, it
 * may be modified by this function.  */
static void
print_info (int mode, const char *prefix, char *text)
{
  char *p;

  if (!text)
    text = "";
  else if ((p = strchr (text,'\n')))
    *p = 0; /* Strip LF.  */

   if (mode > 0)
     log_info ("%s %s\n", prefix, text);
   else
     tty_fprintf (mode? NULL:es_stdout, "%s %s\n", prefix, text);
}


/* Order two signatures.  The actual ordering isn't important.  Our
 * goal is to ensure that identical signatures occur together.  */
static int
sig_comparison (const void *av, const void *bv)
{
  const KBNODE an = *(const KBNODE *) av;
  const KBNODE bn = *(const KBNODE *) bv;
  const PKT_signature *a;
  const PKT_signature *b;
  int ndataa;
  int ndatab;
  int i;

  log_assert (an->pkt->pkttype == PKT_SIGNATURE);
  log_assert (bn->pkt->pkttype == PKT_SIGNATURE);

  a = an->pkt->pkt.signature;
  b = bn->pkt->pkt.signature;

  /* Signatures with a different help counter are not identical for
   * our purpose.  */
  if (a->help_counter < b->help_counter)
    return -1;
  if (a->help_counter > b->help_counter)
    return 1;

  if (a->digest_algo < b->digest_algo)
    return -1;
  if (a->digest_algo > b->digest_algo)
    return 1;

  ndataa = pubkey_get_nsig (a->pubkey_algo);
  ndatab = pubkey_get_nsig (b->pubkey_algo);
  if (ndataa != ndatab)
    return (ndataa < ndatab)? -1 : 1;

  for (i = 0; i < ndataa; i ++)
    {
      int c = gcry_mpi_cmp (a->data[i], b->data[i]);
      if (c != 0)
        return c;
    }

  /* Okay, they are equal.  */
  return 0;
}


static gpg_error_t
remove_duplicate_sigs (kbnode_t kb, int *dups, int *modified)
{
  gpg_error_t err;
  kbnode_t n;
  int nsigs;
  kbnode_t *sigs;  /* Allocated array with the signature packet.  */
  int i;
  int last_i;
  int block;
  PKT_signature *sig;

  /* Count the sigs.  */
  for (nsigs = 0, n = kb; n; n = n->next)
    {
      if (is_deleted_kbnode (n))
        continue;
      else if (n->pkt->pkttype == PKT_SIGNATURE)
        nsigs ++;
    }

  if (!nsigs)
    return 0; /* No signatures at all.  */

  /* Add them all to the SIGS array.  */
  sigs = xtrycalloc (nsigs, sizeof *sigs);
  if (!sigs)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error allocating memory: %s\n"), gpg_strerror (err));
      return err;
    }

  block = 0;
  i = 0;
  for (n = kb; n; n = n->next)
    {
      if (is_deleted_kbnode (n))
        continue;

      if (n->pkt->pkttype != PKT_SIGNATURE)
        {
          switch (n->pkt->pkttype)
            {
            case PKT_PUBLIC_SUBKEY:
            case PKT_SECRET_SUBKEY:
            case PKT_USER_ID:
            case PKT_ATTRIBUTE:
              /* Bump the block number so that we only consider
               * signatures below the same object as duplicates.  */
              block++;
              break;
            default:
              break;
            }
          continue;
        }
      sig = n->pkt->pkt.signature;
      sig->help_counter = block;
      sigs[i++] = n;
    }
  log_assert (i == nsigs);

  qsort (sigs, nsigs, sizeof (sigs[0]), sig_comparison);

  last_i = 0;
  for (i = 1; i < nsigs; i ++)
    {
      log_assert (sigs[last_i]);
      log_assert (sigs[last_i]->pkt->pkttype == PKT_SIGNATURE);
      log_assert (sigs[i]);
      log_assert (sigs[i]->pkt->pkttype == PKT_SIGNATURE);

      if (sig_comparison (&sigs[last_i], &sigs[i]) == 0)
        {
          /* They are the same.  Kill the latter.  */
          if (DBG_PACKET)
            {
              sig = sigs[i]->pkt->pkt.signature;

              log_debug ("Signature appears multiple times, "
                         "deleting duplicate:\n");
              log_debug ("  sig: class 0x%x, issuer: %s,"
                         " timestamp: %s (%lld), digest: %02x %02x\n",
                         sig->sig_class, keystr (sig->keyid),
                         isotimestamp (sig->timestamp),
                         (long long) sig->timestamp,
                         sig->digest_start[0], sig->digest_start[1]);
            }

          /* Remove sigs[i] from the keyblock.  */
          {
            kbnode_t z, *prevp;
            int to_kill = last_i;
            last_i = i;

            for (prevp = &kb, z = kb; z; prevp = &z->next, z = z->next)
              if (z == sigs[to_kill])
                break;

            *prevp = sigs[to_kill]->next;

            sigs[to_kill]->next = NULL;
            release_kbnode (sigs[to_kill]);
            sigs[to_kill] = NULL;

            ++*dups;
            *modified = 1;
          }
        }
      else
        last_i = i;
    }

  xfree (sigs);
  return 0;
}


/* Perform a few sanity checks on a keyblock is okay and possibly
 * repair some damage.  Concretely:
 *
 *   - Detect duplicate signatures and remove them.
 *
 *   - Detect out of order signatures and relocate them (e.g., a sig
 *     over user id X located under subkey Y).
 *
 * Note: this function does not remove signatures that don't belong or
 * components that are not signed!  (Although it would be trivial to
 * do so.)
 *
 * If ONLY_SELFSIGS is true, then this function only reorders self
 * signatures (it still checks all signatures for duplicates,
 * however).
 *
 * Allowed values for MODE are:
 *  -1 - print to the TTY
 *   0 - print to stdout
 *   1 - use log_info.
 *
 * Returns true if the keyblock was modified.  */
int
key_check_all_keysigs (ctrl_t ctrl, int mode, kbnode_t kb,
                       int only_selected, int only_selfsigs)
{
  gpg_error_t err;
  PKT_public_key *pk;
  KBNODE n, n_next, *n_prevp, n2;
  char *pending_desc = NULL;
  PKT_public_key *issuer;
  KBNODE last_printed_component;
  KBNODE current_component = NULL;
  int dups = 0;
  int missing_issuer = 0;
  int reordered = 0;
  int bad_signature = 0;
  int missing_selfsig = 0;
  int modified = 0;
  PKT_signature *sig;

  (void)missing_selfsig;
  log_assert (kb->pkt->pkttype == PKT_PUBLIC_KEY);
  pk = kb->pkt->pkt.public_key;

  /* First we look for duplicates.  */
  if (remove_duplicate_sigs (kb, &dups, &modified))
    goto leave;  /* Error */

  /* Now make sure the sigs occur after the component (aka block)
   * (public key, subkey, user id) that they sign.  */
  issuer = NULL;
  last_printed_component = NULL;
  for (n_prevp = &kb, n = kb;
       n;
       /* If we moved n, then n_prevp is need valid.  */
       n_prevp = (n->next == n_next ? &n->next : n_prevp), n = n_next)
    {
      PACKET *p;
      int processed_current_component;
      int rc;
      int dump_sig_params = 0;

      n_next = n->next;

      if (is_deleted_kbnode (n))
        continue;

      p = n->pkt;

      if (issuer && issuer != pk)
        {
          free_public_key (issuer);
          issuer = NULL;
        }

      xfree (pending_desc);
      pending_desc = NULL;

      switch (p->pkttype)
        {
        case PKT_PUBLIC_KEY:
          log_assert (p->pkt.public_key == pk);
          if (only_selected && ! (n->flag & NODFLG_SELKEY))
            {
              current_component = NULL;
              break;
            }

          if (DBG_PACKET)
            log_debug ("public key %s: timestamp: %s (%lld)\n",
                       pk_keyid_str (pk),
                       isotimestamp (pk->timestamp),
                       (long long) pk->timestamp);
          current_component = n;
          break;
        case PKT_PUBLIC_SUBKEY:
          if (only_selected && ! (n->flag & NODFLG_SELKEY))
            {
              current_component = NULL;
              break;
            }

          if (DBG_PACKET)
            log_debug ("subkey %s: timestamp: %s (%lld)\n",
                       pk_keyid_str (p->pkt.public_key),
                       isotimestamp (p->pkt.public_key->timestamp),
                       (long long) p->pkt.public_key->timestamp);
          current_component = n;
          break;
        case PKT_USER_ID:
          if (only_selected && ! (n->flag & NODFLG_SELUID))
            {
              current_component = NULL;
              break;
            }

          if (DBG_PACKET)
            log_debug ("user id: %s\n",
                       p->pkt.user_id->attrib_data
                       ? "[ photo id ]"
                       : p->pkt.user_id->name);
          current_component = n;
          break;
        case PKT_SIGNATURE:
          if (! current_component)
            /* The current component is not selected, don't check the
               sigs under it.  */
            break;

          sig = n->pkt->pkt.signature;

          pending_desc = xasprintf ("  sig: class: 0x%x, issuer: %s,"
                                    " timestamp: %s (%lld), digest: %02x %02x",
                                    sig->sig_class,
                                    keystr (sig->keyid),
                                    isotimestamp (sig->timestamp),
                                    (long long) sig->timestamp,
                                    sig->digest_start[0], sig->digest_start[1]);


          if (keyid_cmp (pk_keyid (pk), sig->keyid) == 0)
            issuer = pk;
          else /* Issuer is a different key.  */
            {
              if (only_selfsigs)
                continue;

              issuer = xtrycalloc (1, sizeof *issuer);
              if (!issuer)
                err = gpg_error_from_syserror ();
              else
                err = get_pubkey (ctrl, issuer, sig->keyid);
              if (err)
                {
                  xfree (issuer);
                  issuer = NULL;
                  if (DBG_PACKET)
                    {
                      if (pending_desc)
                        log_debug ("%s", pending_desc);
                      log_debug ("    Can't check signature allegedly"
                                 " issued by %s: %s\n",
                                 keystr (sig->keyid), gpg_strerror (err));
                    }
                  missing_issuer ++;
                  break;
                }
            }

          if ((err = openpgp_pk_test_algo (sig->pubkey_algo)))
            {
              if (DBG_PACKET && pending_desc)
                log_debug ("%s", pending_desc);
              log_info (_("can't check signature with unsupported"
                          " public-key algorithm (%d): %s.\n"),
                          sig->pubkey_algo, gpg_strerror (err));
              break;
            }
          if ((err = openpgp_md_test_algo (sig->digest_algo)))
            {
              if (DBG_PACKET && pending_desc)
                log_debug ("%s", pending_desc);
              log_info (_("can't check signature with unsupported"
                          " message-digest algorithm %d: %s.\n"),
                          sig->digest_algo, gpg_strerror (err));
              break;
            }

          /* We iterate over the keyblock.  Most likely, the matching
             component is the current component so always try that
             first.  */
          processed_current_component = 0;
          for (n2 = current_component;
               n2;
               n2 = (processed_current_component ? n2->next : kb),
                 processed_current_component = 1)
            if (is_deleted_kbnode (n2))
              continue;
            else if (processed_current_component && n2 == current_component)
              /* Don't process it twice.  */
              continue;
            else
              {
                err = check_signature_over_key_or_uid (ctrl,
                                                       issuer, sig, kb, n2->pkt,
                                                       NULL, NULL);
                if (! err)
                  break;
              }

          /* n/sig is a signature and n2 is the component (public key,
             subkey or user id) that it signs, if any.
             current_component is that component that it appears to
             apply to (according to the ordering).  */

          if (current_component == n2)
            {
              if (DBG_PACKET)
                {
                  log_debug ("%s", pending_desc);
                  log_debug ("    Good signature over last key or uid!\n");
                }

              rc = 0;
            }
          else if (n2)
            {
              log_assert (n2->pkt->pkttype == PKT_USER_ID
                          || n2->pkt->pkttype == PKT_PUBLIC_KEY
                          || n2->pkt->pkttype == PKT_PUBLIC_SUBKEY);

              if (DBG_PACKET)
                {
                  log_debug ("%s", pending_desc);
                  log_debug ("    Good signature out of order!"
                             "  (Over %s (%d) '%s')\n",
                             n2->pkt->pkttype == PKT_USER_ID
                             ? "user id"
                             : n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
                             ? "subkey"
                             : "primary key",
                             n2->pkt->pkttype,
                             n2->pkt->pkttype == PKT_USER_ID
                             ? n2->pkt->pkt.user_id->name
                             : pk_keyid_str (n2->pkt->pkt.public_key));
                }

              /* Reorder the packets: move the signature n to be just
                 after n2.  */

              /* Unlink the signature.  */
              log_assert (n_prevp);
              *n_prevp = n->next;

              /* Insert the sig immediately after the component.  */
              n->next = n2->next;
              n2->next = n;

              reordered ++;
              modified = 1;

              rc = 0;
            }
          else
            {
              if (DBG_PACKET)
                {
                  log_debug ("%s", pending_desc);
                  log_debug ("    Bad signature.\n");
                }

              if (DBG_PACKET)
                dump_sig_params = 1;

              bad_signature ++;

              rc = GPG_ERR_BAD_SIGNATURE;
            }

          /* We don't cache the result here, because we haven't
             completely checked that the signature is legitimate.  For
             instance, if we have a revocation certificate on Alice's
             key signed by Bob, the signature may be good, but we
             haven't checked that Bob is a designated revoker.  */
          /* cache_sig_result (sig, rc); */

          {
            int has_selfsig = 0;
            if (! rc && issuer == pk)
              {
                if (n2->pkt->pkttype == PKT_PUBLIC_KEY
                    && (/* Direct key signature.  */
                        sig->sig_class == 0x1f
                        /* Key revocation signature.  */
                        || sig->sig_class == 0x20))
                  has_selfsig = 1;
                if (n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
                    && (/* Subkey binding sig.  */
                        sig->sig_class == 0x18
                        /* Subkey revocation sig.  */
                        || sig->sig_class == 0x28))
                  has_selfsig = 1;
                if (n2->pkt->pkttype == PKT_USER_ID
                    && (/* Certification sigs.  */
                        sig->sig_class == 0x10
                        || sig->sig_class == 0x11
                        || sig->sig_class == 0x12
                        || sig->sig_class == 0x13
                        /* Certification revocation sig.  */
                        || sig->sig_class == 0x30))
                  has_selfsig = 1;
              }

            if (DBG_PACKET
                && ((n2 && n2 != last_printed_component)
                    || (! n2 && last_printed_component != current_component)))
              {
                int is_reordered = n2 && n2 != current_component;
                if (n2)
                  last_printed_component = n2;
                else
                  last_printed_component = current_component;

                if (!modified)
                  ;
                else if (last_printed_component->pkt->pkttype == PKT_USER_ID)
                  {
                    log_debug ("uid  ");
                    print_utf8_buffer (log_get_stream (),
                                       last_printed_component
                                       ->pkt->pkt.user_id->name,
                                       last_printed_component
                                       ->pkt->pkt.user_id->len);
                    log_flush ();
                  }
                else if (last_printed_component->pkt->pkttype
                         == PKT_PUBLIC_KEY)
                  log_debug ("pub  %s\n",
                             pk_keyid_str (last_printed_component
                                             ->pkt->pkt.public_key));
                else
                  log_debug ("sub  %s\n",
                             pk_keyid_str (last_printed_component
                                           ->pkt->pkt.public_key));

                if (modified)
                  {
                    if (is_reordered)
                      log_debug ("%s\n", _(" (reordered signatures follow)"));
                  }
              }

            if (DBG_PACKET && modified)
              keyedit_print_one_sig (ctrl, log_get_stream (),
                                     rc, kb, n, NULL, NULL, NULL,
				     has_selfsig, 0, only_selfsigs);
          }

          if (dump_sig_params)
            {
              int i;

              for (i = 0; i < pubkey_get_nsig (sig->pubkey_algo); i ++)
                {
                  char buffer[1024];
                  size_t len;
                  char *printable;
                  if (gcry_mpi_get_flag (sig->data[i], GCRYMPI_FLAG_OPAQUE))
                    {
                      const byte *sigdata;
                      unsigned int nbits;

                      sigdata = gcry_mpi_get_opaque (sig->data[i], &nbits);
                      len = (nbits+7)/8;
                      memcpy (buffer, sigdata, len);
                    }
                  else
                    gcry_mpi_print (GCRYMPI_FMT_USG,
                                    buffer, sizeof (buffer), &len,
                                    sig->data[i]);
                  printable = bin2hex (buffer, len, NULL);
                  log_debug ("        %d: %s\n", i, printable);
                  xfree (printable);
                }
            }
          break;
        default:
          if (DBG_PACKET)
            log_debug ("unhandled packet: %d\n", p->pkttype);
          break;
        }
    }

  xfree (pending_desc);
  pending_desc = NULL;

  if (issuer != pk)
    free_public_key (issuer);
  issuer = NULL;

  /* If we reordered signatures we need to de-duplicate again because
   * a signature can now be a duplicate in another block.  */
  if (reordered)
    {
      if (remove_duplicate_sigs (kb, &dups, &modified))
        goto leave;
    }

  /* Identify keys / uids that don't have a self-sig.  */
  {
    int has_selfsig = 0;
    PACKET *p;

    current_component = NULL;
    for (n = kb; n; n = n->next)
      {
        if (is_deleted_kbnode (n))
          continue;

        p = n->pkt;

        switch (p->pkttype)
          {
          case PKT_PUBLIC_KEY:
          case PKT_PUBLIC_SUBKEY:
          case PKT_USER_ID:
            if (current_component && ! has_selfsig)
              missing_selfsig ++;
            current_component = n;
            has_selfsig = 0;
            break;

          case PKT_SIGNATURE:
            if (! current_component || has_selfsig)
              break;

            sig = n->pkt->pkt.signature;

            if (! (sig->flags.checked && sig->flags.valid))
              break;

            if (keyid_cmp (pk_keyid (pk), sig->keyid) != 0)
              /* Different issuer, couldn't be a self-sig.  */
              break;

            if (current_component->pkt->pkttype == PKT_PUBLIC_KEY
                && (/* Direct key signature.  */
                    sig->sig_class == 0x1f
                    /* Key revocation signature.  */
                    || sig->sig_class == 0x20))
              has_selfsig = 1;
            if (current_component->pkt->pkttype == PKT_PUBLIC_SUBKEY
                && (/* Subkey binding sig.  */
                    sig->sig_class == 0x18
                    /* Subkey revocation sig.  */
                    || sig->sig_class == 0x28))
              has_selfsig = 1;
            if (current_component->pkt->pkttype == PKT_USER_ID
                && (/* Certification sigs.  */
                    sig->sig_class == 0x10
                    || sig->sig_class == 0x11
                    || sig->sig_class == 0x12
                    || sig->sig_class == 0x13
                    /* Certification revocation sig.  */
                    || sig->sig_class == 0x30))
              has_selfsig = 1;

            break;

          default:
            if (current_component && ! has_selfsig)
              missing_selfsig ++;
            current_component = NULL;
          }
      }
  }


 leave:
  if (!opt.quiet)
    {
      char prefix[100];
      char *p;

      /* To avoid string changes in 2.2 we strip the LF here. */
      snprintf (prefix, sizeof prefix, _("key %s:\n"), pk_keyid_str (pk));
      p = strrchr (prefix, '\n');
      if (p)
        *p = 0;

      if (dups)
        {
          p = xtryasprintf
            (ngettext ("%d duplicate signature removed\n",
                       "%d duplicate signatures removed\n", dups), dups);
          print_info (mode, prefix, p);
          xfree (p);
        }

      if (missing_issuer)
        {
          p = xtryasprintf
            (ngettext ("%d signature not checked due to a missing key\n",
                       "%d signatures not checked due to missing keys\n",
                       missing_issuer), missing_issuer);
          print_info (mode, prefix, p);
          xfree (p);
        }
      if (bad_signature)
        {
          p = xtryasprintf (ngettext ("%d bad signature\n",
                                      "%d bad signatures\n",
                                      bad_signature), bad_signature);
          print_info (mode, prefix, p);
          xfree (p);
        }

      if (reordered)
        {
          p = xtryasprintf (ngettext ("%d signature reordered\n",
                                      "%d signatures reordered\n",
                                      reordered), reordered);
          print_info (mode, prefix, p);
          xfree (p);
        }

      if (only_selfsigs && (bad_signature || reordered))
        {
          p = xtryasprintf
            (_("Warning: errors found and only checked self-signatures,"
               " run '%s' to check all signatures.\n"), "check");
          print_info (mode, prefix, p);
          xfree (p);
        }
    }

  return modified;
}
