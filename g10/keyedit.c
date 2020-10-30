/* keyedit.c - Edit properties of a key
 * Copyright (C) 1998-2010 Free Software Foundation, Inc.
 * Copyright (C) 1998-2017 Werner Koch
 * Copyright (C) 2015, 2016 g10 Code GmbH
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
#include <ctype.h>
#ifdef HAVE_LIBREADLINE
# define GNUPG_LIBREADLINE_H_INCLUDED
# include <readline/readline.h>
#endif

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "../common/status.h"
#include "../common/iobuf.h"
#include "keydb.h"
#include "photoid.h"
#include "../common/util.h"
#include "main.h"
#include "trustdb.h"
#include "filter.h"
#include "../common/ttyio.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "keyserver-internal.h"
#include "call-agent.h"
#include "../common/host2net.h"
#include "tofu.h"
#include "key-check.h"
#include "key-clean.h"
#include "keyedit.h"

static void show_prefs (PKT_user_id * uid, PKT_signature * selfsig,
			int verbose);
static void show_names (ctrl_t ctrl, estream_t fp,
                        kbnode_t keyblock, PKT_public_key * pk,
			unsigned int flag, int with_prefs);
static void show_key_with_all_names (ctrl_t ctrl, estream_t fp,
                                     KBNODE keyblock, int only_marked,
				     int with_revoker, int with_fpr,
				     int with_subkeys, int with_prefs,
                                     int nowarn);
static void show_key_and_fingerprint (ctrl_t ctrl,
                                      kbnode_t keyblock, int with_subkeys);
static void show_key_and_grip (kbnode_t keyblock);
static void subkey_expire_warning (kbnode_t keyblock);
static int menu_adduid (ctrl_t ctrl, kbnode_t keyblock,
                        int photo, const char *photo_name, const char *uidstr);
static void menu_deluid (KBNODE pub_keyblock);
static int menu_delsig (ctrl_t ctrl, kbnode_t pub_keyblock);
static int menu_clean (ctrl_t ctrl, kbnode_t keyblock, int self_only);
static void menu_delkey (KBNODE pub_keyblock);
static int menu_addrevoker (ctrl_t ctrl, kbnode_t pub_keyblock, int sensitive);
static gpg_error_t menu_expire (ctrl_t ctrl, kbnode_t pub_keyblock,
                                int unattended, u32 newexpiration);
static int menu_changeusage (ctrl_t ctrl, kbnode_t keyblock);
static int menu_backsign (ctrl_t ctrl, kbnode_t pub_keyblock);
static int menu_set_primary_uid (ctrl_t ctrl, kbnode_t pub_keyblock);
static int menu_set_preferences (ctrl_t ctrl, kbnode_t pub_keyblock);
static int menu_set_keyserver_url (ctrl_t ctrl,
                                   const char *url, kbnode_t pub_keyblock);
static int menu_set_notation (ctrl_t ctrl,
                              const char *string, kbnode_t pub_keyblock);
static int menu_select_uid (KBNODE keyblock, int idx);
static int menu_select_uid_namehash (KBNODE keyblock, const char *namehash);
static int menu_select_key (KBNODE keyblock, int idx, char *p);
static int count_uids (KBNODE keyblock);
static int count_uids_with_flag (KBNODE keyblock, unsigned flag);
static int count_keys_with_flag (KBNODE keyblock, unsigned flag);
static int count_selected_uids (KBNODE keyblock);
static int real_uids_left (KBNODE keyblock);
static int count_selected_keys (KBNODE keyblock);
static int menu_revsig (ctrl_t ctrl, kbnode_t keyblock);
static int menu_revuid (ctrl_t ctrl, kbnode_t keyblock);
static int core_revuid (ctrl_t ctrl, kbnode_t keyblock, KBNODE node,
                        const struct revocation_reason_info *reason,
                        int *modified);
static int menu_revkey (ctrl_t ctrl, kbnode_t pub_keyblock);
static int menu_revsubkey (ctrl_t ctrl, kbnode_t pub_keyblock);
#ifndef NO_TRUST_MODELS
static int enable_disable_key (ctrl_t ctrl, kbnode_t keyblock, int disable);
#endif /*!NO_TRUST_MODELS*/
static void menu_showphoto (ctrl_t ctrl, kbnode_t keyblock);

static int update_trust = 0;

#define CONTROL_D ('D' - 'A' + 1)

struct sign_attrib
{
  int non_exportable, non_revocable;
  struct revocation_reason_info *reason;
  byte trust_depth, trust_value;
  char *trust_regexp;
};



/* TODO: Fix duplicated code between here and the check-sigs/list-sigs
   code in keylist.c. */
static int
print_and_check_one_sig_colon (ctrl_t ctrl, kbnode_t keyblock, kbnode_t node,
			       int *inv_sigs, int *no_key, int *oth_err,
			       int *is_selfsig, int print_without_key)
{
  PKT_signature *sig = node->pkt->pkt.signature;
  int rc, sigrc;

  /* TODO: Make sure a cached sig record here still has the pk that
     issued it.  See also keylist.c:list_keyblock_print */

  rc = check_key_signature (ctrl, keyblock, node, is_selfsig);
  switch (gpg_err_code (rc))
    {
    case 0:
      node->flag &= ~(NODFLG_BADSIG | NODFLG_NOKEY | NODFLG_SIGERR);
      sigrc = '!';
      break;
    case GPG_ERR_BAD_SIGNATURE:
      node->flag = NODFLG_BADSIG;
      sigrc = '-';
      if (inv_sigs)
	++ * inv_sigs;
      break;
    case GPG_ERR_NO_PUBKEY:
    case GPG_ERR_UNUSABLE_PUBKEY:
      node->flag = NODFLG_NOKEY;
      sigrc = '?';
      if (no_key)
	++ * no_key;
      break;
    default:
      node->flag = NODFLG_SIGERR;
      sigrc = '%';
      if (oth_err)
	++ * oth_err;
      break;
    }

  if (sigrc != '?' || print_without_key)
    {
      es_printf ("sig:%c::%d:%08lX%08lX:%lu:%lu:",
                 sigrc, sig->pubkey_algo, (ulong) sig->keyid[0],
                 (ulong) sig->keyid[1], (ulong) sig->timestamp,
                 (ulong) sig->expiredate);

      if (sig->trust_depth || sig->trust_value)
	es_printf ("%d %d", sig->trust_depth, sig->trust_value);

      es_printf (":");

      if (sig->trust_regexp)
	es_write_sanitized (es_stdout,
			    sig->trust_regexp, strlen (sig->trust_regexp),
			    ":", NULL);

      es_printf ("::%02x%c\n", sig->sig_class,
                 sig->flags.exportable ? 'x' : 'l');

      if (opt.show_subpackets)
	print_subpackets_colon (sig);
    }

  return (sigrc == '!');
}


/*
 * Print information about a signature (rc is its status), check it
 * and return true if the signature is okay.  NODE must be a signature
 * packet.  With EXTENDED set all possible signature list options will
 * always be printed.
 */
int
keyedit_print_one_sig (ctrl_t ctrl, estream_t fp,
                       int rc, kbnode_t keyblock, kbnode_t node,
		       int *inv_sigs, int *no_key, int *oth_err,
		       int is_selfsig, int print_without_key, int extended)
{
  PKT_signature *sig = node->pkt->pkt.signature;
  int sigrc;
  int is_rev = sig->sig_class == 0x30;

  /* TODO: Make sure a cached sig record here still has the pk that
     issued it.  See also keylist.c:list_keyblock_print */

  switch (gpg_err_code (rc))
    {
    case 0:
      node->flag &= ~(NODFLG_BADSIG | NODFLG_NOKEY | NODFLG_SIGERR);
      sigrc = '!';
      break;
    case GPG_ERR_BAD_SIGNATURE:
      node->flag = NODFLG_BADSIG;
      sigrc = '-';
      if (inv_sigs)
	++ * inv_sigs;
      break;
    case GPG_ERR_NO_PUBKEY:
    case GPG_ERR_UNUSABLE_PUBKEY:
      node->flag = NODFLG_NOKEY;
      sigrc = '?';
      if (no_key)
	++ * no_key;
      break;
    default:
      node->flag = NODFLG_SIGERR;
      sigrc = '%';
      if (oth_err)
	++ * oth_err;
      break;
    }
  if (sigrc != '?' || print_without_key)
    {
      tty_fprintf (fp, "%s%c%c %c%c%c%c%c%c %s %s",
		  is_rev ? "rev" : "sig", sigrc,
		  (sig->sig_class - 0x10 > 0 &&
		   sig->sig_class - 0x10 <
		   4) ? '0' + sig->sig_class - 0x10 : ' ',
		  sig->flags.exportable ? ' ' : 'L',
		  sig->flags.revocable ? ' ' : 'R',
		  sig->flags.policy_url ? 'P' : ' ',
		  sig->flags.notation ? 'N' : ' ',
		  sig->flags.expired ? 'X' : ' ',
		  (sig->trust_depth > 9) ? 'T' : (sig->trust_depth >
						  0) ? '0' +
		  sig->trust_depth : ' ',
                  keystr (sig->keyid),
		  datestr_from_sig (sig));
      if ((opt.list_options & LIST_SHOW_SIG_EXPIRE) || extended )
	tty_fprintf (fp, " %s", expirestr_from_sig (sig));
      tty_fprintf (fp, "  ");
      if (sigrc == '%')
	tty_fprintf (fp, "[%s] ", gpg_strerror (rc));
      else if (sigrc == '?')
	;
      else if (is_selfsig)
	{
	  tty_fprintf (fp, is_rev ? _("[revocation]") : _("[self-signature]"));
          if (extended && sig->flags.chosen_selfsig)
            tty_fprintf (fp, "*");
	}
      else
	{
	  size_t n;
	  char *p = get_user_id (ctrl, sig->keyid, &n, NULL);
	  tty_print_utf8_string2 (fp, p, n,
				  opt.screen_columns - keystrlen () - 26 -
				  ((opt.
				    list_options & LIST_SHOW_SIG_EXPIRE) ? 11
				   : 0));
	  xfree (p);
	}
      if (fp == log_get_stream ())
        log_printf ("\n");
      else
        tty_fprintf (fp, "\n");

      if (sig->flags.policy_url
          && ((opt.list_options & LIST_SHOW_POLICY_URLS) || extended))
	show_policy_url (sig, 3, (!fp? -1 : fp == log_get_stream ()? 1 : 0));

      if (sig->flags.notation
          && ((opt.list_options & LIST_SHOW_NOTATIONS) || extended))
	show_notation (sig, 3, (!fp? -1 : fp == log_get_stream ()? 1 : 0),
		       ((opt.
			 list_options & LIST_SHOW_STD_NOTATIONS) ? 1 : 0) +
		       ((opt.
			 list_options & LIST_SHOW_USER_NOTATIONS) ? 2 : 0));

      if (sig->flags.pref_ks
          && ((opt.list_options & LIST_SHOW_KEYSERVER_URLS) || extended))
	show_keyserver_url (sig, 3, (!fp? -1 : fp == log_get_stream ()? 1 : 0));

      if (extended)
        {
          PKT_public_key *pk = keyblock->pkt->pkt.public_key;
          const unsigned char *s;

          s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PRIMARY_UID, NULL);
          if (s && *s)
            tty_fprintf (fp, "             [primary]\n");

          s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE, NULL);
          if (s && buf32_to_u32 (s))
            tty_fprintf (fp, "             [expires: %s]\n",
                         isotimestamp (pk->timestamp + buf32_to_u32 (s)));
        }
    }

  return (sigrc == '!');
}


static int
print_and_check_one_sig (ctrl_t ctrl, kbnode_t keyblock, kbnode_t node,
			 int *inv_sigs, int *no_key, int *oth_err,
			 int *is_selfsig, int print_without_key, int extended)
{
  int rc;

  rc = check_key_signature (ctrl, keyblock, node, is_selfsig);
  return keyedit_print_one_sig (ctrl, NULL, rc,
				keyblock, node, inv_sigs, no_key, oth_err,
				*is_selfsig, print_without_key, extended);
}


static int
sign_mk_attrib (PKT_signature * sig, void *opaque)
{
  struct sign_attrib *attrib = opaque;
  byte buf[8];

  if (attrib->non_exportable)
    {
      buf[0] = 0;		/* not exportable */
      build_sig_subpkt (sig, SIGSUBPKT_EXPORTABLE, buf, 1);
    }

  if (attrib->non_revocable)
    {
      buf[0] = 0;		/* not revocable */
      build_sig_subpkt (sig, SIGSUBPKT_REVOCABLE, buf, 1);
    }

  if (attrib->reason)
    revocation_reason_build_cb (sig, attrib->reason);

  if (attrib->trust_depth)
    {
      /* Not critical.  If someone doesn't understand trust sigs,
         this can still be a valid regular signature. */
      buf[0] = attrib->trust_depth;
      buf[1] = attrib->trust_value;
      build_sig_subpkt (sig, SIGSUBPKT_TRUST, buf, 2);

      /* Critical.  If someone doesn't understands regexps, this
         whole sig should be invalid.  Note the +1 for the length -
         regexps are null terminated. */
      if (attrib->trust_regexp)
	build_sig_subpkt (sig, SIGSUBPKT_FLAG_CRITICAL | SIGSUBPKT_REGEXP,
			  attrib->trust_regexp,
			  strlen (attrib->trust_regexp) + 1);
    }

  return 0;
}


static void
trustsig_prompt (byte * trust_value, byte * trust_depth, char **regexp)
{
  char *p;

  *trust_value = 0;
  *trust_depth = 0;
  *regexp = NULL;

  /* Same string as pkclist.c:do_edit_ownertrust */
  tty_printf (_
	      ("Please decide how far you trust this user to correctly verify"
	       " other users' keys\n(by looking at passports, checking"
	       " fingerprints from different sources, etc.)\n"));
  tty_printf ("\n");
  tty_printf (_("  %d = I trust marginally\n"), 1);
  tty_printf (_("  %d = I trust fully\n"), 2);
  tty_printf ("\n");

  while (*trust_value == 0)
    {
      p = cpr_get ("trustsig_prompt.trust_value", _("Your selection? "));
      trim_spaces (p);
      cpr_kill_prompt ();
      /* 60 and 120 are as per RFC2440 */
      if (p[0] == '1' && !p[1])
	*trust_value = 60;
      else if (p[0] == '2' && !p[1])
	*trust_value = 120;
      xfree (p);
    }

  tty_printf ("\n");

  tty_printf (_("Please enter the depth of this trust signature.\n"
		"A depth greater than 1 allows the key you are"
                " signing to make\n"
		"trust signatures on your behalf.\n"));
  tty_printf ("\n");

  while (*trust_depth == 0)
    {
      p = cpr_get ("trustsig_prompt.trust_depth", _("Your selection? "));
      trim_spaces (p);
      cpr_kill_prompt ();
      *trust_depth = atoi (p);
      xfree (p);
    }

  tty_printf ("\n");

  tty_printf (_("Please enter a domain to restrict this signature, "
		"or enter for none.\n"));

  tty_printf ("\n");

  p = cpr_get ("trustsig_prompt.trust_regexp", _("Your selection? "));
  trim_spaces (p);
  cpr_kill_prompt ();

  if (strlen (p) > 0)
    {
      char *q = p;
      int regexplen = 100, ind;

      *regexp = xmalloc (regexplen);

      /* Now mangle the domain the user entered into a regexp.  To do
         this, \-escape everything that isn't alphanumeric, and attach
         "<[^>]+[@.]" to the front, and ">$" to the end. */

      strcpy (*regexp, "<[^>]+[@.]");
      ind = strlen (*regexp);

      while (*q)
	{
	  if (!((*q >= 'A' && *q <= 'Z')
		|| (*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9')))
	    (*regexp)[ind++] = '\\';

	  (*regexp)[ind++] = *q;

	  if ((regexplen - ind) < 3)
	    {
	      regexplen += 100;
	      *regexp = xrealloc (*regexp, regexplen);
	    }

	  q++;
	}

      (*regexp)[ind] = '\0';
      strcat (*regexp, ">$");
    }

  xfree (p);
  tty_printf ("\n");
}


/*
 * Loop over all LOCUSR and sign the uids after asking.  If no
 * user id is marked, all user ids will be signed; if some user_ids
 * are marked only those will be signed.  If QUICK is true the
 * function won't ask the user and use sensible defaults.
 */
static int
sign_uids (ctrl_t ctrl, estream_t fp,
           kbnode_t keyblock, strlist_t locusr, int *ret_modified,
	   int local, int nonrevocable, int trust, int interactive,
           int quick)
{
  int rc = 0;
  SK_LIST sk_list = NULL;
  SK_LIST sk_rover = NULL;
  PKT_public_key *pk = NULL;
  KBNODE node, uidnode;
  PKT_public_key *primary_pk = NULL;
  int select_all = !count_selected_uids (keyblock) || interactive;

  /* Build a list of all signators.
   *
   * We use the CERT flag to request the primary which must always
   * be one which is capable of signing keys.  I can't see a reason
   * why to sign keys using a subkey.  Implementation of USAGE_CERT
   * is just a hack in getkey.c and does not mean that a subkey
   * marked as certification capable will be used. */
  rc = build_sk_list (ctrl, locusr, &sk_list, PUBKEY_USAGE_CERT);
  if (rc)
    goto leave;

  /* Loop over all signators.  */
  for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next)
    {
      u32 sk_keyid[2], pk_keyid[2];
      char *p, *trust_regexp = NULL;
      int class = 0, selfsig = 0;
      u32 duration = 0, timestamp = 0;
      byte trust_depth = 0, trust_value = 0;

      pk = sk_rover->pk;
      keyid_from_pk (pk, sk_keyid);

      /* Set mark A for all selected user ids.  */
      for (node = keyblock; node; node = node->next)
	{
	  if (select_all || (node->flag & NODFLG_SELUID))
	    node->flag |= NODFLG_MARK_A;
	  else
	    node->flag &= ~NODFLG_MARK_A;
	}

      /* Reset mark for uids which are already signed.  */
      uidnode = NULL;
      for (node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	    {
	      primary_pk = node->pkt->pkt.public_key;
	      keyid_from_pk (primary_pk, pk_keyid);

	      /* Is this a self-sig? */
	      if (pk_keyid[0] == sk_keyid[0] && pk_keyid[1] == sk_keyid[1])
                selfsig = 1;
	    }
	  else if (node->pkt->pkttype == PKT_USER_ID)
	    {
	      uidnode = (node->flag & NODFLG_MARK_A) ? node : NULL;
	      if (uidnode)
		{
		  int yesreally = 0;
		  char *user;

                  user = utf8_to_native (uidnode->pkt->pkt.user_id->name,
                                         uidnode->pkt->pkt.user_id->len, 0);

                  if (opt.only_sign_text_ids
                      && uidnode->pkt->pkt.user_id->attribs)
                    {
                      tty_fprintf (fp, _("Skipping user ID \"%s\","
                                         " which is not a text ID.\n"),
                                   user);
                      uidnode->flag &= ~NODFLG_MARK_A;
                      uidnode = NULL;
                    }
		  else if (uidnode->pkt->pkt.user_id->flags.revoked)
		    {
		      tty_fprintf (fp, _("User ID \"%s\" is revoked."), user);

		      if (selfsig)
			tty_fprintf (fp, "\n");
		      else if (opt.expert && !quick)
			{
			  tty_fprintf (fp, "\n");
			  /* No, so remove the mark and continue */
			  if (!cpr_get_answer_is_yes ("sign_uid.revoke_okay",
						      _("Are you sure you "
							"still want to sign "
							"it? (y/N) ")))
			    {
			      uidnode->flag &= ~NODFLG_MARK_A;
			      uidnode = NULL;
			    }
			  else if (interactive)
			    yesreally = 1;
			}
		      else
			{
			  uidnode->flag &= ~NODFLG_MARK_A;
			  uidnode = NULL;
			  tty_fprintf (fp, _("  Unable to sign.\n"));
			}
		    }
		  else if (uidnode->pkt->pkt.user_id->flags.expired)
		    {
		      tty_fprintf (fp, _("User ID \"%s\" is expired."), user);

		      if (selfsig)
			tty_fprintf (fp, "\n");
		      else if (opt.expert && !quick)
			{
			  tty_fprintf (fp, "\n");
			  /* No, so remove the mark and continue */
			  if (!cpr_get_answer_is_yes ("sign_uid.expire_okay",
						      _("Are you sure you "
							"still want to sign "
							"it? (y/N) ")))
			    {
			      uidnode->flag &= ~NODFLG_MARK_A;
			      uidnode = NULL;
			    }
			  else if (interactive)
			    yesreally = 1;
			}
		      else
			{
			  uidnode->flag &= ~NODFLG_MARK_A;
			  uidnode = NULL;
			  tty_fprintf (fp, _("  Unable to sign.\n"));
			}
		    }
		  else if (!uidnode->pkt->pkt.user_id->created && !selfsig)
		    {
		      tty_fprintf (fp, _("User ID \"%s\" is not self-signed."),
                                   user);

		      if (opt.expert && !quick)
			{
			  tty_fprintf (fp, "\n");
			  /* No, so remove the mark and continue */
			  if (!cpr_get_answer_is_yes ("sign_uid.nosig_okay",
						      _("Are you sure you "
							"still want to sign "
							"it? (y/N) ")))
			    {
			      uidnode->flag &= ~NODFLG_MARK_A;
			      uidnode = NULL;
			    }
			  else if (interactive)
			    yesreally = 1;
			}
		      else
			{
			  uidnode->flag &= ~NODFLG_MARK_A;
			  uidnode = NULL;
			  tty_fprintf (fp, _("  Unable to sign.\n"));
			}
		    }

		  if (uidnode && interactive && !yesreally && !quick)
		    {
		      tty_fprintf (fp,
                                   _("User ID \"%s\" is signable.  "), user);
		      if (!cpr_get_answer_is_yes ("sign_uid.sign_okay",
						  _("Sign it? (y/N) ")))
			{
			  uidnode->flag &= ~NODFLG_MARK_A;
			  uidnode = NULL;
			}
		    }

		  xfree (user);
		}
	    }
	  else if (uidnode && node->pkt->pkttype == PKT_SIGNATURE
		   && (node->pkt->pkt.signature->sig_class & ~3) == 0x10)
	    {
	      if (sk_keyid[0] == node->pkt->pkt.signature->keyid[0]
		  && sk_keyid[1] == node->pkt->pkt.signature->keyid[1])
		{
		  char buf[50];
		  char *user;

                  user = utf8_to_native (uidnode->pkt->pkt.user_id->name,
                                         uidnode->pkt->pkt.user_id->len, 0);

		  /* It's a v3 self-sig.  Make it into a v4 self-sig? */
		  if (node->pkt->pkt.signature->version < 4
                      && selfsig && !quick)
		    {
		      tty_fprintf (fp,
                                   _("The self-signature on \"%s\"\n"
                                     "is a PGP 2.x-style signature.\n"), user);

		      /* Note that the regular PGP2 warning below
		         still applies if there are no v4 sigs on
		         this key at all. */

		      if (opt.expert)
			if (cpr_get_answer_is_yes ("sign_uid.v4_promote_okay",
						   _("Do you want to promote "
						     "it to an OpenPGP self-"
						     "signature? (y/N) ")))
			  {
			    node->flag |= NODFLG_DELSIG;
			    xfree (user);
			    continue;
			  }
		    }

		  /* Is the current signature expired? */
		  if (node->pkt->pkt.signature->flags.expired)
		    {
		      tty_fprintf (fp, _("Your current signature on \"%s\"\n"
                                         "has expired.\n"), user);

		      if (quick || cpr_get_answer_is_yes
			  ("sign_uid.replace_expired_okay",
			   _("Do you want to issue a "
			     "new signature to replace "
			     "the expired one? (y/N) ")))
			{
			  /* Mark these for later deletion.  We
			     don't want to delete them here, just in
			     case the replacement signature doesn't
			     happen for some reason.  We only delete
			     these after the replacement is already
			     in place. */

			  node->flag |= NODFLG_DELSIG;
			  xfree (user);
			  continue;
			}
		    }

		  if (!node->pkt->pkt.signature->flags.exportable && !local)
		    {
		      /* It's a local sig, and we want to make a
		         exportable sig. */
		      tty_fprintf (fp, _("Your current signature on \"%s\"\n"
                                         "is a local signature.\n"), user);

		      if (quick || cpr_get_answer_is_yes
			  ("sign_uid.local_promote_okay",
			   _("Do you want to promote "
			     "it to a full exportable " "signature? (y/N) ")))
			{
			  /* Mark these for later deletion.  We
			     don't want to delete them here, just in
			     case the replacement signature doesn't
			     happen for some reason.  We only delete
			     these after the replacement is already
			     in place. */

			  node->flag |= NODFLG_DELSIG;
			  xfree (user);
			  continue;
			}
		    }

		  /* Fixme: see whether there is a revocation in which
		   * case we should allow signing it again. */
		  if (!node->pkt->pkt.signature->flags.exportable && local)
		    tty_fprintf ( fp,
                       _("\"%s\" was already locally signed by key %s\n"),
                       user, keystr_from_pk (pk));
		  else
		    tty_fprintf (fp,
                                _("\"%s\" was already signed by key %s\n"),
				user, keystr_from_pk (pk));

		  if (opt.expert && !quick
		      && cpr_get_answer_is_yes ("sign_uid.dupe_okay",
						_("Do you want to sign it "
						  "again anyway? (y/N) ")))
		    {
		      /* Don't delete the old sig here since this is
		         an --expert thing. */
		      xfree (user);
		      continue;
		    }

		  snprintf (buf, sizeof buf, "%08lX%08lX",
			    (ulong) pk->keyid[0], (ulong) pk->keyid[1]);
		  write_status_text (STATUS_ALREADY_SIGNED, buf);
		  uidnode->flag &= ~NODFLG_MARK_A;	/* remove mark */

		  xfree (user);
		}
	    }
	}

      /* Check whether any uids are left for signing.  */
      if (!count_uids_with_flag (keyblock, NODFLG_MARK_A))
	{
	  tty_fprintf (fp, _("Nothing to sign with key %s\n"),
		      keystr_from_pk (pk));
	  continue;
	}

      /* Ask whether we really should sign these user id(s). */
      tty_fprintf (fp, "\n");
      show_key_with_all_names (ctrl, fp, keyblock, 1, 0, 1, 0, 0, 0);
      tty_fprintf (fp, "\n");

      if (primary_pk->expiredate && !selfsig)
	{
          /* Static analyzer note: A claim that PRIMARY_PK might be
             NULL is not correct because it set from the public key
             packet which is always the first packet in a keyblock and
             parsed in the above loop over the keyblock.  In case the
             keyblock has no packets at all and thus the loop was not
             entered the above count_uids_with_flag would have
             detected this case.  */

	  u32 now = make_timestamp ();

	  if (primary_pk->expiredate <= now)
	    {
	      tty_fprintf (fp, _("This key has expired!"));

	      if (opt.expert && !quick)
		{
		  tty_fprintf (fp, "  ");
		  if (!cpr_get_answer_is_yes ("sign_uid.expired_okay",
					      _("Are you sure you still "
						"want to sign it? (y/N) ")))
		    continue;
		}
	      else
		{
		  tty_fprintf (fp, _("  Unable to sign.\n"));
		  continue;
		}
	    }
	  else
	    {
	      tty_fprintf (fp, _("This key is due to expire on %s.\n"),
                           expirestr_from_pk (primary_pk));

	      if (opt.ask_cert_expire && !quick)
		{
		  char *answer = cpr_get ("sign_uid.expire",
					  _("Do you want your signature to "
					    "expire at the same time? (Y/n) "));
		  if (answer_is_yes_no_default (answer, 1))
		    {
		      /* This fixes the signature timestamp we're
		         going to make as now.  This is so the
		         expiration date is exactly correct, and not
		         a few seconds off (due to the time it takes
		         to answer the questions, enter the
		         passphrase, etc). */
		      timestamp = now;
		      duration = primary_pk->expiredate - now;
		    }

		  cpr_kill_prompt ();
		  xfree (answer);
		}
	    }
	}

      /* Only ask for duration if we haven't already set it to match
         the expiration of the pk */
      if (!duration && !selfsig)
	{
	  if (opt.ask_cert_expire && !quick)
	    duration = ask_expire_interval (1, opt.def_cert_expire);
	  else
	    duration = parse_expire_string (opt.def_cert_expire);
	}

      if (selfsig)
	;
      else
	{
	  if (opt.batch || !opt.ask_cert_level || quick)
	    class = 0x10 + opt.def_cert_level;
	  else
	    {
	      char *answer;

	      tty_fprintf (fp,
                           _("How carefully have you verified the key you are "
			    "about to sign actually belongs\nto the person "
			    "named above?  If you don't know what to "
			    "answer, enter \"0\".\n"));
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp, _("   (0) I will not answer.%s\n"),
			  opt.def_cert_level == 0 ? " (default)" : "");
	      tty_fprintf (fp, _("   (1) I have not checked at all.%s\n"),
			  opt.def_cert_level == 1 ? " (default)" : "");
	      tty_fprintf (fp, _("   (2) I have done casual checking.%s\n"),
			  opt.def_cert_level == 2 ? " (default)" : "");
	      tty_fprintf (fp,
                           _("   (3) I have done very careful checking.%s\n"),
			  opt.def_cert_level == 3 ? " (default)" : "");
	      tty_fprintf (fp, "\n");

	      while (class == 0)
		{
		  answer = cpr_get ("sign_uid.class",
                                    _("Your selection? "
                                      "(enter '?' for more information): "));
		  if (answer[0] == '\0')
		    class = 0x10 + opt.def_cert_level;	/* Default */
		  else if (ascii_strcasecmp (answer, "0") == 0)
		    class = 0x10;	/* Generic */
		  else if (ascii_strcasecmp (answer, "1") == 0)
		    class = 0x11;	/* Persona */
		  else if (ascii_strcasecmp (answer, "2") == 0)
		    class = 0x12;	/* Casual */
		  else if (ascii_strcasecmp (answer, "3") == 0)
		    class = 0x13;	/* Positive */
		  else
		    tty_fprintf (fp, _("Invalid selection.\n"));

		  xfree (answer);
		}
	    }

	  if (trust && !quick)
	    trustsig_prompt (&trust_value, &trust_depth, &trust_regexp);
	}

      if (!quick)
        {
          p = get_user_id_native (ctrl, sk_keyid);
          tty_fprintf (fp,
                   _("Are you sure that you want to sign this key with your\n"
                     "key \"%s\" (%s)\n"), p, keystr_from_pk (pk));
          xfree (p);
        }

      if (selfsig)
	{
	  tty_fprintf (fp, "\n");
	  tty_fprintf (fp, _("This will be a self-signature.\n"));

	  if (local)
	    {
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp, _("WARNING: the signature will not be marked "
                                 "as non-exportable.\n"));
	    }

	  if (nonrevocable)
	    {
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp, _("WARNING: the signature will not be marked "
                                 "as non-revocable.\n"));
	    }
	}
      else
	{
	  if (local)
	    {
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp,
                 _("The signature will be marked as non-exportable.\n"));
	    }

	  if (nonrevocable)
	    {
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp,
                 _("The signature will be marked as non-revocable.\n"));
	    }

	  switch (class)
	    {
	    case 0x11:
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp, _("I have not checked this key at all.\n"));
	      break;

	    case 0x12:
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp, _("I have checked this key casually.\n"));
	      break;

	    case 0x13:
	      tty_fprintf (fp, "\n");
	      tty_fprintf (fp, _("I have checked this key very carefully.\n"));
	      break;
	    }
	}

      tty_fprintf (fp, "\n");

      if (opt.batch && opt.answer_yes)
	;
      else if (quick)
        ;
      else if (!cpr_get_answer_is_yes ("sign_uid.okay",
				       _("Really sign? (y/N) ")))
	continue;

      /* Now we can sign the user ids.  */
    reloop:  /* (Must use this, because we are modifying the list.)  */
      primary_pk = NULL;
      for (node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	    primary_pk = node->pkt->pkt.public_key;
	  else if (node->pkt->pkttype == PKT_USER_ID
		   && (node->flag & NODFLG_MARK_A))
	    {
	      PACKET *pkt;
	      PKT_signature *sig;
	      struct sign_attrib attrib;

	      log_assert (primary_pk);
	      memset (&attrib, 0, sizeof attrib);
	      attrib.non_exportable = local;
	      attrib.non_revocable = nonrevocable;
	      attrib.trust_depth = trust_depth;
	      attrib.trust_value = trust_value;
	      attrib.trust_regexp = trust_regexp;
	      node->flag &= ~NODFLG_MARK_A;

	      /* We force creation of a v4 signature for local
	       * signatures, otherwise we would not generate the
	       * subpacket with v3 keys and the signature becomes
	       * exportable.  */

	      if (selfsig)
		rc = make_keysig_packet (ctrl, &sig, primary_pk,
					 node->pkt->pkt.user_id,
					 NULL,
					 pk,
					 0x13, 0, 0, 0,
					 keygen_add_std_prefs, primary_pk,
                                         NULL);
	      else
		rc = make_keysig_packet (ctrl, &sig, primary_pk,
					 node->pkt->pkt.user_id,
					 NULL,
					 pk,
					 class, 0,
					 timestamp, duration,
					 sign_mk_attrib, &attrib,
                                         NULL);
	      if (rc)
		{
                  write_status_error ("keysig", rc);
		  log_error (_("signing failed: %s\n"), gpg_strerror (rc));
		  goto leave;
		}

	      *ret_modified = 1;	/* We changed the keyblock. */
	      update_trust = 1;

	      pkt = xmalloc_clear (sizeof *pkt);
	      pkt->pkttype = PKT_SIGNATURE;
	      pkt->pkt.signature = sig;
	      insert_kbnode (node, new_kbnode (pkt), PKT_SIGNATURE);
	      goto reloop;
	    }
	}

      /* Delete any sigs that got promoted */
      for (node = keyblock; node; node = node->next)
	if (node->flag & NODFLG_DELSIG)
	  delete_kbnode (node);
    } /* End loop over signators.  */

 leave:
  release_sk_list (sk_list);
  return rc;
}


/*
 * Change the passphrase of the primary and all secondary keys.  Note
 * that it is common to use only one passphrase for the primary and
 * all subkeys.  However, this is now (since GnuPG 2.1) all up to the
 * gpg-agent.  Returns 0 on success or an error code.
 */
static gpg_error_t
change_passphrase (ctrl_t ctrl, kbnode_t keyblock)
{
  gpg_error_t err;
  kbnode_t node;
  PKT_public_key *pk;
  int any;
  u32 keyid[2], subid[2];
  char *hexgrip = NULL;
  char *cache_nonce = NULL;
  char *passwd_nonce = NULL;

  node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; public key missing!\n");
      err = gpg_error (GPG_ERR_INTERNAL);
      goto leave;
    }
  pk = node->pkt->pkt.public_key;
  keyid_from_pk (pk, keyid);

  /* Check whether it is likely that we will be able to change the
     passphrase for any subkey.  */
  for (any = 0, node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
	  || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
          char *serialno;

          pk = node->pkt->pkt.public_key;
          keyid_from_pk (pk, subid);

          xfree (hexgrip);
          err = hexkeygrip_from_pk (pk, &hexgrip);
          if (err)
            goto leave;
          err = agent_get_keyinfo (ctrl, hexgrip, &serialno, NULL);
          if (!err && serialno)
            ; /* Key on card.  */
          else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
            ; /* Maybe stub key. */
          else if (!err)
            any = 1; /* Key is known.  */
          else
            log_error ("key %s: error getting keyinfo from agent: %s\n",
                       keystr_with_sub (keyid, subid), gpg_strerror (err));
          xfree (serialno);
	}
    }
  err = 0;
  if (!any)
    {
      tty_printf (_("Key has only stub or on-card key items - "
		    "no passphrase to change.\n"));
      goto leave;
    }

  /* Change the passphrase for all keys.  */
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
	  || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          char *desc;

          pk = node->pkt->pkt.public_key;
          keyid_from_pk (pk, subid);

          xfree (hexgrip);
          err = hexkeygrip_from_pk (pk, &hexgrip);
          if (err)
            goto leave;

          /* Note that when using --dry-run we don't change the
           * passphrase but merely verify the current passphrase.  */
          desc = gpg_format_keydesc (ctrl, pk, FORMAT_KEYDESC_NORMAL, 1);
          err = agent_passwd (ctrl, hexgrip, desc, !!opt.dry_run,
                              &cache_nonce, &passwd_nonce);
          xfree (desc);

          if (err)
            log_log ((gpg_err_code (err) == GPG_ERR_CANCELED
                      || gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
                     ? GPGRT_LOG_INFO : GPGRT_LOG_ERROR,
                     _("key %s: error changing passphrase: %s\n"),
                       keystr_with_sub (keyid, subid),
                       gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
            break;
        }
    }

 leave:
  xfree (hexgrip);
  xfree (cache_nonce);
  xfree (passwd_nonce);
  return err;
}



/* Fix various problems in the keyblock.  Returns true if the keyblock
   was changed.  Note that a pointer to the keyblock must be given and
   the function may change it (i.e. replacing the first node).  */
static int
fix_keyblock (ctrl_t ctrl, kbnode_t *keyblockp)
{
  int changed = 0;

  if (collapse_uids (keyblockp))
    changed++;
  if (key_check_all_keysigs (ctrl, 1, *keyblockp, 0, 1))
    changed++;
  reorder_keyblock (*keyblockp);
  /* If we modified the keyblock, make sure the flags are right. */
  if (changed)
    merge_keys_and_selfsig (ctrl, *keyblockp);

  return changed;
}


static int
parse_sign_type (const char *str, int *localsig, int *nonrevokesig,
		 int *trustsig)
{
  const char *p = str;

  while (*p)
    {
      if (ascii_strncasecmp (p, "l", 1) == 0)
	{
	  *localsig = 1;
	  p++;
	}
      else if (ascii_strncasecmp (p, "nr", 2) == 0)
	{
	  *nonrevokesig = 1;
	  p += 2;
	}
      else if (ascii_strncasecmp (p, "t", 1) == 0)
	{
	  *trustsig = 1;
	  p++;
	}
      else
	return 0;
    }

  return 1;
}



/*
 * Menu driven key editor.  If seckey_check is true, then a secret key
 * that matches username will be looked for.  If it is false, not all
 * commands will be available.
 *
 * Note: to keep track of certain selections we use node->mark MARKBIT_xxxx.
 */

/* Need an SK for this command */
#define KEYEDIT_NEED_SK 1
/* Need an SUB KEY for this command */
#define KEYEDIT_NEED_SUBSK 2
/* Match the tail of the string */
#define KEYEDIT_TAIL_MATCH 8

enum cmdids
{
  cmdNONE = 0,
  cmdQUIT, cmdHELP, cmdFPR, cmdLIST, cmdSELUID, cmdCHECK, cmdSIGN,
  cmdREVSIG, cmdREVKEY, cmdREVUID, cmdDELSIG, cmdPRIMARY, cmdDEBUG,
  cmdSAVE, cmdADDUID, cmdADDPHOTO, cmdDELUID, cmdADDKEY, cmdDELKEY,
  cmdADDREVOKER, cmdTOGGLE, cmdSELKEY, cmdPASSWD, cmdTRUST, cmdPREF,
  cmdEXPIRE, cmdCHANGEUSAGE, cmdBACKSIGN,
#ifndef NO_TRUST_MODELS
  cmdENABLEKEY, cmdDISABLEKEY,
#endif /*!NO_TRUST_MODELS*/
  cmdSHOWPREF,
  cmdSETPREF, cmdPREFKS, cmdNOTATION, cmdINVCMD, cmdSHOWPHOTO, cmdUPDTRUST,
  cmdCHKTRUST, cmdADDCARDKEY, cmdKEYTOCARD, cmdBKUPTOCARD,
  cmdCLEAN, cmdMINIMIZE, cmdGRIP, cmdNOP
};

static struct
{
  const char *name;
  enum cmdids id;
  int flags;
  const char *desc;
} cmds[] =
{
  { "quit", cmdQUIT, 0, N_("quit this menu")},
  { "q", cmdQUIT, 0, NULL},
  { "save", cmdSAVE, 0, N_("save and quit")},
  { "help", cmdHELP, 0, N_("show this help")},
  { "?", cmdHELP, 0, NULL},
  { "fpr", cmdFPR, 0, N_("show key fingerprint")},
  { "grip", cmdGRIP, 0, N_("show the keygrip")},
  { "list", cmdLIST, 0, N_("list key and user IDs")},
  { "l", cmdLIST, 0, NULL},
  { "uid", cmdSELUID, 0, N_("select user ID N")},
  { "key", cmdSELKEY, 0, N_("select subkey N")},
  { "check", cmdCHECK, 0, N_("check signatures")},
  { "c", cmdCHECK, 0, NULL},
  { "change-usage", cmdCHANGEUSAGE, KEYEDIT_NEED_SK, NULL},
  { "cross-certify", cmdBACKSIGN, KEYEDIT_NEED_SK, NULL},
  { "backsign", cmdBACKSIGN,  KEYEDIT_NEED_SK, NULL},
  { "sign", cmdSIGN,  KEYEDIT_TAIL_MATCH,
    N_("sign selected user IDs [* see below for related commands]")},
  { "s", cmdSIGN, 0, NULL},
    /* "lsign" and friends will never match since "sign" comes first
       and it is a tail match.  They are just here so they show up in
       the help menu. */
  { "lsign", cmdNOP, 0, N_("sign selected user IDs locally")},
  { "tsign", cmdNOP, 0, N_("sign selected user IDs with a trust signature")},
  { "nrsign", cmdNOP, 0,
    N_("sign selected user IDs with a non-revocable signature")},
  { "debug", cmdDEBUG, 0, NULL},
  { "adduid", cmdADDUID,  KEYEDIT_NEED_SK, N_("add a user ID")},
  { "addphoto", cmdADDPHOTO,  KEYEDIT_NEED_SK,
    N_("add a photo ID")},
  { "deluid", cmdDELUID, 0, N_("delete selected user IDs")},
    /* delphoto is really deluid in disguise */
  { "delphoto", cmdDELUID, 0, NULL},
  { "addkey", cmdADDKEY,  KEYEDIT_NEED_SK, N_("add a subkey")},
#ifdef ENABLE_CARD_SUPPORT
  { "addcardkey", cmdADDCARDKEY,  KEYEDIT_NEED_SK,
    N_("add a key to a smartcard")},
  { "keytocard", cmdKEYTOCARD, KEYEDIT_NEED_SK | KEYEDIT_NEED_SUBSK,
    N_("move a key to a smartcard")},
  { "bkuptocard", cmdBKUPTOCARD, KEYEDIT_NEED_SK | KEYEDIT_NEED_SUBSK,
    N_("move a backup key to a smartcard")},
#endif /*ENABLE_CARD_SUPPORT */
  { "delkey", cmdDELKEY, 0, N_("delete selected subkeys")},
  { "addrevoker", cmdADDREVOKER,  KEYEDIT_NEED_SK,
    N_("add a revocation key")},
  { "delsig", cmdDELSIG, 0,
    N_("delete signatures from the selected user IDs")},
  { "expire", cmdEXPIRE,  KEYEDIT_NEED_SK | KEYEDIT_NEED_SUBSK,
    N_("change the expiration date for the key or selected subkeys")},
  { "primary", cmdPRIMARY,  KEYEDIT_NEED_SK,
    N_("flag the selected user ID as primary")},
  { "toggle", cmdTOGGLE, KEYEDIT_NEED_SK, NULL},  /* Dummy command.  */
  { "t", cmdTOGGLE, KEYEDIT_NEED_SK, NULL},
  { "pref", cmdPREF, 0, N_("list preferences (expert)")},
  { "showpref", cmdSHOWPREF, 0, N_("list preferences (verbose)")},
  { "setpref", cmdSETPREF,  KEYEDIT_NEED_SK,
    N_("set preference list for the selected user IDs")},
  { "updpref", cmdSETPREF,  KEYEDIT_NEED_SK, NULL},
  { "keyserver", cmdPREFKS,  KEYEDIT_NEED_SK,
    N_("set the preferred keyserver URL for the selected user IDs")},
  { "notation", cmdNOTATION,  KEYEDIT_NEED_SK,
    N_("set a notation for the selected user IDs")},
  { "passwd", cmdPASSWD,  KEYEDIT_NEED_SK | KEYEDIT_NEED_SUBSK,
    N_("change the passphrase")},
  { "password", cmdPASSWD,  KEYEDIT_NEED_SK | KEYEDIT_NEED_SUBSK, NULL},
#ifndef NO_TRUST_MODELS
  { "trust", cmdTRUST, 0, N_("change the ownertrust")},
#endif /*!NO_TRUST_MODELS*/
  { "revsig", cmdREVSIG, 0,
    N_("revoke signatures on the selected user IDs")},
  { "revuid", cmdREVUID,  KEYEDIT_NEED_SK,
    N_("revoke selected user IDs")},
  { "revphoto", cmdREVUID,  KEYEDIT_NEED_SK, NULL},
  { "revkey", cmdREVKEY,  KEYEDIT_NEED_SK,
    N_("revoke key or selected subkeys")},
#ifndef NO_TRUST_MODELS
  { "enable", cmdENABLEKEY, 0, N_("enable key")},
  { "disable", cmdDISABLEKEY, 0, N_("disable key")},
#endif /*!NO_TRUST_MODELS*/
  { "showphoto", cmdSHOWPHOTO, 0, N_("show selected photo IDs")},
  { "clean", cmdCLEAN, 0,
    N_("compact unusable user IDs and remove unusable signatures from key")},
  { "minimize", cmdMINIMIZE, 0,
    N_("compact unusable user IDs and remove all signatures from key")},

  { NULL, cmdNONE, 0, NULL}
};



#ifdef HAVE_LIBREADLINE

/*
   These two functions are used by readline for command completion.
 */

static char *
command_generator (const char *text, int state)
{
  static int list_index, len;
  const char *name;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the
     index variable to 0. */
  if (!state)
    {
      list_index = 0;
      len = strlen (text);
    }

  /* Return the next partial match */
  while ((name = cmds[list_index].name))
    {
      /* Only complete commands that have help text */
      if (cmds[list_index++].desc && strncmp (name, text, len) == 0)
	return strdup (name);
    }

  return NULL;
}

static char **
keyedit_completion (const char *text, int start, int end)
{
  /* If we are at the start of a line, we try and command-complete.
     If not, just do nothing for now. */

  (void) end;

  if (start == 0)
    return rl_completion_matches (text, command_generator);

  rl_attempted_completion_over = 1;

  return NULL;
}
#endif /* HAVE_LIBREADLINE */



/* Main function of the menu driven key editor.  */
void
keyedit_menu (ctrl_t ctrl, const char *username, strlist_t locusr,
	      strlist_t commands, int quiet, int seckey_check)
{
  enum cmdids cmd = 0;
  gpg_error_t err = 0;
  KBNODE keyblock = NULL;
  KEYDB_HANDLE kdbhd = NULL;
  int have_seckey = 0;
  int have_anyseckey = 0;
  char *answer = NULL;
  int redisplay = 1;
  int modified = 0;
  int sec_shadowing = 0;
  int run_subkey_warnings = 0;
  int have_commands = !!commands;

  if (opt.command_fd != -1)
    ;
  else if (opt.batch && !have_commands)
    {
      log_error (_("can't do this in batch mode\n"));
      goto leave;
    }

#ifdef HAVE_W32_SYSTEM
  /* Due to Windows peculiarities we need to make sure that the
     trustdb stale check is done before we open another file
     (i.e. by searching for a key).  In theory we could make sure
     that the files are closed after use but the open/close caches
     inhibits that and flushing the cache right before the stale
     check is not easy to implement.  Thus we take the easy way out
     and run the stale check as early as possible.  Note, that for
     non- W32 platforms it is run indirectly trough a call to
     get_validity ().  */
  check_trustdb_stale (ctrl);
#endif

  /* Get the public key */
  err = get_pubkey_byname (ctrl, GET_PUBKEY_NO_AKL,
                           NULL, NULL, username, &keyblock, &kdbhd, 1);
  if (err)
    {
      log_error (_("key \"%s\" not found: %s\n"), username, gpg_strerror (err));
      goto leave;
    }

  if (fix_keyblock (ctrl, &keyblock))
    modified++;

  /* See whether we have a matching secret key.  */
  if (seckey_check)
    {
      have_anyseckey = !agent_probe_any_secret_key (ctrl, keyblock);
      if (have_anyseckey
          && !agent_probe_secret_key (ctrl, keyblock->pkt->pkt.public_key))
        {
          /* The primary key is also available.   */
          have_seckey = 1;
        }

      if (have_seckey && !quiet)
        tty_printf (_("Secret key is available.\n"));
      else if (have_anyseckey && !quiet)
        tty_printf (_("Secret subkeys are available.\n"));
    }

  /* Main command loop.  */
  for (;;)
    {
      int i, arg_number, photo;
      const char *arg_string = "";
      char *p;
      PKT_public_key *pk = keyblock->pkt->pkt.public_key;

      tty_printf ("\n");

      if (redisplay && !quiet)
	{
          /* Show using flags: with_revoker, with_subkeys.  */
	  show_key_with_all_names (ctrl, NULL, keyblock, 0, 1, 0, 1, 0, 0);
	  tty_printf ("\n");
	  redisplay = 0;
	}

      if (run_subkey_warnings)
        {
          run_subkey_warnings = 0;
          if (!count_selected_keys (keyblock))
            subkey_expire_warning (keyblock);
        }

      do
	{
	  xfree (answer);
	  if (have_commands)
	    {
	      if (commands)
		{
		  answer = xstrdup (commands->d);
		  commands = commands->next;
		}
	      else if (opt.batch)
		{
		  answer = xstrdup ("quit");
		}
	      else
		have_commands = 0;
	    }
	  if (!have_commands)
	    {
#ifdef HAVE_LIBREADLINE
	      tty_enable_completion (keyedit_completion);
#endif
	      answer = cpr_get_no_help ("keyedit.prompt", GPG_NAME "> ");
	      cpr_kill_prompt ();
	      tty_disable_completion ();
	    }
	  trim_spaces (answer);
	}
      while (*answer == '#');

      arg_number = 0; /* Here is the init which egcc complains about.  */
      photo = 0;      /* Same here. */
      if (!*answer)
	cmd = cmdLIST;
      else if (*answer == CONTROL_D)
	cmd = cmdQUIT;
      else if (digitp (answer))
	{
	  cmd = cmdSELUID;
	  arg_number = atoi (answer);
	}
      else
	{
	  if ((p = strchr (answer, ' ')))
	    {
	      *p++ = 0;
	      trim_spaces (answer);
	      trim_spaces (p);
	      arg_number = atoi (p);
	      arg_string = p;
	    }

	  for (i = 0; cmds[i].name; i++)
	    {
	      if (cmds[i].flags & KEYEDIT_TAIL_MATCH)
		{
		  size_t l = strlen (cmds[i].name);
		  size_t a = strlen (answer);
		  if (a >= l)
		    {
		      if (!ascii_strcasecmp (&answer[a - l], cmds[i].name))
			{
			  answer[a - l] = '\0';
			  break;
			}
		    }
		}
	      else if (!ascii_strcasecmp (answer, cmds[i].name))
		break;
	    }
	  if ((cmds[i].flags & (KEYEDIT_NEED_SK|KEYEDIT_NEED_SUBSK))
              && !(((cmds[i].flags & KEYEDIT_NEED_SK) && have_seckey)
                   || ((cmds[i].flags & KEYEDIT_NEED_SUBSK) && have_anyseckey)))
	    {
	      tty_printf (_("Need the secret key to do this.\n"));
	      cmd = cmdNOP;
	    }
          else
	    cmd = cmds[i].id;
	}

      /* Dispatch the command.  */
      switch (cmd)
	{
	case cmdHELP:
	  for (i = 0; cmds[i].name; i++)
	    {
              if ((cmds[i].flags & (KEYEDIT_NEED_SK|KEYEDIT_NEED_SUBSK))
                  && !(((cmds[i].flags & KEYEDIT_NEED_SK) && have_seckey)
                       ||((cmds[i].flags&KEYEDIT_NEED_SUBSK)&&have_anyseckey)))
		; /* Skip those item if we do not have the secret key.  */
	      else if (cmds[i].desc)
		tty_printf ("%-11s %s\n", cmds[i].name, _(cmds[i].desc));
	    }

	  tty_printf ("\n");
	  tty_printf
            (_("* The 'sign' command may be prefixed with an 'l' for local "
               "signatures (lsign),\n"
               "  a 't' for trust signatures (tsign), an 'nr' for "
               "non-revocable signatures\n"
               "  (nrsign), or any combination thereof (ltsign, "
               "tnrsign, etc.).\n"));
	  break;

	case cmdLIST:
	  redisplay = 1;
	  break;

	case cmdFPR:
	  show_key_and_fingerprint
            (ctrl,
             keyblock, (*arg_string == '*'
                        && (!arg_string[1] || spacep (arg_string + 1))));
	  break;

	case cmdGRIP:
	  show_key_and_grip (keyblock);
	  break;

	case cmdSELUID:
	  if (strlen (arg_string) == NAMEHASH_LEN * 2)
	    redisplay = menu_select_uid_namehash (keyblock, arg_string);
	  else
	    {
	      if (*arg_string == '*'
		  && (!arg_string[1] || spacep (arg_string + 1)))
		arg_number = -1;	/* Select all. */
	      redisplay = menu_select_uid (keyblock, arg_number);
	    }
	  break;

	case cmdSELKEY:
	  {
	    if (*arg_string == '*'
		&& (!arg_string[1] || spacep (arg_string + 1)))
	      arg_number = -1;	/* Select all. */
	    if (menu_select_key (keyblock, arg_number, p))
	      redisplay = 1;
	  }
	  break;

	case cmdCHECK:
	  if (key_check_all_keysigs (ctrl, -1, keyblock,
				     count_selected_uids (keyblock),
				     !strcmp (arg_string, "selfsig")))
            modified = 1;
	  break;

	case cmdSIGN:
	  {
	    int localsig = 0, nonrevokesig = 0, trustsig = 0, interactive = 0;

	    if (pk->flags.revoked)
	      {
		tty_printf (_("Key is revoked."));

		if (opt.expert)
		  {
		    tty_printf ("  ");
		    if (!cpr_get_answer_is_yes
                        ("keyedit.sign_revoked.okay",
                         _("Are you sure you still want to sign it? (y/N) ")))
		      break;
		  }
		else
		  {
		    tty_printf (_("  Unable to sign.\n"));
		    break;
		  }
	      }

	    if (count_uids (keyblock) > 1 && !count_selected_uids (keyblock))
              {
                int result;
                if (opt.only_sign_text_ids)
                  result = cpr_get_answer_is_yes
                    ("keyedit.sign_all.okay",
                     _("Really sign all text user IDs? (y/N) "));
                else
                  result = cpr_get_answer_is_yes
                    ("keyedit.sign_all.okay",
                     _("Really sign all user IDs? (y/N) "));

                if (! result)
                  {
                    if (opt.interactive)
                      interactive = 1;
                    else
                      {
                        tty_printf (_("Hint: Select the user IDs to sign\n"));
                        have_commands = 0;
                        break;
                      }

                  }
              }
	    /* What sort of signing are we doing? */
	    if (!parse_sign_type
		(answer, &localsig, &nonrevokesig, &trustsig))
	      {
		tty_printf (_("Unknown signature type '%s'\n"), answer);
		break;
	      }

	    sign_uids (ctrl, NULL, keyblock, locusr, &modified,
		       localsig, nonrevokesig, trustsig, interactive, 0);
	  }
	  break;

	case cmdDEBUG:
	  dump_kbnode (keyblock);
	  break;

	case cmdTOGGLE:
          /* The toggle command is a leftover from old gpg versions
             where we worked with a secret and a public keyring.  It
             is not necessary anymore but we keep this command for the
             sake of scripts using it.  */
	  redisplay = 1;
	  break;

	case cmdADDPHOTO:
	  if (RFC2440)
	    {
	      tty_printf (_("This command is not allowed while in %s mode.\n"),
			  gnupg_compliance_option_string (opt.compliance));
	      break;
	    }
	  photo = 1;
	  /* fall through */
	case cmdADDUID:
	  if (menu_adduid (ctrl, keyblock, photo, arg_string, NULL))
	    {
	      update_trust = 1;
	      redisplay = 1;
	      modified = 1;
	      merge_keys_and_selfsig (ctrl, keyblock);
	    }
	  break;

	case cmdDELUID:
	  {
	    int n1;

	    if (!(n1 = count_selected_uids (keyblock)))
              {
                tty_printf (_("You must select at least one user ID.\n"));
                if (!opt.expert)
                  tty_printf (_("(Use the '%s' command.)\n"), "uid");
              }
	    else if (real_uids_left (keyblock) < 1)
	      tty_printf (_("You can't delete the last user ID!\n"));
	    else if (cpr_get_answer_is_yes
                     ("keyedit.remove.uid.okay",
                      n1 > 1 ? _("Really remove all selected user IDs? (y/N) ")
                      :        _("Really remove this user ID? (y/N) ")))
	      {
		menu_deluid (keyblock);
		redisplay = 1;
		modified = 1;
	      }
	  }
	  break;

	case cmdDELSIG:
	  {
	    int n1;

	    if (!(n1 = count_selected_uids (keyblock)))
              {
                tty_printf (_("You must select at least one user ID.\n"));
                if (!opt.expert)
                  tty_printf (_("(Use the '%s' command.)\n"), "uid");
              }
	    else if (menu_delsig (ctrl, keyblock))
	      {
		/* No redisplay here, because it may scroll away some
		 * of the status output of this command.  */
		modified = 1;
	      }
	  }
	  break;

	case cmdADDKEY:
	  if (!generate_subkeypair (ctrl, keyblock, NULL, NULL, NULL))
	    {
	      redisplay = 1;
	      modified = 1;
	      merge_keys_and_selfsig (ctrl, keyblock);
	    }
	  break;

#ifdef ENABLE_CARD_SUPPORT
	case cmdADDCARDKEY:
	  if (!card_generate_subkey (ctrl, keyblock))
	    {
	      redisplay = 1;
	      modified = 1;
	      merge_keys_and_selfsig (ctrl, keyblock);
	    }
	  break;

	case cmdKEYTOCARD:
	  {
	    KBNODE node = NULL;
	    switch (count_selected_keys (keyblock))
	      {
	      case 0:
		if (cpr_get_answer_is_yes
                    ("keyedit.keytocard.use_primary",
                     /* TRANSLATORS: Please take care: This is about
                        moving the key and not about removing it.  */
                     _("Really move the primary key? (y/N) ")))
		  node = keyblock;
		break;
	      case 1:
		for (node = keyblock; node; node = node->next)
		  {
		    if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
			&& node->flag & NODFLG_SELKEY)
		      break;
		  }
		break;
	      default:
		tty_printf (_("You must select exactly one key.\n"));
		break;
	      }
	    if (node)
	      {
		PKT_public_key *xxpk = node->pkt->pkt.public_key;
		if (card_store_subkey (node, xxpk ? xxpk->pubkey_usage : 0))
		  {
		    redisplay = 1;
		    sec_shadowing = 1;
		  }
	      }
	  }
	  break;

	case cmdBKUPTOCARD:
	  {
	    /* Ask for a filename, check whether this is really a
	       backup key as generated by the card generation, parse
	       that key and store it on card. */
	    KBNODE node;
	    char *fname;
	    PACKET *pkt;
	    IOBUF a;
            struct parse_packet_ctx_s parsectx;

            if (!*arg_string)
	      {
		tty_printf (_("Command expects a filename argument\n"));
		break;
	      }

            if (*arg_string == DIRSEP_C)
              fname = xstrdup (arg_string);
            else if (*arg_string == '~')
              fname = make_filename (arg_string, NULL);
            else
              fname = make_filename (gnupg_homedir (), arg_string, NULL);

	    /* Open that file.  */
	    a = iobuf_open (fname);
	    if (a && is_secured_file (iobuf_get_fd (a)))
	      {
		iobuf_close (a);
		a = NULL;
		gpg_err_set_errno (EPERM);
	      }
            if (!a)
              {
                tty_printf (_("Can't open '%s': %s\n"),
                            fname, strerror (errno));
                xfree (fname);
                break;
              }

	    /* Parse and check that file.  */
	    pkt = xmalloc (sizeof *pkt);
	    init_packet (pkt);
            init_parse_packet (&parsectx, a);
	    err = parse_packet (&parsectx, pkt);
	    deinit_parse_packet (&parsectx);
            iobuf_close (a);
	    iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char *) fname);
	    if (!err && pkt->pkttype != PKT_SECRET_KEY
		&& pkt->pkttype != PKT_SECRET_SUBKEY)
	      err = GPG_ERR_NO_SECKEY;
            if (err)
              {
                tty_printf (_("Error reading backup key from '%s': %s\n"),
                            fname, gpg_strerror (err));
                xfree (fname);
                free_packet (pkt, NULL);
                xfree (pkt);
                break;
              }

	    xfree (fname);
	    node = new_kbnode (pkt);

            /* Transfer it to gpg-agent which handles secret keys.  */
            err = transfer_secret_keys (ctrl, NULL, node, 1, 1, 0);

            /* Treat the pkt as a public key.  */
            pkt->pkttype = PKT_PUBLIC_KEY;

            /* Ask gpg-agent to store the secret key to card.  */
            if (card_store_subkey (node, 0))
              {
                redisplay = 1;
                sec_shadowing = 1;
              }
            release_kbnode (node);
          }
          break;

#endif /* ENABLE_CARD_SUPPORT */

	case cmdDELKEY:
	  {
	    int n1;

	    if (!(n1 = count_selected_keys (keyblock)))
              {
                tty_printf (_("You must select at least one key.\n"));
                if (!opt.expert)
                  tty_printf (_("(Use the '%s' command.)\n"), "key");
              }
	    else if (!cpr_get_answer_is_yes
                     ("keyedit.remove.subkey.okay",
                      n1 > 1 ? _("Do you really want to delete the "
                                 "selected keys? (y/N) ")
                      :  _("Do you really want to delete this key? (y/N) ")))
	      ;
	    else
	      {
		menu_delkey (keyblock);
		redisplay = 1;
		modified = 1;
	      }
	  }
	  break;

	case cmdADDREVOKER:
	  {
	    int sensitive = 0;

	    if (ascii_strcasecmp (arg_string, "sensitive") == 0)
	      sensitive = 1;
	    if (menu_addrevoker (ctrl, keyblock, sensitive))
	      {
		redisplay = 1;
		modified = 1;
		merge_keys_and_selfsig (ctrl, keyblock);
	      }
	  }
	  break;

	case cmdREVUID:
	  {
	    int n1;

	    if (!(n1 = count_selected_uids (keyblock)))
              {
                tty_printf (_("You must select at least one user ID.\n"));
                if (!opt.expert)
                  tty_printf (_("(Use the '%s' command.)\n"), "uid");
              }
	    else if (cpr_get_answer_is_yes
                     ("keyedit.revoke.uid.okay",
                      n1 > 1 ? _("Really revoke all selected user IDs? (y/N) ")
		      :        _("Really revoke this user ID? (y/N) ")))
	      {
		if (menu_revuid (ctrl, keyblock))
		  {
		    modified = 1;
		    redisplay = 1;
		  }
	      }
	  }
	  break;

	case cmdREVKEY:
	  {
	    int n1;

	    if (!(n1 = count_selected_keys (keyblock)))
	      {
		if (cpr_get_answer_is_yes ("keyedit.revoke.subkey.okay",
					   _("Do you really want to revoke"
					     " the entire key? (y/N) ")))
		  {
		    if (menu_revkey (ctrl, keyblock))
		      modified = 1;

		    redisplay = 1;
		  }
	      }
	    else if (cpr_get_answer_is_yes ("keyedit.revoke.subkey.okay",
					    n1 > 1 ?
					    _("Do you really want to revoke"
					      " the selected subkeys? (y/N) ")
					    : _("Do you really want to revoke"
						" this subkey? (y/N) ")))
	      {
		if (menu_revsubkey (ctrl, keyblock))
		  modified = 1;

		redisplay = 1;
	      }

	    if (modified)
	      merge_keys_and_selfsig (ctrl, keyblock);
	  }
	  break;

	case cmdEXPIRE:
	  if (gpg_err_code (menu_expire (ctrl, keyblock, 0, 0)) == GPG_ERR_TRUE)
	    {
	      merge_keys_and_selfsig (ctrl, keyblock);
              run_subkey_warnings = 1;
	      modified = 1;
	      redisplay = 1;
	    }
	  break;

	case cmdCHANGEUSAGE:
	  if (menu_changeusage (ctrl, keyblock))
	    {
	      merge_keys_and_selfsig (ctrl, keyblock);
	      modified = 1;
	      redisplay = 1;
	    }
	  break;

	case cmdBACKSIGN:
	  if (menu_backsign (ctrl, keyblock))
	    {
	      modified = 1;
	      redisplay = 1;
	    }
	  break;

	case cmdPRIMARY:
	  if (menu_set_primary_uid (ctrl, keyblock))
	    {
	      merge_keys_and_selfsig (ctrl, keyblock);
	      modified = 1;
	      redisplay = 1;
	    }
	  break;

	case cmdPASSWD:
	  change_passphrase (ctrl, keyblock);
	  break;

#ifndef NO_TRUST_MODELS
	case cmdTRUST:
	  if (opt.trust_model == TM_EXTERNAL)
	    {
	      tty_printf (_("Owner trust may not be set while "
			    "using a user provided trust database\n"));
	      break;
	    }

	  show_key_with_all_names (ctrl, NULL, keyblock, 0, 0, 0, 1, 0, 0);
	  tty_printf ("\n");
	  if (edit_ownertrust (ctrl, find_kbnode (keyblock,
					    PKT_PUBLIC_KEY)->pkt->pkt.
			       public_key, 1))
	    {
	      redisplay = 1;
	      /* No real need to set update_trust here as
	         edit_ownertrust() calls revalidation_mark()
	         anyway. */
	      update_trust = 1;
	    }
	  break;
#endif /*!NO_TRUST_MODELS*/

	case cmdPREF:
	  {
	    int count = count_selected_uids (keyblock);
	    log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY);
	    show_names (ctrl, NULL, keyblock, keyblock->pkt->pkt.public_key,
			count ? NODFLG_SELUID : 0, 1);
	  }
	  break;

	case cmdSHOWPREF:
	  {
	    int count = count_selected_uids (keyblock);
	    log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY);
	    show_names (ctrl, NULL, keyblock, keyblock->pkt->pkt.public_key,
			count ? NODFLG_SELUID : 0, 2);
	  }
	  break;

	case cmdSETPREF:
	  {
	    PKT_user_id *tempuid;

	    keygen_set_std_prefs (!*arg_string ? "default" : arg_string, 0);

	    tempuid = keygen_get_std_prefs ();
	    tty_printf (_("Set preference list to:\n"));
	    show_prefs (tempuid, NULL, 1);
	    free_user_id (tempuid);

	    if (cpr_get_answer_is_yes
                ("keyedit.setpref.okay",
                 count_selected_uids (keyblock) ?
                 _("Really update the preferences"
                   " for the selected user IDs? (y/N) ")
                 : _("Really update the preferences? (y/N) ")))
	      {
		if (menu_set_preferences (ctrl, keyblock))
		  {
		    merge_keys_and_selfsig (ctrl, keyblock);
		    modified = 1;
		    redisplay = 1;
		  }
	      }
	  }
	  break;

	case cmdPREFKS:
	  if (menu_set_keyserver_url (ctrl, *arg_string ? arg_string : NULL,
				      keyblock))
	    {
	      merge_keys_and_selfsig (ctrl, keyblock);
	      modified = 1;
	      redisplay = 1;
	    }
	  break;

	case cmdNOTATION:
	  if (menu_set_notation (ctrl, *arg_string ? arg_string : NULL,
				 keyblock))
	    {
	      merge_keys_and_selfsig (ctrl, keyblock);
	      modified = 1;
	      redisplay = 1;
	    }
	  break;

	case cmdNOP:
	  break;

	case cmdREVSIG:
	  if (menu_revsig (ctrl, keyblock))
	    {
	      redisplay = 1;
	      modified = 1;
	    }
	  break;

#ifndef NO_TRUST_MODELS
	case cmdENABLEKEY:
	case cmdDISABLEKEY:
	  if (enable_disable_key (ctrl, keyblock, cmd == cmdDISABLEKEY))
	    {
	      redisplay = 1;
	      modified = 1;
	    }
	  break;
#endif /*!NO_TRUST_MODELS*/

	case cmdSHOWPHOTO:
	  menu_showphoto (ctrl, keyblock);
	  break;

	case cmdCLEAN:
	  if (menu_clean (ctrl, keyblock, 0))
	    redisplay = modified = 1;
	  break;

	case cmdMINIMIZE:
	  if (menu_clean (ctrl, keyblock, 1))
	    redisplay = modified = 1;
	  break;

	case cmdQUIT:
	  if (have_commands)
	    goto leave;
	  if (!modified && !sec_shadowing)
	    goto leave;
	  if (!cpr_get_answer_is_yes ("keyedit.save.okay",
				      _("Save changes? (y/N) ")))
	    {
	      if (cpr_enabled ()
		  || cpr_get_answer_is_yes ("keyedit.cancel.okay",
					    _("Quit without saving? (y/N) ")))
		goto leave;
	      break;
	    }
	  /* fall through */
	case cmdSAVE:
	  if (modified)
	    {
              err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
              if (err)
                {
                  log_error (_("update failed: %s\n"), gpg_strerror (err));
                  break;
                }
	    }

	  if (sec_shadowing)
	    {
	      err = agent_scd_learn (NULL, 1);
	      if (err)
                {
                  log_error (_("update failed: %s\n"), gpg_strerror (err));
                  break;
                }
	    }

	  if (!modified && !sec_shadowing)
	    tty_printf (_("Key not changed so no update needed.\n"));

	  if (update_trust)
	    {
	      revalidation_mark (ctrl);
	      update_trust = 0;
	    }
	  goto leave;

	case cmdINVCMD:
	default:
	  tty_printf ("\n");
	  tty_printf (_("Invalid command  (try \"help\")\n"));
	  break;
	}
    } /* End of the main command loop.  */

 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
  xfree (answer);
}


/* Change the passphrase of the secret key identified by USERNAME.  */
void
keyedit_passwd (ctrl_t ctrl, const char *username)
{
  gpg_error_t err;
  PKT_public_key *pk;
  kbnode_t keyblock = NULL;

  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = getkey_byname (ctrl, NULL, pk, username, 1, &keyblock);
  if (err)
    goto leave;

  err = change_passphrase (ctrl, keyblock);

leave:
  release_kbnode (keyblock);
  free_public_key (pk);
  if (err)
    {
      log_info ("error changing the passphrase for '%s': %s\n",
		username, gpg_strerror (err));
      write_status_error ("keyedit.passwd", err);
    }
  else
    write_status_text (STATUS_SUCCESS, "keyedit.passwd");
}


/* Helper for quick commands to find the keyblock for USERNAME.
 * Returns on success the key database handle at R_KDBHD and the
 * keyblock at R_KEYBLOCK.  */
static gpg_error_t
quick_find_keyblock (ctrl_t ctrl, const char *username, int want_secret,
                     KEYDB_HANDLE *r_kdbhd, kbnode_t *r_keyblock)
{
  gpg_error_t err;
  KEYDB_HANDLE kdbhd = NULL;
  kbnode_t keyblock = NULL;
  KEYDB_SEARCH_DESC desc;
  kbnode_t node;

  *r_kdbhd = NULL;
  *r_keyblock = NULL;

  /* Search the key; we don't want the whole getkey stuff here.  */
  kdbhd = keydb_new ();
  if (!kdbhd)
    {
      /* Note that keydb_new has already used log_error.  */
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = classify_user_id (username, &desc, 1);
  if (!err)
    err = keydb_search (kdbhd, &desc, 1, NULL);
  if (!err)
    {
      err = keydb_get_keyblock (kdbhd, &keyblock);
      if (err)
        {
          log_error (_("error reading keyblock: %s\n"), gpg_strerror (err));
          goto leave;
        }
      /* Now with the keyblock retrieved, search again to detect an
         ambiguous specification.  We need to save the found state so
         that we can do an update later.  */
      keydb_push_found_state (kdbhd);
      err = keydb_search (kdbhd, &desc, 1, NULL);
      if (!err)
        err = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
      else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
        err = 0;
      keydb_pop_found_state (kdbhd);

      if (!err && want_secret)
        {
          /* We require the secret primary key to set the primary UID.  */
          node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
          log_assert (node);
          err = agent_probe_secret_key (ctrl, node->pkt->pkt.public_key);
        }
    }
  else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    err = gpg_error (GPG_ERR_NO_PUBKEY);

  if (err)
    {
      log_error (_("key \"%s\" not found: %s\n"),
                 username, gpg_strerror (err));
      goto leave;
    }

  fix_keyblock (ctrl, &keyblock);
  merge_keys_and_selfsig (ctrl, keyblock);

  *r_keyblock = keyblock;
  keyblock = NULL;
  *r_kdbhd = kdbhd;
  kdbhd = NULL;

 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
  return err;
}


/* Unattended adding of a new keyid.  USERNAME specifies the
   key. NEWUID is the new user id to add to the key.  */
void
keyedit_quick_adduid (ctrl_t ctrl, const char *username, const char *newuid)
{
  gpg_error_t err;
  KEYDB_HANDLE kdbhd = NULL;
  kbnode_t keyblock = NULL;
  char *uidstring = NULL;

  uidstring = xstrdup (newuid);
  trim_spaces (uidstring);
  if (!*uidstring)
    {
      log_error ("%s\n", gpg_strerror (GPG_ERR_INV_USER_ID));
      goto leave;
    }

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  /* Search the key; we don't want the whole getkey stuff here.  */
  err = quick_find_keyblock (ctrl, username, 1, &kdbhd, &keyblock);
  if (err)
    goto leave;

  if (menu_adduid (ctrl, keyblock, 0, NULL, uidstring))
    {
      err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
      if (err)
        {
          log_error (_("update failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      if (update_trust)
        revalidation_mark (ctrl);
    }

 leave:
  xfree (uidstring);
  release_kbnode (keyblock);
  keydb_release (kdbhd);
}


/* Unattended revocation of a keyid.  USERNAME specifies the
   key. UIDTOREV is the user id revoke from the key.  */
void
keyedit_quick_revuid (ctrl_t ctrl, const char *username, const char *uidtorev)
{
  gpg_error_t err;
  KEYDB_HANDLE kdbhd = NULL;
  kbnode_t keyblock = NULL;
  kbnode_t node;
  int modified = 0;
  size_t revlen;
  size_t valid_uids;

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  /* Search the key; we don't want the whole getkey stuff here.  */
  err = quick_find_keyblock (ctrl, username, 1, &kdbhd, &keyblock);
  if (err)
    goto leave;

  /* Too make sure that we do not revoke the last valid UID, we first
     count how many valid UIDs there are.  */
  valid_uids = 0;
  for (node = keyblock; node; node = node->next)
    valid_uids += (node->pkt->pkttype == PKT_USER_ID
                   && !node->pkt->pkt.user_id->flags.revoked
                   && !node->pkt->pkt.user_id->flags.expired);

  /* Find the right UID. */
  revlen = strlen (uidtorev);
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID
          && revlen == node->pkt->pkt.user_id->len
          && !memcmp (node->pkt->pkt.user_id->name, uidtorev, revlen))
        {
          struct revocation_reason_info *reason;

          /* Make sure that we do not revoke the last valid UID.  */
          if (valid_uids == 1
              && ! node->pkt->pkt.user_id->flags.revoked
              && ! node->pkt->pkt.user_id->flags.expired)
            {
              log_error (_("cannot revoke the last valid user ID.\n"));
              err = gpg_error (GPG_ERR_INV_USER_ID);
              goto leave;
            }

          reason = get_default_uid_revocation_reason ();
          err = core_revuid (ctrl, keyblock, node, reason, &modified);
          release_revocation_reason_info (reason);
          if (err)
            goto leave;
          err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
          if (err)
            {
              log_error (_("update failed: %s\n"), gpg_strerror (err));
              goto leave;
            }

          revalidation_mark (ctrl);
          goto leave;
        }
    }
  err = gpg_error (GPG_ERR_NO_USER_ID);


 leave:
  if (err)
    {
      log_error (_("revoking the user ID failed: %s\n"), gpg_strerror (err));
      write_status_error ("keyedit.revoke.uid", err);
    }
  release_kbnode (keyblock);
  keydb_release (kdbhd);
}


/* Unattended setting of the primary uid.  USERNAME specifies the key.
   PRIMARYUID is the user id which shall be primary.  */
void
keyedit_quick_set_primary (ctrl_t ctrl, const char *username,
                           const char *primaryuid)
{
  gpg_error_t err;
  KEYDB_HANDLE kdbhd = NULL;
  kbnode_t keyblock = NULL;
  kbnode_t node;
  size_t primaryuidlen;
  int any;

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  err = quick_find_keyblock (ctrl, username, 1, &kdbhd, &keyblock);
  if (err)
    goto leave;

  /* Find and mark the UID - we mark only the first valid one. */
  primaryuidlen = strlen (primaryuid);
  any = 0;
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID
          && !any
          && !node->pkt->pkt.user_id->flags.revoked
          && !node->pkt->pkt.user_id->flags.expired
          && primaryuidlen == node->pkt->pkt.user_id->len
          && !memcmp (node->pkt->pkt.user_id->name, primaryuid, primaryuidlen))
        {
          node->flag |= NODFLG_SELUID;
          any = 1;
        }
      else
        node->flag &= ~NODFLG_SELUID;
    }

  if (!any)
    err = gpg_error (GPG_ERR_NO_USER_ID);
  else if (menu_set_primary_uid (ctrl, keyblock))
    {
      merge_keys_and_selfsig (ctrl, keyblock);
      err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
      if (err)
        {
          log_error (_("update failed: %s\n"), gpg_strerror (err));
          goto leave;
        }
      revalidation_mark (ctrl);
    }
  else
    err = gpg_error (GPG_ERR_GENERAL);

  if (err)
    log_error (_("setting the primary user ID failed: %s\n"),
               gpg_strerror (err));

 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
}


/* Find a keyblock by fingerprint because only this uniquely
 * identifies a key and may thus be used to select a key for
 * unattended subkey creation os key signing.  */
static gpg_error_t
find_by_primary_fpr (ctrl_t ctrl, const char *fpr,
                     kbnode_t *r_keyblock, KEYDB_HANDLE *r_kdbhd)
{
  gpg_error_t err;
  kbnode_t keyblock = NULL;
  KEYDB_HANDLE kdbhd = NULL;
  KEYDB_SEARCH_DESC desc;
  byte fprbin[MAX_FINGERPRINT_LEN];
  size_t fprlen;

  *r_keyblock = NULL;
  *r_kdbhd = NULL;

  if (classify_user_id (fpr, &desc, 1)
      || !(desc.mode == KEYDB_SEARCH_MODE_FPR
           || desc.mode == KEYDB_SEARCH_MODE_FPR16
           || desc.mode == KEYDB_SEARCH_MODE_FPR20))
    {
      log_error (_("\"%s\" is not a fingerprint\n"), fpr);
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }
  err = get_pubkey_byname (ctrl, GET_PUBKEY_NO_AKL,
                           NULL, NULL, fpr, &keyblock, &kdbhd, 1);
  if (err)
    {
      log_error (_("key \"%s\" not found: %s\n"), fpr, gpg_strerror (err));
      goto leave;
    }

  /* Check that the primary fingerprint has been given. */
  fingerprint_from_pk (keyblock->pkt->pkt.public_key, fprbin, &fprlen);
  if (fprlen == 16 && desc.mode == KEYDB_SEARCH_MODE_FPR16
      && !memcmp (fprbin, desc.u.fpr, 16))
    ;
  else if (fprlen == 16 && desc.mode == KEYDB_SEARCH_MODE_FPR
           && !memcmp (fprbin, desc.u.fpr, 16)
           && !desc.u.fpr[16]
           && !desc.u.fpr[17]
           && !desc.u.fpr[18]
           && !desc.u.fpr[19])
    ;
  else if (fprlen == 20 && (desc.mode == KEYDB_SEARCH_MODE_FPR20
                            || desc.mode == KEYDB_SEARCH_MODE_FPR)
           && !memcmp (fprbin, desc.u.fpr, 20))
    ;
  else
    {
      log_error (_("\"%s\" is not the primary fingerprint\n"), fpr);
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  *r_keyblock = keyblock;
  keyblock = NULL;
  *r_kdbhd = kdbhd;
  kdbhd = NULL;
  err = 0;

 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
  return err;
}


/* Unattended key signing function.  If the key specifified by FPR is
   available and FPR is the primary fingerprint all user ids of the
   key are signed using the default signing key.  If UIDS is an empty
   list all usable UIDs are signed, if it is not empty, only those
   user ids matching one of the entries of the list are signed.  With
   LOCAL being true the signatures are marked as non-exportable.  */
void
keyedit_quick_sign (ctrl_t ctrl, const char *fpr, strlist_t uids,
                    strlist_t locusr, int local)
{
  gpg_error_t err;
  kbnode_t keyblock = NULL;
  KEYDB_HANDLE kdbhd = NULL;
  int modified = 0;
  PKT_public_key *pk;
  kbnode_t node;
  strlist_t sl;
  int any;

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  /* We require a fingerprint because only this uniquely identifies a
     key and may thus be used to select a key for unattended key
     signing.  */
  if (find_by_primary_fpr (ctrl, fpr, &keyblock, &kdbhd))
    goto leave;

  if (fix_keyblock (ctrl, &keyblock))
    modified++;

  /* Give some info in verbose.  */
  if (opt.verbose)
    {
      show_key_with_all_names (ctrl, es_stdout, keyblock, 0,
                               1/*with_revoker*/, 1/*with_fingerprint*/,
                               0, 0, 1);
      es_fflush (es_stdout);
    }

  pk = keyblock->pkt->pkt.public_key;
  if (pk->flags.revoked)
    {
      if (!opt.verbose)
        show_key_with_all_names (ctrl, es_stdout, keyblock, 0, 0, 0, 0, 0, 1);
      log_error ("%s%s", _("Key is revoked."), _("  Unable to sign.\n"));
      goto leave;
    }

  /* Set the flags according to the UIDS list.  Fixme: We may want to
     use classify_user_id along with dedicated compare functions so
     that we match the same way as in the key lookup. */
  any = 0;
  menu_select_uid (keyblock, 0);   /* Better clear the flags first. */
  for (sl=uids; sl; sl = sl->next)
    {
      const char *name = sl->d;
      int count = 0;

      sl->flags &= ~(1|2);  /* Clear flags used for error reporting.  */

      for (node = keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_USER_ID)
            {
              PKT_user_id *uid = node->pkt->pkt.user_id;

              if (uid->attrib_data)
                ;
              else if (*name == '='
                       && strlen (name+1) == uid->len
                       && !memcmp (uid->name, name + 1, uid->len))
                { /* Exact match - we don't do a check for ambiguity
                   * in this case.  */
                  node->flag |= NODFLG_SELUID;
                  if (any != -1)
                    {
                      sl->flags |= 1;  /* Report as found.  */
                      any = 1;
                    }
                }
              else if (ascii_memistr (uid->name, uid->len,
                                      *name == '*'? name+1:name))
                {
                  node->flag |= NODFLG_SELUID;
                  if (any != -1)
                    {
                      sl->flags |= 1;  /* Report as found.  */
                      any = 1;
                    }
                  count++;
                }
            }
        }

      if (count > 1)
        {
          any = -1;        /* Force failure at end.  */
          sl->flags |= 2;  /* Report as ambiguous.  */
        }
    }

  /* Check whether all given user ids were found.  */
  for (sl=uids; sl; sl = sl->next)
    if (!(sl->flags & 1))
      any = -1;  /* That user id was not found.  */

  /* Print an error if there was a problem with the user ids.  */
  if (uids && any < 1)
    {
      if (!opt.verbose)
        show_key_with_all_names (ctrl, es_stdout, keyblock, 0, 0, 0, 0, 0, 1);
      es_fflush (es_stdout);
      for (sl=uids; sl; sl = sl->next)
        {
          if ((sl->flags & 2))
            log_info (_("Invalid user ID '%s': %s\n"),
                      sl->d, gpg_strerror (GPG_ERR_AMBIGUOUS_NAME));
          else if (!(sl->flags & 1))
            log_info (_("Invalid user ID '%s': %s\n"),
                      sl->d, gpg_strerror (GPG_ERR_NOT_FOUND));
        }
      log_error ("%s  %s", _("No matching user IDs."), _("Nothing to sign.\n"));
      goto leave;
    }

  /* Sign. */
  sign_uids (ctrl, es_stdout, keyblock, locusr, &modified, local, 0, 0, 0, 1);
  es_fflush (es_stdout);

  if (modified)
    {
      err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
      if (err)
        {
          log_error (_("update failed: %s\n"), gpg_strerror (err));
          goto leave;
        }
    }
  else
    log_info (_("Key not changed so no update needed.\n"));

  if (update_trust)
    revalidation_mark (ctrl);


 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
}


/* Unattended revocation of a key signatures.  USERNAME specifies the
 * key; this should best be a fingerprint. SIGTOREV is the user-id of
 * the key for which the key signature shall be removed.  Only
 * non-self-signatures can be removed with this functions.  If
 * AFFECTED_UIDS is not NULL only the key signatures on these user-ids
 * are revoked. */
void
keyedit_quick_revsig (ctrl_t ctrl, const char *username, const char *sigtorev,
                      strlist_t affected_uids)
{
  gpg_error_t err;
  int no_signing_key = 0;
  KEYDB_HANDLE kdbhd = NULL;
  kbnode_t keyblock = NULL;
  PKT_public_key *primarypk;  /* Points into KEYBLOCK.  */
  u32 *primarykid;
  PKT_public_key *pksigtorev = NULL;
  u32 *pksigtorevkid;
  kbnode_t node, n;
  int skip_remaining;
  int consider_sig;
  strlist_t sl;
  struct sign_attrib attrib = { 0 };

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  /* Search the key; we don't want the whole getkey stuff here.  Noet
   * that we are looking for the public key here.  */
  err = quick_find_keyblock (ctrl, username, 0, &kdbhd, &keyblock);
  if (err)
    goto leave;
  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY
              || keyblock->pkt->pkttype == PKT_SECRET_KEY);
  primarypk = keyblock->pkt->pkt.public_key;
  primarykid = pk_keyid (primarypk);

  /* Get the signing key we want to revoke.  This must be one of our
   * signing keys.  We will compare only the keyid because we don't
   * assume that we have duplicated keyids on our own secret keys.  If
   * a there is a duplicated one we will notice this when creating the
   * revocation.  */
  pksigtorev = xtrycalloc (1, sizeof *pksigtorev);
  if (!pksigtorev)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  pksigtorev->req_usage = PUBKEY_USAGE_CERT;
  err = getkey_byname (ctrl, NULL, pksigtorev, sigtorev, 1, NULL);
  if (err)
    {
      no_signing_key = 1;
      goto leave;
    }
  pksigtorevkid = pk_keyid (pksigtorev);

  /* Find the signatures we want to revoke and set a mark.  */
  skip_remaining = consider_sig = 0;
  for (node = keyblock; node; node = node->next)
    {
      node->flag &= ~NODFLG_MARK_A;
      if (skip_remaining)
        ;
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        skip_remaining = 1;
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
          PKT_user_id *uid = node->pkt->pkt.user_id;

          consider_sig = !affected_uids;
          for (sl = affected_uids; !consider_sig && sl; sl = sl->next)
            {
              const char *name = sl->d;

              if (uid->attrib_data)
                ;
              else if (*name == '='
                       && strlen (name+1) == uid->len
                       && !memcmp (uid->name, name + 1, uid->len))
                { /* Exact match.  */
                  consider_sig = 1;
                }
              else if (ascii_memistr (uid->name, uid->len,
                                      *name == '*'? name+1:name))
                { /* Case-insensitive substring match.  */
                  consider_sig = 1;
                }
            }
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE)
	{
          /* We need to sort the signatures so that we can figure out
           * whether the key signature has been revoked or the
           * revocation has been superseded by a new key
           * signature.  */
          PKT_signature *sig;
          unsigned int sigcount = 0;
          kbnode_t *sigarray;

          /* Allocate an array large enogh for all signatures.  */
          for (n=node; n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
            sigcount++;
          sigarray = xtrycalloc (sigcount, sizeof *sigarray);
          if (!sigarray)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }

          /* Now fill the array with signatures we are interested in.
           * We also move NODE forward to the end.  */
          sigcount = 0;
          for (n=node; n && n->pkt->pkttype == PKT_SIGNATURE; node=n, n=n->next)
            {
              sig = n->pkt->pkt.signature;
              if (!keyid_cmp (primarykid, sig->keyid))
                continue;  /* Ignore self-signatures.  */

              if (keyid_cmp (pksigtorevkid, sig->keyid))
                continue; /* Ignore non-matching signatures.  */

              n->flag &= ~NODFLG_MARK_B; /* Clear flag used by cmp_signode. */
              sigarray[sigcount++] = n;
            }

          if (sigcount)
            {
              qsort (sigarray, sigcount, sizeof *sigarray, cmp_signodes);

              /* log_debug ("Sorted signatures:\n"); */
              /* for (idx=0; idx < sigcount; idx++) */
              /*   { */
              /*     sig = sigarray[idx]->pkt->pkt.signature; */
              /*     log_debug ("%s 0x%02x %s\n", keystr (sig->keyid), */
              /*                sig->sig_class, datestr_from_sig (sig)); */
              /*   } */
              sig = sigarray[sigcount-1]->pkt->pkt.signature;
              if ((consider_sig || !affected_uids) && IS_UID_REV (sig))
                {
                  if (!opt.quiet)
                    log_info ("sig by %s already revoked at %s\n",
                              keystr (sig->keyid), datestr_from_sig (sig));
                }
              else if ((consider_sig && IS_UID_SIG (sig))
                       || (!affected_uids && IS_KEY_SIG (sig)))
                node->flag |= NODFLG_MARK_A;  /* Select signature.  */
            }

          xfree (sigarray);
	}
    }

  /* Check whether any signatures were done by the given key.  We do
   * not return an error if none were found.  */
  for (node = keyblock; node; node = node->next)
    if ((node->flag & NODFLG_MARK_A))
      break;
  if (!node)
    {
      if (opt.verbose)
        log_info (_("Not signed by you.\n"));
      err = 0;
      goto leave;
    }

  /* Revoke all marked signatures.  */
  attrib.reason = get_default_sig_revocation_reason ();

 reloop: /* (we must repeat because we are modifying the list) */
  for (node = keyblock; node; node = node->next)
    {
      kbnode_t unode;
      PKT_signature *sig;
      PACKET *pkt;

      if (!(node->flag & NODFLG_MARK_A))
	continue;
      node->flag &= ~NODFLG_MARK_A;

      if (IS_KEY_SIG (node->pkt->pkt.signature))
        unode = NULL;
      else
        {
          unode = find_prev_kbnode (keyblock, node, PKT_USER_ID);
          log_assert (unode);
        }

      attrib.non_exportable = !node->pkt->pkt.signature->flags.exportable;

      err = make_keysig_packet (ctrl, &sig, primarypk,
                                unode? unode->pkt->pkt.user_id : NULL,
                                NULL, pksigtorev, 0x30, 0, 0, 0,
                                sign_mk_attrib, &attrib, NULL);
      if (err)
        {
          log_error ("signing failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      pkt = xmalloc_clear (sizeof *pkt);
      pkt->pkttype = PKT_SIGNATURE;
      pkt->pkt.signature = sig;
      if (unode)
        insert_kbnode (unode, new_kbnode (pkt), 0);
      goto reloop;
    }

  err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
  if (err)
    {
      log_error (_("update failed: %s\n"), gpg_strerror (err));
      goto leave;
    }
  revalidation_mark (ctrl);

 leave:
  if (err)
    {
      log_error (_("revoking the key signature failed: %s\n"),
                 gpg_strerror (err));
      if (no_signing_key)
        print_further_info ("error getting key used to make the key signature");
      write_status_error ("keyedit.revoke.sig", err);
    }
  release_revocation_reason_info (attrib.reason);
  free_public_key (pksigtorev);
  release_kbnode (keyblock);
  keydb_release (kdbhd);
}


/* Unattended subkey creation function.
 *
 */
void
keyedit_quick_addkey (ctrl_t ctrl, const char *fpr, const char *algostr,
                      const char *usagestr, const char *expirestr)
{
  gpg_error_t err;
  kbnode_t keyblock;
  KEYDB_HANDLE kdbhd;
  int modified = 0;
  PKT_public_key *pk;

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  /* We require a fingerprint because only this uniquely identifies a
   * key and may thus be used to select a key for unattended subkey
   * creation.  */
  if (find_by_primary_fpr (ctrl, fpr, &keyblock, &kdbhd))
    goto leave;

  if (fix_keyblock (ctrl, &keyblock))
    modified++;

  pk = keyblock->pkt->pkt.public_key;
  if (pk->flags.revoked)
    {
      if (!opt.verbose)
        show_key_with_all_names (ctrl, es_stdout, keyblock, 0, 0, 0, 0, 0, 1);
      log_error ("%s%s", _("Key is revoked."), "\n");
      goto leave;
    }

  /* Create the subkey.  Note that the called function already prints
   * an error message. */
  if (!generate_subkeypair (ctrl, keyblock, algostr, usagestr, expirestr))
    modified = 1;
  es_fflush (es_stdout);

  /* Store.  */
  if (modified)
    {
      err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
      if (err)
        {
          log_error (_("update failed: %s\n"), gpg_strerror (err));
          goto leave;
        }
    }
  else
    log_info (_("Key not changed so no update needed.\n"));

 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
}


/* Unattended expiration setting function for the main key.  If
 * SUBKEYFPRS is not NULL and SUBKEYSFPRS[0] is neither NULL, it is
 * expected to be an array of fingerprints for subkeys to change. It
 * may also be an array which just one item "*" to indicate that all
 * keys shall be set to that expiration date.
 */
void
keyedit_quick_set_expire (ctrl_t ctrl, const char *fpr, const char *expirestr,
                          char **subkeyfprs)
{
  gpg_error_t err;
  kbnode_t keyblock, node;
  KEYDB_HANDLE kdbhd;
  int modified = 0;
  PKT_public_key *pk;
  u32 expire;
  int primary_only = 0;
  int idx;

#ifdef HAVE_W32_SYSTEM
  /* See keyedit_menu for why we need this.  */
  check_trustdb_stale (ctrl);
#endif

  /* We require a fingerprint because only this uniquely identifies a
   * key and may thus be used to select a key for unattended
   * expiration setting.  */
  err = find_by_primary_fpr (ctrl, fpr, &keyblock, &kdbhd);
  if (err)
    goto leave;

  if (fix_keyblock (ctrl, &keyblock))
    modified++;

  pk = keyblock->pkt->pkt.public_key;
  if (pk->flags.revoked)
    {
      if (!opt.verbose)
        show_key_with_all_names (ctrl, es_stdout, keyblock, 0, 0, 0, 0, 0, 1);
      log_error ("%s%s", _("Key is revoked."), "\n");
      err = gpg_error (GPG_ERR_CERT_REVOKED);
      goto leave;
    }

  expire = parse_expire_string (expirestr);
  if (expire == (u32)-1 )
    {
      log_error (_("'%s' is not a valid expiration time\n"), expirestr);
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  if (expire)
    expire += make_timestamp ();

  /* Check whether a subkey's expiration time shall be changed or the
   * expiration time of all keys.  */
  if (!subkeyfprs || !subkeyfprs[0])
    primary_only = 1;
  else if ( !strcmp (subkeyfprs[0], "*") && !subkeyfprs[1])
    {
      /* Change all subkeys keys which have not been revoked and are
       * not yet expired.  */
      merge_keys_and_selfsig (ctrl, keyblock);
      for (node = keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
              && (pk = node->pkt->pkt.public_key)
              && !pk->flags.revoked
              && !pk->has_expired)
            node->flag |= NODFLG_SELKEY;
        }
    }
  else
    {
      /* Change specified subkeys.  */
      KEYDB_SEARCH_DESC desc;
      byte fprbin[MAX_FINGERPRINT_LEN];
      size_t fprlen;

      err = 0;
      merge_keys_and_selfsig (ctrl, keyblock);
      for (idx=0; subkeyfprs[idx]; idx++)
        {
          int any = 0;

          /* Parse the fingerprint.  */
          if (classify_user_id (subkeyfprs[idx], &desc, 1)
              || !(desc.mode == KEYDB_SEARCH_MODE_FPR
                   || desc.mode == KEYDB_SEARCH_MODE_FPR20))
            {
              log_error (_("\"%s\" is not a proper fingerprint\n"),
                         subkeyfprs[idx] );
              if (!err)
                err = gpg_error (GPG_ERR_INV_NAME);
              continue;
            }

          /* Set the flag for the matching non revoked subkey.  */
          for (node = keyblock; node; node = node->next)
            {
              if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                  && (pk = node->pkt->pkt.public_key)
                  && !pk->flags.revoked )
                {
                  fingerprint_from_pk (pk, fprbin, &fprlen);
                  if (fprlen == 20 && !memcmp (fprbin, desc.u.fpr, 20))
                    {
                      node->flag |= NODFLG_SELKEY;
                      any = 1;
                    }
                }
            }
          if (!any)
            {
              log_error (_("subkey \"%s\" not found\n"), subkeyfprs[idx]);
              if (!err)
                err = gpg_error (GPG_ERR_NOT_FOUND);
            }
        }

      if (err)
        goto leave;
    }

  /* Set the new expiration date.  */
  err = menu_expire (ctrl, keyblock, primary_only? 1 : 2, expire);
  if (gpg_err_code (err) == GPG_ERR_TRUE)
    modified = 1;
  else if (err)
    goto leave;
  es_fflush (es_stdout);

  /* Store.  */
  if (modified)
    {
      err = keydb_update_keyblock (ctrl, kdbhd, keyblock);
      if (err)
        {
          log_error (_("update failed: %s\n"), gpg_strerror (err));
          goto leave;
        }
      if (update_trust)
        revalidation_mark (ctrl);
    }
  else
    log_info (_("Key not changed so no update needed.\n"));

 leave:
  release_kbnode (keyblock);
  keydb_release (kdbhd);
  if (err)
    write_status_error ("set_expire", err);
}



static void
tty_print_notations (int indent, PKT_signature * sig)
{
  int first = 1;
  struct notation *notation, *nd;

  if (indent < 0)
    {
      first = 0;
      indent = -indent;
    }

  notation = sig_to_notation (sig);

  for (nd = notation; nd; nd = nd->next)
    {
      if (!first)
	tty_printf ("%*s", indent, "");
      else
	first = 0;

      tty_print_utf8_string (nd->name, strlen (nd->name));
      tty_printf ("=");
      tty_print_utf8_string (nd->value, strlen (nd->value));
      tty_printf ("\n");
    }

  free_notation (notation);
}


/*
 * Show preferences of a public keyblock.
 */
static void
show_prefs (PKT_user_id * uid, PKT_signature * selfsig, int verbose)
{
  const prefitem_t fake = { 0, 0 };
  const prefitem_t *prefs;
  int i;

  if (!uid)
    return;

  if (uid->prefs)
    prefs = uid->prefs;
  else if (verbose)
    prefs = &fake;
  else
    return;

  if (verbose)
    {
      int any, des_seen = 0, sha1_seen = 0, uncomp_seen = 0;

      tty_printf ("     ");
      tty_printf (_("Cipher: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_SYM)
	    {
	      if (any)
		tty_printf (", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (!openpgp_cipher_test_algo (prefs[i].value)
		  && prefs[i].value < 100)
		tty_printf ("%s", openpgp_cipher_algo_name (prefs[i].value));
	      else
		tty_printf ("[%d]", prefs[i].value);
	      if (prefs[i].value == CIPHER_ALGO_3DES)
		des_seen = 1;
	    }
	}
      if (!des_seen)
	{
	  if (any)
	    tty_printf (", ");
	  tty_printf ("%s", openpgp_cipher_algo_name (CIPHER_ALGO_3DES));
	}
      tty_printf ("\n     ");
      tty_printf (_("AEAD: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_AEAD)
	    {
	      if (any)
		tty_printf (", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (!openpgp_aead_test_algo (prefs[i].value)
		  && prefs[i].value < 100)
		tty_printf ("%s", openpgp_aead_algo_name (prefs[i].value));
	      else
		tty_printf ("[%d]", prefs[i].value);
	    }
	}
      tty_printf ("\n     ");
      tty_printf (_("Digest: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_HASH)
	    {
	      if (any)
		tty_printf (", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (!gcry_md_test_algo (prefs[i].value) && prefs[i].value < 100)
		tty_printf ("%s", gcry_md_algo_name (prefs[i].value));
	      else
		tty_printf ("[%d]", prefs[i].value);
	      if (prefs[i].value == DIGEST_ALGO_SHA1)
		sha1_seen = 1;
	    }
	}
      if (!sha1_seen)
	{
	  if (any)
	    tty_printf (", ");
	  tty_printf ("%s", gcry_md_algo_name (DIGEST_ALGO_SHA1));
	}
      tty_printf ("\n     ");
      tty_printf (_("Compression: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_ZIP)
	    {
	      const char *s = compress_algo_to_string (prefs[i].value);

	      if (any)
		tty_printf (", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (s && prefs[i].value < 100)
		tty_printf ("%s", s);
	      else
		tty_printf ("[%d]", prefs[i].value);
	      if (prefs[i].value == COMPRESS_ALGO_NONE)
		uncomp_seen = 1;
	    }
	}
      if (!uncomp_seen)
	{
	  if (any)
	    tty_printf (", ");
	  else
	    {
	      tty_printf ("%s", compress_algo_to_string (COMPRESS_ALGO_ZIP));
	      tty_printf (", ");
	    }
	  tty_printf ("%s", compress_algo_to_string (COMPRESS_ALGO_NONE));
	}
      if (uid->flags.mdc || uid->flags.aead || !uid->flags.ks_modify)
	{
	  tty_printf ("\n     ");
	  tty_printf (_("Features: "));
	  any = 0;
	  if (uid->flags.mdc)
	    {
	      tty_printf ("MDC");
	      any = 1;
	    }
	  if (!uid->flags.aead)
	    {
	      if (any)
		tty_printf (", ");
	      tty_printf ("AEAD");
	    }
	  if (!uid->flags.ks_modify)
	    {
	      if (any)
		tty_printf (", ");
	      tty_printf (_("Keyserver no-modify"));
	    }
	}
      tty_printf ("\n");

      if (selfsig)
	{
	  const byte *pref_ks;
	  size_t pref_ks_len;

	  pref_ks = parse_sig_subpkt (selfsig->hashed,
				      SIGSUBPKT_PREF_KS, &pref_ks_len);
	  if (pref_ks && pref_ks_len)
	    {
	      tty_printf ("     ");
	      tty_printf (_("Preferred keyserver: "));
	      tty_print_utf8_string (pref_ks, pref_ks_len);
	      tty_printf ("\n");
	    }

	  if (selfsig->flags.notation)
	    {
	      tty_printf ("     ");
	      tty_printf (_("Notations: "));
	      tty_print_notations (5 + strlen (_("Notations: ")), selfsig);
	    }
	}
    }
  else
    {
      tty_printf ("    ");
      for (i = 0; prefs[i].type; i++)
	{
	  tty_printf (" %c%d", prefs[i].type == PREFTYPE_SYM ? 'S' :
		      prefs[i].type == PREFTYPE_AEAD ? 'A' :
		      prefs[i].type == PREFTYPE_HASH ? 'H' :
		      prefs[i].type == PREFTYPE_ZIP ? 'Z' : '?',
		      prefs[i].value);
	}
      if (uid->flags.mdc)
	tty_printf (" [mdc]");
      if (uid->flags.aead)
	tty_printf (" [aead]");
      if (!uid->flags.ks_modify)
	tty_printf (" [no-ks-modify]");
      tty_printf ("\n");
    }
}


/* This is the version of show_key_with_all_names used when
   opt.with_colons is used.  It prints all available data in a easy to
   parse format and does not translate utf8 */
static void
show_key_with_all_names_colon (ctrl_t ctrl, estream_t fp, kbnode_t keyblock)
{
  KBNODE node;
  int i, j, ulti_hack = 0;
  byte pk_version = 0;
  PKT_public_key *primary = NULL;
  int have_seckey;

  if (!fp)
    fp = es_stdout;

  /* the keys */
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
	  || (node->pkt->pkttype == PKT_PUBLIC_SUBKEY))
	{
	  PKT_public_key *pk = node->pkt->pkt.public_key;
	  u32 keyid[2];

	  if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	    {
	      pk_version = pk->version;
	      primary = pk;
	    }

	  keyid_from_pk (pk, keyid);
          have_seckey = !agent_probe_secret_key (ctrl, pk);

          if (node->pkt->pkttype == PKT_PUBLIC_KEY)
            es_fputs (have_seckey? "sec:" : "pub:", fp);
          else
            es_fputs (have_seckey? "ssb:" : "sub:", fp);

	  if (!pk->flags.valid)
	    es_putc ('i', fp);
	  else if (pk->flags.revoked)
	    es_putc ('r', fp);
	  else if (pk->has_expired)
	    es_putc ('e', fp);
	  else if (!(opt.fast_list_mode || opt.no_expensive_trust_checks))
	    {
	      int trust = get_validity_info (ctrl, keyblock, pk, NULL);
	      if (trust == 'u')
		ulti_hack = 1;
	      es_putc (trust, fp);
	    }

	  es_fprintf (fp, ":%u:%d:%08lX%08lX:%lu:%lu::",
                      nbits_from_pk (pk),
                      pk->pubkey_algo,
                      (ulong) keyid[0], (ulong) keyid[1],
                      (ulong) pk->timestamp, (ulong) pk->expiredate);
	  if (node->pkt->pkttype == PKT_PUBLIC_KEY
	      && !(opt.fast_list_mode || opt.no_expensive_trust_checks))
	    es_putc (get_ownertrust_info (ctrl, pk, 0), fp);
	  es_putc (':', fp);
	  es_putc (':', fp);
	  es_putc (':', fp);
	  /* Print capabilities.  */
	  if ((pk->pubkey_usage & PUBKEY_USAGE_ENC))
	    es_putc ('e', fp);
	  if ((pk->pubkey_usage & PUBKEY_USAGE_SIG))
	    es_putc ('s', fp);
	  if ((pk->pubkey_usage & PUBKEY_USAGE_CERT))
	    es_putc ('c', fp);
	  if ((pk->pubkey_usage & PUBKEY_USAGE_AUTH))
	    es_putc ('a', fp);
	  es_putc ('\n', fp);

	  print_fingerprint (ctrl, fp, pk, 0);
	  print_revokers (fp, pk);
	}
    }

  /* the user ids */
  i = 0;
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;

	  ++i;

	  if (uid->attrib_data)
	    es_fputs ("uat:", fp);
	  else
	    es_fputs ("uid:", fp);

	  if (uid->flags.revoked)
	    es_fputs ("r::::::::", fp);
	  else if (uid->flags.expired)
	    es_fputs ("e::::::::", fp);
	  else if (opt.fast_list_mode || opt.no_expensive_trust_checks)
	    es_fputs ("::::::::", fp);
	  else
	    {
	      int uid_validity;

	      if (primary && !ulti_hack)
		uid_validity = get_validity_info (ctrl, keyblock, primary, uid);
	      else
		uid_validity = 'u';
	      es_fprintf (fp, "%c::::::::", uid_validity);
	    }

	  if (uid->attrib_data)
	    es_fprintf (fp, "%u %lu", uid->numattribs, uid->attrib_len);
	  else
	    es_write_sanitized (fp, uid->name, uid->len, ":", NULL);

	  es_putc (':', fp);
	  /* signature class */
	  es_putc (':', fp);
	  /* capabilities */
	  es_putc (':', fp);
	  /* preferences */
	  if (pk_version > 3 || uid->selfsigversion > 3)
	    {
	      const prefitem_t *prefs = uid->prefs;

	      for (j = 0; prefs && prefs[j].type; j++)
		{
		  if (j)
		    es_putc (' ', fp);
		  es_fprintf (fp,
                              "%c%d", prefs[j].type == PREFTYPE_SYM ? 'S' :
                              prefs[j].type == PREFTYPE_HASH ? 'H' :
                              prefs[j].type == PREFTYPE_ZIP ? 'Z' : '?',
                              prefs[j].value);
		}
	      if (uid->flags.mdc)
		es_fputs (",mdc", fp);
	      if (!uid->flags.ks_modify)
		es_fputs (",no-ks-modify", fp);
	    }
	  es_putc (':', fp);
	  /* flags */
	  es_fprintf (fp, "%d,", i);
	  if (uid->flags.primary)
	    es_putc ('p', fp);
	  if (uid->flags.revoked)
	    es_putc ('r', fp);
	  if (uid->flags.expired)
	    es_putc ('e', fp);
	  if ((node->flag & NODFLG_SELUID))
	    es_putc ('s', fp);
	  if ((node->flag & NODFLG_MARK_A))
	    es_putc ('m', fp);
	  es_putc (':', fp);
	  if (opt.trust_model == TM_TOFU || opt.trust_model == TM_TOFU_PGP)
	    {
#ifdef USE_TOFU
	      enum tofu_policy policy;
	      if (! tofu_get_policy (ctrl, primary, uid, &policy)
		  && policy != TOFU_POLICY_NONE)
		es_fprintf (fp, "%s", tofu_policy_str (policy));
#endif /*USE_TOFU*/
	    }
	  es_putc (':', fp);
	  es_putc ('\n', fp);
	}
    }
}


static void
show_names (ctrl_t ctrl, estream_t fp,
            kbnode_t keyblock, PKT_public_key * pk, unsigned int flag,
	    int with_prefs)
{
  KBNODE node;
  int i = 0;

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID && !is_deleted_kbnode (node))
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  ++i;
	  if (!flag || (flag && (node->flag & flag)))
	    {
	      if (!(flag & NODFLG_MARK_A) && pk)
		tty_fprintf (fp, "%s ", uid_trust_string_fixed (ctrl, pk, uid));

	      if (flag & NODFLG_MARK_A)
		tty_fprintf (fp, "     ");
	      else if (node->flag & NODFLG_SELUID)
		tty_fprintf (fp, "(%d)* ", i);
	      else if (uid->flags.primary)
		tty_fprintf (fp, "(%d). ", i);
	      else
		tty_fprintf (fp, "(%d)  ", i);
	      tty_print_utf8_string2 (fp, uid->name, uid->len, 0);
	      tty_fprintf (fp, "\n");
	      if (with_prefs && pk)
		{
		  if (pk->version > 3 || uid->selfsigversion > 3)
		    {
		      PKT_signature *selfsig = NULL;
		      KBNODE signode;

		      for (signode = node->next;
			   signode && signode->pkt->pkttype == PKT_SIGNATURE;
			   signode = signode->next)
			{
			  if (signode->pkt->pkt.signature->
			      flags.chosen_selfsig)
			    {
			      selfsig = signode->pkt->pkt.signature;
			      break;
			    }
			}

		      show_prefs (uid, selfsig, with_prefs == 2);
		    }
		  else
		    tty_fprintf (fp, _("There are no preferences on a"
                                       " PGP 2.x-style user ID.\n"));
		}
	    }
	}
    }
}


/*
 * Display the key a the user ids, if only_marked is true, do only so
 * for user ids with mark A flag set and do not display the index
 * number.  If FP is not NULL print to the given stream and not to the
 * tty (ignored in with-colons mode).
 */
static void
show_key_with_all_names (ctrl_t ctrl, estream_t fp,
                         KBNODE keyblock, int only_marked, int with_revoker,
			 int with_fpr, int with_subkeys, int with_prefs,
                         int nowarn)
{
  gpg_error_t err;
  kbnode_t node;
  int i;
  int do_warn = 0;
  int have_seckey = 0;
  char *serialno = NULL;
  PKT_public_key *primary = NULL;
  char pkstrbuf[PUBKEY_STRING_SIZE];

  if (opt.with_colons)
    {
      show_key_with_all_names_colon (ctrl, fp, keyblock);
      return;
    }

  /* the keys */
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
	  || (with_subkeys && node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	      && !is_deleted_kbnode (node)))
	{
	  PKT_public_key *pk = node->pkt->pkt.public_key;
	  const char *otrust = "err";
	  const char *trust = "err";

	  if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	    {
	      /* do it here, so that debug messages don't clutter the
	       * output */
	      static int did_warn = 0;

	      trust = get_validity_string (ctrl, pk, NULL);
	      otrust = get_ownertrust_string (ctrl, pk, 0);

	      /* Show a warning once */
	      if (!did_warn
		  && (get_validity (ctrl, keyblock, pk, NULL, NULL, 0)
		      & TRUST_FLAG_PENDING_CHECK))
		{
		  did_warn = 1;
		  do_warn = 1;
		}

	      primary = pk;
	    }

	  if (pk->flags.revoked)
	    {
	      char *user = get_user_id_string_native (ctrl, pk->revoked.keyid);
              tty_fprintf (fp,
                           _("The following key was revoked on"
                            " %s by %s key %s\n"),
			  revokestr_from_pk (pk),
                          gcry_pk_algo_name (pk->revoked.algo), user);
	      xfree (user);
	    }

	  if (with_revoker)
	    {
	      if (!pk->revkey && pk->numrevkeys)
		BUG ();
	      else
		for (i = 0; i < pk->numrevkeys; i++)
		  {
		    u32 r_keyid[2];
		    char *user;
		    const char *algo;

		    algo = gcry_pk_algo_name (pk->revkey[i].algid);
		    keyid_from_fingerprint (ctrl, pk->revkey[i].fpr,
					    MAX_FINGERPRINT_LEN, r_keyid);

		    user = get_user_id_string_native (ctrl, r_keyid);
		    tty_fprintf (fp,
                                 _("This key may be revoked by %s key %s"),
                                 algo ? algo : "?", user);

		    if (pk->revkey[i].class & 0x40)
		      {
			tty_fprintf (fp, " ");
			tty_fprintf (fp, _("(sensitive)"));
		      }

		    tty_fprintf (fp, "\n");
		    xfree (user);
		  }
	    }

	  keyid_from_pk (pk, NULL);

          xfree (serialno);
          serialno = NULL;
          {
            char *hexgrip;

            err = hexkeygrip_from_pk (pk, &hexgrip);
            if (err)
              {
                log_error ("error computing a keygrip: %s\n",
                           gpg_strerror (err));
                have_seckey = 0;
              }
            else
              have_seckey = !agent_get_keyinfo (ctrl, hexgrip, &serialno, NULL);
            xfree (hexgrip);
          }

	  tty_fprintf
            (fp, "%s%c %s/%s",
             node->pkt->pkttype == PKT_PUBLIC_KEY && have_seckey? "sec" :
             node->pkt->pkttype == PKT_PUBLIC_KEY ?               "pub" :
             have_seckey ?                                        "ssb" :
                                                                  "sub",
             (node->flag & NODFLG_SELKEY) ? '*' : ' ',
             pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
             keystr (pk->keyid));

          if (opt.legacy_list_mode)
            tty_fprintf (fp, "  ");
          else
            tty_fprintf (fp, "\n     ");

          tty_fprintf (fp, _("created: %s"), datestr_from_pk (pk));
	  tty_fprintf (fp, "  ");
	  if (pk->flags.revoked)
	    tty_fprintf (fp, _("revoked: %s"), revokestr_from_pk (pk));
	  else if (pk->has_expired)
	    tty_fprintf (fp, _("expired: %s"), expirestr_from_pk (pk));
	  else
	    tty_fprintf (fp, _("expires: %s"), expirestr_from_pk (pk));
	  tty_fprintf (fp, "  ");
	  tty_fprintf (fp, _("usage: %s"), usagestr_from_pk (pk, 1));
	  tty_fprintf (fp, "\n");

          if (serialno)
            {
              /* The agent told us that a secret key is available and
                 that it has been stored on a card.  */
	      tty_fprintf (fp, "%*s%s", opt.legacy_list_mode? 21:5, "",
                           _("card-no: "));
              if (strlen (serialno) == 32
                  && !strncmp (serialno, "D27600012401", 12))
                {
                  /* This is an OpenPGP card.  Print the relevant part.  */
                  /* Example: D2760001240101010001000003470000 */
                  /*                          xxxxyyyyyyyy     */
                  tty_fprintf (fp, "%.*s %.*s\n",
                               4, serialno+16, 8, serialno+20);
                }
              else
                tty_fprintf (fp, "%s\n", serialno);

            }
	  else if (pk->seckey_info
              && pk->seckey_info->is_protected
              && pk->seckey_info->s2k.mode == 1002)
	    {
              /* FIXME: Check whether this code path is still used.  */
	      tty_fprintf (fp, "%*s%s", opt.legacy_list_mode? 21:5, "",
                           _("card-no: "));
	      if (pk->seckey_info->ivlen == 16
		  && !memcmp (pk->seckey_info->iv,
                              "\xD2\x76\x00\x01\x24\x01", 6))
		{
                  /* This is an OpenPGP card. */
		  for (i = 8; i < 14; i++)
		    {
		      if (i == 10)
			tty_fprintf (fp, " ");
		      tty_fprintf (fp, "%02X", pk->seckey_info->iv[i]);
		    }
		}
	      else
		{
                  /* Unknown card: Print all. */
		  for (i = 0; i < pk->seckey_info->ivlen; i++)
		    tty_fprintf (fp, "%02X", pk->seckey_info->iv[i]);
		}
	      tty_fprintf (fp, "\n");
	    }

	  if (node->pkt->pkttype == PKT_PUBLIC_KEY
              || node->pkt->pkttype == PKT_SECRET_KEY)
	    {
	      if (opt.trust_model != TM_ALWAYS)
		{
		  tty_fprintf (fp, "%*s",
                               opt.legacy_list_mode?
                               ((int) keystrlen () + 13):5, "");
		  /* Ownertrust is only meaningful for the PGP or
		     classic trust models, or PGP combined with TOFU */
		  if (opt.trust_model == TM_PGP
		      || opt.trust_model == TM_CLASSIC
		      || opt.trust_model == TM_TOFU_PGP)
		    {
		      int width = 14 - strlen (otrust);
		      if (width <= 0)
			width = 1;
		      tty_fprintf (fp, _("trust: %s"), otrust);
		      tty_fprintf (fp, "%*s", width, "");
		    }

		  tty_fprintf (fp, _("validity: %s"), trust);
		  tty_fprintf (fp, "\n");
		}
	      if (node->pkt->pkttype == PKT_PUBLIC_KEY
		  && (get_ownertrust (ctrl, pk) & TRUST_FLAG_DISABLED))
		{
		  tty_fprintf (fp, "*** ");
		  tty_fprintf (fp, _("This key has been disabled"));
		  tty_fprintf (fp, "\n");
		}
	    }

	  if ((node->pkt->pkttype == PKT_PUBLIC_KEY
               || node->pkt->pkttype == PKT_SECRET_KEY) && with_fpr)
	    {
              print_fingerprint (ctrl, fp, pk, 2);
	      tty_fprintf (fp, "\n");
	    }
	}
    }

  show_names (ctrl, fp,
              keyblock, primary, only_marked ? NODFLG_MARK_A : 0, with_prefs);

  if (do_warn && !nowarn)
    tty_fprintf (fp, _("Please note that the shown key validity"
                       " is not necessarily correct\n"
                       "unless you restart the program.\n"));

  xfree (serialno);
}


/* Display basic key information.  This function is suitable to show
 * information on the key without any dependencies on the trustdb or
 * any other internal GnuPG stuff.  KEYBLOCK may either be a public or
 * a secret key.  This function may be called with KEYBLOCK containing
 * secret keys and thus the printing of "pub" vs. "sec" does only
 * depend on the packet type and not by checking with gpg-agent.  If
 * PRINT_SEC ist set "sec" is printed instead of "pub".  */
void
show_basic_key_info (ctrl_t ctrl, kbnode_t keyblock, int print_sec)
{
  KBNODE node;
  int i;
  char pkstrbuf[PUBKEY_STRING_SIZE];

  /* The primary key */
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
          || node->pkt->pkttype == PKT_SECRET_KEY)
	{
	  PKT_public_key *pk = node->pkt->pkt.public_key;
          const char *tag;

          if (node->pkt->pkttype == PKT_SECRET_KEY || print_sec)
            tag = "sec";
          else
            tag = "pub";

	  /* Note, we use the same format string as in other show
	     functions to make the translation job easier. */
	  tty_printf ("%s  %s/%s  ",
                      tag,
                      pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
		      keystr_from_pk (pk));
	  tty_printf (_("created: %s"), datestr_from_pk (pk));
	  tty_printf ("  ");
	  tty_printf (_("expires: %s"), expirestr_from_pk (pk));
	  tty_printf ("\n");
	  print_fingerprint (ctrl, NULL, pk, 3);
	  tty_printf ("\n");
	}
    }

  /* The user IDs. */
  for (i = 0, node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  ++i;

	  tty_printf ("     ");
	  if (uid->flags.revoked)
	    tty_printf ("[%s] ", _("revoked"));
	  else if (uid->flags.expired)
	    tty_printf ("[%s] ", _("expired"));
	  tty_print_utf8_string (uid->name, uid->len);
	  tty_printf ("\n");
	}
    }
}


static void
show_key_and_fingerprint (ctrl_t ctrl, kbnode_t keyblock, int with_subkeys)
{
  kbnode_t node;
  PKT_public_key *pk = NULL;
  char pkstrbuf[PUBKEY_STRING_SIZE];

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  pk = node->pkt->pkt.public_key;
	  tty_printf ("pub   %s/%s %s ",
                      pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                      keystr_from_pk(pk),
                      datestr_from_pk (pk));
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  tty_print_utf8_string (uid->name, uid->len);
	  break;
	}
    }
  tty_printf ("\n");
  if (pk)
    print_fingerprint (ctrl, NULL, pk, 2);
  if (with_subkeys)
    {
      for (node = keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
            {
              pk = node->pkt->pkt.public_key;
              tty_printf ("sub   %s/%s %s [%s]\n",
                          pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                          keystr_from_pk(pk),
                          datestr_from_pk (pk),
                          usagestr_from_pk (pk, 0));

              print_fingerprint (ctrl, NULL, pk, 4);
            }
        }
    }
}


/* Show a listing of the primary and its subkeys along with their
   keygrips.  */
static void
show_key_and_grip (kbnode_t keyblock)
{
  kbnode_t node;
  PKT_public_key *pk = NULL;
  char pkstrbuf[PUBKEY_STRING_SIZE];
  char *hexgrip;

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          pk = node->pkt->pkt.public_key;
          tty_printf ("%s   %s/%s %s [%s]\n",
                      node->pkt->pkttype == PKT_PUBLIC_KEY? "pub":"sub",
                      pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                      keystr_from_pk(pk),
                      datestr_from_pk (pk),
                      usagestr_from_pk (pk, 0));

          if (!hexkeygrip_from_pk (pk, &hexgrip))
            {
              tty_printf ("      Keygrip: %s\n", hexgrip);
              xfree (hexgrip);
            }
        }
    }
}


/* Show a warning if no uids on the key have the primary uid flag
   set. */
static void
no_primary_warning (KBNODE keyblock)
{
  KBNODE node;
  int have_primary = 0, uid_count = 0;

  /* TODO: if we ever start behaving differently with a primary or
     non-primary attribute ID, we will need to check for attributes
     here as well. */

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID
	  && node->pkt->pkt.user_id->attrib_data == NULL)
	{
	  uid_count++;

	  if (node->pkt->pkt.user_id->flags.primary == 2)
	    {
	      have_primary = 1;
	      break;
	    }
	}
    }

  if (uid_count > 1 && !have_primary)
    log_info (_
	      ("WARNING: no user ID has been marked as primary.  This command"
	       " may\n              cause a different user ID to become"
	       " the assumed primary.\n"));
}


/* Print a warning if the latest encryption subkey expires soon.  This
   function is called after the expire data of the primary key has
   been changed.  */
static void
subkey_expire_warning (kbnode_t keyblock)
{
  u32 curtime = make_timestamp ();
  kbnode_t node;
  PKT_public_key *pk;
  /* u32 mainexpire = 0; */
  u32 subexpire = 0;
  u32 latest_date = 0;

  for (node = keyblock; node; node = node->next)
    {
      /* if (node->pkt->pkttype == PKT_PUBLIC_KEY) */
      /*   { */
      /*     pk = node->pkt->pkt.public_key; */
      /*     mainexpire = pk->expiredate; */
      /*   } */

      if (node->pkt->pkttype != PKT_PUBLIC_SUBKEY)
        continue;
      pk = node->pkt->pkt.public_key;

      if (!pk->flags.valid)
        continue;
      if (pk->flags.revoked)
        continue;
      if (pk->timestamp > curtime)
        continue; /* Ignore future keys.  */
      if (!(pk->pubkey_usage & PUBKEY_USAGE_ENC))
        continue; /* Not an encryption key.  */

      if (pk->timestamp > latest_date || (!pk->timestamp && !latest_date))
        {
          latest_date = pk->timestamp;
          subexpire = pk->expiredate;
        }
    }

  if (!subexpire)
    return;  /* No valid subkey with an expiration time.  */

  if (curtime + (10*86400) > subexpire)
    {
      log_info (_("WARNING: Your encryption subkey expires soon.\n"));
      log_info (_("You may want to change its expiration date too.\n"));
    }
}


/*
 * Ask for a new user id, add the self-signature, and update the
 * keyblock.  If UIDSTRING is not NULL the user ID is generated
 * unattended using that string.  UIDSTRING is expected to be utf-8
 * encoded and white space trimmed.  Returns true if there is a new
 * user id.
 */
static int
menu_adduid (ctrl_t ctrl, kbnode_t pub_keyblock,
             int photo, const char *photo_name, const char *uidstring)
{
  PKT_user_id *uid;
  PKT_public_key *pk = NULL;
  PKT_signature *sig = NULL;
  PACKET *pkt;
  KBNODE node;
  KBNODE pub_where = NULL;
  gpg_error_t err;

  if (photo && uidstring)
    return 0;  /* Not allowed.  */

  for (node = pub_keyblock; node; pub_where = node, node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	pk = node->pkt->pkt.public_key;
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	break;
    }
  if (!node) /* No subkey.  */
    pub_where = NULL;
  log_assert (pk);

  if (photo)
    {
      int hasattrib = 0;

      for (node = pub_keyblock; node; node = node->next)
	if (node->pkt->pkttype == PKT_USER_ID &&
	    node->pkt->pkt.user_id->attrib_data != NULL)
	  {
	    hasattrib = 1;
	    break;
	  }

      /* It is legal but bad for compatibility to add a photo ID to a
         v3 key as it means that PGP2 will not be able to use that key
         anymore.  Also, PGP may not expect a photo on a v3 key.
         Don't bother to ask this if the key already has a photo - any
         damage has already been done at that point. -dms */
      if (pk->version == 3 && !hasattrib)
	{
	  if (opt.expert)
	    {
	      tty_printf (_("WARNING: This is a PGP2-style key.  "
			    "Adding a photo ID may cause some versions\n"
			    "         of PGP to reject this key.\n"));

	      if (!cpr_get_answer_is_yes ("keyedit.v3_photo.okay",
					  _("Are you sure you still want "
					    "to add it? (y/N) ")))
		return 0;
	    }
	  else
	    {
	      tty_printf (_("You may not add a photo ID to "
			    "a PGP2-style key.\n"));
	      return 0;
	    }
	}

      uid = generate_photo_id (ctrl, pk, photo_name);
    }
  else
    uid = generate_user_id (pub_keyblock, uidstring);
  if (!uid)
    {
      if (uidstring)
        {
          write_status_error ("adduid", gpg_error (304));
          log_error ("%s", _("Such a user ID already exists on this key!\n"));
        }
      return 0;
    }

  err = make_keysig_packet (ctrl, &sig, pk, uid, NULL, pk, 0x13, 0, 0, 0,
                            keygen_add_std_prefs, pk, NULL);
  if (err)
    {
      write_status_error ("keysig", err);
      log_error ("signing failed: %s\n", gpg_strerror (err));
      free_user_id (uid);
      return 0;
    }

  /* Insert/append to public keyblock */
  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_USER_ID;
  pkt->pkt.user_id = uid;
  node = new_kbnode (pkt);
  if (pub_where)
    insert_kbnode (pub_where, node, 0);
  else
    add_kbnode (pub_keyblock, node);
  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  if (pub_where)
    insert_kbnode (node, new_kbnode (pkt), 0);
  else
    add_kbnode (pub_keyblock, new_kbnode (pkt));
  return 1;
}


/*
 * Remove all selected userids from the keyring
 */
static void
menu_deluid (KBNODE pub_keyblock)
{
  KBNODE node;
  int selected = 0;

  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  selected = node->flag & NODFLG_SELUID;
	  if (selected)
	    {
	      /* Only cause a trust update if we delete a
	         non-revoked user id */
	      if (!node->pkt->pkt.user_id->flags.revoked)
		update_trust = 1;
	      delete_kbnode (node);
	    }
	}
      else if (selected && node->pkt->pkttype == PKT_SIGNATURE)
	delete_kbnode (node);
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	selected = 0;
    }
  commit_kbnode (&pub_keyblock);
}


static int
menu_delsig (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  KBNODE node;
  PKT_user_id *uid = NULL;
  int changed = 0;

  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  uid = (node->flag & NODFLG_SELUID) ? node->pkt->pkt.user_id : NULL;
	}
      else if (uid && node->pkt->pkttype == PKT_SIGNATURE)
	{
	  int okay, valid, selfsig, inv_sig, no_key, other_err;

	  tty_printf ("uid  ");
	  tty_print_utf8_string (uid->name, uid->len);
	  tty_printf ("\n");

	  okay = inv_sig = no_key = other_err = 0;
	  if (opt.with_colons)
	    valid = print_and_check_one_sig_colon (ctrl, pub_keyblock, node,
						   &inv_sig, &no_key,
						   &other_err, &selfsig, 1);
	  else
	    valid = print_and_check_one_sig (ctrl, pub_keyblock, node,
					     &inv_sig, &no_key, &other_err,
					     &selfsig, 1, 0);

	  if (valid)
	    {
	      okay = cpr_get_answer_yes_no_quit
                ("keyedit.delsig.valid",
                 _("Delete this good signature? (y/N/q)"));

	      /* Only update trust if we delete a good signature.
	         The other two cases do not affect trust. */
	      if (okay)
		update_trust = 1;
	    }
	  else if (inv_sig || other_err)
	    okay = cpr_get_answer_yes_no_quit
              ("keyedit.delsig.invalid",
               _("Delete this invalid signature? (y/N/q)"));
	  else if (no_key)
	    okay = cpr_get_answer_yes_no_quit
              ("keyedit.delsig.unknown",
               _("Delete this unknown signature? (y/N/q)"));

	  if (okay == -1)
	    break;
	  if (okay && selfsig
	      && !cpr_get_answer_is_yes
              ("keyedit.delsig.selfsig",
               _("Really delete this self-signature? (y/N)")))
	    okay = 0;
	  if (okay)
	    {
	      delete_kbnode (node);
	      changed++;
	    }

	}
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	uid = NULL;
    }

  if (changed)
    {
      commit_kbnode (&pub_keyblock);
      tty_printf (ngettext("Deleted %d signature.\n",
                           "Deleted %d signatures.\n", changed), changed);
    }
  else
    tty_printf (_("Nothing deleted.\n"));

  return changed;
}


static int
menu_clean (ctrl_t ctrl, kbnode_t keyblock, int self_only)
{
  KBNODE uidnode;
  int modified = 0, select_all = !count_selected_uids (keyblock);

  for (uidnode = keyblock->next;
       uidnode && uidnode->pkt->pkttype != PKT_PUBLIC_SUBKEY;
       uidnode = uidnode->next)
    {
      if (uidnode->pkt->pkttype == PKT_USER_ID
	  && (uidnode->flag & NODFLG_SELUID || select_all))
	{
	  int uids = 0, sigs = 0;
	  char *user = utf8_to_native (uidnode->pkt->pkt.user_id->name,
				       uidnode->pkt->pkt.user_id->len,
				       0);

	  clean_one_uid (ctrl, keyblock, uidnode, opt.verbose, self_only, &uids,
			 &sigs);
	  if (uids)
	    {
	      const char *reason;

	      if (uidnode->pkt->pkt.user_id->flags.revoked)
		reason = _("revoked");
	      else if (uidnode->pkt->pkt.user_id->flags.expired)
		reason = _("expired");
	      else
		reason = _("invalid");

	      tty_printf (_("User ID \"%s\" compacted: %s\n"), user, reason);

	      modified = 1;
	    }
	  else if (sigs)
	    {
	      tty_printf (ngettext("User ID \"%s\": %d signature removed\n",
                                   "User ID \"%s\": %d signatures removed\n",
                                   sigs), user, sigs);
	      modified = 1;
	    }
	  else
	    {
	      tty_printf (self_only == 1 ?
			  _("User ID \"%s\": already minimized\n") :
			  _("User ID \"%s\": already clean\n"), user);
	    }

	  xfree (user);
	}
    }

  return modified;
}


/*
 * Remove some of the secondary keys
 */
static void
menu_delkey (KBNODE pub_keyblock)
{
  KBNODE node;
  int selected = 0;

  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  selected = node->flag & NODFLG_SELKEY;
	  if (selected)
            delete_kbnode (node);
	}
      else if (selected && node->pkt->pkttype == PKT_SIGNATURE)
	delete_kbnode (node);
      else
	selected = 0;
    }
  commit_kbnode (&pub_keyblock);

  /* No need to set update_trust here since signing keys are no
     longer used to certify other keys, so there is no change in
     trust when revoking/removing them.   */
}


/*
 * Ask for a new revoker, create the self-signature and put it into
 * the keyblock.  Returns true if there is a new revoker.
 */
static int
menu_addrevoker (ctrl_t ctrl, kbnode_t pub_keyblock, int sensitive)
{
  PKT_public_key *pk = NULL;
  PKT_public_key *revoker_pk = NULL;
  PKT_signature *sig = NULL;
  PACKET *pkt;
  struct revocation_key revkey;
  size_t fprlen;
  int rc;

  log_assert (pub_keyblock->pkt->pkttype == PKT_PUBLIC_KEY);

  pk = pub_keyblock->pkt->pkt.public_key;

  if (pk->numrevkeys == 0 && pk->version == 3)
    {
      /* It is legal but bad for compatibility to add a revoker to a
         v3 key as it means that PGP2 will not be able to use that key
         anymore.  Also, PGP may not expect a revoker on a v3 key.
         Don't bother to ask this if the key already has a revoker -
         any damage has already been done at that point. -dms */
      if (opt.expert)
	{
	  tty_printf (_("WARNING: This is a PGP 2.x-style key.  "
			"Adding a designated revoker may cause\n"
			"         some versions of PGP to reject this key.\n"));

	  if (!cpr_get_answer_is_yes ("keyedit.v3_revoker.okay",
				      _("Are you sure you still want "
					"to add it? (y/N) ")))
	    return 0;
	}
      else
	{
	  tty_printf (_("You may not add a designated revoker to "
			"a PGP 2.x-style key.\n"));
	  return 0;
	}
    }

  for (;;)
    {
      char *answer;

      free_public_key (revoker_pk);
      revoker_pk = xmalloc_clear (sizeof (*revoker_pk));

      tty_printf ("\n");

      answer = cpr_get_utf8
        ("keyedit.add_revoker",
         _("Enter the user ID of the designated revoker: "));
      if (answer[0] == '\0' || answer[0] == CONTROL_D)
	{
	  xfree (answer);
	  goto fail;
	}

      /* Note that I'm requesting CERT here, which usually implies
         primary keys only, but some casual testing shows that PGP and
         GnuPG both can handle a designated revocation from a subkey. */
      revoker_pk->req_usage = PUBKEY_USAGE_CERT;
      rc = get_pubkey_byname (ctrl, GET_PUBKEY_NO_AKL,
                              NULL, revoker_pk, answer, NULL, NULL, 1);
      if (rc)
	{
	  log_error (_("key \"%s\" not found: %s\n"), answer,
		     gpg_strerror (rc));
	  xfree (answer);
	  continue;
	}

      xfree (answer);

      fingerprint_from_pk (revoker_pk, revkey.fpr, &fprlen);
      if (fprlen != 20)
	{
	  log_error (_("cannot appoint a PGP 2.x style key as a "
		       "designated revoker\n"));
	  continue;
	}

      revkey.class = 0x80;
      if (sensitive)
	revkey.class |= 0x40;
      revkey.algid = revoker_pk->pubkey_algo;

      if (cmp_public_keys (revoker_pk, pk) == 0)
	{
	  /* This actually causes no harm (after all, a key that
	     designates itself as a revoker is the same as a
	     regular key), but it's easy enough to check. */
	  log_error (_("you cannot appoint a key as its own "
		       "designated revoker\n"));

	  continue;
	}

      keyid_from_pk (pk, NULL);

      /* Does this revkey already exist? */
      if (!pk->revkey && pk->numrevkeys)
	BUG ();
      else
	{
	  int i;

	  for (i = 0; i < pk->numrevkeys; i++)
	    {
	      if (memcmp (&pk->revkey[i], &revkey,
			  sizeof (struct revocation_key)) == 0)
		{
		  char buf[50];

		  log_error (_("this key has already been designated "
			       "as a revoker\n"));

                  format_keyid (pk_keyid (pk), KF_LONG, buf, sizeof (buf));
		  write_status_text (STATUS_ALREADY_SIGNED, buf);

		  break;
		}
	    }

	  if (i < pk->numrevkeys)
	    continue;
	}

      print_pubkey_info (ctrl, NULL, revoker_pk);
      print_fingerprint (ctrl, NULL, revoker_pk, 2);
      tty_printf ("\n");

      tty_printf (_("WARNING: appointing a key as a designated revoker "
		    "cannot be undone!\n"));

      tty_printf ("\n");

      if (!cpr_get_answer_is_yes ("keyedit.add_revoker.okay",
				  _("Are you sure you want to appoint this "
				    "key as a designated revoker? (y/N) ")))
	continue;

      free_public_key (revoker_pk);
      revoker_pk = NULL;
      break;
    }

  rc = make_keysig_packet (ctrl, &sig, pk, NULL, NULL, pk, 0x1F, 0, 0, 0,
			   keygen_add_revkey, &revkey, NULL);
  if (rc)
    {
      write_status_error ("keysig", rc);
      log_error ("signing failed: %s\n", gpg_strerror (rc));
      goto fail;
    }

  /* Insert into public keyblock.  */
  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  insert_kbnode (pub_keyblock, new_kbnode (pkt), PKT_SIGNATURE);

  return 1;

fail:
  if (sig)
    free_seckey_enc (sig);
  free_public_key (revoker_pk);

  return 0;
}


/* With FORCE_MAINKEY cleared this function handles the interactive
 * menu option "expire".  With UNATTENDED set to 1 this function only
 * sets the expiration date of the primary key to NEWEXPIRATION and
 * avoid all interactivity; with a value of 2 only the flagged subkeys
 * are set to NEWEXPIRATION.  Returns 0 if nothing was done,
 * GPG_ERR_TRUE if the key was modified, or any other error code. */
static gpg_error_t
menu_expire (ctrl_t ctrl, kbnode_t pub_keyblock,
             int unattended, u32 newexpiration)
{
  int signumber, rc;
  u32 expiredate;
  int only_mainkey;  /* Set if only the mainkey is to be updated.  */
  PKT_public_key *main_pk, *sub_pk;
  PKT_user_id *uid;
  kbnode_t node;
  u32 keyid[2];

  if (unattended)
    {
      only_mainkey = (unattended == 1);
      expiredate = newexpiration;
    }
  else
    {
      int n1;

      only_mainkey = 0;
      n1 = count_selected_keys (pub_keyblock);
      if (n1 > 1)
        {
          if (!cpr_get_answer_is_yes
              ("keyedit.expire_multiple_subkeys.okay",
               _("Are you sure you want to change the"
                 " expiration time for multiple subkeys? (y/N) ")))
            return gpg_error (GPG_ERR_CANCELED);;
        }
      else if (n1)
        tty_printf (_("Changing expiration time for a subkey.\n"));
      else
        {
          tty_printf (_("Changing expiration time for the primary key.\n"));
          only_mainkey = 1;
          no_primary_warning (pub_keyblock);
        }

      expiredate = ask_expiredate ();
    }


  /* Now we can actually change the self-signature(s) */
  main_pk = sub_pk = NULL;
  uid = NULL;
  signumber = 0;
  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk (main_pk, keyid);
	  main_pk->expiredate = expiredate;
	}
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
          if ((node->flag & NODFLG_SELKEY) && unattended != 1)
            {
              /* The flag is set and we do not want to set the
               * expiration date only for the main key.  */
              sub_pk = node->pkt->pkt.public_key;
              sub_pk->expiredate = expiredate;
            }
          else
            sub_pk = NULL;
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	uid = node->pkt->pkt.user_id;
      else if (main_pk && node->pkt->pkttype == PKT_SIGNATURE
	       && (only_mainkey || sub_pk))
	{
	  PKT_signature *sig = node->pkt->pkt.signature;

	  if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	      && ((only_mainkey && uid
		   && uid->created && (sig->sig_class & ~3) == 0x10)
		  || (!only_mainkey && sig->sig_class == 0x18))
	      && sig->flags.chosen_selfsig)
	    {
	      /* This is a self-signature which is to be replaced.  */
	      PKT_signature *newsig;
	      PACKET *newpkt;

	      signumber++;

	      if ((only_mainkey && main_pk->version < 4)
		  || (!only_mainkey && sub_pk->version < 4))
		{
		  log_info
                    (_("You can't change the expiration date of a v3 key\n"));
		  return gpg_error (GPG_ERR_LEGACY_KEY);
		}

	      if (only_mainkey)
		rc = update_keysig_packet (ctrl,
                                           &newsig, sig, main_pk, uid, NULL,
					   main_pk, keygen_add_key_expire,
					   main_pk);
	      else
		rc =
		  update_keysig_packet (ctrl,
                                        &newsig, sig, main_pk, NULL, sub_pk,
					main_pk, keygen_add_key_expire, sub_pk);
	      if (rc)
		{
		  log_error ("make_keysig_packet failed: %s\n",
			     gpg_strerror (rc));
                  if (gpg_err_code (rc) == GPG_ERR_TRUE)
                    rc = GPG_ERR_GENERAL;
		  return rc;
		}

	      /* Replace the packet.  */
	      newpkt = xmalloc_clear (sizeof *newpkt);
	      newpkt->pkttype = PKT_SIGNATURE;
	      newpkt->pkt.signature = newsig;
	      free_packet (node->pkt, NULL);
	      xfree (node->pkt);
	      node->pkt = newpkt;
	      sub_pk = NULL;
	    }
	}
    }

  update_trust = 1;
  return gpg_error (GPG_ERR_TRUE);
}


/* Change the capability of a selected key.  This command should only
 * be used to rectify badly created keys and as such is not suggested
 * for general use.  */
static int
menu_changeusage (ctrl_t ctrl, kbnode_t keyblock)
{
  int n1, rc;
  int mainkey = 0;
  PKT_public_key *main_pk, *sub_pk;
  PKT_user_id *uid;
  kbnode_t node;
  u32 keyid[2];

  n1 = count_selected_keys (keyblock);
  if (n1 > 1)
    {
      tty_printf (_("You must select exactly one key.\n"));
      return 0;
    }
  else if (n1)
    tty_printf (_("Changing usage of a subkey.\n"));
  else
    {
      tty_printf (_("Changing usage of the primary key.\n"));
      mainkey = 1;
    }

  /* Now we can actually change the self-signature(s) */
  main_pk = sub_pk = NULL;
  uid = NULL;
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk (main_pk, keyid);
	}
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
          if (node->flag & NODFLG_SELKEY)
            sub_pk = node->pkt->pkt.public_key;
          else
            sub_pk = NULL;
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	uid = node->pkt->pkt.user_id;
      else if (main_pk && node->pkt->pkttype == PKT_SIGNATURE
	       && (mainkey || sub_pk))
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	      && ((mainkey && uid
		   && uid->created && (sig->sig_class & ~3) == 0x10)
		  || (!mainkey && sig->sig_class == 0x18))
	      && sig->flags.chosen_selfsig)
	    {
	      /* This is the self-signature which is to be replaced.  */
	      PKT_signature *newsig;
	      PACKET *newpkt;

	      if ((mainkey && main_pk->version < 4)
		  || (!mainkey && sub_pk->version < 4))
		{
                  /* Note: This won't happen because we don't support
                   * v3 keys anymore.  */
		  log_info ("You can't change the capabilities of a v3 key\n");
		  return 0;
		}

              if (mainkey)
                main_pk->pubkey_usage = ask_key_flags (main_pk->pubkey_algo, 0,
                                                       main_pk->pubkey_usage);
              else
                sub_pk->pubkey_usage  = ask_key_flags (sub_pk->pubkey_algo, 1,
                                                       sub_pk->pubkey_usage);

	      if (mainkey)
		rc = update_keysig_packet (ctrl,
                                           &newsig, sig, main_pk, uid, NULL,
					   main_pk, keygen_add_key_flags,
					   main_pk);
	      else
		rc =
		  update_keysig_packet (ctrl,
                                        &newsig, sig, main_pk, NULL, sub_pk,
					main_pk, keygen_add_key_flags, sub_pk);
	      if (rc)
		{
		  log_error ("make_keysig_packet failed: %s\n",
                             gpg_strerror (rc));
		  return 0;
		}

	      /* Replace the packet.  */
	      newpkt = xmalloc_clear (sizeof *newpkt);
	      newpkt->pkttype = PKT_SIGNATURE;
	      newpkt->pkt.signature = newsig;
	      free_packet (node->pkt, NULL);
	      xfree (node->pkt);
	      node->pkt = newpkt;
	      sub_pk = NULL;
              break;
	    }
	}
    }

  return 1;
}


static int
menu_backsign (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  int rc, modified = 0;
  PKT_public_key *main_pk;
  KBNODE node;
  u32 timestamp;

  log_assert (pub_keyblock->pkt->pkttype == PKT_PUBLIC_KEY);

  merge_keys_and_selfsig (ctrl, pub_keyblock);
  main_pk = pub_keyblock->pkt->pkt.public_key;
  keyid_from_pk (main_pk, NULL);

  /* We use the same timestamp for all backsigs so that we don't
     reveal information about the used machine.  */
  timestamp = make_timestamp ();

  for (node = pub_keyblock; node; node = node->next)
    {
      PKT_public_key *sub_pk = NULL;
      KBNODE node2, sig_pk = NULL /*,sig_sk = NULL*/;
      /* char *passphrase; */

      /* Find a signing subkey with no backsig */
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  if (node->pkt->pkt.public_key->pubkey_usage & PUBKEY_USAGE_SIG)
	    {
	      if (node->pkt->pkt.public_key->flags.backsig)
		tty_printf (_
			    ("signing subkey %s is already cross-certified\n"),
			    keystr_from_pk (node->pkt->pkt.public_key));
	      else
		sub_pk = node->pkt->pkt.public_key;
	    }
	  else
	    tty_printf (_("subkey %s does not sign and so does"
			  " not need to be cross-certified\n"),
			keystr_from_pk (node->pkt->pkt.public_key));
	}

      if (!sub_pk)
	continue;

      /* Find the selected selfsig on this subkey */
      for (node2 = node->next;
	   node2 && node2->pkt->pkttype == PKT_SIGNATURE; node2 = node2->next)
	if (node2->pkt->pkt.signature->version >= 4
	    && node2->pkt->pkt.signature->flags.chosen_selfsig)
	  {
	    sig_pk = node2;
	    break;
	  }

      if (!sig_pk)
	continue;

      /* Find the secret subkey that matches the public subkey */
      log_debug ("FIXME: Check whether a secret subkey is available.\n");
      /* if (!sub_sk) */
      /*   { */
      /*     tty_printf (_("no secret subkey for public subkey %s - ignoring\n"), */
      /*   	      keystr_from_pk (sub_pk)); */
      /*     continue; */
      /*   } */


      /* Now we can get to work.  */

      rc = make_backsig (ctrl,
                         sig_pk->pkt->pkt.signature, main_pk, sub_pk, sub_pk,
			 timestamp, NULL);
      if (!rc)
	{
	  PKT_signature *newsig;
	  PACKET *newpkt;

	  rc = update_keysig_packet (ctrl,
                                     &newsig, sig_pk->pkt->pkt.signature,
                                     main_pk, NULL, sub_pk, main_pk,
                                     NULL, NULL);
	  if (!rc)
	    {
	      /* Put the new sig into place on the pubkey */
	      newpkt = xmalloc_clear (sizeof (*newpkt));
	      newpkt->pkttype = PKT_SIGNATURE;
	      newpkt->pkt.signature = newsig;
	      free_packet (sig_pk->pkt, NULL);
	      xfree (sig_pk->pkt);
	      sig_pk->pkt = newpkt;

	      modified = 1;
	    }
	  else
	    {
	      log_error ("update_keysig_packet failed: %s\n",
			 gpg_strerror (rc));
	      break;
	    }
	}
      else
	{
	  log_error ("make_backsig failed: %s\n", gpg_strerror (rc));
	  break;
	}
    }

  return modified;
}


static int
change_primary_uid_cb (PKT_signature * sig, void *opaque)
{
  byte buf[1];

  /* first clear all primary uid flags so that we are sure none are
   * lingering around */
  delete_sig_subpkt (sig->hashed, SIGSUBPKT_PRIMARY_UID);
  delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PRIMARY_UID);

  /* if opaque is set,we want to set the primary id */
  if (opaque)
    {
      buf[0] = 1;
      build_sig_subpkt (sig, SIGSUBPKT_PRIMARY_UID, buf, 1);
    }

  return 0;
}


/*
 * Set the primary uid flag for the selected UID.  We will also reset
 * all other primary uid flags.  For this to work we have to update
 * all the signature timestamps.  If we would do this with the current
 * time, we lose quite a lot of information, so we use a kludge to
 * do this: Just increment the timestamp by one second which is
 * sufficient to updated a signature during import.
 */
static int
menu_set_primary_uid (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  PKT_public_key *main_pk;
  PKT_user_id *uid;
  KBNODE node;
  u32 keyid[2];
  int selected;
  int attribute = 0;
  int modified = 0;

  if (count_selected_uids (pub_keyblock) != 1)
    {
      tty_printf (_("Please select exactly one user ID.\n"));
      return 0;
    }

  main_pk = NULL;
  uid = NULL;
  selected = 0;

  /* Is our selected uid an attribute packet? */
  for (node = pub_keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_USER_ID && node->flag & NODFLG_SELUID)
      attribute = (node->pkt->pkt.user_id->attrib_data != NULL);

  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	break; /* No more user ids expected - ready.  */

      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk (main_pk, keyid);
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
	  uid = node->pkt->pkt.user_id;
	  selected = node->flag & NODFLG_SELUID;
	}
      else if (main_pk && uid && node->pkt->pkttype == PKT_SIGNATURE)
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	      && (uid && (sig->sig_class & ~3) == 0x10)
	      && attribute == (uid->attrib_data != NULL)
	      && sig->flags.chosen_selfsig)
	    {
	      if (sig->version < 4)
		{
		  char *user =
		    utf8_to_native (uid->name, strlen (uid->name), 0);

		  log_info (_("skipping v3 self-signature on user ID \"%s\"\n"),
                            user);
		  xfree (user);
		}
	      else
		{
		  /* This is a selfsignature which is to be replaced.
		     We can just ignore v3 signatures because they are
		     not able to carry the primary ID flag.  We also
		     ignore self-sigs on user IDs that are not of the
		     same type that we are making primary.  That is, if
		     we are making a user ID primary, we alter user IDs.
		     If we are making an attribute packet primary, we
		     alter attribute packets. */

		  /* FIXME: We must make sure that we only have one
		     self-signature per user ID here (not counting
		     revocations) */
		  PKT_signature *newsig;
		  PACKET *newpkt;
		  const byte *p;
		  int action;

		  /* See whether this signature has the primary UID flag.  */
		  p = parse_sig_subpkt (sig->hashed,
					SIGSUBPKT_PRIMARY_UID, NULL);
		  if (!p)
		    p = parse_sig_subpkt (sig->unhashed,
					  SIGSUBPKT_PRIMARY_UID, NULL);
		  if (p && *p)	/* yes */
		    action = selected ? 0 : -1;
		  else		/* no */
		    action = selected ? 1 : 0;

		  if (action)
		    {
		      int rc = update_keysig_packet (ctrl, &newsig, sig,
						     main_pk, uid, NULL,
						     main_pk,
						     change_primary_uid_cb,
						     action > 0 ? "x" : NULL);
		      if (rc)
			{
			  log_error ("update_keysig_packet failed: %s\n",
				     gpg_strerror (rc));
			  return 0;
			}
		      /* replace the packet */
		      newpkt = xmalloc_clear (sizeof *newpkt);
		      newpkt->pkttype = PKT_SIGNATURE;
		      newpkt->pkt.signature = newsig;
		      free_packet (node->pkt, NULL);
		      xfree (node->pkt);
		      node->pkt = newpkt;
		      modified = 1;
		    }
		}
	    }
	}
    }

  return modified;
}


/*
 * Set preferences to new values for the selected user IDs
 */
static int
menu_set_preferences (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  PKT_public_key *main_pk;
  PKT_user_id *uid;
  KBNODE node;
  u32 keyid[2];
  int selected, select_all;
  int modified = 0;

  no_primary_warning (pub_keyblock);

  select_all = !count_selected_uids (pub_keyblock);

  /* Now we can actually change the self signature(s) */
  main_pk = NULL;
  uid = NULL;
  selected = 0;
  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	break; /* No more user-ids expected - ready.  */

      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk (main_pk, keyid);
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
	  uid = node->pkt->pkt.user_id;
	  selected = select_all || (node->flag & NODFLG_SELUID);
	}
      else if (main_pk && uid && selected
	       && node->pkt->pkttype == PKT_SIGNATURE)
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	      && (uid && (sig->sig_class & ~3) == 0x10)
	      && sig->flags.chosen_selfsig)
	    {
	      if (sig->version < 4)
		{
		  char *user =
		    utf8_to_native (uid->name, strlen (uid->name), 0);

		  log_info (_("skipping v3 self-signature on user ID \"%s\"\n"),
			    user);
		  xfree (user);
		}
	      else
		{
		  /* This is a selfsignature which is to be replaced
		   * We have to ignore v3 signatures because they are
		   * not able to carry the preferences.  */
		  PKT_signature *newsig;
		  PACKET *newpkt;
		  int rc;

		  rc = update_keysig_packet (ctrl, &newsig, sig,
					     main_pk, uid, NULL, main_pk,
                                             keygen_upd_std_prefs, NULL);
		  if (rc)
		    {
		      log_error ("update_keysig_packet failed: %s\n",
				 gpg_strerror (rc));
		      return 0;
		    }
		  /* replace the packet */
		  newpkt = xmalloc_clear (sizeof *newpkt);
		  newpkt->pkttype = PKT_SIGNATURE;
		  newpkt->pkt.signature = newsig;
		  free_packet (node->pkt, NULL);
		  xfree (node->pkt);
		  node->pkt = newpkt;
		  modified = 1;
		}
	    }
	}
    }

  return modified;
}


static int
menu_set_keyserver_url (ctrl_t ctrl, const char *url, kbnode_t pub_keyblock)
{
  PKT_public_key *main_pk;
  PKT_user_id *uid;
  KBNODE node;
  u32 keyid[2];
  int selected, select_all;
  int modified = 0;
  char *answer, *uri;

  no_primary_warning (pub_keyblock);

  if (url)
    answer = xstrdup (url);
  else
    {
      answer = cpr_get_utf8 ("keyedit.add_keyserver",
			     _("Enter your preferred keyserver URL: "));
      if (answer[0] == '\0' || answer[0] == CONTROL_D)
	{
	  xfree (answer);
	  return 0;
	}
    }

  if (ascii_strcasecmp (answer, "none") == 0)
    uri = NULL;
  else
    {
      struct keyserver_spec *keyserver = NULL;
      /* Sanity check the format */
      keyserver = parse_keyserver_uri (answer, 1);
      xfree (answer);
      if (!keyserver)
	{
	  log_info (_("could not parse keyserver URL\n"));
	  return 0;
	}
      uri = xstrdup (keyserver->uri);
      free_keyserver_spec (keyserver);
    }

  select_all = !count_selected_uids (pub_keyblock);

  /* Now we can actually change the self signature(s) */
  main_pk = NULL;
  uid = NULL;
  selected = 0;
  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	break; /* ready */

      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk (main_pk, keyid);
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
	  uid = node->pkt->pkt.user_id;
	  selected = select_all || (node->flag & NODFLG_SELUID);
	}
      else if (main_pk && uid && selected
	       && node->pkt->pkttype == PKT_SIGNATURE)
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	      && (uid && (sig->sig_class & ~3) == 0x10)
	      && sig->flags.chosen_selfsig)
	    {
	      char *user = utf8_to_native (uid->name, strlen (uid->name), 0);
	      if (sig->version < 4)
		log_info (_("skipping v3 self-signature on user ID \"%s\"\n"),
			  user);
	      else
		{
		  /* This is a selfsignature which is to be replaced
		   * We have to ignore v3 signatures because they are
		   * not able to carry the subpacket. */
		  PKT_signature *newsig;
		  PACKET *newpkt;
		  int rc;
		  const byte *p;
		  size_t plen;

		  p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_KS, &plen);
		  if (p && plen)
		    {
		      tty_printf ("Current preferred keyserver for user"
				  " ID \"%s\": ", user);
		      tty_print_utf8_string (p, plen);
		      tty_printf ("\n");
		      if (!cpr_get_answer_is_yes
                          ("keyedit.confirm_keyserver",
                           uri
                           ? _("Are you sure you want to replace it? (y/N) ")
                           : _("Are you sure you want to delete it? (y/N) ")))
			continue;
		    }
		  else if (uri == NULL)
		    {
		      /* There is no current keyserver URL, so there
		         is no point in trying to un-set it. */
		      continue;
		    }

		  rc = update_keysig_packet (ctrl, &newsig, sig,
					     main_pk, uid, NULL,
					     main_pk,
					     keygen_add_keyserver_url, uri);
		  if (rc)
		    {
		      log_error ("update_keysig_packet failed: %s\n",
				 gpg_strerror (rc));
		      xfree (uri);
		      return 0;
		    }
		  /* replace the packet */
		  newpkt = xmalloc_clear (sizeof *newpkt);
		  newpkt->pkttype = PKT_SIGNATURE;
		  newpkt->pkt.signature = newsig;
		  free_packet (node->pkt, NULL);
		  xfree (node->pkt);
		  node->pkt = newpkt;
		  modified = 1;
		}

	      xfree (user);
	    }
	}
    }

  xfree (uri);
  return modified;
}


static int
menu_set_notation (ctrl_t ctrl, const char *string, KBNODE pub_keyblock)
{
  PKT_public_key *main_pk;
  PKT_user_id *uid;
  KBNODE node;
  u32 keyid[2];
  int selected, select_all;
  int modified = 0;
  char *answer;
  struct notation *notation;

  no_primary_warning (pub_keyblock);

  if (string)
    answer = xstrdup (string);
  else
    {
      answer = cpr_get_utf8 ("keyedit.add_notation",
			     _("Enter the notation: "));
      if (answer[0] == '\0' || answer[0] == CONTROL_D)
	{
	  xfree (answer);
	  return 0;
	}
    }

  if (!ascii_strcasecmp (answer, "none")
      || !ascii_strcasecmp (answer, "-"))
    notation = NULL; /* Delete them all.  */
  else
    {
      notation = string_to_notation (answer, 0);
      if (!notation)
	{
	  xfree (answer);
	  return 0;
	}
    }

  xfree (answer);

  select_all = !count_selected_uids (pub_keyblock);

  /* Now we can actually change the self signature(s) */
  main_pk = NULL;
  uid = NULL;
  selected = 0;
  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	break; /* ready */

      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk (main_pk, keyid);
	}
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
	  uid = node->pkt->pkt.user_id;
	  selected = select_all || (node->flag & NODFLG_SELUID);
	}
      else if (main_pk && uid && selected
	       && node->pkt->pkttype == PKT_SIGNATURE)
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if (keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	      && (uid && (sig->sig_class & ~3) == 0x10)
	      && sig->flags.chosen_selfsig)
	    {
	      char *user = utf8_to_native (uid->name, strlen (uid->name), 0);
	      if (sig->version < 4)
		log_info (_("skipping v3 self-signature on user ID \"%s\"\n"),
			  user);
	      else
		{
		  PKT_signature *newsig;
		  PACKET *newpkt;
		  int rc, skip = 0, addonly = 1;

		  if (sig->flags.notation)
		    {
		      tty_printf ("Current notations for user ID \"%s\":\n",
				  user);
		      tty_print_notations (-9, sig);
		    }
		  else
		    {
		      tty_printf ("No notations on user ID \"%s\"\n", user);
		      if (notation == NULL)
			{
			  /* There are no current notations, so there
			     is no point in trying to un-set them. */
			  continue;
			}
		    }

		  if (notation)
		    {
		      struct notation *n;
		      int deleting = 0;

		      notation->next = sig_to_notation (sig);

		      for (n = notation->next; n; n = n->next)
			if (strcmp (n->name, notation->name) == 0)
			  {
			    if (notation->value)
			      {
				if (strcmp (n->value, notation->value) == 0)
				  {
				    if (notation->flags.ignore)
				      {
					/* Value match with a delete
					   flag. */
					n->flags.ignore = 1;
					deleting = 1;
				      }
				    else
				      {
					/* Adding the same notation
					   twice, so don't add it at
					   all. */
					skip = 1;
					tty_printf ("Skipping notation:"
						    " %s=%s\n",
						    notation->name,
						    notation->value);
					break;
				      }
				  }
			      }
			    else
			      {
				/* No value, so it means delete. */
				n->flags.ignore = 1;
				deleting = 1;
			      }

			    if (n->flags.ignore)
			      {
				tty_printf ("Removing notation: %s=%s\n",
					    n->name, n->value);
				addonly = 0;
			      }
			  }

		      if (!notation->flags.ignore && !skip)
			tty_printf ("Adding notation: %s=%s\n",
				    notation->name, notation->value);

		      /* We tried to delete, but had no matches.  */
		      if (notation->flags.ignore && !deleting)
			continue;
		    }
		  else
		    {
		      tty_printf ("Removing all notations\n");
		      addonly = 0;
		    }

		  if (skip
		      || (!addonly
			  &&
			  !cpr_get_answer_is_yes ("keyedit.confirm_notation",
						  _("Proceed? (y/N) "))))
		    continue;

		  rc = update_keysig_packet (ctrl, &newsig, sig,
					     main_pk, uid, NULL,
					     main_pk,
					     keygen_add_notations, notation);
		  if (rc)
		    {
		      log_error ("update_keysig_packet failed: %s\n",
				 gpg_strerror (rc));
		      free_notation (notation);
		      xfree (user);
		      return 0;
		    }

		  /* replace the packet */
		  newpkt = xmalloc_clear (sizeof *newpkt);
		  newpkt->pkttype = PKT_SIGNATURE;
		  newpkt->pkt.signature = newsig;
		  free_packet (node->pkt, NULL);
		  xfree (node->pkt);
		  node->pkt = newpkt;
		  modified = 1;

		  if (notation)
		    {
		      /* Snip off the notation list from the sig */
		      free_notation (notation->next);
		      notation->next = NULL;
		    }

		  xfree (user);
		}
	    }
	}
    }

  free_notation (notation);
  return modified;
}


/*
 * Select one user id or remove all selection if IDX is 0 or select
 * all if IDX is -1.  Returns: True if the selection changed.
 */
static int
menu_select_uid (KBNODE keyblock, int idx)
{
  KBNODE node;
  int i;

  if (idx == -1)		/* Select all. */
    {
      for (node = keyblock; node; node = node->next)
	if (node->pkt->pkttype == PKT_USER_ID)
	  node->flag |= NODFLG_SELUID;
      return 1;
    }
  else if (idx)			/* Toggle.  */
    {
      for (i = 0, node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_USER_ID)
	    if (++i == idx)
	      break;
	}
      if (!node)
	{
	  tty_printf (_("No user ID with index %d\n"), idx);
	  return 0;
	}

      for (i = 0, node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_USER_ID)
	    {
	      if (++i == idx)
		{
		  if ((node->flag & NODFLG_SELUID))
		    node->flag &= ~NODFLG_SELUID;
		  else
		    node->flag |= NODFLG_SELUID;
		}
	    }
	}
    }
  else				/* Unselect all */
    {
      for (node = keyblock; node; node = node->next)
	if (node->pkt->pkttype == PKT_USER_ID)
	  node->flag &= ~NODFLG_SELUID;
    }

  return 1;
}


/* Search in the keyblock for a uid that matches namehash */
static int
menu_select_uid_namehash (KBNODE keyblock, const char *namehash)
{
  byte hash[NAMEHASH_LEN];
  KBNODE node;
  int i;

  log_assert (strlen (namehash) == NAMEHASH_LEN * 2);

  for (i = 0; i < NAMEHASH_LEN; i++)
    hash[i] = hextobyte (&namehash[i * 2]);

  for (node = keyblock->next; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  namehash_from_uid (node->pkt->pkt.user_id);
	  if (memcmp (node->pkt->pkt.user_id->namehash, hash, NAMEHASH_LEN) ==
	      0)
	    {
	      if (node->flag & NODFLG_SELUID)
		node->flag &= ~NODFLG_SELUID;
	      else
		node->flag |= NODFLG_SELUID;

	      break;
	    }
	}
    }

  if (!node)
    {
      tty_printf (_("No user ID with hash %s\n"), namehash);
      return 0;
    }

  return 1;
}


/*
 * Select secondary keys
 * Returns: True if the selection changed.
 */
static int
menu_select_key (KBNODE keyblock, int idx, char *p)
{
  KBNODE node;
  int i, j;
  int is_hex_digits;

  is_hex_digits = p && strlen (p) >= 8;
  if (is_hex_digits)
    {
      /* Skip initial spaces.  */
      while (spacep (p))
        p ++;
      /* If the id starts with 0x accept and ignore it.  */
      if (p[0] == '0' && p[1] == 'x')
        p += 2;

      for (i = 0, j = 0; p[i]; i ++)
        if (hexdigitp (&p[i]))
          {
            p[j] = toupper (p[i]);
            j ++;
          }
        else if (spacep (&p[i]))
          /* Skip spaces.  */
          {
          }
        else
          {
            is_hex_digits = 0;
            break;
          }
      if (is_hex_digits)
        /* In case we skipped some spaces, add a new NUL terminator.  */
        {
          p[j] = 0;
          /* If we skipped some spaces, make sure that we still have
             at least 8 characters.  */
          is_hex_digits = (/* Short keyid.  */
                           strlen (p) == 8
                           /* Long keyid.  */
                           || strlen (p) == 16
                           /* Fingerprints are (currently) 32 or 40
                              characters.  */
                           || strlen (p) >= 32);
        }
    }

  if (is_hex_digits)
    {
      int found_one = 0;
      for (node = keyblock; node; node = node->next)
	if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || node->pkt->pkttype == PKT_SECRET_SUBKEY)
          {
            int match = 0;
            if (strlen (p) == 8 || strlen (p) == 16)
              {
                u32 kid[2];
                char kid_str[17];
                keyid_from_pk (node->pkt->pkt.public_key, kid);
                format_keyid (kid, strlen (p) == 8 ? KF_SHORT : KF_LONG,
                              kid_str, sizeof (kid_str));

                if (strcmp (p, kid_str) == 0)
                  match = 1;
              }
            else
              {
                char fp[2*MAX_FINGERPRINT_LEN + 1];
                hexfingerprint (node->pkt->pkt.public_key, fp, sizeof (fp));
                if (strcmp (fp, p) == 0)
                  match = 1;
              }

            if (match)
              {
                if ((node->flag & NODFLG_SELKEY))
                  node->flag &= ~NODFLG_SELKEY;
                else
                  node->flag |= NODFLG_SELKEY;

                found_one = 1;
              }
          }

      if (found_one)
        return 1;

      tty_printf (_("No subkey with key ID '%s'.\n"), p);
      return 0;
    }

  if (idx == -1)		/* Select all.  */
    {
      for (node = keyblock; node; node = node->next)
	if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || node->pkt->pkttype == PKT_SECRET_SUBKEY)
	  node->flag |= NODFLG_SELKEY;
    }
  else if (idx)			/* Toggle selection.  */
    {
      for (i = 0, node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	      || node->pkt->pkttype == PKT_SECRET_SUBKEY)
	    if (++i == idx)
	      break;
	}
      if (!node)
	{
	  tty_printf (_("No subkey with index %d\n"), idx);
	  return 0;
	}

      for (i = 0, node = keyblock; node; node = node->next)
	{
	  if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	      || node->pkt->pkttype == PKT_SECRET_SUBKEY)
	    if (++i == idx)
	      {
		if ((node->flag & NODFLG_SELKEY))
		  node->flag &= ~NODFLG_SELKEY;
		else
		  node->flag |= NODFLG_SELKEY;
	      }
	}
    }
  else				/* Unselect all. */
    {
      for (node = keyblock; node; node = node->next)
	if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || node->pkt->pkttype == PKT_SECRET_SUBKEY)
	  node->flag &= ~NODFLG_SELKEY;
    }

  return 1;
}


static int
count_uids_with_flag (KBNODE keyblock, unsigned flag)
{
  KBNODE node;
  int i = 0;

  for (node = keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_USER_ID && (node->flag & flag))
      i++;
  return i;
}


static int
count_keys_with_flag (KBNODE keyblock, unsigned flag)
{
  KBNODE node;
  int i = 0;

  for (node = keyblock; node; node = node->next)
    if ((node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	 || node->pkt->pkttype == PKT_SECRET_SUBKEY) && (node->flag & flag))
      i++;
  return i;
}


static int
count_uids (KBNODE keyblock)
{
  KBNODE node;
  int i = 0;

  for (node = keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_USER_ID)
      i++;
  return i;
}


/*
 * Returns true if there is at least one selected user id
 */
static int
count_selected_uids (KBNODE keyblock)
{
  return count_uids_with_flag (keyblock, NODFLG_SELUID);
}


static int
count_selected_keys (KBNODE keyblock)
{
  return count_keys_with_flag (keyblock, NODFLG_SELKEY);
}


/* Returns how many real (i.e. not attribute) uids are unmarked.  */
static int
real_uids_left (KBNODE keyblock)
{
  KBNODE node;
  int real = 0;

  for (node = keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_USER_ID && !(node->flag & NODFLG_SELUID) &&
	!node->pkt->pkt.user_id->attrib_data)
      real++;

  return real;
}


/*
 * Ask whether the signature should be revoked.  If the user commits this,
 * flag bit MARK_A is set on the signature and the user ID.
 */
static void
ask_revoke_sig (ctrl_t ctrl, kbnode_t keyblock, kbnode_t node)
{
  int doit = 0;
  PKT_user_id *uid;
  PKT_signature *sig = node->pkt->pkt.signature;
  KBNODE unode = find_prev_kbnode (keyblock, node, PKT_USER_ID);

  if (!unode)
    {
      log_error ("Oops: no user ID for signature\n");
      return;
    }

  uid = unode->pkt->pkt.user_id;

  if (opt.with_colons)
    {
      if (uid->attrib_data)
	printf ("uat:::::::::%u %lu", uid->numattribs, uid->attrib_len);
      else
	{
	  es_printf ("uid:::::::::");
	  es_write_sanitized (es_stdout, uid->name, uid->len, ":", NULL);
	}

      es_printf ("\n");

      print_and_check_one_sig_colon (ctrl, keyblock, node,
                                     NULL, NULL, NULL, NULL, 1);
    }
  else
    {
      char *p = utf8_to_native (unode->pkt->pkt.user_id->name,
				unode->pkt->pkt.user_id->len, 0);
      tty_printf (_("user ID: \"%s\"\n"), p);
      xfree (p);

      tty_printf (_("signed by your key %s on %s%s%s\n"),
		  keystr (sig->keyid), datestr_from_sig (sig),
		  sig->flags.exportable ? "" : _(" (non-exportable)"), "");
    }
  if (sig->flags.expired)
    {
      tty_printf (_("This signature expired on %s.\n"),
		  expirestr_from_sig (sig));
      /* Use a different question so we can have different help text */
      doit = cpr_get_answer_is_yes
        ("ask_revoke_sig.expired",
         _("Are you sure you still want to revoke it? (y/N) "));
    }
  else
    doit = cpr_get_answer_is_yes
      ("ask_revoke_sig.one",
       _("Create a revocation certificate for this signature? (y/N) "));

  if (doit)
    {
      node->flag |= NODFLG_MARK_A;
      unode->flag |= NODFLG_MARK_A;
    }
}


/*
 * Display all user ids of the current public key together with signatures
 * done by one of our keys.  Then walk over all this sigs and ask the user
 * whether he wants to revoke this signature.
 * Return: True when the keyblock has changed.
 */
static int
menu_revsig (ctrl_t ctrl, kbnode_t keyblock)
{
  PKT_signature *sig;
  PKT_public_key *primary_pk;
  KBNODE node;
  int changed = 0;
  int rc, any, skip = 1, all = !count_selected_uids (keyblock);
  struct revocation_reason_info *reason = NULL;

  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY);

  /* First check whether we have any signatures at all.  */
  any = 0;
  for (node = keyblock; node; node = node->next)
    {
      node->flag &= ~(NODFLG_SELSIG | NODFLG_MARK_A);
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  if (node->flag & NODFLG_SELUID || all)
	    skip = 0;
	  else
	    skip = 1;
	}
      else if (!skip && node->pkt->pkttype == PKT_SIGNATURE
	       && ((sig = node->pkt->pkt.signature),
		   have_secret_key_with_kid (sig->keyid)))
	{
	  if ((sig->sig_class & ~3) == 0x10)
	    {
	      any = 1;
	      break;
	    }
	}
    }

  if (!any)
    {
      tty_printf (_("Not signed by you.\n"));
      return 0;
    }


  /* FIXME: detect duplicates here  */
  tty_printf (_("You have signed these user IDs on key %s:\n"),
	      keystr_from_pk (keyblock->pkt->pkt.public_key));
  for (node = keyblock; node; node = node->next)
    {
      node->flag &= ~(NODFLG_SELSIG | NODFLG_MARK_A);
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  if (node->flag & NODFLG_SELUID || all)
	    {
	      PKT_user_id *uid = node->pkt->pkt.user_id;
	      /* Hmmm: Should we show only UIDs with a signature? */
	      tty_printf ("     ");
	      tty_print_utf8_string (uid->name, uid->len);
	      tty_printf ("\n");
	      skip = 0;
	    }
	  else
	    skip = 1;
	}
      else if (!skip && node->pkt->pkttype == PKT_SIGNATURE
	       && ((sig = node->pkt->pkt.signature),
		   have_secret_key_with_kid (sig->keyid)))
	{
	  if ((sig->sig_class & ~3) == 0x10)
	    {
	      tty_printf ("   ");
	      tty_printf (_("signed by your key %s on %s%s%s\n"),
			  keystr (sig->keyid), datestr_from_sig (sig),
			  sig->flags.exportable ? "" : _(" (non-exportable)"),
			  sig->flags.revocable ? "" : _(" (non-revocable)"));
	      if (sig->flags.revocable)
		node->flag |= NODFLG_SELSIG;
	    }
	  else if (sig->sig_class == 0x30)
	    {
	      tty_printf ("   ");
	      tty_printf (_("revoked by your key %s on %s\n"),
			  keystr (sig->keyid), datestr_from_sig (sig));
	    }
	}
    }

  tty_printf ("\n");

  /* ask */
  for (node = keyblock; node; node = node->next)
    {
      if (!(node->flag & NODFLG_SELSIG))
	continue;
      ask_revoke_sig (ctrl, keyblock, node);
    }

  /* present selected */
  any = 0;
  for (node = keyblock; node; node = node->next)
    {
      if (!(node->flag & NODFLG_MARK_A))
	continue;
      if (!any)
	{
	  any = 1;
	  tty_printf (_("You are about to revoke these signatures:\n"));
	}
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  tty_printf ("     ");
	  tty_print_utf8_string (uid->name, uid->len);
	  tty_printf ("\n");
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE)
	{
	  sig = node->pkt->pkt.signature;
	  tty_printf ("   ");
	  tty_printf (_("signed by your key %s on %s%s%s\n"),
		      keystr (sig->keyid), datestr_from_sig (sig), "",
		      sig->flags.exportable ? "" : _(" (non-exportable)"));
	}
    }
  if (!any)
    return 0;			/* none selected */

  if (!cpr_get_answer_is_yes
      ("ask_revoke_sig.okay",
       _("Really create the revocation certificates? (y/N) ")))
    return 0;			/* forget it */

  reason = ask_revocation_reason (0, 1, 0);
  if (!reason)
    {				/* user decided to cancel */
      return 0;
    }

  /* now we can sign the user ids */
reloop:			/* (must use this, because we are modifying the list) */
  primary_pk = keyblock->pkt->pkt.public_key;
  for (node = keyblock; node; node = node->next)
    {
      KBNODE unode;
      PACKET *pkt;
      struct sign_attrib attrib;
      PKT_public_key *signerkey;

      if (!(node->flag & NODFLG_MARK_A)
	  || node->pkt->pkttype != PKT_SIGNATURE)
	continue;
      unode = find_prev_kbnode (keyblock, node, PKT_USER_ID);
      log_assert (unode); /* we already checked this */

      memset (&attrib, 0, sizeof attrib);
      attrib.reason = reason;
      attrib.non_exportable = !node->pkt->pkt.signature->flags.exportable;

      node->flag &= ~NODFLG_MARK_A;
      signerkey = xmalloc_secure_clear (sizeof *signerkey);
      if (get_seckey (ctrl, signerkey, node->pkt->pkt.signature->keyid))
	{
	  log_info (_("no secret key\n"));
          free_public_key (signerkey);
	  continue;
	}
      rc = make_keysig_packet (ctrl, &sig, primary_pk,
			       unode->pkt->pkt.user_id,
			       NULL, signerkey, 0x30, 0, 0, 0,
                               sign_mk_attrib, &attrib, NULL);
      free_public_key (signerkey);
      if (rc)
	{
          write_status_error ("keysig", rc);
	  log_error (_("signing failed: %s\n"), gpg_strerror (rc));
	  release_revocation_reason_info (reason);
	  return changed;
	}
      changed = 1;		/* we changed the keyblock */
      update_trust = 1;
      /* Are we revoking our own uid? */
      if (primary_pk->keyid[0] == sig->keyid[0] &&
	  primary_pk->keyid[1] == sig->keyid[1])
	unode->pkt->pkt.user_id->flags.revoked = 1;
      pkt = xmalloc_clear (sizeof *pkt);
      pkt->pkttype = PKT_SIGNATURE;
      pkt->pkt.signature = sig;
      insert_kbnode (unode, new_kbnode (pkt), 0);
      goto reloop;
    }

  release_revocation_reason_info (reason);
  return changed;
}


/* return 0 if revocation of NODE (which must be a User ID) was
   successful, non-zero if there was an error.  *modified will be set
   to 1 if a change was made. */
static int
core_revuid (ctrl_t ctrl, kbnode_t keyblock, KBNODE node,
             const struct revocation_reason_info *reason, int *modified)
{
  PKT_public_key *pk = keyblock->pkt->pkt.public_key;
  gpg_error_t rc;

  if (node->pkt->pkttype != PKT_USER_ID)
    {
      rc = gpg_error (GPG_ERR_NO_USER_ID);
      write_status_error ("keysig", rc);
      log_error (_("tried to revoke a non-user ID: %s\n"), gpg_strerror (rc));
      return 1;
    }
  else
    {
      PKT_user_id *uid = node->pkt->pkt.user_id;

      if (uid->flags.revoked)
        {
          char *user = utf8_to_native (uid->name, uid->len, 0);
          log_info (_("user ID \"%s\" is already revoked\n"), user);
          xfree (user);
        }
      else
        {
          PACKET *pkt;
          PKT_signature *sig;
          struct sign_attrib attrib;
          u32 timestamp = make_timestamp ();

          if (uid->created >= timestamp)
            {
              /* Okay, this is a problem.  The user ID selfsig was
                 created in the future, so we need to warn the user and
                 set our revocation timestamp one second after that so
                 everything comes out clean. */

              log_info (_("WARNING: a user ID signature is dated %d"
                          " seconds in the future\n"),
                        uid->created - timestamp);

              timestamp = uid->created + 1;
            }

          memset (&attrib, 0, sizeof attrib);
          /* should not need to cast away const here; but
             revocation_reason_build_cb needs to take a non-const
             void* in order to meet the function signature for the
             mksubpkt argument to make_keysig_packet */
          attrib.reason = (struct revocation_reason_info *)reason;

          rc = make_keysig_packet (ctrl, &sig, pk, uid, NULL, pk, 0x30, 0,
                                   timestamp, 0,
                                   sign_mk_attrib, &attrib, NULL);
          if (rc)
            {
              write_status_error ("keysig", rc);
              log_error (_("signing failed: %s\n"), gpg_strerror (rc));
              return 1;
            }
          else
            {
              pkt = xmalloc_clear (sizeof *pkt);
              pkt->pkttype = PKT_SIGNATURE;
              pkt->pkt.signature = sig;
              insert_kbnode (node, new_kbnode (pkt), 0);

#ifndef NO_TRUST_MODELS
              /* If the trustdb has an entry for this key+uid then the
                 trustdb needs an update. */
              if (!update_trust
                  && ((get_validity (ctrl, keyblock, pk, uid, NULL, 0)
                       & TRUST_MASK)
                      >= TRUST_UNDEFINED))
                update_trust = 1;
#endif /*!NO_TRUST_MODELS*/

              node->pkt->pkt.user_id->flags.revoked = 1;
              if (modified)
                *modified = 1;
            }
        }
      return 0;
    }
}

/* Revoke a user ID (i.e. revoke a user ID selfsig).  Return true if
   keyblock changed.  */
static int
menu_revuid (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  PKT_public_key *pk = pub_keyblock->pkt->pkt.public_key;
  KBNODE node;
  int changed = 0;
  int rc;
  struct revocation_reason_info *reason = NULL;
  size_t valid_uids;

  /* Note that this is correct as per the RFCs, but nevertheless
     somewhat meaningless in the real world.  1991 did define the 0x30
     sig class, but PGP 2.x did not actually implement it, so it would
     probably be safe to use v4 revocations everywhere. -ds */

  for (node = pub_keyblock; node; node = node->next)
    if (pk->version > 3 || (node->pkt->pkttype == PKT_USER_ID &&
			    node->pkt->pkt.user_id->selfsigversion > 3))
      {
	if ((reason = ask_revocation_reason (0, 1, 4)))
	  break;
	else
	  goto leave;
      }

  /* Too make sure that we do not revoke the last valid UID, we first
     count how many valid UIDs there are.  */
  valid_uids = 0;
  for (node = pub_keyblock; node; node = node->next)
    valid_uids +=
      node->pkt->pkttype == PKT_USER_ID
      && ! node->pkt->pkt.user_id->flags.revoked
      && ! node->pkt->pkt.user_id->flags.expired;

 reloop: /* (better this way because we are modifying the keyring) */
  for (node = pub_keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_USER_ID && (node->flag & NODFLG_SELUID))
      {
        int modified = 0;

        /* Make sure that we do not revoke the last valid UID.  */
        if (valid_uids == 1
            && ! node->pkt->pkt.user_id->flags.revoked
            && ! node->pkt->pkt.user_id->flags.expired)
          {
            log_error (_("Cannot revoke the last valid user ID.\n"));
            goto leave;
          }

        rc = core_revuid (ctrl, pub_keyblock, node, reason, &modified);
        if (rc)
          goto leave;
        if (modified)
          {
	    node->flag &= ~NODFLG_SELUID;
            changed = 1;
            goto reloop;
          }
      }

  if (changed)
    commit_kbnode (&pub_keyblock);

leave:
  release_revocation_reason_info (reason);
  return changed;
}


/*
 * Revoke the whole key.
 */
static int
menu_revkey (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  PKT_public_key *pk = pub_keyblock->pkt->pkt.public_key;
  int rc, changed = 0;
  struct revocation_reason_info *reason;
  PACKET *pkt;
  PKT_signature *sig;

  if (pk->flags.revoked)
    {
      tty_printf (_("Key %s is already revoked.\n"), keystr_from_pk (pk));
      return 0;
    }

  reason = ask_revocation_reason (1, 0, 0);
  /* user decided to cancel */
  if (!reason)
    return 0;

  rc = make_keysig_packet (ctrl, &sig, pk, NULL, NULL, pk,
			   0x20, 0, 0, 0,
			   revocation_reason_build_cb, reason, NULL);
  if (rc)
    {
      write_status_error ("keysig", rc);
      log_error (_("signing failed: %s\n"), gpg_strerror (rc));
      goto scram;
    }

  changed = 1;			/* we changed the keyblock */

  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  insert_kbnode (pub_keyblock, new_kbnode (pkt), 0);
  commit_kbnode (&pub_keyblock);

  update_trust = 1;

 scram:
  release_revocation_reason_info (reason);
  return changed;
}


static int
menu_revsubkey (ctrl_t ctrl, kbnode_t pub_keyblock)
{
  PKT_public_key *mainpk;
  KBNODE node;
  int changed = 0;
  int rc;
  struct revocation_reason_info *reason = NULL;

  reason = ask_revocation_reason (1, 0, 0);
  if (!reason)
      return 0; /* User decided to cancel.  */

 reloop: /* (better this way because we are modifying the keyring) */
  mainpk = pub_keyblock->pkt->pkt.public_key;
  for (node = pub_keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	  && (node->flag & NODFLG_SELKEY))
	{
	  PACKET *pkt;
	  PKT_signature *sig;
	  PKT_public_key *subpk = node->pkt->pkt.public_key;
	  struct sign_attrib attrib;

	  if (subpk->flags.revoked)
	    {
	      tty_printf (_("Subkey %s is already revoked.\n"),
			  keystr_from_pk (subpk));
	      continue;
	    }

	  memset (&attrib, 0, sizeof attrib);
	  attrib.reason = reason;

	  node->flag &= ~NODFLG_SELKEY;
	  rc = make_keysig_packet (ctrl, &sig, mainpk, NULL, subpk, mainpk,
				   0x28, 0, 0, 0, sign_mk_attrib, &attrib,
                                   NULL);
	  if (rc)
	    {
              write_status_error ("keysig", rc);
	      log_error (_("signing failed: %s\n"), gpg_strerror (rc));
	      release_revocation_reason_info (reason);
	      return changed;
	    }
	  changed = 1;		/* we changed the keyblock */

	  pkt = xmalloc_clear (sizeof *pkt);
	  pkt->pkttype = PKT_SIGNATURE;
	  pkt->pkt.signature = sig;
	  insert_kbnode (node, new_kbnode (pkt), 0);
	  goto reloop;
	}
    }
  commit_kbnode (&pub_keyblock);

  /* No need to set update_trust here since signing keys no longer
     are used to certify other keys, so there is no change in trust
     when revoking/removing them */

  release_revocation_reason_info (reason);
  return changed;
}


/* Note that update_ownertrust is going to mark the trustdb dirty when
   enabling or disabling a key.  This is arguably sub-optimal as
   disabled keys are still counted in the web of trust, but perhaps
   not worth adding extra complexity to change. -ds */
#ifndef NO_TRUST_MODELS
static int
enable_disable_key (ctrl_t ctrl, kbnode_t keyblock, int disable)
{
  PKT_public_key *pk =
    find_kbnode (keyblock, PKT_PUBLIC_KEY)->pkt->pkt.public_key;
  unsigned int trust, newtrust;

  trust = newtrust = get_ownertrust (ctrl, pk);
  newtrust &= ~TRUST_FLAG_DISABLED;
  if (disable)
    newtrust |= TRUST_FLAG_DISABLED;
  if (trust == newtrust)
    return 0;			/* already in that state */
  update_ownertrust (ctrl, pk, newtrust);
  return 0;
}
#endif /*!NO_TRUST_MODELS*/


static void
menu_showphoto (ctrl_t ctrl, kbnode_t keyblock)
{
  KBNODE node;
  int select_all = !count_selected_uids (keyblock);
  int count = 0;
  PKT_public_key *pk = NULL;

  /* Look for the public key first.  We have to be really, really,
     explicit as to which photo this is, and what key it is a UID on
     since people may want to sign it. */

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
	pk = node->pkt->pkt.public_key;
      else if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  count++;

	  if ((select_all || (node->flag & NODFLG_SELUID)) &&
	      uid->attribs != NULL)
	    {
	      int i;

	      for (i = 0; i < uid->numattribs; i++)
		{
		  byte type;
		  u32 size;

		  if (uid->attribs[i].type == ATTRIB_IMAGE &&
		      parse_image_header (&uid->attribs[i], &type, &size))
		    {
		      tty_printf (_("Displaying %s photo ID of size %ld for "
				    "key %s (uid %d)\n"),
				  image_type_to_string (type, 1),
				  (ulong) size, keystr_from_pk (pk), count);
		      show_photos (ctrl, &uid->attribs[i], 1, pk, uid);
		    }
		}
	    }
	}
    }
}
