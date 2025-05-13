/* keylist.c - Print information about OpenPGP keys
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2010, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2013, 2014  Werner Koch
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
#ifdef HAVE_DOSISH_SYSTEM
# include <fcntl.h>		/* for setmode() */
#endif

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "../common/status.h"
#include "keydb.h"
#include "photoid.h"
#include "../common/util.h"
#include "../common/ttyio.h"
#include "trustdb.h"
#include "main.h"
#include "../common/i18n.h"
#include "../common/status.h"
#include "call-agent.h"
#include "../common/mbox-util.h"
#include "../common/zb32.h"
#include "tofu.h"
#include "../common/init.h"
#include "../common/recsel.h"
#include "../common/compliance.h"
#include "../common/pkscreening.h"


static void list_all (ctrl_t, int, int);
static void list_one (ctrl_t ctrl,
                      strlist_t names, int secret, int mark_secret);
static void locate_one (ctrl_t ctrl, strlist_t names, int no_local);
static void print_card_serialno (const char *serialno);

struct keylist_context
{
  int check_sigs;  /* If set signatures shall be verified.  */
  int good_sigs;   /* Counter used if CHECK_SIGS is set.  */
  int inv_sigs;    /* Counter used if CHECK_SIGS is set.  */
  int no_key;      /* Counter used if CHECK_SIGS is set.  */
  int oth_err;     /* Counter used if CHECK_SIGS is set.  */
  int no_validity; /* Do not show validity.  */
};

/* An object and a global instance to store selectors created from
 * --list-filter select=EXPR.
 */
struct list_filter_s
{
  recsel_expr_t selkey;
};
struct list_filter_s list_filter;


/* The stream used to write attribute packets to.  */
static estream_t attrib_fp;




static void list_keyblock (ctrl_t ctrl,
                           kbnode_t keyblock, int secret, int has_secret,
                           int fpr, struct keylist_context *listctx);

/* Release resources from a keylist context.  */
static void
keylist_context_release (struct keylist_context *listctx)
{
  (void)listctx; /* Nothing to release.  */
}


static void
release_list_filter (struct list_filter_s *filt)
{
  recsel_release (filt->selkey);
  filt->selkey = NULL;
}


static void
cleanup_keylist_globals (void)
{
  release_list_filter (&list_filter);
}


/* Parse and set an list filter from string.  STRING has the format
 * "NAME=EXPR" with NAME being the name of the filter.  Spaces before
 * and after NAME are not allowed.  If this function is all called
 * several times all expressions for the same NAME are concatenated.
 * Supported filter names are:
 *
 *  - select :: If the expression evaluates to true for a certain key
 *              this key will be listed.  The expression may use any
 *              variable defined for the export and import filters.
 *
 */
gpg_error_t
parse_and_set_list_filter (const char *string)
{
  gpg_error_t err;

  /* Auto register the cleanup function.  */
  register_mem_cleanup_func (cleanup_keylist_globals);

  if (!strncmp (string, "select=", 7))
    err = recsel_parse_expr (&list_filter.selkey, string+7);
  else
    err = gpg_error (GPG_ERR_INV_NAME);

  return err;
}


/* List the keys.  If list is NULL, all available keys are listed.
 * With LOCATE_MODE set the locate algorithm is used to find a key; if
 * in addition NO_LOCAL is set the locate does not look into the local
 * keyring.  */
void
public_key_list (ctrl_t ctrl, strlist_t list, int locate_mode, int no_local)
{
#ifndef NO_TRUST_MODELS
  if (opt.with_colons)
    {
      byte trust_model, marginals, completes, cert_depth, min_cert_level;
      ulong created, nextcheck;

      read_trust_options (ctrl, &trust_model, &created, &nextcheck,
			  &marginals, &completes, &cert_depth, &min_cert_level);

      es_fprintf (es_stdout, "tru:");

      if (nextcheck && nextcheck <= make_timestamp ())
	es_fprintf (es_stdout, "o");
      if (trust_model != opt.trust_model)
	es_fprintf (es_stdout, "t");
      if (opt.trust_model == TM_PGP || opt.trust_model == TM_CLASSIC
	  || opt.trust_model == TM_TOFU_PGP)
	{
	  if (marginals != opt.marginals_needed)
	    es_fprintf (es_stdout, "m");
	  if (completes != opt.completes_needed)
	    es_fprintf (es_stdout, "c");
	  if (cert_depth != opt.max_cert_depth)
	    es_fprintf (es_stdout, "d");
	  if (min_cert_level != opt.min_cert_level)
	    es_fprintf (es_stdout, "l");
	}

      es_fprintf (es_stdout, ":%d:%lu:%lu", trust_model, created, nextcheck);

      /* Only show marginals, completes, and cert_depth in the classic
         or PGP trust models since they are not meaningful
         otherwise. */

      if (trust_model == TM_PGP || trust_model == TM_CLASSIC)
	es_fprintf (es_stdout, ":%d:%d:%d", marginals, completes, cert_depth);
      es_fprintf (es_stdout, "\n");
    }
#endif /*!NO_TRUST_MODELS*/

  /* We need to do the stale check right here because it might need to
     update the keyring while we already have the keyring open.  This
     is very bad for W32 because of a sharing violation. For real OSes
     it might lead to false results if we are later listing a keyring
     which is associated with the inode of a deleted file.  */
  check_trustdb_stale (ctrl);

#ifdef USE_TOFU
  tofu_begin_batch_update (ctrl);
#endif

  if (locate_mode)
    locate_one (ctrl, list, no_local);
  else if (!list)
    list_all (ctrl, 0, opt.with_secret);
  else
    list_one (ctrl, list, 0, opt.with_secret);

#ifdef USE_TOFU
  tofu_end_batch_update (ctrl);
#endif
}


void
secret_key_list (ctrl_t ctrl, strlist_t list)
{
  (void)ctrl;

  check_trustdb_stale (ctrl);

  if (!list)
    list_all (ctrl, 1, 0);
  else				/* List by user id */
    list_one (ctrl, list, 1, 0);
}


/* Helper for print_key_info and print_key_info_log.  */
static char *
format_key_info (ctrl_t ctrl, PKT_public_key *pk, int secret)
{
  u32 keyid[2];
  char *p;
  char pkstrbuf[PUBKEY_STRING_SIZE];
  char *result;

  keyid_from_pk (pk, keyid);

  /* If the pk was chosen by a particular user ID, that is the one to
     print.  */
  if (pk->user_id)
    p = utf8_to_native (pk->user_id->name, pk->user_id->len, 0);
  else
    p = get_user_id_native (ctrl, keyid);

  result = xtryasprintf ("%s  %s/%s %s %s",
                         secret? (pk->flags.primary? "sec":"ssb")
                         /* */ : (pk->flags.primary? "pub":"sub"),
                         pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                         keystr (keyid), datestr_from_pk (pk), p);
  xfree (p);
  return result;
}


/* Print basic information about a public or secret key.  With FP
 * passed as NULL, the tty output interface is used, otherwise output
 * is directed to the given stream.  INDENT gives the requested
 * indentation; if that is a negative value indentation is suppressed
 * for the first line.  SECRET tells that the PK has a secret part.
 * FIXME: This is similar in use to print_key_line and thus both
 * functions should eventually be united.
 */
void
print_key_info (ctrl_t ctrl, estream_t fp,
                int indent, PKT_public_key *pk, int secret)
{
  int indentabs = indent >= 0? indent : -indent;
  char *info;

  /* Note: Negative values for INDENT are not yet needed. */

  info = format_key_info (ctrl, pk, secret);

  if (!fp && indent >= 0)
    tty_printf ("\n");  /* (Backward compatibility to old code) */
  tty_fprintf (fp, "%*s%s\n", indentabs, "",
               info? info : "[Ooops - out of core]");

  xfree (info);
}


/* Same as print_key_info put print using the log functions at
 * LOGLEVEL.  */
void
print_key_info_log (ctrl_t ctrl, int loglevel,
                    int indent, PKT_public_key *pk, int secret)
{
  int indentabs = indent >= 0? indent : -indent;
  char *info;

  info = format_key_info (ctrl, pk, secret);

  log_log (loglevel, "%*s%s\n", indentabs, "",
           info? info : "[Ooops - out of core]");

  xfree (info);
}


/* Print basic information of a secret key including the card serial
   number information.  */
#ifdef ENABLE_CARD_SUPPORT
void
print_card_key_info (estream_t fp, kbnode_t keyblock)
{
  kbnode_t node;
  char *hexgrip;
  char *serialno;
  int s2k_char;
  char pkstrbuf[PUBKEY_STRING_SIZE];
  int indent;

  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
          || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          int rc;
          PKT_public_key *pk = node->pkt->pkt.public_key;

          serialno = NULL;
          rc = hexkeygrip_from_pk (pk, &hexgrip);
          if (rc)
            {
              log_error ("error computing a keygrip: %s\n", gpg_strerror (rc));
              s2k_char = '?';
            }
          else if (!agent_get_keyinfo (NULL, hexgrip, &serialno, NULL))
            s2k_char = serialno? '>':' ';
          else
            s2k_char = '#';  /* Key not found.  */

          tty_fprintf (fp, "%s%c  %s/%s  %n",
                       node->pkt->pkttype == PKT_PUBLIC_KEY ? "sec" : "ssb",
                       s2k_char,
                       pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                       keystr_from_pk (pk),
                       &indent);
          tty_fprintf (fp, _("created: %s"), datestr_from_pk (pk));
          tty_fprintf (fp, "  ");
          tty_fprintf (fp, _("expires: %s"), expirestr_from_pk (pk));
          if (serialno)
            {
              tty_fprintf (fp, "\n%*s%s", indent, "", _("card-no: "));
              if (strlen (serialno) == 32
                  && !strncmp (serialno, "D27600012401", 12))
                {
                  /* This is an OpenPGP card.  Print the relevant part.  */
                  /* Example: D2760001240101010001000003470000 */
                  /*                          xxxxyyyyyyyy     */
                  tty_fprintf (fp, "%.*s %.*s", 4, serialno+16, 8, serialno+20);
                }
              else
                tty_fprintf (fp, "%s", serialno);
            }
          tty_fprintf (fp, "\n");
          xfree (hexgrip);
          xfree (serialno);
        }
    }
}
#endif /*ENABLE_CARD_SUPPORT*/


/* Print the preferences line.  Allowed values for MODE are:
 *  -1 - print to the TTY
 *   0 - print to stdout.
 *   1 - use log_info
 */
void
show_preferences (PKT_user_id *uid, int indent, int mode, int verbose)
{
  estream_t fp = mode < 0? NULL : mode ? log_get_stream () : es_stdout;
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

      tty_fprintf (fp, "%*s %s", indent, "", _("Cipher: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_SYM)
	    {
	      if (any)
		tty_fprintf (fp, ", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (!openpgp_cipher_test_algo (prefs[i].value)
		  && prefs[i].value < 100)
		tty_fprintf (fp, "%s", openpgp_cipher_algo_name (prefs[i].value));
	      else
		tty_fprintf (fp, "[%d]", prefs[i].value);
	      if (prefs[i].value == CIPHER_ALGO_3DES)
		des_seen = 1;
	    }
	}
      if (!des_seen)
	{
	  if (any)
	    tty_fprintf (fp, ", ");
	  tty_fprintf (fp, "%s", openpgp_cipher_algo_name (CIPHER_ALGO_3DES));
	}
      tty_fprintf (fp, "\n%*s %s", indent, "", _("AEAD: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_AEAD)
	    {
	      if (any)
		tty_fprintf (fp, ", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (!openpgp_aead_test_algo (prefs[i].value)
		  && prefs[i].value < 100)
		tty_fprintf (fp, "%s", openpgp_aead_algo_name (prefs[i].value));
	      else
		tty_fprintf (fp, "[%d]", prefs[i].value);
	    }
	}
      tty_fprintf (fp, "\n%*s %s", indent, "", _("Digest: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_HASH)
	    {
	      if (any)
		tty_fprintf (fp, ", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (!gcry_md_test_algo (prefs[i].value) && prefs[i].value < 100)
		tty_fprintf (fp, "%s", gcry_md_algo_name (prefs[i].value));
	      else
		tty_fprintf (fp, "[%d]", prefs[i].value);
	      if (prefs[i].value == DIGEST_ALGO_SHA1)
		sha1_seen = 1;
	    }
	}
      if (!sha1_seen)
	{
	  if (any)
	    tty_fprintf (fp, ", ");
	  tty_fprintf (fp, "%s", gcry_md_algo_name (DIGEST_ALGO_SHA1));
	}
      tty_fprintf (fp, "\n%*s %s", indent, "", _("Compression: "));
      for (i = any = 0; prefs[i].type; i++)
	{
	  if (prefs[i].type == PREFTYPE_ZIP)
	    {
	      const char *s = compress_algo_to_string (prefs[i].value);

	      if (any)
		tty_fprintf (fp, ", ");
	      any = 1;
	      /* We don't want to display strings for experimental algos */
	      if (s && prefs[i].value < 100)
		tty_fprintf (fp, "%s", s);
	      else
		tty_fprintf (fp, "[%d]", prefs[i].value);
	      if (prefs[i].value == COMPRESS_ALGO_NONE)
		uncomp_seen = 1;
	    }
	}
      if (!uncomp_seen)
	{
	  if (any)
	    tty_fprintf (fp, ", ");
	  else
	    {
	      tty_fprintf (fp, "%s",
                           compress_algo_to_string (COMPRESS_ALGO_ZIP));
	      tty_fprintf (fp, ", ");
	    }
	  tty_fprintf (fp, "%s", compress_algo_to_string (COMPRESS_ALGO_NONE));
	}
      if (uid->flags.mdc || uid->flags.aead || !uid->flags.ks_modify)
	{
          tty_fprintf (fp, "\n%*s %s", indent, "", _("Features: "));
	  any = 0;
	  if (uid->flags.mdc)
	    {
	      tty_fprintf (fp, "MDC");
	      any = 1;
	    }
	  if (uid->flags.aead)
	    {
	      if (any)
		tty_fprintf (fp, ", ");
	      tty_fprintf (fp, "AEAD");
	    }
	  if (!uid->flags.ks_modify)
	    {
	      if (any)
		tty_fprintf (fp, ", ");
	      tty_fprintf (fp, _("Keyserver no-modify"));
	    }
	}
      tty_fprintf (fp, "\n");
    }
  else
    {
      tty_fprintf (fp, "%*s", indent, "");
      for (i = 0; prefs[i].type; i++)
        {
          tty_fprintf (fp, " %c%d", prefs[i].type == PREFTYPE_SYM ? 'S' :
                       prefs[i].type == PREFTYPE_AEAD ? 'A' :
                       prefs[i].type == PREFTYPE_HASH ? 'H' :
                       prefs[i].type == PREFTYPE_ZIP ? 'Z' : '?',
                       prefs[i].value);
        }
      if (uid->flags.mdc)
        tty_fprintf (fp, " [mdc]");
      if (uid->flags.aead)
        tty_fprintf (fp, " [aead]");
      if (!uid->flags.ks_modify)
        tty_fprintf (fp, " [no-ks-modify]");
      tty_fprintf (fp, "\n");
    }
}


/* Flags = 0x01 hashed 0x02 critical.  */
static void
status_one_subpacket (sigsubpkttype_t type, size_t len, int flags,
		      const byte * buf)
{
  char status[40];

  /* Don't print these. */
  if (len > 256)
    return;

  snprintf (status, sizeof status,
            "%d %u %u ", type, flags, (unsigned int) len);

  write_status_text_and_buffer (STATUS_SIG_SUBPACKET, status, buf, len, 0);
}


/* Print a policy URL.  Allowed values for MODE are:
 *  -1 - print to the TTY
 *   0 - print to stdout.
 *   1 - use log_info and emit status messages.
 *   2 - emit only status messages.
 */
void
show_policy_url (PKT_signature * sig, int indent, int mode)
{
  const byte *p;
  size_t len;
  int seq = 0, crit;
  estream_t fp = mode < 0? NULL : mode ? log_get_stream () : es_stdout;

  while ((p = enum_sig_subpkt (sig, 1, SIGSUBPKT_POLICY, &len, &seq, &crit)))
    {
      if (mode != 2)
	{
	  const char *str;

          tty_fprintf (fp, "%*s", indent, "");

	  if (crit)
	    str = _("Critical signature policy: ");
	  else
	    str = _("Signature policy: ");
	  if (mode > 0)
	    log_info ("%s", str);
	  else
	    tty_fprintf (fp, "%s", str);
	  tty_print_utf8_string2 (fp, p, len, 0);
	  tty_fprintf (fp, "\n");
	}

      if (mode > 0)
	write_status_buffer (STATUS_POLICY_URL, p, len, 0);
    }
}


/* Print a keyserver URL.  Allowed values for MODE are:
 *  -1 - print to the TTY
 *   0 - print to stdout.
 *   1 - use log_info and emit status messages.
 *   2 - emit only status messages.
 */
void
show_keyserver_url (PKT_signature * sig, int indent, int mode)
{
  const byte *p;
  size_t len;
  int seq = 0, crit;
  estream_t fp = mode < 0? NULL : mode ? log_get_stream () : es_stdout;

  while ((p = enum_sig_subpkt (sig, 1, SIGSUBPKT_PREF_KS, &len, &seq, &crit)))
    {
      if (mode != 2)
	{
	  const char *str;

          tty_fprintf (fp, "%*s", indent, "");

	  if (crit)
	    str = _("Critical preferred keyserver: ");
	  else
	    str = _("Preferred keyserver: ");
	  if (mode > 0)
	    log_info ("%s", str);
	  else
	    tty_fprintf (fp, "%s", str);
	  tty_print_utf8_string2 (fp, p, len, 0);
	  tty_fprintf (fp, "\n");
	}

      if (mode > 0)
	status_one_subpacket (SIGSUBPKT_PREF_KS, len,
			      (crit ? 0x02 : 0) | 0x01, p);
    }
}


/* Print notation data.  Allowed values for MODE are:
 *  -1 - print to the TTY
 *   0 - print to stdout.
 *   1 - use log_info and emit status messages.
 *   2 - emit only status messages.
 *
 * Defined bits in WHICH:
 *   1 - standard notations
 *   2 - user notations
 */
void
show_notation (PKT_signature * sig, int indent, int mode, int which)
{
  estream_t fp = mode < 0? NULL : mode ? log_get_stream () : es_stdout;
  notation_t nd, notations;

  if (which == 0)
    which = 3;

  notations = sig_to_notation (sig);

  /* There may be multiple notations in the same sig. */
  for (nd = notations; nd; nd = nd->next)
    {
      if (mode != 2)
	{
	  int has_at = !!strchr (nd->name, '@');

	  if ((which & 1 && !has_at) || (which & 2 && has_at))
	    {
	      const char *str;

              tty_fprintf (fp, "%*s", indent, "");

	      if (nd->flags.critical)
		str = _("Critical signature notation: ");
	      else
		str = _("Signature notation: ");
	      if (mode > 0)
		log_info ("%s", str);
	      else
		tty_fprintf (fp, "%s", str);
	      /* This is all UTF8 */
	      tty_print_utf8_string2 (fp, nd->name, strlen (nd->name), 0);
	      tty_fprintf (fp, "=");
	      tty_print_utf8_string2 (fp, nd->value, strlen (nd->value), 0);
              /* (We need to use log_printf so that the next call to a
                  log function does not insert an extra LF.)  */
              if (mode > 0)
                log_printf ("\n");
              else
                tty_fprintf (fp, "\n");
	    }
	}

      if (mode > 0)
	{
	  write_status_buffer (STATUS_NOTATION_NAME,
			       nd->name, strlen (nd->name), 0);
          if (nd->flags.critical || nd->flags.human)
            write_status_text (STATUS_NOTATION_FLAGS,
                               nd->flags.critical && nd->flags.human? "1 1" :
                               nd->flags.critical? "1 0" : "0 1");
          if (!nd->flags.human && nd->bdat && nd->blen)
            write_status_buffer (STATUS_NOTATION_DATA,
                                 nd->bdat, nd->blen, 250);
          else
            write_status_buffer (STATUS_NOTATION_DATA,
                                 nd->value, strlen (nd->value), 50);
	}
    }

  free_notation (notations);
}


static void
print_signature_stats (struct keylist_context *s)
{
  if (!s->check_sigs)
    return;  /* Signature checking was not requested.  */

  /* Better flush stdout so that the stats are always printed after
   * the output.  */
  es_fflush (es_stdout);

  if (s->good_sigs)
    log_info (ngettext("%d good signature\n",
                       "%d good signatures\n", s->good_sigs), s->good_sigs);

  if (s->inv_sigs)
    log_info (ngettext("%d bad signature\n",
                       "%d bad signatures\n", s->inv_sigs), s->inv_sigs);

  if (s->no_key)
    log_info (ngettext("%d signature not checked due to a missing key\n",
                       "%d signatures not checked due to missing keys\n",
                       s->no_key), s->no_key);

  if (s->oth_err)
    log_info (ngettext("%d signature not checked due to an error\n",
                       "%d signatures not checked due to errors\n",
                       s->oth_err), s->oth_err);
}


/* List all keys.  If SECRET is true only secret keys are listed.  If
   MARK_SECRET is true secret keys are indicated in a public key
   listing.  */
static void
list_all (ctrl_t ctrl, int secret, int mark_secret)
{
  KEYDB_HANDLE hd;
  KBNODE keyblock = NULL;
  int rc = 0;
  int any_secret;
  const char *lastresname, *resname;
  struct keylist_context listctx;

  memset (&listctx, 0, sizeof (listctx));
  if (opt.check_sigs)
    listctx.check_sigs = 1;

  hd = keydb_new (ctrl);
  if (!hd)
    rc = gpg_error_from_syserror ();
  else
    rc = keydb_search_first (hd);
  if (rc)
    {
      if (gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
	log_error ("keydb_search_first failed: %s\n", gpg_strerror (rc));
      goto leave;
    }

  lastresname = NULL;
  do
    {
      if (secret)
        glo_ctrl.silence_parse_warnings++;
      rc = keydb_get_keyblock (hd, &keyblock);
      if (secret)
        glo_ctrl.silence_parse_warnings--;
      if (rc)
	{
          if (gpg_err_code (rc) == GPG_ERR_LEGACY_KEY)
            continue;  /* Skip legacy keys.  */
	  log_error ("keydb_get_keyblock failed: %s\n", gpg_strerror (rc));
	  goto leave;
	}

      if (secret || mark_secret)
        any_secret = !agent_probe_any_secret_key (ctrl, keyblock);
      else
        any_secret = 0;

      if (secret && !any_secret)
        ; /* Secret key listing requested but this isn't one.  */
      else
        {
          if (!opt.with_colons && !(opt.list_options & LIST_SHOW_ONLY_FPR_MBOX))
            {
              resname = keydb_get_resource_name (hd);
              if (lastresname != resname)
                {
                  int i;

                  es_fprintf (es_stdout, "%s\n", resname);
                  for (i = strlen (resname); i; i--)
                    es_putc ('-', es_stdout);
                  es_putc ('\n', es_stdout);
                  lastresname = resname;
                }
            }
          merge_keys_and_selfsig (ctrl, keyblock);
          list_keyblock (ctrl, keyblock, secret, any_secret, opt.fingerprint,
                         &listctx);
        }
      release_kbnode (keyblock);
      keyblock = NULL;
    }
  while (!(rc = keydb_search_next (hd)));
  es_fflush (es_stdout);
  if (rc && gpg_err_code (rc) != GPG_ERR_NOT_FOUND)
    log_error ("keydb_search_next failed: %s\n", gpg_strerror (rc));
  if (keydb_get_skipped_counter (hd))
    log_info (ngettext("Warning: %lu key skipped due to its large size\n",
                       "Warning: %lu keys skipped due to their large sizes\n",
                       keydb_get_skipped_counter (hd)),
              keydb_get_skipped_counter (hd));

  if (opt.check_sigs && !opt.with_colons)
    print_signature_stats (&listctx);

 leave:
  keylist_context_release (&listctx);
  release_kbnode (keyblock);
  keydb_release (hd);
}


static void
list_one (ctrl_t ctrl, strlist_t names, int secret, int mark_secret)
{
  int rc = 0;
  KBNODE keyblock = NULL;
  GETKEY_CTX ctx;
  int any_secret;
  const char *resname;
  const char *keyring_str = _("Keyring");
  int i;
  struct keylist_context listctx;

  memset (&listctx, 0, sizeof (listctx));
  if (!secret && opt.check_sigs)
    listctx.check_sigs = 1;

  /* fixme: using the bynames function has the disadvantage that we
   * don't know whether one of the names given was not found.  OTOH,
   * this function has the advantage to list the names in the
   * sequence as defined by the keyDB and does not duplicate
   * outputs.  A solution could be do test whether all given have
   * been listed (this needs a way to use the keyDB search
   * functions) or to have the search function return indicators for
   * found names.  Yet another way is to use the keydb search
   * facilities directly. */
  rc = getkey_bynames (ctrl, &ctx, NULL, names, secret, &keyblock);
  if (rc)
    {
      log_error ("error reading key: %s\n", gpg_strerror (rc));
      getkey_end (ctrl, ctx);
      write_status_error ("keylist.getkey", rc);
      return;
    }

  do
    {
      /* getkey_bynames makes sure that only secret keys are returned
       * if requested, thus we do not need to test again.  With
       * MARK_SECRET set (ie. option --with-secret) we have to test
       * for a secret key, though.  */
      if (secret)
        any_secret = 1;
      else if (mark_secret)
        any_secret = !agent_probe_any_secret_key (ctrl, keyblock);
      else
        any_secret = 0;

      if (secret && !any_secret)
        ;/* Secret key listing requested but getkey_bynames failed.  */
      else
        {
          if ((opt.list_options & LIST_SHOW_KEYRING) && !opt.with_colons)
            {
              resname = keydb_get_resource_name (get_ctx_handle (ctx));
              es_fprintf (es_stdout, "%s: %s\n", keyring_str, resname);
              for (i = strlen (resname) + strlen (keyring_str) + 2; i; i--)
                es_putc ('-', es_stdout);
              es_putc ('\n', es_stdout);
            }
          list_keyblock (ctrl, keyblock, secret, any_secret,
                         opt.fingerprint, &listctx);
        }
      release_kbnode (keyblock);
    }
  while (!getkey_next (ctrl, ctx, NULL, &keyblock));
  getkey_end (ctrl, ctx);

  if (opt.check_sigs && !opt.with_colons)
    print_signature_stats (&listctx);

  keylist_context_release (&listctx);
}


static void
locate_one (ctrl_t ctrl, strlist_t names, int no_local)
{
  int rc = 0;
  strlist_t sl;
  GETKEY_CTX ctx = NULL;
  KBNODE keyblock = NULL;
  struct keylist_context listctx;

  memset (&listctx, 0, sizeof (listctx));
  if (opt.check_sigs)
    listctx.check_sigs = 1;

  for (sl = names; sl; sl = sl->next)
    {
      rc = get_best_pubkey_byname (ctrl,
                                   no_local? GET_PUBKEY_NO_LOCAL
                                   /*    */: GET_PUBKEY_NORMAL,
                                   &ctx, NULL, sl->d, &keyblock, 1);
      if (rc)
	{
	  if (gpg_err_code (rc) != GPG_ERR_NO_PUBKEY)
	    log_error ("error reading key: %s\n", gpg_strerror (rc));
          else if (opt.verbose)
            log_info (_("key \"%s\" not found: %s\n"),
                      sl->d, gpg_strerror (rc));
	}
      else
	{
	  do
	    {
	      list_keyblock (ctrl, keyblock, 0, 0, opt.fingerprint, &listctx);
	      release_kbnode (keyblock);
	    }
	  while (ctx && !getkey_next (ctrl, ctx, NULL, &keyblock));
	  getkey_end (ctrl, ctx);
	  ctx = NULL;
	}
    }

  if (opt.check_sigs && !opt.with_colons)
    print_signature_stats (&listctx);

  keylist_context_release (&listctx);
}


static void
print_key_data (PKT_public_key * pk)
{
  int n = pk ? pubkey_get_npkey (pk->pubkey_algo) : 0;
  int i;

  for (i = 0; i < n; i++)
    {
      es_fprintf (es_stdout, "pkd:%d:%u:", i, mpi_get_nbits (pk->pkey[i]));
      mpi_print (es_stdout, pk->pkey[i], 1);
      es_putc (':', es_stdout);
      es_putc ('\n', es_stdout);
    }
}


/* Various public key screenings.  (Right now just ROCA).  With
 * COLON_MODE set the output is formatted for use in the compliance
 * field of a colon listing.
 */
static void
print_pk_screening (PKT_public_key *pk, int colon_mode)
{
  gpg_error_t err;

  if (is_RSA (pk->pubkey_algo) && pubkey_get_npkey (pk->pubkey_algo))
    {
      err = screen_key_for_roca (pk->pkey[0]);
      if (!err)
        ;
      else if (gpg_err_code (err) == GPG_ERR_TRUE)
        {
          if (colon_mode)
            es_fprintf (es_stdout, colon_mode > 1? " %d":"%d", 6001);
          else
            es_fprintf (es_stdout,
                        "      Screening: ROCA vulnerability detected\n");
        }
      else if (!colon_mode)
        es_fprintf (es_stdout, "      Screening: [ROCA check failed: %s]\n",
                    gpg_strerror (err));
    }

}


static void
print_capabilities (ctrl_t ctrl, PKT_public_key *pk, KBNODE keyblock)
{
  unsigned int use = pk->pubkey_usage;
  int c_printed = 0;

  if (use & PUBKEY_USAGE_ENC)
    es_putc ('e', es_stdout);

  if (use & PUBKEY_USAGE_SIG)
    {
      es_putc ('s', es_stdout);
      if (pk->flags.primary)
        {
          es_putc ('c', es_stdout);
          /* The PUBKEY_USAGE_CERT flag was introduced later and we
             used to always print 'c' for a primary key.  To avoid any
             regression here we better track whether we printed 'c'
             already.  */
          c_printed = 1;
        }
    }

  if ((use & PUBKEY_USAGE_CERT) && !c_printed)
    es_putc ('c', es_stdout);

  if ((use & PUBKEY_USAGE_AUTH))
    es_putc ('a', es_stdout);

  if (use & PUBKEY_USAGE_RENC)
    es_putc ('r', es_stdout);
  if ((use & PUBKEY_USAGE_TIME))
    es_putc ('t', es_stdout);
  if ((use & PUBKEY_USAGE_GROUP))
    es_putc ('g', es_stdout);

  if ((use & PUBKEY_USAGE_UNKNOWN))
    es_putc ('?', es_stdout);

  if (keyblock)
    {
      /* Figure out the usable capabilities.  */
      KBNODE k;
      int enc = 0, sign = 0, cert = 0, auth = 0, disabled = 0;

      for (k = keyblock; k; k = k->next)
	{
	  if (k->pkt->pkttype == PKT_PUBLIC_KEY
	      || k->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	    {
	      pk = k->pkt->pkt.public_key;

	      if (pk->flags.primary)
		disabled = pk_is_disabled (pk);

	      if (pk->flags.valid && !pk->flags.revoked && !pk->has_expired)
		{
		  if (pk->pubkey_usage & PUBKEY_USAGE_ENC)
		    enc = 1;
		  if (pk->pubkey_usage & PUBKEY_USAGE_SIG)
		    {
		      sign = 1;
		      if (pk->flags.primary)
			cert = 1;
		    }
		  if (pk->pubkey_usage & PUBKEY_USAGE_CERT)
		    cert = 1;
		  if ((pk->pubkey_usage & PUBKEY_USAGE_AUTH))
		    auth = 1;
		}
	    }
	}
      if (enc)
	es_putc ('E', es_stdout);
      if (sign)
	es_putc ('S', es_stdout);
      if (cert)
	es_putc ('C', es_stdout);
      if (auth)
	es_putc ('A', es_stdout);
      if (disabled)
	es_putc ('D', es_stdout);
    }

  es_putc (':', es_stdout);
}


/* FLAGS: 0x01 hashed
          0x02 critical  */
static void
print_one_subpacket (sigsubpkttype_t type, size_t len, int flags,
		     const byte * buf)
{
  size_t i;

  es_fprintf (es_stdout, "spk:%d:%u:%u:", type, flags, (unsigned int) len);

  for (i = 0; i < len; i++)
    {
      /* printable ascii other than : and % */
      if (buf[i] >= 32 && buf[i] <= 126 && buf[i] != ':' && buf[i] != '%')
	es_fprintf (es_stdout, "%c", buf[i]);
      else
	es_fprintf (es_stdout, "%%%02X", buf[i]);
    }

  es_fprintf (es_stdout, "\n");
}


void
print_subpackets_colon (PKT_signature * sig)
{
  byte *i;

  log_assert (opt.show_subpackets);

  for (i = opt.show_subpackets; *i; i++)
    {
      const byte *p;
      size_t len;
      int seq, crit;

      seq = 0;

      while ((p = enum_sig_subpkt (sig, 1, *i, &len, &seq, &crit)))
	print_one_subpacket (*i, len, 0x01 | (crit ? 0x02 : 0), p);

      seq = 0;

      while ((p = enum_sig_subpkt (sig, 0, *i, &len, &seq, &crit)))
	print_one_subpacket (*i, len, 0x00 | (crit ? 0x02 : 0), p);
    }
}


void
dump_attribs (const PKT_user_id *uid, PKT_public_key *pk)
{
  int i;

  if (!attrib_fp)
    return;

  for (i = 0; i < uid->numattribs; i++)
    {
      if (is_status_enabled ())
	{
	  byte array[MAX_FINGERPRINT_LEN], *p;
	  char buf[(MAX_FINGERPRINT_LEN * 2) + 90];
	  size_t j, n;

          if (!pk)
            BUG ();
          fingerprint_from_pk (pk, array, &n);

	  p = array;
	  for (j = 0; j < n; j++, p++)
	    sprintf (buf + 2 * j, "%02X", *p);

	  sprintf (buf + strlen (buf), " %lu %u %u %u %lu %lu %u",
		   (ulong) uid->attribs[i].len, uid->attribs[i].type, i + 1,
		   uid->numattribs, (ulong) uid->created,
		   (ulong) uid->expiredate,
		   ((uid->flags.primary ? 0x01 : 0) | (uid->flags.revoked ? 0x02 : 0) |
		    (uid->flags.expired ? 0x04 : 0)));
	  write_status_text (STATUS_ATTRIBUTE, buf);
	}

      es_fwrite (uid->attribs[i].data, uid->attribs[i].len, 1, attrib_fp);
      es_fflush (attrib_fp);
    }
}


/* Order two signatures.  We first order by keyid and then by creation
 * time.  */
int
cmp_signodes (const void *av, const void *bv)
{
  const kbnode_t an = *(const kbnode_t *)av;
  const kbnode_t bn = *(const kbnode_t *)bv;
  const PKT_signature *a;
  const PKT_signature *b;
  int i;

  /* log_assert (an->pkt->pkttype == PKT_SIGNATURE); */
  /* log_assert (bn->pkt->pkttype == PKT_SIGNATURE); */

  a = an->pkt->pkt.signature;
  b = bn->pkt->pkt.signature;

  /* Self-signatures are ordered first.  */
  if ((an->flag & NODFLG_MARK_B) && !(bn->flag & NODFLG_MARK_B))
    return -1;
  if (!(an->flag & NODFLG_MARK_B) && (bn->flag & NODFLG_MARK_B))
    return 1;

  /* then the keyids.  (which are or course the same for self-sigs). */
  i = keyid_cmp (a->keyid, b->keyid);
  if (i)
    return i;

  /* Followed by creation time */
  if (a->timestamp > b->timestamp)
    return 1;
  if (a->timestamp < b->timestamp)
    return -1;

  /* followed by the class in a way that a rev comes first.  */
  if (a->sig_class > b->sig_class)
    return 1;
  if (a->sig_class < b->sig_class)
    return -1;

  /* To make the sort stable we compare the entire structure as last resort.  */
  return memcmp (a, b, sizeof *a);
}


/* Helper for list_keyblock_print.  The caller must have set
 * NODFLG_MARK_B to indicate self-signatures.  */
static void
list_signature_print (ctrl_t ctrl, kbnode_t keyblock, kbnode_t node,
                      struct keylist_context *listctx)
{
          /* (extra indentation to keep the diff history short)  */
	  PKT_signature *sig = node->pkt->pkt.signature;
	  int rc, sigrc;
	  char *sigstr;
          char *reason_text = NULL;
          char *reason_comment = NULL;
          size_t reason_commentlen;
          int reason_code = 0;

	  if (listctx->check_sigs)
	    {
	      rc = check_key_signature (ctrl, keyblock, node, NULL);
	      switch (gpg_err_code (rc))
		{
		case 0:
		  listctx->good_sigs++;
		  sigrc = '!';
		  break;
		case GPG_ERR_BAD_SIGNATURE:
		  listctx->inv_sigs++;
		  sigrc = '-';
		  break;
		case GPG_ERR_NO_PUBKEY:
		case GPG_ERR_UNUSABLE_PUBKEY:
		  listctx->no_key++;
		  return;
                case GPG_ERR_DIGEST_ALGO:
                case GPG_ERR_PUBKEY_ALGO:
                  if (!(opt.list_options & LIST_SHOW_UNUSABLE_SIGS))
                    return;
                  /* fallthru. */
		default:
		  listctx->oth_err++;
		  sigrc = '%';
		  break;
		}

	      /* TODO: Make sure a cached sig record here still has
	         the pk that issued it.  See also
	         keyedit.c:print_and_check_one_sig */
	    }
	  else
	    {
              if (!(opt.list_options & LIST_SHOW_UNUSABLE_SIGS)
                  && (gpg_err_code (openpgp_pk_test_algo (sig->pubkey_algo)
                                    == GPG_ERR_PUBKEY_ALGO)
                      || gpg_err_code (openpgp_md_test_algo (sig->digest_algo)
                                       == GPG_ERR_DIGEST_ALGO)
                      || (sig->digest_algo == DIGEST_ALGO_SHA1
                          && !(node->flag & NODFLG_MARK_B) /*no selfsig*/
                          && !opt.flags.allow_weak_key_signatures)))
                return;
	      rc = 0;
	      sigrc = ' ';
	    }

	  if (sig->sig_class == 0x20 || sig->sig_class == 0x28
	      || sig->sig_class == 0x30)
            {
              sigstr = "rev";
              reason_code = get_revocation_reason (sig, &reason_text,
                                                   &reason_comment,
                                                   &reason_commentlen);
            }
	  else if ((sig->sig_class & ~3) == 0x10)
	    sigstr = "sig";
	  else if (sig->sig_class == 0x18)
	    sigstr = "sig";
	  else if (sig->sig_class == 0x1F)
	    sigstr = "sig";
	  else
	    {
	      es_fprintf (es_stdout, "sig                             "
		      "[unexpected signature class 0x%02x]\n",
		      sig->sig_class);
	      return;
	    }

	  es_fputs (sigstr, es_stdout);
	  es_fprintf (es_stdout, "%c%c %c%c%c%c%c%c %s %s",
		  sigrc, (sig->sig_class - 0x10 > 0 &&
			  sig->sig_class - 0x10 <
			  4) ? '0' + sig->sig_class - 0x10 : ' ',
		  sig->flags.exportable ? ' ' : 'L',
		  sig->flags.revocable ? ' ' : 'R',
		  sig->flags.policy_url ? 'P' : ' ',
		  sig->flags.notation ? 'N' : ' ',
		  sig->flags.expired ? 'X' : ' ',
		  (sig->trust_depth > 9) ? 'T' : (sig->trust_depth >
						  0) ? '0' +
		  sig->trust_depth : ' ', keystr (sig->keyid),
		  datestr_from_sig (sig));
	  if (opt.list_options & LIST_SHOW_SIG_EXPIRE)
	    es_fprintf (es_stdout, " %s", expirestr_from_sig (sig));
	  es_fprintf (es_stdout, "  ");
	  if (sigrc == '%')
	    es_fprintf (es_stdout, "[%s] ", gpg_strerror (rc));
	  else if (sigrc == '?')
	    ;
	  else if ((node->flag & NODFLG_MARK_B))
            es_fputs (_("[self-signature]"), es_stdout);
          else if (!opt.fast_list_mode )
	    {
	      size_t n;
	      char *p = get_user_id (ctrl, sig->keyid, &n, NULL);
	      print_utf8_buffer (es_stdout, p, n);
	      xfree (p);
	    }
	  es_putc ('\n', es_stdout);

	  if (sig->flags.policy_url
	      && (opt.list_options & LIST_SHOW_POLICY_URLS))
	    show_policy_url (sig, 3, 0);

	  if (sig->flags.notation && (opt.list_options & LIST_SHOW_NOTATIONS))
	    show_notation (sig, 3, 0,
			   ((opt.
			     list_options & LIST_SHOW_STD_NOTATIONS) ? 1 : 0)
			   +
			   ((opt.
			     list_options & LIST_SHOW_USER_NOTATIONS) ? 2 :
			    0));

	  if (sig->flags.pref_ks
	      && (opt.list_options & LIST_SHOW_KEYSERVER_URLS))
	    show_keyserver_url (sig, 3, 0);

          if (reason_text && (reason_code || reason_comment))
            {
              es_fprintf (es_stdout, "      %s%s\n",
                          _("reason for revocation: "), reason_text);
              if (reason_comment)
                {
                  const byte *s, *s_lf;
                  size_t n, n_lf;

                  s = reason_comment;
                  n = reason_commentlen;
                  s_lf = NULL;
                  do
                    {
                      /* We don't want any empty lines, so we skip them.  */
                      for (;n && *s == '\n'; s++, n--)
                        ;
                      if (n)
                        {
                          s_lf = memchr (s, '\n', n);
                          n_lf = s_lf? s_lf - s : n;
                          es_fprintf (es_stdout, "         %s",
                                      _("revocation comment: "));
                          es_write_sanitized (es_stdout, s, n_lf, NULL, NULL);
                          es_putc ('\n', es_stdout);
                          s += n_lf; n -= n_lf;
                        }
                    } while (s_lf);
                }
            }

          xfree (reason_text);
          xfree (reason_comment);

	  /* fixme: check or list other sigs here */
}


static void
list_keyblock_print (ctrl_t ctrl, kbnode_t keyblock, int secret, int fpr,
                     struct keylist_context *listctx)
{
  int rc;
  kbnode_t node;
  PKT_public_key *pk;
  u32 *mainkid;
  int skip_sigs = 0;
  char *hexgrip = NULL;
  char *serialno = NULL;

  /* Get the keyid from the keyblock.  */
  node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; key lost!\n");
      dump_kbnode (keyblock);
      return;
    }

  pk = node->pkt->pkt.public_key;
  mainkid = pk_keyid (pk);

  if (secret || opt.with_keygrip)
    {
      rc = hexkeygrip_from_pk (pk, &hexgrip);
      if (rc)
        log_error ("error computing a keygrip: %s\n", gpg_strerror (rc));
    }

  if (secret)
    {
      /* Encode some info about the secret key in SECRET.  */
      if (!agent_get_keyinfo (NULL, hexgrip, &serialno, NULL))
        secret = serialno? 3 : 1;
      else
        secret = 2;  /* Key not found.  */
    }

  if (!listctx->no_validity)
    check_trustdb_stale (ctrl);

  /* Print the "pub" line and in KF_NONE mode the fingerprint.  */
  print_key_line (ctrl, es_stdout, pk, secret);

  if (fpr)
    print_fingerprint (ctrl, NULL, pk, 0);

  if (opt.with_keygrip && hexgrip)
    es_fprintf (es_stdout, "      Keygrip = %s\n", hexgrip);

  if (serialno)
    print_card_serialno (serialno);

  if (opt.with_key_data)
    print_key_data (pk);

  if (opt.with_key_screening)
    print_pk_screening (pk, 0);

  if (opt.with_key_origin
      && (pk->keyorg || pk->keyupdate || pk->updateurl))
    {
      char updatestr[MK_DATESTR_SIZE];

      es_fprintf (es_stdout, "      origin=%s last=%s %s",
                  key_origin_string (pk->keyorg),
                  mk_datestr (updatestr, sizeof updatestr, pk->keyupdate),
                  pk->updateurl? "url=":"");
      if (pk->updateurl)
        print_utf8_string (es_stdout, pk->updateurl);
      es_putc ('\n', es_stdout);
    }

  print_revokers (es_stdout, 0, pk);

  for (node = keyblock; node; node = node->next)
    {
      if (is_deleted_kbnode (node))
        continue;

      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
          int indent;
          int kl = opt.keyid_format == KF_NONE? 10 : keystrlen ();

	  if ((uid->flags.expired || uid->flags.revoked)
	      && !(opt.list_options & LIST_SHOW_UNUSABLE_UIDS))
	    {
	      skip_sigs = 1;
	      continue;
	    }
	  else
	    skip_sigs = 0;

	  if (attrib_fp && uid->attrib_data != NULL)
	    dump_attribs (uid, pk);

	  if ((uid->flags.revoked || uid->flags.expired)
	      || ((opt.list_options & LIST_SHOW_UID_VALIDITY)
                  && !listctx->no_validity))
	    {
	      const char *validity;

	      validity = uid_trust_string_fixed (ctrl, pk, uid);
	      indent = ((kl + (opt.legacy_list_mode? 9:11))
                        - atoi (uid_trust_string_fixed (ctrl, NULL, NULL)));
	      if (indent < 0 || indent > 40)
		indent = 0;

	      es_fprintf (es_stdout, "uid%*s%s ", indent, "", validity);
	    }
	  else
            {
              indent = kl + (opt.legacy_list_mode? 10:12);
              es_fprintf (es_stdout, "uid%*s", indent, "");
            }

	  print_utf8_buffer (es_stdout, uid->name, uid->len);
	  es_putc ('\n', es_stdout);

          if ((opt.list_options & LIST_SHOW_PREF_VERBOSE))
            show_preferences (uid, indent+2, 0, 1);
          else if ((opt.list_options & LIST_SHOW_PREF))
            show_preferences (uid, indent+2, 0, 0);

          if (opt.with_wkd_hash)
            {
              char *mbox, *hash, *p;
              char hashbuf[32];

              mbox = mailbox_from_userid (uid->name, 0);
              if (mbox && (p = strchr (mbox, '@')))
                {
                  *p++ = 0;
                  gcry_md_hash_buffer (GCRY_MD_SHA1, hashbuf,
                                       mbox, strlen (mbox));
                  hash = zb32_encode (hashbuf, 8*20);
                  if (hash)
                    {
                      es_fprintf (es_stdout, "   %*s%s@%s\n",
                                  indent, "", hash, p);
                      xfree (hash);
                    }
                }
              xfree (mbox);
            }

          if (opt.with_key_origin
              && (uid->keyorg || uid->keyupdate || uid->updateurl))
            {
              char updatestr[MK_DATESTR_SIZE];

              es_fprintf (es_stdout, "   %*sorigin=%s last=%s %s",
                          indent, "",
                          key_origin_string (uid->keyorg),
                          mk_datestr (updatestr, sizeof updatestr,
                                      uid->keyupdate),
                          uid->updateurl? "url=":"");
              if (uid->updateurl)
                print_utf8_string (es_stdout, uid->updateurl);
              es_putc ('\n', es_stdout);
            }

	  if ((opt.list_options & LIST_SHOW_PHOTOS) && uid->attribs != NULL)
	    show_photos (ctrl, uid->attribs, uid->numattribs, pk, uid);
	}
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  PKT_public_key *pk2 = node->pkt->pkt.public_key;

	  if ((pk2->flags.revoked || pk2->has_expired)
	      && !(opt.list_options & LIST_SHOW_UNUSABLE_SUBKEYS))
	    {
	      skip_sigs = 1;
	      continue;
	    }
	  else
	    skip_sigs = 0;

          xfree (serialno); serialno = NULL;
          xfree (hexgrip); hexgrip = NULL;
          if (secret || opt.with_keygrip)
            {
              rc = hexkeygrip_from_pk (pk2, &hexgrip);
              if (rc)
                log_error ("error computing a keygrip: %s\n",
                           gpg_strerror (rc));
            }
          if (secret)
            {
              if (!agent_get_keyinfo (NULL, hexgrip, &serialno, NULL))
                secret = serialno? 3 : 1;
              else
                secret = 2;  /* Key not found.  */
            }

          /* Print the "sub" line.  */
          print_key_line (ctrl, es_stdout, pk2, secret);
	  if (fpr > 1 || opt.with_subkey_fingerprint)
            {
              print_fingerprint (ctrl, NULL, pk2, 0);
              if (serialno)
                print_card_serialno (serialno);
            }
          if (opt.with_keygrip && hexgrip)
            es_fprintf (es_stdout, "      Keygrip = %s\n", hexgrip);
	  if (opt.with_key_data)
	    print_key_data (pk2);
          if (opt.with_key_screening)
            print_pk_screening (pk2, 0);
	}
      else if (opt.list_sigs
	       && node->pkt->pkttype == PKT_SIGNATURE && !skip_sigs)
	{
          kbnode_t n;
          unsigned int sigcount = 0;
          kbnode_t *sigarray;
          unsigned int idx;

          for (n=node; n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
            sigcount++;
          sigarray = xcalloc (sigcount, sizeof *sigarray);

          sigcount = 0;
          for (n=node; n && n->pkt->pkttype == PKT_SIGNATURE; n = n->next)
            {
              if (keyid_eq (mainkid, n->pkt->pkt.signature->keyid))
                n->flag |= NODFLG_MARK_B;  /* Is a self-sig.  */
              else
                n->flag &= ~NODFLG_MARK_B;

              sigarray[sigcount++] = node = n;
            }
          /* Note that NODE is now at the last signature.  */

          if ((opt.list_options & LIST_SORT_SIGS))
            qsort (sigarray, sigcount, sizeof *sigarray, cmp_signodes);

          for (idx=0; idx < sigcount; idx++)
            list_signature_print (ctrl, keyblock, sigarray[idx], listctx);
          xfree (sigarray);
	}
    }
  es_putc ('\n', es_stdout);
  xfree (serialno);
  xfree (hexgrip);
}


/* Do a simple key listing printing only the fingerprint and the mail
 * address of valid keys.  */
static void
list_keyblock_simple (ctrl_t ctrl, kbnode_t keyblock)
{
  gpg_err_code_t ec;
  kbnode_t kbctx;
  kbnode_t node;
  char hexfpr[2*MAX_FINGERPRINT_LEN+1];
  char *mbox;

  (void)ctrl;

  node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; key lost!\n");
      dump_kbnode (keyblock);
      return;
    }
  hexfingerprint (node->pkt->pkt.public_key, hexfpr, sizeof hexfpr);

  for (kbctx = NULL; (node = walk_kbnode (keyblock, &kbctx, 0));)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;

	  if (uid->attrib_data)
	    continue;

	  if ((uid->flags.expired || uid->flags.revoked)
              && !(opt.list_options & LIST_SHOW_UNUSABLE_UIDS))
            continue;

          mbox = mailbox_from_userid (uid->name, 0);
          if (!mbox)
            {
              ec = gpg_err_code_from_syserror ();
              if (ec != GPG_ERR_EINVAL)
                log_error ("error getting mailbox from user-id: %s\n",
                           gpg_strerror (ec));
              continue;
            }
          es_fprintf (es_stdout, "%s %s\n", hexfpr, mbox);
          xfree (mbox);
	}
    }
}


/* Print the revoker records. */
void
print_revokers (estream_t fp, int colon_mode, PKT_public_key * pk)
{
  int i, j;
  const byte *p;

  if (!pk->revkey && pk->numrevkeys)
    BUG ();

  for (i = 0; i < pk->numrevkeys; i++)
    {
      if (colon_mode)
        {
          es_fprintf (fp, "rvk:::%d::::::", pk->revkey[i].algid);
          p = pk->revkey[i].fpr;
          for (j = 0; j < pk->revkey[i].fprlen; j++, p++)
            es_fprintf (fp, "%02X", *p);
          es_fprintf (fp, ":%02x%s:\n",
                      pk->revkey[i].class,
                      (pk->revkey[i].class & 0x40) ? "s" : "");
        }
      else
        {
          es_fprintf (fp, "%*s%s", 6, "", _("Revocable by: "));
          p = pk->revkey[i].fpr;
          es_write_hexstring (fp, pk->revkey[i].fpr, pk->revkey[i].fprlen,
                              0, NULL);
          if ((pk->revkey[i].class & 0x40))
            es_fprintf (fp, " %s", _("(sensitive)"));
          /* Class bit 7 must always be set, bit 6 indicates sensitive
           * and all others bits are reserved.  */
          if (!(pk->revkey[i].class & ~0x40)
              || (pk->revkey[i].class & ~(0x40|0x80)))
            es_fprintf (fp, " (unknown class %02x)", pk->revkey[i].class);
	  es_fprintf (fp, "\n");
        }
    }
}


/* Print the compliance flags to field 18.  PK is the public key.
 * KEYLENGTH is the length of the key in bits and CURVENAME is either
 * NULL or the name of the curve.  The latter two args are here
 * merely because the caller has already computed them.  */
static void
print_compliance_flags (PKT_public_key *pk,
                        unsigned int keylength, const char *curvename)
{
  int any = 0;

  if (!keylength)
    keylength = nbits_from_pk (pk);

  if (pk->version == 5)
    {
      es_fputs (gnupg_status_compliance_flag (CO_GNUPG), es_stdout);
      any++;
    }
  if (gnupg_pk_is_compliant (CO_DE_VS, pk->pubkey_algo, 0, pk->pkey,
			     keylength, curvename))
    {
      es_fprintf (es_stdout, any ? " %s" : "%s",
		  gnupg_status_compliance_flag (CO_DE_VS));
      any++;
    }

  if (opt.with_key_screening)
    print_pk_screening (pk, 1+any);
}


/* List a key in colon mode.  If SECRET is true this is a secret key
   record (i.e. requested via --list-secret-key).  If HAS_SECRET a
   secret key is available even if SECRET is not set.  */
static void
list_keyblock_colon (ctrl_t ctrl, kbnode_t keyblock,
                     int secret, int has_secret)
{
  int rc;
  KBNODE kbctx;
  KBNODE node;
  PKT_public_key *pk;
  u32 keyid[2];
  int trustletter = 0;
  int trustletter_print;
  int ownertrust_print;
  int ulti_hack = 0;
  int i;
  char *hexgrip_buffer = NULL;
  const char *hexgrip = NULL;
  char *serialno = NULL;
  int stubkey;
  unsigned int keylength;
  char *curve = NULL;
  const char *curvename = NULL;

  /* Get the keyid from the keyblock.  */
  node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; key lost!\n");
      dump_kbnode (keyblock);
      return;
    }

  pk = node->pkt->pkt.public_key;
  if (secret || has_secret || opt.with_keygrip || opt.with_key_data)
    {
      rc = hexkeygrip_from_pk (pk, &hexgrip_buffer);
      if (rc)
        log_error ("error computing a keygrip: %s\n", gpg_strerror (rc));
      /* In the error case we print an empty string so that we have a
       * "grp" record for each primary and subkey - even if it is
       * empty.  This may help to prevent sync problems.  */
      hexgrip = hexgrip_buffer? hexgrip_buffer : "";
    }
  stubkey = 0;
  if ((secret || has_secret)
      && agent_get_keyinfo (NULL, hexgrip, &serialno, NULL))
    stubkey = 1;  /* Key not found.  */

  keyid_from_pk (pk, keyid);
  if (!pk->flags.valid)
    trustletter_print = 'i';
  else if (pk->flags.revoked)
    trustletter_print = 'r';
  else if (pk->has_expired)
    trustletter_print = 'e';
  else if (opt.fast_list_mode || opt.no_expensive_trust_checks)
    trustletter_print = 0;
  else
    {
      trustletter = get_validity_info (ctrl, keyblock, pk, NULL);
      if (trustletter == 'u')
        ulti_hack = 1;
      trustletter_print = trustletter;
    }

  if (!opt.fast_list_mode && !opt.no_expensive_trust_checks)
    ownertrust_print = get_ownertrust_info (ctrl, pk, 0);
  else
    ownertrust_print = 0;

  keylength = nbits_from_pk (pk);

  es_fputs (secret? "sec:":"pub:", es_stdout);
  if (trustletter_print)
    es_putc (trustletter_print, es_stdout);
  es_fprintf (es_stdout, ":%u:%d:%08lX%08lX:%s:%s::",
              keylength,
              pk->pubkey_algo,
              (ulong) keyid[0], (ulong) keyid[1],
              colon_datestr_from_pk (pk), colon_strtime (pk->expiredate));

  if (ownertrust_print)
    es_putc (ownertrust_print, es_stdout);
  es_putc (':', es_stdout);

  es_putc (':', es_stdout);
  es_putc (':', es_stdout);
  print_capabilities (ctrl, pk, keyblock);
  es_putc (':', es_stdout);		/* End of field 13. */
  es_putc (':', es_stdout);		/* End of field 14. */
  if (secret || has_secret)
    {
      if (stubkey)
	es_putc ('#', es_stdout);
      else if (serialno)
        es_fputs (serialno, es_stdout);
      else if (has_secret)
        es_putc ('+', es_stdout);
    }
  es_putc (':', es_stdout);		/* End of field 15. */
  es_putc (':', es_stdout);		/* End of field 16. */
  if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA
      || pk->pubkey_algo == PUBKEY_ALGO_EDDSA
      || pk->pubkey_algo == PUBKEY_ALGO_ECDH)
    {
      curve = openpgp_oid_to_str (pk->pkey[0]);
      curvename = openpgp_oid_to_curve (curve, 0);
      if (!curvename)
        curvename = curve;
      es_fputs (curvename, es_stdout);
    }
  es_putc (':', es_stdout);		/* End of field 17. */
  print_compliance_flags (pk, keylength, curvename);
  es_putc (':', es_stdout);		/* End of field 18 (compliance). */
  if (pk->keyupdate)
    es_fputs (colon_strtime (pk->keyupdate), es_stdout);
  es_putc (':', es_stdout);		/* End of field 19 (last_update). */
  es_fprintf (es_stdout, "%d%s", pk->keyorg, pk->updateurl? " ":"");
  if (pk->updateurl)
    es_write_sanitized (es_stdout, pk->updateurl, strlen (pk->updateurl),
                        ":", NULL);
  es_putc (':', es_stdout);		/* End of field 20 (origin). */
  es_putc ('\n', es_stdout);

  print_revokers (es_stdout, 1, pk);
  print_fingerprint (ctrl, NULL, pk, 0);
  if (hexgrip)
    es_fprintf (es_stdout, "grp:::::::::%s:\n", hexgrip);
  if (opt.with_key_data)
    print_key_data (pk);

  for (kbctx = NULL; (node = walk_kbnode (keyblock, &kbctx, 0));)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
          int uid_validity;

	  if (attrib_fp && uid->attrib_data != NULL)
	    dump_attribs (uid, pk);

	  if (uid->flags.revoked)
	    uid_validity = 'r';
	  else if (uid->flags.expired)
	    uid_validity = 'e';
	  else if (opt.no_expensive_trust_checks)
	    uid_validity = 0;
	  else if (ulti_hack)
            uid_validity = 'u';
          else
            uid_validity = get_validity_info (ctrl, keyblock, pk, uid);

          es_fputs (uid->attrib_data? "uat:":"uid:", es_stdout);
          if (uid_validity)
            es_putc (uid_validity, es_stdout);
          es_fputs ("::::", es_stdout);

	  es_fprintf (es_stdout, "%s:", colon_strtime (uid->created));
	  es_fprintf (es_stdout, "%s:", colon_strtime (uid->expiredate));

	  namehash_from_uid (uid);

	  for (i = 0; i < 20; i++)
	    es_fprintf (es_stdout, "%02X", uid->namehash[i]);

	  es_fprintf (es_stdout, "::");

	  if (uid->attrib_data)
	    es_fprintf (es_stdout, "%u %lu", uid->numattribs, uid->attrib_len);
	  else
	    es_write_sanitized (es_stdout, uid->name, uid->len, ":", NULL);
	  es_fputs (":::::::::", es_stdout);
          if (uid->keyupdate)
            es_fputs (colon_strtime (uid->keyupdate), es_stdout);
          es_putc (':', es_stdout);	/* End of field 19 (last_update). */
          es_fprintf (es_stdout, "%d%s", uid->keyorg, uid->updateurl? " ":"");
          if (uid->updateurl)
            es_write_sanitized (es_stdout,
                                uid->updateurl, strlen (uid->updateurl),
                                ":", NULL);
          es_putc (':', es_stdout);	/* End of field 20 (origin). */
	  es_putc ('\n', es_stdout);
#ifdef USE_TOFU
	  if (!uid->attrib_data && opt.with_tofu_info
              && (opt.trust_model == TM_TOFU || opt.trust_model == TM_TOFU_PGP))
	    {
              /* Print a "tfs" record.  */
              tofu_write_tfs_record (ctrl, es_stdout, pk, uid->name);
	    }
#endif /*USE_TOFU*/
	}
      else if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  u32 keyid2[2];
	  PKT_public_key *pk2;
          int need_hexgrip = !!hexgrip;

          pk2 = node->pkt->pkt.public_key;
          xfree (hexgrip_buffer); hexgrip_buffer = NULL; hexgrip = NULL;
          xfree (serialno); serialno = NULL;
          if (need_hexgrip
              || secret || has_secret || opt.with_keygrip || opt.with_key_data)
            {
              rc = hexkeygrip_from_pk (pk2, &hexgrip_buffer);
              if (rc)
                log_error ("error computing a keygrip: %s\n",
                           gpg_strerror (rc));
              hexgrip = hexgrip_buffer? hexgrip_buffer : "";
            }
          stubkey = 0;
          if ((secret||has_secret)
              && agent_get_keyinfo (NULL, hexgrip, &serialno, NULL))
            stubkey = 1;  /* Key not found.  */

	  keyid_from_pk (pk2, keyid2);
	  es_fputs (secret? "ssb:":"sub:", es_stdout);
	  if (!pk2->flags.valid)
	    es_putc ('i', es_stdout);
	  else if (pk2->flags.revoked)
	    es_putc ('r', es_stdout);
	  else if (pk2->has_expired)
	    es_putc ('e', es_stdout);
	  else if (opt.fast_list_mode || opt.no_expensive_trust_checks)
	    ;
	  else
	    {
	      /* TRUSTLETTER should always be defined here. */
	      if (trustletter)
		es_fprintf (es_stdout, "%c", trustletter);
	    }
          keylength = nbits_from_pk (pk2);
	  es_fprintf (es_stdout, ":%u:%d:%08lX%08lX:%s:%s:::::",
                      keylength,
                      pk2->pubkey_algo,
                      (ulong) keyid2[0], (ulong) keyid2[1],
                      colon_datestr_from_pk (pk2),
                      colon_strtime (pk2->expiredate));
	  print_capabilities (ctrl, pk2, NULL);
          es_putc (':', es_stdout);	/* End of field 13. */
          es_putc (':', es_stdout);	/* End of field 14. */
          if (secret || has_secret)
            {
              if (stubkey)
                es_putc ('#', es_stdout);
              else if (serialno)
                es_fputs (serialno, es_stdout);
              else if (has_secret)
                es_putc ('+', es_stdout);
            }
          es_putc (':', es_stdout);	/* End of field 15. */
          es_putc (':', es_stdout);	/* End of field 16. */
          if (pk2->pubkey_algo == PUBKEY_ALGO_ECDSA
              || pk2->pubkey_algo == PUBKEY_ALGO_EDDSA
              || pk2->pubkey_algo == PUBKEY_ALGO_ECDH)
            {
              xfree (curve);
              curve = openpgp_oid_to_str (pk2->pkey[0]);
              curvename = openpgp_oid_to_curve (curve, 0);
              if (!curvename)
                curvename = curve;
              es_fputs (curvename, es_stdout);
            }
          es_putc (':', es_stdout);	/* End of field 17. */
          print_compliance_flags (pk2, keylength, curvename);
          es_putc (':', es_stdout);	/* End of field 18. */
	  es_putc ('\n', es_stdout);
          print_fingerprint (ctrl, NULL, pk2, 0);
          if (hexgrip)
            es_fprintf (es_stdout, "grp:::::::::%s:\n", hexgrip);
          if (opt.with_key_data)
            print_key_data (pk2);
	}
      else if (opt.list_sigs && node->pkt->pkttype == PKT_SIGNATURE)
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  int sigrc, fprokay = 0;
	  char *sigstr;
	  size_t fplen;
	  byte fparray[MAX_FINGERPRINT_LEN];
          char *siguid;
          size_t siguidlen;
          char *issuer_fpr = NULL;
          char *reason_text = NULL;
          char *reason_comment = NULL;
          size_t reason_commentlen;
          int reason_code = 0;  /* Init to silence compiler warning.  */

	  if (sig->sig_class == 0x20 || sig->sig_class == 0x28
	      || sig->sig_class == 0x30)
            {
              sigstr = "rev";
              reason_code = get_revocation_reason (sig, &reason_text,
                                                   &reason_comment,
                                                   &reason_commentlen);
            }
	  else if ((sig->sig_class & ~3) == 0x10)
	    sigstr = "sig";
	  else if (sig->sig_class == 0x18)
	    sigstr = "sig";
	  else if (sig->sig_class == 0x1F)
	    sigstr = "sig";
	  else
	    {
	      es_fprintf (es_stdout, "sig::::::::::%02x%c:\n",
		      sig->sig_class, sig->flags.exportable ? 'x' : 'l');
	      continue;
	    }

	  if (opt.check_sigs)
	    {
	      PKT_public_key *signer_pk = NULL;

	      es_fflush (es_stdout);
	      if (opt.no_sig_cache)
		signer_pk = xmalloc_clear (sizeof (PKT_public_key));

	      rc = check_key_signature2 (ctrl, keyblock, node, NULL, signer_pk,
					 NULL, NULL, NULL);
	      switch (gpg_err_code (rc))
		{
		case 0:
		  sigrc = '!';
		  break;
		case GPG_ERR_BAD_SIGNATURE:
		  sigrc = '-';
		  break;
		case GPG_ERR_NO_PUBKEY:
		case GPG_ERR_UNUSABLE_PUBKEY:
		  sigrc = '?';
		  break;
		default:
		  sigrc = '%';
		  break;
		}

	      if (opt.no_sig_cache)
		{
		  if (!rc)
		    {
		      fingerprint_from_pk (signer_pk, fparray, &fplen);
		      fprokay = 1;
		    }
		  free_public_key (signer_pk);
		}
	    }
	  else
	    {
	      rc = 0;
	      sigrc = ' '; /* Note the fix-up below in --list-sigs mode.  */
	    }

	  if (sigrc != '%' && sigrc != '?' && !opt.fast_list_mode)
            {
              int nouid;
              siguid = get_user_id (ctrl, sig->keyid, &siguidlen, &nouid);
              if (!opt.check_sigs && nouid)
                sigrc = '?';  /* No key in local keyring.  */
            }
          else
            {
              siguid = NULL;
              siguidlen = 0;
            }


	  es_fputs (sigstr, es_stdout);
	  es_putc (':', es_stdout);
	  if (sigrc != ' ')
	    es_putc (sigrc, es_stdout);
	  es_fprintf (es_stdout, "::%d:%08lX%08lX:%s:%s:", sig->pubkey_algo,
		  (ulong) sig->keyid[0], (ulong) sig->keyid[1],
		  colon_datestr_from_sig (sig),
		  colon_expirestr_from_sig (sig));

	  if (sig->trust_depth || sig->trust_value)
	    es_fprintf (es_stdout, "%d %d", sig->trust_depth, sig->trust_value);
	  es_fprintf (es_stdout, ":");

	  if (sig->trust_regexp)
	    es_write_sanitized (es_stdout, sig->trust_regexp,
                                strlen (sig->trust_regexp), ":", NULL);
	  es_fprintf (es_stdout, ":");

	  if (sigrc == '%')
	    es_fprintf (es_stdout, "[%s] ", gpg_strerror (rc));
	  else if (siguid)
            es_write_sanitized (es_stdout, siguid, siguidlen, ":", NULL);

	  es_fprintf (es_stdout, ":%02x%c", sig->sig_class,
                      sig->flags.exportable ? 'x' : 'l');
          if (reason_text)
            es_fprintf (es_stdout, ",%02x", reason_code);
          es_fputs ("::", es_stdout);

	  if (opt.no_sig_cache && opt.check_sigs && fprokay)
	    {
	      for (i = 0; i < fplen; i++)
		es_fprintf (es_stdout, "%02X", fparray[i]);
	    }
          else if ((issuer_fpr = issuer_fpr_string (sig)))
            es_fputs (issuer_fpr, es_stdout);

	  es_fprintf (es_stdout, ":::%d:", sig->digest_algo);

          if (reason_comment)
            {
              es_fputs ("::::", es_stdout);
              es_write_sanitized (es_stdout, reason_comment, reason_commentlen,
                                  ":", NULL);
              es_putc (':', es_stdout);
            }
          es_putc ('\n', es_stdout);

	  if (opt.show_subpackets)
	    print_subpackets_colon (sig);

	  /* fixme: check or list other sigs here */
          xfree (reason_text);
          xfree (reason_comment);
          xfree (siguid);
          xfree (issuer_fpr);
	}
    }

  xfree (curve);
  xfree (hexgrip_buffer);
  xfree (serialno);
}

/*
 * Reorder the keyblock so that the primary user ID (and not attribute
 * packet) comes first.  Fixme: Replace this by a generic sort
 * function.  */
static void
do_reorder_keyblock (KBNODE keyblock, int attr)
{
  KBNODE primary = NULL, primary0 = NULL, primary2 = NULL;
  KBNODE last, node;

  for (node = keyblock; node; primary0 = node, node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID &&
	  ((attr && node->pkt->pkt.user_id->attrib_data) ||
	   (!attr && !node->pkt->pkt.user_id->attrib_data)) &&
	  node->pkt->pkt.user_id->flags.primary)
	{
	  primary = primary2 = node;
	  for (node = node->next; node; primary2 = node, node = node->next)
	    {
	      if (node->pkt->pkttype == PKT_USER_ID
		  || node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		  || node->pkt->pkttype == PKT_SECRET_SUBKEY)
		{
		  break;
		}
	    }
	  break;
	}
    }
  if (!primary)
    return; /* No primary key flag found (should not happen).  */

  for (last = NULL, node = keyblock; node; last = node, node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
	break;
    }
  log_assert (node);
  log_assert (last);	 /* The user ID is never the first packet.  */
  log_assert (primary0); /* Ditto (this is the node before primary).  */
  if (node == primary)
    return; /* Already the first one.  */

  last->next = primary;
  primary0->next = primary2->next;
  primary2->next = node;
}

void
reorder_keyblock (KBNODE keyblock)
{
  do_reorder_keyblock (keyblock, 1);
  do_reorder_keyblock (keyblock, 0);
}


static void
list_keyblock (ctrl_t ctrl,
               KBNODE keyblock, int secret, int has_secret, int fpr,
               struct keylist_context *listctx)
{
  reorder_keyblock (keyblock);

  if (list_filter.selkey)
    {
      int selected = 0;
      struct impex_filter_parm_s parm;
      parm.ctrl = ctrl;

      for (parm.node = keyblock; parm.node; parm.node = parm.node->next)
        {
          if (recsel_select (list_filter.selkey, impex_filter_getval, &parm))
            {
              selected = 1;
              break;
            }
        }
      if (!selected)
        return;  /* Skip this one.  */
    }

  if (opt.with_colons)
    list_keyblock_colon (ctrl, keyblock, secret, has_secret);
  else if ((opt.list_options & LIST_SHOW_ONLY_FPR_MBOX))
    {
      if (!listctx->no_validity)
        check_trustdb_stale (ctrl);
      list_keyblock_simple (ctrl, keyblock);
    }
  else
    list_keyblock_print (ctrl, keyblock, secret, fpr, listctx);

  if (secret)
    es_fflush (es_stdout);
}


/* Public function used by keygen to list a keyblock.  If NO_VALIDITY
 * is set the validity of a key is never shown.  */
void
list_keyblock_direct (ctrl_t ctrl,
                      kbnode_t keyblock, int secret, int has_secret, int fpr,
                      int no_validity)
{
  struct keylist_context listctx;

  memset (&listctx, 0, sizeof (listctx));
  listctx.no_validity = !!no_validity;
  list_keyblock (ctrl, keyblock, secret, has_secret, fpr, &listctx);
  keylist_context_release (&listctx);
}


/* Print an hex digit in ICAO spelling.  */
static void
print_icao_hexdigit (estream_t fp, int c)
{
  static const char *list[16] = {
    "Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven",
    "Eight", "Niner", "Alfa", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot"
  };

  tty_fprintf (fp, "%s", list[c&15]);
}


/*
 * Function to print the finperprint.
 * mode 0: as used in key listings, opt.with_colons is honored
 *      1: print using log_info ()
 *      2: direct use of tty
 *      3: direct use of tty but only primary key.
 *      4: direct use of tty but only subkey.
 *     10: Same as 0 but with_colons etc is ignored.
 *     20: Same as 0 but using a compact format.
 *
 * Modes 1 and 2 will try and print both subkey and primary key
 * fingerprints.  A MODE with bit 7 set is used internally.  If
 * OVERRIDE_FP is not NULL that stream will be used in  0 instead
 * of es_stdout or instead of the TTY in modes 2 and 3.
 */
void
print_fingerprint (ctrl_t ctrl, estream_t override_fp,
                   PKT_public_key *pk, int mode)
{
  char hexfpr[2*MAX_FINGERPRINT_LEN+1];
  char *p;
  size_t i;
  estream_t fp;
  const char *text;
  int primary = 0;
  int with_colons = opt.with_colons;
  int with_icao   = opt.with_icao_spelling;
  int compact = 0;

  if (mode == 10)
    {
      mode = 0;
      with_colons = 0;
      with_icao = 0;
    }
  else if (mode == 20)
    {
      mode = 0;
      with_colons = 0;
      compact = 1;
    }

  if (!opt.fingerprint && !opt.with_fingerprint
      && opt.with_subkey_fingerprint)
    compact = 1;

  if (pk->main_keyid[0] == pk->keyid[0]
      && pk->main_keyid[1] == pk->keyid[1])
    primary = 1;

  /* Just to be safe */
  if ((mode & 0x80) && !primary)
    {
      log_error ("primary key is not really primary!\n");
      return;
    }

  mode &= ~0x80;

  if (!primary && (mode == 1 || mode == 2))
    {
      PKT_public_key *primary_pk = xmalloc_clear (sizeof (*primary_pk));
      get_pubkey (ctrl, primary_pk, pk->main_keyid);
      print_fingerprint (ctrl, override_fp, primary_pk, (mode | 0x80));
      free_public_key (primary_pk);
    }

  if (mode == 1)
    {
      fp = log_get_stream ();
      if (primary)
	text = _("Primary key fingerprint:");
      else
	text = _("     Subkey fingerprint:");
    }
  else if (mode == 2)
    {
      fp = override_fp; /* Use tty or given stream.  */
      if (primary)
	/* TRANSLATORS: this should fit into 24 bytes so that the
	 * fingerprint data is properly aligned with the user ID */
	text = _(" Primary key fingerprint:");
      else
	text = _("      Subkey fingerprint:");
    }
  else if (mode == 3)
    {
      fp = override_fp; /* Use tty or given stream.  */
      text = _("      Key fingerprint =");
    }
  else if (mode == 4)
    {
      fp = override_fp; /* Use tty or given stream.  */
      text = _("      Subkey fingerprint:");
    }
  else
    {
      fp = override_fp? override_fp : es_stdout;
      if (opt.keyid_format == KF_NONE)
        {
          text = "     ";  /* To indent ICAO spelling.  */
          compact = 1;
        }
      else
        text = _("      Key fingerprint =");
    }

  hexfingerprint (pk, hexfpr, sizeof hexfpr);
  if (with_colons && !mode)
    {
      es_fprintf (fp, "fpr:::::::::%s:", hexfpr);
      if (opt.with_v5_fingerprint && pk->version == 4)
        {
          char *v5fpr = v5hexfingerprint (pk, NULL, 0);
          es_fprintf (fp, "\nfp2:::::::::%s:", v5fpr);
          xfree (v5fpr);
        }
    }
  else if (compact && !opt.fingerprint && !opt.with_fingerprint)
    {
      tty_fprintf (fp, "%*s%s", 6, "", hexfpr);
    }
  else
    {
      char fmtfpr[MAX_FORMATTED_FINGERPRINT_LEN + 1];
      format_hexfingerprint (hexfpr, fmtfpr, sizeof fmtfpr);
      if (compact)
        tty_fprintf (fp, "%*s%s", 6, "", fmtfpr);
      else
        tty_fprintf (fp, "%s %s", text, fmtfpr);
    }
  tty_fprintf (fp, "\n");
  if (!with_colons && with_icao)
    {
      ;
      tty_fprintf (fp, "%*s\"", (int)strlen(text)+1, "");
      for (i = 0, p = hexfpr; *p; i++, p++)
        {
          if (!i)
            ;
          else if (!(i%10))
            tty_fprintf (fp, "\n%*s ", (int)strlen(text)+1, "");
          else if (!(i%5))
            tty_fprintf (fp, "  ");
          else
            tty_fprintf (fp, " ");
          print_icao_hexdigit (fp, xtoi_1 (p));
        }
      tty_fprintf (fp, "\"\n");
    }
}

/* Print the serial number of an OpenPGP card if available.  */
static void
print_card_serialno (const char *serialno)
{
  if (!serialno)
    return;
  if (opt.with_colons)
    return; /* Handled elsewhere. */

  es_fputs (_("      Card serial no. ="), es_stdout);
  es_putc (' ', es_stdout);
  if (strlen (serialno) == 32 && !strncmp (serialno, "D27600012401", 12))
    {
      /* This is an OpenPGP card.  Print the relevant part.  */
      /* Example: D2760001240101010001000003470000 */
      /*                          xxxxyyyyyyyy     */
      es_fprintf (es_stdout, "%.*s %.*s", 4, serialno+16, 8, serialno+20);
    }
 else
   es_fputs (serialno, es_stdout);
  es_putc ('\n', es_stdout);
}


/* Print a public or secret (sub)key line.  Example:
 *
 * pub   dsa2048 2007-12-31 [SC] [expires: 2018-12-31]
 *       80615870F5BAD690333686D0F2AD85AC1E42B367
 *
 * pub   rsa2048 2017-12-31 [SC] [expires: 2028-12-31]
 *       80615870F5BAD690333686D0F2AD85AC1E42B3671122334455
 *
 * Some global options may result in a different output format.  If
 * SECRET is set, "sec" or "ssb" is used instead of "pub" or "sub" and
 * depending on the value a flag character is shown:
 *
 *    1 := ' ' Regular secret key
 *    2 := '#' Stub secret key
 *    3 := '>' Secret key is on a token.
 */
void
print_key_line (ctrl_t ctrl, estream_t fp, PKT_public_key *pk, int secret)
{
  char pkstrbuf[PUBKEY_STRING_SIZE];

  tty_fprintf (fp, "%s%c  %s",
               pk->flags.primary? (secret? "sec":"pub")
               /**/             : (secret? "ssb":"sub"),
               secret == 2? '#' : secret == 3? '>' : ' ',
               pubkey_string (pk, pkstrbuf, sizeof pkstrbuf));
  if (opt.keyid_format != KF_NONE)
    tty_fprintf (fp, "/%s", keystr_from_pk (pk));
  tty_fprintf (fp, " %s", datestr_from_pk (pk));

  if (pk->flags.primary
      && !(openpgp_pk_algo_usage (pk->pubkey_algo)
           & (PUBKEY_USAGE_CERT| PUBKEY_USAGE_SIG|PUBKEY_USAGE_AUTH)))
    {
      /* A primary key which is really not capable to sign.  */
      tty_fprintf (fp, " [INVALID_ALGO]");
    }
  else if ((opt.list_options & LIST_SHOW_USAGE))
    {
      tty_fprintf (fp, " [%s]", usagestr_from_pk (pk, 0));
    }

  if (pk->flags.primary && (opt.list_options & LIST_SHOW_OWNERTRUST))
    {
      tty_fprintf (fp, " [%s]", get_ownertrust_string (ctrl, pk, 0));
    }

  if (pk->flags.revoked)
    {
      tty_fprintf (fp, " [");
      tty_fprintf (fp, _("revoked: %s"), revokestr_from_pk (pk));
      tty_fprintf (fp, "]");
    }
  else if (pk->has_expired)
    {
      tty_fprintf (fp, " [");
      tty_fprintf (fp, _("expired: %s"), expirestr_from_pk (pk));
      tty_fprintf (fp, "]");
    }
  else if (pk->expiredate)
    {
      tty_fprintf (fp, " [");
      tty_fprintf (fp, _("expires: %s"), expirestr_from_pk (pk));
      tty_fprintf (fp, "]");
    }

  if (pk->pubkey_algo >= 100)
    tty_fprintf (fp, " [experimental algorithm %d]", pk->pubkey_algo);

  tty_fprintf (fp, "\n");

  if (pk->flags.primary && pk_is_disabled (pk))
    es_fprintf (es_stdout, "      *** %s\n", _("This key has been disabled"));

  /* if the user hasn't explicitly asked for human-readable
     fingerprints, show compact fpr of primary key: */
  if (pk->flags.primary &&
      !opt.fingerprint && !opt.with_fingerprint)
    print_fingerprint (ctrl, fp, pk, 20);
}


void
set_attrib_fd (int fd)
{
  static int last_fd = -1;

  if (fd != -1 && last_fd == fd)
    return;

  /* Fixme: Do we need to check for the log stream here?  */
  if (attrib_fp && attrib_fp != log_get_stream ())
    es_fclose (attrib_fp);
  attrib_fp = NULL;
  if (fd == -1)
    return;

  if (! gnupg_fd_valid (fd))
    log_fatal ("attribute-fd is invalid: %s\n", strerror (errno));

#ifdef HAVE_DOSISH_SYSTEM
  setmode (fd, O_BINARY);
#endif
  if (fd == 1)
    attrib_fp = es_stdout;
  else if (fd == 2)
    attrib_fp = es_stderr;
  else
    attrib_fp = es_fdopen (fd, "wb");
  if (!attrib_fp)
    {
      log_fatal ("can't open fd %d for attribute output: %s\n",
		 fd, strerror (errno));
    }

  last_fd = fd;
}
