/* export.c - Export keys in the OpenPGP defined format.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2010 Free Software Foundation, Inc.
 * Copyright (C) 1998-2016  Werner Koch
 * Copyright (C) 2022 g10 Code GmbH
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
#include "main.h"
#include "../common/i18n.h"
#include "../common/membuf.h"
#include "../common/host2net.h"
#include "../common/zb32.h"
#include "../common/recsel.h"
#include "../common/mbox-util.h"
#include "../common/init.h"
#include "trustdb.h"
#include "call-agent.h"
#include "key-clean.h"
#include "pkglue.h"


/* An object to keep track of subkeys. */
struct subkey_list_s
{
  struct subkey_list_s *next;
  u32 kid[2];
};
typedef struct subkey_list_s *subkey_list_t;


/* An object to track statistics for export operations.  */
struct export_stats_s
{
  ulong count;            /* Number of processed keys.        */
  ulong secret_count;     /* Number of secret keys seen.      */
  ulong exported;         /* Number of actual exported keys.  */
};


/* Global variables to store the selectors created from
 * --export-filter keep-uid=EXPR.
 * --export-filter drop-subkey=EXPR.
 * --export-filter select=EXPR.
 *
 * FIXME: We should put this into the CTRL object but that requires a
 * lot more changes right now.
 */
static recsel_expr_t export_keep_uid;
static recsel_expr_t export_drop_subkey;
static recsel_expr_t export_select_filter;


/* An object used for a linked list to implement the
 * push_export_filter/pop_export_filters functions.  */
struct export_filter_attic_s
{
  struct export_filter_attic_s *next;
  recsel_expr_t export_keep_uid;
  recsel_expr_t export_drop_subkey;
  recsel_expr_t export_select_filter;
};
static struct export_filter_attic_s *export_filter_attic;



/* Local prototypes.  */
static int do_export (ctrl_t ctrl, strlist_t users, int secret,
                      unsigned int options, export_stats_t stats);
static int do_export_stream (ctrl_t ctrl, iobuf_t out,
                             strlist_t users, int secret,
                             kbnode_t *keyblock_out, unsigned int options,
			     export_stats_t stats, int *any);
static gpg_error_t print_dane_records
/**/                 (iobuf_t out, kbnode_t keyblock, PKT_public_key *pk,
                      const void *data, size_t datalen);


static void
cleanup_export_globals (void)
{
  recsel_release (export_keep_uid);
  export_keep_uid = NULL;
  recsel_release (export_drop_subkey);
  export_drop_subkey = NULL;
  recsel_release (export_select_filter);
  export_select_filter = NULL;
}


/* Option parser for export options.  See parse_options for
   details.  */
int
parse_export_options(char *str,unsigned int *options,int noisy)
{
  struct parse_options export_opts[]=
    {
      {"export-local-sigs",EXPORT_LOCAL_SIGS,NULL,
       N_("export signatures that are marked as local-only")},
      {"export-attributes",EXPORT_ATTRIBUTES,NULL,
       N_("export attribute user IDs (generally photo IDs)")},
      {"export-sensitive-revkeys",EXPORT_SENSITIVE_REVKEYS,NULL,
       N_("export revocation keys marked as \"sensitive\"")},
      {"export-clean",EXPORT_CLEAN,NULL,
       N_("remove unusable parts from key during export")},
      {"export-realclean",EXPORT_MINIMAL|EXPORT_REALCLEAN|EXPORT_CLEAN,NULL,
       NULL},
      {"export-minimal",EXPORT_MINIMAL|EXPORT_CLEAN,NULL,
       N_("remove as much as possible from key during export")},

      {"export-dane", EXPORT_DANE_FORMAT, NULL, NULL },

      {"export-revocs", EXPORT_REVOCS, NULL,
       N_("export only revocation certificates") },

      {"backup", EXPORT_BACKUP, NULL,
       N_("use the GnuPG key backup format")},
      {"export-backup", EXPORT_BACKUP, NULL, NULL },

      {"mode1003", EXPORT_MODE1003, NULL,
       N_("export secret keys using the GnuPG format") },

      /* Aliases for backward compatibility */
      {"include-local-sigs",EXPORT_LOCAL_SIGS,NULL,NULL},
      {"include-attributes",EXPORT_ATTRIBUTES,NULL,NULL},
      {"include-sensitive-revkeys",EXPORT_SENSITIVE_REVKEYS,NULL,NULL},
      /* dummy */
      {"export-unusable-sigs",0,NULL,NULL},
      {"export-clean-sigs",0,NULL,NULL},
      {"export-clean-uids",0,NULL,NULL},
      {NULL,0,NULL,NULL}
      /* add tags for include revoked and disabled? */
    };
  int rc;

  rc = parse_options (str, options, export_opts, noisy);
  if (!rc)
    return 0;

  /* Alter other options we want or don't want for restore.  */
  if ((*options & EXPORT_BACKUP))
    {
      *options |= (EXPORT_LOCAL_SIGS | EXPORT_ATTRIBUTES
                   | EXPORT_SENSITIVE_REVKEYS);
      *options &= ~(EXPORT_CLEAN | EXPORT_MINIMAL | EXPORT_REALCLEAN
                    | EXPORT_DANE_FORMAT);
    }

  return rc;
}


/* Parse and set an export filter from string.  STRING has the format
 * "NAME=EXPR" with NAME being the name of the filter.  Spaces before
 * and after NAME are not allowed.  If this function is called several
 * times all expressions for the same NAME are concatenated.
 * Supported filter names are:
 *
 *  - keep-uid :: If the expression evaluates to true for a certain
 *                user ID packet, that packet and all it dependencies
 *                will be exported.  The expression may use these
 *                variables:
 *
 *                - uid  :: The entire user ID.
 *                - mbox :: The mail box part of the user ID.
 *                - primary :: Evaluate to true for the primary user ID.
 *
 *  - drop-subkey :: If the expression evaluates to true for a subkey
 *                packet that subkey and all it dependencies will be
 *                remove from the keyblock.  The expression may use these
 *                variables:
 *
 *                - secret   :: 1 for a secret subkey, else 0.
 *                - key_algo :: Public key algorithm id
 *
 *  - select :: The key is only exported if the filter returns true.
 */
gpg_error_t
parse_and_set_export_filter (const char *string)
{
  gpg_error_t err;

  /* Auto register the cleanup function.  */
  register_mem_cleanup_func (cleanup_export_globals);

  if (!strncmp (string, "keep-uid=", 9))
    err = recsel_parse_expr (&export_keep_uid, string+9);
  else if (!strncmp (string, "drop-subkey=", 12))
    err = recsel_parse_expr (&export_drop_subkey, string+12);
  else if (!strncmp (string, "select=", 7))
    err = recsel_parse_expr (&export_select_filter, string+7);
  else
    err = gpg_error (GPG_ERR_INV_NAME);

  return err;
}


/* Push the current export filters onto a stack so that new export
 * filters can be defined which will be active until the next
 * pop_export_filters or another push_export_filters.  */
void
push_export_filters (void)
{
  struct export_filter_attic_s *item;

  item = xcalloc (1, sizeof *item);
  item->export_keep_uid = export_keep_uid;
  export_keep_uid = NULL;
  item->export_drop_subkey = export_drop_subkey;
  export_drop_subkey = NULL;
  item->export_select_filter = export_select_filter;
  export_select_filter = NULL;
  item->next = export_filter_attic;
  export_filter_attic = item;
}


/* Revert the last push_export_filters.  */
void
pop_export_filters (void)
{
  struct export_filter_attic_s *item;

  item = export_filter_attic;
  if (!item)
    BUG (); /* No corresponding push.  */
  export_filter_attic = item->next;
  cleanup_export_globals ();
  export_keep_uid = item->export_keep_uid;
  export_drop_subkey = item->export_drop_subkey;
  export_select_filter = item->export_select_filter;
}



/* Create a new export stats object initialized to zero.  On error
   returns NULL and sets ERRNO.  */
export_stats_t
export_new_stats (void)
{
  export_stats_t stats;

  return xtrycalloc (1, sizeof *stats);
}


/* Release an export stats object.  */
void
export_release_stats (export_stats_t stats)
{
  xfree (stats);
}


/* Print export statistics using the status interface.  */
void
export_print_stats (export_stats_t stats)
{
  if (!stats)
    return;

  if (is_status_enabled ())
    {
      char buf[15*20];

      snprintf (buf, sizeof buf, "%lu %lu %lu",
		stats->count,
		stats->secret_count,
		stats->exported );
      write_status_text (STATUS_EXPORT_RES, buf);
    }
}


/*
 * Export public keys (to stdout or to --output FILE).
 *
 * Depending on opt.armor the output is armored.  OPTIONS are defined
 * in main.h.  If USERS is NULL, all keys will be exported.  STATS is
 * either an export stats object for update or NULL.
 *
 * This function is the core of "gpg --export".
 */
int
export_pubkeys (ctrl_t ctrl, strlist_t users, unsigned int options,
                export_stats_t stats)
{
  return do_export (ctrl, users, 0, options, stats);
}


/*
 * Export secret keys (to stdout or to --output FILE).
 *
 * Depending on opt.armor the output is armored.  OPTIONS are defined
 * in main.h.  If USERS is NULL, all secret keys will be exported.
 * STATS is either an export stats object for update or NULL.
 *
 * This function is the core of "gpg --export-secret-keys".
 */
int
export_seckeys (ctrl_t ctrl, strlist_t users, unsigned int options,
                export_stats_t stats)
{
  return do_export (ctrl, users, 1, options, stats);
}


/*
 * Export secret sub keys (to stdout or to --output FILE).
 *
 * This is the same as export_seckeys but replaces the primary key by
 * a stub key.  Depending on opt.armor the output is armored.  OPTIONS
 * are defined in main.h.  If USERS is NULL, all secret subkeys will
 * be exported.  STATS is either an export stats object for update or
 * NULL.
 *
 * This function is the core of "gpg --export-secret-subkeys".
 */
int
export_secsubkeys (ctrl_t ctrl, strlist_t users, unsigned int options,
                   export_stats_t stats)
{
  return do_export (ctrl, users, 2, options, stats);
}


/*
 * Export a single key into a memory buffer.  STATS is either an
 * export stats object for update or NULL.  If PREFIX is not NULL
 * PREFIXLEN bytes from PREFIX are prepended to the R_DATA.
 */
gpg_error_t
export_pubkey_buffer (ctrl_t ctrl, const char *keyspec, unsigned int options,
                      const void *prefix, size_t prefixlen,
                      export_stats_t stats,
                      kbnode_t *r_keyblock, void **r_data, size_t *r_datalen)
{
  gpg_error_t err;
  iobuf_t iobuf;
  int any;
  strlist_t helplist;

  *r_keyblock = NULL;
  *r_data = NULL;
  *r_datalen = 0;

  helplist = NULL;
  if (!add_to_strlist_try (&helplist, keyspec))
    return gpg_error_from_syserror ();

  iobuf = iobuf_temp ();
  if (prefix && prefixlen)
    iobuf_write (iobuf, prefix, prefixlen);
  err = do_export_stream (ctrl, iobuf, helplist, 0, r_keyblock, options,
                          stats, &any);
  if (!err && !any)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  if (!err)
    {
      const void *src;
      size_t datalen;

      iobuf_flush_temp (iobuf);
      src = iobuf_get_temp_buffer (iobuf);
      datalen = iobuf_get_temp_length (iobuf);
      if (!datalen)
        err = gpg_error (GPG_ERR_NO_PUBKEY);
      else if (!(*r_data = xtrymalloc (datalen)))
        err = gpg_error_from_syserror ();
      else
        {
          memcpy (*r_data, src, datalen);
          *r_datalen = datalen;
        }
    }
  iobuf_close (iobuf);
  free_strlist (helplist);
  if (err && *r_keyblock)
    {
      release_kbnode (*r_keyblock);
      *r_keyblock = NULL;
    }
  return err;
}


/* Export the keys identified by the list of strings in USERS.  If
   Secret is false public keys will be exported.  With secret true
   secret keys will be exported; in this case 1 means the entire
   secret keyblock and 2 only the subkeys.  OPTIONS are the export
   options to apply.  */
static int
do_export (ctrl_t ctrl, strlist_t users, int secret, unsigned int options,
           export_stats_t stats)
{
  IOBUF out = NULL;
  int any, rc;
  armor_filter_context_t *afx = NULL;
  compress_filter_context_t zfx;

  memset( &zfx, 0, sizeof zfx);

  rc = open_outfile (-1, NULL, 0, !!secret, &out );
  if (rc)
    return rc;

  if ( opt.armor && !(options & EXPORT_DANE_FORMAT) )
    {
      afx = new_armor_context ();
      afx->what = secret? 5 : 1;
      push_armor_filter (afx, out);
    }

  rc = do_export_stream (ctrl, out, users, secret, NULL, options, stats, &any);

  if ( rc || !any )
    iobuf_cancel (out);
  else
    iobuf_close (out);
  release_armor_context (afx);
  return rc;
}



/* Release an entire subkey list. */
static void
release_subkey_list (subkey_list_t list)
{
  while (list)
    {
      subkey_list_t tmp = list->next;;
      xfree (list);
      list = tmp;
    }
}


/* Returns true if NODE is a subkey and contained in LIST. */
static int
subkey_in_list_p (subkey_list_t list, KBNODE node)
{
  if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
      || node->pkt->pkttype == PKT_SECRET_SUBKEY )
    {
      u32 kid[2];

      keyid_from_pk (node->pkt->pkt.public_key, kid);

      for (; list; list = list->next)
        if (list->kid[0] == kid[0] && list->kid[1] == kid[1])
          return 1;
    }
  return 0;
}

/* Allocate a new subkey list item from NODE. */
static subkey_list_t
new_subkey_list_item (KBNODE node)
{
  subkey_list_t list = xcalloc (1, sizeof *list);

  if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
      || node->pkt->pkttype == PKT_SECRET_SUBKEY)
    keyid_from_pk (node->pkt->pkt.public_key, list->kid);

  return list;
}


/* Helper function to check whether the subkey at NODE actually
   matches the description at DESC.  The function returns true if the
   key under question has been specified by an exact specification
   (keyID or fingerprint) and does match the one at NODE.  It is
   assumed that the packet at NODE is either a public or secret
   subkey. */
int
exact_subkey_match_p (KEYDB_SEARCH_DESC *desc, kbnode_t node)
{
  u32 kid[2];
  byte fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  int result = 0;

  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_SHORT_KID:
    case KEYDB_SEARCH_MODE_LONG_KID:
      keyid_from_pk (node->pkt->pkt.public_key, kid);
      break;

    case KEYDB_SEARCH_MODE_FPR:
      fingerprint_from_pk (node->pkt->pkt.public_key, fpr, &fprlen);
      break;

    default:
      break;
    }

  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_SHORT_KID:
      if (desc->u.kid[1] == kid[1])
        result = 1;
      break;

    case KEYDB_SEARCH_MODE_LONG_KID:
      if (desc->u.kid[0] == kid[0] && desc->u.kid[1] == kid[1])
        result = 1;
      break;

    case KEYDB_SEARCH_MODE_FPR:
      if (fprlen == desc->fprlen && !memcmp (desc->u.fpr, fpr, desc->fprlen))
        result = 1;
      break;

    default:
      break;
    }

  return result;
}


/* Return an error if the key represented by the S-expression S_KEY
 * and the OpenPGP key represented by PK do not use the same curve. */
static gpg_error_t
match_curve_skey_pk (gcry_sexp_t s_key, PKT_public_key *pk)
{
  gcry_sexp_t curve = NULL;
  gcry_sexp_t flags = NULL;
  char *curve_str = NULL;
  char *flag;
  const char *oidstr = NULL;
  gcry_mpi_t curve_as_mpi = NULL;
  gpg_error_t err;
  int is_eddsa = 0;
  int idx = 0;

  if (!(pk->pubkey_algo==PUBKEY_ALGO_ECDH
        || pk->pubkey_algo==PUBKEY_ALGO_ECDSA
        || pk->pubkey_algo==PUBKEY_ALGO_EDDSA))
    return gpg_error (GPG_ERR_PUBKEY_ALGO);

  curve = gcry_sexp_find_token (s_key, "curve", 0);
  if (!curve)
    {
      log_error ("no reported curve\n");
      return gpg_error (GPG_ERR_UNKNOWN_CURVE);
    }
  curve_str = gcry_sexp_nth_string (curve, 1);
  gcry_sexp_release (curve); curve = NULL;
  if (!curve_str)
    {
      log_error ("no curve name\n");
      return gpg_error (GPG_ERR_UNKNOWN_CURVE);
    }
  if (!strcmp (curve_str, "Ed448"))
    is_eddsa = 1;
  oidstr = openpgp_curve_to_oid (curve_str, NULL, NULL);
  if (!oidstr)
    {
      log_error ("no OID known for curve '%s'\n", curve_str);
      xfree (curve_str);
      return gpg_error (GPG_ERR_UNKNOWN_CURVE);
    }
  xfree (curve_str);
  err = openpgp_oid_from_str (oidstr, &curve_as_mpi);
  if (err)
    return err;
  if (gcry_mpi_cmp (pk->pkey[0], curve_as_mpi))
    {
      log_error ("curves do not match\n");
      gcry_mpi_release (curve_as_mpi);
      return gpg_error (GPG_ERR_INV_CURVE);
    }
  gcry_mpi_release (curve_as_mpi);
  flags = gcry_sexp_find_token (s_key, "flags", 0);
  if (flags)
    {
      for (idx = 1; idx < gcry_sexp_length (flags); idx++)
        {
          flag = gcry_sexp_nth_string (flags, idx);
          if (flag && (strcmp ("eddsa", flag) == 0))
            is_eddsa = 1;
          gcry_free (flag);
        }
    }
  if (is_eddsa != (pk->pubkey_algo == PUBKEY_ALGO_EDDSA))
    {
      log_error ("disagreement about EdDSA\n");
      err = gpg_error (GPG_ERR_INV_CURVE);
    }

  return err;
}


/* Return a canonicalized public key algorithms.  This is used to
   compare different flavors of algorithms (e.g. ELG and ELG_E are
   considered the same).  */
static enum gcry_pk_algos
canon_pk_algo (enum gcry_pk_algos algo)
{
  switch (algo)
    {
    case GCRY_PK_RSA:
    case GCRY_PK_RSA_E:
    case GCRY_PK_RSA_S: return GCRY_PK_RSA;
    case GCRY_PK_ELG:
    case GCRY_PK_ELG_E: return GCRY_PK_ELG;
    case GCRY_PK_ECC:
    case GCRY_PK_ECDSA:
    case GCRY_PK_ECDH: return GCRY_PK_ECC;
    default: return algo;
    }
}


/* Take an s-expression with the public and private key and change the
 * parameter array in PK to include the secret parameters.  */
static gpg_error_t
secret_key_to_mode1003 (gcry_sexp_t s_key, PKT_public_key *pk)
{
  gpg_error_t err;
  gcry_sexp_t list = NULL;
  gcry_sexp_t l2;
  enum gcry_pk_algos pk_algo;
  struct seckey_info *ski;
  int idx;
  char *string;
  size_t npkey, nskey;
  gcry_mpi_t pub_params[10] = { NULL };

  /* We look for a private-key, then the first element in it tells us
     the type */
  list = gcry_sexp_find_token (s_key, "protected-private-key", 0);
  if (!list)
    list = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!list)
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  log_assert (!pk->seckey_info);

  /* Parse the gcrypt PK algo and check that it is okay.  */
  l2 = gcry_sexp_cadr (list);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }
  gcry_sexp_release (list);
  list = l2;
  string = gcry_sexp_nth_string (list, 0);
  if (!string)
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }
  pk_algo = gcry_pk_map_name (string);
  xfree (string); string = NULL;
  if (gcry_pk_algo_info (pk_algo, GCRYCTL_GET_ALGO_NPKEY, NULL, &npkey)
      || gcry_pk_algo_info (pk_algo, GCRYCTL_GET_ALGO_NSKEY, NULL, &nskey)
      || !npkey || npkey >= nskey)
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  /* Check that the pubkey algo and the received parameters matches
   * those from the public key.  */
  switch (canon_pk_algo (pk_algo))
    {
    case GCRY_PK_RSA:
      if (!is_RSA (pk->pubkey_algo) || npkey != 2)
        err = gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Does not match.  */
      else
        err = gcry_sexp_extract_param (list, NULL, "ne",
                                       &pub_params[0],
                                       &pub_params[1],
                                       NULL);
      break;

    case GCRY_PK_DSA:
      if (!is_DSA (pk->pubkey_algo) || npkey != 4)
        err = gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Does not match.  */
      else
        err = gcry_sexp_extract_param (list, NULL, "pqgy",
                                       &pub_params[0],
                                       &pub_params[1],
                                       &pub_params[2],
                                       &pub_params[3],
                                       NULL);
      break;

    case GCRY_PK_ELG:
      if (!is_ELGAMAL (pk->pubkey_algo) || npkey != 3)
        err = gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Does not match.  */
      else
        err = gcry_sexp_extract_param (list, NULL, "pgy",
                                       &pub_params[0],
                                       &pub_params[1],
                                       &pub_params[2],
                                       NULL);
      break;

    case GCRY_PK_ECC:
      err = 0;
      if (!(pk->pubkey_algo == PUBKEY_ALGO_ECDSA
            || pk->pubkey_algo == PUBKEY_ALGO_ECDH
            || pk->pubkey_algo == PUBKEY_ALGO_EDDSA))
        {
          err = gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Does not match.  */
          goto leave;
        }
      npkey = 2;
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDH)
        npkey++;
      /* Dedicated check of the curve.  */
      pub_params[0] = NULL;
      err = match_curve_skey_pk (list, pk);
      if (err)
        goto leave;
      /* ... and of the Q parameter.  */
      err = sexp_extract_param_sos (list, "q", &pub_params[1]);
      if (!err && (gcry_mpi_cmp (pk->pkey[1], pub_params[1])))
        err = gpg_error (GPG_ERR_BAD_PUBKEY);
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Unknown.  */
      break;
    }
  if (err)
    goto leave;

  nskey = npkey + 1;  /* We only have one skey param.  */
  if (nskey > PUBKEY_MAX_NSKEY)
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  /* Check that the public key parameters match.  For ECC we already
   * did this in the switch above.  */
  if (canon_pk_algo (pk_algo) != GCRY_PK_ECC)
    {
      for (idx=0; idx < npkey; idx++)
        if (gcry_mpi_cmp (pk->pkey[idx], pub_params[idx]))
          {
            err = gpg_error (GPG_ERR_BAD_PUBKEY);
            goto leave;
          }
    }

  /* Store the maybe protected secret key as an s-expression.  */
  pk->seckey_info = ski = xtrycalloc (1, sizeof *ski);
  if (!ski)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  pk->seckey_info = ski = xtrycalloc (1, sizeof *ski);
  if (!ski)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  ski->is_protected = 1;
  ski->s2k.mode = 1003;

  {
    unsigned char *buf;
    size_t buflen;

    err = make_canon_sexp (s_key, &buf, &buflen);
    if (err)
      goto leave;
    pk->pkey[npkey] = gcry_mpi_set_opaque (NULL, buf, buflen*8);
    for (idx=npkey+1; idx < PUBKEY_MAX_NSKEY; idx++)
      pk->pkey[idx] = NULL;
  }

 leave:
  gcry_sexp_release (list);
  for (idx=0; idx < DIM(pub_params); idx++)
    gcry_mpi_release (pub_params[idx]);
  return err;
}


/* Take a cleartext dump of a secret key in PK and change the
 * parameter array in PK to include the secret parameters.  */
static gpg_error_t
cleartext_secret_key_to_openpgp (gcry_sexp_t s_key, PKT_public_key *pk)
{
  gpg_error_t err;
  gcry_sexp_t top_list;
  gcry_sexp_t key = NULL;
  char *key_type = NULL;
  enum gcry_pk_algos pk_algo;
  struct seckey_info *ski;
  int idx, sec_start;
  gcry_mpi_t pub_params[10] = { NULL };

  /* we look for a private-key, then the first element in it tells us
     the type */
  top_list = gcry_sexp_find_token (s_key, "private-key", 0);
  if (!top_list)
    goto bad_seckey;

  /* ignore all S-expression after the first sublist -- we assume that
     they are comments or otherwise irrelevant to OpenPGP */
  if (gcry_sexp_length(top_list) < 2)
    goto bad_seckey;
  key = gcry_sexp_nth (top_list, 1);
  if (!key)
    goto bad_seckey;
  key_type = gcry_sexp_nth_string(key, 0);
  pk_algo = gcry_pk_map_name (key_type);

  log_assert (!pk->seckey_info);

  pk->seckey_info = ski = xtrycalloc (1, sizeof *ski);
  if (!ski)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  switch (canon_pk_algo (pk_algo))
    {
    case GCRY_PK_RSA:
      if (!is_RSA (pk->pubkey_algo))
        goto bad_pubkey_algo;
      err = gcry_sexp_extract_param (key, NULL, "ne",
                                     &pub_params[0],
                                     &pub_params[1],
                                     NULL);
      for (idx=0; idx < 2 && !err; idx++)
        if (gcry_mpi_cmp(pk->pkey[idx], pub_params[idx]))
          err = gpg_error (GPG_ERR_BAD_PUBKEY);
      if (!err)
        {
          for (idx = 2; idx < 6 && !err; idx++)
            {
              gcry_mpi_release (pk->pkey[idx]);
              pk->pkey[idx] = NULL;
            }
          err = gcry_sexp_extract_param (key, NULL, "dpqu",
                                         &pk->pkey[2],
                                         &pk->pkey[3],
                                         &pk->pkey[4],
                                         &pk->pkey[5],
                                         NULL);
        }
      if (!err)
        {
          for (idx = 2; idx < 6; idx++)
            ski->csum += checksum_mpi (pk->pkey[idx]);
        }
      break;

    case GCRY_PK_DSA:
      if (!is_DSA (pk->pubkey_algo))
        goto bad_pubkey_algo;
      err = gcry_sexp_extract_param (key, NULL, "pqgy",
                                     &pub_params[0],
                                     &pub_params[1],
                                     &pub_params[2],
                                     &pub_params[3],
                                     NULL);
      for (idx=0; idx < 4 && !err; idx++)
        if (gcry_mpi_cmp(pk->pkey[idx], pub_params[idx]))
          err = gpg_error (GPG_ERR_BAD_PUBKEY);
      if (!err)
        {
          gcry_mpi_release (pk->pkey[4]);
          pk->pkey[4] = NULL;
          err = gcry_sexp_extract_param (key, NULL, "x",
                                         &pk->pkey[4],
                                         NULL);
        }
      if (!err)
        ski->csum += checksum_mpi (pk->pkey[4]);
      break;

    case GCRY_PK_ELG:
      if (!is_ELGAMAL (pk->pubkey_algo))
        goto bad_pubkey_algo;
      err = gcry_sexp_extract_param (key, NULL, "pgy",
                                     &pub_params[0],
                                     &pub_params[1],
                                     &pub_params[2],
                                     NULL);
      for (idx=0; idx < 3 && !err; idx++)
        if (gcry_mpi_cmp(pk->pkey[idx], pub_params[idx]))
          err = gpg_error (GPG_ERR_BAD_PUBKEY);
      if (!err)
        {
          gcry_mpi_release (pk->pkey[3]);
          pk->pkey[3] = NULL;
          err = gcry_sexp_extract_param (key, NULL, "x",
                                         &pk->pkey[3],
                                         NULL);
        }
      if (!err)
        ski->csum += checksum_mpi (pk->pkey[3]);
      break;

    case GCRY_PK_ECC:
      err = match_curve_skey_pk (key, pk);
      if (err)
        goto leave;
      else
        err = sexp_extract_param_sos (key, "q", &pub_params[0]);
      if (!err && (gcry_mpi_cmp(pk->pkey[1], pub_params[0])))
        err = gpg_error (GPG_ERR_BAD_PUBKEY);

      sec_start = 2;
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDH)
        sec_start += 1;
      if (!err)
        {
          gcry_mpi_release (pk->pkey[sec_start]);
          pk->pkey[sec_start] = NULL;
          err = sexp_extract_param_sos (key, "d", &pk->pkey[sec_start]);
        }

      if (!err)
        ski->csum += checksum_mpi (pk->pkey[sec_start]);
      break;

    default:
      pk->seckey_info = NULL;
      xfree (ski);
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;
    }

 leave:
  gcry_sexp_release (top_list);
  gcry_sexp_release (key);
  gcry_free (key_type);

  for (idx=0; idx < DIM(pub_params); idx++)
    gcry_mpi_release (pub_params[idx]);
  return err;

 bad_pubkey_algo:
  err = gpg_error (GPG_ERR_PUBKEY_ALGO);
  goto leave;

 bad_seckey:
  err = gpg_error (GPG_ERR_BAD_SECKEY);
  goto leave;
}


/* Use the key transfer format given in S_PGP to create the secinfo
   structure in PK and change the parameter array in PK to include the
   secret parameters.  */
static gpg_error_t
transfer_format_to_openpgp (gcry_sexp_t s_pgp, PKT_public_key *pk)
{
  gpg_error_t err;
  gcry_sexp_t top_list;
  gcry_sexp_t list = NULL;
  char *curve = NULL;
  const char *value;
  size_t valuelen;
  char *string;
  int  idx;
  int  is_v4, is_protected;
  enum gcry_pk_algos pk_algo;
  int  protect_algo = 0;
  char iv[16];
  int  ivlen = 0;
  int  s2k_mode = 0;
  int  s2k_algo = 0;
  byte s2k_salt[8];
  u32  s2k_count = 0;
  int  is_ecdh = 0;
  size_t npkey, nskey;
  gcry_mpi_t skey[10];  /* We support up to 9 parameters.  */
  int skeyidx = 0;
  struct seckey_info *ski;

  /* gcry_log_debugsxp ("transferkey", s_pgp); */
  top_list = gcry_sexp_find_token (s_pgp, "openpgp-private-key", 0);
  if (!top_list)
    goto bad_seckey;

  list = gcry_sexp_find_token (top_list, "version", 0);
  if (!list)
    goto bad_seckey;
  value = gcry_sexp_nth_data (list, 1, &valuelen);
  if (!value || valuelen != 1 || !(value[0] == '3' || value[0] == '4'))
    goto bad_seckey;
  is_v4 = (value[0] == '4');

  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "protection", 0);
  if (!list)
    goto bad_seckey;
  value = gcry_sexp_nth_data (list, 1, &valuelen);
  if (!value)
    goto bad_seckey;
  if (valuelen == 4 && !memcmp (value, "sha1", 4))
    is_protected = 2;
  else if (valuelen == 3 && !memcmp (value, "sum", 3))
    is_protected = 1;
  else if (valuelen == 4 && !memcmp (value, "none", 4))
    is_protected = 0;
  else
    goto bad_seckey;
  if (is_protected)
    {
      string = gcry_sexp_nth_string (list, 2);
      if (!string)
        goto bad_seckey;
      protect_algo = gcry_cipher_map_name (string);
      xfree (string);

      value = gcry_sexp_nth_data (list, 3, &valuelen);
      if (!value || !valuelen || valuelen > sizeof iv)
        goto bad_seckey;
      memcpy (iv, value, valuelen);
      ivlen = valuelen;

      string = gcry_sexp_nth_string (list, 4);
      if (!string)
        goto bad_seckey;
      s2k_mode = strtol (string, NULL, 10);
      xfree (string);

      string = gcry_sexp_nth_string (list, 5);
      if (!string)
        goto bad_seckey;
      s2k_algo = gcry_md_map_name (string);
      xfree (string);

      value = gcry_sexp_nth_data (list, 6, &valuelen);
      if (!value || !valuelen || valuelen > sizeof s2k_salt)
        goto bad_seckey;
      memcpy (s2k_salt, value, valuelen);

      string = gcry_sexp_nth_string (list, 7);
      if (!string)
        goto bad_seckey;
      s2k_count = strtoul (string, NULL, 10);
      xfree (string);
    }

  /* Parse the gcrypt PK algo and check that it is okay.  */
  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "algo", 0);
  if (!list)
    goto bad_seckey;
  string = gcry_sexp_nth_string (list, 1);
  if (!string)
    goto bad_seckey;
  pk_algo = gcry_pk_map_name (string);
  xfree (string); string = NULL;
  if (gcry_pk_algo_info (pk_algo, GCRYCTL_GET_ALGO_NPKEY, NULL, &npkey)
      || gcry_pk_algo_info (pk_algo, GCRYCTL_GET_ALGO_NSKEY, NULL, &nskey)
      || !npkey || npkey >= nskey)
    goto bad_seckey;

  /* Check that the pubkey algo matches the one from the public key.  */
  switch (canon_pk_algo (pk_algo))
    {
    case GCRY_PK_RSA:
      if (!is_RSA (pk->pubkey_algo))
        pk_algo = 0;  /* Does not match.  */
      break;
    case GCRY_PK_DSA:
      if (!is_DSA (pk->pubkey_algo))
        pk_algo = 0;  /* Does not match.  */
      break;
    case GCRY_PK_ELG:
      if (!is_ELGAMAL (pk->pubkey_algo))
        pk_algo = 0;  /* Does not match.  */
      break;
    case GCRY_PK_ECC:
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA)
        ;
      else if (pk->pubkey_algo == PUBKEY_ALGO_ECDH)
        is_ecdh = 1;
      else if (pk->pubkey_algo == PUBKEY_ALGO_EDDSA)
        ;
      else
        pk_algo = 0;  /* Does not match.  */
      /* For ECC we do not have the domain parameters thus fix our info.  */
      npkey = 1;
      nskey = 2;
      break;
    default:
      pk_algo = 0;   /* Oops.  */
      break;
    }
  if (!pk_algo)
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  /* This check has to go after the ecc adjustments. */
  if (nskey > PUBKEY_MAX_NSKEY)
    goto bad_seckey;

  /* Parse the key parameters.  */
  gcry_sexp_release (list);
  list = gcry_sexp_find_token (top_list, "skey", 0);
  if (!list)
    goto bad_seckey;
  for (idx=0;;)
    {
      int is_enc;

      value = gcry_sexp_nth_data (list, ++idx, &valuelen);
      if (!value && skeyidx >= npkey)
        break;  /* Ready.  */

      /* Check for too many parameters.  Note that depending on the
         protection mode and version number we may see less than NSKEY
         (but at least NPKEY+1) parameters.  */
      if (idx >= 2*nskey)
        goto bad_seckey;
      if (skeyidx >= DIM (skey)-1)
        goto bad_seckey;

      if (!value || valuelen != 1 || !(value[0] == '_' || value[0] == 'e'))
        goto bad_seckey;
      is_enc = (value[0] == 'e');
      value = gcry_sexp_nth_data (list, ++idx, &valuelen);
      if (!value || !valuelen)
        goto bad_seckey;
      if (is_enc
          || pk->pubkey_algo == PUBKEY_ALGO_ECDSA
          || pk->pubkey_algo == PUBKEY_ALGO_EDDSA
          || pk->pubkey_algo == PUBKEY_ALGO_ECDH)
        {
          unsigned int nbits = valuelen*8;
          const unsigned char *p = value;

          if (*p && nbits >= 8 && !(*p & 0x80))
            if (--nbits >= 7 && !(*p & 0x40))
              if (--nbits >= 6 && !(*p & 0x20))
                if (--nbits >= 5 && !(*p & 0x10))
                  if (--nbits >= 4 && !(*p & 0x08))
                    if (--nbits >= 3 && !(*p & 0x04))
                      if (--nbits >= 2 && !(*p & 0x02))
                        if (--nbits >= 1 && !(*p & 0x01))
                          --nbits;

          skey[skeyidx] = gcry_mpi_set_opaque_copy (NULL, value, nbits);
          if (!skey[skeyidx])
            goto outofmem;
          if (is_enc)
            gcry_mpi_set_flag (skey[skeyidx], GCRYMPI_FLAG_USER1);
          else
            gcry_mpi_set_flag (skey[skeyidx], GCRYMPI_FLAG_USER2);
        }
      else
        {
          if (gcry_mpi_scan (skey + skeyidx, GCRYMPI_FMT_STD,
                             value, valuelen, NULL))
            goto bad_seckey;
        }
      skeyidx++;
    }
  skey[skeyidx++] = NULL;

  gcry_sexp_release (list); list = NULL;

  /* We have no need for the CSUM value thus we don't parse it.  */
  /* list = gcry_sexp_find_token (top_list, "csum", 0); */
  /* if (list) */
  /*   { */
  /*     string = gcry_sexp_nth_string (list, 1); */
  /*     if (!string) */
  /*       goto bad_seckey; */
  /*     desired_csum = strtoul (string, NULL, 10); */
  /*     xfree (string); */
  /*   } */
  /* else */
  /*   desired_csum = 0; */
  /* gcry_sexp_release (list); list = NULL; */

  /* Get the curve name if any,  */
  list = gcry_sexp_find_token (top_list, "curve", 0);
  if (list)
    {
      curve = gcry_sexp_nth_string (list, 1);
      gcry_sexp_release (list); list = NULL;
    }

  gcry_sexp_release (top_list); top_list = NULL;

  /* log_debug ("XXX is_v4=%d\n", is_v4); */
  /* log_debug ("XXX pubkey_algo=%d\n", pubkey_algo); */
  /* log_debug ("XXX is_protected=%d\n", is_protected); */
  /* log_debug ("XXX protect_algo=%d\n", protect_algo); */
  /* log_printhex ("XXX iv", iv, ivlen); */
  /* log_debug ("XXX ivlen=%d\n", ivlen); */
  /* log_debug ("XXX s2k_mode=%d\n", s2k_mode); */
  /* log_debug ("XXX s2k_algo=%d\n", s2k_algo); */
  /* log_printhex ("XXX s2k_salt", s2k_salt, sizeof s2k_salt); */
  /* log_debug ("XXX s2k_count=%lu\n", (unsigned long)s2k_count); */
  /* for (idx=0; skey[idx]; idx++) */
  /*   { */
  /*     int is_enc = gcry_mpi_get_flag (skey[idx], GCRYMPI_FLAG_OPAQUE); */
  /*     log_info ("XXX skey[%d]%s:", idx, is_enc? " (enc)":""); */
  /*     if (is_enc) */
  /*       { */
  /*         void *p; */
  /*         unsigned int nbits; */
  /*         p = gcry_mpi_get_opaque (skey[idx], &nbits); */
  /*         log_printhex (NULL, p, (nbits+7)/8); */
  /*       } */
  /*     else */
  /*       gcry_mpi_dump (skey[idx]); */
  /*     log_printf ("\n"); */
  /*   } */

  if (!is_v4 || is_protected != 2 )
    {
      /* We only support the v4 format and a SHA-1 checksum.  */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      goto leave;
    }

  /* We need to change the received parameters for ECC algorithms.
     The transfer format has the curve name and the parameters
     separate.  We put them all into the SKEY array.  */
  if (canon_pk_algo (pk_algo) == GCRY_PK_ECC)
    {
      const char *oidstr;

      /* Assert that all required parameters are available.  We also
         check that the array does not contain more parameters than
         needed (this was used by some beta versions of 2.1.  */
      if (!curve || !skey[0] || !skey[1] || skey[2])
        {
          err = gpg_error (GPG_ERR_INTERNAL);
          goto leave;
        }

      oidstr = openpgp_curve_to_oid (curve, NULL, NULL);
      if (!oidstr)
        {
          log_error ("no OID known for curve '%s'\n", curve);
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
          goto leave;
        }
      /* Put the curve's OID into the MPI array.  This requires
         that we shift Q and D.  For ECDH also insert the KDF parms. */
      if (is_ecdh)
        {
          skey[4] = NULL;
          skey[3] = skey[1];
          skey[2] = gcry_mpi_copy (pk->pkey[2]);
        }
      else
        {
          skey[3] = NULL;
          skey[2] = skey[1];
        }
      skey[1] = skey[0];
      skey[0] = NULL;
      err = openpgp_oid_from_str (oidstr, skey + 0);
      if (err)
        goto leave;
      /* Fixup the NPKEY and NSKEY to match OpenPGP reality.  */
      npkey = 2 + is_ecdh;
      nskey = 3 + is_ecdh;

      /* for (idx=0; skey[idx]; idx++) */
      /*   { */
      /*     log_info ("YYY skey[%d]:", idx); */
      /*     if (gcry_mpi_get_flag (skey[idx], GCRYMPI_FLAG_OPAQUE)) */
      /*       { */
      /*         void *p; */
      /*         unsigned int nbits; */
      /*         p = gcry_mpi_get_opaque (skey[idx], &nbits); */
      /*         log_printhex (NULL, p, (nbits+7)/8); */
      /*       } */
      /*     else */
      /*       gcry_mpi_dump (skey[idx]); */
      /*     log_printf ("\n"); */
      /*   } */
    }

  /* Do some sanity checks.  */
  if (s2k_count > 255)
    {
      /* We expect an already encoded S2K count.  */
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  err = openpgp_cipher_test_algo (protect_algo);
  if (err)
    goto leave;
  err = openpgp_md_test_algo (s2k_algo);
  if (err)
    goto leave;

  /* Check that the public key parameters match.  Note that since
     Libgcrypt 1.5 gcry_mpi_cmp handles opaque MPI correctly.  */
  for (idx=0; idx < npkey; idx++)
    if (gcry_mpi_cmp (pk->pkey[idx], skey[idx]))
      {
        err = gpg_error (GPG_ERR_BAD_PUBKEY);
        goto leave;
      }

  /* Check that the first secret key parameter in SKEY is encrypted
     and that there are no more secret key parameters.  The latter is
     guaranteed by the v4 packet format.  */
  if (!gcry_mpi_get_flag (skey[npkey], GCRYMPI_FLAG_USER1))
    goto bad_seckey;
  if (npkey+1 < DIM (skey) && skey[npkey+1])
    goto bad_seckey;

  /* Check that the secret key parameters in PK are all set to NULL. */
  for (idx=npkey; idx < nskey; idx++)
    if (pk->pkey[idx])
      goto bad_seckey;

  /* Now build the protection info. */
  pk->seckey_info = ski = xtrycalloc (1, sizeof *ski);
  if (!ski)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  ski->is_protected = 1;
  ski->sha1chk = 1;
  ski->algo = protect_algo;
  ski->s2k.mode = s2k_mode;
  ski->s2k.hash_algo = s2k_algo;
  log_assert (sizeof ski->s2k.salt == sizeof s2k_salt);
  memcpy (ski->s2k.salt, s2k_salt, sizeof s2k_salt);
  ski->s2k.count = s2k_count;
  log_assert (ivlen <= sizeof ski->iv);
  memcpy (ski->iv, iv, ivlen);
  ski->ivlen = ivlen;

  /* Store the protected secret key parameter.  */
  pk->pkey[npkey] = skey[npkey];
  skey[npkey] = NULL;

  /* That's it.  */

 leave:
  gcry_free (curve);
  gcry_sexp_release (list);
  gcry_sexp_release (top_list);
  for (idx=0; idx < skeyidx; idx++)
    gcry_mpi_release (skey[idx]);
  return err;

 bad_seckey:
  err = gpg_error (GPG_ERR_BAD_SECKEY);
  goto leave;

 outofmem:
  err = gpg_error (GPG_ERR_ENOMEM);
  goto leave;
}


/* Print an "EXPORTED" status line.  PK is the primary public key.  */
static void
print_status_exported (PKT_public_key *pk)
{
  char *hexfpr;

  if (!is_status_enabled ())
    return;

  hexfpr = hexfingerprint (pk, NULL, 0);
  write_status_text (STATUS_EXPORTED, hexfpr? hexfpr : "[?]");
  xfree (hexfpr);
}


/*
 * Receive a secret key from agent specified by HEXGRIP.
 *
 * Since the key data from the agent is encrypted, decrypt it using
 * CIPHERHD context.  Then, parse the decrypted key data into transfer
 * format, and put secret parameters into PK.
 *
 * If CLEARTEXT is 0, store the secret key material
 * passphrase-protected.  Otherwise, store secret key material in the
 * clear.
 *
 * If MODE1003 is set, the key is requested in raw GnuPG format from
 * the agent.  This usually does not require a passphrase unless the
 * gpg-agent has not yet used the key and needs to convert it to its
 * internal format first.
 *
 * CACHE_NONCE_ADDR is used to share nonce for multiple key retrievals.
 *
 * If PK is NULL, the raw key is returned (e.g. for ssh export) at
 * R_KEY.  CLEARTEXT and CACHE_NONCE_ADDR ared ignored in this case.
 */
gpg_error_t
receive_seckey_from_agent (ctrl_t ctrl, gcry_cipher_hd_t cipherhd,
                           int cleartext, int mode1003,
                           char **cache_nonce_addr, const char *hexgrip,
                           PKT_public_key *pk, gcry_sexp_t *r_key)
{
  gpg_error_t err = 0;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  unsigned char *key = NULL;
  size_t keylen, realkeylen;
  gcry_sexp_t s_skey = NULL;
  char *prompt;

  if (r_key)
    *r_key = NULL;
  if (opt.verbose)
    log_info ("key %s: asking agent for the secret parts\n", hexgrip);

  if (pk)
    {
      prompt = gpg_format_keydesc (ctrl, pk, FORMAT_KEYDESC_EXPORT, 1);
      err = agent_export_key (ctrl, hexgrip, prompt, !cleartext, mode1003,
                              cache_nonce_addr,
                              &wrappedkey, &wrappedkeylen,
                              pk->keyid, pk->main_keyid, pk->pubkey_algo);
    }
  else
    {
      prompt = gpg_format_keydesc (ctrl, NULL, FORMAT_KEYDESC_KEYGRIP, 1);
      err = agent_export_key (ctrl, hexgrip, prompt, 0, 0,
                              NULL,
                              &wrappedkey, &wrappedkeylen,
                              NULL, NULL, 0);
    }
  xfree (prompt);

  if (err)
    goto unwraperror;
  if (wrappedkeylen < 24)
    {
      err = gpg_error (GPG_ERR_INV_LENGTH);
      goto unwraperror;
    }
  keylen = wrappedkeylen - 8;
  key = xtrymalloc_secure (keylen);
  if (!key)
    {
      err = gpg_error_from_syserror ();
      goto unwraperror;
    }
  err = gcry_cipher_decrypt (cipherhd, key, keylen, wrappedkey, wrappedkeylen);
  if (err)
    goto unwraperror;
  realkeylen = gcry_sexp_canon_len (key, keylen, NULL, &err);
  if (!realkeylen)
    goto unwraperror; /* Invalid csexp.  */

  err = gcry_sexp_sscan (&s_skey, NULL, key, realkeylen);
  if (!err)
    {
      if (pk && mode1003)
        err = secret_key_to_mode1003 (s_skey, pk);
      else if (pk && cleartext)
        err = cleartext_secret_key_to_openpgp (s_skey, pk);
      else if (pk)
        err = transfer_format_to_openpgp (s_skey, pk);
      else if (r_key)
        {
          *r_key = s_skey;
          s_skey = NULL;
        }
    }

 unwraperror:
  gcry_sexp_release (s_skey);
  xfree (key);
  xfree (wrappedkey);
  if (err)
    {
      log_error ("key %s: error receiving key from agent:"
                 " %s%s\n", hexgrip, gpg_strerror (err),
                 gpg_err_code (err) == GPG_ERR_FULLY_CANCELED?
                 "":_(" - skipped"));
    }
  return err;
}


/* Write KEYBLOCK either to stdout or to the file set with the
 * --output option.  This is a simplified version of do_export_stream
 * which supports only a few export options.  */
gpg_error_t
write_keyblock_to_output (kbnode_t keyblock, int with_armor,
                          unsigned int options)
{
  gpg_error_t err;
  const char *fname;
  iobuf_t out;
  kbnode_t node;
  armor_filter_context_t *afx = NULL;
  iobuf_t out_help = NULL;
  PKT_public_key *pk = NULL;

  fname = opt.outfile? opt.outfile : "-";
  if (is_secured_filename (fname) )
    return gpg_error (GPG_ERR_EPERM);

  out = iobuf_create (fname, 0);
  if (!out)
    {
      err = gpg_error_from_syserror ();
      log_error(_("can't create '%s': %s\n"), fname, gpg_strerror (err));
      return err;
    }
  if (opt.verbose)
    log_info (_("writing to '%s'\n"), iobuf_get_fname_nonnull (out));

  if ((options & EXPORT_DANE_FORMAT))
    {
      with_armor = 0;
      out_help = iobuf_temp ();
    }

  if (with_armor)
    {
      afx = new_armor_context ();
      afx->what = 1;
      push_armor_filter (afx, out);
    }

  for (node = keyblock; node; node = node->next)
    {
      if (is_deleted_kbnode (node))
        continue;
      if (node->pkt->pkttype == PKT_RING_TRUST)
        continue; /* Skip - they should not be here anyway.  */

      if (!pk && (node->pkt->pkttype == PKT_PUBLIC_KEY
                  || node->pkt->pkttype == PKT_SECRET_KEY))
        pk = node->pkt->pkt.public_key;

      if ((options & EXPORT_BACKUP))
        err = build_packet_and_meta (out_help? out_help : out, node->pkt);
      else
        err = build_packet (out_help? out_help : out, node->pkt);
      if (err)
        {
          log_error ("build_packet(%d) failed: %s\n",
                     node->pkt->pkttype, gpg_strerror (err) );
          goto leave;
        }
    }
  err = 0;

  if (out_help && pk && (options & EXPORT_DANE_FORMAT))
    {
      const void *data;
      size_t datalen;

      iobuf_flush_temp (out_help);
      data = iobuf_get_temp_buffer (out_help);
      datalen = iobuf_get_temp_length (out_help);

      err = print_dane_records (out, keyblock, pk, data, datalen);
    }

 leave:
  if (err)
    iobuf_cancel (out);
  else
    iobuf_close (out);
  iobuf_cancel (out_help);
  release_armor_context (afx);
  return err;
}


/*
 * Apply the keep-uid filter to the keyblock.  The deleted nodes are
 * marked and thus the caller should call commit_kbnode afterwards.
 * KEYBLOCK must not have any blocks marked as deleted.
 */
static void
apply_keep_uid_filter (ctrl_t ctrl, kbnode_t keyblock, recsel_expr_t selector)
{
  kbnode_t node;
  struct impex_filter_parm_s parm;

  parm.ctrl = ctrl;

  for (node = keyblock->next; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          parm.node = node;
          if (!recsel_select (selector, impex_filter_getval, &parm))
            {
              /* log_debug ("keep-uid: deleting '%s'\n", */
              /*            node->pkt->pkt.user_id->name); */
              /* The UID packet and all following packets up to the
               * next UID or a subkey.  */
              delete_kbnode (node);
              for (; node->next
                     && node->next->pkt->pkttype != PKT_USER_ID
                     && node->next->pkt->pkttype != PKT_PUBLIC_SUBKEY
                     && node->next->pkt->pkttype != PKT_SECRET_SUBKEY ;
                   node = node->next)
                delete_kbnode (node->next);
	    }
          /* else */
          /*   log_debug ("keep-uid: keeping '%s'\n", */
          /*              node->pkt->pkt.user_id->name); */
        }
    }
}


/*
 * Apply the drop-subkey filter to the keyblock.  The deleted nodes are
 * marked and thus the caller should call commit_kbnode afterwards.
 * KEYBLOCK must not have any blocks marked as deleted.
 */
static void
apply_drop_subkey_filter (ctrl_t ctrl, kbnode_t keyblock,
                          recsel_expr_t selector)
{
  kbnode_t node;
  struct impex_filter_parm_s parm;

  parm.ctrl = ctrl;

  for (node = keyblock->next; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY)
        {
          parm.node = node;
          if (recsel_select (selector, impex_filter_getval, &parm))
            {
              /*log_debug ("drop-subkey: deleting a key\n");*/
              /* The subkey packet and all following packets up to the
               * next subkey.  */
              delete_kbnode (node);
              for (; node->next
                     && node->next->pkt->pkttype != PKT_PUBLIC_SUBKEY
                     && node->next->pkt->pkttype != PKT_SECRET_SUBKEY ;
                   node = node->next)
                delete_kbnode (node->next);
	    }
        }
    }
}


/* Print DANErecords for all user IDs in KEYBLOCK to OUT.  The data
 * for the record is taken from (DATA,DATELEN).  PK is the public key
 * packet with the primary key. */
static gpg_error_t
print_dane_records (iobuf_t out, kbnode_t keyblock, PKT_public_key *pk,
                    const void *data, size_t datalen)
{
  gpg_error_t err = 0;
  kbnode_t kbctx, node;
  PKT_user_id *uid;
  char *mbox = NULL;
  char hashbuf[32];
  char *hash = NULL;
  char *domain;
  const char *s;
  unsigned int len;
  estream_t fp = NULL;
  char *hexdata = NULL;
  char *hexfpr;

  hexfpr = hexfingerprint (pk, NULL, 0);
  if (!hexfpr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  hexdata = bin2hex (data, datalen, NULL);
  if (!hexdata)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ascii_strlwr (hexdata);
  fp = es_fopenmem (0, "rw,samethread");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  for (kbctx = NULL; (node = walk_kbnode (keyblock, &kbctx, 0));)
    {
      if (node->pkt->pkttype != PKT_USER_ID)
        continue;
      uid = node->pkt->pkt.user_id;

      if (uid->flags.expired || uid->flags.revoked)
        continue;

      xfree (mbox);
      mbox = mailbox_from_userid (uid->name, 0);
      if (!mbox)
        continue;

      domain = strchr (mbox, '@');
      *domain++ = 0;

      if (1)
        {
          es_fprintf (fp, "$ORIGIN _openpgpkey.%s.\n; %s\n; ", domain, hexfpr);
          print_utf8_buffer (fp, uid->name, uid->len);
          es_putc ('\n', fp);
          gcry_md_hash_buffer (GCRY_MD_SHA256, hashbuf, mbox, strlen (mbox));
          xfree (hash);
          hash = bin2hex (hashbuf, 28, NULL);
          if (!hash)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          ascii_strlwr (hash);
          len = strlen (hexdata)/2;
          es_fprintf (fp, "%s TYPE61 \\# %u (\n", hash, len);
          for (s = hexdata; ;)
            {
              es_fprintf (fp, "\t%.64s\n", s);
              if (strlen (s) < 64)
                break;
              s += 64;
            }
          es_fputs ("\t)\n\n", fp);
        }
    }

  /* Make sure it is a string and write it.  */
  es_fputc (0, fp);
  {
    void *vp;

    if (es_fclose_snatch (fp, &vp, NULL))
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
    fp = NULL;
    iobuf_writestr (out, vp);
    es_free (vp);
  }
  err = 0;

 leave:
  xfree (hash);
  xfree (mbox);
  es_fclose (fp);
  xfree (hexdata);
  xfree (hexfpr);
  return err;
}


/* Helper for do_export_stream which writes one keyblock to OUT.  */
static gpg_error_t
do_export_one_keyblock (ctrl_t ctrl, kbnode_t keyblock, u32 *keyid,
                        iobuf_t out, int secret, unsigned int options,
                        export_stats_t stats, int *any,
                        KEYDB_SEARCH_DESC *desc, size_t ndesc,
                        size_t descindex, gcry_cipher_hd_t cipherhd)
{
  gpg_error_t err = gpg_error (GPG_ERR_NOT_FOUND);
  char *cache_nonce = NULL;
  subkey_list_t subkey_list = NULL;  /* Track already processed subkeys. */
  int skip_until_subkey = 0;
  int cleartext = 0;
  char *hexgrip = NULL;
  char *serialno = NULL;
  PKT_public_key *pk;
  u32 subkidbuf[2], *subkid;
  kbnode_t kbctx, node;

  /* NB: walk_kbnode skips packets marked as deleted.  */
  for (kbctx=NULL; (node = walk_kbnode (keyblock, &kbctx, 0)); )
    {
      if (skip_until_subkey)
        {
          if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
            skip_until_subkey = 0;
          else
            continue;
        }

      /* We used to use comment packets, but not any longer.  In
       * case we still have comments on a key, strip them here
       * before we call build_packet(). */
      if (node->pkt->pkttype == PKT_COMMENT)
        continue;

      /* Skip ring trust packets - they should not be here anyway.  */
      if (node->pkt->pkttype == PKT_RING_TRUST)
        continue;

      /* If exact is set, then we only export what was requested
       * (plus the primary key, if the user didn't specifically
       * request it). */
      if (desc[descindex].exact && node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          if (!exact_subkey_match_p (desc+descindex, node))
            {
              /* Before skipping this subkey, check whether any
               * other description wants an exact match on a
               * subkey and include that subkey into the output
               * too.  Need to add this subkey to a list so that
               * it won't get processed a second time.
               *
               * So the first step here is to check that list and
               * skip in any case if the key is in that list.
               *
               * We need this whole mess because the import
               * function of GnuPG < 2.1 is not able to merge
               * secret keys and thus it is useless to output them
               * as two separate keys and have import merge them.
               */
              if (subkey_in_list_p (subkey_list, node))
                skip_until_subkey = 1; /* Already processed this one. */
              else
                {
                  size_t j;

                  for (j=0; j < ndesc; j++)
                    if (j != descindex && desc[j].exact
                        && exact_subkey_match_p (desc+j, node))
                      break;
                  if (!(j < ndesc))
                    skip_until_subkey = 1; /* No other one matching. */
                }
            }

          if (skip_until_subkey)
            continue;

          /* Mark this one as processed. */
          {
            subkey_list_t tmp = new_subkey_list_item (node);
            tmp->next = subkey_list;
            subkey_list = tmp;
          }
        }

      if (node->pkt->pkttype == PKT_SIGNATURE)
        {
          /* Do not export packets which are marked as not
           * exportable.  */
          if (!(options & EXPORT_LOCAL_SIGS)
              && !node->pkt->pkt.signature->flags.exportable)
            continue; /* not exportable */

          /* Do not export packets with a "sensitive" revocation key
           * unless the user wants us to.  Note that we do export
           * these when issuing the actual revocation (see revoke.c). */
          if (!(options & EXPORT_SENSITIVE_REVKEYS)
              && node->pkt->pkt.signature->revkey)
            {
              int i;

              for (i = 0; i < node->pkt->pkt.signature->numrevkeys; i++)
                if ((node->pkt->pkt.signature->revkey[i].class & 0x40))
                  break;
              if (i < node->pkt->pkt.signature->numrevkeys)
                continue;
            }
        }

      /* Don't export attribs? */
      if (!(options & EXPORT_ATTRIBUTES)
          && node->pkt->pkttype == PKT_USER_ID
          && node->pkt->pkt.user_id->attrib_data)
        {
          /* Skip until we get to something that is not an attrib or a
           * signature on an attrib.  */
          while (kbctx->next && kbctx->next->pkt->pkttype == PKT_SIGNATURE)
            kbctx = kbctx->next;

          continue;
        }

      if (secret && (node->pkt->pkttype == PKT_PUBLIC_KEY
                     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY))
        {
          pk = node->pkt->pkt.public_key;
          if (node->pkt->pkttype == PKT_PUBLIC_KEY)
            subkid = NULL;
          else
            {
              keyid_from_pk (pk, subkidbuf);
              subkid = subkidbuf;
            }

          if (pk->seckey_info)
            {
              log_error ("key %s: oops: seckey_info already set"
                         " - skipped\n", keystr_with_sub (keyid, subkid));
              skip_until_subkey = 1;
              continue;
            }

          xfree (hexgrip);
          err = hexkeygrip_from_pk (pk, &hexgrip);
          if (err)
            {
              log_error ("key %s: error computing keygrip: %s"
                         " - skipped\n", keystr_with_sub (keyid, subkid),
                         gpg_strerror (err));
              skip_until_subkey = 1;
              err = 0;
              continue;
            }

          xfree (serialno);
          serialno = NULL;
          if (secret == 2 && node->pkt->pkttype == PKT_PUBLIC_KEY)
            {
              /* We are asked not to export the secret parts of the
               * primary key.  Make up an error code to create the
               * stub.  */
              err = GPG_ERR_NOT_FOUND;
            }
          else
            err = agent_get_keyinfo (ctrl, hexgrip, &serialno, &cleartext);

          if ((!err && serialno)
              && secret == 2 && node->pkt->pkttype == PKT_PUBLIC_KEY)
            {
              /* It does not make sense to export a key with its
               * primary key on card using a non-key stub.  Thus we
               * skip those keys when used with --export-secret-subkeys. */
              log_info (_("key %s: key material on-card - skipped\n"),
                        keystr_with_sub (keyid, subkid));
              skip_until_subkey = 1;
            }
          else if (gpg_err_code (err) == GPG_ERR_NOT_FOUND
                   || (!err && serialno))
            {
              /* Create a key stub.  */
              struct seckey_info *ski;
              const char *s;

              pk->seckey_info = ski = xtrycalloc (1, sizeof *ski);
              if (!ski)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }

              ski->is_protected = 1;
              if (err)
                ski->s2k.mode = 1001; /* GNU dummy (no secret key).  */
              else
                {
                  ski->s2k.mode = 1002; /* GNU-divert-to-card.  */
                  for (s=serialno; sizeof (ski->ivlen) && *s && s[1];
                       ski->ivlen++, s += 2)
                    ski->iv[ski->ivlen] = xtoi_2 (s);
                }

              if ((options & EXPORT_BACKUP))
                err = build_packet_and_meta (out, node->pkt);
              else
                err = build_packet (out, node->pkt);
              if (!err && node->pkt->pkttype == PKT_PUBLIC_KEY)
                {
                  stats->exported++;
                  print_status_exported (node->pkt->pkt.public_key);
                }
            }
          else if (!err)
            {
              err = receive_seckey_from_agent (ctrl, cipherhd,
                                               cleartext,
                                               !!(options & EXPORT_MODE1003),
                                               &cache_nonce,
                                               hexgrip, pk, NULL);
              if (err)
                {
                  /* If we receive a fully canceled error we stop
                   * immediately.  If we receive a cancel for a public
                   * key we also stop immediately because a
                   * public/secret key is always required first
                   * (right, we could instead write a stub key but
                   * that is also kind of surprising).  If we receive
                   * a subkey we skip to the next subkey.  */
                  if (gpg_err_code (err) == GPG_ERR_FULLY_CANCELED
                      || (node->pkt->pkttype == PKT_PUBLIC_KEY
                          && gpg_err_code (err) == GPG_ERR_CANCELED))
                    goto leave;
                  write_status_error ("export_keys.secret", err);
                  skip_until_subkey = 1;
                  err = 0;
                }
              else
                {
                  if ((options & EXPORT_BACKUP))
                    err = build_packet_and_meta (out, node->pkt);
                  else
                    err = build_packet (out, node->pkt);
                  if (node->pkt->pkttype == PKT_PUBLIC_KEY)
                    {
                      stats->exported++;
                      print_status_exported (node->pkt->pkt.public_key);
                    }
                }
            }
          else
            {
              log_error ("key %s: error getting keyinfo from agent: %s"
                         " - skipped\n", keystr_with_sub (keyid, subkid),
                             gpg_strerror (err));
              skip_until_subkey = 1;
              err = 0;
            }

          xfree (pk->seckey_info);
          pk->seckey_info = NULL;
          {
            int i;
            for (i = pubkey_get_npkey (pk->pubkey_algo);
                 i < pubkey_get_nskey (pk->pubkey_algo); i++)
              {
                gcry_mpi_release (pk->pkey[i]);
                pk->pkey[i] = NULL;
              }
          }
        }
      else /* Not secret or common packets.  */
        {
          if ((options & EXPORT_BACKUP))
            err = build_packet_and_meta (out, node->pkt);
          else
            err = build_packet (out, node->pkt);
          if (!err && node->pkt->pkttype == PKT_PUBLIC_KEY)
            {
              stats->exported++;
              print_status_exported (node->pkt->pkt.public_key);
            }
        }

      if (err)
        {
          log_error ("build_packet(%d) failed: %s\n",
                     node->pkt->pkttype, gpg_strerror (err));
          goto leave;
        }

      if (!skip_until_subkey)
        *any = 1;
    }

 leave:
  release_subkey_list (subkey_list);
  xfree (serialno);
  xfree (hexgrip);
  xfree (cache_nonce);
  return err;
}


/* Helper for do_export_stream which writes the own revocations
 * certificates (if any) from KEYBLOCK to OUT. */
static gpg_error_t
do_export_revocs (ctrl_t ctrl, kbnode_t keyblock, u32 *keyid,
                  iobuf_t out, unsigned int options, int *any)
{
  gpg_error_t err = 0;
  kbnode_t kbctx, node;
  PKT_signature *sig;

  (void)ctrl;

  /* NB: walk_kbnode skips packets marked as deleted.  */
  for (kbctx=NULL; (node = walk_kbnode (keyblock, &kbctx, 0)); )
    {
      if (node->pkt->pkttype != PKT_SIGNATURE)
        continue;
      sig = node->pkt->pkt.signature;

      /* We are only interested in revocation certifcates.  */
      if (!(IS_KEY_REV (sig) || IS_UID_REV (sig) || IS_SUBKEY_REV (sig)))
        continue;

      if (!(sig->keyid[0] == keyid[0] && sig->keyid[1] == keyid[1]))
        continue;  /* Not a self-signature.  */

      /* Do not export signature packets which are marked as not
       * exportable.  */
      if (!(options & EXPORT_LOCAL_SIGS)
          && !sig->flags.exportable)
        continue; /* not exportable */

      /* Do not export packets with a "sensitive" revocation key
       * unless the user wants us to.  */
      if (!(options & EXPORT_SENSITIVE_REVKEYS)
          && sig->revkey)
        {
          int i;

          for (i = 0; i < sig->numrevkeys; i++)
            if ((sig->revkey[i].class & 0x40))
              break;
          if (i < sig->numrevkeys)
            continue;
        }

      if (!sig->flags.checked)
        {
          log_info ("signature not marked as checked - ignored\n");
          continue;
        }
      if (!sig->flags.valid)
        {
          log_info ("signature not not valid - ignored\n");
          continue;
        }

      err = build_packet (out, node->pkt);
      if (err)
        {
          log_error ("build_packet(%d) failed: %s\n",
                     node->pkt->pkttype, gpg_strerror (err));
          goto leave;
        }
      *any = 1;
    }

 leave:
  return err;
}


/* For secret key export we need to setup a decryption context.
 * Returns 0 and the context at r_cipherhd.  */
static gpg_error_t
get_keywrap_key (ctrl_t ctrl, gcry_cipher_hd_t *r_cipherhd)
{
#ifdef ENABLE_SELINUX_HACKS
  (void)ctrl;
  *r_cipherhd = NULL;
  log_error (_("exporting secret keys not allowed\n"));
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#else
  gpg_error_t err;
  void *kek = NULL;
  size_t keklen;
  gcry_cipher_hd_t cipherhd;

  *r_cipherhd = NULL;

  err = agent_keywrap_key (ctrl, 1, &kek, &keklen);
  if (err)
    {
      log_error ("error getting the KEK: %s\n", gpg_strerror (err));
      return err;
    }

  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = gcry_cipher_setkey (cipherhd, kek, keklen);
  if (err)
    log_error ("error setting up an encryption context: %s\n",
               gpg_strerror (err));

  if (!err)
    *r_cipherhd = cipherhd;
  else
    gcry_cipher_close (cipherhd);
  xfree (kek);
  return err;
#endif
}


/* Export the keys identified by the list of strings in USERS to the
   stream OUT.  If SECRET is false public keys will be exported.  With
   secret true secret keys will be exported; in this case 1 means the
   entire secret keyblock and 2 only the subkeys.  OPTIONS are the
   export options to apply.  If KEYBLOCK_OUT is not NULL, AND the exit
   code is zero, a pointer to the first keyblock found and exported
   will be stored at this address; no other keyblocks are exported in
   this case.  The caller must free the returned keyblock.  If any
   key has been exported true is stored at ANY. */
static int
do_export_stream (ctrl_t ctrl, iobuf_t out, strlist_t users, int secret,
		  kbnode_t *keyblock_out, unsigned int options,
                  export_stats_t stats, int *any)
{
  gpg_error_t err = 0;
  PACKET pkt;
  kbnode_t keyblock = NULL;
  kbnode_t node;
  size_t ndesc, descindex;
  KEYDB_SEARCH_DESC *desc = NULL;
  KEYDB_HANDLE kdbhd;
  strlist_t sl;
  gcry_cipher_hd_t cipherhd = NULL;
  struct export_stats_s dummystats;
  iobuf_t out_help = NULL;

  if (!stats)
    stats = &dummystats;
  *any = 0;
  init_packet (&pkt);
  kdbhd = keydb_new (ctrl);
  if (!kdbhd)
    return gpg_error_from_syserror ();

  /* For the DANE format open a helper iobuf and
   * enforce some options.  */
  if ((options & EXPORT_DANE_FORMAT))
    {
      out_help = iobuf_temp ();
      options |= EXPORT_MINIMAL | EXPORT_CLEAN;
    }

  if (!users)
    {
      ndesc = 1;
      desc = xcalloc (ndesc, sizeof *desc);
      desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
    }
  else
    {
      for (ndesc=0, sl=users; sl; sl = sl->next, ndesc++)
        ;
      desc = xmalloc ( ndesc * sizeof *desc);

      for (ndesc=0, sl=users; sl; sl = sl->next)
        {
          if (!(err=classify_user_id (sl->d, desc+ndesc, 1)))
            ndesc++;
          else
            log_error (_("key \"%s\" not found: %s\n"),
                       sl->d, gpg_strerror (err));
        }

      keydb_disable_caching (kdbhd);  /* We are looping the search.  */

      /* It would be nice to see which of the given users did actually
         match one in the keyring.  To implement this we need to have
         a found flag for each entry in desc.  To set this flag we
         must check all those entries after a match to mark all
         matched one - currently we stop at the first match.  To do
         this we need an extra flag to enable this feature.  */
    }

  /* For secret key export we need to setup a decryption context.  */
  if (secret && (err = get_keywrap_key (ctrl, &cipherhd)))
    goto leave;

  for (;;)
    {
      u32 keyid[2];
      PKT_public_key *pk;

      err = keydb_search (kdbhd, desc, ndesc, &descindex);
      if (!users)
        desc[0].mode = KEYDB_SEARCH_MODE_NEXT;
      if (err)
        break;

      /* Read the keyblock. */
      release_kbnode (keyblock);
      keyblock = NULL;
      err = keydb_get_keyblock (kdbhd, &keyblock);
      if (err)
        {
          log_error (_("error reading keyblock: %s\n"), gpg_strerror (err));
          goto leave;
	}

      node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
      if (!node)
        {
          log_error ("public key packet not found in keyblock - skipped\n");
          continue;
        }
      stats->count++;
      setup_main_keyids (keyblock);  /* gpg_format_keydesc needs it.  */
      pk = node->pkt->pkt.public_key;
      keyid_from_pk (pk, keyid);

      /* If a secret key export is required we need to check whether
         we have a secret key at all and if so create the seckey_info
         structure.  */
      if (secret)
        {
          if (agent_probe_any_secret_key (ctrl, keyblock))
            continue;  /* No secret key (neither primary nor subkey).  */

          /* No v3 keys with GNU mode 1001. */
          if (secret == 2 && pk->version == 3)
            {
              log_info (_("key %s: PGP 2.x style key - skipped\n"),
                        keystr (keyid));
              continue;
            }

          /* The agent does not yet allow export of v3 packets.  It is
             actually questionable whether we should allow them at
             all.  */
          if (pk->version == 3)
            {
              log_info ("key %s: PGP 2.x style key (v3) export "
                        "not yet supported - skipped\n", keystr (keyid));
              continue;
            }
          stats->secret_count++;
        }

      /* Always do the cleaning on the public key part if requested.
       * A designated revocation is never stripped, even with
       * export-minimal set.  */
      if ((options & EXPORT_CLEAN))
        {
          merge_keys_and_selfsig (ctrl, keyblock);
          clean_all_uids (ctrl, keyblock, opt.verbose, options, NULL, NULL);
          clean_all_subkeys (ctrl, keyblock, opt.verbose,
                             (options&EXPORT_MINIMAL)? KEY_CLEAN_ALL
                             /**/                    : KEY_CLEAN_AUTHENCR,
                             NULL, NULL);
          commit_kbnode (&keyblock);
        }
      else if (export_keep_uid || export_drop_subkey || export_select_filter)
        {
          /* Need to merge so that for example the "usage" property
           * has been setup.  */
          merge_keys_and_selfsig (ctrl, keyblock);
        }


      if (export_select_filter)
        {
          int selected = 0;
          struct impex_filter_parm_s parm;
          parm.ctrl = ctrl;

          for (parm.node = keyblock; parm.node; parm.node = parm.node->next)
            {
              if (recsel_select (export_select_filter,
                                 impex_filter_getval, &parm))
                {
                  selected = 1;
                  break;
                }
            }
          if (!selected)
            continue;  /* Skip this keyblock.  */
        }

      if (export_keep_uid)
        {
          commit_kbnode (&keyblock);
          apply_keep_uid_filter (ctrl, keyblock, export_keep_uid);
          commit_kbnode (&keyblock);
        }

      if (export_drop_subkey)
        {
          commit_kbnode (&keyblock);
          apply_drop_subkey_filter (ctrl, keyblock, export_drop_subkey);
          commit_kbnode (&keyblock);
        }

      /* And write it. */
      if ((options & EXPORT_REVOCS))
        err = do_export_revocs (ctrl, keyblock, keyid,
                                out_help? out_help : out,
                                options, any);
      else
        err = do_export_one_keyblock (ctrl, keyblock, keyid,
                                      out_help? out_help : out,
                                      secret, options, stats, any,
                                      desc, ndesc, descindex, cipherhd);
      if (err)
        break;

      if (keyblock_out)
        {
          *keyblock_out = keyblock;
          break;
        }

      if (out_help && (options & EXPORT_DANE_FORMAT))
        {
          /* We want to write DANE records.  OUT_HELP has the
           * keyblock and we print a record for each uid to OUT. */
          const void *data;
          size_t datalen;

          iobuf_flush_temp (out_help);
          data = iobuf_get_temp_buffer (out_help);
          datalen = iobuf_get_temp_length (out_help);

          err = print_dane_records (out, keyblock, pk, data, datalen);
          if (err)
            goto leave;

          iobuf_close (out_help);
          out_help = iobuf_temp ();
        }

    }
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    err = 0;

 leave:
  iobuf_cancel (out_help);
  gcry_cipher_close (cipherhd);
  xfree(desc);
  keydb_release (kdbhd);
  if (err || !keyblock_out)
    release_kbnode( keyblock );
  if( !*any && !opt.quiet)
    log_info (_("WARNING: nothing exported\n"));
  return err;
}



/* Write the uint32 VALUE to MB in networ byte order.  */
static void
mb_write_uint32 (membuf_t *mb, u32 value)
{
  unsigned char buffer[4];

  ulongtobuf (buffer, (ulong)value);
  put_membuf (mb, buffer, 4);
}

/* Write the byte C to MB.  */
static void
mb_write_uint8 (membuf_t *mb, int c)
{
  unsigned char buf[1];

  buf[0] = c;
  put_membuf (mb, buf, 1);
}


/* Simple wrapper around put_membuf.  */
static void
mb_write_data (membuf_t *mb, const void *data, size_t datalen)
{
  put_membuf (mb, data, datalen);
}

/* Write STRING with terminating Nul to MB.  */
static void
mb_write_cstring (membuf_t *mb, const char *string)
{
  put_membuf (mb, string, strlen (string)+1);
}

/* Write an SSH style string to MB.  */
static void
mb_write_string (membuf_t *mb, const void *string, size_t n)
{
  mb_write_uint32 (mb, (u32)n);
  mb_write_data (mb, string, n);
}

/* Write an MPI as SSH style string to MB   */
static void
mb_write_mpi (membuf_t *mb, gcry_mpi_t mpi, int strip_prefix)
{
  unsigned int nbits;
  const unsigned char *p;
  size_t n;

  if (gcry_mpi_get_flag (mpi, GCRYMPI_FLAG_OPAQUE))
    {
      p = gcry_mpi_get_opaque (mpi, &nbits);
      n = (nbits + 7) / 8;

      if (strip_prefix && n > 1 && p[0] == 0x40)
        {
          /* We need to strip our 0x40 prefix.  */
          p++;
          n--;
        }
      mb_write_string (mb, p, n);
    }
  else
    {
      gpg_error_t err;
      unsigned char *buf;

      err = gcry_mpi_aprint (GCRYMPI_FMT_SSH, &buf, &n, mpi);
      if (err)
        set_membuf_err (mb, err);
      else
        {
          mb_write_data (mb, buf, n);
          gcry_free (buf);
        }
    }
}



static gpg_error_t
key_to_sshblob (membuf_t *mb, const char *identifier, ...)
{
  va_list arg_ptr;
  gpg_error_t err = 0;
  unsigned char nbuf[4];
  unsigned char *buf;
  size_t buflen;
  gcry_mpi_t a;

  buflen = strlen (identifier);
  ulongtobuf (nbuf, (ulong)buflen);
  put_membuf (mb, nbuf, 4);
  put_membuf (mb, identifier, buflen);
  if (buflen > 11 && !memcmp (identifier, "ecdsa-sha2-", 11))
    {
      /* Store the name of the curve taken from the identifier.  */
      ulongtobuf (nbuf, (ulong)(buflen - 11));
      put_membuf (mb, nbuf, 4);
      put_membuf (mb, identifier+11, buflen - 11);
    }
  va_start (arg_ptr, identifier);
  while ((a = va_arg (arg_ptr, gcry_mpi_t)))
    {
      if (gcry_mpi_get_flag (a, GCRYMPI_FLAG_OPAQUE))
        {
          unsigned int nbits;
          const unsigned char *p;

          p = gcry_mpi_get_opaque (a, &nbits);
          buflen = (nbits + 7) / 8;

          if (!strcmp (identifier, "ssh-ed25519")
              && buflen > 1 && p[0] == 0x40)
            {
              /* We need to strip our 0x40 prefix.  */
              put_membuf (mb, "\x00\x00\x00\x20", 4);
              put_membuf (mb, p+1, buflen-1);
            }
          else
            {
              unsigned char c;

              c = buflen >> 24;
              put_membuf (mb, &c, 1);
              c = buflen >> 16;
              put_membuf (mb, &c, 1);
              c = buflen >> 8;
              put_membuf (mb, &c, 1);
              c = buflen;
              put_membuf (mb, &c, 1);
              put_membuf (mb, p, buflen);
            }
        }
      else
        {
          err = gcry_mpi_aprint (GCRYMPI_FMT_SSH, &buf, &buflen, a);
          if (err)
            break;
          put_membuf (mb, buf, buflen);
          gcry_free (buf);
        }
    }
  va_end (arg_ptr);
  return err;
}


static gpg_error_t
export_one_ssh_key (estream_t fp, PKT_public_key *pk)
{
  gpg_error_t err;
  const char *identifier = NULL;
  membuf_t mb;
  void *blob;
  size_t bloblen;

  init_membuf (&mb, 4096);

  switch (pk->pubkey_algo)
    {
    case PUBKEY_ALGO_DSA:
      identifier = "ssh-dss";
      err = key_to_sshblob (&mb, identifier,
                            pk->pkey[0], pk->pkey[1], pk->pkey[2], pk->pkey[3],
                            NULL);
      break;

    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_S:
      identifier = "ssh-rsa";
      err = key_to_sshblob (&mb, identifier, pk->pkey[1], pk->pkey[0], NULL);
      break;

    case PUBKEY_ALGO_ECDSA:
      {
        char *curveoid;
        const char *curve;

        curveoid = openpgp_oid_to_str (pk->pkey[0]);
        if (!curveoid)
          err = gpg_error_from_syserror ();
        else if (!(curve = openpgp_oid_to_curve (curveoid, 0)))
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
        else
          {
            if (!strcmp (curve, "nistp256"))
              identifier = "ecdsa-sha2-nistp256";
            else if (!strcmp (curve, "nistp384"))
              identifier = "ecdsa-sha2-nistp384";
            else if (!strcmp (curve, "nistp521"))
              identifier = "ecdsa-sha2-nistp521";

            if (!identifier)
              err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
            else
              err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL);
          }
        xfree (curveoid);
      }
      break;

    case PUBKEY_ALGO_EDDSA:
      if (openpgp_oid_is_ed25519 (pk->pkey[0]))
        {
          identifier = "ssh-ed25519";
          err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL);
        }
      else if (openpgp_oid_is_ed448 (pk->pkey[0]))
        {
          identifier = "ssh-ed448";
          err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL);
        }
      else
        err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      break;

    case PUBKEY_ALGO_ELGAMAL_E:
    case PUBKEY_ALGO_ELGAMAL:
      err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
      break;

    default:
      err = GPG_ERR_PUBKEY_ALGO;
      break;
    }

  if (err)
    goto leave;

  blob = get_membuf (&mb, &bloblen);
  if (blob)
    {
      struct b64state b64_state;

      es_fprintf (fp, "%s ", identifier);
      err = b64enc_start_es (&b64_state, fp, "");
      if (err)
        {
          xfree (blob);
          goto leave;
        }

      err = b64enc_write (&b64_state, blob, bloblen);
      b64enc_finish (&b64_state);

      es_fprintf (fp, " openpgp:0x%08lX\n", (ulong)keyid_from_pk (pk, NULL));
      xfree (blob);
    }

 leave:
  xfree (get_membuf (&mb, NULL));
  return err;
}

/* Export the key identified by USERID in the SSH public key format.
   The function exports the latest subkey with Authentication
   capability unless the '!' suffix is used to export a specific
   key.  */
gpg_error_t
export_ssh_key (ctrl_t ctrl, const char *userid)
{
  gpg_error_t err;
  kbnode_t keyblock = NULL;
  KEYDB_SEARCH_DESC desc;
  u32 latest_date;
  u32 curtime = make_timestamp ();
  kbnode_t latest_key, node;
  PKT_public_key *pk;
  estream_t fp = NULL;
  const char *fname = "-";

  /* We need to know whether the key has been specified using the
     exact syntax ('!' suffix).  Thus we need to run a
     classify_user_id on our own.  */
  err = classify_user_id (userid, &desc, 1);

  /* Get the public key.  */
  if (!err)
    {
      getkey_ctx_t getkeyctx;

      err = get_pubkey_byname (ctrl, GET_PUBKEY_NO_AKL,
                               &getkeyctx, NULL, userid, &keyblock,
                               NULL,
                               0  /* Only usable keys or given exact. */);
      if (!err)
        {
          err = getkey_next (ctrl, getkeyctx, NULL, NULL);
          if (!err)
            err = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
          else if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
            err = 0;
        }
      getkey_end (ctrl, getkeyctx);
    }
  if (err)
    {
      log_error (_("key \"%s\" not found: %s\n"), userid, gpg_strerror (err));
      return err;
    }

  /* The finish_lookup code in getkey.c does not handle auth keys,
     thus we have to duplicate the code here to find the latest
     subkey.  However, if the key has been found using an exact match
     ('!' notation) we use that key without any further checks and
     even allow the use of the primary key. */
  latest_date = 0;
  latest_key = NULL;
  for (node = keyblock; node; node = node->next)
    {
      if ((node->pkt->pkttype == PKT_PUBLIC_SUBKEY
           || node->pkt->pkttype == PKT_PUBLIC_KEY)
          && node->pkt->pkt.public_key->flags.exact)
        {
          latest_key = node;
          break;
        }
    }
  if (!latest_key)
    {
      for (node = keyblock; node; node = node->next)
        {
          if (node->pkt->pkttype != PKT_PUBLIC_SUBKEY)
            continue;

          pk = node->pkt->pkt.public_key;
          if (DBG_LOOKUP)
            log_debug ("\tchecking subkey %08lX\n",
                       (ulong) keyid_from_pk (pk, NULL));
          if (!(pk->pubkey_usage & PUBKEY_USAGE_AUTH))
            {
              if (DBG_LOOKUP)
                log_debug ("\tsubkey not usable for authentication\n");
              continue;
            }
          if (!pk->flags.valid)
            {
              if (DBG_LOOKUP)
                log_debug ("\tsubkey not valid\n");
              continue;
            }
          if (pk->flags.revoked)
            {
              if (DBG_LOOKUP)
                log_debug ("\tsubkey has been revoked\n");
              continue;
            }
          if (pk->has_expired)
            {
              if (DBG_LOOKUP)
                log_debug ("\tsubkey has expired\n");
              continue;
            }
          if (pk->timestamp > curtime && !opt.ignore_valid_from)
            {
              if (DBG_LOOKUP)
                log_debug ("\tsubkey not yet valid\n");
              continue;
            }
          if (DBG_LOOKUP)
            log_debug ("\tsubkey might be fine\n");
          /* In case a key has a timestamp of 0 set, we make sure that it
             is used.  A better change would be to compare ">=" but that
             might also change the selected keys and is as such a more
             intrusive change.  */
          if (pk->timestamp > latest_date || (!pk->timestamp && !latest_date))
            {
              latest_date = pk->timestamp;
              latest_key = node;
            }
        }

      /* If no subkey was suitable check the primary key.  */
      if (!latest_key
          && (node = keyblock) && node->pkt->pkttype == PKT_PUBLIC_KEY)
        {
          pk = node->pkt->pkt.public_key;
          if (DBG_LOOKUP)
            log_debug ("\tchecking primary key %08lX\n",
                       (ulong) keyid_from_pk (pk, NULL));
          if (!(pk->pubkey_usage & PUBKEY_USAGE_AUTH))
            {
              if (DBG_LOOKUP)
                log_debug ("\tprimary key not usable for authentication\n");
            }
          else if (!pk->flags.valid)
            {
              if (DBG_LOOKUP)
                log_debug ("\tprimary key not valid\n");
            }
          else if (pk->flags.revoked)
            {
              if (DBG_LOOKUP)
                log_debug ("\tprimary key has been revoked\n");
            }
          else if (pk->has_expired)
            {
              if (DBG_LOOKUP)
                log_debug ("\tprimary key has expired\n");
            }
          else if (pk->timestamp > curtime && !opt.ignore_valid_from)
            {
              if (DBG_LOOKUP)
                log_debug ("\tprimary key not yet valid\n");
            }
          else
            {
              if (DBG_LOOKUP)
                log_debug ("\tprimary key is fine\n");
              latest_date = pk->timestamp;
              latest_key = node;
            }
        }
    }

  if (!latest_key)
    {
      err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
      log_error (_("key \"%s\" not found: %s\n"), userid, gpg_strerror (err));
      goto leave;
    }

  pk = latest_key->pkt->pkt.public_key;
  if (DBG_LOOKUP)
    log_debug ("\tusing key %08lX\n", (ulong) keyid_from_pk (pk, NULL));

  if (opt.outfile && *opt.outfile && strcmp (opt.outfile, "-"))
    fp = es_fopen ((fname = opt.outfile), "w");
  else
    fp = es_stdout;
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  err = export_one_ssh_key (fp, pk);
  if (err)
    goto leave;

  if (es_ferror (fp))
    err = gpg_error_from_syserror ();
  else
    {
      if (fp != es_stdout && es_fclose (fp))
        err = gpg_error_from_syserror ();
      fp = NULL;
    }

  if (err)
    log_error (_("error writing '%s': %s\n"), fname, gpg_strerror (err));

 leave:
  if (fp != es_stdout)
    es_fclose (fp);
  release_kbnode (keyblock);
  return err;
}


/* Export the key identified by USERID in the SSH secret key format.
 * The USERID must be given in keygrip format (prefixed with a '&')
 * and thus no OpenPGP key is required.  The exported key is not
 * protected.  */
gpg_error_t
export_secret_ssh_key (ctrl_t ctrl, const char *userid)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  estream_t fp = NULL;
  const char *fname = "-";
  gcry_cipher_hd_t cipherhd = NULL;
  char hexgrip[KEYGRIP_LEN * 2 + 1];
  gcry_sexp_t skey = NULL;
  gcry_sexp_t skeyalgo = NULL;
  const char *identifier = NULL;
  membuf_t mb;
  membuf_t mb2;
  void *blob = NULL;
  size_t bloblen;
  const char *s;
  size_t n;
  char *p;
  int pkalgo;
  int i;
  gcry_mpi_t keyparam[10] = { NULL };
  struct b64state b64_state;

  init_membuf_secure (&mb, 1024);
  init_membuf_secure (&mb2, 1024);

  /* Check that a keygrip has been given.  */
  err = classify_user_id (userid, &desc, 1);
  if (err || desc.mode != KEYDB_SEARCH_MODE_KEYGRIP )
    {
      log_error (_("key \"%s\" not found: %s\n"), userid,
                 err? gpg_strerror (err) : "Not a Keygrip" );
      return err;
    }

  bin2hex (desc.u.grip, KEYGRIP_LEN, hexgrip);

  if ((err = get_keywrap_key (ctrl, &cipherhd)))
    goto leave;

  err = receive_seckey_from_agent (ctrl, cipherhd, 0, 0, NULL, hexgrip, NULL,
                                   &skey);
  if (err)
    goto leave;

  /* Get the type of the key expression.  */
  s = gcry_sexp_nth_data (skey, 0, &n);
  if (!s || !(n == 11 && !memcmp (s, "private-key", 11)))
    {
      log_info ("Note: only on-disk secret keys may be exported\n");
      err = gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }

  mb_write_cstring (&mb, "openssh-key-v1"); /* Auth_Magic. */
  mb_write_string (&mb, "none", 4); /* ciphername */
  mb_write_string (&mb, "none", 4); /* kdfname  */
  mb_write_uint32 (&mb, 0);         /* kdfoptions  */
  mb_write_uint32 (&mb, 1);         /* number of keys  */

  pkalgo = get_pk_algo_from_key (skey);
  switch (pkalgo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_S:
      identifier = "ssh-rsa";
      err = gcry_sexp_extract_param (skey, NULL, "nedpq",
                                     &keyparam[0],
                                     &keyparam[1],
                                     &keyparam[2],
                                     &keyparam[3],
                                     &keyparam[4],
                                     NULL);
      if (err)
        goto leave;
      mb_write_string (&mb2, identifier, strlen (identifier));
      mb_write_mpi (&mb2, keyparam[1], 0);  /* e (right, e is first here) */
      mb_write_mpi (&mb2, keyparam[0], 0);  /* n */
      /* Append public to the output block as an SSH string.  */
      p = get_membuf (&mb2, &n);
      if (!p)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      mb_write_string (&mb, p, n);
      xfree (p);
      init_membuf_secure (&mb2, 1024);
      mb_write_string (&mb2, identifier, strlen (identifier));
      {
        char checkbytes[4];
        gcry_create_nonce (checkbytes, sizeof checkbytes);
        mb_write_data (&mb2, checkbytes, sizeof checkbytes);
        mb_write_data (&mb2, checkbytes, sizeof checkbytes);
      }
      mb_write_mpi (&mb2, keyparam[0], 0);  /* n */
      mb_write_mpi (&mb2, keyparam[1], 0);  /* e */
      /*FIXME: Fixup u,p,q to match the OpenSSH format.  */
      mb_write_mpi (&mb2, keyparam[2], 0);  /* d */
      mb_write_mpi (&mb2, keyparam[1], 0);  /* iqmp1 */
      mb_write_mpi (&mb2, keyparam[3], 0);  /* p */
      mb_write_mpi (&mb2, keyparam[4], 0);  /* q */
      /* Fixme: take the comment from skey.  */
      mb_write_string (&mb2, "<comment>", 9);
      /* Pad to a blocksize of 8 (for cipher "none").  */
      i = 0;
      while (peek_membuf (&mb2, &n) && (n % 8))
        mb_write_uint8 (&mb2, ++i);
      /* Append encrypted block to the output as an SSH string.  */
      p = get_membuf (&mb2, &n);
      if (!p)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      mb_write_string (&mb, p, n);
      xfree (p);
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;

    /* case PUBKEY_ALGO_ECDSA: */
    /*   { */
    /*     char *curveoid; */
    /*     const char *curve; */

    /*     curveoid = openpgp_oid_to_str (pk->pkey[0]); */
    /*     if (!curveoid) */
    /*       err = gpg_error_from_syserror (); */
    /*     else if (!(curve = openpgp_oid_to_curve (curveoid, 0))) */
    /*       err = gpg_error (GPG_ERR_UNKNOWN_CURVE); */
    /*     else */
    /*       { */
    /*         if (!strcmp (curve, "nistp256")) */
    /*           identifier = "ecdsa-sha2-nistp256"; */
    /*         else if (!strcmp (curve, "nistp384")) */
    /*           identifier = "ecdsa-sha2-nistp384"; */
    /*         else if (!strcmp (curve, "nistp521")) */
    /*           identifier = "ecdsa-sha2-nistp521"; */

    /*         if (!identifier) */
    /*           err = gpg_error (GPG_ERR_UNKNOWN_CURVE); */
    /*         else */
    /*           err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL); */
    /*       } */
    /*     xfree (curveoid); */
    /*   } */
    /*   break; */

    /* case PUBKEY_ALGO_EDDSA: */
    /*   if (openpgp_oid_is_ed25519 (pk->pkey[0])) */
    /*     { */
    /*       identifier = "ssh-ed25519"; */
    /*       err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL); */
    /*     } */
    /*   else if (openpgp_oid_is_ed448 (pk->pkey[0])) */
    /*     { */
    /*       identifier = "ssh-ed448"; */
    /*       err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL); */
    /*     } */
    /*   else */
    /*     err = gpg_error (GPG_ERR_UNKNOWN_CURVE); */
    /*   break; */

    case PUBKEY_ALGO_DSA:
      log_info ("Note: export of ssh-dsa keys is not supported\n");
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      break;

    case PUBKEY_ALGO_ELGAMAL_E:
    case PUBKEY_ALGO_ELGAMAL:
      err = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      break;

    default:
      err = GPG_ERR_PUBKEY_ALGO;
      break;
    }

  if (err)
    goto leave;

  blob = get_membuf (&mb, &bloblen);
  if (!blob)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (opt.outfile && *opt.outfile && strcmp (opt.outfile, "-"))
    fp = es_fopen ((fname = opt.outfile), "w");
  else
    fp = es_stdout;
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating '%s': %s\n"), fname, gpg_strerror (err));
      goto leave;
    }

  err = b64enc_start_es (&b64_state, fp, "OPENSSH PRIVATE_KEY");
  if (err)
    goto leave;
  err = b64enc_write (&b64_state, blob, bloblen);
  b64enc_finish (&b64_state);
  if (err)
    goto leave;

  if (es_ferror (fp))
    err = gpg_error_from_syserror ();
  else
    {
      if (fp != es_stdout && es_fclose (fp))
        err = gpg_error_from_syserror ();
      fp = NULL;
    }

  log_info ("Beware: the private key is not protected;"
            " use \"ssh-keygen -p\" to protect it\n");
  if (err)
    log_error (_("error writing '%s': %s\n"), fname, gpg_strerror (err));


 leave:
  xfree (blob);
  gcry_sexp_release (skey);
  gcry_sexp_release (skeyalgo);
  gcry_cipher_close (cipherhd);
  xfree (get_membuf (&mb2, NULL));
  xfree (get_membuf (&mb, NULL));
  if (fp != es_stdout)
    es_fclose (fp);
  return err;
}
