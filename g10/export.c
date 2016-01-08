/* export.c - Export keys in the OpenPGP defined format.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2010 Free Software Foundation, Inc.
 * Copyright (C) 1998-2016  Werner Koch
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

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "status.h"
#include "keydb.h"
#include "util.h"
#include "main.h"
#include "i18n.h"
#include "membuf.h"
#include "host2net.h"
#include "trustdb.h"
#include "call-agent.h"

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


/* Local prototypes.  */
static int do_export (ctrl_t ctrl, strlist_t users, int secret,
                      unsigned int options, export_stats_t stats);
static int do_export_stream (ctrl_t ctrl, iobuf_t out,
                             strlist_t users, int secret,
                             kbnode_t *keyblock_out, unsigned int options,
			     export_stats_t stats, int *any);




/* Option parser for export options.  See parse_options fro
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
      {"export-minimal",EXPORT_MINIMAL|EXPORT_CLEAN,NULL,
       N_("remove as much as possible from key during export")},
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

  return parse_options(str,options,export_opts,noisy);
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
 * Depending on opt.armor the output is armored.  If USERS is NULL,
 * all secret keys will be exported.  STATS is either an export stats
 * object for update or NULL.
 *
 * This function is the core of "gpg --export-secret-keys".
 */
int
export_seckeys (ctrl_t ctrl, strlist_t users, export_stats_t stats)
{
  return do_export (ctrl, users, 1, 0, stats);
}


/*
 * Export secret sub keys (to stdout or to --output FILE).
 *
 * This is the same as export_seckeys but replaces the primary key by
 * a stub key.  Depending on opt.armor the output is armored.  If
 * USERS is NULL, all secret subkeys will be exported.  STATS is
 * either an export stats object for update or NULL.
 *
 * This function is the core of "gpg --export-secret-subkeys".
 */
int
export_secsubkeys (ctrl_t ctrl, strlist_t users, export_stats_t stats)
{
  return do_export (ctrl, users, 2, 0, stats);
}


/*
 * Export a single key into a memory buffer.  STATS is either an
 * export stats object for update or NULL.
 */
gpg_error_t
export_pubkey_buffer (ctrl_t ctrl, const char *keyspec, unsigned int options,
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

  if ( opt.armor )
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
static int
exact_subkey_match_p (KEYDB_SEARCH_DESC *desc, KBNODE node)
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

    case KEYDB_SEARCH_MODE_FPR16:
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      fingerprint_from_pk (node->pkt->pkt.public_key, fpr,&fprlen);
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

    case KEYDB_SEARCH_MODE_FPR16:
      if (!memcmp (desc->u.fpr, fpr, 16))
        result = 1;
      break;

    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      if (!memcmp (desc->u.fpr, fpr, 20))
        result = 1;
      break;

    default:
      break;
    }

  return result;
}


/* Return a canonicalized public key algoithms.  This is used to
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
      if (is_enc)
        {
          void *p = xtrymalloc (valuelen);
          if (!p)
            goto outofmem;
          memcpy (p, value, valuelen);
          skey[skeyidx] = gcry_mpi_set_opaque (NULL, p, valuelen*8);
          if (!skey[skeyidx])
            goto outofmem;
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

      oidstr = openpgp_curve_to_oid (curve, NULL);
      if (!oidstr)
        {
          log_error ("no OID known for curve '%s'\n", curve);
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
          goto leave;
        }
      /* Put the curve's OID into into the MPI array.  This requires
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
  if (!gcry_mpi_get_flag (skey[npkey], GCRYMPI_FLAG_OPAQUE))
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
  assert (sizeof ski->s2k.salt == sizeof s2k_salt);
  memcpy (ski->s2k.salt, s2k_salt, sizeof s2k_salt);
  ski->s2k.count = s2k_count;
  assert (ivlen <= sizeof ski->iv);
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
 * Since the key data from agant is encrypted, decrypt it by CIPHERHD.
 * Then, parse the decrypted key data in transfer format, and put
 * secret papameters into PK.
 *
 * CACHE_NONCE_ADDR is used to share nonce for multple key retrievals.
 */
gpg_error_t
receive_seckey_from_agent (ctrl_t ctrl, gcry_cipher_hd_t cipherhd,
                           char **cache_nonce_addr, const char *hexgrip,
                           PKT_public_key *pk)
{
  gpg_error_t err = 0;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  unsigned char *key = NULL;
  size_t keylen, realkeylen;
  gcry_sexp_t s_skey;
  char *prompt;

  if (opt.verbose)
    log_info ("key %s: asking agent for the secret parts\n", hexgrip);

  prompt = gpg_format_keydesc (pk, FORMAT_KEYDESC_EXPORT,1);
  err = agent_export_key (ctrl, hexgrip, prompt, cache_nonce_addr,
                          &wrappedkey, &wrappedkeylen);
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
      err = transfer_format_to_openpgp (s_skey, pk);
      gcry_sexp_release (s_skey);
    }

 unwraperror:
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


/* Export the keys identified by the list of strings in USERS to the
   stream OUT.  If Secret is false public keys will be exported.  With
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
  KBNODE keyblock = NULL;
  KBNODE kbctx, node;
  size_t ndesc, descindex;
  KEYDB_SEARCH_DESC *desc = NULL;
  subkey_list_t subkey_list = NULL;  /* Track already processed subkeys. */
  KEYDB_HANDLE kdbhd;
  strlist_t sl;
  gcry_cipher_hd_t cipherhd = NULL;
  char *cache_nonce = NULL;
  struct export_stats_s dummystats;

  if (!stats)
    stats = &dummystats;
  *any = 0;
  init_packet (&pkt);
  kdbhd = keydb_new ();
  if (!kdbhd)
    return gpg_error_from_syserror ();

  /* For the DANE format override the options.  */
  if ((options & EXPORT_DANE_FORMAT))
    options = (EXPORT_DANE_FORMAT | EXPORT_MINIMAL | EXPORT_CLEAN);


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

#ifdef ENABLE_SELINUX_HACKS
  if (secret)
    {
      log_error (_("exporting secret keys not allowed\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }
#endif

  /* For secret key export we need to setup a decryption context.  */
  if (secret)
    {
      void *kek = NULL;
      size_t keklen;

      err = agent_keywrap_key (ctrl, 1, &kek, &keklen);
      if (err)
        {
          log_error ("error getting the KEK: %s\n", gpg_strerror (err));
          goto leave;
        }

      /* Prepare a cipher context.  */
      err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                              GCRY_CIPHER_MODE_AESWRAP, 0);
      if (!err)
        err = gcry_cipher_setkey (cipherhd, kek, keklen);
      if (err)
        {
          log_error ("error setting up an encryption context: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      xfree (kek);
      kek = NULL;
    }

  for (;;)
    {
      int skip_until_subkey = 0;
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

          /* The agent does not yet allow to export v3 packets.  It is
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
         Note that we don't yet set this option if we are exporting
         secret keys.  Note that both export-clean and export-minimal
         only apply to UID sigs (0x10, 0x11, 0x12, and 0x13).  A
         designated revocation is never stripped, even with
         export-minimal set.  */
      if ((options & EXPORT_CLEAN))
        clean_key (keyblock, opt.verbose, (options&EXPORT_MINIMAL), NULL, NULL);

      /* And write it. */
      xfree (cache_nonce);
      cache_nonce = NULL;
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
             case we still have comments on a key, strip them here
             before we call build_packet(). */
          if (node->pkt->pkttype == PKT_COMMENT)
            continue;

          /* Make sure that ring_trust packets never get exported. */
          if (node->pkt->pkttype == PKT_RING_TRUST)
            continue;

          /* If exact is set, then we only export what was requested
             (plus the primary key, if the user didn't specifically
             request it). */
          if (desc[descindex].exact
              && node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
            {
              if (!exact_subkey_match_p (desc+descindex, node))
                {
                  /* Before skipping this subkey, check whether any
                     other description wants an exact match on a
                     subkey and include that subkey into the output
                     too.  Need to add this subkey to a list so that
                     it won't get processed a second time.

                     So the first step here is to check that list and
                     skip in any case if the key is in that list.

                     We need this whole mess because the import
                     function of GnuPG < 2.1 is not able to merge
                     secret keys and thus it is useless to output them
                     as two separate keys and have import merge them.  */
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

              if(skip_until_subkey)
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
                 exportable.  */
              if (!(options&EXPORT_LOCAL_SIGS)
                  && !node->pkt->pkt.signature->flags.exportable)
                continue; /* not exportable */

              /* Do not export packets with a "sensitive" revocation
                 key unless the user wants us to.  Note that we do
                 export these when issuing the actual revocation
                 (see revoke.c). */
              if (!(options&EXPORT_SENSITIVE_REVKEYS)
                  && node->pkt->pkt.signature->revkey)
                {
                  int i;

                  for (i=0;i<node->pkt->pkt.signature->numrevkeys;i++)
                    if ( (node->pkt->pkt.signature->revkey[i].class & 0x40))
                      break;

                  if (i < node->pkt->pkt.signature->numrevkeys)
                    continue;
                }
            }

          /* Don't export attribs? */
          if (!(options&EXPORT_ATTRIBUTES)
              && node->pkt->pkttype == PKT_USER_ID
              && node->pkt->pkt.user_id->attrib_data )
            {
	      /* Skip until we get to something that is not an attrib
		 or a signature on an attrib */
	      while (kbctx->next && kbctx->next->pkt->pkttype==PKT_SIGNATURE)
                kbctx = kbctx->next;

	      continue;
	    }

          if (secret && (node->pkt->pkttype == PKT_PUBLIC_KEY
                         || node->pkt->pkttype == PKT_PUBLIC_SUBKEY))
            {
              u32 subkidbuf[2], *subkid;
              char *hexgrip, *serialno;

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

              if (secret == 2 && node->pkt->pkttype == PKT_PUBLIC_KEY)
                {
                  /* We are asked not to export the secret parts of
                     the primary key.  Make up an error code to create
                     the stub.  */
                  err = GPG_ERR_NOT_FOUND;
                  serialno = NULL;
                }
              else
                err = agent_get_keyinfo (ctrl, hexgrip, &serialno);

              if ((!err && serialno)
                  && secret == 2 && node->pkt->pkttype == PKT_PUBLIC_KEY)
                {
                  /* It does not make sense to export a key with its
                     primary key on card using a non-key stub.  Thus
                     we skip those keys when used with
                     --export-secret-subkeys. */
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
                      xfree (hexgrip);
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

                  err = build_packet (out, node->pkt);
                  if (!err && node->pkt->pkttype == PKT_PUBLIC_KEY)
                    {
                      stats->exported++;
                      print_status_exported (node->pkt->pkt.public_key);
                    }
                }
              else if (!err)
                {
                  err = receive_seckey_from_agent (ctrl, cipherhd, &cache_nonce,
                                                   hexgrip, pk);
                  if (err)
                    {
                      if (gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
                        goto leave;
                      skip_until_subkey = 1;
                      err = 0;
                    }
                  else
                    {
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
              xfree (hexgrip);
            }
          else
            {
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

      if (keyblock_out)
        {
          *keyblock_out = keyblock;
          break;
        }
    }
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    err = 0;

 leave:
  gcry_cipher_close (cipherhd);
  release_subkey_list (subkey_list);
  xfree(desc);
  keydb_release (kdbhd);
  if (err || !keyblock_out)
    release_kbnode( keyblock );
  xfree (cache_nonce);
  if( !*any )
    log_info(_("WARNING: nothing exported\n"));
  return err;
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

  ulongtobuf (nbuf, (ulong)strlen (identifier));
  put_membuf (mb, nbuf, 4);
  put_membuf_str (mb, identifier);
  if (!strncmp (identifier, "ecdsa-sha2-", 11))
    {
      ulongtobuf (nbuf, (ulong)strlen (identifier+11));
      put_membuf (mb, nbuf, 4);
      put_membuf_str (mb, identifier+11);
    }
  va_start (arg_ptr, identifier);
  while ((a = va_arg (arg_ptr, gcry_mpi_t)))
    {
      err = gcry_mpi_aprint (GCRYMPI_FMT_SSH, &buf, &buflen, a);
      if (err)
        break;
      if (!strcmp (identifier, "ssh-ed25519")
          && buflen > 5 && buf[4] == 0x40)
        {
          /* We need to strip our 0x40 prefix.  */
          put_membuf (mb, "\x00\x00\x00\x20", 4);
          put_membuf (mb, buf+5, buflen-5);
        }
      else
        put_membuf (mb, buf, buflen);
      gcry_free (buf);
    }
  va_end (arg_ptr);
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
  const char *identifier;
  membuf_t mb;
  estream_t fp = NULL;
  struct b64state b64_state;
  const char *fname = "-";

  init_membuf (&mb, 4096);

  /* We need to know whether the key has been specified using the
     exact syntax ('!' suffix).  Thus we need to run a
     classify_user_id on our own.  */
  err = classify_user_id (userid, &desc, 1);

  /* Get the public key.  */
  if (!err)
    {
      getkey_ctx_t getkeyctx;

      err = get_pubkey_byname (ctrl, &getkeyctx, NULL, userid, &keyblock,
                               NULL,
                               0  /* Only usable keys or given exact. */,
                               1  /* No AKL lookup.  */);
      if (!err)
        {
          err = getkey_next (getkeyctx, NULL, NULL);
          if (!err)
            err = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
          else if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
            err = 0;
        }
      getkey_end (getkeyctx);
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
            else
              identifier = NULL;

            if (!identifier)
              err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
            else
              err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL);
          }
        xfree (curveoid);
      }
      break;

    case PUBKEY_ALGO_EDDSA:
      if (!openpgp_oid_is_ed25519 (pk->pkey[0]))
        err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      else
        {
          identifier = "ssh-ed25519";
          err = key_to_sshblob (&mb, identifier, pk->pkey[1], NULL);
        }
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

  es_fprintf (fp, "%s ", identifier);
  err = b64enc_start_es (&b64_state, fp, "");
  if (err)
    goto leave;
  {
    void *blob;
    size_t bloblen;

    blob = get_membuf (&mb, &bloblen);
    if (!blob)
      err = gpg_error_from_syserror ();
    else
      err = b64enc_write (&b64_state, blob, bloblen);
    xfree (blob);
    if (err)
      goto leave;
  }
  err = b64enc_finish (&b64_state);
  if (err)
    goto leave;
  es_fprintf (fp, " openpgp:0x%08lX\n", (ulong)keyid_from_pk (pk, NULL));

  if (es_ferror (fp))
    err = gpg_error_from_syserror ();
  else
    {
      if (es_fclose (fp))
        err = gpg_error_from_syserror ();
      fp = NULL;
    }

  if (err)
    log_error (_("error writing '%s': %s\n"), fname, gpg_strerror (err));

 leave:
  es_fclose (fp);
  xfree (get_membuf (&mb, NULL));
  release_kbnode (keyblock);
  return err;
}
