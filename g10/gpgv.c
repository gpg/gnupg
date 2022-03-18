/* gpgv.c - The GnuPG signature verify utility
 * Copyright (C) 1998-2020 Free Software Foundation, Inc.
 * Copyright (C) 1998-2019 Werner Koch
 * Copyright (C) 2015-2020 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_DOSISH_SYSTEM
#include <fcntl.h> /* for setmode() */
#endif
#ifdef HAVE_LIBREADLINE
#define GNUPG_LIBREADLINE_H_INCLUDED
#include <readline/readline.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/iobuf.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "filter.h"
#include "../common/ttyio.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/status.h"
#include "call-agent.h"
#include "../common/init.h"


enum cmd_and_opt_values {
  aNull = 0,
  oQuiet	  = 'q',
  oVerbose	  = 'v',
  oOutput	  = 'o',
  oBatch	  = 500,
  oKeyring,
  oIgnoreTimeConflict,
  oStatusFD,
  oLoggerFD,
  oLoggerFile,
  oHomedir,
  oWeakDigest,
  oEnableSpecialFilenames,
  oDebug,
  aTest
};


static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,   "quiet",   N_("be somewhat more quiet")),
  ARGPARSE_s_s (oKeyring, "keyring",
                N_("|FILE|take the keys from the keyring FILE")),
  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict",
                N_("make timestamp conflicts only a warning")),
  ARGPARSE_s_i (oStatusFD, "status-fd",
                N_("|FD|write status info to this FD")),
  ARGPARSE_s_i (oLoggerFD, "logger-fd", "@"),
  ARGPARSE_s_s (oLoggerFile, "log-file", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_s (oWeakDigest, "weak-digest",
                N_("|ALGO|reject signatures made with ALGO")),
  ARGPARSE_s_n (oEnableSpecialFilenames, "enable-special-filenames", "@"),
  ARGPARSE_s_s (oDebug, "debug", "@"),

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_PACKET_VALUE , "packet"  },
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_FILTER_VALUE , "filter"  },
    { DBG_IOBUF_VALUE  , "iobuf"   },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_TRUST_VALUE  , "trust"   },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_CLOCK_VALUE  , "clock"   },
    { DBG_LOOKUP_VALUE , "lookup"  },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };


int g10_errors_seen = 0;


static char *
make_libversion (const char *libname, const char *(*getfnc)(const char*))
{
  const char *s;
  char *result;

  s = getfnc (NULL);
  result = xmalloc (strlen (libname) + 1 + strlen (s) + 1);
  strcpy (stpcpy (stpcpy (result, libname), " "), s);
  return result;
}

static const char *
my_strusage( int level )
{
  static char *ver_gcry;
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "@GPG@v (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: gpgv [options] [files] (-h for help)");
      break;
    case 41: p = _("Syntax: gpgv [options] [files]\n"
                   "Check signatures against known trusted keys\n");
	break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;


    default: p = NULL;
    }
  return p;
}



int
main( int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int rc=0;
  strlist_t sl;
  strlist_t nrings = NULL;
  ctrl_t ctrl;

  early_system_init ();
  set_strusage (my_strusage);
  log_set_prefix ("gpgv", GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

  gnupg_init_signals (0, NULL);

  opt.command_fd = -1; /* no command fd */
  opt.keyserver_options.options |= KEYSERVER_AUTO_KEY_RETRIEVE;
  opt.trust_model = TM_ALWAYS;
  opt.no_sig_cache = 1;
  opt.flags.require_cross_cert = 1;
  opt.batch = 1;
  opt.answer_yes = 1;

  opt.weak_digests = NULL;

  tty_no_terminal(1);
  tty_batchmode(1);
  dotlock_disable ();
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  additional_weak_digest("MD5");
  gnupg_initialize_compliance (GNUPG_MODULE_NAME_GPG);

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= ARGPARSE_FLAG_KEEP;
  while (gnupg_argparser (&pargs, opts, NULL))
    {
      switch (pargs.r_opt)
        {
        case ARGPARSE_CONFFILE: break;

        case oQuiet: opt.quiet = 1; break;
        case oVerbose:
          opt.verbose++;
          opt.list_sigs=1;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;
        case oDebug:
          if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
          break;
        case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
        case oOutput: opt.outfile = pargs.r.ret_str; break;
        case oStatusFD:
          set_status_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
          break;
        case oLoggerFD:
          log_set_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
          break;
        case oLoggerFile:
          log_set_file (pargs.r.ret_str);
          log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX
                                 | GPGRT_LOG_WITH_TIME
                                 | GPGRT_LOG_WITH_PID) );
          break;
        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;
        case oWeakDigest:
          additional_weak_digest(pargs.r.ret_str);
          break;
        case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
        case oEnableSpecialFilenames:
          enable_special_filenames ();
          break;
        default : pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  gnupg_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (log_get_errorcount (0))
    g10_exit(2);

  if (opt.verbose > 1)
    set_packet_list_mode(1);

  /* Note: We open all keyrings in read-only mode.  */
  if (!nrings)  /* No keyring given: use default one. */
    keydb_add_resource ("trustedkeys" EXTSEP_S "kbx",
                        (KEYDB_RESOURCE_FLAG_READONLY
                         |KEYDB_RESOURCE_FLAG_GPGVDEF));
  for (sl = nrings; sl; sl = sl->next)
    keydb_add_resource (sl->d, KEYDB_RESOURCE_FLAG_READONLY);

  FREE_STRLIST (nrings);

  ctrl = xcalloc (1, sizeof *ctrl);

  if ((rc = verify_signatures (ctrl, argc, argv)))
    log_error("verify signatures failed: %s\n", gpg_strerror (rc) );

  keydb_release (ctrl->cached_getkey_kdb);
  xfree (ctrl);

  /* cleanup */
  g10_exit (0);
  return 8; /*NOTREACHED*/
}


void
g10_exit( int rc )
{
  rc = rc? rc : log_get_errorcount(0)? 2 : g10_errors_seen? 1 : 0;
  exit(rc );
}


/* Stub:
 * We have to override the trustcheck from pkclist.c because
 * this utility assumes that all keys in the keyring are trustworthy
 */
int
check_signatures_trust (ctrl_t ctrl, PKT_signature *sig)
{
  (void)ctrl;
  (void)sig;
  return 0;
}

void
read_trust_options (ctrl_t ctrl,
                    byte *trust_model, ulong *created, ulong *nextcheck,
                    byte *marginals, byte *completes, byte *cert_depth,
                    byte *min_cert_level)
{
  (void)ctrl;
  (void)trust_model;
  (void)created;
  (void)nextcheck;
  (void)marginals;
  (void)completes;
  (void)cert_depth;
  (void)min_cert_level;
}

/* Stub:
 * We don't have the trustdb , so we have to provide some stub functions
 * instead
 */

int
cache_disabled_value (ctrl_t ctrl, PKT_public_key *pk)
{
  (void)ctrl;
  (void)pk;
  return 0;
}

void
check_trustdb_stale (ctrl_t ctrl)
{
  (void)ctrl;
}

int
get_validity_info (ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk,
                   PKT_user_id *uid)
{
  (void)ctrl;
  (void)kb;
  (void)pk;
  (void)uid;
  return '?';
}

unsigned int
get_validity (ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk, PKT_user_id *uid,
              PKT_signature *sig, int may_ask)
{
  (void)ctrl;
  (void)kb;
  (void)pk;
  (void)uid;
  (void)sig;
  (void)may_ask;
  return 0;
}

const char *
trust_value_to_string (unsigned int value)
{
  (void)value;
  return "err";
}

const char *
uid_trust_string_fixed (ctrl_t ctrl, PKT_public_key *key, PKT_user_id *uid)
{
  (void)ctrl;
  (void)key;
  (void)uid;
  return "err";
}

int
get_ownertrust_info (ctrl_t ctrl, PKT_public_key *pk, int no_create)
{
  (void)ctrl;
  (void)pk;
  (void)no_create;
  return '?';
}

unsigned int
get_ownertrust (ctrl_t ctrl, PKT_public_key *pk)
{
  (void)ctrl;
  (void)pk;
  return TRUST_UNKNOWN;
}


/* Stubs:
 * Because we only work with trusted keys, it does not make sense to
 * get them from a keyserver
 */

struct keyserver_spec *
keyserver_match (struct keyserver_spec *spec)
{
  (void)spec;
  return NULL;
}

int
keyserver_any_configured (ctrl_t ctrl)
{
  (void)ctrl;
  return 0;
}

int
keyserver_import_keyid (u32 *keyid, void *dummy, unsigned int flags)
{
  (void)keyid;
  (void)dummy;
  (void)flags;
  return -1;
}

int
keyserver_import_fprint (ctrl_t ctrl, const byte *fprint,size_t fprint_len,
			 struct keyserver_spec *keyserver, unsigned int flags)
{
  (void)ctrl;
  (void)fprint;
  (void)fprint_len;
  (void)keyserver;
  (void)flags;
  return -1;
}

int
keyserver_import_fprint_ntds (ctrl_t ctrl,
                              const byte *fprint, size_t fprint_len)
{
  (void)ctrl;
  (void)fprint;
  (void)fprint_len;
  return -1;
}

int
keyserver_import_cert (const char *name)
{
  (void)name;
  return -1;
}

int
keyserver_import_pka (const char *name,unsigned char *fpr)
{
  (void)name;
  (void)fpr;
  return -1;
}

gpg_error_t
keyserver_import_wkd (ctrl_t ctrl, const char *name, unsigned int flags,
                      unsigned char **fpr, size_t *fpr_len)
{
  (void)ctrl;
  (void)name;
  (void)flags;
  (void)fpr;
  (void)fpr_len;
  return GPG_ERR_BUG;
}

int
keyserver_import_mbox (const char *name,struct keyserver_spec *spec)
{
  (void)name;
  (void)spec;
  return -1;
}

int
keyserver_import_ntds (ctrl_t ctrl, const char *mbox,
                       unsigned char **fpr, size_t *fprlen)
{
  (void)ctrl;
  (void)mbox;
  (void)fpr;
  (void)fprlen;
  return -1;
}

int
keyserver_import_ldap (const char *name)
{
  (void)name;
  return -1;
}


gpg_error_t
read_key_from_file_or_buffer (ctrl_t ctrl, const char *fname,
                              const void *buffer, size_t buflen,
                              kbnode_t *r_keyblock)
{
  (void)ctrl;
  (void)fname;
  (void)buffer;
  (void)buflen;
  (void)r_keyblock;
  return -1;
}

gpg_error_t
import_included_key_block (ctrl_t ctrl, kbnode_t keyblock)
{
  (void)ctrl;
  (void)keyblock;
  return -1;
}


/* Stub:
 * No encryption here but mainproc links to these functions.
 */
gpg_error_t
get_session_key (ctrl_t ctrl, PKT_pubkey_enc *k, DEK *dek)
{
  (void)ctrl;
  (void)k;
  (void)dek;
  return GPG_ERR_GENERAL;
}

/* Stub: */
gpg_error_t
get_override_session_key (DEK *dek, const char *string)
{
  (void)dek;
  (void)string;
  return GPG_ERR_GENERAL;
}

/* Stub: */
int
decrypt_data (ctrl_t ctrl, void *procctx, PKT_encrypted *ed, DEK *dek,
              int *compliance_error)
{
  (void)ctrl;
  (void)procctx;
  (void)ed;
  (void)dek;
  (void)compliance_error;
  return GPG_ERR_GENERAL;
}


/* Stub:
 * No interactive commands, so we don't need the helptexts
 */
void
display_online_help (const char *keyword)
{
  (void)keyword;
}

/* Stub:
 * We don't use secret keys, but getkey.c links to this
 */
int
check_secret_key (PKT_public_key *pk, int n)
{
  (void)pk;
  (void)n;
  return GPG_ERR_GENERAL;
}

/* Stub:
 * No secret key, so no passphrase needed
 */
DEK *
passphrase_to_dek (int cipher_algo, STRING2KEY *s2k, int create, int nocache,
                   const char *tmp, unsigned int flags, int *canceled)
{
  (void)cipher_algo;
  (void)s2k;
  (void)create;
  (void)nocache;
  (void)tmp;
  (void)flags;

  if (canceled)
    *canceled = 0;
  return NULL;
}

void
passphrase_clear_cache (const char *cacheid)
{
  (void)cacheid;
}

struct keyserver_spec *
parse_preferred_keyserver(PKT_signature *sig)
{
  (void)sig;
  return NULL;
}

struct keyserver_spec *
parse_keyserver_uri (const char *uri, int require_scheme,
                     const char *configname, unsigned int configlineno)
{
  (void)uri;
  (void)require_scheme;
  (void)configname;
  (void)configlineno;
  return NULL;
}

void
free_keyserver_spec (struct keyserver_spec *keyserver)
{
  (void)keyserver;
}

/* Stubs to avoid linking to photoid.c */
void
show_photos (const struct user_attribute *attrs, int count, PKT_public_key *pk)
{
  (void)attrs;
  (void)count;
  (void)pk;
}

int
parse_image_header (const struct user_attribute *attr, byte *type, u32 *len)
{
  (void)attr;
  (void)type;
  (void)len;
  return 0;
}

char *
image_type_to_string (byte type, int string)
{
  (void)type;
  (void)string;
  return NULL;
}

#ifdef ENABLE_CARD_SUPPORT
int
agent_scd_getattr (const char *name, struct agent_card_info_s *info)
{
  (void)name;
  (void)info;
  return 0;
}
#endif /* ENABLE_CARD_SUPPORT */

/* We do not do any locking, so use these stubs here */
void
dotlock_disable (void)
{
}

dotlock_t
dotlock_create (const char *file_to_lock, unsigned int flags)
{
  (void)file_to_lock;
  (void)flags;
  return NULL;
}

void
dotlock_destroy (dotlock_t h)
{
  (void)h;
}

int
dotlock_take (dotlock_t h, long timeout)
{
  (void)h;
  (void)timeout;
  return 0;
}

int
dotlock_release (dotlock_t h)
{
  (void)h;
  return 0;
}

void
dotlock_remove_lockfiles (void)
{
}

gpg_error_t
agent_probe_secret_key (ctrl_t ctrl, PKT_public_key *pk)
{
  (void)ctrl;
  (void)pk;
  return gpg_error (GPG_ERR_NO_SECKEY);
}

gpg_error_t
agent_probe_any_secret_key (ctrl_t ctrl, kbnode_t keyblock)
{
  (void)ctrl;
  (void)keyblock;
  return gpg_error (GPG_ERR_NO_SECKEY);
}

gpg_error_t
agent_get_keyinfo (ctrl_t ctrl, const char *hexkeygrip,
                   char **r_serialno, int *r_cleartext)
{
  (void)ctrl;
  (void)hexkeygrip;
  (void)r_cleartext;
  *r_serialno = NULL;
  return gpg_error (GPG_ERR_NO_SECKEY);
}

gpg_error_t
gpg_dirmngr_get_pka (ctrl_t ctrl, const char *userid,
                     unsigned char **r_fpr, size_t *r_fprlen,
                     char **r_url)
{
  (void)ctrl;
  (void)userid;
  if (r_fpr)
    *r_fpr = NULL;
  if (r_fprlen)
    *r_fprlen = 0;
  if (r_url)
    *r_url = NULL;
  return gpg_error (GPG_ERR_NOT_FOUND);
}

gpg_error_t
export_pubkey_buffer (ctrl_t ctrl, const char *keyspec, unsigned int options,
                      const void *prefix, size_t prefixlen,
                      export_stats_t stats,
                      kbnode_t *r_keyblock, void **r_data, size_t *r_datalen)
{
  (void)ctrl;
  (void)keyspec;
  (void)options;
  (void)prefix;
  (void)prefixlen;
  (void)stats;

  *r_keyblock = NULL;
  *r_data = NULL;
  *r_datalen = 0;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}

gpg_error_t
tofu_write_tfs_record (ctrl_t ctrl, estream_t fp,
                       PKT_public_key *pk, const char *user_id)
{
  (void)ctrl;
  (void)fp;
  (void)pk;
  (void)user_id;
  return gpg_error (GPG_ERR_GENERAL);
}

gpg_error_t
tofu_get_policy (ctrl_t ctrl, PKT_public_key *pk, PKT_user_id *user_id,
		 enum tofu_policy *policy)
{
  (void)ctrl;
  (void)pk;
  (void)user_id;
  (void)policy;
  return gpg_error (GPG_ERR_GENERAL);
}

const char *
tofu_policy_str (enum tofu_policy policy)
{
  (void)policy;

  return "unknown";
}

void
tofu_begin_batch_update (ctrl_t ctrl)
{
  (void)ctrl;
}

void
tofu_end_batch_update (ctrl_t ctrl)
{
  (void)ctrl;
}

gpg_error_t
tofu_notice_key_changed (ctrl_t ctrl, kbnode_t kb)
{
  (void) ctrl;
  (void) kb;

  return 0;
}


int
get_revocation_reason (PKT_signature *sig, char **r_reason,
                       char **r_comment, size_t *r_commentlen)
{
  (void)sig;
  (void)r_commentlen;

  if (r_reason)
    *r_reason = NULL;
  if (r_comment)
    *r_comment = NULL;
  return 0;
}
