/* gpgsm.c - GnuPG for S/MIME 
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h> /* malloc hooks */

#include "../kbx/keybox.h" /* malloc hooks */
#include "i18n.h"
#include "keydb.h"
#include "sysutils.h"

enum cmd_and_opt_values {
  aNull = 0,
  oArmor        = 'a',
  aDetachedSign = 'b',
  aSym	        = 'c',
  aDecrypt	= 'd',
  aEncr	        = 'e',
  oInteractive  = 'i',
  aListKeys	= 'k',
  aListSecretKeys = 'K',
  oDryRun	= 'n',
  oOutput	= 'o',
  oQuiet	= 'q',
  oRecipient	= 'r',
  aSign	        = 's',
  oTextmodeShort= 't',
  oUser	        = 'u',
  oVerbose	= 'v',
  oCompress	= 'z',
  oNotation	= 'N',
  oBatch	= 500,
  aClearsign,
  aStore,
  aKeygen,
  aSignEncr,
  aSignKey,
  aLSignKey,
  aListPackets,
  aEditKey,
  aDeleteKey,
  aImport,
  aVerify,
  aVerifyFiles,
  aListExternalKeys,
  aListSigs,
  aSendKeys,
  aRecvKeys,
  aExport,
  aExportSecretKeyP12,
  aCheckKeys, /* nyi */
  aServer,                        
  aLearnCard,
  aCallDirmngr,
  aCallProtectTool,
  aPasswd,
  aGPGConfList,
  aDumpKeys,
  aDumpSecretKeys,
  aDumpExternalKeys,
  aKeydbClearSomeCertFlags,

  oOptions,
  oDebug,
  oDebugLevel,
  oDebugAll,
  oDebugWait,
  oDebugAllowCoreDump,
  oDebugNoChainValidation,
  oDebugIgnoreExpiration,
  oLogFile,

  oEnableSpecialFilenames,

  oAgentProgram,
  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,

  oDirmngrProgram,
  oProtectToolProgram,
  oFakedSystemTime,


  oAssumeArmor,
  oAssumeBase64,
  oAssumeBinary,

  oBase64,
  oNoArmor,

  oDisableCRLChecks,
  oEnableCRLChecks,
  oForceCRLRefresh,

  oDisableOCSP,
  oEnableOCSP,

  oIncludeCerts,
  oPolicyFile,
  oDisablePolicyChecks,
  oEnablePolicyChecks,
  oAutoIssuerKeyRetrieve,
  

  oTextmode,
  oFingerprint,
  oWithFingerprint,
  oWithMD5Fingerprint,
  oAnswerYes,
  oAnswerNo,
  oKeyring,
  oSecretKeyring,
  oDefaultKey,
  oDefRecipient,
  oDefRecipientSelf,
  oNoDefRecipient,
  oStatusFD,
  oNoComment,
  oNoVersion,
  oEmitVersion,
  oCompletesNeeded,
  oMarginalsNeeded,
  oMaxCertDepth,
  oLoadExtension,
  oRFC1991,
  oOpenPGP,
  oCipherAlgo,
  oDigestAlgo,
  oCompressAlgo,
  oCommandFD,
  oNoVerbose,
  oTrustDBName,
  oNoSecmemWarn,
  oNoDefKeyring,
  oNoGreeting,
  oNoTTY,
  oNoOptions,
  oNoBatch,
  oHomedir,
  oWithColons,
  oWithKeyData,
  oWithValidation,
  oSkipVerify,
  oCompressKeys,
  oCompressSigs,
  oAlwaysTrust,
  oRunAsShmCP,
  oSetFilename,
  oSetPolicyURL,
  oUseEmbeddedFilename,
  oComment,
  oDefaultComment,
  oThrowKeyid,
  oForceV3Sigs,
  oForceMDC,
  oS2KMode,
  oS2KDigest,
  oS2KCipher,
  oCharset,
  oNotDashEscaped,
  oEscapeFrom,
  oLockOnce,
  oLockMultiple,
  oLockNever,
  oKeyServer,
  oEncryptTo,
  oNoEncryptTo,
  oLoggerFD,
  oUtf8Strings,
  oNoUtf8Strings,
  oDisableCipherAlgo,
  oDisablePubkeyAlgo,
  oAllowNonSelfsignedUID,
  oAllowFreeformUID,
  oNoLiteral,
  oSetFilesize,
  oHonorHttpProxy,
  oFastListMode,
  oListOnly,
  oIgnoreTimeConflict,
  oNoRandomSeedFile,
  oNoAutoKeyRetrieve,
  oUseAgent,
  oMergeOnly,
  oTryAllSecrets,
  oTrustedKey,
  oEmuMDEncodeBug,
  aDummy
 };


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

    { aSign, "sign",      256, N_("|[FILE]|make a signature")},
    { aClearsign, "clearsign", 256, N_("|[FILE]|make a clear text signature") },
    { aDetachedSign, "detach-sign", 256, N_("make a detached signature")},
    { aEncr, "encrypt",   256, N_("encrypt data")},
    { aSym, "symmetric", 256, N_("encryption only with symmetric cipher")},
    { aDecrypt, "decrypt",   256, N_("decrypt data (default)")},
    { aVerify, "verify"   , 256, N_("verify a signature")},
    { aVerifyFiles, "verify-files" , 256, "@" },
    { aListKeys, "list-keys", 256, N_("list keys")},
    { aListExternalKeys, "list-external-keys", 256, N_("list external keys")},
    { aListSecretKeys, "list-secret-keys", 256, N_("list secret keys")},
    { aListSigs,   "list-sigs", 256, N_("list certificate chain")}, 
    { aListSigs,   "check-sigs",256, "@"},
    { oFingerprint, "fingerprint", 256, N_("list keys and fingerprints")},
    { aKeygen,	   "gen-key",  256, N_("generate a new key pair")},
    { aDeleteKey, "delete-key",256, N_("remove key from the public keyring")},
    { aSendKeys, "send-keys"     , 256, N_("export keys to a key server") },
    { aRecvKeys, "recv-keys"     , 256, N_("import keys from a key server") },
    { aImport, "import",      256     , N_("import certificates")},
    { aExport, "export",      256     , N_("export certificates")},
    { aLearnCard, "learn-card", 256 ,N_("register a smartcard")},
    { aServer, "server",      256, N_("run in server mode")},
    { aCallDirmngr, "call-dirmngr", 256, N_("pass a command to the dirmngr")},
    { aCallProtectTool, "call-protect-tool", 256,
                                   N_("invoke gpg-protect-tool")},
    { aPasswd, "passwd",      256, N_("change a passphrase")},
    { aGPGConfList, "gpgconf-list", 256, "@" },

    { aDumpKeys, "dump-keys", 256, "@"},
    { aDumpExternalKeys, "dump-external-keys", 256, "@"},
    { aDumpSecretKeys, "dump-secret-keys", 256, "@"},
    { aKeydbClearSomeCertFlags, "keydb-clear-some-cert-flags", 256, "@"},

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oArmor, "armor",     0, N_("create ascii armored output")},
    { oArmor, "armour",    0, "@" },
    { oBase64, "base64",    0, N_("create base-64 encoded output")},
    
    { oAssumeArmor,  "assume-armor", 0, N_("assume input is in PEM format")},
    { oAssumeBase64, "assume-base64", 0,
                                      N_("assume input is in base-64 format")},
    { oAssumeBinary, "assume-binary", 0,
                                      N_("assume input is in binary format")},

    { oRecipient, "recipient", 2, N_("|NAME|encrypt for NAME")},


    { oDisableCRLChecks, "disable-crl-checks", 0, N_("never consult a CRL")},
    { oEnableCRLChecks, "enable-crl-checks", 0, "@"},
    { oForceCRLRefresh, "force-crl-refresh", 0, "@"},

    { oDisableOCSP, "disable-ocsp", 0, "@" },
    { oEnableOCSP,  "enable-ocsp", 0, N_("check validity using OCSP")},

    { oIncludeCerts, "include-certs", 1,
                                 N_("|N|number of certificates to include") },

    { oPolicyFile, "policy-file", 2,
                    N_("|FILE|take policy information from FILE") },

    { oDisablePolicyChecks, "disable-policy-checks", 0,
                           N_("do not check certificate policies")},
    { oEnablePolicyChecks, "enable-policy-checks", 0, "@"},

    { oAutoIssuerKeyRetrieve, "auto-issuer-key-retrieve", 0, 
      N_("fetch missing issuer certificates")},

#if 0
    { oDefRecipient, "default-recipient" ,2,
				  N_("|NAME|use NAME as default recipient")},
    { oDefRecipientSelf, "default-recipient-self" ,0,
				N_("use the default key as default recipient")},
    { oNoDefRecipient, "no-default-recipient", 0, "@" },
#endif
    { oEncryptTo, "encrypt-to", 2, "@" },
    { oNoEncryptTo, "no-encrypt-to", 0, "@" },

    { oUser, "local-user",2, N_("use this user-id to sign or decrypt")},

#if 0
    { oCompress, NULL,	      1, N_("|N|set compress level N (0 disables)") },
    { oTextmodeShort, NULL,   0, "@"},
    { oTextmode, "textmode",  0, N_("use canonical text mode")},
#endif

    { oOutput, "output",    2, N_("use as output file")},
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",   0, N_("be somewhat more quiet") },
    { oNoTTY, "no-tty", 0, N_("don't use the terminal at all") },
    { oLogFile, "log-file"   ,2, N_("use a log file for the server")},
#if 0
    { oForceV3Sigs, "force-v3-sigs", 0, N_("force v3 signatures") },
    { oForceMDC, "force-mdc", 0, N_("always use a MDC for encryption") },
#endif
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
  /*{ oInteractive, "interactive", 0, N_("prompt before overwriting") }, */
    /*{ oUseAgent, "use-agent",0, N_("use the gpg-agent")},*/
    { oBatch, "batch",     0, N_("batch mode: never ask")},
    { oAnswerYes, "yes",       0, N_("assume yes on most questions")},
    { oAnswerNo,  "no",        0, N_("assume no on most questions")},

    { oKeyring, "keyring"   ,2, N_("add this keyring to the list of keyrings")},
    { oSecretKeyring, "secret-keyring" ,2, N_("add this secret keyring to the list")},
    { oDefaultKey, "default-key" ,2, N_("|NAME|use NAME as default secret key")},
    { oKeyServer, "keyserver",2, N_("|HOST|use this keyserver to lookup keys")},
    { oCharset, "charset"   , 2, N_("|NAME|set terminal charset to NAME") },
    { oOptions, "options"   , 2, N_("read options from file")},

    { oDebug, "debug"     ,4|16, "@"},
    { oDebugLevel, "debug-level" ,2, "@"},
    { oDebugAll, "debug-all" ,0, "@"},
    { oDebugWait, "debug-wait" ,1, "@"},
    { oDebugAllowCoreDump, "debug-allow-core-dump", 0, "@" },
    { oDebugNoChainValidation, "debug-no-chain-validation", 0, "@"},
    { oDebugIgnoreExpiration,  "debug-ignore-expiration", 0, "@"},
    { oStatusFD, "status-fd" ,1, N_("|FD|write status info to this FD") },
    { aDummy, "no-comment", 0,   "@"},
    { aDummy, "completes-needed", 1, "@"},
    { aDummy, "marginals-needed", 1, "@"},
    { oMaxCertDepth,	"max-cert-depth", 1, "@" },
    { aDummy, "trusted-key", 2, "@"},
    { oLoadExtension, "load-extension" ,2,
      N_("|FILE|load extension module FILE")},
    { aDummy, "rfc1991",   0, "@"},
    { aDummy, "openpgp",   0, "@"},
    { aDummy, "s2k-mode",  1, "@"},
    { aDummy, "s2k-digest-algo",2, "@"},
    { aDummy, "s2k-cipher-algo",2, "@"},
    { oCipherAlgo, "cipher-algo", 2 , N_("|NAME|use cipher algorithm NAME")},
    { oDigestAlgo, "digest-algo", 2 ,
      N_("|NAME|use message digest algorithm NAME")},
#if 0
    { oCompressAlgo, "compress-algo", 1 , N_("|N|use compress algorithm N")},
#endif
    { aDummy, "throw-keyid", 0, "@"},
    { aDummy, "notation-data", 2, "@"},
    { aExportSecretKeyP12, "export-secret-key-p12", 256, "@"}, 
    

    { 302, NULL, 0, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
		      )},

    { 303, NULL, 0, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " --clearsign [file]         make a clear text signature\n"
    " --detach-sign [file]       make a detached signature\n"
    " --list-keys [names]        show keys\n"
    " --fingerprint [names]      show fingerprints\n"  ) },

  /* hidden options */
    { oNoVerbose, "no-verbose", 0, "@"},

    { oEnableSpecialFilenames, "enable-special-filenames", 0, "@" },


    { oTrustDBName, "trustdb-name", 2, "@" },
    { oNoSecmemWarn, "no-secmem-warning", 0, "@" }, 
    { oNoArmor, "no-armor",   0, "@"},
    { oNoArmor, "no-armour",   0, "@"},
    { oNoDefKeyring, "no-default-keyring", 0, "@" },
    { oNoGreeting, "no-greeting", 0, "@" },
    { oNoOptions, "no-options", 0, "@" }, /* shortcut for --options /dev/null */
    { oHomedir, "homedir", 2, "@" },   /* defaults to "~/.gnupg" */
    { oAgentProgram, "agent-program", 2 , "@" },
    { oDisplay,    "display",     2, "@" },
    { oTTYname,    "ttyname",     2, "@" },
    { oTTYtype,    "ttytype",     2, "@" },
    { oLCctype,    "lc-ctype",    2, "@" },
    { oLCmessages, "lc-messages", 2, "@" },
    { oDirmngrProgram, "dirmngr-program", 2 , "@" },
    { oProtectToolProgram, "protect-tool-program", 2 , "@" },
    { oFakedSystemTime, "faked-system-time", 4, "@" }, /* (epoch time) */


    { oNoBatch, "no-batch", 0, "@" },
    { oWithColons, "with-colons", 0, "@"},
    { oWithKeyData,"with-key-data", 0, "@"},
    { oWithValidation, "with-validation", 0, "@"},
    { oWithMD5Fingerprint, "with-md5-fingerprint", 0, "@"},
    { aListKeys, "list-key", 0, "@" }, /* alias */
    { aListSigs, "list-sig", 0, "@" }, /* alias */
    { aListSigs, "check-sig",0, "@" }, /* alias */
    { oSkipVerify, "skip-verify",0, "@" },
    { oCompressKeys, "compress-keys",0, "@"},
    { oCompressSigs, "compress-sigs",0, "@"},
    { oAlwaysTrust, "always-trust", 0, "@"},
    { oNoVersion, "no-version", 0, "@"},
    { oLockOnce, "lock-once", 0, "@" },
    { oLockMultiple, "lock-multiple", 0, "@" },
    { oLockNever, "lock-never", 0, "@" },
    { oLoggerFD, "logger-fd",1, "@" },
    { oWithFingerprint, "with-fingerprint", 0, "@" },
    { oDisableCipherAlgo,  "disable-cipher-algo", 2, "@" },
    { oDisablePubkeyAlgo,  "disable-pubkey-algo", 2, "@" },
    { oHonorHttpProxy,"honor-http-proxy", 0, "@" },
    { oListOnly, "list-only", 0, "@"},
    { oIgnoreTimeConflict, "ignore-time-conflict", 0, "@" },
    { oNoRandomSeedFile,  "no-random-seed-file", 0, "@" },
{0} };



int gpgsm_errors_seen = 0;

/* It is possible that we are currentlu running under setuid permissions */
static int maybe_setuid = 1;

/* Option --enable-special-filenames */
static int allow_special_filenames;


static char *build_list (const char *text,
			 const char *(*mapf)(int), int (*chkf)(int));
static void set_cmd (enum cmd_and_opt_values *ret_cmd,
                     enum cmd_and_opt_values new_cmd );

static void emergency_cleanup (void);
static int check_special_filename (const char *fname);
static int open_read (const char *filename);
static FILE *open_fwrite (const char *filename);
static void run_protect_tool (int argc, char **argv);


static int
our_pk_test_algo (int algo)
{
  return 1;
}

static int
our_cipher_test_algo (int algo)
{
  return 1;
}

static int
our_md_test_algo (int algo)
{
  return 1;
}

static const char *
my_strusage( int level )
{
  static char *digests, *pubkeys, *ciphers;
  const char *p;

  switch (level)
    {
    case 11: p = "gpgsm (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p = _("Usage: gpgsm [options] [files] (-h for help)");
      break;
    case 41:
      p = _("Syntax: gpgsm [options] [files]\n"
            "sign, check, encrypt or decrypt using the S/MIME protocol\n"
            "default operation depends on the input data\n");
      break;

    case 31: p = "\nHome: "; break;
    case 32: p = opt.homedir; break;
    case 33: p = _("\nSupported algorithms:\n"); break;
    case 34:
      if (!ciphers)
        ciphers = build_list ("Cipher: ", gcry_cipher_algo_name,
                              our_cipher_test_algo );
      p = ciphers;
      break;
    case 35:
      if (!pubkeys)
        pubkeys = build_list ("Pubkey: ", gcry_pk_algo_name,
                              our_pk_test_algo );
      p = pubkeys;
      break;
    case 36:
      if (!digests)
        digests = build_list("Hash: ", gcry_md_algo_name, our_md_test_algo );
      p = digests;
      break;
      
    default: p = NULL; break;
    }
  return p;
}


static char *
build_list (const char *text, const char * (*mapf)(int), int (*chkf)(int))
{
  int i;
  size_t n=strlen(text)+2;
  char *list, *p;
  
  if (maybe_setuid) {
    gcry_control (GCRYCTL_DROP_PRIVS); /* drop setuid */
  }

  for (i=1; i < 110; i++ )
    if (!chkf(i))
      n += strlen(mapf(i)) + 2;
  list = xmalloc (21 + n);
  *list = 0;
  for (p=NULL, i=1; i < 110; i++)
    {
      if (!chkf(i))
        {
          if( !p )
            p = stpcpy (list, text );
          else
            p = stpcpy (p, ", ");
          p = stpcpy (p, mapf(i) );
	}
    }
  if (p)
    p = stpcpy(p, "\n" );
  return list;
}


static void
i18n_init(void)
{
#ifdef USE_SIMPLE_GETTEXT
  set_gettext_file (PACKAGE_GT);
#else
# ifdef ENABLE_NLS
#  ifdef HAVE_LC_MESSAGES
  setlocale (LC_TIME, "");
  setlocale (LC_MESSAGES, "");
#  else
  setlocale (LC_ALL, "" );
#  endif
  bindtextdomain (PACKAGE_GT, LOCALEDIR);
  textdomain (PACKAGE_GT);
# endif
#endif
}


static void
wrong_args (const char *text)
{
  fputs (_("usage: gpgsm [options] "), stderr);
  fputs (text, stderr);
  putc ('\n', stderr);
  gpgsm_exit (2);
}


/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. */
static void
set_debug (const char *level)
{
  if (!level)
    ;
  else if (!strcmp (level, "none"))
    opt.debug = 0;
  else if (!strcmp (level, "basic"))
    opt.debug = DBG_ASSUAN_VALUE;
  else if (!strcmp (level, "advanced"))
    opt.debug = DBG_ASSUAN_VALUE|DBG_X509_VALUE;
  else if (!strcmp (level, "expert"))
    opt.debug = (DBG_ASSUAN_VALUE|DBG_X509_VALUE
                 |DBG_CACHE_VALUE|DBG_CRYPTO_VALUE);
  else if (!strcmp (level, "guru"))
    opt.debug = ~0;
  else
    {
      log_error (_("invalid debug-level `%s' given\n"), level);
      gpgsm_exit(2);
    }


  if (opt.debug && !opt.verbose)
    {
      opt.verbose = 1;
      gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
    }
  if (opt.debug && opt.quiet)
    opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
}
 


static void
set_cmd (enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd)
{
  enum cmd_and_opt_values cmd = *ret_cmd;

  if (!cmd || cmd == new_cmd)
    cmd = new_cmd;
  else if ( cmd == aSign && new_cmd == aEncr )
    cmd = aSignEncr;
  else if ( cmd == aEncr && new_cmd == aSign )
    cmd = aSignEncr;
  else if ( (cmd == aSign && new_cmd == aClearsign)
            || (cmd == aClearsign && new_cmd == aSign) )
    cmd = aClearsign;
  else 
    {
      log_error(_("conflicting commands\n"));
      gpgsm_exit(2);
    }

  *ret_cmd = cmd;
}


/* Helper to add recipients to a list. */
static void
do_add_recipient (ctrl_t ctrl, const char *name,
                  certlist_t *recplist, int is_encrypt_to)
{
  int rc = gpgsm_add_to_certlist (ctrl, name, 0, recplist, is_encrypt_to);
  if (rc)
    {
      log_error (_("can't encrypt to `%s': %s\n"), name, gpg_strerror (rc));
      gpgsm_status2 (ctrl, STATUS_INV_RECP,
                     gpg_err_code (rc) == -1?                         "1":
                     gpg_err_code (rc) == GPG_ERR_NO_PUBKEY?          "1":
                     gpg_err_code (rc) == GPG_ERR_AMBIGUOUS_NAME?     "2":
                     gpg_err_code (rc) == GPG_ERR_WRONG_KEY_USAGE?    "3":
                     gpg_err_code (rc) == GPG_ERR_CERT_REVOKED?       "4":
                     gpg_err_code (rc) == GPG_ERR_CERT_EXPIRED?       "5":
                     gpg_err_code (rc) == GPG_ERR_NO_CRL_KNOWN?       "6":
                     gpg_err_code (rc) == GPG_ERR_CRL_TOO_OLD?        "7":
                     gpg_err_code (rc) == GPG_ERR_NO_POLICY_MATCH?    "8":
                     "0",
                     name, NULL);
    }
}


int
main ( int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  const char *fname;
  /*  char *username;*/
  int may_coredump;
  STRLIST sl, remusr= NULL, locusr=NULL;
  STRLIST nrings=NULL;
  int detached_sig = 0;
  FILE *configfp = NULL;
  char *configname = NULL;
  unsigned configlineno;
  int parse_debug = 0;
  int no_more_options = 0;
  int default_config =1;
  int default_keyring = 1;
  char *logfile = NULL;
  int greeting = 0;
  int nogreeting = 0;
  int debug_wait = 0;
  const char *debug_level = NULL;
  int use_random_seed = 1;
  int with_fpr = 0;
  char *def_digest_string = NULL;
  enum cmd_and_opt_values cmd = 0;
  struct server_control_s ctrl;
  CERTLIST recplist = NULL;
  CERTLIST signerlist = NULL;
  int do_not_setup_keys = 0;

  /* trap_unaligned ();*/
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* We don't need any locking in libgcrypt unless we use any kind of
     threading. */
  gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING);

  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to secmem_init()
     somewhere after the option parsing */
  log_set_prefix ("gpgsm", 1);

  /* Try to auto set the character set.  */
  set_native_charset (NULL); 

  /* Check that the libraries are suitable.  Do it here because the
     option parse may need services of the library */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }
  if (!ksba_check_version (NEED_KSBA_VERSION) )
    {
      log_fatal( _("libksba is too old (need %s, have %s)\n"),
                 NEED_KSBA_VERSION, ksba_check_version (NULL) );
    }

  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();
  
  gnupg_init_signals (0, emergency_cleanup);
  
  create_dotlock (NULL); /* register locking cleanup */
  i18n_init();

  opt.def_cipher_algoid = "1.2.840.113549.3.7";  /*des-EDE3-CBC*/
#ifdef __MINGW32__
  opt.homedir = read_w32_registry_string ( NULL,
                                           "Software\\GNU\\GnuPG", "HomeDir" );
#else
  opt.homedir = getenv ("GNUPGHOME");
#endif
  if (!opt.homedir || !*opt.homedir ) 
    opt.homedir = GNUPG_DEFAULT_HOMEDIR;

  /* first check whether we have a config file on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
        parse_debug++;
      else if (pargs.r_opt == oOptions)
        { /* yes there is one, so we do not try the default one but
             read the config file when it is encountered at the
             commandline */
          default_config = 0;
	}
      else if (pargs.r_opt == oNoOptions)
        default_config = 0; /* --no-options */
      else if (pargs.r_opt == oHomedir)
        opt.homedir = pargs.r.ret_str;
      else if (pargs.r_opt == aCallProtectTool)
        break; /* This break makes sure that --version and --help are
                  passed to the protect-tool. */
    }
  
  
  /* initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /* 
     Now we are now working under our real uid 
  */

  ksba_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free );

  assuan_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
  assuan_set_assuan_log_stream (log_get_stream ());
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));

  keybox_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);

  /* Setup a default control structure for command line mode */
  memset (&ctrl, 0, sizeof ctrl);
  gpgsm_init_default_ctrl (&ctrl);
  ctrl.no_server = 1;
  ctrl.status_fd = -1; /* not status output */
  ctrl.autodetect_encoding = 1;

  /* set the default option file */
  if (default_config )
    configname = make_filename (opt.homedir, "gpgsm.conf", NULL);
  /* cet the default policy file */
  opt.policy_file = make_filename (opt.homedir, "policies.txt", NULL);
  
  argc        = orig_argc;
  argv        = orig_argv;
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags =  1;  /* do not remove the args */

 next_pass:
  if (configname) {
    configlineno = 0;
    configfp = fopen (configname, "r");
    if (!configfp)
      {
        if (default_config)
          {
            if (parse_debug)
              log_info (_("NOTE: no default option file `%s'\n"), configname);
          }
        else 
          {
            log_error (_("option file `%s': %s\n"), configname, strerror(errno));
            gpgsm_exit(2);
          }
        xfree(configname);
        configname = NULL;
      }
    if (parse_debug && configname)
      log_info (_("reading options from `%s'\n"), configname);
    default_config = 0;
  }

  while (!no_more_options 
         && optfile_parse (configfp, configname, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
	case aGPGConfList: 
          set_cmd (&cmd, pargs.r_opt);
          do_not_setup_keys = 1;
          nogreeting = 1;
          break;

        case aServer: 
          opt.batch = 1;
          set_cmd (&cmd, aServer);
          break;

        case aCallDirmngr:
          opt.batch = 1;
          set_cmd (&cmd, aCallDirmngr);
          do_not_setup_keys = 1;
          break;

        case aCallProtectTool:
          opt.batch = 1;
          set_cmd (&cmd, aCallProtectTool);
          no_more_options = 1; /* Stop parsing. */
          do_not_setup_keys = 1;
          break;
        
        case aDeleteKey:
          set_cmd (&cmd, aDeleteKey);
          /*greeting=1;*/
          do_not_setup_keys = 1;
          break;

        case aDetachedSign:
          detached_sig = 1;
          set_cmd (&cmd, aSign ); 
          break;

        case aKeygen:
          set_cmd (&cmd, aKeygen);
          greeting=1; 
          do_not_setup_keys = 1;
          break;

        case aCheckKeys:
        case aImport: 
        case aSendKeys: 
        case aRecvKeys: 
        case aExport: 
        case aExportSecretKeyP12: 
        case aDumpKeys:
        case aDumpExternalKeys: 
        case aDumpSecretKeys: 
        case aListKeys:
        case aListExternalKeys: 
        case aListSecretKeys: 
        case aListSigs: 
        case aLearnCard: 
        case aPasswd: 
        case aKeydbClearSomeCertFlags:
          do_not_setup_keys = 1;
          set_cmd (&cmd, pargs.r_opt);
          break;

        case aSym:
        case aDecrypt: 
        case aEncr: 
        case aSign: 
        case aClearsign: 
        case aVerify: 
          set_cmd (&cmd, pargs.r_opt);
          break;

          /* output encoding selection */
        case oArmor:
          ctrl.create_pem = 1;
          break;
        case oBase64: 
          ctrl.create_pem = 0;
          ctrl.create_base64 = 1;
          break;
        case oNoArmor: 
          ctrl.create_pem = 0;
          ctrl.create_base64 = 0;
          break;
          
          /* Input encoding selection */
        case oAssumeArmor:
          ctrl.autodetect_encoding = 0;
          ctrl.is_pem = 1;
          ctrl.is_base64 = 0;
          break;
        case oAssumeBase64:
          ctrl.autodetect_encoding = 0;
          ctrl.is_pem = 0;
          ctrl.is_base64 = 1;
          break;
        case oAssumeBinary:
          ctrl.autodetect_encoding = 0;
          ctrl.is_pem = 0;
          ctrl.is_base64 = 0;
          break;

        case oDisableCRLChecks:
          opt.no_crl_check = 1;
          break;
        case oEnableCRLChecks:
          opt.no_crl_check = 0;
          break;
        case oForceCRLRefresh:
          opt.force_crl_refresh = 1;
          break;

        case oDisableOCSP:
          ctrl.use_ocsp = opt.enable_ocsp = 0;
          break;
        case oEnableOCSP:
          ctrl.use_ocsp = opt.enable_ocsp = 1;
          break;

        case oIncludeCerts: ctrl.include_certs = pargs.r.ret_int; break;

        case oPolicyFile:
          xfree (opt.policy_file);
          if (*pargs.r.ret_str)
            opt.policy_file = xstrdup (pargs.r.ret_str);
          else
            opt.policy_file = NULL;
          break;

        case oDisablePolicyChecks:
          opt.no_policy_check = 1;
          break;
        case oEnablePolicyChecks:
          opt.no_policy_check = 0;
          break;
          
        case oAutoIssuerKeyRetrieve:
          opt.auto_issuer_key_retrieve = 1;
          break;

        case oOutput: opt.outfile = pargs.r.ret_str; break;

        
        case oQuiet: opt.quiet = 1; break;
        case oNoTTY: /* fixme:tty_no_terminal(1);*/ break;
        case oDryRun: opt.dry_run = 1; break;

        case oVerbose:
          opt.verbose++;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;
        case oNoVerbose:
          opt.verbose = 0;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;

        case oLogFile: logfile = pargs.r.ret_str; break;
          
        case oBatch: 
          opt.batch = 1;
          greeting = 0;
          break;
        case oNoBatch: opt.batch = 0; break;
          
        case oAnswerYes: opt.answer_yes = 1; break;
        case oAnswerNo: opt.answer_no = 1; break;

        case oKeyring: append_to_strlist (&nrings, pargs.r.ret_str); break;

        case oDebug: opt.debug |= pargs.r.ret_ulong; break;
        case oDebugAll: opt.debug = ~0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: debug_wait = pargs.r.ret_int; break;
        case oDebugAllowCoreDump:
          may_coredump = enable_core_dumps ();
          break;
        case oDebugNoChainValidation: opt.no_chain_validation = 1; break;
        case oDebugIgnoreExpiration: opt.ignore_expiration = 1; break;

        case oStatusFD: ctrl.status_fd = pargs.r.ret_int; break;
        case oLoggerFD: log_set_fd (pargs.r.ret_int ); break;
        case oWithMD5Fingerprint:
          opt.with_md5_fingerprint=1; /*fall thru*/
        case oWithFingerprint:
          with_fpr=1; /*fall thru*/
        case oFingerprint:
          opt.fingerprint++;
          break;

        case oOptions:
          /* config files may not be nested (silently ignore them) */
          if (!configfp)
            {
              xfree(configname);
              configname = xstrdup (pargs.r.ret_str);
              goto next_pass;
	    }
          break;
        case oNoOptions: break; /* no-options */
        case oHomedir: opt.homedir = pargs.r.ret_str; break;
        case oAgentProgram: opt.agent_program = pargs.r.ret_str;  break;
        case oDisplay: opt.display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: opt.ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: opt.ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: opt.lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: opt.lc_messages = xstrdup (pargs.r.ret_str); break;
        case oDirmngrProgram: opt.dirmngr_program = pargs.r.ret_str;  break;
        case oProtectToolProgram:
          opt.protect_tool_program = pargs.r.ret_str; 
          break;
          
        case oFakedSystemTime:
          gnupg_set_time ( (time_t)pargs.r.ret_ulong, 0);
          break;

        case oNoDefKeyring: default_keyring = 0; break;
        case oNoGreeting: nogreeting = 1; break;

        case oDefaultKey:
          /* fixme:opt.def_secret_key = pargs.r.ret_str;*/
          break;
        case oDefRecipient:
          if (*pargs.r.ret_str)
            opt.def_recipient = xstrdup (pargs.r.ret_str);
          break;
        case oDefRecipientSelf:
          xfree (opt.def_recipient);
          opt.def_recipient = NULL;
          opt.def_recipient_self = 1;
          break;
        case oNoDefRecipient:
          xfree (opt.def_recipient);
          opt.def_recipient = NULL;
          opt.def_recipient_self = 0;
          break;

        case oWithKeyData: opt.with_key_data=1; /* fall thru */
        case oWithColons: ctrl.with_colons = 1; break;
        case oWithValidation: ctrl.with_validation=1; break;

        case oSkipVerify: opt.skip_verify=1; break;

        case oNoEncryptTo: opt.no_encrypt_to = 1; break;
        case oEncryptTo: /* Store the recipient in the second list */
          sl = add_to_strlist (&remusr, pargs.r.ret_str);
          sl->flags = 1;
          break;

        case oRecipient: /* store the recipient */
          add_to_strlist ( &remusr, pargs.r.ret_str);
          break;

        case oTextmodeShort: /*fixme:opt.textmode = 2;*/ break;
        case oTextmode: /*fixme:opt.textmode=1;*/  break;

        case oUser: /* store the local users, the first one is the default */
          if (!opt.local_user)
            opt.local_user = pargs.r.ret_str;
          add_to_strlist (&locusr, pargs.r.ret_str);
          break;

        case oNoSecmemWarn:
          gcry_control (GCRYCTL_DISABLE_SECMEM_WARN); 
          break;

        case oCipherAlgo:
          opt.def_cipher_algoid = pargs.r.ret_str;
          break;

        case oDisableCipherAlgo: 
          {
            int algo = gcry_cipher_map_name (pargs.r.ret_str);
            gcry_cipher_ctl (NULL, GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
          }
          break;
        case oDisablePubkeyAlgo: 
          {
            int algo = gcry_pk_map_name (pargs.r.ret_str);
            gcry_pk_ctl (GCRYCTL_DISABLE_ALGO,&algo, sizeof algo );
          }
          break;

        case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
        case oNoRandomSeedFile: use_random_seed = 0; break;

        case oEnableSpecialFilenames: allow_special_filenames =1; break;
          

        case aDummy:
          break;
        default: 
          pargs.err = configfp? 1:2; 
          break;
	}
    }

  if (configfp)
    {
      fclose (configfp);
      configfp = NULL;
      /* Keep a copy of the config filename. */
      opt.config_filename = configname;
      configname = NULL;
      goto next_pass;
    }
  xfree (configname);
  configname = NULL;

  if (!opt.config_filename)
    opt.config_filename = make_filename (opt.homedir, "gpgsm.conf", NULL);

  if (log_get_errorcount(0))
    gpgsm_exit(2);
  
  if (nogreeting)
    greeting = 0;
  
  if (greeting)
    {
      fprintf(stderr, "%s %s; %s\n",
              strusage(11), strusage(13), strusage(14) );
      fprintf(stderr, "%s\n", strusage(15) );
    }
#  ifdef IS_DEVELOPMENT_VERSION
  if (!opt.batch)
    {
      log_info ("NOTE: THIS IS A DEVELOPMENT VERSION!\n");
      log_info ("It is only intended for test purposes and should NOT be\n");
      log_info ("used in a production environment or with production keys!\n");
    }
#  endif

  if (may_coredump && !opt.quiet)
    log_info (_("WARNING: program may create a core file!\n"));

  if (logfile && cmd == aServer)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, 1|2|4);
    }

  if (gnupg_faked_time_p ())
    {
      gnupg_isotime_t tbuf;

      log_info (_("WARNING: running with faked system time: "));
      gnupg_get_isotime (tbuf);
      gpgsm_dump_time (tbuf);
      log_printf ("\n");
    }
  
/*FIXME    if (opt.batch) */
/*      tty_batchmode (1); */

  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  set_debug (debug_level);

  /* Although we alwasy use gpgsm_exit, we better install a regualr
     exit handler so that at least the secure memory gets wiped
     out. */
  if (atexit (emergency_cleanup))
    {
      log_error ("atexit failed\n");
      gpgsm_exit (2);
    }

  /* Must do this after dropping setuid, because the mapping functions
     may try to load an module and we may have disabled an algorithm. */
  if ( !gcry_cipher_map_name (opt.def_cipher_algoid)
       || !gcry_cipher_mode_from_oid (opt.def_cipher_algoid))
    log_error (_("selected cipher algorithm is invalid\n"));

  if (def_digest_string)
    {
      opt.def_digest_algo = gcry_md_map_name (def_digest_string);
      xfree (def_digest_string);
      def_digest_string = NULL;
      if (our_md_test_algo(opt.def_digest_algo) )
        log_error (_("selected digest algorithm is invalid\n"));
    }

  if (log_get_errorcount(0))
    gpgsm_exit(2);
  
  /* Set the random seed file. */
  if (use_random_seed) {
    char *p = make_filename (opt.homedir, "random_seed", NULL);
    gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
    xfree(p);
  }


  if (!cmd && opt.fingerprint && !with_fpr)
    set_cmd (&cmd, aListKeys);
  
  if (!nrings && default_keyring)  /* add default keybox */
    keydb_add_resource ("pubring.kbx", 0, 0);
  for (sl = nrings; sl; sl = sl->next)
    keydb_add_resource (sl->d, 0, 0);
  FREE_STRLIST(nrings);

  if (!do_not_setup_keys)
    {
      for (sl = locusr; sl ; sl = sl->next)
        {
          int rc = gpgsm_add_to_certlist (&ctrl, sl->d, 1, &signerlist, 0);
          if (rc)
            {
              log_error (_("can't sign using `%s': %s\n"),
                         sl->d, gpg_strerror (rc));
              gpgsm_status2 (&ctrl, STATUS_INV_RECP,
                         gpg_err_code (rc) == -1?                      "1":
                         gpg_err_code (rc) == GPG_ERR_NO_PUBKEY?       "1":
                         gpg_err_code (rc) == GPG_ERR_AMBIGUOUS_NAME?  "2":
                         gpg_err_code (rc) == GPG_ERR_WRONG_KEY_USAGE? "3":
                         gpg_err_code (rc) == GPG_ERR_CERT_REVOKED?    "4":
                         gpg_err_code (rc) == GPG_ERR_CERT_EXPIRED?    "5":
                         gpg_err_code (rc) == GPG_ERR_NO_CRL_KNOWN?    "6":
                         gpg_err_code (rc) == GPG_ERR_CRL_TOO_OLD?     "7":
                         gpg_err_code (rc) == GPG_ERR_NO_POLICY_MATCH? "8":
                         gpg_err_code (rc) == GPG_ERR_NO_SECKEY?       "9":
                         "0",
                         sl->d, NULL);
            }
        }
      
      /* Build the recipient list.  We first add the regular ones and then
         the encrypt-to ones because the underlying function will silenty
         ignore duplicates and we can't allow to keep a duplicate which is
         flagged as encrypt-to as the actually encrypt function would then
         complain about no (regular) recipients. */
      for (sl = remusr; sl; sl = sl->next)
        if (!(sl->flags & 1))
          do_add_recipient (&ctrl, sl->d, &recplist, 0);
      if (!opt.no_encrypt_to)
        {
          for (sl = remusr; sl; sl = sl->next)
            if ((sl->flags & 1))
              do_add_recipient (&ctrl, sl->d, &recplist, 1);
        }
    }

  if (log_get_errorcount(0))
    gpgsm_exit(1); /* must stop for invalid recipients */
  
  fname = argc? *argv : NULL;
  
  switch (cmd)
    {
    case aGPGConfList: 
      { /* List options and default values in the GPG Conf format.  */

        /* The following list is taken from gnupg/tools/gpgconf-comp.c.  */
        /* Option flags.  YOU MUST NOT CHANGE THE NUMBERS OF THE EXISTING
           FLAGS, AS THEY ARE PART OF THE EXTERNAL INTERFACE.  */
#define GC_OPT_FLAG_NONE	0UL
        /* The RUNTIME flag for an option indicates that the option can be
           changed at runtime.  */
#define GC_OPT_FLAG_RUNTIME	(1UL << 3)
        /* The DEFAULT flag for an option indicates that the option has a
           default value.  */
#define GC_OPT_FLAG_DEFAULT	(1UL << 4)
        /* The DEF_DESC flag for an option indicates that the option has a
           default, which is described by the value of the default field.  */
#define GC_OPT_FLAG_DEF_DESC	(1UL << 5)
        /* The NO_ARG_DESC flag for an option indicates that the argument has
           a default, which is described by the value of the ARGDEF field.  */
#define GC_OPT_FLAG_NO_ARG_DESC	(1UL << 6)

        printf ("gpgconf-gpgsm.conf:%lu:\"%s\n",
                GC_OPT_FLAG_DEFAULT, opt.config_filename);
        
        printf ("verbose:%lu:\n"
                "quiet:%lu:\n"
                "debug-level:%lu:\"none:\n"
                "log-file:%lu:\n",
                GC_OPT_FLAG_NONE,
                GC_OPT_FLAG_NONE,
                GC_OPT_FLAG_DEFAULT,
                GC_OPT_FLAG_NONE );
        printf ("disable-crl-checks:%lu:\n",
                GC_OPT_FLAG_NONE );
        printf ("enable-ocsp:%lu:\n",
                GC_OPT_FLAG_NONE );
        printf ("include-certs:%lu:1:\n",
                GC_OPT_FLAG_DEFAULT );
        printf ("disable-policy-checks:%lu:\n",
                GC_OPT_FLAG_NONE );
        printf ("auto-issuer-key-retrieve:%lu:\n",
                GC_OPT_FLAG_NONE );

      }
      break;

    case aServer:
      if (debug_wait)
        {
          log_debug ("waiting for debugger - my pid is %u .....\n",
                     (unsigned int)getpid());
          sleep (debug_wait);
          log_debug ("... okay\n");
         }
      gpgsm_server (recplist);
      break;

    case aCallDirmngr:
      if (!argc)
        wrong_args ("--call-dirmngr <command> {args}");
      else
        if (gpgsm_dirmngr_run_command (&ctrl, *argv, argc-1, argv+1))
          gpgsm_exit (1);
      break;

    case aCallProtectTool:
      run_protect_tool (argc, argv);
      break;

    case aEncr: /* encrypt the given file */
      if (!argc)
        gpgsm_encrypt (&ctrl, recplist, 0, stdout); /* from stdin */
      else if (argc == 1)
        gpgsm_encrypt (&ctrl, recplist, open_read (*argv), stdout); /* from file */
      else
        wrong_args ("--encrypt [datafile]");
      break;

    case aSign: /* sign the given file */
      /* FIXME: We don't handle --output yet. We should also allow
         to concatenate multiple files for signing because that is
         what gpg does.*/
      if (!argc)
        gpgsm_sign (&ctrl, signerlist,
                    0, detached_sig, stdout); /* create from stdin */
      else if (argc == 1)
        gpgsm_sign (&ctrl, signerlist,
                    open_read (*argv), detached_sig, stdout); /* from file */
      else
        wrong_args ("--sign [datafile]");
      break;
        
    case aSignEncr: /* sign and encrypt the given file */
      log_error ("this command has not yet been implemented\n");
      break;

    case aClearsign: /* make a clearsig */
      log_error ("this command has not yet been implemented\n");
      break;

    case aVerify:
      {
        FILE *fp = NULL;

        if (argc == 2 && opt.outfile)
          log_info ("option --output ignored for a detached signature\n");
        else if (opt.outfile)
          fp = open_fwrite (opt.outfile);

        if (!argc)
          gpgsm_verify (&ctrl, 0, -1, fp); /* normal signature from stdin */
        else if (argc == 1)
          gpgsm_verify (&ctrl, open_read (*argv), -1, fp); /* std signature */
        else if (argc == 2) /* detached signature (sig, detached) */
          gpgsm_verify (&ctrl, open_read (*argv), open_read (argv[1]), NULL); 
        else
          wrong_args ("--verify [signature [detached_data]]");

        if (fp && fp != stdout)
          fclose (fp);
      }
      break;

    case aVerifyFiles:
      log_error (_("this command has not yet been implemented\n"));
      break;

    case aDecrypt:
      if (!argc)
        gpgsm_decrypt (&ctrl, 0, stdout); /* from stdin */
      else if (argc == 1)
        gpgsm_decrypt (&ctrl, open_read (*argv), stdout); /* from file */
      else
        wrong_args ("--decrypt [filename]");
      break;

    case aDeleteKey:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_delete (&ctrl, sl);
      free_strlist(sl);
      break;

    case aListSigs:
      ctrl.with_chain = 1;
    case aListKeys:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_list_keys (&ctrl, sl, stdout, (0 | (1<<6)));
      free_strlist(sl);
      break;

    case aDumpKeys:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_list_keys (&ctrl, sl, stdout, (256 | (1<<6)));
      free_strlist(sl);
      break;

    case aListExternalKeys:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_list_keys (&ctrl, sl, stdout,
                       (0 | (1<<7)));
      free_strlist(sl);
      break;

    case aDumpExternalKeys:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_list_keys (&ctrl, sl, stdout,
                       (256 | (1<<7)));
      free_strlist(sl);
      break;

    case aListSecretKeys:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_list_keys (&ctrl, sl, stdout, (2 | (1<<6)));
      free_strlist(sl);
      break;

    case aDumpSecretKeys:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_list_keys (&ctrl, sl, stdout, (256 | 2 | (1<<6)));
      free_strlist(sl);
      break;

    case aKeygen: /* generate a key */
      log_error ("this function is not yet available from the commandline\n");
      break;

    case aImport:
      gpgsm_import_files (&ctrl, argc, argv, open_read);
      break;

    case aExport:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_export (&ctrl, sl, stdout);
      free_strlist(sl);
      break;

    case aExportSecretKeyP12:
      if (argc == 1)
        gpgsm_p12_export (&ctrl, *argv, stdout);
      else
        wrong_args ("--export-secret-key-p12 KEY-ID");
      break;
      
    case aSendKeys:
    case aRecvKeys:
      log_error ("this command has not yet been implemented\n");
      break;


    case aLearnCard:
      if (argc)
        wrong_args ("--learn-card");
      else
        {
          int rc = gpgsm_agent_learn (&ctrl);
          if (rc)
            log_error ("error learning card: %s\n", gpg_strerror (rc));
        }
      break;

    case aPasswd:
      if (argc != 1)
        wrong_args ("--passwd <key-Id>");
      else
        {
          int rc;
          ksba_cert_t cert = NULL;
          char *grip = NULL;

          rc = gpgsm_find_cert (*argv, &cert);
          if (rc)
            ;
          else if (!(grip = gpgsm_get_keygrip_hexstring (cert)))
            rc = gpg_error (GPG_ERR_BUG);
          else 
            {
              char *desc = gpgsm_format_keydesc (cert);
              rc = gpgsm_agent_passwd (&ctrl, grip, desc);
              xfree (desc);
            }
          if (rc)
            log_error ("error changing passphrase: %s\n", gpg_strerror (rc));
          xfree (grip);
          ksba_cert_release (cert);
        }
      break;

    case aKeydbClearSomeCertFlags:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      keydb_clear_some_cert_flags (&ctrl, sl);
      free_strlist(sl);
      break;


    default:
        log_error ("invalid command (there is no implicit command)\n");
	break;
    }
  
  /* cleanup */
  gpgsm_release_certlist (recplist);
  gpgsm_release_certlist (signerlist);
  FREE_STRLIST(remusr);
  FREE_STRLIST(locusr);
  gpgsm_exit(0);
  return 8; /*NEVER REACHED*/
}

/* Note: This function is used by signal handlers!. */
static void
emergency_cleanup (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM );
}


void
gpgsm_exit (int rc)
{
  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE);
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
  emergency_cleanup ();
  rc = rc? rc : log_get_errorcount(0)? 2 : gpgsm_errors_seen? 1 : 0;
  exit (rc);
}


void
gpgsm_init_default_ctrl (struct server_control_s *ctrl)
{
  ctrl->include_certs = 1;  /* only include the signer's cert */
  ctrl->use_ocsp = opt.enable_ocsp;
}



/* Check whether the filename has the form "-&nnnn", where n is a
   non-zero number.  Returns this number or -1 if it is not the case.  */
static int
check_special_filename (const char *fname)
{
  if (allow_special_filenames
      && fname && *fname == '-' && fname[1] == '&' ) {
    int i;
    
    fname += 2;
    for (i=0; isdigit (fname[i]); i++ )
      ;
    if ( !fname[i] ) 
      return atoi (fname);
  }
  return -1;
}



/* Open the FILENAME for read and return the filedescriptor.  Stop
   with an error message in case of problems.  "-" denotes stdin and
   if special filenames are allowed the given fd is opened instead. */
static int 
open_read (const char *filename)
{
  int fd;

  if (filename[0] == '-' && !filename[1])
    return 0; /* stdin */
  fd = check_special_filename (filename);
  if (fd != -1)
    return fd;
  fd = open (filename, O_RDONLY);
  if (fd == -1)
    {
      log_error (_("can't open `%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fd;
}

/* Open FILENAME for fwrite and return the stream.  Stop with an error
   message in case of problems.  "-" denotes stdout and if special
   filenames are allowed the given fd is opened instead. Caller must
   close the returned stream unless it is stdout. */
static FILE *
open_fwrite (const char *filename)
{
  int fd;
  FILE *fp;

  if (filename[0] == '-' && !filename[1])
    return stdout;

  fd = check_special_filename (filename);
  if (fd != -1)
    {
      fp = fdopen (dup (fd), "wb");
      if (!fp)
        {
          log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
          gpgsm_exit (2);
        }
      return fp;
    }
  fp = fopen (filename, "wb");
  if (!fp)
    {
      log_error (_("can't open `%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fp;
}


static void
run_protect_tool (int argc, char **argv)
{
  const char *pgm;
  char **av;
  int i;

  if (!opt.protect_tool_program || !*opt.protect_tool_program)
    pgm = GNUPG_DEFAULT_PROTECT_TOOL;
  else
    pgm = opt.protect_tool_program;

  av = xcalloc (argc+2, sizeof *av);
  av[0] = strrchr (pgm, '/');
  if (!av[0])
    av[0] = xstrdup (pgm);
  for (i=1; argc; i++, argc--, argv++)
    av[i] = *argv;
  av[i] = NULL;
  execv (pgm, av); 
  log_error ("error executing `%s': %s\n", pgm, strerror (errno));
  gpgsm_exit (2);
}
