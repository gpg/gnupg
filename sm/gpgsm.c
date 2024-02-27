/* gpgsm.c - GnuPG for S/MIME
 * Copyright (C) 2001-2020 Free Software Foundation, Inc.
 * Copyright (C) 2001-2019 Werner Koch
 * Copyright (C) 2015-2021 g10 Code GmbH
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
#include <fcntl.h>
/*#include <mcheck.h>*/
#include <npth.h>

#define INCLUDED_BY_MAIN_MODULE 1

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h> /* malloc hooks */

#include "passphrase.h"
#include "../common/shareddefs.h"
#include "../kbx/keybox.h" /* malloc hooks */
#include "../common/i18n.h"
#include "keydb.h"
#include "../common/sysutils.h"
#include "../common/gc-opt-flags.h"
#include "../common/asshelp.h"
#include "../common/init.h"
#include "../common/compliance.h"
#include "../common/comopt.h"
#include "minip12.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

enum cmd_and_opt_values {
  aNull = 0,
  oArmor        = 'a',
  aDetachedSign = 'b',
  aSym	        = 'c',
  aDecrypt	= 'd',
  aEncr	        = 'e',
  aListKeys	= 'k',
  aListSecretKeys = 'K',
  oDryRun	= 'n',
  oOutput	= 'o',
  oQuiet	= 'q',
  oRecipient	= 'r',
  aSign	        = 's',
  oUser	        = 'u',
  oVerbose	= 'v',
  oBatch	= 500,
  aClearsign,
  aKeygen,
  aSignEncr,
  aDeleteKey,
  aImport,
  aVerify,
  aListExternalKeys,
  aListChain,
  aSendKeys,
  aRecvKeys,
  aExport,
  aExportSecretKeyP12,
  aExportSecretKeyP8,
  aExportSecretKeyRaw,
  aServer,
  aLearnCard,
  aCallDirmngr,
  aCallProtectTool,
  aPasswd,
  aGPGConfList,
  aGPGConfTest,
  aDumpKeys,
  aDumpChain,
  aDumpSecretKeys,
  aDumpExternalKeys,
  aShowCerts,
  aKeydbClearSomeCertFlags,
  aFingerprint,

  oOptions,
  oDebug,
  oDebugLevel,
  oDebugAll,
  oDebugNone,
  oDebugWait,
  oDebugAllowCoreDump,
  oDebugNoChainValidation,
  oDebugIgnoreExpiration,
  oDebugForceECDHSHA1KDF,
  oLogFile,
  oNoLogFile,
  oAuditLog,
  oHtmlAuditLog,
  oLogTime,

  oEnableSpecialFilenames,

  oAgentProgram,
  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,
  oXauthority,

  oPreferSystemDirmngr,
  oDirmngrProgram,
  oDisableDirmngr,
  oProtectToolProgram,
  oFakedSystemTime,

  oPassphraseFD,
  oPinentryMode,
  oRequestOrigin,

  oAssumeArmor,
  oAssumeBase64,
  oAssumeBinary,
  oInputSizeHint,

  oBase64,
  oNoArmor,
  oP12Charset,

  oCompliance,

  oDisableCRLChecks,
  oEnableCRLChecks,
  oDisableTrustedCertCRLCheck,
  oEnableTrustedCertCRLCheck,
  oForceCRLRefresh,
  oEnableIssuerBasedCRLCheck,

  oDisableOCSP,
  oEnableOCSP,

  oIncludeCerts,
  oPolicyFile,
  oDisablePolicyChecks,
  oEnablePolicyChecks,
  oAutoIssuerKeyRetrieve,
  oMinRSALength,

  oWithFingerprint,
  oWithMD5Fingerprint,
  oWithKeygrip,
  oWithSecret,
  oWithKeyScreening,
  oAnswerYes,
  oAnswerNo,
  oNoPrettyDN,
  oKeyring,
  oDefaultKey,
  oDefRecipient,
  oDefRecipientSelf,
  oNoDefRecipient,
  oStatusFD,
  oCipherAlgo,
  oDigestAlgo,
  oExtraDigestAlgo,
  oNoVerbose,
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
  oWithEphemeralKeys,
  oSkipVerify,
  oValidationModel,
  oKeyServer,
  oKeyServer_deprecated,
  oEncryptTo,
  oNoEncryptTo,
  oLoggerFD,
  oDisableCipherAlgo,
  oDisablePubkeyAlgo,
  oIgnoreTimeConflict,
  oNoRandomSeedFile,
  oNoCommonCertsImport,
  oIgnoreCertExtension,
  oIgnoreCertWithOID,
  oAuthenticode,
  oAttribute,
  oChUid,
  oUseKeyboxd,
  oKeyboxdProgram,
  oRequireCompliance,
  oCompatibilityFlags,
  oKbxBufferSize,
  oAlwaysTrust,
  oNoAutostart
 };


static gpgrt_opt_t opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aSign, "sign", N_("make a signature")),
/*ARGPARSE_c (aClearsign, "clearsign", N_("make a clear text signature") ),*/
  ARGPARSE_c (aDetachedSign, "detach-sign", N_("make a detached signature")),
  ARGPARSE_c (aEncr, "encrypt", N_("encrypt data")),
/*ARGPARSE_c (aSym, "symmetric", N_("encryption only with symmetric cipher")),*/
  ARGPARSE_c (aDecrypt, "decrypt", N_("decrypt data (default)")),
  ARGPARSE_c (aVerify, "verify",  N_("verify a signature")),
  ARGPARSE_c (aListKeys, "list-keys", N_("list keys")),
  ARGPARSE_c (aListExternalKeys, "list-external-keys",
              N_("list external keys")),
  ARGPARSE_c (aListSecretKeys, "list-secret-keys", N_("list secret keys")),
  ARGPARSE_c (aListChain,   "list-chain",  N_("list certificate chain")),
  ARGPARSE_c (aFingerprint, "fingerprint", N_("list keys and fingerprints")),
  ARGPARSE_c (aKeygen, "generate-key", N_("generate a new key pair")),
  ARGPARSE_c (aKeygen, "gen-key", "@"),
  ARGPARSE_c (aDeleteKey, "delete-keys",
              N_("remove keys from the public keyring")),
/*ARGPARSE_c (aSendKeys, "send-keys", N_("export keys to a keyserver")),*/
/*ARGPARSE_c (aRecvKeys, "recv-keys", N_("import keys from a keyserver")),*/
  ARGPARSE_c (aImport, "import", N_("import certificates")),
  ARGPARSE_c (aExport, "export", N_("export certificates")),

  /* We use -raw and not -p1 for pkcs#1 secret key export so that it
     won't accidentally be used in case -p12 was intended.  */
  ARGPARSE_c (aExportSecretKeyP12, "export-secret-key-p12", "@"),
  ARGPARSE_c (aExportSecretKeyP8,  "export-secret-key-p8", "@"),
  ARGPARSE_c (aExportSecretKeyRaw, "export-secret-key-raw", "@"),

  ARGPARSE_c (aLearnCard, "learn-card", N_("register a smartcard")),
  ARGPARSE_c (aServer, "server", N_("run in server mode")),
  ARGPARSE_c (aCallDirmngr, "call-dirmngr",
              N_("pass a command to the dirmngr")),
  ARGPARSE_c (aCallProtectTool, "call-protect-tool",
              N_("invoke gpg-protect-tool")),
  ARGPARSE_c (aPasswd, "change-passphrase", N_("change a passphrase")),
  ARGPARSE_c (aPasswd, "passwd", "@"),
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_c (aShowCerts, "show-certs", "@"),
  ARGPARSE_c (aDumpKeys, "dump-cert", "@"),
  ARGPARSE_c (aDumpKeys, "dump-keys", "@"),
  ARGPARSE_c (aDumpChain, "dump-chain", "@"),
  ARGPARSE_c (aDumpExternalKeys, "dump-external-keys", "@"),
  ARGPARSE_c (aDumpSecretKeys, "dump-secret-keys", "@"),
  ARGPARSE_c (aKeydbClearSomeCertFlags, "keydb-clear-some-cert-flags", "@"),


  ARGPARSE_header ("Monitor", N_("Options controlling the diagnostic output")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),
  ARGPARSE_s_n (oNoTTY, "no-tty", N_("don't use the terminal at all")),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level",
                N_("|LEVEL|set the debugging level to LEVEL")),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugNone, "debug-none", "@"),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_n (oDebugAllowCoreDump, "debug-allow-core-dump", "@"),
  ARGPARSE_s_n (oDebugNoChainValidation, "debug-no-chain-validation", "@"),
  ARGPARSE_s_n (oDebugIgnoreExpiration,  "debug-ignore-expiration", "@"),
  ARGPARSE_s_n (oDebugForceECDHSHA1KDF,  "debug-force-ecdh-sha1kdf", "@"),
  ARGPARSE_s_s (oLogFile, "log-file",
                N_("|FILE|write server mode logs to FILE")),
  ARGPARSE_s_n (oNoLogFile, "no-log-file", "@"),
  ARGPARSE_s_i (oLoggerFD, "logger-fd", "@"),
  ARGPARSE_s_n (oLogTime, "log-time", "@"),
  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),


  ARGPARSE_header ("Configuration",
                   N_("Options controlling the configuration")),

  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_n (oPreferSystemDirmngr,"prefer-system-dirmngr", "@"),
  ARGPARSE_s_s (oValidationModel, "validation-model", "@"),
  ARGPARSE_s_i (oIncludeCerts, "include-certs",
                N_("|N|number of certificates to include") ),
  ARGPARSE_s_s (oPolicyFile, "policy-file",
                N_("|FILE|take policy information from FILE")),
  ARGPARSE_s_s (oCompliance, "compliance",   "@"),
  ARGPARSE_p_u (oMinRSALength, "min-rsa-length", "@"),
  ARGPARSE_s_n (oNoCommonCertsImport, "no-common-certs-import", "@"),
  ARGPARSE_s_s (oIgnoreCertExtension, "ignore-cert-extension", "@"),
  ARGPARSE_s_s (oIgnoreCertWithOID, "ignore-cert-with-oid", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oKeyboxdProgram, "keyboxd-program", "@"),
  ARGPARSE_s_s (oDirmngrProgram, "dirmngr-program", "@"),
  ARGPARSE_s_s (oProtectToolProgram, "protect-tool-program", "@"),


  ARGPARSE_header ("Input", N_("Options controlling the input")),

  ARGPARSE_s_n (oAssumeArmor, "assume-armor",
                N_("assume input is in PEM format")),
  ARGPARSE_s_n (oAssumeBase64, "assume-base64",
                N_("assume input is in base-64 format")),
  ARGPARSE_s_n (oAssumeBinary, "assume-binary",
                N_("assume input is in binary format")),
  ARGPARSE_s_s (oInputSizeHint, "input-size-hint", "@"),


  ARGPARSE_header ("Output", N_("Options controlling the output")),

  ARGPARSE_s_n (oArmor, "armor", N_("create ascii armored output")),
  ARGPARSE_s_n (oArmor, "armour", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armor", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armour", "@"),
  ARGPARSE_s_n (oBase64, "base64", N_("create base-64 encoded output")),
  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_n (oAuthenticode, "authenticode", "@"),
  ARGPARSE_s_s (oAttribute,    "attribute", "@"),


  ARGPARSE_header (NULL, N_("Options to specify keys")),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),
  ARGPARSE_s_s (oDefaultKey, "default-key",
                N_("|USER-ID|use USER-ID as default secret key")),
  ARGPARSE_s_s (oEncryptTo, "encrypt-to",
                N_("|NAME|encrypt to user ID NAME as well")),
  ARGPARSE_s_n (oNoEncryptTo, "no-encrypt-to", "@"),
  /* Not yet used: */
  /*   ARGPARSE_s_s (oDefRecipient, "default-recipient", */
  /*                  N_("|NAME|use NAME as default recipient")), */
  /*   ARGPARSE_s_n (oDefRecipientSelf, "default-recipient-self", */
  /*                  N_("use the default key as default recipient")), */
  /*   ARGPARSE_s_n (oNoDefRecipient, "no-default-recipient", "@"), */
  ARGPARSE_s_s (oKeyring, "keyring",
                N_("|FILE|add keyring to the list of keyrings")),
  ARGPARSE_s_n (oNoDefKeyring, "no-default-keyring", "@"),
  ARGPARSE_s_s (oKeyServer_deprecated, "ldapserver", "@"),
  ARGPARSE_s_s (oKeyServer, "keyserver", "@"),
  ARGPARSE_s_n (oUseKeyboxd,    "use-keyboxd", "@"),


  ARGPARSE_header ("ImportExport",
                   N_("Options controlling key import and export")),

  ARGPARSE_s_n (oDisableDirmngr, "disable-dirmngr",
                N_("disable all access to the dirmngr")),
  ARGPARSE_s_n (oAutoIssuerKeyRetrieve, "auto-issuer-key-retrieve",
                N_("fetch missing issuer certificates")),
  ARGPARSE_s_s (oP12Charset, "p12-charset",
                N_("|NAME|use encoding NAME for PKCS#12 passphrases")),


  ARGPARSE_header ("Keylist", N_("Options controlling key listings")),

  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oWithKeyData,"with-key-data", "@"),
  ARGPARSE_s_n (oWithValidation, "with-validation", "@"),
  ARGPARSE_s_n (oWithMD5Fingerprint, "with-md5-fingerprint", "@"),
  ARGPARSE_s_n (oWithEphemeralKeys,  "with-ephemeral-keys", "@"),
  ARGPARSE_s_n (oSkipVerify, "skip-verify", "@"),
  ARGPARSE_s_n (oWithFingerprint, "with-fingerprint", "@"),
  ARGPARSE_s_n (oWithKeygrip,     "with-keygrip", "@"),
  ARGPARSE_s_n (oWithSecret,      "with-secret", "@"),
  ARGPARSE_s_n (oWithKeyScreening,"with-key-screening", "@"),
  ARGPARSE_s_n (oNoPrettyDN, "no-pretty-dn", "@"),


  ARGPARSE_header ("Security", N_("Options controlling the security")),

  ARGPARSE_s_n (oDisableCRLChecks, "disable-crl-checks",
                N_("never consult a CRL")),
  ARGPARSE_s_n (oEnableCRLChecks, "enable-crl-checks", "@"),
  ARGPARSE_s_n (oDisableTrustedCertCRLCheck,
                "disable-trusted-cert-crl-check",
                N_("do not check CRLs for root certificates")),
  ARGPARSE_s_n (oEnableTrustedCertCRLCheck,
                "enable-trusted-cert-crl-check", "@"),
  ARGPARSE_s_n (oDisableOCSP, "disable-ocsp", "@"),
  ARGPARSE_s_n (oEnableOCSP,  "enable-ocsp", N_("check validity using OCSP")),
  ARGPARSE_s_n (oDisablePolicyChecks, "disable-policy-checks",
                N_("do not check certificate policies")),
  ARGPARSE_s_n (oEnablePolicyChecks, "enable-policy-checks", "@"),
  ARGPARSE_s_s (oCipherAlgo, "cipher-algo",
                N_("|NAME|use cipher algorithm NAME")),
  ARGPARSE_s_s (oDigestAlgo, "digest-algo",
                N_("|NAME|use message digest algorithm NAME")),
  ARGPARSE_s_s (oExtraDigestAlgo, "extra-digest-algo", "@"),
  ARGPARSE_s_s (oDisableCipherAlgo,  "disable-cipher-algo", "@"),
  ARGPARSE_s_s (oDisablePubkeyAlgo,  "disable-pubkey-algo", "@"),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),
  ARGPARSE_s_n (oRequireCompliance, "require-compliance", "@"),
  ARGPARSE_s_n (oAlwaysTrust,       "always-trust", "@"),

  ARGPARSE_header (NULL, N_("Options for unattended use")),

  ARGPARSE_s_n (oBatch, "batch", N_("batch mode: never ask")),
  ARGPARSE_s_n (oNoBatch, "no-batch", "@"),
  ARGPARSE_s_n (oAnswerYes, "yes", N_("assume yes on most questions")),
  ARGPARSE_s_n (oAnswerNo,  "no",  N_("assume no on most questions")),
  ARGPARSE_s_i (oStatusFD, "status-fd", N_("|FD|write status info to this FD")),
  ARGPARSE_s_n (oEnableSpecialFilenames, "enable-special-filenames", "@"),
  ARGPARSE_s_i (oPassphraseFD,    "passphrase-fd", "@"),
  ARGPARSE_s_s (oPinentryMode,    "pinentry-mode", "@"),


  ARGPARSE_header (NULL, N_("Other options")),

  ARGPARSE_conffile (oOptions, "options", N_("|FILE|read options from FILE")),
  ARGPARSE_noconffile (oNoOptions, "no-options", "@"),
  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),
  ARGPARSE_s_s (oRequestOrigin,   "request-origin", "@"),
  ARGPARSE_s_n (oForceCRLRefresh, "force-crl-refresh", "@"),
  ARGPARSE_s_n (oEnableIssuerBasedCRLCheck, "enable-issuer-based-crl-check",
                "@"),
  ARGPARSE_s_s (oAuditLog, "audit-log",
                N_("|FILE|write an audit log to FILE")),
  ARGPARSE_s_s (oHtmlAuditLog, "html-audit-log", "@"),
  ARGPARSE_s_s (oDisplay,    "display", "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname", "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype", "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages", "@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oChUid, "chuid", "@"),
  ARGPARSE_s_s (oCompatibilityFlags, "compatibility-flags", "@"),
  ARGPARSE_p_u (oKbxBufferSize,  "kbx-buffer-size", "@"),

  ARGPARSE_header (NULL, ""),  /* Stop the header group.  */


  /* Command aliases.  */
  ARGPARSE_c (aListKeys, "list-key", "@"),
  ARGPARSE_c (aListChain, "list-signatures", "@"),
  ARGPARSE_c (aListChain, "list-sigs", "@"),
  ARGPARSE_c (aListChain, "check-signatures", "@"),
  ARGPARSE_c (aListChain, "check-sigs", "@"),
  ARGPARSE_c (aDeleteKey, "delete-key", "@"),

  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
  )),

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_X509_VALUE   , "x509"    },
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_CLOCK_VALUE  , "clock"   },
    { DBG_LOOKUP_VALUE , "lookup"  },
    { 0, NULL }
  };


/* The list of compatibility flags.  */
static struct compatibility_flags_s compatibility_flags [] =
  {
    { COMPAT_ALLOW_KA_TO_ENCR, "allow-ka-to-encr" },
    { 0, NULL }
  };


/* Global variable to keep an error count. */
int gpgsm_errors_seen = 0;

/* It is possible that we are currentlu running under setuid permissions */
static int maybe_setuid = 1;

/* Helper to implement --debug-level and --debug*/
static const char *debug_level;
static unsigned int debug_value;

/* Helper for --log-time;  */
static int opt_log_time;

/* Default value for include-certs.  We need an extra macro for
   gpgconf-list because the variable will be changed by the command
   line option.

   It is often cumbersome to locate intermediate certificates, thus by
   default we include all certificates in the chain.  However we leave
   out the root certificate because that would make it too easy for
   the recipient to import that root certificate.  A root certificate
   should be installed only after due checks and thus it won't help to
   send it along with each message.  */
#define DEFAULT_INCLUDE_CERTS -2 /* Include all certs but root. */
static int default_include_certs = DEFAULT_INCLUDE_CERTS;

/* Whether the chain mode shall be used for validation.  */
static int default_validation_model;

/* The default cipher algo.  */
#define DEFAULT_CIPHER_ALGO "AES256"


static char *build_list (const char *text,
			 const char *(*mapf)(int), int (*chkf)(int));
static void set_cmd (enum cmd_and_opt_values *ret_cmd,
                     enum cmd_and_opt_values new_cmd );

static void emergency_cleanup (void);
static int open_read (const char *filename);
static estream_t open_es_fread (const char *filename, const char *mode);
static estream_t open_es_fwrite (const char *filename);
static void run_protect_tool (int argc, char **argv);

static int
our_pk_test_algo (int algo)
{
  switch (algo)
    {
    case GCRY_PK_RSA:
    case GCRY_PK_ECDSA:
    case GCRY_PK_EDDSA:
      return gcry_pk_test_algo (algo);
    default:
      return 1;
    }
}

static int
our_cipher_test_algo (int algo)
{
  switch (algo)
    {
    case GCRY_CIPHER_3DES:
    case GCRY_CIPHER_AES128:
    case GCRY_CIPHER_AES192:
    case GCRY_CIPHER_AES256:
    case GCRY_CIPHER_SERPENT128:
    case GCRY_CIPHER_SERPENT192:
    case GCRY_CIPHER_SERPENT256:
    case GCRY_CIPHER_SEED:
    case GCRY_CIPHER_CAMELLIA128:
    case GCRY_CIPHER_CAMELLIA192:
    case GCRY_CIPHER_CAMELLIA256:
      return gcry_cipher_test_algo (algo);
    default:
      return 1;
    }
}


static int
our_md_test_algo (int algo)
{
  switch (algo)
    {
    case GCRY_MD_MD5:
    case GCRY_MD_SHA1:
    case GCRY_MD_RMD160:
    case GCRY_MD_SHA224:
    case GCRY_MD_SHA256:
    case GCRY_MD_SHA384:
    case GCRY_MD_SHA512:
    case GCRY_MD_WHIRLPOOL:
      return gcry_md_test_algo (algo);
    default:
      return 1;
    }
}


/* nPth wrapper function definitions. */
ASSUAN_SYSTEM_NPTH_IMPL;


static char *
make_libversion (const char *libname, const char *(*getfnc)(const char*))
{
  const char *s;
  char *result;

  if (maybe_setuid)
    {
      gcry_control (GCRYCTL_INIT_SECMEM, 0, 0);  /* Drop setuid. */
      maybe_setuid = 0;
    }
  s = getfnc (NULL);
  result = xmalloc (strlen (libname) + 1 + strlen (s) + 1);
  strcpy (stpcpy (stpcpy (result, libname), " "), s);
  return result;
}


static const char *
my_strusage( int level )
{
  static char *digests, *pubkeys, *ciphers;
  static char *ver_gcry, *ver_ksba;
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "@GPGSM@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: @GPGSM@ [options] [files] (-h for help)");
      break;
    case 41:
      p = _("Syntax: @GPGSM@ [options] [files]\n"
            "Sign, check, encrypt or decrypt using the S/MIME protocol\n"
            "Default operation depends on the input data\n");
      break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;
    case 21:
      if (!ver_ksba)
        ver_ksba = make_libversion ("libksba", ksba_check_version);
      p = ver_ksba;
      break;

    case 31: p = "\nHome: "; break;
    case 32: p = gnupg_homedir (); break;
    case 33: p = _("\nSupported algorithms:\n"); break;
    case 34:
      if (!ciphers)
        ciphers = build_list ("Cipher: ", gnupg_cipher_algo_name,
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

  for (i=1; i < 400; i++ )
    if (!chkf(i))
      n += strlen(mapf(i)) + 2;
  list = xmalloc (21 + n);
  *list = 0;
  for (p=NULL, i=1; i < 400; i++)
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
    strcpy (p, "\n" );
  return list;
}


/* Set the file pointer into binary mode if required.  */
static void
set_binary (FILE *fp)
{
#ifdef HAVE_DOSISH_SYSTEM
  setmode (fileno (fp), O_BINARY);
#else
  (void)fp;
#endif
}



static void
wrong_args (const char *text)
{
  fprintf (stderr, _("usage: %s [options] %s\n"), GPGSM_NAME, text);
  gpgsm_exit (2);
}


static void
set_opt_session_env (const char *name, const char *value)
{
  gpg_error_t err;

  err = session_env_setenv (opt.session_env, name, value);
  if (err)
    log_fatal ("error setting session environment: %s\n",
               gpg_strerror (err));
}


/* Setup the debugging.  With a DEBUG_LEVEL of NULL only the active
   debug flags are propagated to the subsystems.  With DEBUG_LEVEL
   set, a specific set of debug flags is set; and individual debugging
   flags will be added on top.  */
static void
set_debug (void)
{
  int numok = (debug_level && digitp (debug_level));
  int numlvl = numok? atoi (debug_level) : 0;

  if (!debug_level)
    ;
  else if (!strcmp (debug_level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp (debug_level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp (debug_level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_IPC_VALUE|DBG_X509_VALUE;
  else if (!strcmp (debug_level, "expert")  || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE|DBG_X509_VALUE
                 |DBG_CACHE_VALUE|DBG_CRYPTO_VALUE);
  else if (!strcmp (debug_level, "guru") || numok)
    {
      opt.debug = ~0;
      /* Unless the "guru" string has been used we don't want to allow
         hashing debugging.  The rationale is that people tend to
         select the highest debug value and would then clutter their
         disk with debug files which may reveal confidential data.  */
      if (numok)
        opt.debug &= ~(DBG_HASHING_VALUE);
    }
  else
    {
      log_error (_("invalid debug-level '%s' given\n"), debug_level);
      gpgsm_exit (2);
    }

  opt.debug |= debug_value;

  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug)
    opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);

  /* minip12.c may be used outside of GnuPG, thus we don't have the
   * opt structure over there.  */
  p12_set_verbosity (opt.verbose, opt.debug);
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
                  certlist_t *recplist, int is_encrypt_to, int recp_required)
{
  int rc = gpgsm_add_to_certlist (ctrl, name, 0, recplist, is_encrypt_to);
  if (rc)
    {
      if (recp_required)
        {
          log_error ("can't encrypt to '%s': %s\n", name, gpg_strerror (rc));
          gpgsm_status2 (ctrl, STATUS_INV_RECP,
                         get_inv_recpsgnr_code (rc), name, NULL);
        }
      else
        log_info (_("Note: won't be able to encrypt to '%s': %s\n"),
                  name, gpg_strerror (rc));
    }
}


static void
parse_validation_model (const char *model)
{
  int i = gpgsm_parse_validation_model (model);
  if (i == -1)
    log_error (_("unknown validation model '%s'\n"), model);
  else
    default_validation_model = i;
}



int
main ( int argc, char **argv)
{
  gpg_error_t err = 0;
  gpgrt_argparse_t pargs;
  int orig_argc;
  char **orig_argv;
  /*  char *username;*/
  int may_coredump;
  strlist_t sl, remusr= NULL, locusr=NULL;
  strlist_t nrings=NULL;
  int detached_sig = 0;
  char *last_configname = NULL;
  const char *configname = NULL; /* NULL or points to last_configname.
                                  * NULL also indicates that we are
                                  * processing options from the cmdline.  */
  int debug_argparser = 0;
  int no_more_options = 0;
  int default_keyring = 1;
  char *logfile = NULL;
  char *auditlog = NULL;
  char *htmlauditlog = NULL;
  int greeting = 0;
  int nogreeting = 0;
  int debug_wait = 0;
  int use_random_seed = 1;
  int no_common_certs_import = 0;
  int with_fpr = 0;
  const char *forced_digest_algo = NULL;
  const char *extra_digest_algo = NULL;
  enum cmd_and_opt_values cmd = 0;
  struct server_control_s ctrl;
  certlist_t recplist = NULL;
  certlist_t signerlist = NULL;
  int do_not_setup_keys = 0;
  int recp_required = 0;
  estream_t auditfp = NULL;
  estream_t htmlauditfp = NULL;
  struct assuan_malloc_hooks malloc_hooks;
  int pwfd = -1;

  static const char *homedirvalue;
  static const char *changeuser;


  early_system_init ();
  gnupg_reopen_std (GPGSM_NAME);
  /* trap_unaligned ();*/
  gnupg_rl_initialize ();
  gpgrt_set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to secmem_init()
     somewhere after the option parsing */
  log_set_prefix (GPGSM_NAME, GPGRT_LOG_WITH_PREFIX|GPGRT_LOG_NO_REGISTRY);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  /* Check that the libraries are suitable.  Do it here because the
     option parse may need services of the library */
  if (!ksba_check_version (NEED_KSBA_VERSION) )
    log_fatal (_("%s is too old (need %s, have %s)\n"), "libksba",
               NEED_KSBA_VERSION, ksba_check_version (NULL) );


  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  gnupg_init_signals (0, emergency_cleanup);

  dotlock_create (NULL, 0); /* Register lockfile cleanup.  */

  /* Tell the compliance module who we are.  */
  gnupg_initialize_compliance (GNUPG_MODULE_NAME_GPGSM);

  opt.autostart = 1;
  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

  /* Note: If you change this default cipher algorithm , please
     remember to update the Gpgconflist entry as well.  */
  opt.def_cipher_algoid = DEFAULT_CIPHER_ALGO;


  /* First check whether we have a config file on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oDebug:
        case oDebugAll:
          debug_argparser++;
          break;

        case oNoOptions:
          /* Set here here because the homedir would otherwise be
           * created before main option parsing starts.  */
          opt.no_homedir_creation = 1;
          break;

        case oHomedir:
          homedirvalue = pargs.r.ret_str;
          break;

        case oChUid:
          changeuser = pargs.r.ret_str;
          break;

        case aCallProtectTool:
          /* Make sure that --version and --help are passed to the
           * protect-tool. */
          goto leave_cmdline_parser;
        }
    }
 leave_cmdline_parser:
  /* Reset the flags.  */
  pargs.flags &= ~(ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /*
     Now we are now working under our real uid
   */

  ksba_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free );

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks (&malloc_hooks);
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  setup_libassuan_logging (&opt.debug, NULL);

  /* Change UID and then set homedir.  */
  if (changeuser && gnupg_chuid (changeuser, 0))
    log_inc_errorcount (); /* Force later termination.  */
  gnupg_set_homedir (homedirvalue);

  /* Setup a default control structure for command line mode */
  memset (&ctrl, 0, sizeof ctrl);
  gpgsm_init_default_ctrl (&ctrl);
  ctrl.no_server = 1;
  ctrl.status_fd = -1; /* No status output. */
  ctrl.autodetect_encoding = 1;

  /* Set the default policy file */
  opt.policy_file = make_filename (gnupg_homedir (), "policies.txt", NULL);

  /* The configuraton directories for use by gpgrt_argparser.  */
  gpgrt_set_confdir (GPGRT_CONFDIR_SYS, gnupg_sysconfdir ());
  gpgrt_set_confdir (GPGRT_CONFDIR_USER, gnupg_homedir ());

  /* We are re-using the struct, thus the reset flag.  We OR the
   * flags so that the internal intialized flag won't be cleared. */
  argc        = orig_argc;
  argv        = orig_argv;
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags |=  (ARGPARSE_FLAG_RESET
                   | ARGPARSE_FLAG_KEEP
                   | ARGPARSE_FLAG_SYS
                   | ARGPARSE_FLAG_USER);

  while (!no_more_options
         && gpgrt_argparser (&pargs, opts, GPGSM_NAME EXTSEP_S "conf"))
    {
      switch (pargs.r_opt)
        {
        case ARGPARSE_CONFFILE:
          if (debug_argparser)
            log_info (_("reading options from '%s'\n"),
                      pargs.r_type? pargs.r.ret_str: "[cmdline]");
          if (pargs.r_type)
            {
              xfree (last_configname);
              last_configname = xstrdup (pargs.r.ret_str);
              configname = last_configname;
            }
          else
            configname = NULL;
          break;

	case aGPGConfList:
	case aGPGConfTest:
          set_cmd (&cmd, pargs.r_opt);
          do_not_setup_keys = 1;
          default_keyring = 0;
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

        case aImport:
        case aSendKeys:
        case aRecvKeys:
        case aExport:
        case aExportSecretKeyP12:
        case aExportSecretKeyP8:
        case aExportSecretKeyRaw:
        case aShowCerts:
        case aDumpKeys:
        case aDumpChain:
        case aDumpExternalKeys:
        case aDumpSecretKeys:
        case aListKeys:
        case aListExternalKeys:
        case aListSecretKeys:
        case aListChain:
        case aLearnCard:
        case aPasswd:
        case aKeydbClearSomeCertFlags:
          do_not_setup_keys = 1;
          set_cmd (&cmd, pargs.r_opt);
          break;

        case aEncr:
          recp_required = 1;
          set_cmd (&cmd, pargs.r_opt);
          break;

        case aSym:
        case aDecrypt:
        case aSign:
        case aClearsign:
        case aVerify:
          set_cmd (&cmd, pargs.r_opt);
          break;

          /* Output encoding selection.  */
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

        case oP12Charset:
          opt.p12_charset = pargs.r.ret_str;
          break;

        case oPassphraseFD:
	  pwfd = translate_sys2libc_fd_int (pargs.r.ret_int, 0);
	  break;

        case oPinentryMode:
	  opt.pinentry_mode = parse_pinentry_mode (pargs.r.ret_str);
	  if (opt.pinentry_mode == -1)
            log_error (_("invalid pinentry mode '%s'\n"), pargs.r.ret_str);
	  break;

        case oRequestOrigin:
          opt.request_origin = parse_request_origin (pargs.r.ret_str);
          if (opt.request_origin == -1)
            log_error (_("invalid request origin '%s'\n"), pargs.r.ret_str);
          break;

          /* Input encoding selection.  */
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

        case oInputSizeHint:
          ctrl.input_size_hint = string_to_u64 (pargs.r.ret_str);
          break;

        case oDisableCRLChecks:
          opt.no_crl_check = 1;
          break;
        case oEnableCRLChecks:
          opt.no_crl_check = 0;
          break;
        case oDisableTrustedCertCRLCheck:
          opt.no_trusted_cert_crl_check = 1;
          break;
        case oEnableTrustedCertCRLCheck:
          opt.no_trusted_cert_crl_check = 0;
          break;
        case oForceCRLRefresh:
          opt.force_crl_refresh = 1;
          break;
        case oEnableIssuerBasedCRLCheck:
          opt.enable_issuer_based_crl_check = 1;
          break;

        case oDisableOCSP:
          ctrl.use_ocsp = opt.enable_ocsp = 0;
          break;
        case oEnableOCSP:
          ctrl.use_ocsp = opt.enable_ocsp = 1;
          break;

        case oIncludeCerts:
          ctrl.include_certs = default_include_certs = pargs.r.ret_int;
          break;

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
        case oNoLogFile: logfile = NULL; break;
        case oLogTime: opt_log_time = 1; break;

        case oAuditLog: auditlog = pargs.r.ret_str; break;
        case oHtmlAuditLog: htmlauditlog = pargs.r.ret_str; break;

        case oBatch:
          opt.batch = 1;
          greeting = 0;
          break;
        case oNoBatch: opt.batch = 0; break;

        case oAnswerYes: opt.answer_yes = 1; break;
        case oAnswerNo: opt.answer_no = 1; break;

        case oKeyring: append_to_strlist (&nrings, pargs.r.ret_str); break;
        case oUseKeyboxd: opt.use_keyboxd = 1; break;

        case oDebug:
          if (parse_debug_flag (pargs.r.ret_str, &debug_value, debug_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
          break;
        case oDebugAll: debug_value = ~0; break;
        case oDebugNone: debug_value = 0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: debug_wait = pargs.r.ret_int; break;
        case oDebugAllowCoreDump:
          may_coredump = enable_core_dumps ();
          break;
        case oDebugNoChainValidation: opt.no_chain_validation = 1; break;
        case oDebugIgnoreExpiration: opt.ignore_expiration = 1; break;
        case oDebugForceECDHSHA1KDF: opt.force_ecdh_sha1kdf = 1; break;

        case oCompatibilityFlags:
          if (parse_compatibility_flags (pargs.r.ret_str, &opt.compat_flags,
                                         compatibility_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
          break;

        case oStatusFD:
            ctrl.status_fd = translate_sys2libc_fd_int (pargs.r.ret_int, 1);
            break;
        case oLoggerFD:
            log_set_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
            break;
        case oWithMD5Fingerprint:
          opt.with_md5_fingerprint=1; /*fall through*/
        case oWithFingerprint:
          with_fpr=1; /*fall through*/
        case aFingerprint:
          opt.fingerprint++;
          break;

        case oWithKeygrip:
          opt.with_keygrip = 1;
          break;

        case oWithKeyScreening:
          opt.with_key_screening = 1;
          break;

        case oNoPrettyDN:
          opt.no_pretty_dn = 1;
          break;

        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;
        case oChUid: break;  /* Command line only (see above).  */

        case oAgentProgram:
          xfree (opt.agent_program);
          opt.agent_program = make_filename (pargs.r.ret_str, NULL);
          break;
        case oKeyboxdProgram:
          xfree (opt.keyboxd_program);
          opt.keyboxd_program = make_filename (pargs.r.ret_str, NULL);
          break;
        case oDirmngrProgram:
          xfree (opt.dirmngr_program);
          opt.dirmngr_program = make_filename (pargs.r.ret_str, NULL);
          break;

        case oDisplay:
          set_opt_session_env ("DISPLAY", pargs.r.ret_str);
          break;
        case oTTYname:
          set_opt_session_env ("GPG_TTY", pargs.r.ret_str);
          break;
        case oTTYtype:
          set_opt_session_env ("TERM", pargs.r.ret_str);
          break;
        case oXauthority:
          set_opt_session_env ("XAUTHORITY", pargs.r.ret_str);
          break;

        case oLCctype: opt.lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: opt.lc_messages = xstrdup (pargs.r.ret_str); break;

        case oDisableDirmngr: opt.disable_dirmngr = 1;  break;
        case oPreferSystemDirmngr: /* Obsolete */; break;
        case oProtectToolProgram:
          opt.protect_tool_program = pargs.r.ret_str;
          break;

        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oNoDefKeyring: default_keyring = 0; break;
        case oNoGreeting: nogreeting = 1; break;

        case oDefaultKey:
          if (*pargs.r.ret_str)
            {
              xfree (opt.local_user);
              opt.local_user = xstrdup (pargs.r.ret_str);
            }
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

        case oWithKeyData: opt.with_key_data=1; /* fall through */
        case oWithColons: ctrl.with_colons = 1; break;
        case oWithSecret: ctrl.with_secret = 1; break;
        case oWithValidation: ctrl.with_validation=1; break;
        case oWithEphemeralKeys: ctrl.with_ephemeral_keys=1; break;

        case oSkipVerify: opt.skip_verify=1; break;

        case oNoEncryptTo: opt.no_encrypt_to = 1; break;
        case oEncryptTo: /* Store the recipient in the second list */
          sl = add_to_strlist (&remusr, pargs.r.ret_str);
          sl->flags = 1;
          break;

        case oRecipient: /* store the recipient */
          add_to_strlist ( &remusr, pargs.r.ret_str);
          break;

        case oUser: /* Store the local users, the first one is the default */
          if (!opt.local_user)
            opt.local_user = xstrdup (pargs.r.ret_str);
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

        case oDigestAlgo:
          forced_digest_algo = pargs.r.ret_str;
          break;

        case oExtraDigestAlgo:
          extra_digest_algo = pargs.r.ret_str;
          break;

        case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
        case oNoRandomSeedFile: use_random_seed = 0; break;
        case oNoCommonCertsImport: no_common_certs_import = 1; break;

        case oEnableSpecialFilenames:
          enable_special_filenames ();
          break;

        case oValidationModel: parse_validation_model (pargs.r.ret_str); break;

	case oKeyServer:
          append_to_strlist (&opt.keyserver, pargs.r.ret_str);
	  break;

        case oKeyServer_deprecated:
          obsolete_option (configname, pargs.lineno, "ldapserver");
          break;

        case oIgnoreCertExtension:
          add_to_strlist (&opt.ignored_cert_extensions, pargs.r.ret_str);
          break;

        case oIgnoreCertWithOID:
          add_to_strlist (&opt.ignore_cert_with_oid, pargs.r.ret_str);
          break;

        case oAuthenticode: opt.authenticode = 1; break;

        case oAttribute:
          add_to_strlist (&opt.attributes, pargs.r.ret_str);
          break;

        case oNoAutostart: opt.autostart = 0; break;

        case oCompliance:
          {
            struct gnupg_compliance_option compliance_options[] =
              {
                { "gnupg", CO_GNUPG },
                { "de-vs", CO_DE_VS }
              };
            int compliance = gnupg_parse_compliance_option
              (pargs.r.ret_str, compliance_options, DIM (compliance_options),
               opt.quiet);
            if (compliance < 0)
              log_inc_errorcount (); /* Force later termination.  */
            opt.compliance = compliance;
          }
          break;

        case oMinRSALength: opt.min_rsa_length = pargs.r.ret_ulong; break;

        case oRequireCompliance: opt.require_compliance = 1;  break;
        case oAlwaysTrust: opt.always_trust = 1;  break;

        case oKbxBufferSize:
          keybox_set_buffersize (pargs.r.ret_ulong, 0);
          break;

        default:
          if (configname)
            pargs.err = ARGPARSE_PRINT_WARNING;
          else
            {
              pargs.err = ARGPARSE_PRINT_ERROR;
              /* The argparse function calls a plain exit and thus we
               * need to print a status here.  */
              gpgsm_status_with_error (&ctrl, STATUS_FAILURE, "option-parser",
                                       gpg_error (GPG_ERR_GENERAL));
            }
          break;
	}
    }

  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (!last_configname)
    opt.config_filename = gpgrt_fnameconcat (gnupg_homedir (),
                                             GPGSM_NAME EXTSEP_S "conf",
                                             NULL);
  else
    opt.config_filename = last_configname;

  if (log_get_errorcount(0))
    {
      gpgsm_status_with_error (&ctrl, STATUS_FAILURE,
                               "option-parser", gpg_error (GPG_ERR_GENERAL));
      gpgsm_exit(2);
    }

  /* Process common component options.  */
  if (parse_comopt (GNUPG_MODULE_NAME_GPGSM, debug_argparser))
    {
      gpgsm_status_with_error (&ctrl, STATUS_FAILURE,
                               "option-parser", gpg_error (GPG_ERR_GENERAL));
      gpgsm_exit(2);
    }

  if (opt.use_keyboxd)
    log_info ("Note: Please move option \"%s\" to \"common.conf\"\n",
              "use-keyboxd");
  opt.use_keyboxd = comopt.use_keyboxd;  /* Override.  */

  if (opt.keyboxd_program)
    log_info ("Note: Please move option \"%s\" to \"common.conf\"\n",
              "keyboxd-program");
  if (!opt.keyboxd_program && comopt.keyboxd_program)
    {
      opt.keyboxd_program = comopt.keyboxd_program;
      comopt.keyboxd_program = NULL;
    }

  if (comopt.no_autostart)
    opt.autostart = 0;

  if (pwfd != -1)	/* Read the passphrase now.  */
    read_passphrase_from_fd (pwfd);

  /* Now that we have the options parsed we need to update the default
     control structure.  */
  gpgsm_init_default_ctrl (&ctrl);

  if (nogreeting)
    greeting = 0;

  if (greeting)
    {
      es_fprintf (es_stderr, "%s %s; %s\n",
                  gpgrt_strusage(11), gpgrt_strusage(13), gpgrt_strusage(14) );
      es_fprintf (es_stderr, "%s\n", gpgrt_strusage(15) );
    }
#ifdef IS_DEVELOPMENT_VERSION
  if (!opt.batch)
    {
      log_info ("NOTE: THIS IS A DEVELOPMENT VERSION!\n");
      log_info ("It is only intended for test purposes and should NOT be\n");
      log_info ("used in a production environment or with production keys!\n");
    }
#endif

  if (may_coredump && !opt.quiet)
    log_info (_("WARNING: program may create a core file!\n"));

  if (opt.require_compliance && opt.always_trust)
    {
      opt.always_trust = 0;
      if (opt.quiet)
        log_info (_("WARNING: %s overrides %s\n"),
                  "--require-compliance","--always-trust");
    }


  npth_init ();
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  gpgrt_set_syscall_clamp (npth_unprotect, npth_protect);


/*   if (opt.qualsig_approval && !opt.quiet) */
/*     log_info (_("This software has officially been approved to " */
/*                 "create and verify\n" */
/*                 "qualified signatures according to German law.\n")); */

  if (logfile && cmd == aServer)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, GPGRT_LOG_WITH_PREFIX | GPGRT_LOG_WITH_TIME | GPGRT_LOG_WITH_PID);
    }
  else if (opt_log_time)
    log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX|GPGRT_LOG_NO_REGISTRY
                           |GPGRT_LOG_WITH_TIME));


  if (gnupg_faked_time_p ())
    {
      gnupg_isotime_t tbuf;

      log_info (_("WARNING: running with faked system time: "));
      gnupg_get_isotime (tbuf);
      dump_isotime (tbuf);
      log_printf ("\n");
    }

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }

/*FIXME    if (opt.batch) */
/*      tty_batchmode (1); */

  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  set_debug ();
  if (opt.verbose) /* Print the compatibility flags.  */
    parse_compatibility_flags (NULL, &opt.compat_flags, compatibility_flags);
  gnupg_set_compliance_extra_info (opt.min_rsa_length);

  /* Although we always use gpgsm_exit, we better install a regular
     exit handler so that at least the secure memory gets wiped
     out. */
  if (atexit (emergency_cleanup))
    {
      log_error ("atexit failed\n");
      gpgsm_exit (2);
    }

  /* Must do this after dropping setuid, because the mapping functions
     may try to load an module and we may have disabled an algorithm.
     We remap the commonly used algorithms to the OIDs for
     convenience.  We need to work with the OIDs because they are used
     to check whether the encryption mode is actually available. */
  if (!strcmp (opt.def_cipher_algoid, "3DES") )
    opt.def_cipher_algoid = "1.2.840.113549.3.7";
  else if (!strcmp (opt.def_cipher_algoid, "AES")
           || !strcmp (opt.def_cipher_algoid, "AES128"))
    opt.def_cipher_algoid = "2.16.840.1.101.3.4.1.2";
  else if (!strcmp (opt.def_cipher_algoid, "AES192") )
    opt.def_cipher_algoid = "2.16.840.1.101.3.4.1.22";
  else if (!strcmp (opt.def_cipher_algoid, "AES256") )
    opt.def_cipher_algoid = "2.16.840.1.101.3.4.1.42";
  else if (!strcmp (opt.def_cipher_algoid, "SERPENT")
           || !strcmp (opt.def_cipher_algoid, "SERPENT128") )
    opt.def_cipher_algoid = "1.3.6.1.4.1.11591.13.2.2";
  else if (!strcmp (opt.def_cipher_algoid, "SERPENT192") )
    opt.def_cipher_algoid = "1.3.6.1.4.1.11591.13.2.22";
  else if (!strcmp (opt.def_cipher_algoid, "SERPENT256") )
    opt.def_cipher_algoid = "1.3.6.1.4.1.11591.13.2.42";
  else if (!strcmp (opt.def_cipher_algoid, "SEED") )
    opt.def_cipher_algoid = "1.2.410.200004.1.4";
  else if (!strcmp (opt.def_cipher_algoid, "CAMELLIA")
           || !strcmp (opt.def_cipher_algoid, "CAMELLIA128") )
    opt.def_cipher_algoid = "1.2.392.200011.61.1.1.1.2";
  else if (!strcmp (opt.def_cipher_algoid, "CAMELLIA192") )
    opt.def_cipher_algoid = "1.2.392.200011.61.1.1.1.3";
  else if (!strcmp (opt.def_cipher_algoid, "CAMELLIA256") )
    opt.def_cipher_algoid = "1.2.392.200011.61.1.1.1.4";

  if (cmd != aGPGConfList)
    {
      if ( !gcry_cipher_map_name (opt.def_cipher_algoid)
           || !gcry_cipher_mode_from_oid (opt.def_cipher_algoid))
        log_error (_("selected cipher algorithm is invalid\n"));

      if (forced_digest_algo)
        {
          opt.forced_digest_algo = gcry_md_map_name (forced_digest_algo);
          if (our_md_test_algo(opt.forced_digest_algo) )
            log_error (_("selected digest algorithm is invalid\n"));
        }
      if (extra_digest_algo)
        {
          opt.extra_digest_algo = gcry_md_map_name (extra_digest_algo);
          if (our_md_test_algo (opt.extra_digest_algo) )
            log_error (_("selected digest algorithm is invalid\n"));
        }
    }

  /* Check our chosen algorithms against the list of allowed
   * algorithms in the current compliance mode, and fail hard if it is
   * not.  This is us being nice to the user informing her early that
   * the chosen algorithms are not available.  We also check and
   * enforce this right before the actual operation.  */
  if (! gnupg_cipher_is_allowed (opt.compliance,
                                 cmd == aEncr || cmd == aSignEncr,
                                 gcry_cipher_map_name (opt.def_cipher_algoid),
                                 GCRY_CIPHER_MODE_NONE)
      && ! gnupg_cipher_is_allowed (opt.compliance,
                                    cmd == aEncr || cmd == aSignEncr,
                                    gcry_cipher_mode_from_oid
                                    (opt.def_cipher_algoid),
                                    GCRY_CIPHER_MODE_NONE))
    log_error (_("cipher algorithm '%s' may not be used in %s mode\n"),
               opt.def_cipher_algoid,
               gnupg_compliance_option_string (opt.compliance));

  if (forced_digest_algo
      && ! gnupg_digest_is_allowed (opt.compliance,
                                     cmd == aSign
                                     || cmd == aSignEncr
                                     || cmd == aClearsign,
                                     opt.forced_digest_algo))
    log_error (_("digest algorithm '%s' may not be used in %s mode\n"),
               forced_digest_algo,
               gnupg_compliance_option_string (opt.compliance));

  if (extra_digest_algo
      && ! gnupg_digest_is_allowed (opt.compliance,
                                     cmd == aSign
                                     || cmd == aSignEncr
                                     || cmd == aClearsign,
                                     opt.extra_digest_algo))
    log_error (_("digest algorithm '%s' may not be used in %s mode\n"),
               extra_digest_algo,
               gnupg_compliance_option_string (opt.compliance));

  if (log_get_errorcount(0))
    {
      gpgsm_status_with_error (&ctrl, STATUS_FAILURE, "option-postprocessing",
                               gpg_error (GPG_ERR_GENERAL));
      gpgsm_exit (2);
    }

  /* Set the random seed file. */
  if (use_random_seed)
    {
      char *p = make_filename (gnupg_homedir (), "random_seed", NULL);
      gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
      xfree(p);
    }

  if (!cmd && opt.fingerprint && !with_fpr)
    set_cmd (&cmd, aListKeys);

  /* If no pinentry is expected shunt
   * gnupg_allow_set_foregound_window to avoid useless error
   * messages on Windows.  */
  if (opt.pinentry_mode != PINENTRY_MODE_ASK)
    {
      gnupg_inhibit_set_foregound_window (1);
    }

  /* Add default keybox. */
  if (!nrings && default_keyring && !opt.use_keyboxd)
    {
      int created;

      keydb_add_resource (&ctrl, "pubring.kbx", 0, &created);
      if (created && !no_common_certs_import)
        {
          /* Import the standard certificates for a new default keybox. */
          char *filelist[2];

          filelist[0] = make_filename (gnupg_datadir (),"com-certs.pem", NULL);
          filelist[1] = NULL;
          if (!gnupg_access (filelist[0], F_OK))
            {
              log_info (_("importing common certificates '%s'\n"),
                        filelist[0]);
              gpgsm_import_files (&ctrl, 1, filelist, open_read);
            }
          xfree (filelist[0]);
        }
    }
  if (!opt.use_keyboxd)
    {
      for (sl = nrings; sl; sl = sl->next)
        keydb_add_resource (&ctrl, sl->d, 0, NULL);
    }
  FREE_STRLIST(nrings);


  /* Prepare the audit log feature for certain commands.  */
  if (auditlog || htmlauditlog)
    {
      switch (cmd)
        {
        case aEncr:
        case aSign:
        case aDecrypt:
        case aVerify:
          audit_release (ctrl.audit);
          ctrl.audit = audit_new ();
          if (auditlog)
            auditfp = open_es_fwrite (auditlog);
          if (htmlauditlog)
            htmlauditfp = open_es_fwrite (htmlauditlog);
          break;
        default:
          break;
        }
    }


  if (!do_not_setup_keys)
    {
      int errcount = log_get_errorcount (0);

      for (sl = locusr; sl ; sl = sl->next)
        {
          int rc = gpgsm_add_to_certlist (&ctrl, sl->d, 1, &signerlist, 0);
          if (rc)
            {
              log_error (_("can't sign using '%s': %s\n"),
                         sl->d, gpg_strerror (rc));
              gpgsm_status2 (&ctrl, STATUS_INV_SGNR,
                             get_inv_recpsgnr_code (rc), sl->d, NULL);
              gpgsm_status2 (&ctrl, STATUS_INV_RECP,
                             get_inv_recpsgnr_code (rc), sl->d, NULL);
            }
        }

      /* Build the recipient list.  We first add the regular ones and then
         the encrypt-to ones because the underlying function will silently
         ignore duplicates and we can't allow keeping a duplicate which is
         flagged as encrypt-to as the actually encrypt function would then
         complain about no (regular) recipients. */
      for (sl = remusr; sl; sl = sl->next)
        if (!(sl->flags & 1))
          do_add_recipient (&ctrl, sl->d, &recplist, 0, recp_required);
      if (!opt.no_encrypt_to)
        {
          for (sl = remusr; sl; sl = sl->next)
            if ((sl->flags & 1))
              do_add_recipient (&ctrl, sl->d, &recplist, 1, recp_required);
        }

      /* We do not require a recipient for decryption but because
       * recipients and signers are always checked and log_error is
       * sometimes used (for failed signing keys or due to a failed
       * CRL checking) that would have bumbed up the error counter.
       * We clear the counter in the decryption case because there is
       * no reason to force decryption to fail. */
      if (cmd == aDecrypt && !errcount)
        log_get_errorcount (1); /* clear counter */
    }

  if (log_get_errorcount(0))
    gpgsm_exit(1); /* Must stop for invalid recipients. */

  /* Dispatch command.  */
  switch (cmd)
    {
    case aGPGConfList:
      { /* List default option values in the GPG Conf format.  */

	es_printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
        es_printf ("include-certs:%lu:%d:\n", GC_OPT_FLAG_DEFAULT,
                   DEFAULT_INCLUDE_CERTS);
        es_printf ("cipher-algo:%lu:\"%s:\n", GC_OPT_FLAG_DEFAULT,
                   DEFAULT_CIPHER_ALGO);
        es_printf ("p12-charset:%lu:\n", GC_OPT_FLAG_DEFAULT);
        es_printf ("default-key:%lu:\n", GC_OPT_FLAG_DEFAULT);
        es_printf ("encrypt-to:%lu:\n", GC_OPT_FLAG_DEFAULT);

        /* The next one is an info only item and should match what
           proc_parameters actually implements.  */
        es_printf ("default_pubkey_algo:%lu:\"%s:\n", GC_OPT_FLAG_DEFAULT,
                   "RSA-3072");

      }
      break;
    case aGPGConfTest:
      /* This is merely a dummy command to test whether the
         configuration file is valid.  */
      break;

    case aServer:
      if (debug_wait)
        {
          log_debug ("waiting for debugger - my pid is %u .....\n",
                     (unsigned int)getpid());
          gnupg_sleep (debug_wait);
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

    case aEncr: /* Encrypt the given file. */
      {
        estream_t fp = open_es_fwrite (opt.outfile?opt.outfile:"-");

        set_binary (stdin);

        if (!argc) /* Source is stdin. */
          err = gpgsm_encrypt (&ctrl, recplist, 0, fp);
        else if (argc == 1)  /* Source is the given file. */
          err = gpgsm_encrypt (&ctrl, recplist, open_read (*argv), fp);
        else
          wrong_args ("--encrypt [datafile]");

        if (err)
          gpgrt_fcancel (fp);
        else
          es_fclose (fp);
      }
      break;

    case aSign: /* Sign the given file. */
      {
        estream_t fp = open_es_fwrite (opt.outfile?opt.outfile:"-");

        /* Fixme: We should also allow concatenation of multiple files for
           signing because that is what gpg does.*/
        set_binary (stdin);
        if (!argc) /* Create from stdin. */
          err = gpgsm_sign (&ctrl, signerlist, 0, detached_sig, fp);
        else if (argc == 1) /* From file. */
          err = gpgsm_sign (&ctrl, signerlist,
                      open_read (*argv), detached_sig, fp);
        else
          wrong_args ("--sign [datafile]");

#if GPGRT_VERSION_NUMBER >= 0x012700 /* >= 1.39 */
        if (err)
          gpgrt_fcancel (fp);
        else
          es_fclose (fp);
#else
        (void)err;
        es_fclose (fp);
#endif
      }
      break;

    case aSignEncr: /* sign and encrypt the given file */
      log_error ("the command '%s' has not yet been implemented\n",
                 "--sign --encrypt");
      gpgsm_status_with_error (&ctrl, STATUS_FAILURE, "option-parser",
                               gpg_error (GPG_ERR_NOT_IMPLEMENTED));
      break;

    case aClearsign: /* make a clearsig */
      log_error ("the command '%s' has not yet been implemented\n",
                 "--clearsign");
      gpgsm_status_with_error (&ctrl, STATUS_FAILURE, "option-parser",
                               gpg_error (GPG_ERR_NOT_IMPLEMENTED));
      break;

    case aVerify:
      {
        estream_t fp = NULL;

        set_binary (stdin);
        if (argc == 2 && opt.outfile)
          log_info ("option --output ignored for a detached signature\n");
        else if (opt.outfile)
          fp = open_es_fwrite (opt.outfile);

        if (!argc)
          gpgsm_verify (&ctrl, 0, -1, fp); /* normal signature from stdin */
        else if (argc == 1)
          gpgsm_verify (&ctrl, open_read (*argv), -1, fp); /* std signature */
        else if (argc == 2) /* detached signature (sig, detached) */
          gpgsm_verify (&ctrl, open_read (*argv), open_read (argv[1]), NULL);
        else
          wrong_args ("--verify [signature [detached_data]]");

        es_fclose (fp);
      }
      break;

    case aDecrypt:
      {
        estream_t fp = open_es_fwrite (opt.outfile?opt.outfile:"-");

        set_binary (stdin);
        if (!argc)
          err = gpgsm_decrypt (&ctrl, 0, fp); /* from stdin */
        else if (argc == 1)
          err = gpgsm_decrypt (&ctrl, open_read (*argv), fp); /* from file */
        else
          wrong_args ("--decrypt [filename]");

        if (err)
          gpgrt_fcancel (fp);
        else
          es_fclose (fp);
      }
      break;

    case aDeleteKey:
      for (sl=NULL; argc; argc--, argv++)
        add_to_strlist (&sl, *argv);
      gpgsm_delete (&ctrl, sl);
      free_strlist(sl);
      break;

    case aListChain:
    case aDumpChain:
       ctrl.with_chain = 1; /* fall through */
    case aListKeys:
    case aDumpKeys:
    case aListExternalKeys:
    case aDumpExternalKeys:
    case aListSecretKeys:
    case aDumpSecretKeys:
      {
        unsigned int mode;
        estream_t fp;

        switch (cmd)
          {
          case aListChain:
          case aListKeys:         mode = (0   | 0 | (1<<6)); break;
          case aDumpChain:
          case aDumpKeys:         mode = (256 | 0 | (1<<6)); break;
          case aListExternalKeys: mode = (0   | 0 | (1<<7)); break;
          case aDumpExternalKeys: mode = (256 | 0 | (1<<7)); break;
          case aListSecretKeys:   mode = (0   | 2 | (1<<6)); break;
          case aDumpSecretKeys:   mode = (256 | 2 | (1<<6)); break;
          default: BUG();
          }

        fp = open_es_fwrite (opt.outfile?opt.outfile:"-");
        for (sl=NULL; argc; argc--, argv++)
          add_to_strlist (&sl, *argv);
        gpgsm_list_keys (&ctrl, sl, fp, mode);
        free_strlist(sl);
        es_fclose (fp);
      }
      break;

    case aShowCerts:
      {
        estream_t fp;

        fp = open_es_fwrite (opt.outfile?opt.outfile:"-");
        gpgsm_show_certs (&ctrl, argc, argv, fp);
        es_fclose (fp);
      }
      break;

    case aKeygen: /* Generate a key; well kind of. */
      {
        estream_t fpin = NULL;
        estream_t fpout;

        if (opt.batch)
          {
            if (!argc) /* Create from stdin. */
              fpin = open_es_fread ("-", "r");
            else if (argc == 1) /* From file. */
              fpin = open_es_fread (*argv, "r");
            else
              wrong_args ("--generate-key --batch [parmfile]");
          }

        fpout = open_es_fwrite (opt.outfile?opt.outfile:"-");

        if (fpin)
          gpgsm_genkey (&ctrl, fpin, fpout);
        else
          gpgsm_gencertreq_tty (&ctrl, fpout);

        es_fclose (fpout);
      }
      break;


    case aImport:
      gpgsm_import_files (&ctrl, argc, argv, open_read);
      break;

    case aExport:
      {
        estream_t fp;

        fp = open_es_fwrite (opt.outfile?opt.outfile:"-");
        for (sl=NULL; argc; argc--, argv++)
          add_to_strlist (&sl, *argv);
        gpgsm_export (&ctrl, sl, fp);
        free_strlist(sl);
        es_fclose (fp);
      }
      break;

    case aExportSecretKeyP12:
      {
        estream_t fp = open_es_fwrite (opt.outfile?opt.outfile:"-");

        if (argc == 1)
          gpgsm_p12_export (&ctrl, *argv, fp, 0);
        else
          wrong_args ("--export-secret-key-p12 KEY-ID");
        if (fp != es_stdout)
          es_fclose (fp);
      }
      break;

    case aExportSecretKeyP8:
      {
        estream_t fp = open_es_fwrite (opt.outfile?opt.outfile:"-");

        if (argc == 1)
          gpgsm_p12_export (&ctrl, *argv, fp, 1);
        else
          wrong_args ("--export-secret-key-p8 KEY-ID");
        if (fp != es_stdout)
          es_fclose (fp);
      }
      break;

    case aExportSecretKeyRaw:
      {
        estream_t fp = open_es_fwrite (opt.outfile?opt.outfile:"-");

        if (argc == 1)
          gpgsm_p12_export (&ctrl, *argv, fp, 2);
        else
          wrong_args ("--export-secret-key-raw KEY-ID");
        if (fp != es_stdout)
          es_fclose (fp);
      }
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
        wrong_args ("--change-passphrase <key-Id>");
      else
        {
          int rc;
          ksba_cert_t cert = NULL;
          char *grip = NULL;

          rc = gpgsm_find_cert (&ctrl, *argv, NULL, &cert, 0);
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
      log_error (_("invalid command (there is no implicit command)\n"));
      gpgsm_status_with_error (&ctrl, STATUS_FAILURE, "option-parser",
                               gpg_error (GPG_ERR_MISSING_ACTION));
      break;
    }

  /* Print the audit result if needed.  */
  if ((auditlog && auditfp) || (htmlauditlog && htmlauditfp))
    {
      if (auditlog && auditfp)
        audit_print_result (ctrl.audit, auditfp, 0);
      if (htmlauditlog && htmlauditfp)
        audit_print_result (ctrl.audit, htmlauditfp, 1);
      audit_release (ctrl.audit);
      ctrl.audit = NULL;
      es_fclose (auditfp);
      es_fclose (htmlauditfp);
    }

  /* cleanup */
  gpgsm_deinit_default_ctrl (&ctrl);
  free_strlist (opt.keyserver);
  opt.keyserver = NULL;
  gpgsm_release_certlist (recplist);
  gpgsm_release_certlist (signerlist);
  FREE_STRLIST (remusr);
  FREE_STRLIST (locusr);
  gpgsm_exit(0);
  return 8; /*NOTREACHED*/
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
  ctrl->include_certs = default_include_certs;
  ctrl->use_ocsp = opt.enable_ocsp;
  ctrl->validation_model = default_validation_model;
  ctrl->offline = opt.disable_dirmngr;
  ctrl->revoked_at[0] = 0;
  ctrl->revocation_reason = NULL;
}


/* This function is called to deinitialize a control object.  The
 * control object is is not released, though.  */
void
gpgsm_deinit_default_ctrl (ctrl_t ctrl)
{
  gpgsm_keydb_deinit_session_data (ctrl);
  xfree (ctrl->revocation_reason);
  ctrl->revocation_reason = NULL;
}


int
gpgsm_parse_validation_model (const char *model)
{
  if (!ascii_strcasecmp (model, "shell") )
    return 0;
  else if ( !ascii_strcasecmp (model, "chain") )
    return 1;
  else if ( !ascii_strcasecmp (model, "steed") )
    return 2;
  else
    return -1;
}



/* Open the FILENAME for read and return the file descriptor.  Stop
   with an error message in case of problems.  "-" denotes stdin and
   if special filenames are allowed the given fd is opened instead.  */
static int
open_read (const char *filename)
{
  int fd;

  if (filename[0] == '-' && !filename[1])
    {
      set_binary (stdin);
      return 0; /* stdin */
    }
  fd = check_special_filename (filename, 0, 0);
  if (fd != -1)
    return fd;
  fd = gnupg_open (filename, O_RDONLY | O_BINARY, 0);
  if (fd == -1)
    {
      log_error (_("can't open '%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fd;
}

/* Same as open_read but return an estream_t.  */
static estream_t
open_es_fread (const char *filename, const char *mode)
{
  int fd;
  estream_t fp;

  if (filename[0] == '-' && !filename[1])
    fd = fileno (stdin);
  else
    fd = check_special_filename (filename, 0, 0);
  if (fd != -1)
    {
      fp = es_fdopen_nc (fd, mode);
      if (!fp)
        {
          log_error ("es_fdopen(%d) failed: %s\n", fd, strerror (errno));
          gpgsm_exit (2);
        }
      return fp;
    }
  fp = es_fopen (filename, mode);
  if (!fp)
    {
      log_error (_("can't open '%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fp;
}


/* Open FILENAME for fwrite and return an extended stream.  Stop with
   an error message in case of problems.  "-" denotes stdout and if
   special filenames are allowed the given fd is opened instead.
   Caller must close the returned stream. */
static estream_t
open_es_fwrite (const char *filename)
{
  int fd;
  estream_t fp;

  if (filename[0] == '-' && !filename[1])
    {
      fflush (stdout);
      fp = es_fdopen_nc (fileno(stdout), "wb");
      return fp;
    }

  fd = check_special_filename (filename, 1, 0);
  if (fd != -1)
    {
      fp = es_fdopen_nc (fd, "wb");
      if (!fp)
        {
          log_error ("es_fdopen(%d) failed: %s\n", fd, strerror (errno));
          gpgsm_exit (2);
        }
      return fp;
    }
  fp = es_fopen (filename, "wb");
  if (!fp)
    {
      log_error (_("can't open '%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fp;
}


static void
run_protect_tool (int argc, char **argv)
{
#ifdef HAVE_W32_SYSTEM
  (void)argc;
  (void)argv;
#else
  const char *pgm;
  char **av;
  int i;

  if (!opt.protect_tool_program || !*opt.protect_tool_program)
    pgm = gnupg_module_name (GNUPG_MODULE_NAME_PROTECT_TOOL);
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
  log_error ("error executing '%s': %s\n", pgm, strerror (errno));
#endif /*!HAVE_W32_SYSTEM*/
  gpgsm_exit (2);
}
