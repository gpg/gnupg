/* gpgsm.c - GnuPG for S/MIME
 * Copyright (C) 2001, 2002, 2003, 2004, 2005,
 *               2006, 2007, 2008  Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
/*#include <mcheck.h>*/

#include "gpgsm.h"
#include <gcrypt.h>
#include <assuan.h> /* malloc hooks */

#include "../kbx/keybox.h" /* malloc hooks */
#include "i18n.h"
#include "keydb.h"
#include "sysutils.h"
#include "gc-opt-flags.h"


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
  oFixedPassphrase,
  oLogFile,
  oNoLogFile,
  oAuditLog,
  oHtmlAuditLog,

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


  oAssumeArmor,
  oAssumeBase64,
  oAssumeBinary,

  oBase64,
  oNoArmor,
  oP12Charset,

  oDisableCRLChecks,
  oEnableCRLChecks,
  oDisableTrustedCertCRLCheck,
  oEnableTrustedCertCRLCheck,
  oForceCRLRefresh,

  oDisableOCSP,
  oEnableOCSP,

  oIncludeCerts,
  oPolicyFile,
  oDisablePolicyChecks,
  oEnablePolicyChecks,
  oAutoIssuerKeyRetrieve,

  oWithFingerprint,
  oWithMD5Fingerprint,
  oAnswerYes,
  oAnswerNo,
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
  oEncryptTo,
  oNoEncryptTo,
  oLoggerFD,
  oDisableCipherAlgo,
  oDisablePubkeyAlgo,
  oIgnoreTimeConflict,
  oNoRandomSeedFile,
  oNoCommonCertsImport,
  oIgnoreCertExtension
 };


static ARGPARSE_OPTS opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aSign, "sign", N_("make a signature")),
  ARGPARSE_c (aClearsign, "clearsign", N_("make a clear text signature") ),
  ARGPARSE_c (aDetachedSign, "detach-sign", N_("make a detached signature")),
  ARGPARSE_c (aEncr, "encrypt", N_("encrypt data")),
  ARGPARSE_c (aSym, "symmetric", N_("encryption only with symmetric cipher")),
  ARGPARSE_c (aDecrypt, "decrypt", N_("decrypt data (default)")),
  ARGPARSE_c (aVerify, "verify",  N_("verify a signature")),
  ARGPARSE_c (aListKeys, "list-keys", N_("list keys")),
  ARGPARSE_c (aListExternalKeys, "list-external-keys",
              N_("list external keys")),
  ARGPARSE_c (aListSecretKeys, "list-secret-keys", N_("list secret keys")),
  ARGPARSE_c (aListChain,   "list-chain",  N_("list certificate chain")),
  ARGPARSE_c (aFingerprint, "fingerprint", N_("list keys and fingerprints")),
  ARGPARSE_c (aKeygen, "gen-key", N_("generate a new key pair")),
  ARGPARSE_c (aDeleteKey, "delete-keys",
              N_("remove keys from the public keyring")),
  ARGPARSE_c (aSendKeys, "send-keys", N_("export keys to a key server")),
  ARGPARSE_c (aRecvKeys, "recv-keys", N_("import keys from a key server")),
  ARGPARSE_c (aImport, "import", N_("import certificates")),
  ARGPARSE_c (aExport, "export", N_("export certificates")),
  ARGPARSE_c (aExportSecretKeyP12, "export-secret-key-p12", "@"),
  ARGPARSE_c (aLearnCard, "learn-card", N_("register a smartcard")),
  ARGPARSE_c (aServer, "server", N_("run in server mode")),
  ARGPARSE_c (aCallDirmngr, "call-dirmngr",
              N_("pass a command to the dirmngr")),
  ARGPARSE_c (aCallProtectTool, "call-protect-tool",
              N_("invoke gpg-protect-tool")),
  ARGPARSE_c (aPasswd, "passwd", N_("change a passphrase")),
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_c (aDumpKeys, "dump-cert", "@"),
  ARGPARSE_c (aDumpKeys, "dump-keys", "@"),
  ARGPARSE_c (aDumpChain, "dump-chain", "@"),
  ARGPARSE_c (aDumpExternalKeys, "dump-external-keys", "@"),
  ARGPARSE_c (aDumpSecretKeys, "dump-secret-keys", "@"),
  ARGPARSE_c (aKeydbClearSomeCertFlags, "keydb-clear-some-cert-flags", "@"),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oArmor, "armor", N_("create ascii armored output")),
  ARGPARSE_s_n (oArmor, "armour", "@"),
  ARGPARSE_s_n (oBase64, "base64", N_("create base-64 encoded output")),

  ARGPARSE_s_s (oP12Charset, "p12-charset", "@"),

  ARGPARSE_s_n (oAssumeArmor, "assume-armor",
                N_("assume input is in PEM format")),
  ARGPARSE_s_n (oAssumeBase64, "assume-base64",
                N_("assume input is in base-64 format")),
  ARGPARSE_s_n (oAssumeBinary, "assume-binary",
                N_("assume input is in binary format")),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),

  ARGPARSE_s_n (oPreferSystemDirmngr,"prefer-system-dirmngr",
                N_("use system's dirmngr if available")),

  ARGPARSE_s_n (oDisableCRLChecks, "disable-crl-checks",
                N_("never consult a CRL")),
  ARGPARSE_s_n (oEnableCRLChecks, "enable-crl-checks", "@"),
  ARGPARSE_s_n (oDisableTrustedCertCRLCheck,
                "disable-trusted-cert-crl-check", "@"),
  ARGPARSE_s_n (oEnableTrustedCertCRLCheck,
                "enable-trusted-cert-crl-check", "@"),

  ARGPARSE_s_n (oForceCRLRefresh, "force-crl-refresh", "@"),

  ARGPARSE_s_n (oDisableOCSP, "disable-ocsp", "@"),
  ARGPARSE_s_n (oEnableOCSP,  "enable-ocsp", N_("check validity using OCSP")),

  ARGPARSE_s_s (oValidationModel, "validation-model", "@"),

  ARGPARSE_s_i (oIncludeCerts, "include-certs",
                N_("|N|number of certificates to include") ),

  ARGPARSE_s_s (oPolicyFile, "policy-file",
                N_("|FILE|take policy information from FILE")),

  ARGPARSE_s_n (oDisablePolicyChecks, "disable-policy-checks",
                N_("do not check certificate policies")),
  ARGPARSE_s_n (oEnablePolicyChecks, "enable-policy-checks", "@"),

  ARGPARSE_s_n (oAutoIssuerKeyRetrieve, "auto-issuer-key-retrieve",
                N_("fetch missing issuer certificates")),

  ARGPARSE_s_s (oEncryptTo, "encrypt-to", "@"),
  ARGPARSE_s_n (oNoEncryptTo, "no-encrypt-to", "@"),

  ARGPARSE_s_s (oUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),

  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),
  ARGPARSE_s_n (oNoTTY, "no-tty", N_("don't use the terminal at all")),
  ARGPARSE_s_s (oLogFile, "log-file",
                N_("|FILE|write a server mode log to FILE")),
  ARGPARSE_s_n (oNoLogFile, "no-log-file", "@"),
  ARGPARSE_s_i (oLoggerFD, "logger-fd", "@"),

  ARGPARSE_s_s (oAuditLog, "audit-log",
                N_("|FILE|write an audit log to FILE")),
  ARGPARSE_s_s (oHtmlAuditLog, "html-audit-log", "@"),
  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),
  ARGPARSE_s_n (oBatch, "batch", N_("batch mode: never ask")),
  ARGPARSE_s_n (oAnswerYes, "yes", N_("assume yes on most questions")),
  ARGPARSE_s_n (oAnswerNo,  "no",  N_("assume no on most questions")),

  ARGPARSE_s_s (oKeyring, "keyring",
                N_("|FILE|add keyring to the list of keyrings")),

  ARGPARSE_s_s (oDefaultKey, "default-key",
                N_("|USER-ID|use USER-ID as default secret key")),

  /* Not yet used: */
  /*   ARGPARSE_s_s (oDefRecipient, "default-recipient", */
  /*                  N_("|NAME|use NAME as default recipient")), */
  /*   ARGPARSE_s_n (oDefRecipientSelf, "default-recipient-self", */
  /*                  N_("use the default key as default recipient")), */
  /*   ARGPARSE_s_n (oNoDefRecipient, "no-default-recipient", "@"), */

  ARGPARSE_s_s (oKeyServer, "keyserver",
                N_("|SPEC|use this keyserver to lookup keys")),
  ARGPARSE_s_s (oOptions, "options", N_("|FILE|read options from FILE")),

  ARGPARSE_p_u (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level",
                N_("|LEVEL|set the debugging level to LEVEL")),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugNone, "debug-none", "@"),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_n (oDebugAllowCoreDump, "debug-allow-core-dump", "@"),
  ARGPARSE_s_n (oDebugNoChainValidation, "debug-no-chain-validation", "@"),
  ARGPARSE_s_n (oDebugIgnoreExpiration,  "debug-ignore-expiration", "@"),
  ARGPARSE_s_s (oFixedPassphrase, "fixed-passphrase", "@"),

  ARGPARSE_s_i (oStatusFD, "status-fd",
                N_("|FD|write status info to this FD")),

  ARGPARSE_s_s (oCipherAlgo, "cipher-algo",
                N_("|NAME|use cipher algorithm NAME")),
  ARGPARSE_s_s (oDigestAlgo, "digest-algo",
                N_("|NAME|use message digest algorithm NAME")),
  ARGPARSE_s_s (oExtraDigestAlgo, "extra-digest-algo", "@"),


  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
  )),

  ARGPARSE_group (303, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " --clearsign [file]         make a clear text signature\n"
    " --detach-sign [file]       make a detached signature\n"
    " --list-keys [names]        show keys\n"
    " --fingerprint [names]      show fingerprints\n"  )),

  /* Hidden options. */
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),
  ARGPARSE_s_n (oEnableSpecialFilenames, "enable-special-filenames", "@"),
  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armor", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armour", "@"),
  ARGPARSE_s_n (oNoDefKeyring, "no-default-keyring", "@"),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_s_n (oNoOptions, "no-options", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDisplay,    "display", "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname", "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype", "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages", "@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oDirmngrProgram, "dirmngr-program", "@"),
  ARGPARSE_s_n (oDisableDirmngr, "disable-dirmngr", "@"),
  ARGPARSE_s_s (oProtectToolProgram, "protect-tool-program", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_n (oNoBatch, "no-batch", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oWithKeyData,"with-key-data", "@"),
  ARGPARSE_s_n (oWithValidation, "with-validation", "@"),
  ARGPARSE_s_n (oWithMD5Fingerprint, "with-md5-fingerprint", "@"),
  ARGPARSE_s_n (oWithEphemeralKeys,  "with-ephemeral-keys", "@"),
  ARGPARSE_s_n (oSkipVerify, "skip-verify", "@"),
  ARGPARSE_s_n (oWithFingerprint, "with-fingerprint", "@"),
  ARGPARSE_s_s (oDisableCipherAlgo,  "disable-cipher-algo", "@"),
  ARGPARSE_s_s (oDisablePubkeyAlgo,  "disable-pubkey-algo", "@"),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),
  ARGPARSE_s_n (oNoCommonCertsImport, "no-common-certs-import", "@"),
  ARGPARSE_s_s (oIgnoreCertExtension, "ignore-cert-extension", "@"),

  /* Command aliases.  */
  ARGPARSE_c (aListKeys, "list-key", "@"),
  ARGPARSE_c (aListChain, "list-sig", "@"),
  ARGPARSE_c (aListChain, "list-sigs", "@"),
  ARGPARSE_c (aListChain, "check-sig", "@"),
  ARGPARSE_c (aListChain, "check-sigs", "@"),
  ARGPARSE_c (aDeleteKey, "delete-key", "@"),

  ARGPARSE_end ()
};




/* Global variable to keep an error count. */
int gpgsm_errors_seen = 0;

/* It is possible that we are currentlu running under setuid permissions */
static int maybe_setuid = 1;

/* Helper to implement --debug-level and --debug*/
static const char *debug_level;
static unsigned int debug_value;

/* Option --enable-special-filenames */
static int allow_special_filenames;

/* Default value for include-certs.  We need an extra macro for
   gpgconf-list because the variable will be changed by the command
   line option.  */
#define DEFAULT_INCLUDE_CERTS -2 /* Include all certs but root. */
static int default_include_certs = DEFAULT_INCLUDE_CERTS;

/* Whether the chain mode shall be used for validation.  */
static int default_validation_model;


static char *build_list (const char *text,
			 const char *(*mapf)(int), int (*chkf)(int));
static void set_cmd (enum cmd_and_opt_values *ret_cmd,
                     enum cmd_and_opt_values new_cmd );

static void emergency_cleanup (void);
static int check_special_filename (const char *fname, int for_write);
static int open_read (const char *filename);
static estream_t open_es_fread (const char *filename);
static FILE *open_fwrite (const char *filename);
static estream_t open_es_fwrite (const char *filename);
static void run_protect_tool (int argc, char **argv);

static int
our_pk_test_algo (int algo)
{
  switch (algo)
    {
    case GCRY_PK_RSA:
    case GCRY_PK_ECDSA:
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
    case 11: p = "gpgsm (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: gpgsm [options] [files] (-h for help)");
      break;
    case 41:
      p = _("Syntax: gpgsm [options] [files]\n"
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
    p = stpcpy(p, "\n" );
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
  fputs (_("usage: gpgsm [options] "), stderr);
  fputs (text, stderr);
  putc ('\n', stderr);
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
    opt.debug = DBG_ASSUAN_VALUE;
  else if (!strcmp (debug_level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_ASSUAN_VALUE|DBG_X509_VALUE;
  else if (!strcmp (debug_level, "expert")  || (numok && numlvl <= 8))
    opt.debug = (DBG_ASSUAN_VALUE|DBG_X509_VALUE
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
      log_error (_("invalid debug-level `%s' given\n"), debug_level);
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
    log_info ("enabled debug flags:%s%s%s%s%s%s%s%s\n",
              (opt.debug & DBG_X509_VALUE   )? " x509":"",
              (opt.debug & DBG_MPI_VALUE    )? " mpi":"",
              (opt.debug & DBG_CRYPTO_VALUE )? " crypto":"",
              (opt.debug & DBG_MEMORY_VALUE )? " memory":"",
              (opt.debug & DBG_CACHE_VALUE  )? " cache":"",
              (opt.debug & DBG_MEMSTAT_VALUE)? " memstat":"",
              (opt.debug & DBG_HASHING_VALUE)? " hashing":"",
              (opt.debug & DBG_ASSUAN_VALUE )? " assuan":"" );
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
          log_error ("can't encrypt to `%s': %s\n", name, gpg_strerror (rc));
          gpgsm_status2 (ctrl, STATUS_INV_RECP,
                         get_inv_recpsgnr_code (rc), name, NULL);
        }
      else
        log_info (_("NOTE: won't be able to encrypt to `%s': %s\n"),
                  name, gpg_strerror (rc));
    }
}


static void
parse_validation_model (const char *model)
{
  int i = gpgsm_parse_validation_model (model);
  if (i == -1)
    log_error (_("unknown validation model `%s'\n"), model);
  else
    default_validation_model = i;
}


/* Release the list of SERVERS.  As usual it is okay to call this
   function with SERVERS passed as NULL.  */
void
keyserver_list_free (struct keyserver_spec *servers)
{
  while (servers)
    {
      struct keyserver_spec *tmp = servers->next;
      xfree (servers->host);
      xfree (servers->user);
      if (servers->pass)
        memset (servers->pass, 0, strlen (servers->pass));
      xfree (servers->pass);
      xfree (servers->base);
      xfree (servers);
      servers = tmp;
    }
}

/* See also dirmngr ldapserver_parse_one().  */
struct keyserver_spec *
parse_keyserver_line (char *line,
		      const char *filename, unsigned int lineno)
{
  char *p;
  char *endp;
  struct keyserver_spec *server;
  int fieldno;
  int fail = 0;

  /* Parse the colon separated fields.  */
  server = xcalloc (1, sizeof *server);
  for (fieldno = 1, p = line; p; p = endp, fieldno++ )
    {
      endp = strchr (p, ':');
      if (endp)
	*endp++ = '\0';
      trim_spaces (p);
      switch (fieldno)
	{
	case 1:
	  if (*p)
	    server->host = xstrdup (p);
	  else
	    {
	      log_error (_("%s:%u: no hostname given\n"),
			 filename, lineno);
	      fail = 1;
	    }
	  break;

	case 2:
	  if (*p)
	    server->port = atoi (p);
	  break;

	case 3:
	  if (*p)
	    server->user = xstrdup (p);
	  break;

	case 4:
	  if (*p && !server->user)
	    {
	      log_error (_("%s:%u: password given without user\n"),
			 filename, lineno);
	      fail = 1;
	    }
	  else if (*p)
	    server->pass = xstrdup (p);
	  break;

	case 5:
	  if (*p)
	    server->base = xstrdup (p);
	  break;

	default:
	  /* (We silently ignore extra fields.) */
	  break;
	}
    }

  if (fail)
    {
      log_info (_("%s:%u: skipping this line\n"), filename, lineno);
      keyserver_list_free (server);
    }

  return server;
}


int
main ( int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  /*  char *username;*/
  int may_coredump;
  strlist_t sl, remusr= NULL, locusr=NULL;
  strlist_t nrings=NULL;
  int detached_sig = 0;
  FILE *configfp = NULL;
  char *configname = NULL;
  unsigned configlineno;
  int parse_debug = 0;
  int no_more_options = 0;
  int default_config =1;
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

  /*mtrace();*/

  gnupg_reopen_std ("gpgsm");
  /* trap_unaligned ();*/
  gnupg_rl_initialize ();
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* We don't need any locking in libgcrypt unless we use any kind of
     threading. */
  gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING);

  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to secmem_init()
     somewhere after the option parsing */
  log_set_prefix ("gpgsm", 1);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems ();

  /* Check that the libraries are suitable.  Do it here because the
     option parse may need services of the library */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    log_fatal (_("%s is too old (need %s, have %s)\n"), "libgcrypt",
               NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
  if (!ksba_check_version (NEED_KSBA_VERSION) )
    log_fatal (_("%s is too old (need %s, have %s)\n"), "libksba",
               NEED_KSBA_VERSION, ksba_check_version (NULL) );


  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  gnupg_init_signals (0, emergency_cleanup);

  create_dotlock (NULL); /* register locking cleanup */

  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

  /* Note: If you change this default cipher algorithm , please
     remember to update the Gpgconflist entry as well.  */
  opt.def_cipher_algoid = "3DES";  /*des-EDE3-CBC*/

  opt.homedir = default_homedir ();

  /* First check whether we have a config file on the commandline */
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
  assuan_set_assuan_log_prefix (log_get_prefix (NULL));
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);

  keybox_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);

  /* Setup a default control structure for command line mode */
  memset (&ctrl, 0, sizeof ctrl);
  gpgsm_init_default_ctrl (&ctrl);
  ctrl.no_server = 1;
  ctrl.status_fd = -1; /* No status output. */
  ctrl.autodetect_encoding = 1;

  /* Set the default option file */
  if (default_config )
    configname = make_filename (opt.homedir, "gpgsm.conf", NULL);
  /* Set the default policy file */
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
	case aGPGConfTest:
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

        case aImport:
        case aSendKeys:
        case aRecvKeys:
        case aExport:
        case aExportSecretKeyP12:
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

        case oDebug: debug_value |= pargs.r.ret_ulong; break;
        case oDebugAll: debug_value = ~0; break;
        case oDebugNone: debug_value = 0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: debug_wait = pargs.r.ret_int; break;
        case oDebugAllowCoreDump:
          may_coredump = enable_core_dumps ();
          break;
        case oDebugNoChainValidation: opt.no_chain_validation = 1; break;
        case oDebugIgnoreExpiration: opt.ignore_expiration = 1; break;
        case oFixedPassphrase: opt.fixed_passphrase = pargs.r.ret_str; break;

        case oStatusFD: ctrl.status_fd = pargs.r.ret_int; break;
        case oLoggerFD: log_set_fd (pargs.r.ret_int ); break;
        case oWithMD5Fingerprint:
          opt.with_md5_fingerprint=1; /*fall thru*/
        case oWithFingerprint:
          with_fpr=1; /*fall thru*/
        case aFingerprint:
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

        case oDirmngrProgram: opt.dirmngr_program = pargs.r.ret_str;  break;
        case oDisableDirmngr: opt.disable_dirmngr = 1;  break;
        case oPreferSystemDirmngr: opt.prefer_system_dirmngr = 1; break;
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

        case oWithKeyData: opt.with_key_data=1; /* fall thru */
        case oWithColons: ctrl.with_colons = 1; break;
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

        case oEnableSpecialFilenames: allow_special_filenames =1; break;

        case oValidationModel: parse_validation_model (pargs.r.ret_str); break;

	case oKeyServer:
	  {
	    struct keyserver_spec *keyserver;
	    keyserver = parse_keyserver_line (pargs.r.ret_str,
					      configname, configlineno);
	    if (! keyserver)
	      log_error (_("could not parse keyserver\n"));
	    else
	      {
		/* FIXME: Keep last next pointer.  */
		struct keyserver_spec **next_p = &opt.keyserver;
		while (*next_p)
		  next_p = &(*next_p)->next;
		*next_p = keyserver;
	      }
	  }
	  break;

        case oIgnoreCertExtension:
          add_to_strlist (&opt.ignored_cert_extensions, pargs.r.ret_str);
          break;

        default:
          pargs.err = configfp? ARGPARSE_PRINT_WARNING:ARGPARSE_PRINT_ERROR;
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

  /* Now that we have the options parsed we need to update the default
     control structure.  */
  gpgsm_init_default_ctrl (&ctrl);

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

/*   if (opt.qualsig_approval && !opt.quiet) */
/*     log_info (_("This software has offically been approved to " */
/*                 "create and verify\n" */
/*                 "qualified signatures according to German law.\n")); */

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
      dump_isotime (tbuf);
      log_printf ("\n");
    }

/*FIXME    if (opt.batch) */
/*      tty_batchmode (1); */

  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  set_debug ();

  /* Although we alwasy use gpgsm_exit, we better install a regualr
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
  else if (!strcmp (opt.def_cipher_algoid, "AES256") )
    opt.def_cipher_algoid = "2.16.840.1.101.3.4.1.42";
  else if (!strcmp (opt.def_cipher_algoid, "SERPENT")
           || !strcmp (opt.def_cipher_algoid, "SERPENT128") )
    opt.def_cipher_algoid = "1.3.6.1.4.1.11591.13.2.2";
  else if (!strcmp (opt.def_cipher_algoid, "SERPENT192") )
    opt.def_cipher_algoid = "1.3.6.1.4.1.11591.13.2.22";
  else if (!strcmp (opt.def_cipher_algoid, "SERPENT192") )
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

  if (log_get_errorcount(0))
    gpgsm_exit(2);

  /* Set the random seed file. */
  if (use_random_seed)
    {
      char *p = make_filename (opt.homedir, "random_seed", NULL);
      gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
      xfree(p);
    }

  if (!cmd && opt.fingerprint && !with_fpr)
    set_cmd (&cmd, aListKeys);

  /* Add default keybox. */
  if (!nrings && default_keyring)
    {
      int created;

      keydb_add_resource ("pubring.kbx", 0, 0, &created);
      if (created && !no_common_certs_import)
        {
          /* Import the standard certificates for a new default keybox. */
          char *filelist[2];

          filelist[0] = make_filename (gnupg_datadir (),"com-certs.pem", NULL);
          filelist[1] = NULL;
          if (!access (filelist[0], F_OK))
            {
              log_info (_("importing common certificates `%s'\n"),
                        filelist[0]);
              gpgsm_import_files (&ctrl, 1, filelist, open_read);
            }
          xfree (filelist[0]);
        }
    }
  for (sl = nrings; sl; sl = sl->next)
    keydb_add_resource (sl->d, 0, 0, NULL);
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
      for (sl = locusr; sl ; sl = sl->next)
        {
          int rc = gpgsm_add_to_certlist (&ctrl, sl->d, 1, &signerlist, 0);
          if (rc)
            {
              log_error (_("can't sign using `%s': %s\n"),
                         sl->d, gpg_strerror (rc));
              gpgsm_status2 (&ctrl, STATUS_INV_SGNR,
                             get_inv_recpsgnr_code (rc), sl->d, NULL);
              gpgsm_status2 (&ctrl, STATUS_INV_RECP,
                             get_inv_recpsgnr_code (rc), sl->d, NULL);
            }
        }

      /* Build the recipient list.  We first add the regular ones and then
         the encrypt-to ones because the underlying function will silently
         ignore duplicates and we can't allow to keep a duplicate which is
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
    }

  if (log_get_errorcount(0))
    gpgsm_exit(1); /* Must stop for invalid recipients. */

  /* Dispatch command.  */
  switch (cmd)
    {
    case aGPGConfList:
      { /* List options and default values in the GPG Conf format.  */
	char *config_filename_esc = percent_escape (opt.config_filename, NULL);

        printf ("gpgconf-gpgsm.conf:%lu:\"%s\n",
                GC_OPT_FLAG_DEFAULT, config_filename_esc);
        xfree (config_filename_esc);

        printf ("verbose:%lu:\n", GC_OPT_FLAG_NONE);
	printf ("quiet:%lu:\n", GC_OPT_FLAG_NONE);
	printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
	printf ("log-file:%lu:\n", GC_OPT_FLAG_NONE);
        printf ("disable-crl-checks:%lu:\n", GC_OPT_FLAG_NONE);
        printf ("disable-trusted-cert-crl-check:%lu:\n", GC_OPT_FLAG_NONE);
        printf ("enable-ocsp:%lu:\n", GC_OPT_FLAG_NONE);
        printf ("include-certs:%lu:%d:\n", GC_OPT_FLAG_DEFAULT,
                DEFAULT_INCLUDE_CERTS);
        printf ("disable-policy-checks:%lu:\n", GC_OPT_FLAG_NONE);
        printf ("auto-issuer-key-retrieve:%lu:\n", GC_OPT_FLAG_NONE);
        printf ("disable-dirmngr:%lu:\n", GC_OPT_FLAG_NONE);
#ifndef HAVE_W32_SYSTEM
        printf ("prefer-system-dirmngr:%lu:\n", GC_OPT_FLAG_NONE);
#endif
        printf ("cipher-algo:%lu:\"3DES:\n", GC_OPT_FLAG_DEFAULT);
        printf ("p12-charset:%lu:\n", GC_OPT_FLAG_DEFAULT);
        printf ("default-key:%lu:\n", GC_OPT_FLAG_DEFAULT);
        printf ("encrypt-to:%lu:\n", GC_OPT_FLAG_DEFAULT);
	printf ("keyserver:%lu:\n", GC_OPT_FLAG_NONE);

        /* The next one is an info only item and should match what
           proc_parameters actually implements.  */
        printf ("default_pubkey_algo:%lu:\"%s:\n", GC_OPT_FLAG_DEFAULT,
                "RSA-2048");
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
        FILE *fp = open_fwrite (opt.outfile?opt.outfile:"-");

        set_binary (stdin);

        if (!argc) /* Source is stdin. */
          gpgsm_encrypt (&ctrl, recplist, 0, fp);
        else if (argc == 1)  /* Source is the given file. */
          gpgsm_encrypt (&ctrl, recplist, open_read (*argv), fp);
        else
          wrong_args ("--encrypt [datafile]");

        if (fp != stdout)
          fclose (fp);
      }
      break;

    case aSign: /* Sign the given file. */
      {
        FILE *fp = open_fwrite (opt.outfile?opt.outfile:"-");

        /* Fixme: We should also allow to concatenate multiple files for
           signing because that is what gpg does.*/
        set_binary (stdin);
        if (!argc) /* Create from stdin. */
          gpgsm_sign (&ctrl, signerlist, 0, detached_sig, fp);
        else if (argc == 1) /* From file. */
          gpgsm_sign (&ctrl, signerlist,
                      open_read (*argv), detached_sig, fp);
        else
          wrong_args ("--sign [datafile]");

        if (fp != stdout)
          fclose (fp);
      }
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

        set_binary (stdin);
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

    case aDecrypt:
      {
        FILE *fp = open_fwrite (opt.outfile?opt.outfile:"-");

        set_binary (stdin);
        if (!argc)
          gpgsm_decrypt (&ctrl, 0, fp); /* from stdin */
        else if (argc == 1)
          gpgsm_decrypt (&ctrl, open_read (*argv), fp); /* from file */
        else
          wrong_args ("--decrypt [filename]");
        if (fp != stdout)
          fclose (fp);
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
       ctrl.with_chain = 1;
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


    case aKeygen: /* Generate a key; well kind of. */
      {
        estream_t fpin = NULL;
        FILE *fpout;

        if (opt.batch)
          {
            if (!argc) /* Create from stdin. */
              fpin = open_es_fread ("-");
            else if (argc == 1) /* From file. */
              fpin = open_es_fread (*argv);
            else
              wrong_args ("--gen-key --batch [parmfile]");
          }

        fpout = open_fwrite (opt.outfile?opt.outfile:"-");

        if (fpin)
          gpgsm_genkey (&ctrl, fpin, fpout);
        else
          gpgsm_gencertreq_tty (&ctrl, fpout);

        if (fpout != stdout)
          fclose (fpout);
      }
      break;


    case aImport:
      gpgsm_import_files (&ctrl, argc, argv, open_read);
      break;

    case aExport:
      {
        FILE *fp = open_fwrite (opt.outfile?opt.outfile:"-");

        for (sl=NULL; argc; argc--, argv++)
          add_to_strlist (&sl, *argv);
        gpgsm_export (&ctrl, sl, fp, NULL);
        free_strlist(sl);
        if (fp != stdout)
          fclose (fp);
      }
      break;

    case aExportSecretKeyP12:
      {
        FILE *fp = open_fwrite (opt.outfile?opt.outfile:"-");

        if (argc == 1)
          gpgsm_p12_export (&ctrl, *argv, fp);
        else
          wrong_args ("--export-secret-key-p12 KEY-ID");
        if (fp != stdout)
          fclose (fp);
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
        wrong_args ("--passwd <key-Id>");
      else
        {
          int rc;
          ksba_cert_t cert = NULL;
          char *grip = NULL;

          rc = gpgsm_find_cert (*argv, NULL, &cert);
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
  keyserver_list_free (opt.keyserver);
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
}


int
gpgsm_parse_validation_model (const char *model)
{
  if (!ascii_strcasecmp (model, "shell") )
    return 0;
  else if ( !ascii_strcasecmp (model, "chain") )
    return 1;
  else
    return -1;
}


/* Check whether the filename has the form "-&nnnn", where n is a
   non-zero number.  Returns this number or -1 if it is not the case.  */
static int
check_special_filename (const char *fname, int for_write)
{
  if (allow_special_filenames
      && fname && *fname == '-' && fname[1] == '&' ) {
    int i;

    fname += 2;
    for (i=0; isdigit (fname[i]); i++ )
      ;
    if ( !fname[i] )
      return translate_sys2libc_fd_int (atoi (fname), for_write);
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
    {
      set_binary (stdin);
      return 0; /* stdin */
    }
  fd = check_special_filename (filename, 0);
  if (fd != -1)
    return fd;
  fd = open (filename, O_RDONLY | O_BINARY);
  if (fd == -1)
    {
      log_error (_("can't open `%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fd;
}

/* Same as open_read but return an estream_t.  */
static estream_t
open_es_fread (const char *filename)
{
  int fd;
  estream_t fp;

  if (filename[0] == '-' && !filename[1])
    fd = fileno (stdin);
  else
    fd = check_special_filename (filename, 0);
  if (fd != -1)
    {
      fp = es_fdopen_nc (fd, "rb");
      if (!fp)
        {
          log_error ("es_fdopen(%d) failed: %s\n", fd, strerror (errno));
          gpgsm_exit (2);
        }
      return fp;
    }
  fp = es_fopen (filename, "rb");
  if (!fp)
    {
      log_error (_("can't open `%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fp;
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
    {
      set_binary (stdout);
      return stdout;
    }

  fd = check_special_filename (filename, 1);
  if (fd != -1)
    {
      fp = fdopen (dup (fd), "wb");
      if (!fp)
        {
          log_error ("fdopen(%d) failed: %s\n", fd, strerror (errno));
          gpgsm_exit (2);
        }
      set_binary (fp);
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

  fd = check_special_filename (filename, 1);
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
      log_error (_("can't open `%s': %s\n"), filename, strerror (errno));
      gpgsm_exit (2);
    }
  return fp;
}


static void
run_protect_tool (int argc, char **argv)
{
#ifndef HAVE_W32_SYSTEM
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
  log_error ("error executing `%s': %s\n", pgm, strerror (errno));
#endif /*HAVE_W32_SYSTEM*/
  gpgsm_exit (2);
}
