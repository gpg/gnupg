/* gpgsm.c - GnuPG for S/MIME 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#include <gcrypt.h>
#include "gpgsm.h"
#include "../assuan/assuan.h" /* malloc hooks */
#include "i18n.h"

enum cmd_and_opt_values {
  aNull = 0,
  oArmor	  = 'a',
  aDetachedSign = 'b',
  aSym	  = 'c',
  aDecrypt	  = 'd',
  aEncr	  = 'e',
  oInteractive  = 'i',
  oKOption	  = 'k',
  oDryRun	  = 'n',
  oOutput	  = 'o',
  oQuiet	  = 'q',
  oRecipient	  = 'r',
  aSign	  = 's',
  oTextmodeShort= 't',
  oUser	  = 'u',
  oVerbose	  = 'v',
  oCompress	  = 'z',
  oNotation	  = 'N',
  oBatch	  = 500,
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
  aListKeys,
  aListSigs,
  aListSecretKeys,
  aSendKeys,
  aRecvKeys,
  aExport,
  aExportAll,
  aCheckKeys,
  aServer,                        

  oTextmode,
  oFingerprint,
  oWithFingerprint,
  oAnswerYes,
  oAnswerNo,
  oKeyring,
  oSecretKeyring,
  oDefaultKey,
  oDefRecipient,
  oDefRecipientSelf,
  oNoDefRecipient,
  oOptions,
  oDebug,
  oDebugAll,
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
  oPasswdFD,
  oCommandFD,
  oNoVerbose,
  oTrustDBName,
  oNoSecmemWarn,
  oNoArmor,
  oNoDefKeyring,
  oNoGreeting,
  oNoTTY,
  oNoOptions,
  oNoBatch,
  oHomedir,
  oWithColons,
  oWithKeyData,
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
  aTest
 };


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

    { aSign, "sign",      256, N_("|[file]|make a signature")},
    { aClearsign, "clearsign", 256, N_("|[file]|make a clear text signature") },
    { aDetachedSign, "detach-sign", 256, N_("make a detached signature")},
    { aEncr, "encrypt",   256, N_("encrypt data")},
    { aSym, "symmetric", 256, N_("encryption only with symmetric cipher")},
    { aDecrypt, "decrypt",   256, N_("decrypt data (default)")},
    { aVerify, "verify"   , 256, N_("verify a signature")},
    { aVerifyFiles, "verify-files" , 256, "@" },
    { aListKeys, "list-keys", 256, N_("list keys")},
    { aListKeys, "list-public-keys", 256, "@" },
    { aListSigs, "list-sigs", 256, N_("list keys and signatures")},
    { aCheckKeys, "check-sigs",256, N_("check key signatures")},
    { oFingerprint, "fingerprint", 256, N_("list keys and fingerprints")},
    { aListSecretKeys, "list-secret-keys", 256, N_("list secret keys")},
    { aKeygen,	   "gen-key",  256, N_("generate a new key pair")},
    { aDeleteKey, "delete-key",256, N_("remove key from the public keyring")},
    { aExport, "export"           , 256, N_("export keys") },
    { aSendKeys, "send-keys"     , 256, N_("export keys to a key server") },
    { aRecvKeys, "recv-keys"     , 256, N_("import keys from a key server") },
    { aImport, "import",      256     , N_("import/merge keys")},
    { aServer, "server",      256, N_("run in server mode")},
    

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oArmor, "armor",     0, N_("create ascii armored output")},
    { oArmor, "armour",     0, "@" },
    { oRecipient, "recipient", 2, N_("|NAME|encrypt for NAME")},
    { oRecipient, "remote-user", 2, "@"},  /* old option name */
    { oDefRecipient, "default-recipient" ,2,
				  N_("|NAME|use NAME as default recipient")},
    { oDefRecipientSelf, "default-recipient-self" ,0,
				N_("use the default key as default recipient")},
    { oNoDefRecipient, "no-default-recipient", 0, "@" },
    { oEncryptTo, "encrypt-to", 2, "@" },
    { oNoEncryptTo, "no-encrypt-to", 0, "@" },
    { oUser, "local-user",2, N_("use this user-id to sign or decrypt")},
    { oCompress, NULL,	      1, N_("|N|set compress level N (0 disables)") },
    { oTextmodeShort, NULL,   0, "@"},
    { oTextmode, "textmode",  0, N_("use canonical text mode")},
    { oOutput, "output",    2, N_("use as output file")},
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",   0, N_("be somewhat more quiet") },
    { oNoTTY, "no-tty", 0, N_("don't use the terminal at all") },
    { oForceV3Sigs, "force-v3-sigs", 0, N_("force v3 signatures") },
    { oForceMDC, "force-mdc", 0, N_("always use a MDC for encryption") },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
  /*{ oInteractive, "interactive", 0, N_("prompt before overwriting") }, */
    { oUseAgent, "use-agent",0, N_("use the gpg-agent")},
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
    { oDebugAll, "debug-all" ,0, "@"},
    { oStatusFD, "status-fd" ,1, N_("|FD|write status info to this FD") },
    { oNoComment, "no-comment", 0,   "@"},
    { oCompletesNeeded, "completes-needed", 1, "@"},
    { oMarginalsNeeded, "marginals-needed", 1, "@"},
    { oMaxCertDepth,	"max-cert-depth", 1, "@" },
    { oTrustedKey, "trusted-key", 2, N_("|KEYID|ulimately trust this key")},
    { oLoadExtension, "load-extension" ,2, N_("|FILE|load extension module FILE")},
    { oRFC1991, "rfc1991",   0, N_("emulate the mode described in RFC1991")},
    { oOpenPGP, "openpgp", 0, N_("set all packet, cipher and digest options to OpenPGP behavior")},
    { oS2KMode, "s2k-mode",  1, N_("|N|use passphrase mode N")},
    { oS2KDigest, "s2k-digest-algo",2,
		N_("|NAME|use message digest algorithm NAME for passphrases")},
    { oS2KCipher, "s2k-cipher-algo",2,
		N_("|NAME|use cipher algorithm NAME for passphrases")},
    { oCipherAlgo, "cipher-algo", 2 , N_("|NAME|use cipher algorithm NAME")},
    { oDigestAlgo, "digest-algo", 2 , N_("|NAME|use message digest algorithm NAME")},
    { oCompressAlgo, "compress-algo", 1 , N_("|N|use compress algorithm N")},
    { oThrowKeyid, "throw-keyid", 0, N_("throw keyid field of encrypted packets")},
    { oNotation,   "notation-data", 2, N_("|NAME=VALUE|use this notation data")},

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
    { oTrustDBName, "trustdb-name", 2, "@" },
    { oNoSecmemWarn, "no-secmem-warning", 0, "@" }, /* used only by regression tests */
    { oNoArmor, "no-armor",   0, "@"},
    { oNoArmor, "no-armour",   0, "@"},
    { oNoDefKeyring, "no-default-keyring", 0, "@" },
    { oNoGreeting, "no-greeting", 0, "@" },
    { oNoOptions, "no-options", 0, "@" }, /* shortcut for --options /dev/null */
    { oHomedir, "homedir", 2, "@" },   /* defaults to "~/.gnupg" */
    { oNoBatch, "no-batch", 0, "@" },
    { oWithColons, "with-colons", 0, "@"},
    { oWithKeyData,"with-key-data", 0, "@"},
    { aListKeys, "list-key", 0, "@" }, /* alias */
    { aListSigs, "list-sig", 0, "@" }, /* alias */
    { aCheckKeys, "check-sig",0, "@" }, /* alias */
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

static int maybe_setuid = 1;

static char *build_list (const char *text,
			 const char *(*mapf)(int), int (*chkf)(int));
static void set_cmd (enum cmd_and_opt_values *ret_cmd,
                     enum cmd_and_opt_values new_cmd );


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
    case 19: p = _("Please report bugs to <bug-gnupg@gnu.org>.\n");
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
  set_gettext_file (PACKAGE);
#else
# ifdef ENABLE_NLS
#  ifdef HAVE_LC_MESSAGES
  setlocale (LC_TIME, "");
  setlocale (LC_MESSAGES, "");
#  else
  setlocale (LC_ALL, "" );
#  endif
  bindtextdomain (PACKAGE, GNUPG_LOCALEDIR);
  textdomain (PACKAGE);
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


static void
set_debug(void)
{
  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CIPHER_VALUE )
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
  int default_config =1;
  int default_keyring = 1;
  int greeting = 0;
  int nogreeting = 0;
  int use_random_seed = 1;
  int with_fpr = 0;
  char *def_cipher_string = NULL;
  char *def_digest_string = NULL;
  enum cmd_and_opt_values cmd = 0;

  /* FIXME: trap_unaligned ();*/
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to secmem_init()
     somewhere after the option parsing */
  /* FIXME: log_set_name ("gpgsm");*/
  /* check that the libraries are suitable.  Do it here because the
     option parse may need services of the library */
  if (!gcry_check_version ( "1.1.4" ) )
    {
      log_fatal( _("libgcrypt is too old (need %s, have %s)\n"),
                 VERSION, gcry_check_version (NULL) );
    }

  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = 0/* FIXME: disable_core_dumps()*/;
  
  /* FIXME: init_signals();*/
  
  create_dotlock (NULL); /* register locking cleanup */
  i18n_init();

#ifdef __MINGW32__
  opt.homedir = read_w32_registry_string ( NULL,
                                           "Software\\GNU\\GnuPG", "HomeDir" );
#else
  opt.homedir = getenv ("GNUPGHOME");
#endif
  if (!opt.homedir || !*opt.homedir ) 
    {
      opt.homedir = "~/.gnupg-test" /*fixme: GNUPG_HOMEDIR*/;
    }

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
    }
  
  
  /* initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /* 
     Now we are now working under our real uid 
  */

  assuan_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);
  /*  ksba_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free );*/

  if (default_config )
    configname = make_filename (opt.homedir, "gpgsm.conf", NULL);
  
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

  while (optfile_parse (configfp, configname, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case aServer: 
          opt.batch = 1;
          set_cmd (&cmd, aServer);
          break;

        case aCheckKeys: set_cmd (&cmd, aCheckKeys); break;
        case aImport: set_cmd (&cmd, aImport); break;
        case aSendKeys: set_cmd (&cmd, aSendKeys); break;
        case aRecvKeys: set_cmd (&cmd, aRecvKeys); break;
        case aExport: set_cmd (&cmd, aExport); break;
        case aListKeys: set_cmd (&cmd, aListKeys); break;

        case aDeleteKey:
          set_cmd (&cmd, aDeleteKey);
          greeting=1;
          break;

        case aDetachedSign:
          detached_sig = 1;
          set_cmd (&cmd, aSign ); 
          break;
          
        case aSym: set_cmd (&cmd, aSym); break;
        case aDecrypt: set_cmd (&cmd, aDecrypt); break;
        case aEncr: set_cmd (&cmd, aEncr); break;
        case aSign: set_cmd (&cmd, aSign );  break;
        case aKeygen: set_cmd (&cmd, aKeygen); greeting=1; break;
        case aClearsign: set_cmd (&cmd, aClearsign); break;
        case aVerify: set_cmd (&cmd, aVerify); break;

        case oArmor: opt.armor = 1; opt.no_armor=0; break;
        case oNoArmor: opt.no_armor=1; opt.armor=0; break;
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

        case oStatusFD: /* fixme: set_status_fd (pargs.r.ret_int );*/ break;
        case oLoggerFD: /* fixme: log_set_logfile (NULL, pargs.r.ret_int );*/ break;
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
        case oWithColons: opt.with_colons=':'; break;

        case oSkipVerify: opt.skip_verify=1; break;

        case oNoEncryptTo: /*fixme: opt.no_encrypt_to = 1;*/ break;
        case oEncryptTo: /* store the recipient in the second list */
          sl = add_to_strlist (&remusr, pargs.r.ret_str);
          sl->flags = 1;
          break;

        case oRecipient: /* store the recipient */
          add_to_strlist ( &remusr, pargs.r.ret_str);
          break;

        case oTextmodeShort: /*fixme:opt.textmode = 2;*/ break;
        case oTextmode: /*fixme:opt.textmode=1;*/  break;

        case oUser: /* store the local users */
          add_to_strlist ( &locusr, pargs.r.ret_str);
          break;

        case oNoSecmemWarn:
          gcry_control (GCRYCTL_DISABLE_SECMEM_WARN); 
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
          
        default: 
          pargs.err = configfp? 1:2; 
          break;
	}
    }

  if (configfp)
    {
      fclose (configfp);
      configfp = NULL;
      xfree (configname);
      configname = NULL;
      goto next_pass;
    }
  
  xfree (configname);
  configname = NULL;

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
  
/*FIXME    if (opt.batch) */
/*      tty_batchmode (1); */

  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  set_debug ();
  /* FIXME: should set filenames of libgcrypt explicitly
   * gpg_opt_homedir = opt.homedir; */

  /* must do this after dropping setuid, because string_to...
   * may try to load an module */
  if (def_cipher_string) 
    {
      opt.def_cipher_algo = gcry_cipher_map_name (def_cipher_string);
      xfree (def_cipher_string);
      def_cipher_string = NULL;
      if ( our_cipher_test_algo (opt.def_cipher_algo) )
        log_error (_("selected cipher algorithm is invalid\n"));
    }
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
  
  /* set the random seed file */
  if (use_random_seed) {
    char *p = make_filename (opt.homedir, "random_seed", NULL);
#if 0
#warning set_random_seed_file not yet available in Libgcrypt
    set_random_seed_file(p);
#endif
    xfree(p);
  }

  if (!cmd && opt.fingerprint && !with_fpr)
    set_cmd (&cmd, aListKeys);
  
#if 0 /* fixme */
  if (!nrings && default_keyring)  /* add default ring */
    add_keyblock_resource ("pubcerts.gpg", 0, 0);
  for (sl = nrings; sl; sl = sl->next)
    add_keyblock_resource( sl->d, 0, 0 );
#endif
  FREE_STRLIST(nrings);
  
  fname = argc? *argv : NULL;
  
  switch (cmd)
    {
    case aServer:
      gpgsm_server ();
      break;

    case aEncr: /* encrypt the given file */
#if 0
      if (argc > 1)
        wrong_args(_("--encrypt [filename]"));
      if ((rc = encode_crypt(fname,remusr)) )
        log_error ("%s: encryption failed: %s\n",
                   print_fname_stdin(fname), gpg_errstr(rc) );
      break;
#endif

    case aSign: /* sign the given file */
#if 0
      sl = NULL;
      if (detached_sig)
        { /* sign all files */
          for (; argc; argc--, argv++ )
            add_to_strlist ( &sl, *argv );
	}
      else
        {
          if (argc > 1 )
            wrong_args (_("--sign [filename]"));
          if (argc)
            {
              sl = xcalloc (1, sizeof *sl + strlen(fname));
              strcpy(sl->d, fname);
	    }
	}
      if ( (rc = sign_file( sl, detached_sig, locusr, 0, NULL, NULL)) )
        log_error ("signing failed: %s\n", gpg_errstr(rc) );
      free_strlist(sl);
#endif
      break;
        
    case aSignEncr: /* sign and encrypt the given file */
#if 0
      if (argc > 1)
        wrong_args(_("--sign --encrypt [filename]"));
      if (argc)
        {
          sl = xcalloc( 1, sizeof *sl + strlen(fname));
          strcpy(sl->d, fname);
        }
      else
        sl = NULL;

      if ( (rc = sign_file(sl, detached_sig, locusr, 1, remusr, NULL)) )
        log_error ("%s: sign+encrypt failed: %s\n",
                   print_fname_stdin(fname), gpg_errstr(rc) );
      free_strlist(sl);
#endif
      break;

    case aClearsign: /* make a clearsig */
#if 0
      if (argc > 1)
        wrong_args (_("--clearsign [filename]"));
      if ( (rc = clearsign_file(fname, locusr, NULL)) )
        log_error ("%s: clearsign failed: %s\n",
                   print_fname_stdin(fname), gpg_errstr(rc) );
#endif
      break;

    case aVerify:
/*        if ((rc = verify_signatures( argc, argv ) )) */
/*          log_error ("verify signatures failed: %s\n", gpg_errstr(rc) ); */
      break;

    case aVerifyFiles:
/*        if ((rc = verify_files( argc, argv ))) */
/*          log_error ("verify files failed: %s\n", gpg_errstr(rc) ); */
      break;

    case aDecrypt:
/*        if (argc > 1) */
/*          wrong_args (_("--decrypt [filename]")); */
/*        if ((rc = decrypt_message( fname ) )) */
/*          log_error ("decrypt_message failed: %s\n", gpg_errstr(rc) ); */
      break;

    case aDeleteKey:
      if (argc != 1)
        wrong_args(_("--delete-key user-id"));
/*        username = make_username (fname); */
/*        if( (rc = delete_key(username)) ) */
/*          log_error ("%s: delete key failed: %s\n", username, gpg_errstr(rc) ); */
/*        xfree(username); */
      break;

    case aListKeys:
      sl = NULL;
      for ( ; argc; argc--, argv++ )
        add_to_strlist (&sl, *argv);
/*        public_key_list( sl ); */
      free_strlist(sl);
      break;

    case aListSecretKeys:
      sl = NULL;
      for( ; argc; argc--, argv++ )
        add_to_strlist (&sl, *argv);
/*        secret_key_list ( sl ); */
      free_strlist(sl);
      break;

    case aKeygen: /* generate a key */
/*        if (opt.batch) */
/*          { */
/*            if (argc > 1) */
/*              wrong_args("--gen-key [parameterfile]"); */
/*            generate_keypair (argc? *argv : NULL); */
/*  	} */
/*        else */
/*          { */
/*            if (argc) */
/*              wrong_args ("--gen-key"); */
/*            generate_keypair(NULL); */
/*  	} */
      break;

    case aImport:
/*        import_keys (argc? argv:NULL, argc); */
      break;
      
    case aExport:
    case aSendKeys:
    case aRecvKeys:
/*        sl = NULL; */
/*        for ( ; argc; argc--, argv++ ) */
/*          add_to_strlist (&sl, *argv); */
/*        if ( cmd == aSendKeys ) */
/*          ldap_export (sl); */
/*        else if (cmd == aRecvKeys ) */
/*          ldap_import (sl); */
/*        else */
/*          export_pubkeys (sl, (cmd == aExport)); */
/*        free_strlist (sl); */
      break;

      default:
	if (argc > 1)
          wrong_args(_("[filename]"));
	/* Issue some output for the unix newbie */
	if ( !fname && !opt.outfile && isatty( fileno(stdin) )
            && isatty (fileno(stdout) ) && isatty (fileno(stderr) ) )
          log_info (_("Go ahead and type your message ...\n"));
        
#if 0
	if ( !(a = iobuf_open(fname)) )
          log_error (_("can't open `%s'\n"), print_fname_stdin(fname));
	else
          {
	    if (!opt.no_armor) 
              iobuf_close(a);
	}
#endif
	break;
    }
  
  /* cleanup */
  FREE_STRLIST(remusr);
  FREE_STRLIST(locusr);
  gpgsm_exit(0);
  return 8; /*NEVER REACHED*/
}


void
gpgsm_exit (int rc)
{
  #if 0
#warning no update_random_seed_file
  update_random_seed_file();
  #endif
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
  gcry_control (GCRYCTL_TERM_SECMEM );
  rc = rc? rc : log_get_errorcount(0)? 2 : gpgsm_errors_seen? 1 : 0;
  exit (rc);
}
