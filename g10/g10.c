/* g10.c - The GnuPG utility (main for gpg)
 * Copyright (C) 1998,1999,2000,2001,2002 Free Software Foundation, Inc.
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
#ifdef HAVE_DOSISH_SYSTEM
  #include <fcntl.h> /* for setmode() */
#endif
#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "mpi.h"
#include "cipher.h"
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"
#include "status.h"
#include "g10defs.h"
#include "keyserver-internal.h"
#include "exec.h"

enum cmd_and_opt_values { aNull = 0,
    oArmor	  = 'a',
    aDetachedSign = 'b',
    aSym	  = 'c',
    aDecrypt	  = 'd',
    aEncr	  = 'e',
    aEncrFiles,
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
    oSigNotation,
    oCertNotation,
    oShowNotation,
    oNoShowNotation,
    aDecryptFiles,                          
    aClearsign,
    aStore,
    aKeygen,
    aSignEncr,
    aSignSym,
    aSignKey,
    aLSignKey,
    aNRSignKey,
    aNRLSignKey,
    aListPackets,
    aEditKey,
    aDeleteKeys,
    aDeleteSecretKeys,
    aDeleteSecretAndPublicKeys,
    aKMode,
    aKModeC,
    aImport,
    aFastImport,
    aVerify,
    aVerifyFiles,
    aListKeys,
    aListSigs,
    aListSecretKeys,
    aSendKeys,
    aRecvKeys,
    aSearchKeys,
    aExport,
    aExportAll,
    aExportSecret,
    aExportSecretSub,
    aCheckKeys,
    aGenRevoke,
    aDesigRevoke,
    aPrimegen,
    aPrintMD,
    aPrintMDs,
    aCheckTrustDB,
    aUpdateTrustDB,
    aFixTrustDB,
    aListTrustDB,
    aListTrustPath,
    aExportOwnerTrust,
    aImportOwnerTrust,
    aDeArmor,
    aEnArmor,
    aGenRandom,
    aPipeMode,
    aRebuildKeydbCaches,
    aRefreshKeys,

    oTextmode,
    oExpert,
    oNoExpert,
    oAskSigExpire,
    oNoAskSigExpire,
    oAskCertExpire,
    oNoAskCertExpire,
    oFingerprint,
    oWithFingerprint,
    oAnswerYes,
    oAnswerNo,
    oDefCertCheckLevel,
    oKeyring,
    oSecretKeyring,
    oShowKeyring,
    oDefaultKey,
    oDefRecipient,
    oDefRecipientSelf,
    oNoDefRecipient,
    oOptions,
    oDebug,
    oDebugAll,
    oStatusFD,
#ifdef __riscos__
    oStatusFile,
#endif /* __riscos__ */
    oAttributeFD,
#ifdef __riscos__
    oAttributeFile,
#endif /* __riscos__ */
    oSKComments,
    oNoSKComments,
    oNoVersion,
    oEmitVersion,
    oCompletesNeeded,
    oMarginalsNeeded,
    oMaxCertDepth,
    oLoadExtension,
    oRFC1991,
    oOpenPGP,
    oPGP2,
    oNoPGP2,
    oPGP6,
    oNoPGP6,
    oPGP7,
    oNoPGP7,
    oCipherAlgo,
    oDigestAlgo,
    oCertDigestAlgo,
    oCompressAlgo,
    oPasswdFD,
#ifdef __riscos__
    oPasswdFile,
#endif /* __riscos__ */
    oCommandFD,
#ifdef __riscos__
    oCommandFile,
#endif /* __riscos__ */
    oQuickRandom,
    oNoVerbose,
    oTrustDBName,
    oNoSecmemWarn,
    oNoPermissionWarn,
    oNoMDCWarn,
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
    oEmuChecksumBug,
    oRunAsShmCP,
    oSetFilename,
    oForYourEyesOnly,
    oNoForYourEyesOnly,
    oSetPolicyURL,
    oSigPolicyURL,
    oCertPolicyURL,
    oShowPolicyURL,
    oNoShowPolicyURL,
    oUseEmbeddedFilename,
    oComment,
    oDefaultComment,
    oThrowKeyid,
    oShowPhotos,
    oNoShowPhotos,
    oPhotoViewer,
    oForceV3Sigs,
    oNoForceV3Sigs,
    oForceV4Certs,
    oNoForceV4Certs,
    oForceMDC,
    oNoForceMDC,
    oDisableMDC,
    oNoDisableMDC,
    oS2KMode,
    oS2KDigest,
    oS2KCipher,
    oSimpleSKChecksum,                          
    oCharset,
    oNotDashEscaped,
    oEscapeFrom,
    oNoEscapeFrom,
    oLockOnce,
    oLockMultiple,
    oLockNever,
    oKeyServer,
    oKeyServerOptions,
    oImportOptions,
    oExportOptions,
    oTempDir,
    oExecPath,
    oEncryptTo,
    oNoEncryptTo,
    oLoggerFD,
#ifdef __riscos__
    oLoggerFile,
#endif /* __riscos__ */
    oUtf8Strings,
    oNoUtf8Strings,
    oDisableCipherAlgo,
    oDisablePubkeyAlgo,
    oAllowNonSelfsignedUID,
    oNoAllowNonSelfsignedUID,
    oAllowFreeformUID,
    oNoAllowFreeformUID,
    oAllowSecretKeyImport,                      
    oEnableSpecialFilenames,
    oNoLiteral,
    oSetFilesize,
    oHonorHttpProxy,
    oFastListMode,
    oListOnly,
    oIgnoreTimeConflict,
    oIgnoreValidFrom,
    oIgnoreCrcError,
    oIgnoreMDCError,
    oShowSessionKey,
    oOverrideSessionKey,
    oNoRandomSeedFile,
    oAutoKeyRetrieve,
    oNoAutoKeyRetrieve,
    oUseAgent,
    oNoUseAgent,
    oGpgAgentInfo,
    oMergeOnly,
    oTryAllSecrets,
    oTrustedKey,
    oNoExpensiveTrustChecks,
    oFixedListMode,
    oNoSigCache,
    oNoSigCreateCheck,
    oAutoCheckTrustDB,
    oNoAutoCheckTrustDB,
    oPreservePermissions,
    oDefaultPreferenceList,
    oPersonalCipherPreferences,
    oPersonalDigestPreferences,
    oPersonalCompressPreferences,
    oEmuMDEncodeBug,
    oDisplay,
    oTTYname,
    oTTYtype,
    oLCctype,
    oLCmessages,
    oGroup,
aTest };


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

    { aSign, "sign",      256, N_("|[file]|make a signature")},
    { aClearsign, "clearsign", 256, N_("|[file]|make a clear text signature") },
    { aDetachedSign, "detach-sign", 256, N_("make a detached signature")},
    { aEncr, "encrypt",   256, N_("encrypt data")},
    { aEncrFiles, "encrypt-files", 256, N_("|[files]|encrypt files")},
    { aSym, "symmetric", 256, N_("encryption only with symmetric cipher")},
    { aStore, "store",     256, N_("store only")},
    { aDecrypt, "decrypt",   256, N_("decrypt data (default)")},
    { aDecryptFiles, "decrypt-files", 256, N_("|[files]|decrypt files")},
    { aVerify, "verify"   , 256, N_("verify a signature")},
    { aVerifyFiles, "verify-files" , 256, "@" },
    { aListKeys, "list-keys", 256, N_("list keys")},
    { aListKeys, "list-public-keys", 256, "@" },
    { aListSigs, "list-sigs", 256, N_("list keys and signatures")},
    { aCheckKeys, "check-sigs",256, N_("check key signatures")},
    { oFingerprint, "fingerprint", 256, N_("list keys and fingerprints")},
    { aListSecretKeys, "list-secret-keys", 256, N_("list secret keys")},
    { aKeygen,	   "gen-key",  256, N_("generate a new key pair")},
    { aDeleteKeys,"delete-keys",256,N_("remove keys from the public keyring")},
    { aDeleteSecretKeys, "delete-secret-keys",256,
				    N_("remove keys from the secret keyring")},
    { aSignKey,  "sign-key"   ,256, N_("sign a key")},
    { aLSignKey, "lsign-key"  ,256, N_("sign a key locally")},
    { aNRSignKey, "nrsign-key"  ,256, N_("sign a key non-revocably")},
    { aNRLSignKey, "nrlsign-key"  ,256, N_("sign a key locally and non-revocably")},
    { aEditKey,  "edit-key"   ,256, N_("sign or edit a key")},
    { aGenRevoke, "gen-revoke",256, N_("generate a revocation certificate")},
    { aDesigRevoke, "desig-revoke",256, "@" },
    { aExport, "export"           , 256, N_("export keys") },
    { aSendKeys, "send-keys"     , 256, N_("export keys to a key server") },
    { aRecvKeys, "recv-keys"     , 256, N_("import keys from a key server") },
    { aSearchKeys, "search-keys" , 256,
                                    N_("search for keys on a key server") },
    { aRefreshKeys, "refresh-keys", 256,
                                    N_("update all keys from a keyserver")},
    { aExportAll, "export-all"    , 256, "@" },
    { aExportSecret, "export-secret-keys" , 256, "@" },
    { aExportSecretSub, "export-secret-subkeys" , 256, "@" },
    { aImport, "import",      256     , N_("import/merge keys")},
    { aFastImport, "fast-import",  256 , "@"},
    { aListPackets, "list-packets",256,N_("list only the sequence of packets")},
    { aExportOwnerTrust,
	      "export-ownertrust", 256, N_("export the ownertrust values")},
    { aImportOwnerTrust,
	      "import-ownertrust", 256 , N_("import ownertrust values")},
    { aUpdateTrustDB,
	      "update-trustdb",0 , N_("update the trust database")},
    { aCheckTrustDB,
	      "check-trustdb",0 , N_("unattended trust database update")},
    { aFixTrustDB, "fix-trustdb",0 , N_("fix a corrupted trust database")},
    { aDeArmor, "dearmor", 256, N_("De-Armor a file or stdin") },
    { aDeArmor, "dearmour", 256, "@" },
    { aEnArmor, "enarmor", 256, N_("En-Armor a file or stdin") },
    { aEnArmor, "enarmour", 256, "@" },
    { aPrintMD,  "print-md" , 256, N_("|algo [files]|print message digests")},
    { aPrimegen, "gen-prime" , 256, "@" },
    { aGenRandom, "gen-random" , 256, "@" },

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
    { oTempDir, "temp-directory", 2, "@" },
    { oExecPath, "exec-path", 2, "@" },
    { oEncryptTo, "encrypt-to", 2, "@" },
    { oNoEncryptTo, "no-encrypt-to", 0, "@" },
    { oUser, "local-user",2, N_("use this user-id to sign or decrypt")},
    { oCompress, NULL,	      1, N_("|N|set compress level N (0 disables)") },
    { oTextmodeShort, NULL,   0, "@"},
    { oTextmode, "textmode",  0, N_("use canonical text mode")},
    { oExpert, "expert",   0, "@"},
    { oNoExpert, "no-expert",   0, "@"},
    { oAskSigExpire, "ask-sig-expire",   0, "@"},
    { oNoAskSigExpire, "no-ask-sig-expire",   0, "@"},
    { oAskCertExpire, "ask-cert-expire",   0, "@"},
    { oNoAskCertExpire, "no-ask-cert-expire",   0, "@"},
    { oOutput, "output",    2, N_("use as output file")},
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",   0, N_("be somewhat more quiet") },
    { oNoTTY, "no-tty", 0, N_("don't use the terminal at all") },
    { oForceV3Sigs, "force-v3-sigs", 0, N_("force v3 signatures") },
    { oNoForceV3Sigs, "no-force-v3-sigs", 0, N_("do not force v3 signatures") },
    { oForceV4Certs, "force-v4-certs", 0, N_("force v4 key signatures") },
    { oNoForceV4Certs, "no-force-v4-certs", 0, N_("do not force v4 key signatures") },
    { oForceMDC, "force-mdc", 0, N_("always use a MDC for encryption") },
    { oNoForceMDC, "no-force-mdc", 0, "@" },
    { oDisableMDC, "disable-mdc", 0, N_("never use a MDC for encryption") },
    { oNoDisableMDC, "no-disable-mdc", 0, "@" },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
    { oInteractive, "interactive", 0, N_("prompt before overwriting") },
    { oUseAgent, "use-agent",0, N_("use the gpg-agent")},
    { oNoUseAgent, "no-use-agent",0, "@"},
    { oGpgAgentInfo, "gpg-agent-info",2, "@"},
    { oBatch, "batch",     0, N_("batch mode: never ask")},
    { oAnswerYes, "yes",       0, N_("assume yes on most questions")},
    { oAnswerNo,  "no",        0, N_("assume no on most questions")},
    { oKeyring, "keyring"   ,2, N_("add this keyring to the list of keyrings")},
    { oSecretKeyring, "secret-keyring" ,2, N_("add this secret keyring to the list")},
    { oShowKeyring, "show-keyring", 0, N_("show which keyring a listed key is on")},
    { oDefaultKey, "default-key" ,2, N_("|NAME|use NAME as default secret key")},
    { oKeyServer, "keyserver",2, N_("|HOST|use this keyserver to lookup keys")},
    { oKeyServerOptions, "keyserver-options",2,"@"},
    { oImportOptions, "import-options",2,"@"},
    { oExportOptions, "export-options",2,"@"},
    { oCharset, "charset"   , 2, N_("|NAME|set terminal charset to NAME") },
    { oOptions, "options"   , 2, N_("read options from file")},

    { oDebug, "debug"     ,4|16, "@"},
    { oDebugAll, "debug-all" ,0, "@"},
    { oStatusFD, "status-fd" ,1, N_("|FD|write status info to this FD") },
#ifdef __riscos__
    { oStatusFile, "status-file" ,2, N_("|[file]|write status info to file") },
#endif /* __riscos__ */
    { oAttributeFD, "attribute-fd" ,1, "@" },
#ifdef __riscos__
    { oAttributeFile, "attribute-file" ,2, "@" },
#endif /* __riscos__ */
    { oNoSKComments, "no-comment", 0,   "@"},
    { oNoSKComments, "no-sk-comments", 0,   "@"},
    { oSKComments, "sk-comments", 0,   "@"},
    { oCompletesNeeded, "completes-needed", 1, "@"},
    { oMarginalsNeeded, "marginals-needed", 1, "@"},
    { oMaxCertDepth,	"max-cert-depth", 1, "@" },
    { oTrustedKey, "trusted-key", 2, N_("|KEYID|ultimately trust this key")},
    { oLoadExtension, "load-extension" ,2, N_("|FILE|load extension module FILE")},
    { oRFC1991, "rfc1991",   0, N_("emulate the mode described in RFC1991")},
    { oOpenPGP, "openpgp", 0, N_("set all packet, cipher and digest options to OpenPGP behavior")},
    { oPGP2, "pgp2", 0, N_("set all packet, cipher and digest options to PGP 2.x behavior")},
    { oNoPGP2, "no-pgp2", 0, "@"},
    { oPGP6, "pgp6", 0, "@"},
    { oNoPGP6, "no-pgp6", 0, "@"},
    { oPGP7, "pgp7", 0, "@"},
    { oNoPGP7, "no-pgp7", 0, "@"},
    { oS2KMode, "s2k-mode",  1, N_("|N|use passphrase mode N")},
    { oS2KDigest, "s2k-digest-algo",2,
		N_("|NAME|use message digest algorithm NAME for passphrases")},
    { oS2KCipher, "s2k-cipher-algo",2,
		N_("|NAME|use cipher algorithm NAME for passphrases")},
    { oSimpleSKChecksum, "simple-sk-checksum", 0, "@"},
    { oCipherAlgo, "cipher-algo", 2 , N_("|NAME|use cipher algorithm NAME")},
    { oDigestAlgo, "digest-algo", 2 , N_("|NAME|use message digest algorithm NAME")},
    { oCertDigestAlgo, "cert-digest-algo", 2 , "@" },
    { oCompressAlgo, "compress-algo", 1 , N_("|N|use compress algorithm N")},
    { oThrowKeyid, "throw-keyid", 0, N_("throw keyid field of encrypted packets")},
    { oShowPhotos,   "show-photos", 0, N_("Show Photo IDs")},
    { oNoShowPhotos, "no-show-photos", 0, N_("Don't show Photo IDs")},
    { oPhotoViewer,  "photo-viewer", 2, N_("Set command line to view Photo IDs")},
    { oNotation,   "notation-data", 2, "@" },
    { oSigNotation,   "sig-notation", 2, "@" },
    { oCertNotation,  "cert-notation", 2, "@" },

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
    { aExportOwnerTrust, "list-ownertrust",0 , "@"},  /* alias */
    { aPrintMDs, "print-mds" , 256, "@"}, /* old */
    { aListTrustDB, "list-trustdb",0 , "@"},
    { aListTrustPath, "list-trust-path",0, "@"},
    { aPipeMode,  "pipemode", 0, "@" },
    { oKOption, NULL,	 0, "@"},
    { oPasswdFD, "passphrase-fd",1, "@" },
#ifdef __riscos__
    { oPasswdFile, "passphrase-file",2, "@" },
#endif /* __riscos__ */
    { oCommandFD, "command-fd",1, "@" },
#ifdef __riscos__
    { oCommandFile, "command-file",2, "@" },
#endif /* __riscos__ */
    { oQuickRandom, "quick-random", 0, "@"},
    { oNoVerbose, "no-verbose", 0, "@"},
    { oTrustDBName, "trustdb-name", 2, "@" },
    { oNoSecmemWarn, "no-secmem-warning", 0, "@" }, /* used only by regression tests */
    { oNoPermissionWarn, "no-permission-warning", 0, "@" },
    { oNoMDCWarn, "no-mdc-warning", 0, "@" },
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
    { oDefCertCheckLevel, "default-cert-check-level", 1, "@"},
    { oAlwaysTrust, "always-trust", 0, "@"},
    { oEmuChecksumBug, "emulate-checksum-bug", 0, "@"},
    { oRunAsShmCP, "run-as-shm-coprocess", 4, "@" },
    { oSetFilename, "set-filename", 2, "@" },
    { oForYourEyesOnly, "for-your-eyes-only", 0, "@" },
    { oNoForYourEyesOnly, "no-for-your-eyes-only", 0, "@" },
    { oSetPolicyURL, "set-policy-url", 2, "@" },
    { oSigPolicyURL, "sig-policy-url", 2, "@" },
    { oCertPolicyURL, "cert-policy-url", 2, "@" },
    { oShowPolicyURL, "show-policy-url", 0, "@" },
    { oNoShowPolicyURL, "no-show-policy-url", 0, "@" },
    { oShowNotation, "show-notation", 0, "@" },
    { oNoShowNotation, "no-show-notation", 0, "@" },
    { oComment, "comment", 2, "@" },
    { oDefaultComment, "default-comment", 0, "@" },
    { oNoVersion, "no-version", 0, "@"},
    { oEmitVersion, "emit-version", 0, "@"},
    { oNotDashEscaped, "not-dash-escaped", 0, "@" },
    { oEscapeFrom, "escape-from-lines", 0, "@" },
    { oNoEscapeFrom, "no-escape-from-lines", 0, "@" },
    { oLockOnce, "lock-once", 0, "@" },
    { oLockMultiple, "lock-multiple", 0, "@" },
    { oLockNever, "lock-never", 0, "@" },
    { oLoggerFD, "logger-fd",1, "@" },
#ifdef __riscos__
    { oLoggerFile, "logger-file",2, "@" },
#endif /* __riscos__ */
    { oUseEmbeddedFilename, "use-embedded-filename", 0, "@" },
    { oUtf8Strings, "utf8-strings", 0, "@" },
    { oNoUtf8Strings, "no-utf8-strings", 0, "@" },
    { oWithFingerprint, "with-fingerprint", 0, "@" },
    { oDisableCipherAlgo,  "disable-cipher-algo", 2, "@" },
    { oDisablePubkeyAlgo,  "disable-pubkey-algo", 2, "@" },
    { oAllowNonSelfsignedUID, "allow-non-selfsigned-uid", 0, "@" },
    { oNoAllowNonSelfsignedUID, "no-allow-non-selfsigned-uid", 0, "@" },
    { oAllowFreeformUID, "allow-freeform-uid", 0, "@" },
    { oNoAllowFreeformUID, "no-allow-freeform-uid", 0, "@" },
    { oNoLiteral, "no-literal", 0, "@" },
    { oSetFilesize, "set-filesize", 20, "@" },
    { oHonorHttpProxy,"honor-http-proxy", 0, "@" },
    { oFastListMode,"fast-list-mode", 0, "@" },
    { oFixedListMode,"fixed-list-mode", 0, "@" },
    { oListOnly, "list-only", 0, "@"},
    { oIgnoreTimeConflict, "ignore-time-conflict", 0, "@" },
    { oIgnoreValidFrom,    "ignore-valid-from",    0, "@" },
    { oIgnoreCrcError, "ignore-crc-error", 0,"@" },
    { oIgnoreMDCError, "ignore-mdc-error", 0,"@" },
    { oShowSessionKey, "show-session-key", 0, "@" },
    { oOverrideSessionKey, "override-session-key", 2, "@" },
    { oNoRandomSeedFile,  "no-random-seed-file", 0, "@" },
    { oAutoKeyRetrieve, "auto-key-retrieve", 0, "@" },
    { oNoAutoKeyRetrieve, "no-auto-key-retrieve", 0, "@" },
    { oNoSigCache,         "no-sig-cache", 0, "@" },
    { oNoSigCreateCheck,   "no-sig-create-check", 0, "@" },
    { oAutoCheckTrustDB, "auto-check-trustdb", 0, "@"},
    { oNoAutoCheckTrustDB, "no-auto-check-trustdb", 0, "@"},
    { oMergeOnly,	  "merge-only", 0, "@" },
    { oAllowSecretKeyImport, "allow-secret-key-import", 0, "@" },
    { oTryAllSecrets,  "try-all-secrets", 0, "@" },
    { oEnableSpecialFilenames, "enable-special-filenames", 0, "@" },
    { oNoExpensiveTrustChecks, "no-expensive-trust-checks", 0, "@" },
    { aDeleteSecretAndPublicKeys, "delete-secret-and-public-keys",256, "@" },
    { aRebuildKeydbCaches, "rebuild-keydb-caches", 256, "@"},
    { oPreservePermissions, "preserve-permissions", 0, "@"},
    { oDefaultPreferenceList,  "default-preference-list", 2, "@"},
    { oPersonalCipherPreferences,  "personal-cipher-preferences", 2, "@"},
    { oPersonalDigestPreferences,  "personal-digest-preferences", 2, "@"},
    { oPersonalCompressPreferences,  "personal-compress-preferences", 2, "@"},
    { oEmuMDEncodeBug,	"emulate-md-encode-bug", 0, "@"},
    { oDisplay,    "display",     2, "@" },
    { oTTYname,    "ttyname",     2, "@" },
    { oTTYtype,    "ttytype",     2, "@" },
    { oLCctype,    "lc-ctype",    2, "@" },
    { oLCmessages, "lc-messages", 2, "@" },
    { oGroup,      "group",       2, "@" },
{0} };



int g10_errors_seen = 0;

static int utf8_strings = 0;
static int maybe_setuid = 1;

static char *build_list( const char *text, char letter,
			 const char *(*mapf)(int), int (*chkf)(int) );
static void set_cmd( enum cmd_and_opt_values *ret_cmd,
			enum cmd_and_opt_values new_cmd );
static void print_hex( byte *p, size_t n );
static void print_mds( const char *fname, int algo );
static void add_notation_data( const char *string, int which );
static void add_policy_url( const char *string, int which );

#ifdef __riscos__
RISCOS_GLOBAL_STATICS("GnuPG Heap")
#endif /* __riscos__ */

const char *
strusage( int level )
{
  static char *digests, *pubkeys, *ciphers, *zips;
    const char *p;
    switch( level ) {
      case 11: p = "gpg (GnuPG)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p =
	    _("Please report bugs to <gnupg-bugs@gnu.org>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: gpg [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: gpg [options] [files]\n"
	      "sign, check, encrypt or decrypt\n"
	      "default operation depends on the input data\n");
	break;

      case 31: p = "\nHome: "; break;
#ifndef __riscos__
      case 32: p = opt.homedir; break;
#else /* __riscos__ */
      case 32: p = make_filename(opt.homedir, NULL); break;
#endif /* __riscos__ */
      case 33: p = _("\nSupported algorithms:\n"); break;
      case 34:
	if( !pubkeys )
	    pubkeys = build_list("Pubkey: ", 0, pubkey_algo_to_string,
							check_pubkey_algo );
	p = pubkeys;
	break;
      case 35:
	if( !ciphers )
	    ciphers = build_list("Cipher: ", 'S', cipher_algo_to_string,
							check_cipher_algo );
	p = ciphers;
	break;
      case 36:
	if( !digests )
	    digests = build_list("Hash: ", 'H', digest_algo_to_string,
							check_digest_algo );
	p = digests;
	break;
      case 37:
	if( !zips )
	    zips = build_list("Compress: ",'Z',compress_algo_to_string,
			                                check_compress_algo);
	p = zips;
	break;

      default:	p = default_strusage(level);
    }
    return p;
}


static char *
build_list( const char *text, char letter,
	    const char * (*mapf)(int), int (*chkf)(int) )
{
    int i;
    const char *s;
    size_t n=strlen(text)+2;
    char *list, *p, *line=NULL;

    if( maybe_setuid )
	secmem_init( 0 );    /* drop setuid */

    for(i=0; i <= 110; i++ )
	if( !chkf(i) && (s=mapf(i)) )
	    n += strlen(s) + 7 + 2;
    list = m_alloc( 21 + n ); *list = 0;
    for(p=NULL, i=0; i <= 110; i++ ) {
	if( !chkf(i) && (s=mapf(i)) ) {
	    if( !p ) {
		p = stpcpy( list, text );
		line=p;
	    }
	    else
		p = stpcpy( p, ", ");

	    if(strlen(line)>60) {
	      int spaces=strlen(text);

	      list=m_realloc(list,n+spaces+1);
	      /* realloc could move the block, so find the end again */
	      p=list;
	      while(*p)
		p++;

	      p=stpcpy(p, "\n");
	      line=p;
	      for(;spaces;spaces--)
		p=stpcpy(p, " ");
	    }

	    p = stpcpy(p, s );
	    if(opt.verbose && letter)
	      {
		char num[8];
		sprintf(num," (%c%d)",letter,i);
		p = stpcpy(p,num);
	      }
	}
    }
    if( p )
	p = stpcpy(p, "\n" );
    return list;
}


static void
i18n_init(void)
{
  #ifdef USE_SIMPLE_GETTEXT
    set_gettext_file( PACKAGE );
  #else
  #ifdef ENABLE_NLS
    setlocale( LC_ALL, "" );
    bindtextdomain( PACKAGE, G10_LOCALEDIR );
    textdomain( PACKAGE );
  #endif
  #endif
}

static void
wrong_args( const char *text)
{
    fputs(_("usage: gpg [options] "),stderr);
    fputs(text,stderr);
    putc('\n',stderr);
    g10_exit(2);
}


static char *
make_username( const char *string )
{
    char *p;
    if( utf8_strings )
	p = m_strdup(string);
    else
	p = native_to_utf8( string );
    return p;
}


static void
set_debug(void)
{
    if( opt.debug & DBG_MEMORY_VALUE )
	memory_debug_mode = 1;
    if( opt.debug & DBG_MEMSTAT_VALUE )
	memory_stat_debug_mode = 1;
    if( opt.debug & DBG_MPI_VALUE )
	mpi_debug_mode = 1;
    if( opt.debug & DBG_CIPHER_VALUE )
	g10c_debug_mode = 1;
    if( opt.debug & DBG_IOBUF_VALUE )
	iobuf_debug_mode = 1;

}


/* We need the home directory also in some other directories, so make
   sure that both variables are always in sync. */
static void
set_homedir (char *dir)
{
  if (!dir)
    dir = "";
  g10_opt_homedir = opt.homedir = dir;
}


static void
set_cmd( enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd )
{
    enum cmd_and_opt_values cmd = *ret_cmd;

    if( !cmd || cmd == new_cmd )
	cmd = new_cmd;
    else if( cmd == aSign && new_cmd == aEncr )
	cmd = aSignEncr;
    else if( cmd == aEncr && new_cmd == aSign )
	cmd = aSignEncr;
    else if( cmd == aSign && new_cmd == aSym )
	cmd = aSignSym;
    else if( cmd == aSym && new_cmd == aSign )
	cmd = aSignSym;
    else if( cmd == aKMode && new_cmd == aSym )
	cmd = aKModeC;
    else if(	( cmd == aSign	   && new_cmd == aClearsign )
	     || ( cmd == aClearsign && new_cmd == aSign )  )
	cmd = aClearsign;
    else {
	log_error(_("conflicting commands\n"));
	g10_exit(2);
    }

    *ret_cmd = cmd;
}


static void add_group(char *string)
{
  char *name,*value;
  struct groupitem *item;
  STRLIST values=NULL;

  /* Break off the group name */
  name=strsep(&string,"=");
  if(string==NULL)
    {
      log_error(_("no = sign found in group definition \"%s\"\n"),name);
      return;
    }

  /* Break apart the values */
  while((value=strsep(&string," ")) && *value!='\0')
    add_to_strlist2(&values,value,utf8_strings);

  item=m_alloc(sizeof(struct groupitem));
  item->name=name;
  item->values=values;
  item->next=opt.grouplist;

  opt.grouplist=item;
}

/* We need to check three things.

   0) The homedir.  It must be x00, a directory, and owned by the
   user.

   1) The options file.  Okay unless it or its containing directory is
   group or other writable or not owned by us.  disable exec in this
   case.

   2) Extensions.  Same as #2.

   Returns true if the item is unsafe. */
static int
check_permissions(const char *path,int item)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  static int homedir_cache=-1;
  char *tmppath,*isa,*dir;
  struct stat statbuf,dirbuf;
  int homedir=0,ret=0,checkonly=0;
  int perm=0,own=0,enc_dir_perm=0,enc_dir_own=0;

  if(opt.no_perm_warn)
    return 0;

  /* extensions may attach a path */
  if(item==2 && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(GNUPG_LIBDIR,path,NULL);
    }
  else
    tmppath=m_strdup(path);

  /* If the item is located in the homedir, but isn't the homedir,
     don't continue if we already checked the homedir itself.  This is
     to avoid user confusion with an extra options file warning which
     could be rectified if the homedir itself had proper
     permissions. */
  if(item!=0 && homedir_cache>-1
     && ascii_strncasecmp(opt.homedir,tmppath,strlen(opt.homedir))==0)
    {
      ret=homedir_cache;
      goto end;
    }

  /* It's okay if the file or directory doesn't exist */
  if(stat(tmppath,&statbuf)!=0)
    {
      ret=0;
      goto end;
    }

  /* Now check the enclosing directory.  Theoretically, we could walk
     this test up to the root directory /, but for the sake of sanity,
     I'm stopping at one level down. */
  dir=make_dirname(tmppath);

  if(stat(dir,&dirbuf)!=0 || !S_ISDIR(dirbuf.st_mode))
    {
      /* Weird error */
      ret=1;
      goto end;
    }

  m_free(dir);

  /* Assume failure */
  ret=1;

  if(item==0)
    {
      isa="homedir";

      /* The homedir must be x00, a directory, and owned by the user. */

      if(S_ISDIR(statbuf.st_mode))
	{
	  if(statbuf.st_uid==getuid())
	    {
	      if((statbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
		ret=0;
	      else
		perm=1;
	    }
	  else
	    own=1;

	  homedir_cache=ret;
	}
    }
  else if(item==1 || item==2)
    {
      if(item==1)
	isa="configuration file";
      else
	isa="extension";

      /* The options or extension file.  Okay unless it or its
	 containing directory is group or other writable or not owned
	 by us or root. */

      if(S_ISREG(statbuf.st_mode))
	{
	  if(statbuf.st_uid==getuid() || statbuf.st_uid==0)
	    {
	      if((statbuf.st_mode & (S_IWGRP|S_IWOTH))==0)
		{
		  /* it's not writable, so make sure the enclosing
                     directory is also not writable */
		  if(dirbuf.st_uid==getuid() || dirbuf.st_uid==0)
		    {
		      if((dirbuf.st_mode & (S_IWGRP|S_IWOTH))==0)
			ret=0;
		      else
			enc_dir_perm=1;
		    }
		  else
		    enc_dir_own=1;
		}
	      else
		{
		  /* it's writable, so the enclosing directory had
                     better not let people get to it. */
		  if(dirbuf.st_uid==getuid() || dirbuf.st_uid==0)
		    {
		      if((dirbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
			ret=0;
		      else
			perm=enc_dir_perm=1; /* unclear which one to fix! */
		    }
		  else
		    enc_dir_own=1;
		}
	    }
	  else
	    own=1;
	}
    }
  else
    BUG();

  if(!checkonly)
    {
      if(own)
	log_info(_("WARNING: unsafe ownership on %s \"%s\"\n"),
		 isa,tmppath);
      if(perm)
	log_info(_("WARNING: unsafe permissions on %s \"%s\"\n"),
		 isa,tmppath);
      if(enc_dir_own)
	log_info(_("WARNING: unsafe enclosing directory "
		   "ownership on %s \"%s\"\n"),
		 isa,tmppath);
      if(enc_dir_perm)
	log_info(_("WARNING: unsafe enclosing directory "
		   "permissions on %s \"%s\"\n"),
		 isa,tmppath);
    }

 end:
  m_free(tmppath);

  if(homedir)
    homedir_cache=ret;

  return ret;

#endif /* HAVE_STAT && !HAVE_DOSISH_SYSTEM */

  return 0;
}

int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc=0;
    int orig_argc;
    char **orig_argv;
    const char *fname;
    char *username;
    int may_coredump;
    STRLIST sl, remusr= NULL, locusr=NULL;
    STRLIST nrings=NULL, sec_nrings=NULL;
    armor_filter_context_t afx;
    int detached_sig = 0;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_debug = 0;
    int default_config = 1;
    int default_keyring = 1;
    int greeting = 0;
    int nogreeting = 0;
    int use_random_seed = 1;
    enum cmd_and_opt_values cmd = 0;
    const char *trustdb_name = NULL;
    char *def_cipher_string = NULL;
    char *def_digest_string = NULL;
    char *cert_digest_string = NULL;
    char *s2k_cipher_string = NULL;
    char *s2k_digest_string = NULL;
    char *pers_cipher_list = NULL;
    char *pers_digest_list = NULL;
    char *pers_compress_list = NULL;
    int eyes_only=0;
    int pwfd = -1;
    int with_fpr = 0; /* make an option out of --fingerprint */
    int any_explicit_recipient = 0;
  #ifdef USE_SHM_COPROCESSING
    ulong requested_shm_size=0;
  #endif

  #ifdef __riscos__
    riscos_global_defaults();
    opt.lock_once = 1;
  #endif /* __riscos__ */

    trap_unaligned();
    secmem_set_flags( secmem_get_flags() | 2 ); /* suspend warnings */
    /* Please note that we may running SUID(ROOT), so be very CAREFUL
     * when adding any stuff between here and the call to
     * secmem_init()  somewhere after the option parsing
     */
    log_set_name("gpg");
    secure_random_alloc(); /* put random number into secure memory */
    may_coredump = disable_core_dumps();
    init_signals();
    create_dotlock(NULL); /* register locking cleanup */
    i18n_init();
    opt.command_fd = -1; /* no command fd */
    opt.compress = -1; /* defaults to standard compress level */
    /* note: if you change these lines, look at oOpenPGP */
    opt.def_cipher_algo = 0;
    opt.def_digest_algo = 0;
    opt.cert_digest_algo = 0;
    opt.def_compress_algo = -1;
    opt.s2k_mode = 3; /* iterated+salted */
    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
    opt.s2k_cipher_algo = CIPHER_ALGO_CAST5;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.max_cert_depth = 5;
    opt.pgp2_workarounds = 1;
    opt.force_v3_sigs = 1;
    opt.escape_from = 1;
    opt.import_options=0;
    opt.export_options=
      EXPORT_INCLUDE_NON_RFC|EXPORT_INCLUDE_ATTRIBUTES;
    opt.keyserver_options.import_options=IMPORT_REPAIR_HKP_SUBKEY_BUG;
    opt.keyserver_options.export_options=
      EXPORT_INCLUDE_NON_RFC|EXPORT_INCLUDE_ATTRIBUTES;
    opt.keyserver_options.include_subkeys=1;
    opt.keyserver_options.include_revoked=1;
#if defined (__MINGW32__)
    set_homedir ( read_w32_registry_string( NULL,
                                    "Software\\GNU\\GnuPG", "HomeDir" ));
#else
    set_homedir ( getenv("GNUPGHOME") );
#endif
    if( !*opt.homedir )
	set_homedir ( GNUPG_HOMEDIR );

    /* check whether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == oDebug || pargs.r_opt == oDebugAll )
	    parse_debug++;
	else if( pargs.r_opt == oOptions ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
	else if( pargs.r_opt == oNoOptions )
	    default_config = 0; /* --no-options */
	else if( pargs.r_opt == oHomedir )
	    set_homedir ( pargs.r.ret_str );
	else if( pargs.r_opt == oNoPermissionWarn )
	    opt.no_perm_warn=1;
      #ifdef USE_SHM_COPROCESSING
	else if( pargs.r_opt == oRunAsShmCP ) {
	    /* does not make sense in a options file, we do it here,
	     * so that we are the able to drop setuid as soon as possible */
	    opt.shm_coprocess = 1;
	    requested_shm_size = pargs.r.ret_ulong;
	}
	else if ( pargs.r_opt == oStatusFD ) {
	    /* this is needed to ensure that the status-fd filedescriptor is
	     * initialized when init_shm_coprocessing() is called */
	    set_status_fd( iobuf_translate_file_handle (pargs.r.ret_int, 1) );
	}
      #endif
    }

#ifdef HAVE_DOSISH_SYSTEM
    if ( strchr (opt.homedir,'\\') ) {
        char *d, *buf = m_alloc (strlen (opt.homedir)+1);
        const char *s = opt.homedir;
        for (d=buf,s=opt.homedir; *s; s++)
            *d++ = *s == '\\'? '/': *s;
        *d = 0;
        set_homedir (buf);
    }
#endif
#ifdef USE_SHM_COPROCESSING
    if( opt.shm_coprocess ) {
	init_shm_coprocessing(requested_shm_size, 1 );
    }
#endif
    /* initialize the secure memory. */
    secmem_init( 16384 );
    maybe_setuid = 0;
    /* Okay, we are now working under our real uid */

    set_native_charset (NULL); /* Try to auto set the character set */

    if( default_config )
      {
	configname = make_filename(opt.homedir, "gpg" EXTSEP_S "conf", NULL );
        if (!access (configname, R_OK))
          { /* Print a warning when both config files are present. */
            char *p = make_filename(opt.homedir, "options", NULL );
            if (!access (p, R_OK))
              log_info (_("NOTE: old default options file `%s' ignored\n"), p);
            m_free (p);
          }
        else
          { /* Keep on using the old default one. */
            m_free (configname);
            configname = make_filename(opt.homedir, "options", NULL );
          }
      }
    argc = orig_argc;
    argv = orig_argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */

    /* By this point we have a homedir, and cannot change it. */
    check_permissions(opt.homedir,0);

  next_pass:
    if( configname ) {
      if(check_permissions(configname,1))
	{
	  /* If any options file is unsafe, then disable any external
	     programs for keyserver calls or photo IDs.  Since the
	     external program to call is set in the options file, a
	     unsafe options file can lead to an arbitrary program
	     being run. */

	  opt.exec_disable=1;
	}

	configlineno = 0;
	configfp = fopen( configname, "r" );
	if( !configfp ) {
	    if( default_config ) {
		if( parse_debug )
		    log_info(_("NOTE: no default option file `%s'\n"),
							    configname );
	    }
	    else {
		log_error(_("option file `%s': %s\n"),
				    configname, strerror(errno) );
		g10_exit(2);
	    }
	    m_free(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info(_("reading options from `%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case aCheckKeys: set_cmd( &cmd, aCheckKeys); break;
	  case aListPackets: set_cmd( &cmd, aListPackets); break;
	  case aImport: set_cmd( &cmd, aImport); break;
	  case aFastImport: set_cmd( &cmd, aFastImport); break;
	  case aSendKeys: set_cmd( &cmd, aSendKeys); break;
	  case aRecvKeys: set_cmd( &cmd, aRecvKeys); break;
	  case aSearchKeys: set_cmd( &cmd, aSearchKeys); break;
	  case aRefreshKeys: set_cmd( &cmd, aRefreshKeys); break;
	  case aExport: set_cmd( &cmd, aExport); break;
	  case aExportAll: set_cmd( &cmd, aExportAll); break;
	  case aListKeys: set_cmd( &cmd, aListKeys); break;
	  case aListSigs: set_cmd( &cmd, aListSigs); break;
	  case aExportSecret: set_cmd( &cmd, aExportSecret); break;
	  case aExportSecretSub: set_cmd( &cmd, aExportSecretSub); break;
	  case aDeleteSecretKeys: set_cmd( &cmd, aDeleteSecretKeys);
							greeting=1; break;
	  case aDeleteSecretAndPublicKeys:
            set_cmd( &cmd, aDeleteSecretAndPublicKeys);
            greeting=1; 
            break;
	  case aDeleteKeys: set_cmd( &cmd, aDeleteKeys); greeting=1; break;

	  case aDetachedSign: detached_sig = 1; set_cmd( &cmd, aSign ); break;
	  case aSym: set_cmd( &cmd, aSym); break;

	  case aDecrypt: set_cmd( &cmd, aDecrypt); break;
          case aDecryptFiles: set_cmd( &cmd, aDecryptFiles); break;

	  case aEncr: set_cmd( &cmd, aEncr); break;
	  case aEncrFiles: set_cmd( &cmd, aEncrFiles ); break;
	  case aSign: set_cmd( &cmd, aSign );  break;
	  case aKeygen: set_cmd( &cmd, aKeygen); greeting=1; break;
	  case aSignKey: set_cmd( &cmd, aSignKey); break;
	  case aLSignKey: set_cmd( &cmd, aLSignKey); break;
	  case aNRSignKey: set_cmd( &cmd, aNRSignKey); break;
	  case aNRLSignKey: set_cmd( &cmd, aNRLSignKey); break;
	  case aStore: set_cmd( &cmd, aStore); break;
	  case aEditKey: set_cmd( &cmd, aEditKey); greeting=1; break;
	  case aClearsign: set_cmd( &cmd, aClearsign); break;
	  case aGenRevoke: set_cmd( &cmd, aGenRevoke); break;
	  case aDesigRevoke: set_cmd( &cmd, aDesigRevoke); break;
	  case aVerify: set_cmd( &cmd, aVerify); break;
	  case aVerifyFiles: set_cmd( &cmd, aVerifyFiles); break;
	  case aPrimegen: set_cmd( &cmd, aPrimegen); break;
	  case aGenRandom: set_cmd( &cmd, aGenRandom); break;
	  case aPrintMD: set_cmd( &cmd, aPrintMD); break;
	  case aPrintMDs: set_cmd( &cmd, aPrintMDs); break;
	  case aListTrustDB: set_cmd( &cmd, aListTrustDB); break;
	  case aCheckTrustDB: set_cmd( &cmd, aCheckTrustDB); break;
	  case aUpdateTrustDB: set_cmd( &cmd, aUpdateTrustDB); break;
	  case aFixTrustDB: set_cmd( &cmd, aFixTrustDB); break;
	  case aListTrustPath: set_cmd( &cmd, aListTrustPath); break;
	  case aDeArmor: set_cmd( &cmd, aDeArmor); break;
	  case aEnArmor: set_cmd( &cmd, aEnArmor); break;
	  case aExportOwnerTrust: set_cmd( &cmd, aExportOwnerTrust); break;
	  case aImportOwnerTrust: set_cmd( &cmd, aImportOwnerTrust); break;
          case aPipeMode: set_cmd( &cmd, aPipeMode); break;
          case aRebuildKeydbCaches: set_cmd( &cmd, aRebuildKeydbCaches); break;

	  case oArmor: opt.armor = 1; opt.no_armor=0; break;
	  case oOutput: opt.outfile = pargs.r.ret_str; break;
	  case oQuiet: opt.quiet = 1; break;
	  case oNoTTY: tty_no_terminal(1); break;
	  case oDryRun: opt.dry_run = 1; break;
	  case oInteractive: opt.interactive = 1; break;
	  case oVerbose: g10_opt_verbose++;
		    opt.verbose++; opt.list_sigs=1; break;
	  case oKOption: set_cmd( &cmd, aKMode ); break;

	  case oBatch: opt.batch = 1; nogreeting = 1; break;
          case oUseAgent:
#ifndef __riscos__
            opt.use_agent = 1;
#else /* __riscos__ */
            opt.use_agent = 0;
            not_implemented("use-agent");
#endif /* __riscos__ */
            break;
          case oNoUseAgent: opt.use_agent = 0; break;
	  case oGpgAgentInfo: opt.gpg_agent_info = pargs.r.ret_str; break;
	  case oAnswerYes: opt.answer_yes = 1; break;
	  case oAnswerNo: opt.answer_no = 1; break;
	  case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
	  case oShowKeyring: opt.show_keyring = 1; break;
	  case oDebug: opt.debug |= pargs.r.ret_ulong; break;
	  case oDebugAll: opt.debug = ~0; break;
	  case oStatusFD:
            set_status_fd( iobuf_translate_file_handle (pargs.r.ret_int, 1) );
            break;
#ifdef __riscos__
	  case oStatusFile:
            set_status_fd( iobuf_translate_file_handle ( fdopenfile (pargs.r.ret_str, 1), 1) );
            break;
#endif /* __riscos__ */
	  case oAttributeFD:
            set_attrib_fd(iobuf_translate_file_handle (pargs.r.ret_int, 1));
            break;
#ifdef __riscos__
	  case oAttributeFile:
            set_attrib_fd(iobuf_translate_file_handle ( fdopenfile (pargs.r.ret_str, 1), 1) );
            break;
#endif /* __riscos__ */
	  case oLoggerFD:
            log_set_logfile( NULL,
                             iobuf_translate_file_handle (pargs.r.ret_int, 1) );
            break;
#ifdef __riscos__
	  case oLoggerFile:
            log_set_logfile( NULL,
                             iobuf_translate_file_handle ( fdopenfile (pargs.r.ret_str, 1), 1) );
            break;
#endif /* __riscos__ */
	  case oWithFingerprint:
            opt.with_fingerprint = 1;
            with_fpr=1; /*fall thru*/
	  case oFingerprint: opt.fingerprint++; break;
	  case oSecretKeyring: append_to_strlist( &sec_nrings, pargs.r.ret_str); break;
	  case oOptions:
	    /* config files may not be nested (silently ignore them) */
	    if( !configfp ) {
		m_free(configname);
		configname = m_strdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case oNoArmor: opt.no_armor=1; opt.armor=0; break;
	  case oNoDefKeyring: default_keyring = 0; break;
          case oDefCertCheckLevel: opt.def_cert_check_level=pargs.r.ret_int; break;
	  case oNoGreeting: nogreeting = 1; break;
	  case oNoVerbose: g10_opt_verbose = 0;
			   opt.verbose = 0; opt.list_sigs=0; break;
	  case oQuickRandom: quick_random_gen(1); break;
	  case oSKComments: opt.sk_comments=1; break;
	  case oNoSKComments: opt.sk_comments=0; break;
	  case oNoVersion: opt.no_version=1; break;
	  case oEmitVersion: opt.no_version=0; break;
	  case oCompletesNeeded: opt.completes_needed = pargs.r.ret_int; break;
	  case oMarginalsNeeded: opt.marginals_needed = pargs.r.ret_int; break;
	  case oMaxCertDepth: opt.max_cert_depth = pargs.r.ret_int; break;
	  case oTrustDBName: trustdb_name = pargs.r.ret_str; break;
	  case oDefaultKey: opt.def_secret_key = pargs.r.ret_str; break;
	  case oDefRecipient:
		    if( *pargs.r.ret_str )
			opt.def_recipient = make_username(pargs.r.ret_str);
		    break;
	  case oDefRecipientSelf:
		    m_free(opt.def_recipient); opt.def_recipient = NULL;
		    opt.def_recipient_self = 1;
		    break;
	  case oNoDefRecipient:
		    m_free(opt.def_recipient); opt.def_recipient = NULL;
		    opt.def_recipient_self = 0;
		    break;
	  case oNoOptions: opt.no_homedir_creation = 1; break; /* no-options */
	  case oHomedir: break;
	  case oNoBatch: opt.batch = 0; break;
	  case oWithKeyData: opt.with_key_data=1; /* fall thru */
	  case oWithColons: opt.with_colons=':'; break;

	  case oSkipVerify: opt.skip_verify=1; break;
	  case oCompressAlgo: opt.def_compress_algo = pargs.r.ret_int; break;
	  case oCompressKeys: opt.compress_keys = 1; break;
	  case aListSecretKeys: set_cmd( &cmd, aListSecretKeys); break;
	  case oAlwaysTrust: opt.always_trust = 1; break;
	  case oLoadExtension:
#ifndef __riscos__
#if defined(USE_DYNAMIC_LINKING) || defined(__MINGW32__)
	    if(check_permissions(pargs.r.ret_str,2))
	      log_info(_("cipher extension \"%s\" not loaded due to "
			 "unsafe permissions\n"),pargs.r.ret_str);
	    else
	      register_cipher_extension(orig_argc? *orig_argv:NULL,
					pargs.r.ret_str);
#endif
#else /* __riscos__ */
            not_implemented("load-extension");
#endif /* __riscos__ */
	    break;
	  case oRFC1991:
	    opt.rfc1991 = 1;
	    opt.rfc2440 = 0;
	    opt.force_v4_certs = 0;
	    opt.disable_mdc = 1;
	    opt.escape_from = 1;
	    break;
	  case oOpenPGP:
	    /* TODO: When 2440bis becomes a RFC, these may need
               changing. */
	    opt.rfc1991 = 0;
	    opt.rfc2440 = 1;
	    opt.disable_mdc = 1;
	    opt.allow_non_selfsigned_uid = 1;
	    opt.allow_freeform_uid = 1;
	    opt.pgp2_workarounds = 0;
	    opt.escape_from = 0;
	    opt.force_v3_sigs = 0;
	    opt.compress_keys = 0;	    /* not mandated  but we do it */
	    opt.compress_sigs = 0;	    /* ditto. */
	    opt.not_dash_escaped = 0;
	    opt.def_cipher_algo = 0;
	    opt.def_digest_algo = 0;
	    opt.cert_digest_algo = 0;
	    opt.def_compress_algo = 1;
            opt.s2k_mode = 3; /* iterated+salted */
	    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
	    opt.s2k_cipher_algo = CIPHER_ALGO_CAST5;
	    break;
	  case oPGP2: opt.pgp2 = 1; break;
	  case oNoPGP2: opt.pgp2 = 0; break;
	  case oPGP6: opt.pgp6 = 1; break;
	  case oNoPGP6: opt.pgp6 = 0; break;
	  case oPGP7: opt.pgp7 = 1; break;
	  case oNoPGP7: opt.pgp7 = 0; break;
	  case oEmuMDEncodeBug: opt.emulate_bugs |= EMUBUG_MDENCODE; break;
	  case oCompressSigs: opt.compress_sigs = 1; break;
	  case oRunAsShmCP:
#ifndef __riscos__
# ifndef USE_SHM_COPROCESSING
	    /* not possible in the option file,
	     * but we print the warning here anyway */
	    log_error("shared memory coprocessing is not available\n");
# endif
#else /* __riscos__ */
            not_implemented("run-as-shm-coprocess");
#endif /* __riscos__ */
	    break;
	  case oSetFilename: opt.set_filename = pargs.r.ret_str; break;
	  case oForYourEyesOnly: eyes_only = 1; break;
	  case oNoForYourEyesOnly: eyes_only = 0; break;
	  case oSetPolicyURL:
	    add_policy_url(pargs.r.ret_str,0);
	    add_policy_url(pargs.r.ret_str,1);
	    break;
	  case oSigPolicyURL: add_policy_url(pargs.r.ret_str,0); break;
	  case oCertPolicyURL: add_policy_url(pargs.r.ret_str,1); break;
          case oShowPolicyURL: opt.show_policy_url=1; break;
    	  case oNoShowPolicyURL: opt.show_policy_url=0; break;
	  case oUseEmbeddedFilename: opt.use_embedded_filename = 1; break;
	  case oComment: opt.comment_string = pargs.r.ret_str; break;
	  case oDefaultComment: opt.comment_string = NULL; break;
	  case oThrowKeyid: opt.throw_keyid = 1; break;
	  case oShowPhotos: opt.show_photos = 1; break;
	  case oNoShowPhotos: opt.show_photos = 0; break;
	  case oPhotoViewer: opt.photo_viewer = pargs.r.ret_str; break;
	  case oForceV3Sigs: opt.force_v3_sigs = 1; break;
	  case oNoForceV3Sigs: opt.force_v3_sigs = 0; break;
          case oForceV4Certs: opt.force_v4_certs = 1; break;
          case oNoForceV4Certs: opt.force_v4_certs = 0; break;
	  case oForceMDC: opt.force_mdc = 1; break;
	  case oNoForceMDC: opt.force_mdc = 0; break;
	  case oDisableMDC: opt.disable_mdc = 1; break;
	  case oNoDisableMDC: opt.disable_mdc = 0; break;
	  case oS2KMode:   opt.s2k_mode = pargs.r.ret_int; break;
	  case oS2KDigest: s2k_digest_string = m_strdup(pargs.r.ret_str); break;
	  case oS2KCipher: s2k_cipher_string = m_strdup(pargs.r.ret_str); break;
          case oSimpleSKChecksum: opt.simple_sk_checksum = 1; break;
	  case oNoEncryptTo: opt.no_encrypt_to = 1; break;
	  case oEncryptTo: /* store the recipient in the second list */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 1;
	    break;
	  case oRecipient: /* store the recipient */
	    add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
            any_explicit_recipient = 1;
	    break;
	  case oTextmodeShort: opt.textmode = 2; break;
	  case oTextmode: opt.textmode=1;  break;
	  case oExpert: opt.expert = 1; break;
	  case oNoExpert: opt.expert = 0; break;
	  case oAskSigExpire: opt.ask_sig_expire = 1; break;
	  case oNoAskSigExpire: opt.ask_sig_expire = 0; break;
	  case oAskCertExpire: opt.ask_cert_expire = 1; break;
	  case oNoAskCertExpire: opt.ask_cert_expire = 0; break;
	  case oUser: /* store the local users */
	    add_to_strlist2( &locusr, pargs.r.ret_str, utf8_strings );
	    break;
	  case oCompress: opt.compress = pargs.r.ret_int; break;
	  case oPasswdFD:
            pwfd = iobuf_translate_file_handle (pargs.r.ret_int, 0);
            break;
#ifdef __riscos__
	  case oPasswdFile:
            pwfd = iobuf_translate_file_handle ( fdopenfile (pargs.r.ret_str, 0), 0);
            break;
#endif /* __riscos__ */
	  case oCommandFD:
            opt.command_fd = iobuf_translate_file_handle (pargs.r.ret_int, 0);
            break;
#ifdef __riscos__
	  case oCommandFile:
            opt.command_fd = iobuf_translate_file_handle ( fdopenfile (pargs.r.ret_str, 0), 0);
            break;
#endif /* __riscos__ */
	  case oCipherAlgo: def_cipher_string = m_strdup(pargs.r.ret_str); break;
	  case oDigestAlgo: def_digest_string = m_strdup(pargs.r.ret_str); break;
	  case oCertDigestAlgo: cert_digest_string = m_strdup(pargs.r.ret_str); break;
	  case oNoSecmemWarn: secmem_set_flags( secmem_get_flags() | 1 ); break;
	  case oNoPermissionWarn: opt.no_perm_warn=1; break;
	  case oNoMDCWarn: opt.no_mdc_warn=1; break;
          case oCharset:
	    if( set_native_charset( pargs.r.ret_str ) )
		log_error(_("%s is not a valid character set\n"),
						    pargs.r.ret_str);
	    break;
	  case oNotDashEscaped: opt.not_dash_escaped = 1; break;
	  case oEscapeFrom: opt.escape_from = 1; break;
	  case oNoEscapeFrom: opt.escape_from = 0; break;
	  case oLockOnce: opt.lock_once = 1; break;
	  case oLockNever: disable_dotlock(); break;
	  case oLockMultiple:
#ifndef __riscos__
	    opt.lock_once = 0;
#else /* __riscos__ */
            not_implemented("lock-multiple");
#endif /* __riscos__ */
            break;
	  case oKeyServer:
	    opt.keyserver_uri=m_strdup(pargs.r.ret_str);
	    if(parse_keyserver_uri(pargs.r.ret_str,configname,configlineno))
	      log_error(_("could not parse keyserver URI\n"));
	    break;
	  case oKeyServerOptions:
	    parse_keyserver_options(pargs.r.ret_str);
	    break;
	  case oImportOptions:
	    if(!parse_import_options(pargs.r.ret_str,&opt.import_options))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid import options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid import options\n"));
	      }
	    break;
	  case oExportOptions:
	    if(!parse_export_options(pargs.r.ret_str,&opt.export_options))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid export options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid export options\n"));
	      }
	    break;
	  case oTempDir: opt.temp_dir=pargs.r.ret_str; break;
	  case oExecPath:
	    if(set_exec_path(pargs.r.ret_str,0))
	      log_error(_("unable to set exec-path to %s\n"),pargs.r.ret_str);
	    else
	      opt.exec_path_set=1;
	    break;
	  case oNotation:
	    add_notation_data( pargs.r.ret_str, 0 );
	    add_notation_data( pargs.r.ret_str, 1 );
	    break;
	  case oSigNotation: add_notation_data( pargs.r.ret_str, 0 ); break;
	  case oCertNotation: add_notation_data( pargs.r.ret_str, 1 ); break;
	  case oShowNotation: opt.show_notation=1; break;
	  case oNoShowNotation: opt.show_notation=0; break;
	  case oUtf8Strings: utf8_strings = 1; break;
	  case oNoUtf8Strings: utf8_strings = 0; break;
	  case oDisableCipherAlgo:
		disable_cipher_algo( string_to_cipher_algo(pargs.r.ret_str) );
		break;
	  case oDisablePubkeyAlgo:
		disable_pubkey_algo( string_to_pubkey_algo(pargs.r.ret_str) );
		break;
          case oNoSigCache: opt.no_sig_cache = 1; break;
          case oNoSigCreateCheck: opt.no_sig_create_check = 1; break;
	  case oAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid = 1; break;
	  case oNoAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid=0; break;
	  case oAllowFreeformUID: opt.allow_freeform_uid = 1; break;
	  case oNoAllowFreeformUID: opt.allow_freeform_uid = 0; break;
	  case oNoLiteral: opt.no_literal = 1; break;
	  case oSetFilesize: opt.set_filesize = pargs.r.ret_ulong; break;
	  case oHonorHttpProxy:
                opt.keyserver_options.honor_http_proxy = 1;
		deprecated_warning(configname,configlineno,
				   "--honor-http-proxy",
				   "--keyserver-options ",
				   "honor-http-proxy");
		break;
	  case oFastListMode: opt.fast_list_mode = 1; break;
	  case oFixedListMode: opt.fixed_list_mode = 1; break;
	  case oListOnly: opt.list_only=1; break;
	  case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
	  case oIgnoreValidFrom: opt.ignore_valid_from = 1; break;
	  case oIgnoreCrcError: opt.ignore_crc_error = 1; break;
	  case oIgnoreMDCError: opt.ignore_mdc_error = 1; break;
	  case oNoRandomSeedFile: use_random_seed = 0; break;
	  case oAutoKeyRetrieve:
	  case oNoAutoKeyRetrieve:
	        opt.keyserver_options.auto_key_retrieve=
	                                     (pargs.r_opt==oAutoKeyRetrieve);
		deprecated_warning(configname,configlineno,
			   pargs.r_opt==oAutoKeyRetrieve?"--auto-key-retrieve":
			       "--no-auto-key-retrieve","--keyserver-options ",
			   pargs.r_opt==oAutoKeyRetrieve?"auto-key-retrieve":
			       "no-auto-key-retrieve");
		break;
	  case oShowSessionKey: opt.show_session_key = 1; break;
	  case oOverrideSessionKey:
		opt.override_session_key = pargs.r.ret_str;
		break;
	  case oMergeOnly: opt.merge_only = 1; break;
          case oAllowSecretKeyImport: /* obsolete */ break;
	  case oTryAllSecrets: opt.try_all_secrets = 1; break;
          case oTrustedKey: register_trusted_key( pargs.r.ret_str ); break;
          case oEnableSpecialFilenames:
            iobuf_enable_special_filenames (1);
            break;
          case oNoExpensiveTrustChecks: opt.no_expensive_trust_checks=1; break;
          case oAutoCheckTrustDB: opt.no_auto_check_trustdb=0; break;
          case oNoAutoCheckTrustDB: opt.no_auto_check_trustdb=1; break;
          case oPreservePermissions: opt.preserve_permissions=1; break;
          case oDefaultPreferenceList:
	    opt.def_preference_list = pargs.r.ret_str;
	    break;
          case oPersonalCipherPreferences:
	    pers_cipher_list=pargs.r.ret_str;
	    break;
          case oPersonalDigestPreferences:
	    pers_digest_list=pargs.r.ret_str;
	    break;
          case oPersonalCompressPreferences:
	    pers_compress_list=pargs.r.ret_str;
	    break;
          case oDisplay: opt.display = pargs.r.ret_str; break;
          case oTTYname: opt.ttyname = pargs.r.ret_str; break;
          case oTTYtype: opt.ttytype = pargs.r.ret_str; break;
          case oLCctype: opt.lc_ctype = pargs.r.ret_str; break;
          case oLCmessages: opt.lc_messages = pargs.r.ret_str; break;
	  case oGroup: add_group(pargs.r.ret_str); break;
	  default : pargs.err = configfp? 1:2; break;
	}
    }

    if( configfp ) {
	fclose( configfp );
	configfp = NULL;
	m_free(configname); configname = NULL;
	goto next_pass;
    }
    m_free( configname ); configname = NULL;
    if( log_get_errorcount(0) )
	g10_exit(2);
    if( nogreeting )
	greeting = 0;

    if( greeting ) {
	fprintf(stderr, "%s %s; %s\n",
			strusage(11), strusage(13), strusage(14) );
	fprintf(stderr, "%s\n", strusage(15) );
    }
  #ifdef IS_DEVELOPMENT_VERSION
    if( !opt.batch ) {
	log_info("NOTE: THIS IS A DEVELOPMENT VERSION!\n");
	log_info("It is only intended for test purposes and should NOT be\n");
	log_info("used in a production environment or with production keys!\n");
    }
  #endif

    if (opt.verbose > 2)
        log_info ("using character set `%s'\n", get_native_charset ());

    if( may_coredump && !opt.quiet )
	log_info(_("WARNING: program may create a core file!\n"));

    if (eyes_only) {
      if (opt.set_filename)
	  log_info(_("WARNING: %s overrides %s\n"),
		   "--for-your-eyes-only","--set-filename");

      opt.set_filename="_CONSOLE";
    }

    if (opt.no_literal) {
	log_info(_("NOTE: %s is not for normal use!\n"), "--no-literal");
	if (opt.textmode)
	    log_error(_("%s not allowed with %s!\n"),
		       "--textmode", "--no-literal" );
	if (opt.set_filename)
	    log_error(_("%s makes no sense with %s!\n"),
			eyes_only?"--for-your-eyes-only":"--set-filename",
		        "--no-literal" );
    }

    if (opt.set_filesize)
	log_info(_("NOTE: %s is not for normal use!\n"), "--set-filesize");
    if( opt.batch )
	tty_batchmode( 1 );

    secmem_set_flags( secmem_get_flags() & ~2 ); /* resume warnings */

    set_debug();

    /* Do these after the switch(), so they can override settings. */
    if(opt.pgp2 && (opt.pgp6 || opt.pgp7))
      log_error(_("%s not allowed with %s!\n"),
		"--pgp2",opt.pgp6?"--pgp6":"--pgp7");
    else
      {
	if(opt.pgp2)
	  {
	    int unusable=0;

	    if(cmd==aSign && !detached_sig)
	      {
		log_info(_("you can only make detached or clear signatures "
			   "while in --pgp2 mode\n"));
		unusable=1;
	      }
	    else if(cmd==aSignEncr || cmd==aSignSym)
	      {
		log_info(_("you can't sign and encrypt at the "
			   "same time while in --pgp2 mode\n"));
		unusable=1;
	      }
	    else if(argc==0 && (cmd==aSign || cmd==aEncr || cmd==aSym))
	      {
		log_info(_("you must use files (and not a pipe) when "
			   "working with --pgp2 enabled.\n"));
		unusable=1;
	      }
	    else if(cmd==aEncr || cmd==aSym)
	      {
		/* Everything else should work without IDEA (except using
		   a secret key encrypted with IDEA and setting an IDEA
		   preference, but those have their own error
		   messages). */

		if(check_cipher_algo(CIPHER_ALGO_IDEA))
		  {
		    log_info(_("encrypting a message in --pgp2 mode requires "
			       "the IDEA cipher\n"));
		    idea_cipher_warn(1);
		    unusable=1;
		  }
		else if(cmd==aSym)
		  {
		    /* This only sets IDEA for symmetric encryption
		       since it is set via select_algo_from_prefs for
		       pk encryption. */
		    m_free(def_cipher_string);
		    def_cipher_string = m_strdup("idea");
		  }

		/* PGP2 can't handle the output from the textmode
		   filter, so we disable it for anything that could
		   create a literal packet (only encryption and
		   symmetric encryption, since we disable signing
		   above). */
		if(!unusable)
		  opt.textmode=0;
	      }

	    if(unusable)
	      {
		log_info(_("this message may not be usable by %s\n"),
			 "PGP 2.x");
		opt.pgp2=0;
	      }
	    else
	      {
		opt.rfc1991 = 1;
		opt.rfc2440 = 0;
		opt.force_mdc = 0;
		opt.disable_mdc = 1;
		opt.force_v4_certs = 0;
		opt.sk_comments = 0;
		opt.escape_from = 1;
		opt.force_v3_sigs = 1;
		opt.pgp2_workarounds = 1;
		opt.ask_sig_expire = 0;
		opt.ask_cert_expire = 0;
		m_free(def_digest_string);
		def_digest_string = m_strdup("md5");
		opt.def_compress_algo = 1;
	      }
	  }

	if(opt.pgp6 || opt.pgp7)
	  {
	    opt.sk_comments=0;
	    opt.escape_from=1;
	    opt.force_v3_sigs=1;
	    opt.ask_sig_expire=0;
	    opt.def_compress_algo=1;

	    if(opt.pgp6) /* pgp7 has MDC */
	      {
		opt.force_mdc=0;
		opt.disable_mdc=1;
	      }
	  }
      }

    /* must do this after dropping setuid, because string_to...
     * may try to load an module */
    if( def_cipher_string ) {
	opt.def_cipher_algo = string_to_cipher_algo(def_cipher_string);
	if(opt.def_cipher_algo==0 &&
	   ascii_strcasecmp(def_cipher_string,"idea")==0)
	  idea_cipher_warn(1);
	m_free(def_cipher_string); def_cipher_string = NULL;
	if( check_cipher_algo(opt.def_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( def_digest_string ) {
	opt.def_digest_algo = string_to_digest_algo(def_digest_string);
	m_free(def_digest_string); def_digest_string = NULL;
	if( check_digest_algo(opt.def_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( cert_digest_string ) {
	opt.cert_digest_algo = string_to_digest_algo(cert_digest_string);
	m_free(cert_digest_string); cert_digest_string = NULL;
	if( check_digest_algo(opt.cert_digest_algo) )
	    log_error(_("selected certification digest algorithm is invalid\n"));
    }
    if( s2k_cipher_string ) {
	opt.s2k_cipher_algo = string_to_cipher_algo(s2k_cipher_string);
	m_free(s2k_cipher_string); s2k_cipher_string = NULL;
	if( check_cipher_algo(opt.s2k_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( s2k_digest_string ) {
	opt.s2k_digest_algo = string_to_digest_algo(s2k_digest_string);
	m_free(s2k_digest_string); s2k_digest_string = NULL;
	if( check_digest_algo(opt.s2k_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( opt.def_compress_algo < -1 || opt.def_compress_algo > 2 )
	log_error(_("compress algorithm must be in range %d..%d\n"), 0, 2);
    if( opt.completes_needed < 1 )
	log_error(_("completes-needed must be greater than 0\n"));
    if( opt.marginals_needed < 2 )
	log_error(_("marginals-needed must be greater than 1\n"));
    if( opt.max_cert_depth < 1 || opt.max_cert_depth > 255 )
	log_error(_("max-cert-depth must be in range 1 to 255\n"));
    switch( opt.s2k_mode ) {
      case 0:
	log_info(_("NOTE: simple S2K mode (0) is strongly discouraged\n"));
	break;
      case 1: case 3: break;
      default:
	log_error(_("invalid S2K mode; must be 0, 1 or 3\n"));
    }

    if(opt.def_cert_check_level<0 || opt.def_cert_check_level>3)
      log_error(_("invalid default-check-level; must be 0, 1, 2, or 3\n"));

    /* This isn't actually needed, but does serve to error out if the
       string is invalid. */
    if(opt.def_preference_list &&
	keygen_set_std_prefs(opt.def_preference_list,0))
      log_error(_("invalid default preferences\n"));

    /* We provide defaults for the personal digest list */
    if(!pers_digest_list)
      pers_digest_list="h2";

    if(pers_cipher_list &&
       keygen_set_std_prefs(pers_cipher_list,PREFTYPE_SYM))
      log_error(_("invalid personal cipher preferences\n"));

    if(pers_digest_list &&
       keygen_set_std_prefs(pers_digest_list,PREFTYPE_HASH))
      log_error(_("invalid personal digest preferences\n"));

    if(pers_compress_list &&
       keygen_set_std_prefs(pers_compress_list,PREFTYPE_ZIP))
      log_error(_("invalid personal compress preferences\n"));

    if( log_get_errorcount(0) )
	g10_exit(2);

    /* set the random seed file */
    if( use_random_seed ) {
	char *p = make_filename(opt.homedir, "random_seed", NULL );
	set_random_seed_file(p);
	m_free(p);
    }

    if( !cmd && opt.fingerprint && !with_fpr ) {
	set_cmd( &cmd, aListKeys);
    }

    if( cmd == aKMode || cmd == aKModeC ) { /* kludge to be compatible to pgp */
	if( cmd == aKModeC ) {
	    opt.fingerprint = 1;
	    cmd = aKMode;
	}
	opt.list_sigs = 0;
	if( opt.verbose > 2 )
	    opt.check_sigs++;
	if( opt.verbose > 1 )
	    opt.list_sigs++;

	opt.verbose = opt.verbose > 1;
	g10_opt_verbose = opt.verbose;
    }

    /* Compression algorithm 0 means no compression at all */
    if( opt.def_compress_algo == 0)
        opt.compress = 0;

    /* kludge to let -sat generate a clear text signature */
    if( opt.textmode == 2 && !detached_sig && opt.armor && cmd == aSign )
	cmd = aClearsign;

    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    /* Add the keyrings, but not for some special commands and not in
       case of "-kvv userid keyring".  Also avoid adding the secret
       keyring for a couple of commands to avoid unneeded access in
       case the secrings are stored on a floppy */
    if( cmd != aDeArmor && cmd != aEnArmor
	&& !(cmd == aKMode && argc == 2 ) ) 
      {
        if (cmd != aCheckKeys && cmd != aListSigs && cmd != aListKeys
            && cmd != aVerify && cmd != aVerifyFiles
            && cmd != aSym)
          {
            if (!sec_nrings || default_keyring) /* add default secret rings */
              keydb_add_resource ("secring" EXTSEP_S "gpg", 0, 1);
            for (sl = sec_nrings; sl; sl = sl->next)
              keydb_add_resource ( sl->d, 0, 1 );
          }
	if( !nrings || default_keyring )  /* add default ring */
	    keydb_add_resource ("pubring" EXTSEP_S "gpg", 0, 0);
	for(sl = nrings; sl; sl = sl->next )
	    keydb_add_resource ( sl->d, 0, 0 );
      }
    FREE_STRLIST(nrings);
    FREE_STRLIST(sec_nrings);


    if( pwfd != -1 )  /* read the passphrase now. */
	read_passphrase_from_fd( pwfd );

    fname = argc? *argv : NULL;

    switch( cmd ) {
      case aPrimegen:
      case aPrintMD:
      case aPrintMDs:
      case aGenRandom:
      case aDeArmor:
      case aEnArmor:
      case aFixTrustDB:
	break;
      case aKMode:
      case aListKeys:
      case aListSecretKeys:
      case aCheckKeys:
	if( opt.with_colons ) /* need this to list the trust */
	    rc = setup_trustdb(1, trustdb_name );
	break;
      case aExportOwnerTrust: rc = setup_trustdb( 0, trustdb_name ); break;
      case aListTrustDB: rc = setup_trustdb( argc? 1:0, trustdb_name ); break;
      default: rc = setup_trustdb(1, trustdb_name ); break;
    }
    if( rc )
	log_error(_("failed to initialize the TrustDB: %s\n"), g10_errstr(rc));


    switch (cmd) {
      case aStore: 
      case aSym:  
      case aSign: 
      case aSignSym: 
      case aClearsign: 
        if (!opt.quiet && any_explicit_recipient)
          log_info (_("WARNING: recipients (-r) given "
                      "without using public key encryption\n"));
	break;
      default:
        break;
    }

    switch( cmd ) {
      case aStore: /* only store the file */
	if( argc > 1 )
	    wrong_args(_("--store [filename]"));
	if( (rc = encode_store(fname)) )
	    log_error_f( print_fname_stdin(fname),
			"store failed: %s\n", g10_errstr(rc) );
	break;
      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    wrong_args(_("--symmetric [filename]"));
	if( (rc = encode_symmetric(fname)) )
	    log_error_f(print_fname_stdin(fname),
			"symmetric encryption failed: %s\n",g10_errstr(rc) );
	break;

      case aEncr: /* encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--encrypt [filename]"));
	if( (rc = encode_crypt(fname,remusr)) )
	    log_error("%s: encryption failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aEncrFiles: /* encrypt the given files */
        encode_crypt_files(argc, argv, remusr);
    	break;
          
      case aSign: /* sign the given file */
	sl = NULL;
	if( detached_sig ) { /* sign all files */
	    for( ; argc; argc--, argv++ )
		add_to_strlist( &sl, *argv );
	}
	else {
	    if( argc > 1 )
		wrong_args(_("--sign [filename]"));
	    if( argc ) {
		sl = m_alloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	    }
	}
	if( (rc = sign_file( sl, detached_sig, locusr, 0, NULL, NULL)) )
	    log_error("signing failed: %s\n", g10_errstr(rc) );
	free_strlist(sl);
	break;

      case aSignEncr: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--sign --encrypt [filename]"));
	if( argc ) {
	    sl = m_alloc_clear( sizeof *sl + strlen(fname));
	    strcpy(sl->d, fname);
	}
	else
	    sl = NULL;
	if( (rc = sign_file(sl, detached_sig, locusr, 1, remusr, NULL)) )
	    log_error("%s: sign+encrypt failed: %s\n", print_fname_stdin(fname), g10_errstr(rc) );
	free_strlist(sl);
	break;

      case aSignSym: /* sign and conventionally encrypt the given file */
	if (argc > 1)
	    wrong_args(_("--sign --symmetric [filename]"));
	rc = sign_symencrypt_file (fname, locusr);
        if (rc)
	    log_error("%s: sign+symmetric failed: %s\n",
                      print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aClearsign: /* make a clearsig */
	if( argc > 1 )
	    wrong_args(_("--clearsign [filename]"));
	if( (rc = clearsign_file(fname, locusr, NULL)) )
	    log_error("%s: clearsign failed: %s\n",
                      print_fname_stdin(fname), g10_errstr(rc) );
	break;

      case aVerify:
	if( (rc = verify_signatures( argc, argv ) ))
	    log_error("verify signatures failed: %s\n", g10_errstr(rc) );
	break;

      case aVerifyFiles:
	if( (rc = verify_files( argc, argv ) ))
	    log_error("verify files failed: %s\n", g10_errstr(rc) );
	break;

      case aDecrypt:
	if( argc > 1 )
	    wrong_args(_("--decrypt [filename]"));
	if( (rc = decrypt_message( fname ) ))
	    log_error("decrypt_message failed: %s\n", g10_errstr(rc) );
	break;

      case aDecryptFiles:
        decrypt_messages(argc, argv);
        break;
            
      case aSignKey: /* sign the key given as argument */
	if( argc != 1 )
	    wrong_args(_("--sign-key user-id"));
	username = make_username( fname );
	keyedit_menu(fname, locusr, NULL, 1 );
	m_free(username);
	break;

      case aLSignKey:
	if( argc != 1 )
	    wrong_args(_("--lsign-key user-id"));
	username = make_username( fname );
	keyedit_menu(fname, locusr, NULL, 2 );
	m_free(username);
	break;

      case aNRSignKey:
	if( argc != 1 )
	    wrong_args(_("--nrsign-key user-id"));
	username = make_username( fname );
	keyedit_menu(fname, locusr, NULL, 3 );
        m_free(username);
        break;

      case aNRLSignKey:
	if( argc != 1 )
	    wrong_args(_("--nrlsign-key user-id"));
	username = make_username( fname );
	keyedit_menu(fname, locusr, NULL, 4 );
        m_free(username);
        break;

      case aEditKey: /* Edit a key signature */
	if( !argc )
	    wrong_args(_("--edit-key user-id [commands]"));
	username = make_username( fname );
	if( argc > 1 ) {
	    sl = NULL;
	    for( argc--, argv++ ; argc; argc--, argv++ )
		append_to_strlist( &sl, *argv );
	    keyedit_menu( username, locusr, sl, 0 );
	    free_strlist(sl);
	}
	else
	    keyedit_menu(username, locusr, NULL, 0 );
	m_free(username);
	break;

      case aDeleteKeys:
      case aDeleteSecretKeys:
      case aDeleteSecretAndPublicKeys:
	sl = NULL;
	/* I'm adding these in reverse order as add_to_strlist2
           reverses them again, and it's easier to understand in the
           proper order :) */
	for( ; argc; argc-- )
	  add_to_strlist2( &sl, argv[argc-1], utf8_strings );
	delete_keys(sl,cmd==aDeleteSecretKeys,cmd==aDeleteSecretAndPublicKeys);
	free_strlist(sl);
	break;

      case aCheckKeys:
	opt.check_sigs = 1;
      case aListSigs:
	opt.list_sigs = 1;
      case aListKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	public_key_list( sl );
	free_strlist(sl);
	break;
      case aListSecretKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	secret_key_list( sl );
	free_strlist(sl);
	break;

      case aKMode: /* list keyring -- NOTE: This will be removed soon */
	if( argc < 2 ) { /* -kv [userid] */
	    sl = NULL;
	    if (argc && **argv)
		add_to_strlist2( &sl, *argv, utf8_strings );
	    public_key_list( sl );
	    free_strlist(sl);
	}
	else if( argc == 2 ) { /* -kv userid keyring */
	    if( access( argv[1], R_OK ) ) {
		log_error(_("can't open %s: %s\n"),
			       print_fname_stdin(argv[1]), strerror(errno));
	    }
	    else {
		/* add keyring (default keyrings are not registered in this
		 * special case */
		keydb_add_resource( argv[1], 0, 0 );
		sl = NULL;
		if (**argv)
		    add_to_strlist2( &sl, *argv, utf8_strings );
		public_key_list( sl );
		free_strlist(sl);
	    }
	}
	else
	    wrong_args(_("-k[v][v][v][c] [user-id] [keyring]") );
	break;

      case aKeygen: /* generate a key */
	if( opt.batch ) {
	    if( argc > 1 )
		wrong_args("--gen-key [parameterfile]");
	    generate_keypair( argc? *argv : NULL );
	}
	else {
	    if( argc )
		wrong_args("--gen-key");
	    generate_keypair(NULL);
	}
	break;

      case aFastImport:
      case aImport:
	import_keys( argc? argv:NULL, argc, (cmd == aFastImport),
		     NULL, opt.import_options );
	break;

      case aExport:
      case aExportAll:
      case aSendKeys:
      case aRecvKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	if( cmd == aSendKeys )
	    keyserver_export( sl );
	else if( cmd == aRecvKeys )
	    keyserver_import( sl );
	else
	    export_pubkeys( sl, opt.export_options );
	free_strlist(sl);
	break;

     case aSearchKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	  append_to_strlist2( &sl, *argv, utf8_strings );

	keyserver_search( sl );
	free_strlist(sl);
	break;

      case aRefreshKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	keyserver_refresh(sl);
	free_strlist(sl);
	break;

      case aExportSecret:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	export_seckeys( sl );
	free_strlist(sl);
	break;

      case aExportSecretSub:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	export_secsubkeys( sl );
	free_strlist(sl);
	break;

      case aGenRevoke:
	if( argc != 1 )
	    wrong_args("--gen-revoke user-id");
	username =  make_username(*argv);
	gen_revoke( username );
	m_free( username );
	break;

      case aDesigRevoke:
	if( argc != 1 )
	    wrong_args("--desig-revoke user-id");
	username =  make_username(*argv);
	gen_desig_revoke( username );
	m_free( username );
	break;

      case aDeArmor:
	if( argc > 1 )
	    wrong_args("--dearmor [file]");
	rc = dearmor_file( argc? *argv: NULL );
	if( rc )
	    log_error(_("dearmoring failed: %s\n"), g10_errstr(rc));
	break;

      case aEnArmor:
	if( argc > 1 )
	    wrong_args("--enarmor [file]");
	rc = enarmor_file( argc? *argv: NULL );
	if( rc )
	    log_error(_("enarmoring failed: %s\n"), g10_errstr(rc));
	break;


      case aPrimegen:
	{   int mode = argc < 2 ? 0 : atoi(*argv);

	    if( mode == 1 && argc == 2 ) {
		mpi_print( stdout, generate_public_prime( atoi(argv[1]) ), 1);
	    }
	    else if( mode == 2 && argc == 3 ) {
		mpi_print( stdout, generate_elg_prime(
					     0, atoi(argv[1]),
					     atoi(argv[2]), NULL,NULL ), 1);
	    }
	    else if( mode == 3 && argc == 3 ) {
		MPI *factors;
		mpi_print( stdout, generate_elg_prime(
					     1, atoi(argv[1]),
					     atoi(argv[2]), NULL,&factors ), 1);
		putchar('\n');
		mpi_print( stdout, factors[0], 1 ); /* print q */
	    }
	    else if( mode == 4 && argc == 3 ) {
		MPI g = mpi_alloc(1);
		mpi_print( stdout, generate_elg_prime(
						 0, atoi(argv[1]),
						 atoi(argv[2]), g, NULL ), 1);
		putchar('\n');
		mpi_print( stdout, g, 1 );
		mpi_free(g);
	    }
	    else
		wrong_args("--gen-prime mode bits [qbits] ");
	    putchar('\n');
	}
	break;

      case aGenRandom:
	{
	    int level = argc ? atoi(*argv):0;
	    int count = argc > 1 ? atoi(argv[1]): 0;
	    int endless = !count;

	    if( argc < 1 || argc > 2 || level < 0 || level > 2 || count < 0 )
		wrong_args("--gen-random 0|1|2 [count]");

	    while( endless || count ) {
		byte *p;
                /* Wee need a multiple of 3, so that in case of
                   armored output we get a correct string.  No
                   linefolding is done, as it is best to levae this to
                   other tools */
		size_t n = !endless && count < 99? count : 99;

		p = get_random_bits( n*8, level, 0);
	      #ifdef HAVE_DOSISH_SYSTEM
		setmode ( fileno(stdout), O_BINARY );
	      #endif
                if (opt.armor) {
                    char *tmp = make_radix64_string (p, n);
                    fputs (tmp, stdout);
                    m_free (tmp);
                    if (n%3 == 1)
                      putchar ('=');
                    if (n%3)
                      putchar ('=');
                } else {
                    fwrite( p, n, 1, stdout );
                }
		m_free(p);
		if( !endless )
		    count -= n;
	    }
            if (opt.armor)
                putchar ('\n');
	}
	break;

      case aPrintMD:
	if( argc < 1)
	    wrong_args("--print-md algo [files]");
	{
	    int all_algos = (**argv=='*' && !(*argv)[1]);
	    int algo = all_algos? 0 : string_to_digest_algo(*argv);

	    if( !algo && !all_algos )
		log_error(_("invalid hash algorithm `%s'\n"), *argv );
	    else {
		argc--; argv++;
		if( !argc )
		    print_mds(NULL, algo);
		else {
		    for(; argc; argc--, argv++ )
			print_mds(*argv, algo);
		}
	    }
	}
	break;

      case aPrintMDs: /* old option */
	if( !argc )
	    print_mds(NULL,0);
	else {
	    for(; argc; argc--, argv++ )
		print_mds(*argv,0);
	}
	break;

      case aListTrustDB:
	if( !argc )
	    list_trustdb(NULL);
	else {
	    for( ; argc; argc--, argv++ )
		list_trustdb( *argv );
	}
	break;

      case aUpdateTrustDB:
	if( argc )
	    wrong_args("--update-trustdb");
	update_trustdb();
	break;

      case aCheckTrustDB:
        /* Old versions allowed for arguments - ignore them */
        check_trustdb();
	break;

      case aFixTrustDB:
	log_error("this command is not yet implemented.\n");
	log_error("A workaround is to use \"--export-ownertrust\", remove\n");
	log_error("the trustdb file and do an \"--import-ownertrust\".\n" );
	break;

      case aListTrustPath:
	if( !argc )
	    wrong_args("--list-trust-path <user-ids>");
	for( ; argc; argc--, argv++ ) {
	    username = make_username( *argv );
	    list_trust_path( username );
	    m_free(username);
	}
	break;

      case aExportOwnerTrust:
	if( argc )
	    wrong_args("--export-ownertrust");
	export_ownertrust();
	break;

      case aImportOwnerTrust:
	if( argc > 1 )
	    wrong_args("--import-ownertrust [file]");
	import_ownertrust( argc? *argv:NULL );
	break;
      
      case aPipeMode:
        if ( argc )
            wrong_args ("--pipemode");
        run_in_pipemode ();
        break;

      case aRebuildKeydbCaches:
        if (argc)
            wrong_args ("--rebuild-keydb-caches");
        keydb_rebuild_caches ();
        break;

      case aListPackets:
	opt.list_packets=2;
      default:
	if( argc > 1 )
	    wrong_args(_("[filename]"));
	/* Issue some output for the unix newbie */
	if( !fname && !opt.outfile && isatty( fileno(stdin) )
		&& isatty( fileno(stdout) ) && isatty( fileno(stderr) ) )
	    log_info(_("Go ahead and type your message ...\n"));

	if( !(a = iobuf_open(fname)) )
	    log_error(_("can't open `%s'\n"), print_fname_stdin(fname));
	else {

	    if( !opt.no_armor ) {
		if( use_armor_filter( a ) ) {
		    memset( &afx, 0, sizeof afx);
		    iobuf_push_filter( a, armor_filter, &afx );
		}
	    }
	    if( cmd == aListPackets ) {
		set_packet_list_mode(1);
		opt.list_packets=1;
	    }
	    rc = proc_packets(NULL, a );
	    if( rc )
		log_error("processing message failed: %s\n", g10_errstr(rc) );
	    iobuf_close(a);
	}
	break;
    }

    /* cleanup */
    FREE_STRLIST(remusr);
    FREE_STRLIST(locusr);
    g10_exit(0);
    return 8; /*NEVER REACHED*/
}


void
g10_exit( int rc )
{
    update_random_seed_file();
    if( opt.debug & DBG_MEMSTAT_VALUE ) {
	m_print_stats("on exit");
	random_dump_stats();
    }
    if( opt.debug )
	secmem_dump_stats();
    secmem_term();
    rc = rc? rc : log_get_errorcount(0)? 2 :
			g10_errors_seen? 1 : 0;
    exit(rc );
}




static void
print_hex( byte *p, size_t n )
{
    int i;

    if( n == 20 ) {
	for(i=0; i < n ; i++, i++, p += 2 ) {
	    if( i )
		putchar(' ');
	    if( i == 10 )
		putchar(' ');
	    printf("%02X%02X", *p, p[1] );
	}
    }
    else if( n == 24 ) {
	for(i=0; i < n ; i += 4, p += 4 ) {
	    if( i )
		putchar(' ');
	    if( i == 12 )
		putchar(' ');
	    printf("%02X%02X%02X%02X", *p, p[1], p[2], p[3] );
	}
    }
    else {
	for(i=0; i < n ; i++, p++ ) {
	    if( i )
		putchar(' ');
	    if( i && !(i%8) )
		putchar(' ');
	    printf("%02X", *p );
	}
    }
}

static void
print_hashline( MD_HANDLE md, int algo, const char *fname )
{
    int i, n;
    const byte *p;
    
    if ( fname ) {
        for (p = fname; *p; p++ ) {
            if ( *p <= 32 || *p > 127 || *p == ':' || *p == '%' )
                printf("%%%02X", *p );
            else 
                putchar( *p );
        }
    }
    putchar(':');
    printf("%d:", algo );
    p = md_read( md, algo );
    n = md_digest_length(algo);
    for(i=0; i < n ; i++, p++ ) 
        printf("%02X", *p );
    putchar(':');
    putchar('\n');
}

static void
print_mds( const char *fname, int algo )
{
    FILE *fp;
    char buf[1024];
    size_t n;
    MD_HANDLE md;
    char *pname;

    if( !fname ) {
	fp = stdin;
      #ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
      #endif
	pname = m_strdup("[stdin]: ");
    }
    else {
	pname = m_alloc(strlen(fname)+3);
	strcpy(stpcpy(pname,fname),": ");
	fp = fopen( fname, "rb" );
    }
    if( !fp ) {
	log_error("%s%s\n", pname, strerror(errno) );
	m_free(pname);
	return;
    }

    md = md_open( 0, 0 );
    if( algo )
	md_enable( md, algo );
    else {
	md_enable( md, DIGEST_ALGO_MD5 );
	md_enable( md, DIGEST_ALGO_SHA1 );
	md_enable( md, DIGEST_ALGO_RMD160 );
	if( !check_digest_algo(DIGEST_ALGO_TIGER) )
	    md_enable( md, DIGEST_ALGO_TIGER );
    }

    while( (n=fread( buf, 1, DIM(buf), fp )) )
	md_write( md, buf, n );
    if( ferror(fp) )
	log_error("%s%s\n", pname, strerror(errno) );
    else {
	md_final(md);
        if ( opt.with_colons ) {
            if ( algo ) 
                print_hashline( md, algo, fname );
            else {
                print_hashline( md, DIGEST_ALGO_MD5, fname );
                print_hashline( md, DIGEST_ALGO_SHA1, fname );
                print_hashline( md, DIGEST_ALGO_RMD160, fname );
                if( !check_digest_algo(DIGEST_ALGO_TIGER) ) 
                    print_hashline( md, DIGEST_ALGO_TIGER, fname );
            }
        }
        else {
            if( algo ) {
                if( fname )
                    fputs( pname, stdout );
                print_hex(md_read(md, algo), md_digest_length(algo) );
            }
            else {
                printf(  "%s   MD5 = ", fname?pname:"" );
                print_hex(md_read(md, DIGEST_ALGO_MD5), 16 );
                printf("\n%s  SHA1 = ", fname?pname:""  );
                print_hex(md_read(md, DIGEST_ALGO_SHA1), 20 );
                printf("\n%sRMD160 = ", fname?pname:""  );
                print_hex(md_read(md, DIGEST_ALGO_RMD160), 20 );
                if( !check_digest_algo(DIGEST_ALGO_TIGER) ) {
                    printf("\n%s TIGER = ", fname?pname:""  );
                    print_hex(md_read(md, DIGEST_ALGO_TIGER), 24 );
                }
            }
            putchar('\n');
        }
    }
    md_close(md);

    if( fp != stdin )
	fclose(fp);
}


/****************
 * Check the supplied name,value string and add it to the notation
 * data to be used for signatures.  which==0 for sig notations, and 1
 * for cert notations.
*/
static void
add_notation_data( const char *string, int which )
{
    const char *s;
    STRLIST sl,*notation_data;
    int critical=0;
    int highbit=0;

    if(which)
      notation_data=&opt.cert_notation_data;
    else
      notation_data=&opt.sig_notation_data;

    if( *string == '!' ) {
	critical = 1;
	string++;
    }

    for( s=string ; *s != '='; s++ ) {
	if( !*s || (*s & 0x80) || (!isgraph(*s) && !isspace(*s)) ) {
	    log_error(_("a notation name must have only printable characters "
			"or spaces, and end with an '='\n") );
	    return;
	}
    }
    /* we only support printable text - therefore we enforce the use
     * of only printable characters (an empty value is valid) */
    for( s++; *s ; s++ ) {
	if( iscntrl(*s) ) {
	    log_error(_("a notation value must not use "
			"any control characters\n") );
	    return;
	}
	else if( *s & 0x80 )
	    highbit = 1;
    }

    if( highbit )   /* must use UTF8 encoding */
	sl = add_to_strlist2( notation_data, string, utf8_strings );
    else
	sl = add_to_strlist( notation_data, string );

    if( critical )
	sl->flags |= 1;
}


static void
add_policy_url( const char *string, int which )
{
  int i,critical=0;
  STRLIST sl;

  if(*string=='!')
    {
      string++;
      critical=1;
    }

  for(i=0;i<strlen(string);i++)
    if(string[i]&0x80 || iscntrl(string[i]))
      break;

  if(i==0 || i<strlen(string))
    {
      if(which)
	log_error(_("the given certification policy URL is invalid\n"));
      else
	log_error(_("the given signature policy URL is invalid\n"));
    }

  if(which)
    sl=add_to_strlist( &opt.cert_policy_url, string );
  else
    sl=add_to_strlist( &opt.sig_policy_url, string );

  if(critical)
    sl->flags |= 1;    
}
