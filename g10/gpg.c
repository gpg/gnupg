/* gpg.c - The GnuPG utility (main for gpg)
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2008 Free Software Foundation, Inc.
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
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#ifdef HAVE_DOSISH_SYSTEM
#include <fcntl.h> /* for setmode() */
#endif
#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif
#include <fcntl.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
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
#include "keyserver-internal.h"
#include "exec.h"
#include "cardglue.h"
#ifdef ENABLE_CARD_SUPPORT
#include "ccid-driver.h"
#endif

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
#define MY_O_BINARY  O_BINARY
#ifndef S_IRGRP
# define S_IRGRP 0
# define S_IWGRP 0
#endif
#else
#define MY_O_BINARY  0
#endif


enum cmd_and_opt_values
  {
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
    oHiddenRecipient = 'R',
    aSign	  = 's',
    oTextmodeShort= 't',
    oLocalUser	  = 'u',
    oVerbose	  = 'v',
    oCompress	  = 'z',
    oSetNotation  = 'N',
    aListSecretKeys = 'K',
    oBatch	  = 500,
    oMaxOutput,
    oSigNotation,
    oCertNotation,
    oShowNotation,
    oNoShowNotation,
    aEncrFiles,
    aEncrSym,
    aDecryptFiles,
    aClearsign,
    aStore,
    aKeygen,
    aSignEncr,
    aSignEncrSym,
    aSignSym,
    aSignKey,
    aLSignKey,
    aListConfig,
    aGPGConfList,
    aGPGConfTest,
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
    aSendKeys,
    aRecvKeys,
    aSearchKeys,
    aRefreshKeys,
    aFetchKeys,
    aExport,
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
    aListOwnerTrust,
    aImportOwnerTrust,
    aDeArmor,
    aEnArmor,
    aGenRandom,
    aPipeMode,
    aRebuildKeydbCaches,
    aCardStatus,
    aCardEdit,
    aChangePIN,

    oTextmode,
    oNoTextmode,
    oExpert,
    oNoExpert,
    oDefSigExpire,
    oAskSigExpire,
    oNoAskSigExpire,
    oDefCertExpire,
    oAskCertExpire,
    oNoAskCertExpire,
    oDefCertLevel,
    oMinCertLevel,
    oAskCertLevel,
    oNoAskCertLevel,
    oFingerprint,
    oWithFingerprint,
    oAnswerYes,
    oAnswerNo,
    oKeyring,
    oPrimaryKeyring,
    oSecretKeyring,
    oShowKeyring,
    oDefaultKey,
    oDefRecipient,
    oDefRecipientSelf,
    oNoDefRecipient,
    oOptions,
    oDebug,
    oDebugAll,
    oDebugCCIDDriver,
    oStatusFD,
    oStatusFile,
    oAttributeFD,
    oAttributeFile,
    oEmitVersion,
    oNoEmitVersion,
    oCompletesNeeded,
    oMarginalsNeeded,
    oMaxCertDepth,
    oLoadExtension,
    oGnuPG,
    oRFC1991,
    oRFC2440,
    oRFC4880,
    oOpenPGP,
    oPGP2,
    oPGP6,
    oPGP7,
    oPGP8,
    oRFC2440Text,
    oNoRFC2440Text,
    oCipherAlgo,
    oDigestAlgo,
    oCertDigestAlgo,
    oCompressAlgo,
    oCompressLevel,
    oBZ2CompressLevel,
    oBZ2DecompressLowmem,
    oPasswd,
    oPasswdFD,
    oPasswdFile,
    oPasswdRepeat,
    oCommandFD,
    oCommandFile,
    oQuickRandom,
    oNoVerbose,
    oTrustDBName,
    oNoSecmemWarn,
    oRequireSecmem,
    oNoRequireSecmem,
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
    oTrustModel,
    oForceOwnertrust,
    oRunAsShmCP,
    oSetFilename,
    oForYourEyesOnly,
    oNoForYourEyesOnly,
    oSetPolicyURL,
    oSigPolicyURL,
    oCertPolicyURL,
    oShowPolicyURL,
    oNoShowPolicyURL,
    oSigKeyserverURL,
    oUseEmbeddedFilename,
    oNoUseEmbeddedFilename,
    oComment,
    oDefaultComment,
    oNoComments,
    oThrowKeyids,
    oNoThrowKeyids,
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
    oS2KCount,
    oSimpleSKChecksum,                          
    oDisplayCharset,
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
    oListOptions,
    oVerifyOptions,
    oTempDir,
    oExecPath,
    oEncryptTo,
    oHiddenEncryptTo,
    oNoEncryptTo,
    oLoggerFD,
    oLoggerFile,
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
    oDefaultKeyserverURL,
    oPersonalCipherPreferences,
    oPersonalDigestPreferences,
    oPersonalCompressPreferences,
    oDisplay,
    oTTYname,
    oTTYtype,
    oLCctype,
    oLCmessages,
    oGroup,
    oUnGroup,
    oNoGroups,
    oStrict,
    oNoStrict,
    oMangleDosFilenames,
    oNoMangleDosFilenames,
    oEnableProgressFilter,
    oMultifile,
    oKeyidFormat,
    oExitOnStatusWriteError,
    oLimitCardInsertTries,
    oReaderPort,
    octapiDriver,
    opcscDriver,
    oDisableCCID,
    oRequireCrossCert,
    oNoRequireCrossCert,
    oAutoKeyLocate,
    oNoAutoKeyLocate,
    oAllowMultisigVerification,
    oEnableDSA2,
    oDisableDSA2,
    oAllowMultipleMessages,
    oNoAllowMultipleMessages,

    oNoop
  };


static ARGPARSE_OPTS opts[] = {

    { 300, NULL, 0, N_("@Commands:\n ") },

    { aSign, "sign",      256, N_("|[file]|make a signature")},
    { aClearsign, "clearsign", 256, N_("|[file]|make a clear text signature")},
    { aDetachedSign, "detach-sign", 256, N_("make a detached signature")},
    { aEncr, "encrypt",   256, N_("encrypt data")},
    { aEncrFiles, "encrypt-files", 256, "@"},
    { aSym, "symmetric", 256, N_("encryption only with symmetric cipher")},
    { aStore, "store",     256, "@"},
    { aDecrypt, "decrypt",   256, N_("decrypt data (default)")},
    { aDecryptFiles, "decrypt-files", 256, "@"},
    { aVerify, "verify"   , 256, N_("verify a signature")},
    { aVerifyFiles, "verify-files" , 256, "@" },
    { aListKeys, "list-keys", 256, N_("list keys")},
    { aListKeys, "list-public-keys", 256, "@" },
    { aListSigs, "list-sigs", 256, N_("list keys and signatures")},
    { aCheckKeys, "check-sigs",256, N_("list and check key signatures")},
    { oFingerprint, "fingerprint", 256, N_("list keys and fingerprints")},
    { aListSecretKeys, "list-secret-keys", 256, N_("list secret keys")},
    { aKeygen,	   "gen-key",  256, N_("generate a new key pair")},
    { aDeleteKeys,"delete-keys",256,N_("remove keys from the public keyring")},
    { aDeleteSecretKeys, "delete-secret-keys",256,
				    N_("remove keys from the secret keyring")},
    { aSignKey,  "sign-key"   ,256, N_("sign a key")},
    { aLSignKey, "lsign-key"  ,256, N_("sign a key locally")},
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
    { aFetchKeys, "fetch-keys" , 256, "@" },
    { aExportSecret, "export-secret-keys" , 256, "@" },
    { aExportSecretSub, "export-secret-subkeys" , 256, "@" },
    { aImport, "import",      256     , N_("import/merge keys")},
    { aFastImport, "fast-import",  256 , "@"},
#ifdef ENABLE_CARD_SUPPORT
    { aCardStatus,  "card-status", 256, N_("print the card status")},
    { aCardEdit,   "card-edit",  256, N_("change data on a card")},
    { aChangePIN,  "change-pin", 256, N_("change a card's PIN")},
#endif
    { aListConfig, "list-config", 256, "@"},
    { aGPGConfList, "gpgconf-list", 256, "@" },
    { aGPGConfTest, "gpgconf-test", 256, "@" },
    { aListPackets, "list-packets",256, "@"},
    { aExportOwnerTrust, "export-ownertrust", 256, "@"},
    { aImportOwnerTrust, "import-ownertrust", 256, "@"},
    { aUpdateTrustDB,
	      "update-trustdb",0 , N_("update the trust database")},
    { aCheckTrustDB, "check-trustdb", 0, "@"},
    { aFixTrustDB, "fix-trustdb", 0, "@"},
    { aDeArmor, "dearmor", 256, "@"},
    { aDeArmor, "dearmour", 256, "@"},
    { aEnArmor, "enarmor", 256, "@"},
    { aEnArmor, "enarmour", 256, "@"},
    { aPrintMD,  "print-md" , 256, N_("|algo [files]|print message digests")},
    { aPrimegen, "gen-prime" , 256, "@" },
    { aGenRandom, "gen-random" , 256, "@" },

    { 301, NULL, 0, N_("@\nOptions:\n ") },

    { oArmor, "armor",     0, N_("create ascii armored output")},
    { oArmor, "armour",     0, "@" },
    { oRecipient, "recipient", 2, N_("|NAME|encrypt for NAME")},
    { oHiddenRecipient, "hidden-recipient", 2, "@" },
    { oRecipient, "remote-user", 2, "@"},  /* old option name */
    { oDefRecipient, "default-recipient", 2, "@"},
    { oDefRecipientSelf, "default-recipient-self", 0, "@"},
    { oNoDefRecipient, "no-default-recipient", 0, "@" },
    { oTempDir, "temp-directory", 2, "@" },
    { oExecPath, "exec-path", 2, "@" },
    { oEncryptTo, "encrypt-to", 2, "@" },
    { oHiddenEncryptTo, "hidden-encrypt-to", 2, "@" },
    { oNoEncryptTo, "no-encrypt-to", 0, "@" },
    { oLocalUser, "local-user",2, N_("use this user-id to sign or decrypt")},
    { oCompress, NULL, 1, N_("|N|set compress level N (0 disables)") },
    { oCompressLevel, "compress-level", 1, "@" },
    { oBZ2CompressLevel, "bzip2-compress-level", 1, "@" },
    { oBZ2DecompressLowmem, "bzip2-decompress-lowmem", 0, "@" },
    { oTextmodeShort, NULL,   0, "@"},
    { oTextmode, "textmode",  0, N_("use canonical text mode")},
    { oNoTextmode, "no-textmode",  0, "@"},
    { oExpert, "expert",   0, "@"},
    { oNoExpert, "no-expert",   0, "@"},
    { oDefSigExpire, "default-sig-expire", 2, "@"},
    { oAskSigExpire, "ask-sig-expire",   0, "@"},
    { oNoAskSigExpire, "no-ask-sig-expire",   0, "@"},
    { oDefCertExpire, "default-cert-expire", 2, "@"},
    { oAskCertExpire, "ask-cert-expire",   0, "@"},
    { oNoAskCertExpire, "no-ask-cert-expire",   0, "@"},
    { oDefCertLevel, "default-cert-level", 1, "@"},
    { oMinCertLevel, "min-cert-level", 1, "@"},
    { oAskCertLevel, "ask-cert-level",   0, "@"},
    { oNoAskCertLevel, "no-ask-cert-level",   0, "@"},
    { oOutput, "output",    2, N_("use as output file")},
    { oMaxOutput, "max-output", 16|4, "@" },
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",   0, "@"},
    { oNoTTY, "no-tty", 0, "@"},
    { oForceV3Sigs, "force-v3-sigs", 0, "@"},
    { oNoForceV3Sigs, "no-force-v3-sigs", 0, "@"},
    { oForceV4Certs, "force-v4-certs", 0, "@"},
    { oNoForceV4Certs, "no-force-v4-certs", 0, "@"},
    { oForceMDC, "force-mdc", 0, "@"},
    { oNoForceMDC, "no-force-mdc", 0, "@" },
    { oDisableMDC, "disable-mdc", 0, "@"},
    { oNoDisableMDC, "no-disable-mdc", 0, "@" },
    { oDryRun, "dry-run",   0, N_("do not make any changes") },
    { oInteractive, "interactive", 0, N_("prompt before overwriting") },
    { oUseAgent, "use-agent",0, "@"},
    { oNoUseAgent, "no-use-agent",0, "@"},
    { oGpgAgentInfo, "gpg-agent-info",2, "@"},
    { oBatch, "batch", 0, "@"},
    { oAnswerYes, "yes", 0, "@"},
    { oAnswerNo, "no", 0, "@"},
    { oKeyring, "keyring", 2, "@"},
    { oPrimaryKeyring, "primary-keyring",2, "@" },
    { oSecretKeyring, "secret-keyring", 2, "@"},
    { oShowKeyring, "show-keyring", 0, "@"},
    { oDefaultKey, "default-key", 2, "@"},
    { oKeyServer, "keyserver", 2, "@"},
    { oKeyServerOptions, "keyserver-options",2,"@"},
    { oImportOptions, "import-options",2,"@"},
    { oExportOptions, "export-options",2,"@"},
    { oListOptions, "list-options",2,"@"},
    { oVerifyOptions, "verify-options",2,"@"},
    { oDisplayCharset, "display-charset", 2, "@"},
    { oDisplayCharset, "charset", 2, "@"},
    { oOptions, "options", 2, "@"},
    { oDebug, "debug"     ,4|16, "@"},
    { oDebugAll, "debug-all" ,0, "@"},
    { oStatusFD, "status-fd" ,1, "@"},
    { oStatusFile, "status-file" ,2, "@"},
    { oAttributeFD, "attribute-fd" ,1, "@" },
    { oAttributeFile, "attribute-file" ,2, "@" },
    { oNoop, "sk-comments", 0,   "@"},
    { oNoop, "no-sk-comments", 0,   "@"},
    { oCompletesNeeded, "completes-needed", 1, "@"},
    { oMarginalsNeeded, "marginals-needed", 1, "@"},
    { oMaxCertDepth,	"max-cert-depth", 1, "@" },
    { oTrustedKey, "trusted-key", 2, "@"},
    { oLoadExtension, "load-extension", 2, "@"},
    { oGnuPG, "gnupg",   0, "@"},
    { oGnuPG, "no-pgp2", 0, "@"},
    { oGnuPG, "no-pgp6", 0, "@"},
    { oGnuPG, "no-pgp7", 0, "@"},
    { oGnuPG, "no-pgp8", 0, "@"},
    { oRFC1991, "rfc1991",   0, "@"},
    { oRFC2440, "rfc2440", 0, "@" },
    { oRFC4880, "rfc4880", 0, "@" },
    { oOpenPGP, "openpgp", 0, N_("use strict OpenPGP behavior")},
    { oPGP2, "pgp2", 0, N_("generate PGP 2.x compatible messages")},
    { oPGP6, "pgp6", 0, "@"},
    { oPGP7, "pgp7", 0, "@"},
    { oPGP8, "pgp8", 0, "@"},
    { oRFC2440Text, "rfc2440-text", 0, "@"},
    { oNoRFC2440Text, "no-rfc2440-text", 0, "@"},
    { oS2KMode, "s2k-mode", 1, "@"},
    { oS2KDigest, "s2k-digest-algo", 2, "@"},
    { oS2KCipher, "s2k-cipher-algo", 2, "@"},
    { oS2KCount, "s2k-count", 1, "@"},
    { oSimpleSKChecksum, "simple-sk-checksum", 0, "@"},
    { oCipherAlgo, "cipher-algo", 2, "@"},
    { oDigestAlgo, "digest-algo", 2, "@"},
    { oCertDigestAlgo, "cert-digest-algo", 2 , "@" },
    { oCompressAlgo,"compress-algo", 2, "@"},
    { oCompressAlgo, "compression-algo", 2, "@"}, /* Alias */
    { oThrowKeyids, "throw-keyid", 0, "@"},
    { oThrowKeyids, "throw-keyids", 0, "@"},
    { oNoThrowKeyids, "no-throw-keyid", 0, "@" },
    { oNoThrowKeyids, "no-throw-keyids", 0, "@" },
    { oShowPhotos,   "show-photos", 0, "@" },
    { oNoShowPhotos, "no-show-photos", 0, "@" },
    { oPhotoViewer,  "photo-viewer", 2, "@" },
    { oSetNotation,  "set-notation", 2, "@" },
    { oSetNotation,  "notation-data", 2, "@" }, /* Alias */
    { oSigNotation,  "sig-notation", 2, "@" },
    { oCertNotation, "cert-notation", 2, "@" },

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
    { aListOwnerTrust, "list-ownertrust", 256, "@"}, /* deprecated */
    { aPrintMDs, "print-mds" , 256, "@"}, /* old */
    { aListTrustDB, "list-trustdb",0 , "@"},
    /* Not yet used */
    /* { aListTrustPath, "list-trust-path",0, "@"}, */
    { aPipeMode,  "pipemode", 0, "@" },
    { oKOption, NULL,	 0, "@"},
    { oPasswd, "passphrase",2, "@" },
    { oPasswdFD, "passphrase-fd",1, "@" },
    { oPasswdFile, "passphrase-file",2, "@" },
    { oPasswdRepeat, "passphrase-repeat", 1, "@"},
    { oCommandFD, "command-fd",1, "@" },
    { oCommandFile, "command-file",2, "@" },
    { oQuickRandom, "quick-random", 0, "@"},
    { oNoVerbose, "no-verbose", 0, "@"},
    { oTrustDBName, "trustdb-name", 2, "@" },
    { oNoSecmemWarn, "no-secmem-warning", 0, "@" },
    { oRequireSecmem,"require-secmem", 0, "@" },
    { oNoRequireSecmem,"no-require-secmem", 0, "@" },
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
    { oDefCertLevel, "default-cert-check-level", 1, "@"}, /* Old option */
    { oAlwaysTrust, "always-trust", 0, "@"},
    { oTrustModel, "trust-model", 2, "@"},
    { oForceOwnertrust, "force-ownertrust", 2, "@"},
    { oRunAsShmCP, "run-as-shm-coprocess", 4, "@" },
    { oSetFilename, "set-filename", 2, "@" },
    { oForYourEyesOnly, "for-your-eyes-only", 0, "@" },
    { oNoForYourEyesOnly, "no-for-your-eyes-only", 0, "@" },
    { oSetPolicyURL, "set-policy-url", 2, "@" },
    { oSigPolicyURL, "sig-policy-url", 2, "@" },
    { oCertPolicyURL, "cert-policy-url", 2, "@" },
    { oShowPolicyURL, "show-policy-url", 0, "@" },
    { oNoShowPolicyURL, "no-show-policy-url", 0, "@" },
    { oSigKeyserverURL, "sig-keyserver-url", 2, "@" },
    { oShowNotation, "show-notation", 0, "@" },
    { oNoShowNotation, "no-show-notation", 0, "@" },
    { oComment, "comment", 2, "@" },
    { oDefaultComment, "default-comment", 0, "@" },
    { oNoComments, "no-comments", 0, "@" },
    { oEmitVersion, "emit-version", 0, "@"},
    { oNoEmitVersion, "no-emit-version", 0, "@"},
    { oNoEmitVersion, "no-version", 0, "@"}, /* alias */
    { oNotDashEscaped, "not-dash-escaped", 0, "@" },
    { oEscapeFrom, "escape-from-lines", 0, "@" },
    { oNoEscapeFrom, "no-escape-from-lines", 0, "@" },
    { oLockOnce, "lock-once", 0, "@" },
    { oLockMultiple, "lock-multiple", 0, "@" },
    { oLockNever, "lock-never", 0, "@" },
    { oLoggerFD, "logger-fd",1, "@" },
    { oLoggerFile, "logger-file",2, "@" },
    { oUseEmbeddedFilename, "use-embedded-filename", 0, "@" },
    { oNoUseEmbeddedFilename, "no-use-embedded-filename", 0, "@" },
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
    { oDefaultKeyserverURL,  "default-keyserver-url", 2, "@"},
    { oPersonalCipherPreferences,  "personal-cipher-preferences", 2, "@"},
    { oPersonalDigestPreferences,  "personal-digest-preferences", 2, "@"},
    { oPersonalCompressPreferences,  "personal-compress-preferences", 2, "@"},
    /* Aliases.  I constantly mistype these, and assume other people
       do as well. */
    { oPersonalCipherPreferences, "personal-cipher-prefs", 2, "@"},
    { oPersonalDigestPreferences, "personal-digest-prefs", 2, "@"},
    { oPersonalCompressPreferences, "personal-compress-prefs", 2, "@"},
    { oDisplay,    "display",     2, "@" },
    { oTTYname,    "ttyname",     2, "@" },
    { oTTYtype,    "ttytype",     2, "@" },
    { oLCctype,    "lc-ctype",    2, "@" },
    { oLCmessages, "lc-messages", 2, "@" },
    { oGroup,      "group",       2, "@" },
    { oUnGroup,    "ungroup",     2, "@" },
    { oNoGroups,   "no-groups",    0, "@" },
    { oStrict,     "strict",      0, "@" },
    { oNoStrict,   "no-strict",   0, "@" },
    { oMangleDosFilenames, "mangle-dos-filenames", 0, "@" },
    { oNoMangleDosFilenames, "no-mangle-dos-filenames", 0, "@" },
    { oEnableProgressFilter, "enable-progress-filter", 0, "@" },
    { oMultifile, "multifile", 0, "@" },
    { oKeyidFormat, "keyid-format", 2, "@" },
    { oExitOnStatusWriteError, "exit-on-status-write-error", 0, "@" },
    { oLimitCardInsertTries, "limit-card-insert-tries", 1, "@"},

    { oReaderPort, "reader-port",    2, "@"},
    { octapiDriver, "ctapi-driver",  2, "@"},
    { opcscDriver, "pcsc-driver",    2, "@"},
    { oDisableCCID, "disable-ccid", 0, "@"},
#if defined(ENABLE_CARD_SUPPORT) && defined(HAVE_LIBUSB)
    { oDebugCCIDDriver, "debug-ccid-driver", 0, "@"},
#endif
    { oAllowMultisigVerification, "allow-multisig-verification", 0, "@"},
    { oEnableDSA2, "enable-dsa2", 0, "@"},
    { oDisableDSA2, "disable-dsa2", 0, "@"},
    { oAllowMultipleMessages, "allow-multiple-messages", 0, "@"},
    { oNoAllowMultipleMessages, "no-allow-multiple-messages", 0, "@"},

    /* These two are aliases to help users of the PGP command line
       product use gpg with minimal pain.  Many commands are common
       already as they seem to have borrowed commands from us.  Now
       I'm returning the favor. */
    { oLocalUser, "sign-with", 2, "@" },
    { oRecipient, "user", 2, "@" },
    { oRequireCrossCert, "require-backsigs", 0, "@"},
    { oRequireCrossCert, "require-cross-certification", 0, "@"},
    { oNoRequireCrossCert, "no-require-backsigs", 0, "@"},
    { oNoRequireCrossCert, "no-require-cross-certification", 0, "@"},
    { oAutoKeyLocate, "auto-key-locate", 2, "@"},
    { oNoAutoKeyLocate, "no-auto-key-locate", 0, "@"},
    {0,NULL,0,NULL}
};


#ifdef ENABLE_SELINUX_HACKS
#define ALWAYS_ADD_KEYRINGS 1
#else
#define ALWAYS_ADD_KEYRINGS 0
#endif


int g10_errors_seen = 0;

static int utf8_strings = 0;
static int maybe_setuid = 1;

static char *build_list( const char *text, char letter,
			 const char *(*mapf)(int), int (*chkf)(int) );
static void set_cmd( enum cmd_and_opt_values *ret_cmd,
			enum cmd_and_opt_values new_cmd );
static void print_mds( const char *fname, int algo );
static void add_notation_data( const char *string, int which );
static void add_policy_url( const char *string, int which );
static void add_keyserver_url( const char *string, int which );

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

#ifdef IS_DEVELOPMENT_VERSION
      case 20:
	p="NOTE: THIS IS A DEVELOPMENT VERSION!";
	break;
      case 21:
	p="It is only intended for test purposes and should NOT be";
	break;
      case 22:
	p="used in a production environment or with production keys!";
	break;
#endif

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
	    pubkeys = build_list(_("Pubkey: "), 0, pubkey_algo_to_string,
							check_pubkey_algo );
	p = pubkeys;
	break;
      case 35:
	if( !ciphers )
	    ciphers = build_list(_("Cipher: "), 'S', cipher_algo_to_string,
							check_cipher_algo );
	p = ciphers;
	break;
      case 36:
	if( !digests )
	    digests = build_list(_("Hash: "), 'H', digest_algo_to_string,
							check_digest_algo );
	p = digests;
	break;
      case 37:
	if( !zips )
	    zips = build_list(_("Compression: "),'Z',compress_algo_to_string,
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
    list = xmalloc( 21 + n ); *list = 0;
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

	      list=xrealloc(list,n+spaces+1);
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
    set_gettext_file (PACKAGE, "Software\\GNU\\GnuPG");
#else
#ifdef ENABLE_NLS
    setlocale( LC_ALL, "" );
    bindtextdomain (PACKAGE, LOCALEDIR);
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
	p = xstrdup(string);
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


/* We set the screen dimensions for UI purposes.  Do not allow screens
   smaller than 80x24 for the sake of simplicity. */
static void
set_screen_dimensions(void)
{
#ifndef _WIN32
  char *str;

  str=getenv("COLUMNS");
  if(str)
    opt.screen_columns=atoi(str);

  str=getenv("LINES");
  if(str)
    opt.screen_lines=atoi(str);
#endif

  if(opt.screen_columns<80 || opt.screen_columns>255)
    opt.screen_columns=80;

  if(opt.screen_lines<24 || opt.screen_lines>255)
    opt.screen_lines=24;
}


/* Helper to open a file FNAME either for reading or writing to be
   used with --status-file etc functions.  Not generally useful but it
   avoids the riscos specific functions and well some Windows people
   might like it too.  Prints an error message and returns -1 on
   error. On success the file descriptor is returned.  */
static int
open_info_file (const char *fname, int for_write)
{
#ifdef __riscos__
  return riscos_fdopenfile (fname, for_write);
#elif defined (ENABLE_SELINUX_HACKS)
  /* We can't allow these even when testing for a secured filename
     because files to be secured might not yet been secured.  This is
     similar to the option file but in that case it is unlikely that
     sensitive information may be retrieved by means of error
     messages.  */
  return -1;
#else 
  int fd;

/*   if (is_secured_filename (fname)) */
/*     { */
/*       fd = -1; */
/*       errno = EPERM; */
/*     } */
/*   else */
/*     { */
      do
        {
          if (for_write)
            fd = open (fname, O_CREAT | O_TRUNC | O_WRONLY,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
          else
            fd = open (fname, O_RDONLY | MY_O_BINARY);
        }
      while (fd == -1 && errno == EINTR);
/*     } */
  if ( fd == -1)
    log_error ( for_write? _("can't create `%s': %s\n")
                         : _("can't open `%s': %s\n"), fname, strerror(errno));
  
  return fd;
#endif
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
    else if( cmd == aSym && new_cmd == aEncr )
	cmd = aEncrSym;
    else if( cmd == aEncr && new_cmd == aSym )
	cmd = aEncrSym;
    else if( cmd == aKMode && new_cmd == aSym )
	cmd = aKModeC;
    else if (cmd == aSignEncr && new_cmd == aSym)
        cmd = aSignEncrSym;
    else if (cmd == aSignSym && new_cmd == aEncr)
        cmd = aSignEncrSym;
    else if (cmd == aEncrSym && new_cmd == aSign)
        cmd = aSignEncrSym;
    else if(	( cmd == aSign	   && new_cmd == aClearsign )
	     || ( cmd == aClearsign && new_cmd == aSign )  )
	cmd = aClearsign;
    else {
	log_error(_("conflicting commands\n"));
	g10_exit(2);
    }

    *ret_cmd = cmd;
}


static void
add_group(char *string)
{
  char *name,*value;
  struct groupitem *item;

  /* Break off the group name */
  name=strsep(&string,"=");
  if(string==NULL)
    {
      log_error(_("no = sign found in group definition `%s'\n"),name);
      return;
    }

  trim_trailing_ws(name,strlen(name));

  /* Does this group already exist? */
  for(item=opt.grouplist;item;item=item->next)
    if(strcasecmp(item->name,name)==0)
      break;

  if(!item)
    {
      item=xmalloc(sizeof(struct groupitem));
      item->name=name;
      item->next=opt.grouplist;
      item->values=NULL;
      opt.grouplist=item;
    }

  /* Break apart the values */
  while ((value= strsep(&string," \t")))
    {
      if (*value)
        add_to_strlist2(&item->values,value,utf8_strings);
    }
}


static void
rm_group(char *name)
{
  struct groupitem *item,*last=NULL;

  trim_trailing_ws(name,strlen(name));

  for(item=opt.grouplist;item;last=item,item=item->next)
    {
      if(strcasecmp(item->name,name)==0)
	{
	  if(last)
	    last->next=item->next;
	  else
	    opt.grouplist=item->next;

	  free_strlist(item->values);
	  xfree(item);
	  break;
	}
    }
}


/* We need to check three things.

   0) The homedir.  It must be x00, a directory, and owned by the
   user.

   1) The options/gpg.conf file.  Okay unless it or its containing
   directory is group or other writable or not owned by us.  Disable
   exec in this case.

   2) Extensions.  Same as #1.

   Returns true if the item is unsafe. */
static int
check_permissions(const char *path,int item)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  static int homedir_cache=-1;
  char *tmppath,*dir;
  struct stat statbuf,dirbuf;
  int homedir=0,ret=0,checkonly=0;
  int perm=0,own=0,enc_dir_perm=0,enc_dir_own=0;

  if(opt.no_perm_warn)
    return 0;

  assert(item==0 || item==1 || item==2);

  /* extensions may attach a path */
  if(item==2 && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(GNUPG_LIBDIR,path,NULL);
    }
  else
    tmppath=xstrdup(path);

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

  xfree(dir);

  /* Assume failure */
  ret=1;

  if(item==0)
    {
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
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe ownership on"
		       " homedir `%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe ownership on"
		       " configuration file `%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe ownership on"
		       " extension `%s'\n"),tmppath);
	}
      if(perm)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe permissions on"
		       " homedir `%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe permissions on"
		       " configuration file `%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe permissions on"
		       " extension `%s'\n"),tmppath);
	}
      if(enc_dir_own)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " homedir `%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " configuration file `%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " extension `%s'\n"),tmppath);
	}
      if(enc_dir_perm)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " homedir `%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " configuration file `%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " extension `%s'\n"),tmppath);
	}
    }

 end:
  xfree(tmppath);

  if(homedir)
    homedir_cache=ret;

  return ret;

#endif /* HAVE_STAT && !HAVE_DOSISH_SYSTEM */

  return 0;
}

static void
print_algo_numbers(int (*checker)(int))
{
  int i,first=1;

  for(i=0;i<=110;i++)
    {
      if(!checker(i))
	{
	  if(first)
	    first=0;
	  else
	    printf(";");
	  printf("%d",i);
	}
    }
}

static void
print_algo_names(int (*checker)(int),const char *(*mapper)(int))
{
  int i,first=1;

  for(i=0;i<=110;i++)
    {
      if(!checker(i))
	{
	  if(first)
	    first=0;
	  else
	    printf(";");
	  printf("%s",mapper(i));
	}
    }
}

/* In the future, we can do all sorts of interesting configuration
   output here.  For now, just give "group" as the Enigmail folks need
   it, and pubkey, cipher, hash, and compress as they may be useful
   for frontends. */
static void
list_config(char *items)
{
  int show_all=(items==NULL);
  char *name=NULL;

  if(!opt.with_colons)
    return;

  while(show_all || (name=strsep(&items," ")))
    {
      int any=0;

      if(show_all || ascii_strcasecmp(name,"group")==0)
	{
	  struct groupitem *iter;

	  for(iter=opt.grouplist;iter;iter=iter->next)
	    {
	      STRLIST sl;

	      printf("cfg:group:");
	      print_string(stdout,iter->name,strlen(iter->name),':');
	      printf(":");

	      for(sl=iter->values;sl;sl=sl->next)
		{
		  print_string2(stdout,sl->d,strlen(sl->d),':',';');
		  if(sl->next)
		    printf(";");
		}

	      printf("\n");
	    }

	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"version")==0)
	{
	  printf("cfg:version:");
	  print_string(stdout,VERSION,strlen(VERSION),':');
	  printf("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"pubkey")==0)
	{
	  printf("cfg:pubkey:");
	  print_algo_numbers(check_pubkey_algo);
	  printf("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"cipher")==0)
	{
	  printf("cfg:cipher:");
	  print_algo_numbers(check_cipher_algo);
	  printf("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"ciphername")==0)
	{
	  printf("cfg:ciphername:");
	  print_algo_names(check_cipher_algo,cipher_algo_to_string);
	  printf("\n");
	  any=1;
	}

      if(show_all
	 || ascii_strcasecmp(name,"digest")==0
	 || ascii_strcasecmp(name,"hash")==0)
	{
	  printf("cfg:digest:");
	  print_algo_numbers(check_digest_algo);
	  printf("\n");
	  any=1;
	}

      if(show_all
	 || ascii_strcasecmp(name,"digestname")==0
	 || ascii_strcasecmp(name,"hashname")==0)
	{
	  printf("cfg:digestname:");
	  print_algo_names(check_digest_algo,digest_algo_to_string);
	  printf("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"compress")==0)
	{
	  printf("cfg:compress:");
	  print_algo_numbers(check_compress_algo);
	  printf("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"ccid-reader-id")==0)
	{
#if defined(ENABLE_CARD_SUPPORT) && defined(HAVE_LIBUSB)
          char *p, *p2, *list = ccid_get_reader_list ();

          for (p=list; p && (p2 = strchr (p, '\n')); p = p2+1)
            {
              *p2 = 0;
              printf("cfg:ccid-reader-id:%s\n", p);
            }
          free (list);
#endif
	  any=1;
	}

      if(show_all)
	break;

      if(!any)
	log_error(_("unknown configuration item `%s'\n"),name);
    }
}


/* List options and default values in the GPG Conf format.  This is a
   new tool distributed with gnupg 1.9.x but we also want some limited
   support in older gpg versions.  The output is the name of the
   configuration file and a list of options available for editing by
   gpgconf.  */
static void
gpgconf_list (const char *configfile)
{
  /* The following definitions are taken from gnupg/tools/gpgconf-comp.c.  */
#define GC_OPT_FLAG_NONE	0UL
#define GC_OPT_FLAG_DEFAULT	(1UL << 4)

  printf ("gpgconf-gpg.conf:%lu:\"%s\n",
          GC_OPT_FLAG_DEFAULT,configfile?configfile:"/dev/null");
  printf ("verbose:%lu:\n", GC_OPT_FLAG_NONE);
  printf ("quiet:%lu:\n",   GC_OPT_FLAG_NONE);
  printf ("keyserver:%lu:\n", GC_OPT_FLAG_NONE);
  printf ("reader-port:%lu:\n", GC_OPT_FLAG_NONE);
}


static int
parse_subpacket_list(char *list)
{
  char *tok;
  byte subpackets[128],i;
  int count=0;

  if(!list)
    {
      /* No arguments means all subpackets */
      memset(subpackets+1,1,sizeof(subpackets)-1);
      count=127;
    }
  else
    {
      memset(subpackets,0,sizeof(subpackets));

      /* Merge with earlier copy */
      if(opt.show_subpackets)
	{
	  byte *in;

	  for(in=opt.show_subpackets;*in;in++)
	    {
	      if(*in>127 || *in<1)
		BUG();

	      if(!subpackets[*in])
		count++;
	      subpackets[*in]=1;
	    }
	}

      while((tok=strsep(&list," ,")))
	{
	  if(!*tok)
	    continue;

	  i=atoi(tok);
	  if(i>127 || i<1)
	    return 0;

	  if(!subpackets[i])
	    count++;
	  subpackets[i]=1;
	}
    }

  xfree(opt.show_subpackets);
  opt.show_subpackets=xmalloc(count+1);
  opt.show_subpackets[count--]=0;

  for(i=1;i<128 && count>=0;i++)
    if(subpackets[i])
      opt.show_subpackets[count--]=i;

  return 1;
}


static int
parse_list_options(char *str)
{
  char *subpackets=""; /* something that isn't NULL */
  struct parse_options lopts[]=
    {
      {"show-photos",LIST_SHOW_PHOTOS,NULL,
       N_("display photo IDs during key listings")},
      {"show-policy-urls",LIST_SHOW_POLICY_URLS,NULL,
       N_("show policy URLs during signature listings")},
      {"show-notations",LIST_SHOW_NOTATIONS,NULL,
       N_("show all notations during signature listings")},
      {"show-std-notations",LIST_SHOW_STD_NOTATIONS,NULL,
       N_("show IETF standard notations during signature listings")},
      {"show-standard-notations",LIST_SHOW_STD_NOTATIONS,NULL,
       NULL},
      {"show-user-notations",LIST_SHOW_USER_NOTATIONS,NULL,
       N_("show user-supplied notations during signature listings")},
      {"show-keyserver-urls",LIST_SHOW_KEYSERVER_URLS,NULL,
       N_("show preferred keyserver URLs during signature listings")},
      {"show-uid-validity",LIST_SHOW_UID_VALIDITY,NULL,
       N_("show user ID validity during key listings")},
      {"show-unusable-uids",LIST_SHOW_UNUSABLE_UIDS,NULL,
       N_("show revoked and expired user IDs in key listings")},
      {"show-unusable-subkeys",LIST_SHOW_UNUSABLE_SUBKEYS,NULL,
       N_("show revoked and expired subkeys in key listings")},
      {"show-keyring",LIST_SHOW_KEYRING,NULL,
       N_("show the keyring name in key listings")},
      {"show-sig-expire",LIST_SHOW_SIG_EXPIRE,NULL,
       N_("show expiration dates during signature listings")},
      {"show-sig-subpackets",LIST_SHOW_SIG_SUBPACKETS,NULL,
       NULL},
      {NULL,0,NULL,NULL}
    };

  /* C99 allows for non-constant initializers, but we'd like to
     compile everywhere, so fill in the show-sig-subpackets argument
     here.  Note that if the parse_options array changes, we'll have
     to change the subscript here. */
  lopts[12].value=&subpackets;

  if(parse_options(str,&opt.list_options,lopts,1))
    {
      if(opt.list_options&LIST_SHOW_SIG_SUBPACKETS)
	{
	  /* Unset so users can pass multiple lists in. */
	  opt.list_options&=~LIST_SHOW_SIG_SUBPACKETS;
	  if(!parse_subpacket_list(subpackets))
	    return 0;
	}
      else if(subpackets==NULL && opt.show_subpackets)
	{
	  /* User did 'no-show-subpackets' */
	  xfree(opt.show_subpackets);
	  opt.show_subpackets=NULL;
	}

      return 1;
    }
  else
    return 0;
}


/* Collapses argc/argv into a single string that must be freed */
static char *
collapse_args(int argc,char *argv[])
{
  char *str=NULL;
  int i,first=1,len=0;

  for(i=0;i<argc;i++)
    {
      len+=strlen(argv[i])+2;
      str=xrealloc(str,len);
      if(first)
	{
	  str[0]='\0';
	  first=0;
	}
      else
	strcat(str," ");

      strcat(str,argv[i]);
    }

  return str;
}

static void
parse_trust_model(const char *model)
{
  if(ascii_strcasecmp(model,"pgp")==0)
    opt.trust_model=TM_PGP;
  else if(ascii_strcasecmp(model,"classic")==0)
    opt.trust_model=TM_CLASSIC;
  else if(ascii_strcasecmp(model,"always")==0)
    opt.trust_model=TM_ALWAYS;
  else if(ascii_strcasecmp(model,"direct")==0)
    opt.trust_model=TM_DIRECT;
  else if(ascii_strcasecmp(model,"auto")==0)
    opt.trust_model=TM_AUTO;
  else
    log_error("unknown trust model `%s'\n",model);
}

/* Must be called before we open any files. */
static void
reopen_std(void)
{  
#if defined(HAVE_STAT) && !defined(HAVE_W32_SYSTEM)
  struct stat statbuf;
  int did_stdin=0,did_stdout=0,did_stderr=0;
  FILE *complain;

  if(fstat(STDIN_FILENO,&statbuf)==-1 && errno==EBADF)
    {
      if(open("/dev/null",O_RDONLY)==STDIN_FILENO)
	did_stdin=1;
      else
	did_stdin=2;
    }

  if(fstat(STDOUT_FILENO,&statbuf)==-1 && errno==EBADF)
    {
      if(open("/dev/null",O_WRONLY)==STDOUT_FILENO)
	did_stdout=1;
      else
	did_stdout=2;
    }

  if(fstat(STDERR_FILENO,&statbuf)==-1 && errno==EBADF)
    {
      if(open("/dev/null",O_WRONLY)==STDERR_FILENO)
	did_stderr=1;
      else
	did_stderr=2;
    }

  /* It's hard to log this sort of thing since the filehandle we would
     complain to may be closed... */
  if(did_stderr==0)
    complain=stderr;
  else if(did_stdout==0)
    complain=stdout;
  else
    complain=NULL;

  if(complain)
    {
      if(did_stdin==1)
	fprintf(complain,"gpg: WARNING: standard input reopened\n");
      if(did_stdout==1)
	fprintf(complain,"gpg: WARNING: standard output reopened\n");
      if(did_stderr==1)
	fprintf(complain,"gpg: WARNING: standard error reopened\n");

      if(did_stdin==2 || did_stdout==2 || did_stderr==2)
	fprintf(complain,"gpg: fatal: unable to reopen standard input,"
		" output, or error\n");
    }

  if(did_stdin==2 || did_stdout==2 || did_stderr==2)
    exit(3);
#endif /* HAVE_STAT && !HAVE_W32_SYSTEM */
}

/* Pack an s2k iteration count into the form specified in 2440.  If
   we're in between valid values, round up. */
static unsigned char
encode_s2k_iterations(int iterations)
{
  unsigned char c=0,result;
  unsigned int count;

  if(iterations<=1024)
    return 0;

  if(iterations>=65011712)
    return 255;

  /* Need count to be in the range 16-31 */
  for(count=iterations>>6;count>=32;count>>=1)
    c++;

  result=(c<<4)|(count-16);

  if(S2K_DECODE_COUNT(result)<iterations)
    result++;

  return result;
}


char *
get_default_configname (void)
{
  char *configname = NULL;
  char *name = xstrdup ("gpg" EXTSEP_S "conf-" SAFE_VERSION);
  char *ver = &name[strlen ("gpg" EXTSEP_S "conf-")];

  do
    {
      if (configname)
	{
	  char *tok;
	  
	  xfree (configname);
	  configname = NULL;

	  if ((tok = strrchr (ver, SAFE_VERSION_DASH)))
	    *tok='\0';
	  else if ((tok = strrchr (ver, SAFE_VERSION_DOT)))
	    *tok='\0';
	  else
	    break;
	}
      
      configname = make_filename (opt.homedir, name, NULL);
    }
  while (access (configname, R_OK));

  xfree(name);
  
  if (! configname)
    configname = make_filename (opt.homedir, "gpg" EXTSEP_S "conf", NULL);
  if (! access (configname, R_OK))
    {
      /* Print a warning when both config files are present.  */
      char *p = make_filename (opt.homedir, "options", NULL);
      if (! access (p, R_OK))
	log_info (_("NOTE: old default options file `%s' ignored\n"), p);
      xfree (p);
    }
  else
    {
      /* Use the old default only if it exists.  */
      char *p = make_filename (opt.homedir, "options", NULL);
      if (!access (p, R_OK))
	{
	  xfree (configname);
	  configname = p;
	}
      else
	xfree (p);
    }

  return configname;
}



int
main (int argc, char **argv )
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
    char *save_configname = NULL;
    char *default_configname = NULL;
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
    char *compress_algo_string = NULL;
    char *cert_digest_string = NULL;
    char *s2k_cipher_string = NULL;
    char *s2k_digest_string = NULL;
    char *pers_cipher_list = NULL;
    char *pers_digest_list = NULL;
    char *pers_compress_list = NULL;
    int eyes_only=0;
    int multifile=0;
    int pwfd = -1;
    int with_fpr = 0; /* make an option out of --fingerprint */
    int any_explicit_recipient = 0;
    int require_secmem=0,got_secmem=0;
#ifdef USE_SHM_COPROCESSING
    ulong requested_shm_size=0;
#endif

#ifdef __riscos__
    opt.lock_once = 1;
#endif /* __riscos__ */

    reopen_std();
    trap_unaligned();
    secmem_set_flags( secmem_get_flags() | 2 ); /* suspend warnings */
    /* Please note that we may running SUID(ROOT), so be very CAREFUL
     * when adding any stuff between here and the call to
     * secmem_init()  somewhere after the option parsing
     */
    log_set_name("gpg");
    secure_randoxmalloc(); /* put random number into secure memory */
    may_coredump = disable_core_dumps();
    init_signals();
    create_dotlock(NULL); /* register locking cleanup */
    i18n_init();
    opt.command_fd = -1; /* no command fd */
    opt.compress_level = -1; /* defaults to standard compress level */
    opt.bz2_compress_level = -1; /* defaults to standard compress level */
    /* note: if you change these lines, look at oOpenPGP */
    opt.def_cipher_algo = 0;
    opt.def_digest_algo = 0;
    opt.cert_digest_algo = 0;
    opt.compress_algo = -1; /* defaults to DEFAULT_COMPRESS_ALGO */
    opt.s2k_mode = 3; /* iterated+salted */
    opt.s2k_count = 96; /* 65536 iterations */
#ifdef USE_CAST5
    opt.s2k_cipher_algo = CIPHER_ALGO_CAST5;
#else
    opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
#endif
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.max_cert_depth = 5;
    opt.pgp2_workarounds = 1;
    opt.escape_from = 1;
    opt.flags.require_cross_cert = 1;
    opt.import_options=IMPORT_SK2PK;
    opt.export_options=EXPORT_ATTRIBUTES;
    opt.keyserver_options.import_options=IMPORT_REPAIR_PKS_SUBKEY_BUG;
    opt.keyserver_options.export_options=EXPORT_ATTRIBUTES;
    opt.keyserver_options.options=
      KEYSERVER_HONOR_KEYSERVER_URL|KEYSERVER_HONOR_PKA_RECORD;
    opt.verify_options=
      VERIFY_SHOW_POLICY_URLS|VERIFY_SHOW_STD_NOTATIONS|VERIFY_SHOW_KEYSERVER_URLS;
    opt.trust_model=TM_AUTO;
    opt.mangle_dos_filenames=0;
    opt.min_cert_level=2;
    set_screen_dimensions();
    opt.keyid_format=KF_SHORT;
    opt.def_sig_expire="0";
    opt.def_cert_expire="0";
    set_homedir ( default_homedir () );
    opt.passwd_repeat=1;

#ifdef ENABLE_CARD_SUPPORT
#if defined(_WIN32) || defined(__CYGWIN__)
    opt.pcsc_driver = "winscard.dll";
#elif defined(__APPLE__)
    opt.pcsc_driver = "/System/Library/Frameworks/PCSC.framework/PCSC";
#elif defined(__GLIBC__)
    opt.pcsc_driver = "libpcsclite.so.1"; 
#else
    opt.pcsc_driver = "libpcsclite.so"; 
#endif
#endif /*ENABLE_CARD_SUPPORT*/

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
          {
	    default_config = 0; /* --no-options */
            opt.no_homedir_creation = 1;
          }
	else if( pargs.r_opt == oHomedir )
	    set_homedir ( pargs.r.ret_str );
	else if( pargs.r_opt == oNoPermissionWarn )
	    opt.no_perm_warn=1;
	else if (pargs.r_opt == oStrict )
	  {
	    opt.strict=1;
	    log_set_strict(1);
	  }
	else if (pargs.r_opt == oNoStrict )
	  {
	    opt.strict=0;
	    log_set_strict(0);
	  }
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
        char *d, *buf = xmalloc (strlen (opt.homedir)+1);
        const char *s = opt.homedir;
        for (d=buf,s=opt.homedir; *s; s++)
          {
            *d++ = *s == '\\'? '/': *s;
#ifdef HAVE_W32_SYSTEM
            if (s[1] && IsDBCSLeadByte (*s))
              *d++ = *++s;
#endif
          }
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
    got_secmem=secmem_init( 32768 );
    maybe_setuid = 0;
    /* Okay, we are now working under our real uid */

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
    /* There should be no way to get to this spot while still carrying
       setuid privs.  Just in case, bomb out if we are. */
    if(getuid()!=geteuid())
      BUG();
#endif

    set_native_charset (NULL); /* Try to auto set the character set */

    /* Try for a version specific config file first */
    default_configname = get_default_configname ();
    if (default_config)
      configname = xstrdup (default_configname);

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
        if (configfp && is_secured_file (fileno (configfp)))
          {
            fclose (configfp);
            configfp = NULL;
            errno = EPERM;
          }
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
	    xfree(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info(_("reading options from `%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) )
      {
	switch( pargs.r_opt )
	  {
	  case aCheckKeys: 
	  case aListConfig:
          case aGPGConfList:
          case aGPGConfTest:
	  case aListPackets:
	  case aImport: 
	  case aFastImport: 
	  case aSendKeys: 
	  case aRecvKeys: 
	  case aSearchKeys:
	  case aRefreshKeys:
	  case aFetchKeys:
	  case aExport: 
            set_cmd (&cmd, pargs.r_opt);
            break;
	  case aListKeys: set_cmd( &cmd, aListKeys); break;
	  case aListSigs: set_cmd( &cmd, aListSigs); break;
	  case aExportSecret: set_cmd( &cmd, aExportSecret); break;
	  case aExportSecretSub: set_cmd( &cmd, aExportSecretSub); break;
	  case aDeleteSecretKeys:
	    set_cmd( &cmd, aDeleteSecretKeys);
	    greeting=1;
	    break;
	  case aDeleteSecretAndPublicKeys:
            set_cmd( &cmd, aDeleteSecretAndPublicKeys);
            greeting=1; 
            break;
	  case aDeleteKeys: set_cmd( &cmd, aDeleteKeys); greeting=1; break;

	  case aDetachedSign: detached_sig = 1; set_cmd( &cmd, aSign ); break;
	  case aSym: set_cmd( &cmd, aSym); break;

	  case aDecryptFiles: multifile=1; /* fall through */
	  case aDecrypt: set_cmd( &cmd, aDecrypt); break;

	  case aEncrFiles: multifile=1; /* fall through */
	  case aEncr: set_cmd( &cmd, aEncr); break;

	  case aVerifyFiles: multifile=1; /* fall through */
	  case aVerify: set_cmd( &cmd, aVerify); break;

	  case aSign: set_cmd( &cmd, aSign );  break;
	  case aKeygen: set_cmd( &cmd, aKeygen); greeting=1; break;
	  case aSignKey: set_cmd( &cmd, aSignKey); break;
	  case aLSignKey: set_cmd( &cmd, aLSignKey); break;
	  case aStore: set_cmd( &cmd, aStore); break;
	  case aEditKey: set_cmd( &cmd, aEditKey); greeting=1; break;
	  case aClearsign: set_cmd( &cmd, aClearsign); break;
	  case aGenRevoke: set_cmd( &cmd, aGenRevoke); break;
	  case aDesigRevoke: set_cmd( &cmd, aDesigRevoke); break;
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
	  case aListOwnerTrust:
	    deprecated_warning(configname,configlineno,
			       "--list-ownertrust","--export-ownertrust","");
	  case aExportOwnerTrust: set_cmd( &cmd, aExportOwnerTrust); break;
	  case aImportOwnerTrust: set_cmd( &cmd, aImportOwnerTrust); break;
          case aPipeMode:
	    deprecated_command ("--pipemode");
            set_cmd( &cmd, aPipeMode);
            break;

          case aRebuildKeydbCaches: set_cmd( &cmd, aRebuildKeydbCaches); break;

#ifdef ENABLE_CARD_SUPPORT
          case aCardStatus: set_cmd (&cmd, aCardStatus); break;
          case aCardEdit: set_cmd (&cmd, aCardEdit); break;
          case aChangePIN: set_cmd (&cmd, aChangePIN); break;
          case oReaderPort:
            card_set_reader_port (pargs.r.ret_str);
            break;
          case octapiDriver: opt.ctapi_driver = pargs.r.ret_str; break;
          case opcscDriver: opt.pcsc_driver = pargs.r.ret_str; break;
          case oDisableCCID: opt.disable_ccid = 1; break;
#endif /* ENABLE_CARD_SUPPORT*/

	  case oArmor: opt.armor = 1; opt.no_armor=0; break;
	  case oOutput: opt.outfile = pargs.r.ret_str; break;
	  case oMaxOutput: opt.max_output = pargs.r.ret_ulong; break;
	  case oQuiet: opt.quiet = 1; break;
	  case oNoTTY: tty_no_terminal(1); break;
	  case oDryRun: opt.dry_run = 1; break;
	  case oInteractive: opt.interactive = 1; break;
	  case oVerbose:
	    g10_opt_verbose++;
	    opt.verbose++;
	    opt.list_options|=LIST_SHOW_UNUSABLE_UIDS;
	    opt.list_options|=LIST_SHOW_UNUSABLE_SUBKEYS;
	    break;
	  case oKOption: set_cmd( &cmd, aKMode ); break;

	  case oBatch: opt.batch = 1; nogreeting = 1; break;
          case oUseAgent:
#ifndef __riscos__
            opt.use_agent = 1;
#else /* __riscos__ */
            opt.use_agent = 0;
            riscos_not_implemented("use-agent");
#endif /* __riscos__ */
            break;
          case oNoUseAgent: opt.use_agent = 0; break;
	  case oGpgAgentInfo: opt.gpg_agent_info = pargs.r.ret_str; break;
	  case oAnswerYes: opt.answer_yes = 1; break;
	  case oAnswerNo: opt.answer_no = 1; break;
	  case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
	  case oPrimaryKeyring:
	    sl=append_to_strlist( &nrings, pargs.r.ret_str);
	    sl->flags=2;
	    break;
	  case oShowKeyring:
	    deprecated_warning(configname,configlineno,"--show-keyring",
			       "--list-options ","show-keyring");
	    opt.list_options|=LIST_SHOW_KEYRING;
	    break;
	  case oDebug: opt.debug |= pargs.r.ret_ulong; break;
	  case oDebugAll: opt.debug = ~0; break;
          case oDebugCCIDDriver: 
#if defined(ENABLE_CARD_SUPPORT) && defined(HAVE_LIBUSB)
            ccid_set_debug_level (ccid_set_debug_level (1)+1);
#endif
            break;
	  case oStatusFD:
            set_status_fd( iobuf_translate_file_handle (pargs.r.ret_int, 1) );
            break;
	  case oStatusFile:
            set_status_fd ( open_info_file (pargs.r.ret_str, 1) );
            break;
	  case oAttributeFD:
            set_attrib_fd(iobuf_translate_file_handle (pargs.r.ret_int, 1));
            break;
	  case oAttributeFile:
            set_attrib_fd ( open_info_file (pargs.r.ret_str, 1) );
            break;
	  case oLoggerFD:
            log_set_logfile( NULL,
                             iobuf_translate_file_handle (pargs.r.ret_int, 1));
            break;
	  case oLoggerFile:
            log_set_logfile( NULL, open_info_file (pargs.r.ret_str, 1) );
            break;

	  case oWithFingerprint:
            opt.with_fingerprint = 1;
            with_fpr=1; /*fall thru*/
	  case oFingerprint: opt.fingerprint++; break;
	  case oSecretKeyring:
            append_to_strlist( &sec_nrings, pargs.r.ret_str);
            break;
	  case oOptions:
	    /* config files may not be nested (silently ignore them) */
	    if( !configfp ) {
		xfree(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case oNoArmor: opt.no_armor=1; opt.armor=0; break;
	  case oNoDefKeyring: default_keyring = 0; break;
	  case oNoGreeting: nogreeting = 1; break;
	  case oNoVerbose: g10_opt_verbose = 0;
			   opt.verbose = 0; opt.list_sigs=0; break;
	  case oQuickRandom: quick_random_gen(1); break;
	  case oEmitVersion: opt.no_version=0; break;
	  case oNoEmitVersion: opt.no_version=1; break;
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
		    xfree(opt.def_recipient); opt.def_recipient = NULL;
		    opt.def_recipient_self = 1;
		    break;
	  case oNoDefRecipient:
		    xfree(opt.def_recipient); opt.def_recipient = NULL;
		    opt.def_recipient_self = 0;
		    break;
	  case oNoOptions: opt.no_homedir_creation = 1; break; /* no-options */
	  case oHomedir: break;
	  case oNoBatch: opt.batch = 0; break;
	  case oWithKeyData: opt.with_key_data=1; /* fall thru */
	  case oWithColons: opt.with_colons=':'; break;

	  case oSkipVerify: opt.skip_verify=1; break;
	  case oCompressKeys: opt.compress_keys = 1; break;
	  case aListSecretKeys: set_cmd( &cmd, aListSecretKeys); break;
	    /* There are many programs (like mutt) that call gpg with
	       --always-trust so keep this option around for a long
	       time. */
	  case oAlwaysTrust: opt.trust_model=TM_ALWAYS; break;
	  case oTrustModel:
	    parse_trust_model(pargs.r.ret_str);
	    break;
	  case oForceOwnertrust:
	    log_info(_("NOTE: %s is not for normal use!\n"),
		     "--force-ownertrust");
	    opt.force_ownertrust=string_to_trust_value(pargs.r.ret_str);
	    if(opt.force_ownertrust==-1)
	      {
		log_error("invalid ownertrust `%s'\n",pargs.r.ret_str);
		opt.force_ownertrust=0;
	      }
	    break;
	  case oLoadExtension:
#ifndef __riscos__
#if defined(USE_DYNAMIC_LINKING) || defined(_WIN32)
	    if(check_permissions(pargs.r.ret_str,2))
	      log_info(_("cipher extension `%s' not loaded due to"
			 " unsafe permissions\n"),pargs.r.ret_str);
	    else
	      register_cipher_extension(orig_argc? *orig_argv:NULL,
					pargs.r.ret_str);
#endif
#else /* __riscos__ */
            riscos_not_implemented("load-extension");
#endif /* __riscos__ */
	    break;
	  case oRFC1991:
	    opt.compliance = CO_RFC1991;
	    opt.force_v4_certs = 0;
	    opt.escape_from = 1;
	    break;
	  case oOpenPGP:
	  case oRFC4880:
	    /* This is effectively the same as RFC2440, but with
	       "--enable-dsa2 --no-rfc2440-text --escape-from-lines
	       --require-cross-certification". */
	    opt.compliance = CO_RFC4880;
	    opt.flags.dsa2 = 1;
	    opt.flags.require_cross_cert = 1;
	    opt.rfc2440_text = 0;
	    opt.allow_non_selfsigned_uid = 1;
	    opt.allow_freeform_uid = 1;
	    opt.pgp2_workarounds = 0;
	    opt.escape_from = 1;
	    opt.force_v3_sigs = 0;
	    opt.compress_keys = 0;	    /* not mandated, but we do it */
	    opt.compress_sigs = 0;	    /* ditto. */
	    opt.not_dash_escaped = 0;
	    opt.def_cipher_algo = 0;
	    opt.def_digest_algo = 0;
	    opt.cert_digest_algo = 0;
	    opt.compress_algo = -1;
            opt.s2k_mode = 3; /* iterated+salted */
	    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
	    opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
	    break;
	  case oRFC2440:
	    opt.compliance = CO_RFC2440;
	    opt.flags.dsa2 = 0;
	    opt.rfc2440_text = 1;
	    opt.allow_non_selfsigned_uid = 1;
	    opt.allow_freeform_uid = 1;
	    opt.pgp2_workarounds = 0;
	    opt.escape_from = 0;
	    opt.force_v3_sigs = 0;
	    opt.compress_keys = 0;	    /* not mandated, but we do it */
	    opt.compress_sigs = 0;	    /* ditto. */
	    opt.not_dash_escaped = 0;
	    opt.def_cipher_algo = 0;
	    opt.def_digest_algo = 0;
	    opt.cert_digest_algo = 0;
	    opt.compress_algo = -1;
            opt.s2k_mode = 3; /* iterated+salted */
	    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
	    opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
	    break;
	  case oPGP2:  opt.compliance = CO_PGP2;  break;
	  case oPGP6:  opt.compliance = CO_PGP6;  break;
	  case oPGP7:  opt.compliance = CO_PGP7;  break;
	  case oPGP8:  opt.compliance = CO_PGP8;  break;
	  case oGnuPG: opt.compliance = CO_GNUPG; break;
	  case oCompressSigs: opt.compress_sigs = 1; break;
	  case oRFC2440Text: opt.rfc2440_text=1; break;
	  case oNoRFC2440Text: opt.rfc2440_text=0; break;
	  case oRunAsShmCP:
#ifndef __riscos__
# ifndef USE_SHM_COPROCESSING
	    /* not possible in the option file,
	     * but we print the warning here anyway */
	    log_error("shared memory coprocessing is not available\n");
# endif
#else /* __riscos__ */
            riscos_not_implemented("run-as-shm-coprocess");
#endif /* __riscos__ */
	    break;
	  case oSetFilename:
	    if(utf8_strings)
	      opt.set_filename = pargs.r.ret_str;
	    else
	      opt.set_filename = native_to_utf8(pargs.r.ret_str);
	    break;
	  case oForYourEyesOnly: eyes_only = 1; break;
	  case oNoForYourEyesOnly: eyes_only = 0; break;
	  case oSetPolicyURL:
	    add_policy_url(pargs.r.ret_str,0);
	    add_policy_url(pargs.r.ret_str,1);
	    break;
	  case oSigPolicyURL: add_policy_url(pargs.r.ret_str,0); break;
	  case oCertPolicyURL: add_policy_url(pargs.r.ret_str,1); break;
          case oShowPolicyURL:
	    deprecated_warning(configname,configlineno,"--show-policy-url",
			       "--list-options ","show-policy-urls");
	    deprecated_warning(configname,configlineno,"--show-policy-url",
			       "--verify-options ","show-policy-urls");
	    opt.list_options|=LIST_SHOW_POLICY_URLS;
	    opt.verify_options|=VERIFY_SHOW_POLICY_URLS;
	    break;
	  case oNoShowPolicyURL:
	    deprecated_warning(configname,configlineno,"--no-show-policy-url",
			       "--list-options ","no-show-policy-urls");
	    deprecated_warning(configname,configlineno,"--no-show-policy-url",
			       "--verify-options ","no-show-policy-urls");
	    opt.list_options&=~LIST_SHOW_POLICY_URLS;
	    opt.verify_options&=~VERIFY_SHOW_POLICY_URLS;
	    break;
	  case oSigKeyserverURL: add_keyserver_url(pargs.r.ret_str,0); break;
	  case oUseEmbeddedFilename:
	    opt.flags.use_embedded_filename=1;
	    break;
	  case oNoUseEmbeddedFilename:
	    opt.flags.use_embedded_filename=0;
	    break;
	  case oComment:
	    if(pargs.r.ret_str[0])
	      append_to_strlist(&opt.comments,pargs.r.ret_str);
	    break;
	  case oDefaultComment:
	    deprecated_warning(configname,configlineno,
			       "--default-comment","--no-comments","");
	    /* fall through */
	  case oNoComments:
	    free_strlist(opt.comments);
	    opt.comments=NULL;
	    break;
	  case oThrowKeyids: opt.throw_keyid = 1; break;
	  case oNoThrowKeyids: opt.throw_keyid = 0; break;
	  case oShowPhotos:
	    deprecated_warning(configname,configlineno,"--show-photos",
			       "--list-options ","show-photos");
	    deprecated_warning(configname,configlineno,"--show-photos",
			       "--verify-options ","show-photos");
	    opt.list_options|=LIST_SHOW_PHOTOS;
	    opt.verify_options|=VERIFY_SHOW_PHOTOS;
	    break;
	  case oNoShowPhotos:
	    deprecated_warning(configname,configlineno,"--no-show-photos",
			       "--list-options ","no-show-photos");
	    deprecated_warning(configname,configlineno,"--no-show-photos",
			       "--verify-options ","no-show-photos");
	    opt.list_options&=~LIST_SHOW_PHOTOS;
	    opt.verify_options&=~VERIFY_SHOW_PHOTOS;
	    break;
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
	  case oS2KDigest: s2k_digest_string = xstrdup(pargs.r.ret_str); break;
	  case oS2KCipher: s2k_cipher_string = xstrdup(pargs.r.ret_str); break;
	  case oS2KCount:
	    opt.s2k_count=encode_s2k_iterations(pargs.r.ret_int);
	    break;
          case oSimpleSKChecksum: opt.simple_sk_checksum = 1; break;
	  case oNoEncryptTo: opt.no_encrypt_to = 1; break;
	  case oEncryptTo: /* store the recipient in the second list */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 1;
	    break;
	  case oHiddenEncryptTo: /* store the recipient in the second list */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 1|2;
	    break;
	  case oRecipient: /* store the recipient */
	    add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
            any_explicit_recipient = 1;
	    break;
	  case oHiddenRecipient: /* store the recipient with a flag */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 2;
            any_explicit_recipient = 1;
	    break;
	  case oTextmodeShort: opt.textmode = 2; break;
	  case oTextmode: opt.textmode=1;  break;
	  case oNoTextmode: opt.textmode=0;  break;
	  case oExpert: opt.expert = 1; break;
	  case oNoExpert: opt.expert = 0; break;
	  case oDefSigExpire:
	    if(*pargs.r.ret_str!='\0')
	      {
		if(parse_expire_string(0,pargs.r.ret_str)==(u32)-1)
		  log_error(_("`%s' is not a valid signature expiration\n"),
			    pargs.r.ret_str);
		else
		  opt.def_sig_expire=pargs.r.ret_str;
	      }
	    break;
	  case oAskSigExpire: opt.ask_sig_expire = 1; break;
	  case oNoAskSigExpire: opt.ask_sig_expire = 0; break;
	  case oDefCertExpire:
	    if(*pargs.r.ret_str!='\0')
	      {
		if(parse_expire_string(0,pargs.r.ret_str)==(u32)-1)
		  log_error(_("`%s' is not a valid signature expiration\n"),
			    pargs.r.ret_str);
		else
		  opt.def_cert_expire=pargs.r.ret_str;
	      }
	    break;
	  case oAskCertExpire: opt.ask_cert_expire = 1; break;
	  case oNoAskCertExpire: opt.ask_cert_expire = 0; break;
          case oDefCertLevel: opt.def_cert_level=pargs.r.ret_int; break;
          case oMinCertLevel: opt.min_cert_level=pargs.r.ret_int; break;
	  case oAskCertLevel: opt.ask_cert_level = 1; break;
	  case oNoAskCertLevel: opt.ask_cert_level = 0; break;
	  case oLocalUser: /* store the local users */
	    add_to_strlist2( &locusr, pargs.r.ret_str, utf8_strings );
	    break;
	  case oCompress:
	    /* this is the -z command line option */
	    opt.compress_level = opt.bz2_compress_level = pargs.r.ret_int;
	    break;
	  case oCompressLevel: opt.compress_level = pargs.r.ret_int; break;
	  case oBZ2CompressLevel: opt.bz2_compress_level = pargs.r.ret_int; break;
	  case oBZ2DecompressLowmem: opt.bz2_decompress_lowmem=1; break;
	  case oPasswd:
	    set_passphrase_from_string(pargs.r.ret_str);
	    break;
	  case oPasswdFD:
            pwfd = iobuf_translate_file_handle (pargs.r.ret_int, 0);
            opt.use_agent = 0;
            break;
	  case oPasswdFile:
            pwfd = open_info_file (pargs.r.ret_str, 0);
            break;
	  case oPasswdRepeat: opt.passwd_repeat=pargs.r.ret_int; break;
	  case oCommandFD:
            opt.command_fd = iobuf_translate_file_handle (pargs.r.ret_int, 0);
            break;
	  case oCommandFile:
            opt.command_fd = open_info_file (pargs.r.ret_str, 0);
            break;
	  case oCipherAlgo: 
            def_cipher_string = xstrdup(pargs.r.ret_str);
            break;
	  case oDigestAlgo:
            def_digest_string = xstrdup(pargs.r.ret_str);
            break;
	  case oCompressAlgo:
	    /* If it is all digits, stick a Z in front of it for
	       later.  This is for backwards compatibility with
	       versions that took the compress algorithm number. */
	    {
	      char *pt=pargs.r.ret_str;
	      while(*pt)
		{
		  if (!isascii (*pt) || !isdigit (*pt))
		    break;

		  pt++;
		}

	      if(*pt=='\0')
		{
		  compress_algo_string=xmalloc(strlen(pargs.r.ret_str)+2);
		  strcpy(compress_algo_string,"Z");
		  strcat(compress_algo_string,pargs.r.ret_str);
		}
	      else
		compress_algo_string = xstrdup(pargs.r.ret_str);
	    }
	    break;
	  case oCertDigestAlgo: cert_digest_string = xstrdup(pargs.r.ret_str); break;
	  case oNoSecmemWarn: secmem_set_flags( secmem_get_flags() | 1 ); break;
	  case oRequireSecmem: require_secmem=1; break;
	  case oNoRequireSecmem: require_secmem=0; break;
	  case oNoPermissionWarn: opt.no_perm_warn=1; break;
	  case oNoMDCWarn: opt.no_mdc_warn=1; break;
          case oDisplayCharset:
	    if( set_native_charset( pargs.r.ret_str ) )
		log_error(_("`%s' is not a valid character set\n"),
			  pargs.r.ret_str);
	    break;
	  case oNotDashEscaped: opt.not_dash_escaped = 1; break;
	  case oEscapeFrom: opt.escape_from = 1; break;
	  case oNoEscapeFrom: opt.escape_from = 0; break;
	  case oLockOnce: opt.lock_once = 1; break;
	  case oLockNever:
            disable_dotlock ();
            random_disable_locking ();
            break;
	  case oLockMultiple:
#ifndef __riscos__
	    opt.lock_once = 0;
#else /* __riscos__ */
            riscos_not_implemented("lock-multiple");
#endif /* __riscos__ */
            break;
	  case oKeyServer:
	    {
	      struct keyserver_spec *keyserver;
	      keyserver=parse_keyserver_uri(pargs.r.ret_str,0,
					    configname,configlineno);
	      if(!keyserver)
		log_error(_("could not parse keyserver URL\n"));
	      else
		{
		  keyserver->next=opt.keyserver;
		  opt.keyserver=keyserver;
		}
	    }
	    break;
	  case oKeyServerOptions:
	    if(!parse_keyserver_options(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid keyserver options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid keyserver options\n"));
	      }
	    break;
	  case oImportOptions:
	    if(!parse_import_options(pargs.r.ret_str,&opt.import_options,1))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid import options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid import options\n"));
	      }
	    break;
	  case oExportOptions:
	    if(!parse_export_options(pargs.r.ret_str,&opt.export_options,1))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid export options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid export options\n"));
	      }
	    break;
	  case oListOptions:
	    if(!parse_list_options(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid list options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid list options\n"));
	      }
	    break;
	  case oVerifyOptions:
	    {
	      struct parse_options vopts[]=
		{
		  {"show-photos",VERIFY_SHOW_PHOTOS,NULL,
		   N_("display photo IDs during signature verification")},
		  {"show-policy-urls",VERIFY_SHOW_POLICY_URLS,NULL,
		   N_("show policy URLs during signature verification")},
		  {"show-notations",VERIFY_SHOW_NOTATIONS,NULL,
		   N_("show all notations during signature verification")},
		  {"show-std-notations",VERIFY_SHOW_STD_NOTATIONS,NULL,
		   N_("show IETF standard notations during signature verification")},
		  {"show-standard-notations",VERIFY_SHOW_STD_NOTATIONS,NULL,
		   NULL},
		  {"show-user-notations",VERIFY_SHOW_USER_NOTATIONS,NULL,
		   N_("show user-supplied notations during signature verification")},
		  {"show-keyserver-urls",VERIFY_SHOW_KEYSERVER_URLS,NULL,
		   N_("show preferred keyserver URLs during signature verification")},
		  {"show-uid-validity",VERIFY_SHOW_UID_VALIDITY,NULL,
		   N_("show user ID validity during signature verification")},
		  {"show-unusable-uids",VERIFY_SHOW_UNUSABLE_UIDS,NULL,
		   N_("show revoked and expired user IDs in signature verification")},
		  {"show-primary-uid-only",VERIFY_SHOW_PRIMARY_UID_ONLY,NULL,
		   N_("show only the primary user ID in signature verification")},
		  {"pka-lookups",VERIFY_PKA_LOOKUPS,NULL,
		   N_("validate signatures with PKA data")},
		  {"pka-trust-increase",VERIFY_PKA_TRUST_INCREASE,NULL,
		   N_("elevate the trust of signatures with valid PKA data")},
		  {NULL,0,NULL,NULL}
		};

	      if(!parse_options(pargs.r.ret_str,&opt.verify_options,vopts,1))
		{
		  if(configname)
		    log_error(_("%s:%d: invalid verify options\n"),
			      configname,configlineno);
		  else
		    log_error(_("invalid verify options\n"));
		}
	    }
	    break;
	  case oTempDir: opt.temp_dir=pargs.r.ret_str; break;
	  case oExecPath:
	    if(set_exec_path(pargs.r.ret_str))
	      log_error(_("unable to set exec-path to %s\n"),pargs.r.ret_str);
	    else
	      opt.exec_path_set=1;
	    break;
	  case oSetNotation:
	    add_notation_data( pargs.r.ret_str, 0 );
	    add_notation_data( pargs.r.ret_str, 1 );
	    break;
	  case oSigNotation: add_notation_data( pargs.r.ret_str, 0 ); break;
	  case oCertNotation: add_notation_data( pargs.r.ret_str, 1 ); break;
	  case oShowNotation:
	    deprecated_warning(configname,configlineno,"--show-notation",
			       "--list-options ","show-notations");
	    deprecated_warning(configname,configlineno,"--show-notation",
			       "--verify-options ","show-notations");
	    opt.list_options|=LIST_SHOW_NOTATIONS;
	    opt.verify_options|=VERIFY_SHOW_NOTATIONS;
	    break;
	  case oNoShowNotation:
	    deprecated_warning(configname,configlineno,"--no-show-notation",
			       "--list-options ","no-show-notations");
	    deprecated_warning(configname,configlineno,"--no-show-notation",
			       "--verify-options ","no-show-notations");
	    opt.list_options&=~LIST_SHOW_NOTATIONS;
	    opt.verify_options&=~VERIFY_SHOW_NOTATIONS;
	    break;
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
	        add_to_strlist(&opt.keyserver_options.other,"http-proxy");
		deprecated_warning(configname,configlineno,
				   "--honor-http-proxy",
				   "--keyserver-options ","http-proxy");
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
	        if(pargs.r_opt==oAutoKeyRetrieve)
		  opt.keyserver_options.options|=KEYSERVER_AUTO_KEY_RETRIEVE;
		else
		  opt.keyserver_options.options&=~KEYSERVER_AUTO_KEY_RETRIEVE;

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
	  case oMergeOnly:
	        deprecated_warning(configname,configlineno,"--merge-only",
				   "--import-options ","merge-only");
		opt.import_options|=IMPORT_MERGE_ONLY;
	    break;
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
	  case oDefaultKeyserverURL:
	    {
	      struct keyserver_spec *keyserver;
	      keyserver=parse_keyserver_uri(pargs.r.ret_str,1,
					    configname,configlineno);
	      if(!keyserver)
		log_error(_("could not parse keyserver URL\n"));
	      else
		free_keyserver_spec(keyserver);

	      opt.def_keyserver_url = pargs.r.ret_str;
	    }
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
	  case oUnGroup: rm_group(pargs.r.ret_str); break;
	  case oNoGroups:
	    while(opt.grouplist)
	      {
		struct groupitem *iter=opt.grouplist;
		free_strlist(iter->values);
		opt.grouplist=opt.grouplist->next;
		xfree(iter);
	      }
	    break;
	  case oStrict: opt.strict=1; log_set_strict(1); break;
	  case oNoStrict: opt.strict=0; log_set_strict(0); break;
          case oMangleDosFilenames: opt.mangle_dos_filenames = 1; break;
          case oNoMangleDosFilenames: opt.mangle_dos_filenames = 0; break;
          case oEnableProgressFilter: opt.enable_progress_filter = 1; break;
	  case oMultifile: multifile=1; break;
	  case oKeyidFormat:
	    if(ascii_strcasecmp(pargs.r.ret_str,"short")==0)
	      opt.keyid_format=KF_SHORT;
	    else if(ascii_strcasecmp(pargs.r.ret_str,"long")==0)
	      opt.keyid_format=KF_LONG;
	    else if(ascii_strcasecmp(pargs.r.ret_str,"0xshort")==0)
	      opt.keyid_format=KF_0xSHORT;
	    else if(ascii_strcasecmp(pargs.r.ret_str,"0xlong")==0)
	      opt.keyid_format=KF_0xLONG;
	    else
	      log_error("unknown keyid-format `%s'\n",pargs.r.ret_str);
	    break;

          case oExitOnStatusWriteError:
            opt.exit_on_status_write_error = 1;
            break;

	  case oLimitCardInsertTries: 
            opt.limit_card_insert_tries = pargs.r.ret_int; 
            break;

	  case oRequireCrossCert: opt.flags.require_cross_cert=1; break;
	  case oNoRequireCrossCert: opt.flags.require_cross_cert=0; break;

	  case oAutoKeyLocate:
	    if(!parse_auto_key_locate(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid auto-key-locate list\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid auto-key-locate list\n"));
	      }
	    break;
	  case oNoAutoKeyLocate:
	    release_akl();
	    break;

	  case oEnableDSA2: opt.flags.dsa2=1; break;
	  case oDisableDSA2: opt.flags.dsa2=0; break;

          case oAllowMultisigVerification:
	  case oAllowMultipleMessages:
	    opt.flags.allow_multiple_messages=1;
	    break;

	  case oNoAllowMultipleMessages:
	    opt.flags.allow_multiple_messages=0;
	    break;

	  case oNoop: break;

	  default : pargs.err = configfp? 1:2; break;
	  }
      }


    if( configfp ) {
	fclose( configfp );
	configfp = NULL;
        /* Remember the first config file name. */
        if (!save_configname)
          save_configname = configname;
        else
          xfree(configname);
        configname = NULL;
	goto next_pass;
    }
    xfree( configname ); configname = NULL;
    if( log_get_errorcount(0) )
	g10_exit(2);

    /* The command --gpgconf-list is pretty simple and may be called
       directly after the option parsing. */
    if (cmd == aGPGConfList)
      {
        gpgconf_list (save_configname ? save_configname : default_configname);
        g10_exit (0);
      }
    xfree (save_configname);
    xfree (default_configname);

    if( nogreeting )
	greeting = 0;

    if( greeting ) {
	fprintf(stderr, "%s %s; %s\n",
			strusage(11), strusage(13), strusage(14) );
	fprintf(stderr, "%s\n", strusage(15) );
    }
#ifdef IS_DEVELOPMENT_VERSION
    if( !opt.batch )
      {
	const char *s;

	if((s=strusage(20)))
	  log_info("%s\n",s);
	if((s=strusage(21)))
	  log_info("%s\n",s);
	if((s=strusage(22)))
	  log_info("%s\n",s);
      }
#endif
#ifdef USE_CAMELLIA    
    /* We better also print a runtime warning if people build it with
       support for Camellia (which is not yet defiend by OpenPGP). */
    log_info ("WARNING: This version has been built with support for the "
              "Camellia cipher.\n");
    log_info ("         It is for testing only and is NOT for production "
              "use!\n");
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

#ifndef ENABLE_AGENT_SUPPORT   
    if (opt.use_agent) {
      log_info(_("NOTE: %s is not available in this version\n"),
               "--use-agent");
      opt.use_agent = 0;
    }
#endif /*!ENABLE_AGENT_SUPPORT*/

    if (opt.set_filesize)
	log_info(_("NOTE: %s is not for normal use!\n"), "--set-filesize");
    if( opt.batch )
	tty_batchmode( 1 );

    secmem_set_flags( secmem_get_flags() & ~2 ); /* resume warnings */

    if(require_secmem && !got_secmem)
      {
	log_info(_("will not run with insecure memory due to %s\n"),
		 "--require-secmem");
	g10_exit(2);
      }

    set_debug();

    /* Do these after the switch(), so they can override settings. */
    if(PGP2)
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
		xfree(def_cipher_string);
		def_cipher_string = xstrdup("idea");
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
	  compliance_failure();
	else
	  {
	    opt.force_v4_certs = 0;
	    opt.escape_from = 1;
	    opt.force_v3_sigs = 1;
	    opt.pgp2_workarounds = 1;
	    opt.ask_sig_expire = 0;
	    opt.ask_cert_expire = 0;
	    xfree(def_digest_string);
	    def_digest_string = xstrdup("md5");
	    xfree(s2k_digest_string);
	    s2k_digest_string = xstrdup("md5");
	    opt.compress_algo = COMPRESS_ALGO_ZIP;
	  }
      }
    else if(PGP6)
      {
	opt.escape_from=1;
	opt.force_v3_sigs=1;
	opt.ask_sig_expire=0;
      }
    else if(PGP7)
      {
	opt.escape_from=1;
	opt.force_v3_sigs=1;
	opt.ask_sig_expire=0;
      }
    else if(PGP8)
      {
	opt.escape_from=1;
      }

    /* must do this after dropping setuid, because string_to...
     * may try to load an module */
    if( def_cipher_string ) {
	opt.def_cipher_algo = string_to_cipher_algo(def_cipher_string);
	if(opt.def_cipher_algo==0 &&
	   (ascii_strcasecmp(def_cipher_string,"idea")==0
	    || ascii_strcasecmp(def_cipher_string,"s1")==0))
	  idea_cipher_warn(1);
	xfree(def_cipher_string); def_cipher_string = NULL;
	if( check_cipher_algo(opt.def_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( def_digest_string ) {
	opt.def_digest_algo = string_to_digest_algo(def_digest_string);
	xfree(def_digest_string); def_digest_string = NULL;
	if( check_digest_algo(opt.def_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( compress_algo_string ) {
	opt.compress_algo = string_to_compress_algo(compress_algo_string);
	xfree(compress_algo_string); compress_algo_string = NULL;
	if( check_compress_algo(opt.compress_algo) )
	    log_error(_("selected compression algorithm is invalid\n"));
    }
    if( cert_digest_string ) {
	opt.cert_digest_algo = string_to_digest_algo(cert_digest_string);
	xfree(cert_digest_string); cert_digest_string = NULL;
	if( check_digest_algo(opt.cert_digest_algo) )
	    log_error(_("selected certification digest algorithm is invalid\n"));
    }
    if( s2k_cipher_string ) {
	opt.s2k_cipher_algo = string_to_cipher_algo(s2k_cipher_string);
	xfree(s2k_cipher_string); s2k_cipher_string = NULL;
	if( check_cipher_algo(opt.s2k_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( s2k_digest_string ) {
	opt.s2k_digest_algo = string_to_digest_algo(s2k_digest_string);
	xfree(s2k_digest_string); s2k_digest_string = NULL;
	if( check_digest_algo(opt.s2k_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( opt.completes_needed < 1 )
      log_error(_("completes-needed must be greater than 0\n"));
    if( opt.marginals_needed < 2 )
      log_error(_("marginals-needed must be greater than 1\n"));
    if( opt.max_cert_depth < 1 || opt.max_cert_depth > 255 )
      log_error(_("max-cert-depth must be in the range from 1 to 255\n"));
    if(opt.def_cert_level<0 || opt.def_cert_level>3)
      log_error(_("invalid default-cert-level; must be 0, 1, 2, or 3\n"));
    if( opt.min_cert_level < 1 || opt.min_cert_level > 3 )
      log_error(_("invalid min-cert-level; must be 1, 2, or 3\n"));
    switch( opt.s2k_mode ) {
      case 0:
	log_info(_("NOTE: simple S2K mode (0) is strongly discouraged\n"));
	break;
      case 1: case 3: break;
      default:
	log_error(_("invalid S2K mode; must be 0, 1 or 3\n"));
    }

    /* This isn't actually needed, but does serve to error out if the
       string is invalid. */
    if(opt.def_preference_list &&
	keygen_set_std_prefs(opt.def_preference_list,0))
      log_error(_("invalid default preferences\n"));

    /* We provide defaults for the personal digest list.  This is
       SHA-1. */
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

    /* We don't support all possible commands with multifile yet */
    if(multifile)
      {
	char *cmdname;

	switch(cmd)
	  {
	  case aSign:
	    cmdname="--sign";
	    break;
	  case aClearsign:
	    cmdname="--clearsign";
	    break;
	  case aDetachedSign:
	    cmdname="--detach-sign";
	    break;
	  case aSym:
	    cmdname="--symmetric";
	    break;
	  case aEncrSym:
	    cmdname="--symmetric --encrypt";
	    break;
	  case aStore:
	    cmdname="--store";
	    break;
	  default:
	    cmdname=NULL;
	    break;
	  }

	if(cmdname)
	  log_error(_("%s does not yet work with %s\n"),cmdname,"--multifile");
      }

    if( log_get_errorcount(0) )
	g10_exit(2);

    if(opt.compress_level==0)
      opt.compress_algo=COMPRESS_ALGO_NONE;

    /* Check our chosen algorithms against the list of legal
       algorithms. */

    if(!GNUPG)
      {
	const char *badalg=NULL;
	preftype_t badtype=PREFTYPE_NONE;

	if(opt.def_cipher_algo
	   && !algo_available(PREFTYPE_SYM,opt.def_cipher_algo,NULL))
	  {
	    badalg=cipher_algo_to_string(opt.def_cipher_algo);
	    badtype=PREFTYPE_SYM;
	  }
	else if(opt.def_digest_algo
		&& !algo_available(PREFTYPE_HASH,opt.def_digest_algo,NULL))
	  {
	    badalg=digest_algo_to_string(opt.def_digest_algo);
	    badtype=PREFTYPE_HASH;
	  }
	else if(opt.cert_digest_algo
		&& !algo_available(PREFTYPE_HASH,opt.cert_digest_algo,NULL))
	  {
	    badalg=digest_algo_to_string(opt.cert_digest_algo);
	    badtype=PREFTYPE_HASH;
	  }
	else if(opt.compress_algo!=-1
		&& !algo_available(PREFTYPE_ZIP,opt.compress_algo,NULL))
	  {
	    badalg=compress_algo_to_string(opt.compress_algo);
	    badtype=PREFTYPE_ZIP;
	  }

	if(badalg)
	  {
	    switch(badtype)
	      {
	      case PREFTYPE_SYM:
		log_info(_("you may not use cipher algorithm `%s'"
			   " while in %s mode\n"),
			 badalg,compliance_option_string());
		break;
	      case PREFTYPE_HASH:
		log_info(_("you may not use digest algorithm `%s'"
			   " while in %s mode\n"),
			 badalg,compliance_option_string());
		break;
	      case PREFTYPE_ZIP:
		log_info(_("you may not use compression algorithm `%s'"
			   " while in %s mode\n"),
			 badalg,compliance_option_string());
		break;
	      default:
		BUG();
	      }

	    compliance_failure();
	  }
      }

    /* set the random seed file */
    if( use_random_seed ) {
	char *p = make_filename(opt.homedir, "random_seed", NULL );
	set_random_seed_file(p);
        if (!access (p, F_OK))
          register_secured_file (p);
	xfree(p);
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

    /* kludge to let -sat generate a clear text signature */
    if( opt.textmode == 2 && !detached_sig && opt.armor && cmd == aSign )
	cmd = aClearsign;

    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    if (cmd == aGPGConfTest)
      g10_exit(0);

    /* Add the keyrings, but not for some special commands and not in
       case of "-kvv userid keyring".  Also avoid adding the secret
       keyring for a couple of commands to avoid unneeded access in
       case the secrings are stored on a floppy.
       
       We always need to add the keyrings if we are running under
       SELinux, this is so that the rings are added to the list of
       secured files. */
    if( ALWAYS_ADD_KEYRINGS 
        || (cmd != aDeArmor && cmd != aEnArmor
            && !(cmd == aKMode && argc == 2 )) ) 
      {
        if (ALWAYS_ADD_KEYRINGS
            || (cmd != aCheckKeys && cmd != aListSigs && cmd != aListKeys
                && cmd != aVerify && cmd != aSym))
          {
            if (!sec_nrings || default_keyring) /* add default secret rings */
              keydb_add_resource ("secring" EXTSEP_S "gpg", 4, 1);
            for (sl = sec_nrings; sl; sl = sl->next)
              keydb_add_resource ( sl->d, 0, 1 );
          }
	if( !nrings || default_keyring )  /* add default ring */
	    keydb_add_resource ("pubring" EXTSEP_S "gpg", 4, 0);
	for(sl = nrings; sl; sl = sl->next )
	    keydb_add_resource ( sl->d, sl->flags, 0 );
      }
    FREE_STRLIST(nrings);
    FREE_STRLIST(sec_nrings);


    if( pwfd != -1 )  /* read the passphrase now. */
	read_passphrase_from_fd( pwfd );

    fname = argc? *argv : NULL;

    if(fname && utf8_strings)
      opt.flags.utf8_filename=1;

    switch( cmd ) {
      case aPrimegen:
      case aPrintMD:
      case aPrintMDs:
      case aGenRandom:
      case aDeArmor:
      case aEnArmor:
      case aFixTrustDB:
	break;
      case aExportOwnerTrust: rc = setup_trustdb( 0, trustdb_name ); break;
      case aListTrustDB: rc = setup_trustdb( argc? 1:0, trustdb_name ); break;
      default: rc = setup_trustdb(1, trustdb_name ); break;
    }
    if( rc )
	log_error(_("failed to initialize the TrustDB: %s\n"), g10_errstr(rc));


    switch (cmd)
      {
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

    switch( cmd )
      {
      case aStore: /* only store the file */
	if( argc > 1 )
	    wrong_args(_("--store [filename]"));
	if( (rc = encode_store(fname)) )
	    log_error ("storing `%s' failed: %s\n",
                       print_fname_stdin(fname),g10_errstr(rc) );
	break;
      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    wrong_args(_("--symmetric [filename]"));
	if( (rc = encode_symmetric(fname)) )
            log_error (_("symmetric encryption of `%s' failed: %s\n"),
                        print_fname_stdin(fname),g10_errstr(rc) );
	break;

      case aEncr: /* encrypt the given file */
	if(multifile)
	  encode_crypt_files(argc, argv, remusr);
	else
	  {
	    if( argc > 1 )
	      wrong_args(_("--encrypt [filename]"));
	    if( (rc = encode_crypt(fname,remusr,0)) )
	      log_error("%s: encryption failed: %s\n",
			print_fname_stdin(fname), g10_errstr(rc) );
	  }
	break;

      case aEncrSym:
	/* This works with PGP 8 in the sense that it acts just like a
	   symmetric message.  It doesn't work at all with 2 or 6.  It
	   might work with 7, but alas, I don't have a copy to test
	   with right now. */
	if( argc > 1 )
	  wrong_args(_("--symmetric --encrypt [filename]"));
	else if(opt.s2k_mode==0)
	  log_error(_("you cannot use --symmetric --encrypt"
		      " with --s2k-mode 0\n"));
	else if(PGP2 || PGP6 || PGP7 || RFC1991)
	  log_error(_("you cannot use --symmetric --encrypt"
		      " while in %s mode\n"),compliance_option_string());
	else
	  {
	    if( (rc = encode_crypt(fname,remusr,1)) )
	      log_error("%s: encryption failed: %s\n",
			print_fname_stdin(fname), g10_errstr(rc) );
	  }
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
		sl = xmalloc_clear( sizeof *sl + strlen(fname));
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
	    sl = xmalloc_clear( sizeof *sl + strlen(fname));
	    strcpy(sl->d, fname);
	}
	else
	    sl = NULL;
	if( (rc = sign_file(sl, detached_sig, locusr, 1, remusr, NULL)) )
	    log_error("%s: sign+encrypt failed: %s\n",
		      print_fname_stdin(fname), g10_errstr(rc) );
	free_strlist(sl);
	break;

      case aSignEncrSym: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--symmetric --sign --encrypt [filename]"));
	else if(opt.s2k_mode==0)
	  log_error(_("you cannot use --symmetric --sign --encrypt"
		      " with --s2k-mode 0\n"));
	else if(PGP2 || PGP6 || PGP7 || RFC1991)
	  log_error(_("you cannot use --symmetric --sign --encrypt"
		      " while in %s mode\n"),compliance_option_string());
	else
	  {
	    if( argc )
	      {
		sl = xmalloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	      }
	    else
	      sl = NULL;
	    if( (rc = sign_file(sl, detached_sig, locusr, 2, remusr, NULL)) )
	      log_error("%s: symmetric+sign+encrypt failed: %s\n",
			print_fname_stdin(fname), g10_errstr(rc) );
	    free_strlist(sl);
	  }
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
	if(multifile)
	  {
	    if( (rc = verify_files( argc, argv ) ))
	      log_error("verify files failed: %s\n", g10_errstr(rc) );
	  }
	else
	  {
	    if( (rc = verify_signatures( argc, argv ) ))
	      log_error("verify signatures failed: %s\n", g10_errstr(rc) );
	  }
	break;

      case aDecrypt:
        if(multifile)
	  decrypt_messages(argc, argv);
	else
	  {
	    if( argc > 1 )
	      wrong_args(_("--decrypt [filename]"));
	    if( (rc = decrypt_message( fname ) ))
	      log_error("decrypt_message failed: %s\n", g10_errstr(rc) );
	  }
	break;
            
      case aSignKey:
	if( argc != 1 )
	  wrong_args(_("--sign-key user-id"));
	/* fall through */
      case aLSignKey:
	if( argc != 1 )
	  wrong_args(_("--lsign-key user-id"));
	/* fall through */

	sl=NULL;

	if(cmd==aSignKey)
	  append_to_strlist(&sl,"sign");
	else if(cmd==aLSignKey)
	  append_to_strlist(&sl,"lsign");
	else
	  BUG();

	append_to_strlist( &sl, "save" );
	username = make_username( fname );
	keyedit_menu(fname, locusr, sl, 0, 0 );
	xfree(username);
	free_strlist(sl);
	break;

      case aEditKey: /* Edit a key signature */
	if( !argc )
	    wrong_args(_("--edit-key user-id [commands]"));
	username = make_username( fname );
	if( argc > 1 ) {
	    sl = NULL;
	    for( argc--, argv++ ; argc; argc--, argv++ )
		append_to_strlist( &sl, *argv );
	    keyedit_menu( username, locusr, sl, 0, 1 );
	    free_strlist(sl);
	}
	else
	    keyedit_menu(username, locusr, NULL, 0, 1 );
	xfree(username);
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
		log_error(_("can't open `%s': %s\n"),
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
	    generate_keypair( argc? *argv : NULL, NULL, NULL );
	}
	else {
	    if( argc )
		wrong_args("--gen-key");
	    generate_keypair(NULL, NULL, NULL);
	}
	break;

      case aFastImport:
        opt.import_options |= IMPORT_FAST;
      case aImport:
	import_keys( argc? argv:NULL, argc, NULL, opt.import_options );
	break;

	/* TODO: There are a number of command that use this same
	   "make strlist, call function, report error, free strlist"
	   pattern.  Join them together here and avoid all that
	   duplicated code. */

      case aExport:
      case aSendKeys:
      case aRecvKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	if( cmd == aSendKeys )
	    rc=keyserver_export( sl );
	else if( cmd == aRecvKeys )
	    rc=keyserver_import( sl );
	else
	    rc=export_pubkeys( sl, opt.export_options );
	if(rc)
	  {
	    if(cmd==aSendKeys)
	      log_error(_("keyserver send failed: %s\n"),g10_errstr(rc));
	    else if(cmd==aRecvKeys)
	      log_error(_("keyserver receive failed: %s\n"),g10_errstr(rc));
	    else
	      log_error(_("key export failed: %s\n"),g10_errstr(rc));
	  }
	free_strlist(sl);
	break;

     case aSearchKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	  append_to_strlist2( &sl, *argv, utf8_strings );
	rc=keyserver_search( sl );
	if(rc)
	  log_error(_("keyserver search failed: %s\n"),g10_errstr(rc));
	free_strlist(sl);
	break;

      case aRefreshKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	rc=keyserver_refresh(sl);
	if(rc)
	  log_error(_("keyserver refresh failed: %s\n"),g10_errstr(rc));
	free_strlist(sl);
	break;

      case aFetchKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	rc=keyserver_fetch(sl);
	if(rc)
	  log_error("key fetch failed: %s\n",g10_errstr(rc));
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
	xfree( username );
	break;

      case aDesigRevoke:
	if( argc != 1 )
	    wrong_args("--desig-revoke user-id");
	username =  make_username(*argv);
	gen_desig_revoke( username, locusr );
	xfree( username );
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
                    xfree (tmp);
                    if (n%3 == 1)
                      putchar ('=');
                    if (n%3)
                      putchar ('=');
                } else {
                    fwrite( p, n, 1, stdout );
                }
		xfree(p);
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
	    xfree(username);
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
        keydb_rebuild_caches (1);
        break;

#ifdef ENABLE_CARD_SUPPORT
      case aCardStatus:
        if (argc)
            wrong_args ("--card-status");
        card_status (stdout, NULL, 0);
        break;

      case aCardEdit:
        if (argc) {
            sl = NULL;
            for (argc--, argv++ ; argc; argc--, argv++)
                append_to_strlist (&sl, *argv);
            card_edit (sl);
            free_strlist (sl);
	}
        else
            card_edit (NULL);
        break;

      case aChangePIN:
        if (!argc)
            change_pin (0,1);
        else if (argc == 1)
            change_pin (atoi (*argv),1);
        else
        wrong_args ("--change-pin [no]");
        break;
#endif /* ENABLE_CARD_SUPPORT*/

      case aListConfig:
	{
	  char *str=collapse_args(argc,argv);
	  list_config(str);
	  xfree(str);
	}
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

	a = iobuf_open(fname);
        if (a && is_secured_file (iobuf_get_fd (a)))
          {
            iobuf_close (a);
            a = NULL;
            errno = EPERM;
          }
	if( !a )
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
#ifdef ENABLE_CARD_SUPPORT
    card_close ();
#endif
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


/* Pretty-print hex hashes.  This assumes at least an 80-character
   display, but there are a few other similar assumptions in the
   display code. */
static void
print_hex( MD_HANDLE md, int algo, const char *fname )
{
  int i,n,count,indent=0;
  const byte *p;

  if(fname)
    indent=printf("%s: ",fname);

  if(indent>40)
    {
      printf("\n");
      indent=0;
    }

  if(algo==DIGEST_ALGO_RMD160)
    indent+=printf("RMD160 = ");
  else if(algo>0)
    indent+=printf("%6s = ",digest_algo_to_string(algo));
  else
    algo=abs(algo);

  count=indent;

  p = md_read( md, algo );
  n = md_digest_length(algo);

  count+=printf("%02X",*p++);

  for(i=1;i<n;i++,p++)
    {
      if(n==16)
	{
	  if(count+2>79)
	    {
	      printf("\n%*s",indent," ");
	      count=indent;
	    }
	  else
	    count+=printf(" ");

	  if(!(i%8))
	    count+=printf(" ");
	}
      else if (n==20)
	{
	  if(!(i%2))
	    {
	      if(count+4>79)
		{
		  printf("\n%*s",indent," ");
		  count=indent;
		}
	      else
		count+=printf(" ");
	    }

	  if(!(i%10))
	    count+=printf(" ");
	}
      else
	{
	  if(!(i%4))
	    {
	      if(count+8>79)
		{
		  printf("\n%*s",indent," ");
		  count=indent;
		}
	      else
		count+=printf(" ");
	    }
	}

      count+=printf("%02X",*p);
    }

  printf("\n");
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

    if( !fname ) {
	fp = stdin;
#ifdef HAVE_DOSISH_SYSTEM
	setmode ( fileno(fp) , O_BINARY );
#endif
    }
    else {
	fp = fopen( fname, "rb" );
        if (fp && is_secured_file (fileno (fp)))
          {
            fclose (fp);
            fp = NULL;
            errno = EPERM;
          }
    }
    if( !fp ) {
	log_error("%s: %s\n", fname?fname:"[stdin]", strerror(errno) );
	return;
    }

    md = md_open( 0, 0 );
    if( algo )
	md_enable( md, algo );
    else {
	md_enable( md, DIGEST_ALGO_MD5 );
	md_enable( md, DIGEST_ALGO_SHA1 );
	md_enable( md, DIGEST_ALGO_RMD160 );
#ifdef USE_SHA256
	md_enable( md, DIGEST_ALGO_SHA224 );
	md_enable( md, DIGEST_ALGO_SHA256 );
#endif
#ifdef USE_SHA512
	md_enable( md, DIGEST_ALGO_SHA384 );
	md_enable( md, DIGEST_ALGO_SHA512 );
#endif
    }

    while( (n=fread( buf, 1, DIM(buf), fp )) )
	md_write( md, buf, n );
    if( ferror(fp) )
	log_error("%s: %s\n", fname?fname:"[stdin]", strerror(errno) );
    else {
	md_final(md);
        if ( opt.with_colons ) {
            if ( algo ) 
                print_hashline( md, algo, fname );
            else {
                print_hashline( md, DIGEST_ALGO_MD5, fname );
                print_hashline( md, DIGEST_ALGO_SHA1, fname );
                print_hashline( md, DIGEST_ALGO_RMD160, fname );
#ifdef USE_SHA256
                print_hashline( md, DIGEST_ALGO_SHA224, fname );
                print_hashline( md, DIGEST_ALGO_SHA256, fname );
#endif
#ifdef USE_SHA512
		print_hashline( md, DIGEST_ALGO_SHA384, fname );
		print_hashline( md, DIGEST_ALGO_SHA512, fname );
#endif
            }
        }
        else {
            if( algo )
	       print_hex(md,-algo,fname);
            else {
                print_hex( md, DIGEST_ALGO_MD5, fname );
                print_hex( md, DIGEST_ALGO_SHA1, fname );
                print_hex( md, DIGEST_ALGO_RMD160, fname );
#ifdef USE_SHA256
                print_hex( md, DIGEST_ALGO_SHA224, fname );
                print_hex( md, DIGEST_ALGO_SHA256, fname );
#endif
#ifdef USE_SHA512
		print_hex( md, DIGEST_ALGO_SHA384, fname );
		print_hex( md, DIGEST_ALGO_SHA512, fname );
#endif
            }
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
  struct notation *notation;

  notation=string_to_notation(string,utf8_strings);
  if(notation)
    {
      if(which)
	{
	  notation->next=opt.cert_notations;
	  opt.cert_notations=notation;
	}
      else
	{
	  notation->next=opt.sig_notations;
	  opt.sig_notations=notation;
	}
    }
}

static void
add_policy_url( const char *string, int which )
{
  unsigned int i,critical=0;
  STRLIST sl;

  if(*string=='!')
    {
      string++;
      critical=1;
    }

  for(i=0;i<strlen(string);i++)
    if( !isascii (string[i]) || iscntrl(string[i]))
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

static void
add_keyserver_url( const char *string, int which )
{
  unsigned int i,critical=0;
  STRLIST sl;

  if(*string=='!')
    {
      string++;
      critical=1;
    }

  for(i=0;i<strlen(string);i++)
    if( !isascii (string[i]) || iscntrl(string[i]))
      break;

  if(i==0 || i<strlen(string))
    {
      if(which)
	BUG();
      else
	log_error(_("the given preferred keyserver URL is invalid\n"));
    }

  if(which)
    BUG();
  else
    sl=add_to_strlist( &opt.sig_keyserver_url, string );

  if(critical)
    sl->flags |= 1;    
}
