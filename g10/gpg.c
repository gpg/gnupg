/* gpg.c - The GnuPG utility (main for gpg)
 * Copyright (C) 1998-2020 Free Software Foundation, Inc.
 * Copyright (C) 1997-2019 Werner Koch
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
#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif
#include <fcntl.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "gpg.h"
#include <assuan.h>
#include "../common/iobuf.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/membuf.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "filter.h"
#include "../common/ttyio.h"
#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/status.h"
#include "keyserver-internal.h"
#include "exec.h"
#include "../common/gc-opt-flags.h"
#include "../common/asshelp.h"
#include "call-dirmngr.h"
#include "tofu.h"
#include "../common/init.h"
#include "../common/mbox-util.h"
#include "../common/shareddefs.h"
#include "../common/compliance.h"

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
#define MY_O_BINARY  O_BINARY
#ifndef S_IRGRP
# define S_IRGRP 0
# define S_IWGRP 0
#endif
#else
#define MY_O_BINARY  0
#endif

#ifdef __MINGW32__
int _dowildcard = -1;
#endif

enum cmd_and_opt_values
  {
    aNull = 0,
    oArmor	  = 'a',
    aDetachedSign = 'b',
    aSym	  = 'c',
    aDecrypt	  = 'd',
    aEncr	  = 'e',
    oRecipientFile       = 'f',
    oHiddenRecipientFile = 'F',
    oInteractive  = 'i',
    aListKeys	  = 'k',
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
    oInputSizeHint,
    oSigNotation,
    oCertNotation,
    oShowNotation,
    oNoShowNotation,
    oKnownNotation,
    aEncrFiles,
    aEncrSym,
    aDecryptFiles,
    aClearsign,
    aStore,
    aQuickKeygen,
    aFullKeygen,
    aKeygen,
    aSignEncr,
    aSignEncrSym,
    aSignSym,
    aSignKey,
    aLSignKey,
    aQuickSignKey,
    aQuickLSignKey,
    aQuickRevSig,
    aQuickAddUid,
    aQuickAddKey,
    aQuickRevUid,
    aQuickSetExpire,
    aQuickSetPrimaryUid,
    aListConfig,
    aListGcryptConfig,
    aGPGConfList,
    aGPGConfTest,
    aListPackets,
    aEditKey,
    aDeleteKeys,
    aDeleteSecretKeys,
    aDeleteSecretAndPublicKeys,
    aImport,
    aFastImport,
    aVerify,
    aVerifyFiles,
    aListSigs,
    aSendKeys,
    aRecvKeys,
    aLocateKeys,
    aLocateExtKeys,
    aSearchKeys,
    aRefreshKeys,
    aFetchKeys,
    aShowKeys,
    aExport,
    aExportSecret,
    aExportSecretSub,
    aExportSshKey,
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
    aRebuildKeydbCaches,
    aCardStatus,
    aCardEdit,
    aChangePIN,
    aPasswd,
    aServer,
    aTOFUPolicy,

    oMimemode,
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
    oWithSubkeyFingerprint,
    oWithICAOSpelling,
    oWithKeygrip,
    oWithSecret,
    oWithWKDHash,
    oWithColons,
    oWithKeyData,
    oWithKeyOrigin,
    oWithTofuInfo,
    oWithSigList,
    oWithSigCheck,
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
    oTrySecretKey,
    oOptions,
    oDebug,
    oDebugLevel,
    oDebugAll,
    oDebugIOLBF,
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
    oCompliance,
    oGnuPG,
    oRFC2440,
    oRFC4880,
    oRFC4880bis,
    oOpenPGP,
    oPGP6,
    oPGP7,
    oPGP8,
    oDE_VS,
    oRFC2440Text,
    oNoRFC2440Text,
    oCipherAlgo,
    oDigestAlgo,
    oCertDigestAlgo,
    oCompressAlgo,
    oCompressLevel,
    oBZ2CompressLevel,
    oBZ2DecompressLowmem,
    oPassphrase,
    oPassphraseFD,
    oPassphraseFile,
    oPassphraseRepeat,
    oPinentryMode,
    oCommandFD,
    oCommandFile,
    oQuickRandom,
    oNoVerbose,
    oTrustDBName,
    oNoSecmemWarn,
    oRequireSecmem,
    oNoRequireSecmem,
    oNoPermissionWarn,
    oNoArmor,
    oNoDefKeyring,
    oNoKeyring,
    oNoGreeting,
    oNoTTY,
    oNoOptions,
    oNoBatch,
    oHomedir,
    oSkipVerify,
    oSkipHiddenRecipients,
    oNoSkipHiddenRecipients,
    oAlwaysTrust,
    oTrustModel,
    oForceOwnertrust,
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
    oS2KMode,
    oS2KDigest,
    oS2KCipher,
    oS2KCount,
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
    oImportFilter,
    oExportOptions,
    oExportFilter,
    oListOptions,
    oVerifyOptions,
    oTempDir,
    oExecPath,
    oEncryptTo,
    oHiddenEncryptTo,
    oNoEncryptTo,
    oEncryptToDefaultKey,
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
    oOverrideSessionKeyFD,
    oNoRandomSeedFile,
    oAutoKeyRetrieve,
    oNoAutoKeyRetrieve,
    oAutoKeyImport,
    oNoAutoKeyImport,
    oUseAgent,
    oNoUseAgent,
    oGpgAgentInfo,
    oMergeOnly,
    oTryAllSecrets,
    oTrustedKey,
    oNoExpensiveTrustChecks,
    oFixedListMode,
    oLegacyListMode,
    oNoSigCache,
    oAutoCheckTrustDB,
    oNoAutoCheckTrustDB,
    oPreservePermissions,
    oDefaultPreferenceList,
    oDefaultKeyserverURL,
    oPersonalCipherPreferences,
    oPersonalDigestPreferences,
    oPersonalCompressPreferences,
    oAgentProgram,
    oDirmngrProgram,
    oDisableDirmngr,
    oDisplay,
    oTTYname,
    oTTYtype,
    oLCctype,
    oLCmessages,
    oXauthority,
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
    oEnableLargeRSA,
    oDisableLargeRSA,
    oEnableDSA2,
    oDisableDSA2,
    oAllowMultipleMessages,
    oNoAllowMultipleMessages,
    oAllowWeakDigestAlgos,
    oAllowWeakKeySignatures,
    oFakedSystemTime,
    oNoAutostart,
    oPrintPKARecords,
    oPrintDANERecords,
    oTOFUDefaultPolicy,
    oTOFUDBFormat,
    oDefaultNewKeyAlgo,
    oWeakDigest,
    oUnwrap,
    oOnlySignTextIDs,
    oDisableSignerUID,
    oSender,
    oKeyOrigin,
    oRequestOrigin,
    oNoSymkeyCache,
    oUseOnlyOpenPGPCard,
    oIncludeKeyBlock,
    oNoIncludeKeyBlock,

    oNoop
  };


static ARGPARSE_OPTS opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aSign, "sign", N_("make a signature")),
  ARGPARSE_c (aClearsign, "clear-sign", N_("make a clear text signature")),
  ARGPARSE_c (aClearsign, "clearsign", "@"),
  ARGPARSE_c (aDetachedSign, "detach-sign", N_("make a detached signature")),
  ARGPARSE_c (aEncr, "encrypt",   N_("encrypt data")),
  ARGPARSE_c (aEncrFiles, "encrypt-files", "@"),
  ARGPARSE_c (aSym, "symmetric", N_("encryption only with symmetric cipher")),
  ARGPARSE_c (aStore, "store",     "@"),
  ARGPARSE_c (aDecrypt, "decrypt",   N_("decrypt data (default)")),
  ARGPARSE_c (aDecryptFiles, "decrypt-files", "@"),
  ARGPARSE_c (aVerify, "verify"   , N_("verify a signature")),
  ARGPARSE_c (aVerifyFiles, "verify-files" , "@" ),
  ARGPARSE_c (aListKeys, "list-keys", N_("list keys")),
  ARGPARSE_c (aListKeys, "list-public-keys", "@" ),
  ARGPARSE_c (aListSigs, "list-signatures", N_("list keys and signatures")),
  ARGPARSE_c (aListSigs, "list-sigs", "@"),
  ARGPARSE_c (aCheckKeys, "check-signatures",
	      N_("list and check key signatures")),
  ARGPARSE_c (aCheckKeys, "check-sigs", "@"),
  ARGPARSE_c (oFingerprint, "fingerprint", N_("list keys and fingerprints")),
  ARGPARSE_c (aListSecretKeys, "list-secret-keys", N_("list secret keys")),
  ARGPARSE_c (aKeygen,	    "generate-key",
              N_("generate a new key pair")),
  ARGPARSE_c (aKeygen,	    "gen-key", "@"),
  ARGPARSE_c (aQuickKeygen, "quick-generate-key" ,
              N_("quickly generate a new key pair")),
  ARGPARSE_c (aQuickKeygen, "quick-gen-key", "@"),
  ARGPARSE_c (aQuickAddUid,  "quick-add-uid",
              N_("quickly add a new user-id")),
  ARGPARSE_c (aQuickAddUid,  "quick-adduid", "@"),
  ARGPARSE_c (aQuickAddKey,  "quick-add-key", "@"),
  ARGPARSE_c (aQuickAddKey,  "quick-addkey", "@"),
  ARGPARSE_c (aQuickRevUid,  "quick-revoke-uid",
              N_("quickly revoke a user-id")),
  ARGPARSE_c (aQuickRevUid,  "quick-revuid", "@"),
  ARGPARSE_c (aQuickSetExpire,  "quick-set-expire",
              N_("quickly set a new expiration date")),
  ARGPARSE_c (aQuickSetPrimaryUid,  "quick-set-primary-uid", "@"),
  ARGPARSE_c (aFullKeygen,  "full-generate-key" ,
              N_("full featured key pair generation")),
  ARGPARSE_c (aFullKeygen,  "full-gen-key", "@"),
  ARGPARSE_c (aGenRevoke, "generate-revocation",
	      N_("generate a revocation certificate")),
  ARGPARSE_c (aGenRevoke, "gen-revoke", "@"),
  ARGPARSE_c (aDeleteKeys,"delete-keys",
              N_("remove keys from the public keyring")),
  ARGPARSE_c (aDeleteSecretKeys, "delete-secret-keys",
              N_("remove keys from the secret keyring")),
  ARGPARSE_c (aQuickSignKey,  "quick-sign-key" ,
              N_("quickly sign a key")),
  ARGPARSE_c (aQuickLSignKey, "quick-lsign-key",
              N_("quickly sign a key locally")),
  ARGPARSE_c (aQuickRevSig,   "quick-revoke-sig" ,
              N_("quickly revoke a key signature")),
  ARGPARSE_c (aSignKey,  "sign-key"   ,N_("sign a key")),
  ARGPARSE_c (aLSignKey, "lsign-key"  ,N_("sign a key locally")),
  ARGPARSE_c (aEditKey,  "edit-key"   ,N_("sign or edit a key")),
  ARGPARSE_c (aEditKey,  "key-edit"   ,"@"),
  ARGPARSE_c (aPasswd,   "change-passphrase", N_("change a passphrase")),
  ARGPARSE_c (aPasswd,   "passwd", "@"),
  ARGPARSE_c (aDesigRevoke, "generate-designated-revocation", "@"),
  ARGPARSE_c (aDesigRevoke, "desig-revoke","@" ),
  ARGPARSE_c (aExport, "export"           , N_("export keys") ),
  ARGPARSE_c (aSendKeys, "send-keys"     , N_("export keys to a keyserver") ),
  ARGPARSE_c (aRecvKeys, "receive-keys" , N_("import keys from a keyserver") ),
  ARGPARSE_c (aRecvKeys, "recv-keys"     , "@"),
  ARGPARSE_c (aSearchKeys, "search-keys" ,
              N_("search for keys on a keyserver") ),
  ARGPARSE_c (aRefreshKeys, "refresh-keys",
              N_("update all keys from a keyserver")),
  ARGPARSE_c (aLocateKeys, "locate-keys", "@"),
  ARGPARSE_c (aLocateExtKeys, "locate-external-keys", "@"),
  ARGPARSE_c (aFetchKeys, "fetch-keys" , "@" ),
  ARGPARSE_c (aShowKeys, "show-keys" , "@" ),
  ARGPARSE_c (aExportSecret, "export-secret-keys" , "@" ),
  ARGPARSE_c (aExportSecretSub, "export-secret-subkeys" , "@" ),
  ARGPARSE_c (aExportSshKey, "export-ssh-key", "@" ),
  ARGPARSE_c (aImport, "import", N_("import/merge keys")),
  ARGPARSE_c (aFastImport, "fast-import", "@"),
#ifdef ENABLE_CARD_SUPPORT
  ARGPARSE_c (aCardStatus,  "card-status", N_("print the card status")),
  ARGPARSE_c (aCardEdit,   "edit-card",  N_("change data on a card")),
  ARGPARSE_c (aCardEdit,   "card-edit", "@"),
  ARGPARSE_c (aChangePIN,  "change-pin", N_("change a card's PIN")),
#endif
  ARGPARSE_c (aListConfig, "list-config", "@"),
  ARGPARSE_c (aListGcryptConfig, "list-gcrypt-config", "@"),
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@" ),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@" ),
  ARGPARSE_c (aListPackets, "list-packets","@"),

#ifndef NO_TRUST_MODELS
  ARGPARSE_c (aExportOwnerTrust, "export-ownertrust", "@"),
  ARGPARSE_c (aImportOwnerTrust, "import-ownertrust", "@"),
  ARGPARSE_c (aUpdateTrustDB,"update-trustdb",
              N_("update the trust database")),
  ARGPARSE_c (aCheckTrustDB, "check-trustdb", "@"),
  ARGPARSE_c (aFixTrustDB, "fix-trustdb", "@"),
#endif

  ARGPARSE_c (aDeArmor, "dearmor", "@"),
  ARGPARSE_c (aDeArmor, "dearmour", "@"),
  ARGPARSE_c (aEnArmor, "enarmor", "@"),
  ARGPARSE_c (aEnArmor, "enarmour", "@"),
  ARGPARSE_c (aPrintMD, "print-md", N_("print message digests")),
  ARGPARSE_c (aPrimegen, "gen-prime", "@" ),
  ARGPARSE_c (aGenRandom,"gen-random", "@" ),
  ARGPARSE_c (aServer,   "server",  N_("run in server mode")),
  ARGPARSE_c (aTOFUPolicy, "tofu-policy",
	      N_("|VALUE|set the TOFU policy for a key")),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oArmor, "armor", N_("create ascii armored output")),
  ARGPARSE_s_n (oArmor, "armour", "@"),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oHiddenRecipient, "hidden-recipient", "@"),
  ARGPARSE_s_s (oRecipientFile, "recipient-file", "@"),
  ARGPARSE_s_s (oHiddenRecipientFile, "hidden-recipient-file", "@"),
  ARGPARSE_s_s (oRecipient, "remote-user", "@"),  /* (old option name) */
  ARGPARSE_s_s (oDefRecipient, "default-recipient", "@"),
  ARGPARSE_s_n (oDefRecipientSelf,  "default-recipient-self", "@"),
  ARGPARSE_s_n (oNoDefRecipient, "no-default-recipient", "@"),

  ARGPARSE_s_s (oTempDir,  "temp-directory", "@"),
  ARGPARSE_s_s (oExecPath, "exec-path", "@"),
  ARGPARSE_s_s (oEncryptTo,      "encrypt-to", "@"),
  ARGPARSE_s_n (oNoEncryptTo, "no-encrypt-to", "@"),
  ARGPARSE_s_s (oHiddenEncryptTo, "hidden-encrypt-to", "@"),
  ARGPARSE_s_n (oEncryptToDefaultKey, "encrypt-to-default-key", "@"),
  ARGPARSE_s_s (oLocalUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),
  ARGPARSE_s_s (oSender, "sender", "@"),

  ARGPARSE_s_s (oTrySecretKey, "try-secret-key", "@"),

  ARGPARSE_s_i (oCompress, NULL,
                N_("|N|set compress level to N (0 disables)")),
  ARGPARSE_s_i (oCompressLevel, "compress-level", "@"),
  ARGPARSE_s_i (oBZ2CompressLevel, "bzip2-compress-level", "@"),
  ARGPARSE_s_n (oBZ2DecompressLowmem, "bzip2-decompress-lowmem", "@"),

  ARGPARSE_s_n (oMimemode, "mimemode", "@"),
  ARGPARSE_s_n (oTextmodeShort, NULL, "@"),
  ARGPARSE_s_n (oTextmode,   "textmode", N_("use canonical text mode")),
  ARGPARSE_s_n (oNoTextmode, "no-textmode", "@"),

  ARGPARSE_s_n (oExpert,      "expert", "@"),
  ARGPARSE_s_n (oNoExpert, "no-expert", "@"),

  ARGPARSE_s_s (oDefSigExpire, "default-sig-expire", "@"),
  ARGPARSE_s_n (oAskSigExpire,      "ask-sig-expire", "@"),
  ARGPARSE_s_n (oNoAskSigExpire, "no-ask-sig-expire", "@"),
  ARGPARSE_s_s (oDefCertExpire, "default-cert-expire", "@"),
  ARGPARSE_s_n (oAskCertExpire,      "ask-cert-expire", "@"),
  ARGPARSE_s_n (oNoAskCertExpire, "no-ask-cert-expire", "@"),
  ARGPARSE_s_i (oDefCertLevel, "default-cert-level", "@"),
  ARGPARSE_s_i (oMinCertLevel, "min-cert-level", "@"),
  ARGPARSE_s_n (oAskCertLevel,      "ask-cert-level", "@"),
  ARGPARSE_s_n (oNoAskCertLevel, "no-ask-cert-level", "@"),

  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_p_u (oMaxOutput, "max-output", "@"),
  ARGPARSE_s_s (oInputSizeHint, "input-size-hint", "@"),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	  "quiet",   "@"),
  ARGPARSE_s_n (oNoTTY,   "no-tty",  "@"),

  ARGPARSE_s_n (oDisableSignerUID, "disable-signer-uid", "@"),

  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),
  ARGPARSE_s_n (oInteractive, "interactive", N_("prompt before overwriting")),

  ARGPARSE_s_n (oBatch, "batch", "@"),
  ARGPARSE_s_n (oAnswerYes, "yes", "@"),
  ARGPARSE_s_n (oAnswerNo, "no", "@"),
  ARGPARSE_s_s (oKeyring, "keyring", "@"),
  ARGPARSE_s_s (oPrimaryKeyring, "primary-keyring", "@"),
  ARGPARSE_s_s (oSecretKeyring, "secret-keyring", "@"),
  ARGPARSE_s_n (oShowKeyring, "show-keyring", "@"),
  ARGPARSE_s_s (oDefaultKey, "default-key", "@"),

  ARGPARSE_s_s (oKeyServer, "keyserver", "@"),
  ARGPARSE_s_s (oKeyServerOptions, "keyserver-options", "@"),
  ARGPARSE_s_s (oKeyOrigin, "key-origin", "@"),
  ARGPARSE_s_s (oImportOptions, "import-options", "@"),
  ARGPARSE_s_s (oImportFilter,  "import-filter", "@"),
  ARGPARSE_s_s (oExportOptions, "export-options", "@"),
  ARGPARSE_s_s (oExportFilter,  "export-filter", "@"),
  ARGPARSE_s_s (oListOptions,   "list-options", "@"),
  ARGPARSE_s_s (oVerifyOptions, "verify-options", "@"),

  ARGPARSE_s_s (oDisplayCharset, "display-charset", "@"),
  ARGPARSE_s_s (oDisplayCharset, "charset", "@"),
  ARGPARSE_conffile (oOptions, "options", "@"),

  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level", "@"),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugIOLBF, "debug-iolbf", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", "@"),
  ARGPARSE_s_s (oStatusFile, "status-file", "@"),
  ARGPARSE_s_i (oAttributeFD, "attribute-fd", "@"),
  ARGPARSE_s_s (oAttributeFile, "attribute-file", "@"),

  ARGPARSE_s_i (oCompletesNeeded, "completes-needed", "@"),
  ARGPARSE_s_i (oMarginalsNeeded, "marginals-needed", "@"),
  ARGPARSE_s_i (oMaxCertDepth,	"max-cert-depth", "@" ),
  ARGPARSE_s_s (oTrustedKey, "trusted-key", "@"),

  ARGPARSE_s_s (oLoadExtension, "load-extension", "@"),  /* Dummy.  */

  ARGPARSE_s_s (oCompliance, "compliance",   "@"),
  ARGPARSE_s_n (oGnuPG, "gnupg",   "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp2", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp6", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp7", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp8", "@"),
  ARGPARSE_s_n (oRFC2440, "rfc2440", "@"),
  ARGPARSE_s_n (oRFC4880, "rfc4880", "@"),
  ARGPARSE_s_n (oRFC4880bis, "rfc4880bis", "@"),
  ARGPARSE_s_n (oOpenPGP, "openpgp", N_("use strict OpenPGP behavior")),
  ARGPARSE_s_n (oPGP6, "pgp6", "@"),
  ARGPARSE_s_n (oPGP7, "pgp7", "@"),
  ARGPARSE_s_n (oPGP8, "pgp8", "@"),

  ARGPARSE_s_n (oRFC2440Text,      "rfc2440-text", "@"),
  ARGPARSE_s_n (oNoRFC2440Text, "no-rfc2440-text", "@"),
  ARGPARSE_s_i (oS2KMode, "s2k-mode", "@"),
  ARGPARSE_s_s (oS2KDigest, "s2k-digest-algo", "@"),
  ARGPARSE_s_s (oS2KCipher, "s2k-cipher-algo", "@"),
  ARGPARSE_s_i (oS2KCount, "s2k-count", "@"),
  ARGPARSE_s_s (oCipherAlgo, "cipher-algo", "@"),
  ARGPARSE_s_s (oDigestAlgo, "digest-algo", "@"),
  ARGPARSE_s_s (oCertDigestAlgo, "cert-digest-algo", "@"),
  ARGPARSE_s_s (oCompressAlgo,"compress-algo", "@"),
  ARGPARSE_s_s (oCompressAlgo, "compression-algo", "@"), /* Alias */
  ARGPARSE_s_n (oThrowKeyids, "throw-keyids", "@"),
  ARGPARSE_s_n (oNoThrowKeyids, "no-throw-keyids", "@"),
  ARGPARSE_s_n (oShowPhotos,   "show-photos", "@"),
  ARGPARSE_s_n (oNoShowPhotos, "no-show-photos", "@"),
  ARGPARSE_s_s (oPhotoViewer,  "photo-viewer", "@"),
  ARGPARSE_s_s (oSetNotation,  "set-notation", "@"),
  ARGPARSE_s_s (oSigNotation,  "sig-notation", "@"),
  ARGPARSE_s_s (oCertNotation, "cert-notation", "@"),
  ARGPARSE_s_s (oKnownNotation, "known-notation", "@"),

  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
		      )),

  ARGPARSE_group (303, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " --clear-sign [file]        make a clear text signature\n"
    " --detach-sign [file]       make a detached signature\n"
    " --list-keys [names]        show keys\n"
    " --fingerprint [names]      show fingerprints\n")),

  /* More hidden commands and options. */
  ARGPARSE_c (aPrintMDs, "print-mds", "@"), /* old */
#ifndef NO_TRUST_MODELS
  ARGPARSE_c (aListTrustDB, "list-trustdb", "@"),
#endif

  /* Not yet used:
     ARGPARSE_c (aListTrustPath, "list-trust-path", "@"), */
  ARGPARSE_c (aDeleteSecretAndPublicKeys,
              "delete-secret-and-public-keys", "@"),
  ARGPARSE_c (aRebuildKeydbCaches, "rebuild-keydb-caches", "@"),

  ARGPARSE_o_s (oPassphrase,      "passphrase", "@"),
  ARGPARSE_s_i (oPassphraseFD,    "passphrase-fd", "@"),
  ARGPARSE_s_s (oPassphraseFile,  "passphrase-file", "@"),
  ARGPARSE_s_i (oPassphraseRepeat,"passphrase-repeat", "@"),
  ARGPARSE_s_s (oPinentryMode,    "pinentry-mode", "@"),
  ARGPARSE_s_s (oRequestOrigin,   "request-origin", "@"),
  ARGPARSE_s_i (oCommandFD, "command-fd", "@"),
  ARGPARSE_s_s (oCommandFile, "command-file", "@"),
  ARGPARSE_s_n (oQuickRandom, "debug-quick-random", "@"),
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),

#ifndef NO_TRUST_MODELS
  ARGPARSE_s_s (oTrustDBName, "trustdb-name", "@"),
  ARGPARSE_s_n (oAutoCheckTrustDB, "auto-check-trustdb", "@"),
  ARGPARSE_s_n (oNoAutoCheckTrustDB, "no-auto-check-trustdb", "@"),
  ARGPARSE_s_s (oForceOwnertrust, "force-ownertrust", "@"),
#endif

  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),
  ARGPARSE_s_n (oRequireSecmem, "require-secmem", "@"),
  ARGPARSE_s_n (oNoRequireSecmem, "no-require-secmem", "@"),
  ARGPARSE_s_n (oNoPermissionWarn, "no-permission-warning", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armor", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armour", "@"),
  ARGPARSE_s_n (oNoDefKeyring, "no-default-keyring", "@"),
  ARGPARSE_s_n (oNoKeyring, "no-keyring", "@"),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_noconffile (oNoOptions, "no-options", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_n (oNoBatch, "no-batch", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oWithTofuInfo,"with-tofu-info", "@"),
  ARGPARSE_s_n (oWithKeyData,"with-key-data", "@"),
  ARGPARSE_s_n (oWithSigList,"with-sig-list", "@"),
  ARGPARSE_s_n (oWithSigCheck,"with-sig-check", "@"),
  ARGPARSE_c (aListKeys, "list-key", "@"),   /* alias */
  ARGPARSE_c (aListSigs, "list-sig", "@"),   /* alias */
  ARGPARSE_c (aCheckKeys, "check-sig", "@"), /* alias */
  ARGPARSE_c (aShowKeys,  "show-key", "@"), /* alias */
  ARGPARSE_s_n (oSkipVerify, "skip-verify", "@"),
  ARGPARSE_s_n (oSkipHiddenRecipients, "skip-hidden-recipients", "@"),
  ARGPARSE_s_n (oNoSkipHiddenRecipients, "no-skip-hidden-recipients", "@"),
  ARGPARSE_s_i (oDefCertLevel, "default-cert-check-level", "@"), /* old */
#ifndef NO_TRUST_MODELS
  ARGPARSE_s_n (oAlwaysTrust, "always-trust", "@"),
#endif
  ARGPARSE_s_s (oTrustModel, "trust-model", "@"),
  ARGPARSE_s_s (oTOFUDefaultPolicy, "tofu-default-policy", "@"),
  ARGPARSE_s_s (oSetFilename, "set-filename", "@"),
  ARGPARSE_s_n (oForYourEyesOnly, "for-your-eyes-only", "@"),
  ARGPARSE_s_n (oNoForYourEyesOnly, "no-for-your-eyes-only", "@"),
  ARGPARSE_s_s (oSetPolicyURL,  "set-policy-url", "@"),
  ARGPARSE_s_s (oSigPolicyURL,  "sig-policy-url", "@"),
  ARGPARSE_s_s (oCertPolicyURL, "cert-policy-url", "@"),
  ARGPARSE_s_n (oShowPolicyURL,      "show-policy-url", "@"),
  ARGPARSE_s_n (oNoShowPolicyURL, "no-show-policy-url", "@"),
  ARGPARSE_s_s (oSigKeyserverURL, "sig-keyserver-url", "@"),
  ARGPARSE_s_n (oShowNotation,      "show-notation", "@"),
  ARGPARSE_s_n (oNoShowNotation, "no-show-notation", "@"),
  ARGPARSE_s_s (oComment, "comment", "@"),
  ARGPARSE_s_n (oDefaultComment, "default-comment", "@"),
  ARGPARSE_s_n (oNoComments, "no-comments", "@"),
  ARGPARSE_s_n (oEmitVersion,      "emit-version", "@"),
  ARGPARSE_s_n (oNoEmitVersion, "no-emit-version", "@"),
  ARGPARSE_s_n (oNoEmitVersion, "no-version", "@"), /* alias */
  ARGPARSE_s_n (oNotDashEscaped, "not-dash-escaped", "@"),
  ARGPARSE_s_n (oEscapeFrom,      "escape-from-lines", "@"),
  ARGPARSE_s_n (oNoEscapeFrom, "no-escape-from-lines", "@"),
  ARGPARSE_s_n (oLockOnce,     "lock-once", "@"),
  ARGPARSE_s_n (oLockMultiple, "lock-multiple", "@"),
  ARGPARSE_s_n (oLockNever,    "lock-never", "@"),
  ARGPARSE_s_i (oLoggerFD,   "logger-fd", "@"),
  ARGPARSE_s_s (oLoggerFile, "log-file", "@"),
  ARGPARSE_s_s (oLoggerFile, "logger-file", "@"),  /* 1.4 compatibility.  */
  ARGPARSE_s_n (oUseEmbeddedFilename,      "use-embedded-filename", "@"),
  ARGPARSE_s_n (oNoUseEmbeddedFilename, "no-use-embedded-filename", "@"),
  ARGPARSE_s_n (oUtf8Strings,      "utf8-strings", "@"),
  ARGPARSE_s_n (oNoUtf8Strings, "no-utf8-strings", "@"),
  ARGPARSE_s_n (oWithFingerprint, "with-fingerprint", "@"),
  ARGPARSE_s_n (oWithSubkeyFingerprint, "with-subkey-fingerprint", "@"),
  ARGPARSE_s_n (oWithSubkeyFingerprint, "with-subkey-fingerprints", "@"),
  ARGPARSE_s_n (oWithICAOSpelling, "with-icao-spelling", "@"),
  ARGPARSE_s_n (oWithKeygrip,     "with-keygrip", "@"),
  ARGPARSE_s_n (oWithSecret,      "with-secret", "@"),
  ARGPARSE_s_n (oWithWKDHash,     "with-wkd-hash", "@"),
  ARGPARSE_s_n (oWithKeyOrigin,   "with-key-origin", "@"),
  ARGPARSE_s_s (oDisableCipherAlgo,  "disable-cipher-algo", "@"),
  ARGPARSE_s_s (oDisablePubkeyAlgo,  "disable-pubkey-algo", "@"),
  ARGPARSE_s_n (oAllowNonSelfsignedUID,      "allow-non-selfsigned-uid", "@"),
  ARGPARSE_s_n (oNoAllowNonSelfsignedUID, "no-allow-non-selfsigned-uid", "@"),
  ARGPARSE_s_n (oAllowFreeformUID,      "allow-freeform-uid", "@"),
  ARGPARSE_s_n (oNoAllowFreeformUID, "no-allow-freeform-uid", "@"),
  ARGPARSE_s_n (oNoLiteral, "no-literal", "@"),
  ARGPARSE_p_u (oSetFilesize, "set-filesize", "@"),
  ARGPARSE_s_n (oFastListMode, "fast-list-mode", "@"),
  ARGPARSE_s_n (oFixedListMode, "fixed-list-mode", "@"),
  ARGPARSE_s_n (oLegacyListMode, "legacy-list-mode", "@"),
  ARGPARSE_s_n (oListOnly, "list-only", "@"),
  ARGPARSE_s_n (oPrintPKARecords, "print-pka-records", "@"),
  ARGPARSE_s_n (oPrintDANERecords, "print-dane-records", "@"),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict", "@"),
  ARGPARSE_s_n (oIgnoreValidFrom,    "ignore-valid-from", "@"),
  ARGPARSE_s_n (oIgnoreCrcError, "ignore-crc-error", "@"),
  ARGPARSE_s_n (oIgnoreMDCError, "ignore-mdc-error", "@"),
  ARGPARSE_s_n (oShowSessionKey, "show-session-key", "@"),
  ARGPARSE_s_s (oOverrideSessionKey, "override-session-key", "@"),
  ARGPARSE_s_i (oOverrideSessionKeyFD, "override-session-key-fd", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),
  ARGPARSE_s_n (oAutoKeyRetrieve, "auto-key-retrieve", "@"),
  ARGPARSE_s_n (oNoAutoKeyRetrieve, "no-auto-key-retrieve", "@"),
  ARGPARSE_s_n (oNoSigCache,         "no-sig-cache", "@"),
  ARGPARSE_s_n (oMergeOnly,	  "merge-only", "@" ),
  ARGPARSE_s_n (oAllowSecretKeyImport, "allow-secret-key-import", "@"),
  ARGPARSE_s_n (oTryAllSecrets,  "try-all-secrets", "@"),
  ARGPARSE_s_n (oEnableSpecialFilenames, "enable-special-filenames", "@"),
  ARGPARSE_s_n (oNoExpensiveTrustChecks, "no-expensive-trust-checks", "@"),
  ARGPARSE_s_n (oPreservePermissions, "preserve-permissions", "@"),
  ARGPARSE_s_s (oDefaultPreferenceList,  "default-preference-list", "@"),
  ARGPARSE_s_s (oDefaultKeyserverURL,  "default-keyserver-url", "@"),
  ARGPARSE_s_s (oPersonalCipherPreferences, "personal-cipher-preferences","@"),
  ARGPARSE_s_s (oPersonalDigestPreferences, "personal-digest-preferences","@"),
  ARGPARSE_s_s (oPersonalCompressPreferences,
                                         "personal-compress-preferences", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_s (oWeakDigest, "weak-digest","@"),
  ARGPARSE_s_n (oUnwrap, "unwrap", "@"),
  ARGPARSE_s_n (oOnlySignTextIDs, "only-sign-text-ids", "@"),

  /* Aliases.  I constantly mistype these, and assume other people do
     as well. */
  ARGPARSE_s_s (oPersonalCipherPreferences, "personal-cipher-prefs", "@"),
  ARGPARSE_s_s (oPersonalDigestPreferences, "personal-digest-prefs", "@"),
  ARGPARSE_s_s (oPersonalCompressPreferences, "personal-compress-prefs", "@"),

  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDirmngrProgram, "dirmngr-program", "@"),
  ARGPARSE_s_n (oDisableDirmngr, "disable-dirmngr", "@"),
  ARGPARSE_s_s (oDisplay,    "display",    "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname",    "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype",    "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",   "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages","@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oGroup,      "group",      "@"),
  ARGPARSE_s_s (oUnGroup,    "ungroup",    "@"),
  ARGPARSE_s_n (oNoGroups,   "no-groups",  "@"),
  ARGPARSE_s_n (oStrict,     "strict",     "@"),
  ARGPARSE_s_n (oNoStrict,   "no-strict",  "@"),
  ARGPARSE_s_n (oMangleDosFilenames,      "mangle-dos-filenames", "@"),
  ARGPARSE_s_n (oNoMangleDosFilenames, "no-mangle-dos-filenames", "@"),
  ARGPARSE_s_n (oEnableProgressFilter, "enable-progress-filter", "@"),
  ARGPARSE_s_n (oMultifile, "multifile", "@"),
  ARGPARSE_s_s (oKeyidFormat, "keyid-format", "@"),
  ARGPARSE_s_n (oExitOnStatusWriteError, "exit-on-status-write-error", "@"),
  ARGPARSE_s_i (oLimitCardInsertTries, "limit-card-insert-tries", "@"),

  ARGPARSE_s_n (oAllowMultisigVerification,
                "allow-multisig-verification", "@"),
  ARGPARSE_s_n (oEnableLargeRSA, "enable-large-rsa", "@"),
  ARGPARSE_s_n (oDisableLargeRSA, "disable-large-rsa", "@"),
  ARGPARSE_s_n (oEnableDSA2, "enable-dsa2", "@"),
  ARGPARSE_s_n (oDisableDSA2, "disable-dsa2", "@"),
  ARGPARSE_s_n (oAllowMultipleMessages,      "allow-multiple-messages", "@"),
  ARGPARSE_s_n (oNoAllowMultipleMessages, "no-allow-multiple-messages", "@"),
  ARGPARSE_s_n (oAllowWeakDigestAlgos, "allow-weak-digest-algos", "@"),

  ARGPARSE_s_s (oDefaultNewKeyAlgo, "default-new-key-algo", "@"),

  /* These two are aliases to help users of the PGP command line
     product use gpg with minimal pain.  Many commands are common
     already as they seem to have borrowed commands from us.  Now I'm
     returning the favor. */
  ARGPARSE_s_s (oLocalUser, "sign-with", "@"),
  ARGPARSE_s_s (oRecipient, "user", "@"),

  ARGPARSE_s_n (oRequireCrossCert, "require-backsigs", "@"),
  ARGPARSE_s_n (oRequireCrossCert, "require-cross-certification", "@"),
  ARGPARSE_s_n (oNoRequireCrossCert, "no-require-backsigs", "@"),
  ARGPARSE_s_n (oNoRequireCrossCert, "no-require-cross-certification", "@"),

  /* New options.  Fixme: Should go more to the top.  */
  ARGPARSE_s_s (oAutoKeyLocate, "auto-key-locate", "@"),
  ARGPARSE_s_n (oNoAutoKeyLocate, "no-auto-key-locate", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),
  ARGPARSE_s_n (oNoSymkeyCache, "no-symkey-cache", "@"),
  ARGPARSE_s_n (oIncludeKeyBlock, "include-key-block", "@"),
  ARGPARSE_s_n (oNoIncludeKeyBlock, "no-include-key-block", "@"),
  ARGPARSE_s_n (oAutoKeyImport,   "auto-key-import", "@"),
  ARGPARSE_s_n (oNoAutoKeyImport, "no-auto-key-import", "@"),

  /* Options to override new security defaults.  */
  ARGPARSE_s_n (oAllowWeakKeySignatures, "allow-weak-key-signatures", "@"),

  /* Options which can be used in special circumstances. They are not
   * published and we hope they are never required.  */
  ARGPARSE_s_n (oUseOnlyOpenPGPCard, "use-only-openpgp-card", "@"),

  /* Dummy options with warnings.  */
  ARGPARSE_s_n (oUseAgent,      "use-agent", "@"),
  ARGPARSE_s_n (oNoUseAgent, "no-use-agent", "@"),
  ARGPARSE_s_s (oGpgAgentInfo, "gpg-agent-info", "@"),
  ARGPARSE_s_s (oReaderPort, "reader-port", "@"),
  ARGPARSE_s_s (octapiDriver, "ctapi-driver", "@"),
  ARGPARSE_s_s (opcscDriver, "pcsc-driver", "@"),
  ARGPARSE_s_n (oDisableCCID, "disable-ccid", "@"),
  ARGPARSE_s_n (oHonorHttpProxy, "honor-http-proxy", "@"),
  ARGPARSE_s_s (oTOFUDBFormat, "tofu-db-format", "@"),

  /* Dummy options.  */
  ARGPARSE_s_n (oNoop, "sk-comments", "@"),
  ARGPARSE_s_n (oNoop, "no-sk-comments", "@"),
  ARGPARSE_s_n (oNoop, "compress-keys", "@"),
  ARGPARSE_s_n (oNoop, "compress-sigs", "@"),
  ARGPARSE_s_n (oNoop, "force-v3-sigs", "@"),
  ARGPARSE_s_n (oNoop, "no-force-v3-sigs", "@"),
  ARGPARSE_s_n (oNoop, "force-v4-certs", "@"),
  ARGPARSE_s_n (oNoop, "no-force-v4-certs", "@"),
  ARGPARSE_s_n (oNoop, "no-mdc-warning", "@"),
  ARGPARSE_s_n (oNoop, "force-mdc", "@"),
  ARGPARSE_s_n (oNoop, "no-force-mdc", "@"),
  ARGPARSE_s_n (oNoop, "disable-mdc", "@"),
  ARGPARSE_s_n (oNoop, "no-disable-mdc", "@"),


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


#ifdef ENABLE_SELINUX_HACKS
#define ALWAYS_ADD_KEYRINGS 1
#else
#define ALWAYS_ADD_KEYRINGS 0
#endif

/* The list of the default AKL methods.  */
#define DEFAULT_AKL_LIST "local,wkd"


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
static void emergency_cleanup (void);
static void read_sessionkey_from_fd (int fd);


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


static int
build_list_pk_test_algo (int algo)
{
  /* Show only one "RSA" string.  If RSA_E or RSA_S is available RSA
     is also available.  */
  if (algo == PUBKEY_ALGO_RSA_E
      || algo == PUBKEY_ALGO_RSA_S)
    return GPG_ERR_DIGEST_ALGO;

  return openpgp_pk_test_algo (algo);
}

static const char *
build_list_pk_algo_name (int algo)
{
  return openpgp_pk_algo_name (algo);
}

static int
build_list_cipher_test_algo (int algo)
{
  return openpgp_cipher_test_algo (algo);
}

static const char *
build_list_cipher_algo_name (int algo)
{
  return openpgp_cipher_algo_name (algo);
}

static int
build_list_md_test_algo (int algo)
{
  /* By default we do not accept MD5 based signatures.  To avoid
     confusion we do not announce support for it either.  */
  if (algo == DIGEST_ALGO_MD5)
    return GPG_ERR_DIGEST_ALGO;

  return openpgp_md_test_algo (algo);
}

static const char *
build_list_md_algo_name (int algo)
{
  return openpgp_md_algo_name (algo);
}


static const char *
my_strusage( int level )
{
  static char *digests, *pubkeys, *ciphers, *zips, *ver_gcry;
  const char *p;

  switch (level)
    {
      case  9: p = "GPL-3.0-or-later"; break;
      case 11: p = "@GPG@ (@GNUPG@)";
	break;
      case 13: p = VERSION; break;
      case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;

#ifdef IS_DEVELOPMENT_VERSION
      case 25:
	p="NOTE: THIS IS A DEVELOPMENT VERSION!";
	break;
      case 26:
	p="It is only intended for test purposes and should NOT be";
	break;
      case 27:
	p="used in a production environment or with production keys!";
	break;
#endif

      case 1:
      case 40:	p =
	    _("Usage: @GPG@ [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: @GPG@ [options] [files]\n"
	      "Sign, check, encrypt or decrypt\n"
	      "Default operation depends on the input data\n");
	break;

      case 31: p = "\nHome: "; break;
#ifndef __riscos__
      case 32: p = gnupg_homedir (); break;
#else /* __riscos__ */
      case 32: p = make_filename(gnupg_homedir (), NULL); break;
#endif /* __riscos__ */
      case 33: p = _("\nSupported algorithms:\n"); break;
      case 34:
	if (!pubkeys)
            pubkeys = build_list (_("Pubkey: "), 1,
                                  build_list_pk_algo_name,
                                  build_list_pk_test_algo );
	p = pubkeys;
	break;
      case 35:
	if( !ciphers )
	    ciphers = build_list(_("Cipher: "), 'S',
                                 build_list_cipher_algo_name,
                                 build_list_cipher_test_algo );
	p = ciphers;
	break;
      case 36:
	if( !digests )
	    digests = build_list(_("Hash: "), 'H',
                                 build_list_md_algo_name,
                                 build_list_md_test_algo );
	p = digests;
	break;
      case 37:
	if( !zips )
	    zips = build_list(_("Compression: "),'Z',
                              compress_algo_to_string,
                              check_compress_algo);
	p = zips;
	break;

      default:	p = NULL;
    }
    return p;
}


static char *
build_list (const char *text, char letter,
	    const char * (*mapf)(int), int (*chkf)(int))
{
  membuf_t mb;
  int indent;
  int i, j, len;
  const char *s;
  char *string;

  if (maybe_setuid)
    gcry_control (GCRYCTL_INIT_SECMEM, 0, 0);  /* Drop setuid. */

  indent = utf8_charcount (text, -1);
  len = 0;
  init_membuf (&mb, 512);

  for (i=0; i <= 110; i++ )
    {
      if (!chkf (i) && (s = mapf (i)))
        {
          if (mb.len - len > 60)
            {
              put_membuf_str (&mb, ",\n");
              len = mb.len;
              for (j=0; j < indent; j++)
                put_membuf_str (&mb, " ");
	    }
          else if (mb.len)
            put_membuf_str (&mb, ", ");
          else
            put_membuf_str (&mb, text);

          put_membuf_str (&mb, s);
          if (opt.verbose && letter)
            {
              char num[20];
              if (letter == 1)
                snprintf (num, sizeof num, " (%d)", i);
              else
                snprintf (num, sizeof num, " (%c%d)", letter, i);
              put_membuf_str (&mb, num);
            }
	}
    }
  if (mb.len)
    put_membuf_str (&mb, "\n");
  put_membuf (&mb, "", 1);

  string = get_membuf (&mb, NULL);
  return xrealloc (string, strlen (string)+1);
}


static void
wrong_args( const char *text)
{
  es_fprintf (es_stderr, _("usage: %s [options] %s\n"), GPG_NAME, text);
  log_inc_errorcount ();
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
set_opt_session_env (const char *name, const char *value)
{
  gpg_error_t err;

  err = session_env_setenv (opt.session_env, name, value);
  if (err)
    log_fatal ("error setting session environment: %s\n",
               gpg_strerror (err));
}


/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. */
static void
set_debug (const char *level)
{
  int numok = (level && digitp (level));
  int numlvl = numok? atoi (level) : 0;

  if (!level)
    ;
  else if (!strcmp (level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp (level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_MEMSTAT_VALUE;
  else if (!strcmp (level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_MEMSTAT_VALUE|DBG_TRUST_VALUE|DBG_EXTPROG_VALUE;
  else if (!strcmp (level, "expert")  || (numok && numlvl <= 8))
    opt.debug = (DBG_MEMSTAT_VALUE|DBG_TRUST_VALUE|DBG_EXTPROG_VALUE
                 |DBG_CACHE_VALUE|DBG_LOOKUP|DBG_FILTER_VALUE|DBG_PACKET_VALUE);
  else if (!strcmp (level, "guru") || numok)
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
      log_error (_("invalid debug-level '%s' given\n"), level);
      g10_exit (2);
    }

  if ((opt.debug & DBG_MEMORY_VALUE))
    memory_debug_mode = 1;
  if ((opt.debug & DBG_MEMSTAT_VALUE))
    memory_stat_debug_mode = 1;
  if (DBG_MPI)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (DBG_CRYPTO)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  if ((opt.debug & DBG_IOBUF_VALUE))
    iobuf_debug_mode = 1;
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}


/* We set the screen dimensions for UI purposes.  Do not allow screens
   smaller than 80x24 for the sake of simplicity. */
static void
set_screen_dimensions(void)
{
#ifndef HAVE_W32_SYSTEM
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
   error.  On success the file descriptor is returned.  */
static int
open_info_file (const char *fname, int for_write, int binary)
{
#ifdef __riscos__
  return riscos_fdopenfile (fname, for_write);
#elif defined (ENABLE_SELINUX_HACKS)
  /* We can't allow these even when testing for a secured filename
     because files to be secured might not yet been secured.  This is
     similar to the option file but in that case it is unlikely that
     sensitive information may be retrieved by means of error
     messages.  */
  (void)fname;
  (void)for_write;
  (void)binary;
  return -1;
#else
  int fd;

  if (binary)
    binary = MY_O_BINARY;

/*   if (is_secured_filename (fname)) */
/*     { */
/*       fd = -1; */
/*       gpg_err_set_errno (EPERM); */
/*     } */
/*   else */
/*     { */
      do
        {
          if (for_write)
            fd = gnupg_open (fname, O_CREAT | O_TRUNC | O_WRONLY | binary,
                             S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
          else
            fd = gnupg_open (fname, O_RDONLY | binary, 0);
        }
      while (fd == -1 && errno == EINTR);
/*     } */
  if ( fd == -1)
    log_error ( for_write? _("can't create '%s': %s\n")
                         : _("can't open '%s': %s\n"), fname, strerror(errno));

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
      log_error(_("no = sign found in group definition '%s'\n"),name);
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
check_permissions (const char *path, int item)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  static int homedir_cache=-1;
  char *tmppath,*dir;
  struct stat statbuf,dirbuf;
  int homedir=0,ret=0,checkonly=0;
  int perm=0,own=0,enc_dir_perm=0,enc_dir_own=0;

  if(opt.no_perm_warn)
    return 0;

  log_assert(item==0 || item==1 || item==2);

  /* extensions may attach a path */
  if(item==2 && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(gnupg_libdir (),path,NULL);
    }
  else
    tmppath=xstrdup(path);

  /* If the item is located in the homedir, but isn't the homedir,
     don't continue if we already checked the homedir itself.  This is
     to avoid user confusion with an extra options file warning which
     could be rectified if the homedir itself had proper
     permissions. */
  if(item!=0 && homedir_cache>-1
     && !ascii_strncasecmp (gnupg_homedir (), tmppath,
                            strlen (gnupg_homedir ())))
    {
      ret=homedir_cache;
      goto end;
    }

  /* It's okay if the file or directory doesn't exist */
  if (gnupg_stat (tmppath,&statbuf))
    {
      ret=0;
      goto end;
    }

  /* Now check the enclosing directory.  Theoretically, we could walk
     this test up to the root directory /, but for the sake of sanity,
     I'm stopping at one level down. */
  dir=make_dirname(tmppath);

  if (gnupg_stat (dir,&dirbuf) || !S_ISDIR (dirbuf.st_mode))
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
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe ownership on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe ownership on"
		       " extension '%s'\n"),tmppath);
	}
      if(perm)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe permissions on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe permissions on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe permissions on"
		       " extension '%s'\n"),tmppath);
	}
      if(enc_dir_own)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " extension '%s'\n"),tmppath);
	}
      if(enc_dir_perm)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " extension '%s'\n"),tmppath);
	}
    }

 end:
  xfree(tmppath);

  if(homedir)
    homedir_cache=ret;

  return ret;

#else /*!(HAVE_STAT && !HAVE_DOSISH_SYSTEM)*/
  (void)path;
  (void)item;
  return 0;
#endif /*!(HAVE_STAT && !HAVE_DOSISH_SYSTEM)*/
}


/* Print the OpenPGP defined algo numbers.  */
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
	    es_printf (";");
	  es_printf ("%d",i);
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
	    es_printf (";");
	  es_printf ("%s",mapper(i));
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
  int show_all = !items;
  char *name = NULL;
  const char *s;
  struct groupitem *giter;
  int first, iter;

  if(!opt.with_colons)
    return;

  while(show_all || (name=strsep(&items," ")))
    {
      int any=0;

      if(show_all || ascii_strcasecmp(name,"group")==0)
	{
	  for (giter = opt.grouplist; giter; giter = giter->next)
	    {
	      strlist_t sl;

	      es_fprintf (es_stdout, "cfg:group:");
	      es_write_sanitized (es_stdout, giter->name, strlen(giter->name),
                                  ":", NULL);
	      es_putc (':', es_stdout);

	      for(sl=giter->values; sl; sl=sl->next)
		{
		  es_write_sanitized (es_stdout, sl->d, strlen (sl->d),
                                      ":;", NULL);
		  if(sl->next)
                    es_printf(";");
		}

              es_printf("\n");
	    }

	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"version")==0)
	{
	  es_printf("cfg:version:");
	  es_write_sanitized (es_stdout, VERSION, strlen(VERSION), ":", NULL);
          es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"pubkey")==0)
	{
	  es_printf ("cfg:pubkey:");
	  print_algo_numbers (build_list_pk_test_algo);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"pubkeyname")==0)
	{
	  es_printf ("cfg:pubkeyname:");
	  print_algo_names (build_list_pk_test_algo,
                            build_list_pk_algo_name);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"cipher")==0)
	{
	  es_printf ("cfg:cipher:");
	  print_algo_numbers (build_list_cipher_test_algo);
	  es_printf ("\n");
	  any=1;
	}

      if (show_all || !ascii_strcasecmp (name,"ciphername"))
	{
	  es_printf ("cfg:ciphername:");
	  print_algo_names (build_list_cipher_test_algo,
                            build_list_cipher_algo_name);
	  es_printf ("\n");
	  any = 1;
	}

      if(show_all
	 || ascii_strcasecmp(name,"digest")==0
	 || ascii_strcasecmp(name,"hash")==0)
	{
	  es_printf ("cfg:digest:");
	  print_algo_numbers (build_list_md_test_algo);
	  es_printf ("\n");
	  any=1;
	}

      if (show_all
          || !ascii_strcasecmp(name,"digestname")
          || !ascii_strcasecmp(name,"hashname"))
	{
	  es_printf ("cfg:digestname:");
	  print_algo_names (build_list_md_test_algo,
                            build_list_md_algo_name);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"compress")==0)
	{
	  es_printf ("cfg:compress:");
	  print_algo_numbers(check_compress_algo);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp (name, "compressname") == 0)
	{
	  es_printf ("cfg:compressname:");
	  print_algo_names (check_compress_algo,
			    compress_algo_to_string);
	  es_printf ("\n");
	  any=1;
	}

      if (show_all || !ascii_strcasecmp(name,"ccid-reader-id"))
	{
          /* We ignore this for GnuPG 1.4 backward compatibility.  */
	  any=1;
	}

      if (show_all || !ascii_strcasecmp (name,"curve"))
	{
	  es_printf ("cfg:curve:");
          for (iter=0, first=1; (s = openpgp_enum_curves (&iter)); first=0)
            es_printf ("%s%s", first?"":";", s);
	  es_printf ("\n");
	  any=1;
	}

      /* Curve OIDs are rarely useful and thus only printed if requested.  */
      if (name && !ascii_strcasecmp (name,"curveoid"))
	{
	  es_printf ("cfg:curveoid:");
          for (iter=0, first=1; (s = openpgp_enum_curves (&iter)); first = 0)
            {
              s = openpgp_curve_to_oid (s, NULL);
              es_printf ("%s%s", first?"":";", s? s:"[?]");
            }
	  es_printf ("\n");
	  any=1;
	}

      if(show_all)
	break;

      if(!any)
	log_error(_("unknown configuration item '%s'\n"),name);
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
  char *configfile_esc = percent_escape (configfile, NULL);

  es_printf ("%s-%s.conf:%lu:\"%s\n",
             GPGCONF_NAME, GPG_NAME,
             GC_OPT_FLAG_DEFAULT,
             configfile_esc ? configfile_esc : "/dev/null");
  es_printf ("verbose:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("quiet:%lu:\n",   GC_OPT_FLAG_NONE);
  es_printf ("keyserver:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("reader-port:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("default-key:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("encrypt-to:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("try-secret-key:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("auto-key-locate:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("auto-key-import:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("include-key-block:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("auto-key-retrieve:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("log-file:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
  es_printf ("group:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("compliance:%lu:\"%s:\n", GC_OPT_FLAG_DEFAULT, "gnupg");
  es_printf ("default-new-key-algo:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("trust-model:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("disable-dirmngr:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("max-cert-depth:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("completes-needed:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("marginals-needed:%lu:\n", GC_OPT_FLAG_NONE);

  /* The next one is an info only item and should match the macros at
     the top of keygen.c  */
  es_printf ("default_pubkey_algo:%lu:\"%s:\n", GC_OPT_FLAG_DEFAULT,
             get_default_pubkey_algo ());

  xfree (configfile_esc);
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
      {"show-usage",LIST_SHOW_USAGE,NULL,
       N_("show key usage information during key listings")},
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
      {"show-only-fpr-mbox",LIST_SHOW_ONLY_FPR_MBOX, NULL,
       NULL},
      {NULL,0,NULL,NULL}
    };

  /* C99 allows for non-constant initializers, but we'd like to
     compile everywhere, so fill in the show-sig-subpackets argument
     here.  Note that if the parse_options array changes, we'll have
     to change the subscript here. */
  lopts[13].value=&subpackets;

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


#ifndef NO_TRUST_MODELS
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
#ifdef USE_TOFU
  else if(ascii_strcasecmp(model,"tofu")==0)
    opt.trust_model=TM_TOFU;
  else if(ascii_strcasecmp(model,"tofu+pgp")==0)
    opt.trust_model=TM_TOFU_PGP;
#endif /*USE_TOFU*/
  else if(ascii_strcasecmp(model,"auto")==0)
    opt.trust_model=TM_AUTO;
  else
    log_error("unknown trust model '%s'\n",model);
}
#endif /*NO_TRUST_MODELS*/


static int
parse_tofu_policy (const char *policystr)
{
#ifdef USE_TOFU
  struct { const char *keyword; int policy; } list[] = {
    { "auto",    TOFU_POLICY_AUTO },
    { "good",    TOFU_POLICY_GOOD },
    { "unknown", TOFU_POLICY_UNKNOWN },
    { "bad",     TOFU_POLICY_BAD },
    { "ask",     TOFU_POLICY_ASK }
  };
  int i;

  if (!ascii_strcasecmp (policystr, "help"))
    {
      log_info (_("valid values for option '%s':\n"), "--tofu-policy");
      for (i=0; i < DIM (list); i++)
        log_info ("  %s\n", list[i].keyword);
      g10_exit (1);
    }

  for (i=0; i < DIM (list); i++)
    if (!ascii_strcasecmp (policystr, list[i].keyword))
      return list[i].policy;
#endif /*USE_TOFU*/

  log_error (_("unknown TOFU policy '%s'\n"), policystr);
  if (!opt.quiet)
    log_info (_("(use \"help\" to list choices)\n"));
  g10_exit (1);
}


static struct gnupg_compliance_option compliance_options[] =
  {
    { "gnupg",      oGnuPG },
    { "openpgp",    oOpenPGP },
    { "rfc4880bis", oRFC4880bis },
    { "rfc4880",    oRFC4880 },
    { "rfc2440",    oRFC2440 },
    { "pgp6",       oPGP6 },
    { "pgp7",       oPGP7 },
    { "pgp8",       oPGP8 },
    { "de-vs",      oDE_VS }
  };


/* Helper to set compliance related options.  This is a separate
 * function so that it can also be used by the --compliance option
 * parser.  */
static void
set_compliance_option (enum cmd_and_opt_values option)
{
  switch (option)
    {
    case oRFC4880bis:
      opt.flags.rfc4880bis = 1;
      /* fall through.  */
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
      opt.escape_from = 1;
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
      opt.escape_from = 0;
      opt.not_dash_escaped = 0;
      opt.def_cipher_algo = 0;
      opt.def_digest_algo = 0;
      opt.cert_digest_algo = 0;
      opt.compress_algo = -1;
      opt.s2k_mode = 3; /* iterated+salted */
      opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
      opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
      break;
    case oPGP6:  opt.compliance = CO_PGP6;  break;
    case oPGP7:  opt.compliance = CO_PGP7;  break;
    case oPGP8:  opt.compliance = CO_PGP8;  break;
    case oGnuPG: opt.compliance = CO_GNUPG; break;

    case oDE_VS:
      set_compliance_option (oOpenPGP);
      opt.compliance = CO_DE_VS;
      /* We divert here from the backward compatible rfc4880 algos.  */
      opt.s2k_digest_algo = DIGEST_ALGO_SHA256;
      opt.s2k_cipher_algo = CIPHER_ALGO_AES256;
      break;

    default:
      BUG ();
    }
}






/* This function called to initialized a new control object.  It is
   assumed that this object has been zeroed out before calling this
   function. */
static void
gpg_init_default_ctrl (ctrl_t ctrl)
{
  ctrl->magic = SERVER_CONTROL_MAGIC;
}


/* This function is called to deinitialize a control object.  It is
   not deallocated. */
static void
gpg_deinit_default_ctrl (ctrl_t ctrl)
{
#ifdef USE_TOFU
  tofu_closedbs (ctrl);
#endif
  gpg_dirmngr_deinit_session_data (ctrl);

  keydb_release (ctrl->cached_getkey_kdb);
}


int
main (int argc, char **argv)
{
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc=0;
    int orig_argc;
    char **orig_argv;
    const char *fname;
    char *username;
    int may_coredump;
    strlist_t sl;
    strlist_t remusr = NULL;
    strlist_t locusr = NULL;
    strlist_t nrings = NULL;
    armor_filter_context_t *afx = NULL;
    int detached_sig = 0;
    char *last_configname = NULL;
    const char *configname = NULL; /* NULL or points to last_configname.
                                    * NULL also indicates that we are
                                    * processing options from the cmdline.  */
    int debug_argparser = 0;
    int default_keyring = 1;
    int greeting = 0;
    int nogreeting = 0;
    char *logfile = NULL;
    int use_random_seed = 1;
    enum cmd_and_opt_values cmd = 0;
    const char *debug_level = NULL;
#ifndef NO_TRUST_MODELS
    const char *trustdb_name = NULL;
#endif /*!NO_TRUST_MODELS*/
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
    int ovrseskeyfd = -1;
    int fpr_maybe_cmd = 0; /* --fingerprint maybe a command.  */
    int any_explicit_recipient = 0;
    int default_akl = 1;
    int require_secmem = 0;
    int got_secmem = 0;
    struct assuan_malloc_hooks malloc_hooks;
    ctrl_t ctrl;

    static int print_dane_records;
    static int print_pka_records;


#ifdef __riscos__
    opt.lock_once = 1;
#endif /* __riscos__ */

    /* Please note that we may running SUID(ROOT), so be very CAREFUL
       when adding any stuff between here and the call to
       secmem_init() somewhere after the option parsing. */
    early_system_init ();
    gnupg_reopen_std (GPG_NAME);
    trap_unaligned ();
    gnupg_rl_initialize ();
    set_strusage (my_strusage);
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    log_set_prefix (GPG_NAME, GPGRT_LOG_WITH_PREFIX);

    /* Make sure that our subsystems are ready.  */
    i18n_init();
    init_common_subsystems (&argc, &argv);

    /* Use our own logging handler for Libcgrypt.  */
    setup_libgcrypt_logging ();

    /* Put random number into secure memory */
    gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

    may_coredump = disable_core_dumps();

    gnupg_init_signals (0, emergency_cleanup);

    dotlock_create (NULL, 0); /* Register lock file cleanup. */

    /* Tell the compliance module who we are.  */
    gnupg_initialize_compliance (GNUPG_MODULE_NAME_GPG);

    opt.autostart = 1;
    opt.session_env = session_env_new ();
    if (!opt.session_env)
      log_fatal ("error allocating session environment block: %s\n",
                 strerror (errno));

    opt.command_fd = -1; /* no command fd */
    opt.compress_level = -1; /* defaults to standard compress level */
    opt.bz2_compress_level = -1; /* defaults to standard compress level */
    /* note: if you change these lines, look at oOpenPGP */
    opt.def_cipher_algo = 0;
    opt.def_digest_algo = 0;
    opt.cert_digest_algo = 0;
    opt.compress_algo = -1; /* defaults to DEFAULT_COMPRESS_ALGO */
    opt.s2k_mode = 3; /* iterated+salted */
    opt.s2k_count = 0; /* Auto-calibrate when needed.  */
    opt.s2k_cipher_algo = DEFAULT_CIPHER_ALGO;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.max_cert_depth = 5;
    opt.escape_from = 1;
    opt.flags.require_cross_cert = 1;
    opt.import_options = IMPORT_REPAIR_KEYS;
    opt.export_options = EXPORT_ATTRIBUTES;
    opt.keyserver_options.import_options = (IMPORT_REPAIR_KEYS
					    | IMPORT_REPAIR_PKS_SUBKEY_BUG
                                            | IMPORT_SELF_SIGS_ONLY
                                            | IMPORT_CLEAN);
    opt.keyserver_options.export_options = EXPORT_ATTRIBUTES;
    opt.keyserver_options.options = KEYSERVER_HONOR_PKA_RECORD;
    opt.verify_options = (LIST_SHOW_UID_VALIDITY
                          | VERIFY_SHOW_POLICY_URLS
                          | VERIFY_SHOW_STD_NOTATIONS
                          | VERIFY_SHOW_KEYSERVER_URLS);
    opt.list_options   = (LIST_SHOW_UID_VALIDITY
                          | LIST_SHOW_USAGE);
#ifdef NO_TRUST_MODELS
    opt.trust_model = TM_ALWAYS;
#else
    opt.trust_model = TM_AUTO;
#endif
    opt.tofu_default_policy = TOFU_POLICY_AUTO;
    opt.mangle_dos_filenames = 0;
    opt.min_cert_level = 2;
    set_screen_dimensions ();
    opt.keyid_format = KF_NONE;
    opt.def_sig_expire = "0";
    opt.def_cert_expire = "0";
    gnupg_set_homedir (NULL);
    opt.passphrase_repeat = 1;
    opt.emit_version = 0;
    opt.weak_digests = NULL;

    /* Check special options given on the command line.  */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
    while (gnupg_argparse (NULL, &pargs, opts))
      {
	switch (pargs.r_opt)
          {
          case oDebug:
          case oDebugAll:
            debug_argparser++;
            break;

          case oDebugIOLBF:
            es_setvbuf (es_stdout, NULL, _IOLBF, 0);
            break;

          case oNoOptions:
            /* Set here here because the homedir would otherwise be
             * created before main option parsing starts.  */
            opt.no_homedir_creation = 1;
            break;

          case oHomedir:
            gnupg_set_homedir (pargs.r.ret_str);
            break;

          case oNoPermissionWarn:
            opt.no_perm_warn = 1;
            break;
          }
      }
    /* Reset the flags.  */
    pargs.flags &= ~(ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);

#ifdef HAVE_DOSISH_SYSTEM
    if ( strchr (gnupg_homedir (), '\\') ) {
      char *d, *buf = xmalloc (strlen (gnupg_homedir ())+1);
      const char *s;
      for (d=buf, s = gnupg_homedir (); *s; s++)
          {
            *d++ = *s == '\\'? '/': *s;
#ifdef HAVE_W32_SYSTEM
            if (s[1] && IsDBCSLeadByte (*s))
              *d++ = *++s;
#endif
          }
        *d = 0;
        gnupg_set_homedir (buf);
    }
#endif

    /* Initialize the secure memory. */
    if (!gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_BUFFER_SIZE, 0))
      got_secmem = 1;
#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
    /* There should be no way to get to this spot while still carrying
       setuid privs.  Just in case, bomb out if we are. */
    if ( getuid () != geteuid () )
      BUG ();
#endif
    maybe_setuid = 0;

    /* Okay, we are now working under our real uid */

    /* malloc hooks go here ... */
    malloc_hooks.malloc = gcry_malloc;
    malloc_hooks.realloc = gcry_realloc;
    malloc_hooks.free = gcry_free;
    assuan_set_malloc_hooks (&malloc_hooks);
    assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
    setup_libassuan_logging (&opt.debug, NULL);

    /* Set default options which require that malloc stuff is ready.  */
    additional_weak_digest ("MD5");
    parse_auto_key_locate (DEFAULT_AKL_LIST);

    argc = orig_argc;
    argv = orig_argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    /* We are re-using the struct, thus the reset flag.  We OR the
     * flags so that the internal intialized flag won't be cleared. */
    pargs.flags |= (ARGPARSE_FLAG_RESET
                    | ARGPARSE_FLAG_KEEP
                    | ARGPARSE_FLAG_SYS
                    | ARGPARSE_FLAG_USER
                    | ARGPARSE_FLAG_USERVERS);

    /* By this point we have a homedir, and cannot change it. */
    check_permissions (gnupg_homedir (), 0);

    /* The configuraton directories for use by gpgrt_argparser.  */
    gnupg_set_confdir (GNUPG_CONFDIR_SYS, gnupg_sysconfdir ());
    gnupg_set_confdir (GNUPG_CONFDIR_USER, gnupg_homedir ());

    while (gnupg_argparser (&pargs, opts, GPG_NAME EXTSEP_S "conf"))
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
                if (is_secured_filename (configname))
                  {
                    pargs.r_opt = ARGPARSE_PERMISSION_ERROR;
                    pargs.err = ARGPARSE_PRINT_ERROR;
                  }
                else if (strncmp (configname, gnupg_sysconfdir (),
                                  strlen (gnupg_sysconfdir ())))
                  {
                    /* This is not the global config file and thus we
                     * need to check the permissions: If the file is
                     * unsafe, then disable any external programs for
                     * keyserver calls or photo IDs.  Since the
                     * external program to call is set in the options
                     * file, a unsafe options file can lead to an
                     * arbitrary program being run. */
                    if (check_permissions (configname, 1))
                      opt.exec_disable=1;
                  }
              }
            else
              configname = NULL;
            break;

            /* case oOptions:
             * case oNoOptions:
             * We will never see these options here because
             * gpgrt_argparse handles them for us.
             */

	  case aListConfig:
	  case aListGcryptConfig:
          case aGPGConfList:
          case aGPGConfTest:
            set_cmd (&cmd, pargs.r_opt);
            /* Do not register a keyring for these commands.  */
            default_keyring = -1;
            break;

	  case aCheckKeys:
	  case aListPackets:
	  case aImport:
	  case aFastImport:
	  case aSendKeys:
	  case aRecvKeys:
	  case aSearchKeys:
	  case aRefreshKeys:
	  case aFetchKeys:
	  case aExport:
#ifdef ENABLE_CARD_SUPPORT
          case aCardStatus:
          case aCardEdit:
          case aChangePIN:
#endif /* ENABLE_CARD_SUPPORT*/
	  case aListKeys:
	  case aLocateKeys:
	  case aLocateExtKeys:
	  case aListSigs:
	  case aExportSecret:
	  case aExportSecretSub:
	  case aExportSshKey:
	  case aSym:
	  case aClearsign:
	  case aGenRevoke:
	  case aDesigRevoke:
	  case aPrimegen:
	  case aGenRandom:
	  case aPrintMD:
	  case aPrintMDs:
	  case aListTrustDB:
	  case aCheckTrustDB:
	  case aUpdateTrustDB:
	  case aFixTrustDB:
	  case aListTrustPath:
	  case aDeArmor:
	  case aEnArmor:
	  case aSign:
	  case aQuickSignKey:
	  case aQuickLSignKey:
	  case aQuickRevSig:
	  case aSignKey:
	  case aLSignKey:
	  case aStore:
	  case aQuickKeygen:
	  case aQuickAddUid:
	  case aQuickAddKey:
	  case aQuickRevUid:
	  case aQuickSetExpire:
	  case aQuickSetPrimaryUid:
	  case aExportOwnerTrust:
	  case aImportOwnerTrust:
          case aRebuildKeydbCaches:
            set_cmd (&cmd, pargs.r_opt);
            break;

	  case aKeygen:
	  case aFullKeygen:
	  case aEditKey:
	  case aDeleteSecretKeys:
	  case aDeleteSecretAndPublicKeys:
	  case aDeleteKeys:
          case aPasswd:
            set_cmd (&cmd, pargs.r_opt);
            greeting=1;
            break;

	  case aShowKeys:
            set_cmd (&cmd, pargs.r_opt);
            opt.import_options |= IMPORT_SHOW;
            opt.import_options |= IMPORT_DRY_RUN;
            opt.import_options &= ~IMPORT_REPAIR_KEYS;
            opt.list_options |= LIST_SHOW_UNUSABLE_UIDS;
            opt.list_options |= LIST_SHOW_UNUSABLE_SUBKEYS;
            opt.list_options |= LIST_SHOW_NOTATIONS;
            opt.list_options |= LIST_SHOW_POLICY_URLS;
            break;

	  case aDetachedSign: detached_sig = 1; set_cmd( &cmd, aSign ); break;

	  case aDecryptFiles: multifile=1; /* fall through */
	  case aDecrypt: set_cmd( &cmd, aDecrypt); break;

	  case aEncrFiles: multifile=1; /* fall through */
	  case aEncr: set_cmd( &cmd, aEncr); break;

	  case aVerifyFiles: multifile=1; /* fall through */
	  case aVerify: set_cmd( &cmd, aVerify); break;

          case aServer:
            set_cmd (&cmd, pargs.r_opt);
            opt.batch = 1;
            break;

          case aTOFUPolicy:
            set_cmd (&cmd, pargs.r_opt);
            break;

	  case oArmor: opt.armor = 1; opt.no_armor=0; break;
	  case oOutput: opt.outfile = pargs.r.ret_str; break;

	  case oMaxOutput: opt.max_output = pargs.r.ret_ulong; break;

          case oInputSizeHint:
            opt.input_size_hint = string_to_u64 (pargs.r.ret_str);
            break;

	  case oQuiet: opt.quiet = 1; break;
	  case oNoTTY: tty_no_terminal(1); break;
	  case oDryRun: opt.dry_run = 1; break;
	  case oInteractive: opt.interactive = 1; break;
	  case oVerbose:
	    opt.verbose++;
            gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
	    opt.list_options|=LIST_SHOW_UNUSABLE_UIDS;
	    opt.list_options|=LIST_SHOW_UNUSABLE_SUBKEYS;
	    break;

	  case oBatch:
            opt.batch = 1;
            nogreeting = 1;
            break;

          case oUseAgent: /* Dummy. */
            break;

          case oNoUseAgent:
	    obsolete_option (configname, pargs.lineno, "no-use-agent");
            break;
	  case oGpgAgentInfo:
	    obsolete_option (configname, pargs.lineno, "gpg-agent-info");
            break;
          case oReaderPort:
	    obsolete_scdaemon_option (configname, pargs.lineno, "reader-port");
            break;
          case octapiDriver:
	    obsolete_scdaemon_option (configname, pargs.lineno, "ctapi-driver");
            break;
          case opcscDriver:
	    obsolete_scdaemon_option (configname, pargs.lineno, "pcsc-driver");
            break;
          case oDisableCCID:
	    obsolete_scdaemon_option (configname, pargs.lineno, "disable-ccid");
            break;
          case oHonorHttpProxy:
	    obsolete_option (configname, pargs.lineno, "honor-http-proxy");
            break;

	  case oAnswerYes: opt.answer_yes = 1; break;
	  case oAnswerNo: opt.answer_no = 1; break;
	  case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
	  case oPrimaryKeyring:
	    sl = append_to_strlist (&nrings, pargs.r.ret_str);
	    sl->flags = KEYDB_RESOURCE_FLAG_PRIMARY;
	    break;
	  case oShowKeyring:
	    deprecated_warning(configname,pargs.lineno,"--show-keyring",
			       "--list-options ","show-keyring");
	    opt.list_options|=LIST_SHOW_KEYRING;
	    break;

	  case oDebug:
            if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
              {
                pargs.r_opt = ARGPARSE_INVALID_ARG;
                pargs.err = ARGPARSE_PRINT_ERROR;
              }
            break;

	  case oDebugAll: opt.debug = ~0; break;
          case oDebugLevel: debug_level = pargs.r.ret_str; break;

          case oDebugIOLBF: break; /* Already set in pre-parse step.  */

	  case oStatusFD:
            set_status_fd ( translate_sys2libc_fd_int (pargs.r.ret_int, 1) );
            break;
	  case oStatusFile:
            set_status_fd ( open_info_file (pargs.r.ret_str, 1, 0) );
            break;
	  case oAttributeFD:
            set_attrib_fd ( translate_sys2libc_fd_int (pargs.r.ret_int, 1) );
            break;
	  case oAttributeFile:
            set_attrib_fd ( open_info_file (pargs.r.ret_str, 1, 1) );
            break;
	  case oLoggerFD:
            log_set_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
            break;
          case oLoggerFile:
            logfile = pargs.r.ret_str;
            break;

	  case oWithFingerprint:
            opt.with_fingerprint = 1;
            opt.fingerprint++;
            break;
	  case oWithSubkeyFingerprint:
            opt.with_subkey_fingerprint = 1;
            break;
	  case oWithICAOSpelling:
            opt.with_icao_spelling = 1;
            break;
	  case oFingerprint:
            opt.fingerprint++;
            fpr_maybe_cmd = 1;
            break;

	  case oWithKeygrip:
            opt.with_keygrip = 1;
            break;

	  case oWithSecret:
            opt.with_secret = 1;
            break;

	  case oWithWKDHash:
            opt.with_wkd_hash = 1;
            break;

	  case oWithKeyOrigin:
            opt.with_key_origin = 1;
            break;

	  case oSecretKeyring:
            /* Ignore this old option.  */
            break;

	  case oNoArmor: opt.no_armor=1; opt.armor=0; break;

	  case oNoDefKeyring:
            if (default_keyring > 0)
              default_keyring = 0;
            break;
	  case oNoKeyring:
            default_keyring = -1;
            break;

	  case oNoGreeting: nogreeting = 1; break;
	  case oNoVerbose:
            opt.verbose = 0;
            gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
            opt.list_sigs=0;
            break;
          case oQuickRandom:
            gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
            break;
	  case oEmitVersion: opt.emit_version++; break;
	  case oNoEmitVersion: opt.emit_version=0; break;
	  case oCompletesNeeded: opt.completes_needed = pargs.r.ret_int; break;
	  case oMarginalsNeeded: opt.marginals_needed = pargs.r.ret_int; break;
	  case oMaxCertDepth: opt.max_cert_depth = pargs.r.ret_int; break;

#ifndef NO_TRUST_MODELS
	  case oTrustDBName: trustdb_name = pargs.r.ret_str; break;

#endif /*!NO_TRUST_MODELS*/
	  case oDefaultKey:
            sl = add_to_strlist (&opt.def_secret_key, pargs.r.ret_str);
            sl->flags = (pargs.r_opt << PK_LIST_SHIFT);
            if (configname)
              sl->flags |= PK_LIST_CONFIG;
            break;
	  case oDefRecipient:
            if( *pargs.r.ret_str )
	      {
		xfree (opt.def_recipient);
		opt.def_recipient = make_username(pargs.r.ret_str);
	      }
            break;
	  case oDefRecipientSelf:
            xfree(opt.def_recipient); opt.def_recipient = NULL;
            opt.def_recipient_self = 1;
            break;
	  case oNoDefRecipient:
            xfree(opt.def_recipient); opt.def_recipient = NULL;
            opt.def_recipient_self = 0;
            break;
	  case oHomedir: break;
	  case oNoBatch: opt.batch = 0; break;

          case oWithTofuInfo: opt.with_tofu_info = 1; break;

	  case oWithKeyData: opt.with_key_data=1; /*FALLTHRU*/
	  case oWithColons: opt.with_colons=':'; break;

          case oWithSigCheck: opt.check_sigs = 1; /*FALLTHRU*/
          case oWithSigList: opt.list_sigs = 1; break;

	  case oSkipVerify: opt.skip_verify=1; break;

	  case oSkipHiddenRecipients: opt.skip_hidden_recipients = 1; break;
	  case oNoSkipHiddenRecipients: opt.skip_hidden_recipients = 0; break;

	  case aListSecretKeys: set_cmd( &cmd, aListSecretKeys); break;

#ifndef NO_TRUST_MODELS
	    /* There are many programs (like mutt) that call gpg with
	       --always-trust so keep this option around for a long
	       time. */
	  case oAlwaysTrust: opt.trust_model=TM_ALWAYS; break;
	  case oTrustModel:
	    parse_trust_model(pargs.r.ret_str);
	    break;
#endif /*!NO_TRUST_MODELS*/
	  case oTOFUDefaultPolicy:
	    opt.tofu_default_policy = parse_tofu_policy (pargs.r.ret_str);
	    break;
	  case oTOFUDBFormat:
	    obsolete_option (configname, pargs.lineno, "tofu-db-format");
	    break;

	  case oForceOwnertrust:
	    log_info(_("Note: %s is not for normal use!\n"),
		     "--force-ownertrust");
	    opt.force_ownertrust=string_to_trust_value(pargs.r.ret_str);
	    if(opt.force_ownertrust==-1)
	      {
		log_error("invalid ownertrust '%s'\n",pargs.r.ret_str);
		opt.force_ownertrust=0;
	      }
	    break;
	  case oLoadExtension:
            /* Dummy so that gpg 1.4 conf files can work. Should
               eventually be removed.  */
	    break;

          case oCompliance:
	    {
	      int compliance = gnupg_parse_compliance_option
                (pargs.r.ret_str,
                 compliance_options, DIM (compliance_options),
                 opt.quiet);
	      if (compliance < 0)
		g10_exit (1);
	      set_compliance_option (compliance);
	    }
            break;
          case oOpenPGP:
          case oRFC2440:
          case oRFC4880:
          case oRFC4880bis:
          case oPGP6:
          case oPGP7:
          case oPGP8:
          case oGnuPG:
            set_compliance_option (pargs.r_opt);
            break;

          case oRFC2440Text: opt.rfc2440_text=1; break;
          case oNoRFC2440Text: opt.rfc2440_text=0; break;

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
	    deprecated_warning(configname,pargs.lineno,"--show-policy-url",
			       "--list-options ","show-policy-urls");
	    deprecated_warning(configname,pargs.lineno,"--show-policy-url",
			       "--verify-options ","show-policy-urls");
	    opt.list_options|=LIST_SHOW_POLICY_URLS;
	    opt.verify_options|=VERIFY_SHOW_POLICY_URLS;
	    break;
	  case oNoShowPolicyURL:
	    deprecated_warning(configname,pargs.lineno,"--no-show-policy-url",
			       "--list-options ","no-show-policy-urls");
	    deprecated_warning(configname,pargs.lineno,"--no-show-policy-url",
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
	    deprecated_warning(configname,pargs.lineno,
			       "--default-comment","--no-comments","");
	    /* fall through */
	  case oNoComments:
	    free_strlist(opt.comments);
	    opt.comments=NULL;
	    break;
	  case oThrowKeyids: opt.throw_keyids = 1; break;
	  case oNoThrowKeyids: opt.throw_keyids = 0; break;
	  case oShowPhotos:
	    deprecated_warning(configname,pargs.lineno,"--show-photos",
			       "--list-options ","show-photos");
	    deprecated_warning(configname,pargs.lineno,"--show-photos",
			       "--verify-options ","show-photos");
	    opt.list_options|=LIST_SHOW_PHOTOS;
	    opt.verify_options|=VERIFY_SHOW_PHOTOS;
	    break;
	  case oNoShowPhotos:
	    deprecated_warning(configname,pargs.lineno,"--no-show-photos",
			       "--list-options ","no-show-photos");
	    deprecated_warning(configname,pargs.lineno,"--no-show-photos",
			       "--verify-options ","no-show-photos");
	    opt.list_options&=~LIST_SHOW_PHOTOS;
	    opt.verify_options&=~VERIFY_SHOW_PHOTOS;
	    break;
	  case oPhotoViewer: opt.photo_viewer = pargs.r.ret_str; break;

          case oDisableSignerUID: opt.flags.disable_signer_uid = 1; break;
          case oIncludeKeyBlock:  opt.flags.include_key_block = 1; break;
          case oNoIncludeKeyBlock: opt.flags.include_key_block = 0; break;

	  case oS2KMode:   opt.s2k_mode = pargs.r.ret_int; break;
	  case oS2KDigest: s2k_digest_string = xstrdup(pargs.r.ret_str); break;
	  case oS2KCipher: s2k_cipher_string = xstrdup(pargs.r.ret_str); break;
	  case oS2KCount:
	    if (pargs.r.ret_int)
              opt.s2k_count = encode_s2k_iterations (pargs.r.ret_int);
            else
              opt.s2k_count = 0;  /* Auto-calibrate when needed.  */
	    break;

	  case oRecipient:
	  case oHiddenRecipient:
	  case oRecipientFile:
	  case oHiddenRecipientFile:
            /* Store the recipient.  Note that we also store the
             * option as private data in the flags.  This is achieved
             * by shifting the option value to the left so to keep
             * enough space for the flags.  */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = (pargs.r_opt << PK_LIST_SHIFT);
            if (configname)
              sl->flags |= PK_LIST_CONFIG;
            if (pargs.r_opt == oHiddenRecipient
                || pargs.r_opt == oHiddenRecipientFile)
              sl->flags |= PK_LIST_HIDDEN;
            if (pargs.r_opt == oRecipientFile
                || pargs.r_opt == oHiddenRecipientFile)
              sl->flags |= PK_LIST_FROM_FILE;
            any_explicit_recipient = 1;
	    break;

	  case oEncryptTo:
	  case oHiddenEncryptTo:
            /* Store an additional recipient.  */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = ((pargs.r_opt << PK_LIST_SHIFT) | PK_LIST_ENCRYPT_TO);
            if (configname)
              sl->flags |= PK_LIST_CONFIG;
            if (pargs.r_opt == oHiddenEncryptTo)
              sl->flags |= PK_LIST_HIDDEN;
	    break;

	  case oNoEncryptTo:
            opt.no_encrypt_to = 1;
            break;
          case oEncryptToDefaultKey:
            opt.encrypt_to_default_key = configname ? 2 : 1;
            break;

	  case oTrySecretKey:
	    add_to_strlist2 (&opt.secret_keys_to_try,
                             pargs.r.ret_str, utf8_strings);
	    break;

          case oMimemode: opt.mimemode = opt.textmode = 1; break;
	  case oTextmodeShort: opt.textmode = 2; break;
	  case oTextmode: opt.textmode=1;  break;
	  case oNoTextmode: opt.textmode=opt.mimemode=0;  break;

	  case oExpert: opt.expert = 1; break;
	  case oNoExpert: opt.expert = 0; break;
	  case oDefSigExpire:
	    if(*pargs.r.ret_str!='\0')
	      {
		if(parse_expire_string(pargs.r.ret_str)==(u32)-1)
		  log_error(_("'%s' is not a valid signature expiration\n"),
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
		if(parse_expire_string(pargs.r.ret_str)==(u32)-1)
		  log_error(_("'%s' is not a valid signature expiration\n"),
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
	    sl = add_to_strlist2( &locusr, pargs.r.ret_str, utf8_strings );
            sl->flags = (pargs.r_opt << PK_LIST_SHIFT);
            if (configname)
              sl->flags |= PK_LIST_CONFIG;
	    break;
	  case oSender:
            {
              char *mbox = mailbox_from_userid (pargs.r.ret_str);
              if (!mbox)
                log_error (_("\"%s\" is not a proper mail address\n"),
                           pargs.r.ret_str);
              else
                {
                  add_to_strlist (&opt.sender_list, mbox);
                  xfree (mbox);
                }
            }
	    break;
	  case oCompress:
	    /* this is the -z command line option */
	    opt.compress_level = opt.bz2_compress_level = pargs.r.ret_int;
	    break;
	  case oCompressLevel: opt.compress_level = pargs.r.ret_int; break;
	  case oBZ2CompressLevel: opt.bz2_compress_level = pargs.r.ret_int; break;
	  case oBZ2DecompressLowmem: opt.bz2_decompress_lowmem=1; break;
	  case oPassphrase:
            set_passphrase_from_string (pargs.r_type ? pargs.r.ret_str : "");
	    break;
	  case oPassphraseFD:
            pwfd = translate_sys2libc_fd_int (pargs.r.ret_int, 0);
            break;
	  case oPassphraseFile:
            pwfd = open_info_file (pargs.r.ret_str, 0, 1);
            break;
	  case oPassphraseRepeat:
            opt.passphrase_repeat = pargs.r.ret_int;
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

	  case oCommandFD:
            opt.command_fd = translate_sys2libc_fd_int (pargs.r.ret_int, 0);
	    if (! gnupg_fd_valid (opt.command_fd))
	      log_error ("command-fd is invalid: %s\n", strerror (errno));
            break;
	  case oCommandFile:
            opt.command_fd = open_info_file (pargs.r.ret_str, 0, 1);
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
	  case oCertDigestAlgo:
            cert_digest_string = xstrdup(pargs.r.ret_str);
            break;

	  case oNoSecmemWarn:
            gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
            break;

	  case oRequireSecmem: require_secmem=1; break;
	  case oNoRequireSecmem: require_secmem=0; break;
	  case oNoPermissionWarn: opt.no_perm_warn=1; break;
          case oDisplayCharset:
	    if( set_native_charset( pargs.r.ret_str ) )
		log_error(_("'%s' is not a valid character set\n"),
			  pargs.r.ret_str);
	    break;
	  case oNotDashEscaped: opt.not_dash_escaped = 1; break;
	  case oEscapeFrom: opt.escape_from = 1; break;
	  case oNoEscapeFrom: opt.escape_from = 0; break;
	  case oLockOnce: opt.lock_once = 1; break;
	  case oLockNever:
            dotlock_disable ();
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
	      keyserver_spec_t keyserver;
	      keyserver = parse_keyserver_uri (pargs.r.ret_str, 0);
	      if (!keyserver)
		log_error (_("could not parse keyserver URL\n"));
	      else
		{
		  /* We only support a single keyserver.  Later ones
		     override earlier ones.  (Since we parse the
		     config file first and then the command line
		     arguments, the command line takes
		     precedence.)  */
		  if (opt.keyserver)
		    free_keyserver_spec (opt.keyserver);
		  opt.keyserver = keyserver;
		}
	    }
	    break;
	  case oKeyServerOptions:
	    if(!parse_keyserver_options(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid keyserver options\n"),
			    configname,pargs.lineno);
		else
		  log_error(_("invalid keyserver options\n"));
	      }
	    break;
	  case oImportOptions:
	    if(!parse_import_options(pargs.r.ret_str,&opt.import_options,1))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid import options\n"),
			    configname,pargs.lineno);
		else
		  log_error(_("invalid import options\n"));
	      }
	    break;
	  case oImportFilter:
	    rc = parse_and_set_import_filter (pargs.r.ret_str);
	    if (rc)
              log_error (_("invalid filter option: %s\n"), gpg_strerror (rc));
	    break;
	  case oExportOptions:
	    if(!parse_export_options(pargs.r.ret_str,&opt.export_options,1))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid export options\n"),
			    configname,pargs.lineno);
		else
		  log_error(_("invalid export options\n"));
	      }
	    break;
	  case oExportFilter:
	    rc = parse_and_set_export_filter (pargs.r.ret_str);
	    if (rc)
              log_error (_("invalid filter option: %s\n"), gpg_strerror (rc));
	    break;
	  case oListOptions:
	    if(!parse_list_options(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid list options\n"),
			    configname,pargs.lineno);
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
			      configname,pargs.lineno);
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
          case oKnownNotation: register_known_notation (pargs.r.ret_str); break;
	  case oShowNotation:
	    deprecated_warning(configname,pargs.lineno,"--show-notation",
			       "--list-options ","show-notations");
	    deprecated_warning(configname,pargs.lineno,"--show-notation",
			       "--verify-options ","show-notations");
	    opt.list_options|=LIST_SHOW_NOTATIONS;
	    opt.verify_options|=VERIFY_SHOW_NOTATIONS;
	    break;
	  case oNoShowNotation:
	    deprecated_warning(configname,pargs.lineno,"--no-show-notation",
			       "--list-options ","no-show-notations");
	    deprecated_warning(configname,pargs.lineno,"--no-show-notation",
			       "--verify-options ","no-show-notations");
	    opt.list_options&=~LIST_SHOW_NOTATIONS;
	    opt.verify_options&=~VERIFY_SHOW_NOTATIONS;
	    break;
	  case oUtf8Strings: utf8_strings = 1; break;
	  case oNoUtf8Strings: utf8_strings = 0; break;
	  case oDisableCipherAlgo:
            {
              int algo = string_to_cipher_algo (pargs.r.ret_str);
              gcry_cipher_ctl (NULL, GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
            }
            break;
	  case oDisablePubkeyAlgo:
            {
              int algo = gcry_pk_map_name (pargs.r.ret_str);
              gcry_pk_ctl (GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
            }
            break;
          case oNoSigCache: opt.no_sig_cache = 1; break;
	  case oAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid = 1; break;
	  case oNoAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid=0; break;
	  case oAllowFreeformUID: opt.allow_freeform_uid = 1; break;
	  case oNoAllowFreeformUID: opt.allow_freeform_uid = 0; break;
	  case oNoLiteral: opt.no_literal = 1; break;
	  case oSetFilesize: opt.set_filesize = pargs.r.ret_ulong; break;
	  case oFastListMode: opt.fast_list_mode = 1; break;
	  case oFixedListMode: /* Dummy */ break;
          case oLegacyListMode: opt.legacy_list_mode = 1; break;
	  case oPrintPKARecords: print_pka_records = 1; break;
	  case oPrintDANERecords: print_dane_records = 1; break;
	  case oListOnly: opt.list_only=1; break;
	  case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
	  case oIgnoreValidFrom: opt.ignore_valid_from = 1; break;
	  case oIgnoreCrcError: opt.ignore_crc_error = 1; break;
	  case oIgnoreMDCError: opt.ignore_mdc_error = 1; break;
	  case oNoRandomSeedFile: use_random_seed = 0; break;

          case oAutoKeyImport: opt.flags.auto_key_import = 1; break;
          case oNoAutoKeyImport: opt.flags.auto_key_import = 0; break;

	  case oAutoKeyRetrieve:
            opt.keyserver_options.options |= KEYSERVER_AUTO_KEY_RETRIEVE;
            break;
	  case oNoAutoKeyRetrieve:
            opt.keyserver_options.options &= ~KEYSERVER_AUTO_KEY_RETRIEVE;
            break;

	  case oShowSessionKey: opt.show_session_key = 1; break;
	  case oOverrideSessionKey:
		opt.override_session_key = pargs.r.ret_str;
		break;
	  case oOverrideSessionKeyFD:
                ovrseskeyfd = translate_sys2libc_fd_int (pargs.r.ret_int, 0);
		break;
	  case oMergeOnly:
	        deprecated_warning(configname,pargs.lineno,"--merge-only",
				   "--import-options ","merge-only");
		opt.import_options|=IMPORT_MERGE_ONLY;
	    break;
          case oAllowSecretKeyImport: /* obsolete */ break;
	  case oTryAllSecrets: opt.try_all_secrets = 1; break;
          case oTrustedKey: register_trusted_key( pargs.r.ret_str ); break;

          case oEnableSpecialFilenames:
            enable_special_filenames ();
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
	      keyserver_spec_t keyserver;
	      keyserver = parse_keyserver_uri (pargs.r.ret_str,1 );
	      if (!keyserver)
		log_error (_("could not parse keyserver URL\n"));
	      else
		free_keyserver_spec (keyserver);

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
          case oAgentProgram: opt.agent_program = pargs.r.ret_str;  break;
          case oDirmngrProgram: opt.dirmngr_program = pargs.r.ret_str; break;
	  case oDisableDirmngr: opt.disable_dirmngr = 1;  break;
          case oWeakDigest:
	    additional_weak_digest(pargs.r.ret_str);
	    break;
          case oUnwrap:
            opt.unwrap_encryption = 1;
            break;
          case oOnlySignTextIDs:
            opt.only_sign_text_ids = 1;
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

	  case oStrict:
	  case oNoStrict:
	    /* Not used */
            break;

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
	    else if(ascii_strcasecmp(pargs.r.ret_str,"none")==0)
	      opt.keyid_format = KF_NONE;
	    else
	      log_error("unknown keyid-format '%s'\n",pargs.r.ret_str);
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
            if (default_akl)
              {
                /* This is the first time --auto-key-locate is seen.
                 * We need to reset the default akl.  */
                default_akl = 0;
                release_akl();
              }
	    if(!parse_auto_key_locate(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid auto-key-locate list\n"),
			    configname,pargs.lineno);
		else
		  log_error(_("invalid auto-key-locate list\n"));
	      }
	    break;
	  case oNoAutoKeyLocate:
	    release_akl();
	    break;

	  case oKeyOrigin:
	    if(!parse_key_origin (pargs.r.ret_str))
              log_error (_("invalid argument for option \"%.50s\"\n"),
                         "--key-origin");
	    break;

	  case oEnableLargeRSA:
#if SECMEM_BUFFER_SIZE >= 65536
            opt.flags.large_rsa=1;
#else
            if (configname)
              log_info("%s:%d: WARNING: gpg not built with large secure "
                         "memory buffer.  Ignoring enable-large-rsa\n",
                        configname,pargs.lineno);
            else
              log_info("WARNING: gpg not built with large secure "
                         "memory buffer.  Ignoring --enable-large-rsa\n");
#endif /* SECMEM_BUFFER_SIZE >= 65536 */
            break;
	  case oDisableLargeRSA: opt.flags.large_rsa=0;
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

          case oAllowWeakDigestAlgos:
            opt.flags.allow_weak_digest_algos = 1;
            break;

          case oAllowWeakKeySignatures:
            opt.flags.allow_weak_key_signatures = 1;
            break;

          case oFakedSystemTime:
            {
              size_t len = strlen (pargs.r.ret_str);
              int freeze = 0;
              time_t faked_time;

              if (len > 0 && pargs.r.ret_str[len-1] == '!')
                {
                  freeze = 1;
                  pargs.r.ret_str[len-1] = '\0';
                }

              faked_time = isotime2epoch (pargs.r.ret_str);
              if (faked_time == (time_t)(-1))
                faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
              gnupg_set_time (faked_time, freeze);
            }
            break;

          case oNoAutostart: opt.autostart = 0; break;
          case oNoSymkeyCache: opt.no_symkey_cache = 1; break;

	  case oDefaultNewKeyAlgo:
            opt.def_new_key_algo = pargs.r.ret_str;
            break;

          case oUseOnlyOpenPGPCard:
            opt.flags.use_only_openpgp_card = 1;
            break;

	  case oNoop: break;

	  default:
            if (configname)
              pargs.err = ARGPARSE_PRINT_WARNING;
            else
              {
                pargs.err = ARGPARSE_PRINT_ERROR;
                /* The argparse fucntion calls a plain exit and thus
                 * we need to print a status here.  */
                write_status_failure ("option-parser",
                                      gpg_error(GPG_ERR_GENERAL));
              }
            break;
	  }
      }

    gnupg_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

    if (log_get_errorcount (0))
      {
        write_status_failure ("option-parser", gpg_error(GPG_ERR_GENERAL));
        g10_exit(2);
      }

    /* The command --gpgconf-list is pretty simple and may be called
       directly after the option parsing. */
    if (cmd == aGPGConfList)
      {
        /* Note: Here in gpg 2.2 we need to provide a proper config
         * file even if that file does not exist.  This is because
         * gpgconf checks that an absolute filename is provided.  */
        if (!last_configname)
          last_configname= make_filename (gnupg_homedir (),
                                          GPG_NAME EXTSEP_S "conf", NULL);
        gpgconf_list (last_configname);
        g10_exit (0);
      }
    xfree (last_configname);
    last_configname = NULL;

    if (print_dane_records)
      log_error ("invalid option \"%s\"; use \"%s\" instead\n",
                 "--print-dane-records",
                 "--export-options export-dane");
    if (print_pka_records)
      log_error ("invalid option \"%s\"; use \"%s\" instead\n",
                 "--print-pks-records",
                 "--export-options export-pka");
    if (log_get_errorcount (0))
      {
        write_status_failure ("option-checking", gpg_error(GPG_ERR_GENERAL));
        g10_exit(2);
      }


    if( nogreeting )
	greeting = 0;

    if( greeting )
      {
	es_fprintf (es_stderr, "%s %s; %s\n",
                    strusage(11), strusage(13), strusage(14) );
	es_fprintf (es_stderr, "%s\n", strusage(15) );
      }
#ifdef IS_DEVELOPMENT_VERSION
    if (!opt.batch)
      {
	const char *s;

	if((s=strusage(25)))
	  log_info("%s\n",s);
	if((s=strusage(26)))
	  log_info("%s\n",s);
	if((s=strusage(27)))
	  log_info("%s\n",s);
      }
#endif

    /* FIXME: We should use logging to a file only in server mode;
       however we have not yet implemetyed that.  Thus we try to get
       away with --batch as indication for logging to file
       required. */
    if (logfile && opt.batch)
      {
        log_set_file (logfile);
        log_set_prefix (NULL, GPGRT_LOG_WITH_PREFIX | GPGRT_LOG_WITH_TIME | GPGRT_LOG_WITH_PID);
      }

    if (opt.verbose > 2)
        log_info ("using character set '%s'\n", get_native_charset ());

    if( may_coredump && !opt.quiet )
	log_info(_("WARNING: program may create a core file!\n"));

    if (opt.flags.rfc4880bis)
	log_info ("WARNING: using experimental features from RFC4880bis!\n");
    else
      {
        opt.mimemode = 0; /* This will use text mode instead.  */
      }

    if (eyes_only) {
      if (opt.set_filename)
	  log_info(_("WARNING: %s overrides %s\n"),
		   "--for-your-eyes-only","--set-filename");

      opt.set_filename="_CONSOLE";
    }

    if (opt.no_literal) {
	log_info(_("Note: %s is not for normal use!\n"), "--no-literal");
	if (opt.textmode)
	    log_error(_("%s not allowed with %s!\n"),
		       "--textmode", "--no-literal" );
	if (opt.set_filename)
	    log_error(_("%s makes no sense with %s!\n"),
			eyes_only?"--for-your-eyes-only":"--set-filename",
		        "--no-literal" );
    }


    if (opt.set_filesize)
	log_info(_("Note: %s is not for normal use!\n"), "--set-filesize");
    if( opt.batch )
	tty_batchmode( 1 );

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


    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    if(require_secmem && !got_secmem)
      {
	log_info(_("will not run with insecure memory due to %s\n"),
		 "--require-secmem");
        write_status_failure ("option-checking", gpg_error(GPG_ERR_GENERAL));
	g10_exit(2);
      }

    set_debug (debug_level);
    if (DBG_CLOCK)
      log_clock ("start");

    /* Do these after the switch(), so they can override settings. */
    if(PGP6)
      {
        /* That does not anymore work because we have no more support
           for v3 signatures.  */
	opt.escape_from=1;
	opt.ask_sig_expire=0;
      }
    else if(PGP7)
      {
        /* That does not anymore work because we have no more support
           for v3 signatures.  */
	opt.escape_from=1;
	opt.ask_sig_expire=0;
      }
    else if(PGP8)
      {
	opt.escape_from=1;
      }


    if( def_cipher_string ) {
	opt.def_cipher_algo = string_to_cipher_algo (def_cipher_string);
	xfree(def_cipher_string); def_cipher_string = NULL;
	if ( openpgp_cipher_test_algo (opt.def_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( def_digest_string ) {
	opt.def_digest_algo = string_to_digest_algo (def_digest_string);
	xfree(def_digest_string); def_digest_string = NULL;
	if ( openpgp_md_test_algo (opt.def_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( compress_algo_string ) {
	opt.compress_algo = string_to_compress_algo(compress_algo_string);
	xfree(compress_algo_string); compress_algo_string = NULL;
	if( check_compress_algo(opt.compress_algo) )
          log_error(_("selected compression algorithm is invalid\n"));
    }
    if( cert_digest_string ) {
	opt.cert_digest_algo = string_to_digest_algo (cert_digest_string);
	xfree(cert_digest_string); cert_digest_string = NULL;
	if (openpgp_md_test_algo(opt.cert_digest_algo))
          log_error(_("selected certification digest algorithm is invalid\n"));
    }
    if( s2k_cipher_string ) {
	opt.s2k_cipher_algo = string_to_cipher_algo (s2k_cipher_string);
	xfree(s2k_cipher_string); s2k_cipher_string = NULL;
	if (openpgp_cipher_test_algo (opt.s2k_cipher_algo))
          log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( s2k_digest_string ) {
	opt.s2k_digest_algo = string_to_digest_algo (s2k_digest_string);
	xfree(s2k_digest_string); s2k_digest_string = NULL;
	if (openpgp_md_test_algo(opt.s2k_digest_algo))
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
	log_info(_("Note: simple S2K mode (0) is strongly discouraged\n"));
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
	  case aSignEncr:
	    cmdname="--sign --encrypt";
	    break;
	  case aClearsign:
	    cmdname="--clear-sign";
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
      {
        write_status_failure ("option-postprocessing",
                              gpg_error(GPG_ERR_GENERAL));
	g10_exit (2);
      }

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
	    badalg = openpgp_cipher_algo_name (opt.def_cipher_algo);
	    badtype = PREFTYPE_SYM;
	  }
	else if(opt.def_digest_algo
		&& !algo_available(PREFTYPE_HASH,opt.def_digest_algo,NULL))
	  {
	    badalg = gcry_md_algo_name (opt.def_digest_algo);
	    badtype = PREFTYPE_HASH;
	  }
	else if(opt.cert_digest_algo
		&& !algo_available(PREFTYPE_HASH,opt.cert_digest_algo,NULL))
	  {
	    badalg = gcry_md_algo_name (opt.cert_digest_algo);
	    badtype = PREFTYPE_HASH;
	  }
	else if(opt.compress_algo!=-1
		&& !algo_available(PREFTYPE_ZIP,opt.compress_algo,NULL))
	  {
	    badalg = compress_algo_to_string(opt.compress_algo);
	    badtype = PREFTYPE_ZIP;
	  }

	if(badalg)
	  {
	    switch(badtype)
	      {
	      case PREFTYPE_SYM:
		log_info (_("cipher algorithm '%s'"
                            " may not be used in %s mode\n"),
			 badalg,
                          gnupg_compliance_option_string (opt.compliance));
		break;
	      case PREFTYPE_HASH:
		log_info (_("digest algorithm '%s'"
                            " may not be used in %s mode\n"),
                          badalg,
                          gnupg_compliance_option_string (opt.compliance));
		break;
	      case PREFTYPE_ZIP:
		log_info (_("compression algorithm '%s'"
                            " may not be used in %s mode\n"),
                          badalg,
                          gnupg_compliance_option_string (opt.compliance));
		break;
	      default:
		BUG();
	      }

	    compliance_failure();
	  }
      }

    /* Check our chosen algorithms against the list of allowed
     * algorithms in the current compliance mode, and fail hard if it
     * is not.  This is us being nice to the user informing her early
     * that the chosen algorithms are not available.  We also check
     * and enforce this right before the actual operation.  */
    if (opt.def_cipher_algo
	&& ! gnupg_cipher_is_allowed (opt.compliance,
				      cmd == aEncr
				      || cmd == aSignEncr
				      || cmd == aEncrSym
				      || cmd == aSym
				      || cmd == aSignSym
				      || cmd == aSignEncrSym,
				      opt.def_cipher_algo,
				      GCRY_CIPHER_MODE_NONE))
      log_error (_("cipher algorithm '%s' may not be used in %s mode\n"),
		 openpgp_cipher_algo_name (opt.def_cipher_algo),
		 gnupg_compliance_option_string (opt.compliance));

    if (opt.def_digest_algo
	&& ! gnupg_digest_is_allowed (opt.compliance,
				      cmd == aSign
				      || cmd == aSignEncr
				      || cmd == aSignEncrSym
				      || cmd == aSignSym
				      || cmd == aClearsign,
				      opt.def_digest_algo))
      log_error (_("digest algorithm '%s' may not be used in %s mode\n"),
		 gcry_md_algo_name (opt.def_digest_algo),
		 gnupg_compliance_option_string (opt.compliance));

    /* Fail hard.  */
    if (log_get_errorcount (0))
      {
        write_status_failure ("option-checking", gpg_error(GPG_ERR_GENERAL));
	g10_exit (2);
      }

    /* Set the random seed file. */
    if (use_random_seed)
      {
        char *p = make_filename (gnupg_homedir (), "random_seed", NULL );
        gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
        if (!gnupg_access (p, F_OK))
          register_secured_file (p);
	xfree(p);
      }

    /* If there is no command but the --fingerprint is given, default
       to the --list-keys command.  */
    if (!cmd && fpr_maybe_cmd)
      {
	set_cmd (&cmd, aListKeys);
      }


    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    /* Add the keyrings, but not for some special commands.  We always
     * need to add the keyrings if we are running under SELinux, this
     * is so that the rings are added to the list of secured files.
     * We do not add any keyring if --no-keyring has been used.  */
    if (default_keyring >= 0
        && (ALWAYS_ADD_KEYRINGS
            || (cmd != aDeArmor && cmd != aEnArmor && cmd != aGPGConfTest)))
      {
	if (!nrings || default_keyring > 0)  /* Add default ring. */
	    keydb_add_resource ("pubring" EXTSEP_S GPGEXT_GPG,
                                KEYDB_RESOURCE_FLAG_DEFAULT);
	for (sl = nrings; sl; sl = sl->next )
          keydb_add_resource (sl->d, sl->flags);
      }
    FREE_STRLIST(nrings);

    if (opt.pinentry_mode == PINENTRY_MODE_LOOPBACK)
      /* In loopback mode, never ask for the password multiple
	 times.  */
      {
	opt.passphrase_repeat = 0;
      }

    if (cmd == aGPGConfTest)
      g10_exit(0);


    if (pwfd != -1)  /* Read the passphrase now. */
      read_passphrase_from_fd (pwfd);

    if (ovrseskeyfd != -1 )  /* Read the sessionkey now. */
      read_sessionkey_from_fd (ovrseskeyfd);

    fname = argc? *argv : NULL;

    if(fname && utf8_strings)
      opt.flags.utf8_filename=1;

    ctrl = xcalloc (1, sizeof *ctrl);
    gpg_init_default_ctrl (ctrl);

#ifndef NO_TRUST_MODELS
    switch (cmd)
      {
      case aPrimegen:
      case aPrintMD:
      case aPrintMDs:
      case aGenRandom:
      case aDeArmor:
      case aEnArmor:
      case aListConfig:
      case aListGcryptConfig:
	break;
      case aFixTrustDB:
      case aExportOwnerTrust:
        rc = setup_trustdb (0, trustdb_name);
        break;
      case aListTrustDB:
        rc = setup_trustdb (argc? 1:0, trustdb_name);
        break;
      case aKeygen:
      case aFullKeygen:
      case aQuickKeygen:
        rc = setup_trustdb (1, trustdb_name);
        break;
      default:
        /* If we are using TM_ALWAYS, we do not need to create the
           trustdb.  */
        rc = setup_trustdb (opt.trust_model != TM_ALWAYS, trustdb_name);
        break;
      }
    if (rc)
      log_error (_("failed to initialize the TrustDB: %s\n"),
                 gpg_strerror (rc));
#endif /*!NO_TRUST_MODELS*/

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


    /* Check for certain command whether we need to migrate a
       secring.gpg to the gpg-agent. */
    switch (cmd)
      {
      case aListSecretKeys:
      case aSign:
      case aSignEncr:
      case aSignEncrSym:
      case aSignSym:
      case aClearsign:
      case aDecrypt:
      case aSignKey:
      case aLSignKey:
      case aEditKey:
      case aPasswd:
      case aDeleteSecretKeys:
      case aDeleteSecretAndPublicKeys:
      case aQuickKeygen:
      case aQuickAddUid:
      case aQuickAddKey:
      case aQuickRevUid:
      case aQuickSetPrimaryUid:
      case aFullKeygen:
      case aKeygen:
      case aImport:
      case aExportSecret:
      case aExportSecretSub:
      case aGenRevoke:
      case aDesigRevoke:
      case aCardEdit:
      case aChangePIN:
        migrate_secring (ctrl);
	break;
      case aListKeys:
        if (opt.with_secret)
          migrate_secring (ctrl);
        break;
      default:
        break;
      }

    /* The command dispatcher.  */
    switch( cmd )
      {
      case aServer:
        gpg_server (ctrl);
        break;

      case aStore: /* only store the file */
	if( argc > 1 )
	    wrong_args("--store [filename]");
	if( (rc = encrypt_store(fname)) )
          {
            write_status_failure ("store", rc);
	    log_error ("storing '%s' failed: %s\n",
                       print_fname_stdin(fname),gpg_strerror (rc) );
          }
	break;
      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    wrong_args("--symmetric [filename]");
	if( (rc = encrypt_symmetric(fname)) )
          {
            write_status_failure ("symencrypt", rc);
            log_error (_("symmetric encryption of '%s' failed: %s\n"),
                        print_fname_stdin(fname),gpg_strerror (rc) );
          }
	break;

      case aEncr: /* encrypt the given file */
	if(multifile)
	  encrypt_crypt_files (ctrl, argc, argv, remusr);
	else
	  {
	    if( argc > 1 )
	      wrong_args("--encrypt [filename]");
	    if( (rc = encrypt_crypt (ctrl, -1, fname, remusr, 0, NULL, -1)) )
              {
                write_status_failure ("encrypt", rc);
                log_error("%s: encryption failed: %s\n",
                          print_fname_stdin(fname), gpg_strerror (rc) );
              }
	  }
	break;

      case aEncrSym:
	/* This works with PGP 8 in the sense that it acts just like a
	   symmetric message.  It doesn't work at all with 2 or 6.  It
	   might work with 7, but alas, I don't have a copy to test
	   with right now. */
	if( argc > 1 )
	  wrong_args("--symmetric --encrypt [filename]");
	else if(opt.s2k_mode==0)
	  log_error(_("you cannot use --symmetric --encrypt"
		      " with --s2k-mode 0\n"));
	else if(PGP6 || PGP7)
	  log_error(_("you cannot use --symmetric --encrypt"
		      " in %s mode\n"),
		    gnupg_compliance_option_string (opt.compliance));
	else
	  {
	    if( (rc = encrypt_crypt (ctrl, -1, fname, remusr, 1, NULL, -1)) )
              {
                write_status_failure ("encrypt", rc);
                log_error ("%s: encryption failed: %s\n",
                           print_fname_stdin(fname), gpg_strerror (rc) );
              }
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
		wrong_args("--sign [filename]");
	    if( argc ) {
		sl = xmalloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	    }
	}
	if ((rc = sign_file (ctrl, sl, detached_sig, locusr, 0, NULL, NULL)))
          {
            write_status_failure ("sign", rc);
	    log_error ("signing failed: %s\n", gpg_strerror (rc) );
          }
	free_strlist(sl);
	break;

      case aSignEncr: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args("--sign --encrypt [filename]");
	if( argc ) {
	    sl = xmalloc_clear( sizeof *sl + strlen(fname));
	    strcpy(sl->d, fname);
	}
	else
	    sl = NULL;
	if ((rc = sign_file (ctrl, sl, detached_sig, locusr, 1, remusr, NULL)))
          {
            write_status_failure ("sign-encrypt", rc);
	    log_error("%s: sign+encrypt failed: %s\n",
		      print_fname_stdin(fname), gpg_strerror (rc) );
          }
	free_strlist(sl);
	break;

      case aSignEncrSym: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args("--symmetric --sign --encrypt [filename]");
	else if(opt.s2k_mode==0)
	  log_error(_("you cannot use --symmetric --sign --encrypt"
		      " with --s2k-mode 0\n"));
	else if(PGP6 || PGP7)
	  log_error(_("you cannot use --symmetric --sign --encrypt"
		      " in %s mode\n"),
		    gnupg_compliance_option_string (opt.compliance));
	else
	  {
	    if( argc )
	      {
		sl = xmalloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	      }
	    else
	      sl = NULL;
	    if ((rc = sign_file (ctrl, sl, detached_sig, locusr,
                                 2, remusr, NULL)))
              {
                write_status_failure ("sign-encrypt", rc);
                log_error("%s: symmetric+sign+encrypt failed: %s\n",
                          print_fname_stdin(fname), gpg_strerror (rc) );
              }
	    free_strlist(sl);
	  }
	break;

      case aSignSym: /* sign and conventionally encrypt the given file */
	if (argc > 1)
	    wrong_args("--sign --symmetric [filename]");
	rc = sign_symencrypt_file (ctrl, fname, locusr);
        if (rc)
          {
            write_status_failure ("sign-symencrypt", rc);
	    log_error("%s: sign+symmetric failed: %s\n",
                      print_fname_stdin(fname), gpg_strerror (rc) );
          }
	break;

      case aClearsign: /* make a clearsig */
	if( argc > 1 )
	    wrong_args("--clear-sign [filename]");
	if( (rc = clearsign_file (ctrl, fname, locusr, NULL)) )
          {
            write_status_failure ("sign", rc);
	    log_error("%s: clear-sign failed: %s\n",
                      print_fname_stdin(fname), gpg_strerror (rc) );
          }
	break;

      case aVerify:
	if (multifile)
	  {
	    if ((rc = verify_files (ctrl, argc, argv)))
	      log_error("verify files failed: %s\n", gpg_strerror (rc) );
	  }
	else
	  {
	    if ((rc = verify_signatures (ctrl, argc, argv)))
	      log_error("verify signatures failed: %s\n", gpg_strerror (rc) );
	  }
        if (rc)
          write_status_failure ("verify", rc);
	break;

      case aDecrypt:
        if (multifile)
	  decrypt_messages (ctrl, argc, argv);
	else
	  {
	    if( argc > 1 )
	      wrong_args("--decrypt [filename]");
	    if( (rc = decrypt_message (ctrl, fname) ))
              {
                write_status_failure ("decrypt", rc);
                log_error("decrypt_message failed: %s\n", gpg_strerror (rc) );
              }
	  }
	break;

      case aQuickSignKey:
      case aQuickLSignKey:
        {
          const char *fpr;

          if (argc < 1)
            wrong_args ("--quick-[l]sign-key fingerprint [userids]");
          fpr = *argv++; argc--;
          sl = NULL;
          for( ; argc; argc--, argv++)
	    append_to_strlist2 (&sl, *argv, utf8_strings);
          keyedit_quick_sign (ctrl, fpr, sl, locusr, (cmd == aQuickLSignKey));
          free_strlist (sl);
        }
	break;

      case aQuickRevSig:
        {
          const char *userid, *siguserid;

          if (argc < 2)
            wrong_args ("--quick-revoke-sig USER-ID SIG-USER-ID [userids]");
          userid = *argv++; argc--;
          siguserid = *argv++; argc--;
          sl = NULL;
          for( ; argc; argc--, argv++)
	    append_to_strlist2 (&sl, *argv, utf8_strings);
          keyedit_quick_revsig (ctrl, userid, siguserid, sl);
          free_strlist (sl);
        }
	break;

      case aSignKey:
	if( argc != 1 )
	  wrong_args("--sign-key user-id");
	/* fall through */
      case aLSignKey:
	if( argc != 1 )
	  wrong_args("--lsign-key user-id");
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
	keyedit_menu (ctrl, username, locusr, sl, 0, 0 );
	xfree(username);
	free_strlist(sl);
	break;

      case aEditKey: /* Edit a key signature */
	if( !argc )
	    wrong_args("--edit-key user-id [commands]");
	username = make_username( fname );
	if( argc > 1 ) {
	    sl = NULL;
	    for( argc--, argv++ ; argc; argc--, argv++ )
		append_to_strlist( &sl, *argv );
	    keyedit_menu (ctrl, username, locusr, sl, 0, 1 );
	    free_strlist(sl);
	}
	else
            keyedit_menu (ctrl, username, locusr, NULL, 0, 1 );
	xfree(username);
	break;

      case aPasswd:
        if (argc != 1)
          wrong_args("--change-passphrase <user-id>");
        else
          {
            username = make_username (fname);
            keyedit_passwd (ctrl, username);
            xfree (username);
          }
        break;

      case aDeleteKeys:
      case aDeleteSecretKeys:
      case aDeleteSecretAndPublicKeys:
	sl = NULL;
        /* Print a note if the user did not specify any key.  */
        if (!argc && !opt.quiet)
          log_info (_("Note: %s\n"), gpg_strerror (GPG_ERR_NO_KEY));
        /* I'm adding these in reverse order as add_to_strlist2
           reverses them again, and it's easier to understand in the
           proper order :) */
	for( ; argc; argc-- )
	  add_to_strlist2( &sl, argv[argc-1], utf8_strings );
	delete_keys (ctrl, sl,
                     cmd==aDeleteSecretKeys, cmd==aDeleteSecretAndPublicKeys);
	free_strlist(sl);
	break;

      case aCheckKeys:
	opt.check_sigs = 1; /* fall through */
      case aListSigs:
	opt.list_sigs = 1; /* fall through */
      case aListKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	public_key_list (ctrl, sl, 0, 0);
	free_strlist(sl);
	break;
      case aListSecretKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	secret_key_list (ctrl, sl);
	free_strlist(sl);
	break;
      case aLocateKeys:
      case aLocateExtKeys:
	sl = NULL;
	for (; argc; argc--, argv++)
          add_to_strlist2( &sl, *argv, utf8_strings );
        if (cmd == aLocateExtKeys && akl_empty_or_only_local ())
          {
            /* This is a kludge to let --locate-external-keys even
             * work if the config file has --no-auto-key-locate.  This
             * better matches the expectations of the user.  */
            release_akl ();
            parse_auto_key_locate (DEFAULT_AKL_LIST);
          }
	public_key_list (ctrl, sl, 1, cmd == aLocateExtKeys);


	free_strlist (sl);
	break;

      case aQuickKeygen:
        {
          const char *x_algo, *x_usage, *x_expire;

          if (argc < 1 || argc > 4)
            wrong_args("--quick-generate-key USER-ID [ALGO [USAGE [EXPIRE]]]");
          username = make_username (fname);
          argv++, argc--;
          x_algo = "";
          x_usage = "";
          x_expire = "";
          if (argc)
            {
              x_algo = *argv++; argc--;
              if (argc)
                {
                  x_usage = *argv++; argc--;
                  if (argc)
                    {
                      x_expire = *argv++; argc--;
                    }
                }
            }
          quick_generate_keypair (ctrl, username, x_algo, x_usage, x_expire);
          xfree (username);
        }
        break;

      case aKeygen: /* generate a key */
	if( opt.batch ) {
	    if( argc > 1 )
		wrong_args("--generate-key [parameterfile]");
	    generate_keypair (ctrl, 0, argc? *argv : NULL, NULL, 0);
	}
	else {
            if (opt.command_fd != -1 && argc)
              {
                if( argc > 1 )
                  wrong_args("--generate-key [parameterfile]");

                opt.batch = 1;
                generate_keypair (ctrl, 0, argc? *argv : NULL, NULL, 0);
              }
            else if (argc)
              wrong_args ("--generate-key");
            else
              generate_keypair (ctrl, 0, NULL, NULL, 0);
	}
	break;

      case aFullKeygen: /* Generate a key with all options. */
	if (opt.batch)
          {
	    if (argc > 1)
              wrong_args ("--full-generate-key [parameterfile]");
	    generate_keypair (ctrl, 1, argc? *argv : NULL, NULL, 0);
          }
	else
          {
	    if (argc)
              wrong_args("--full-generate-key");
	    generate_keypair (ctrl, 1, NULL, NULL, 0);
	}
	break;

      case aQuickAddUid:
        {
          const char *uid, *newuid;

          if (argc != 2)
            wrong_args ("--quick-add-uid USER-ID NEW-USER-ID");
          uid = *argv++; argc--;
          newuid = *argv++; argc--;
          keyedit_quick_adduid (ctrl, uid, newuid);
        }
	break;

      case aQuickAddKey:
        {
          const char *x_fpr, *x_algo, *x_usage, *x_expire;

          if (argc < 1 || argc > 4)
            wrong_args ("--quick-add-key FINGERPRINT [ALGO [USAGE [EXPIRE]]]");
          x_fpr = *argv++; argc--;
          x_algo = "";
          x_usage = "";
          x_expire = "";
          if (argc)
            {
              x_algo = *argv++; argc--;
              if (argc)
                {
                  x_usage = *argv++; argc--;
                  if (argc)
                   {
                     x_expire = *argv++; argc--;
                   }
                }
            }
          keyedit_quick_addkey (ctrl, x_fpr, x_algo, x_usage, x_expire);
        }
	break;

      case aQuickRevUid:
        {
          const char *uid, *uidtorev;

          if (argc != 2)
            wrong_args ("--quick-revoke-uid USER-ID USER-ID-TO-REVOKE");
          uid = *argv++; argc--;
          uidtorev = *argv++; argc--;
          keyedit_quick_revuid (ctrl, uid, uidtorev);
        }
	break;

      case aQuickSetExpire:
        {
          const char *x_fpr, *x_expire;

          if (argc < 2)
            wrong_args ("--quick-set-exipre FINGERPRINT EXPIRE [SUBKEY-FPRS]");
          x_fpr = *argv++; argc--;
          x_expire = *argv++; argc--;
          keyedit_quick_set_expire (ctrl, x_fpr, x_expire, argv);
        }
	break;

      case aQuickSetPrimaryUid:
        {
          const char *uid, *primaryuid;

          if (argc != 2)
            wrong_args ("--quick-set-primary-uid USER-ID PRIMARY-USER-ID");
          uid = *argv++; argc--;
          primaryuid = *argv++; argc--;
          keyedit_quick_set_primary (ctrl, uid, primaryuid);
        }
	break;

      case aFastImport:
        opt.import_options |= IMPORT_FAST; /* fall through */
      case aImport:
      case aShowKeys:
	import_keys (ctrl, argc? argv:NULL, argc, NULL,
                     opt.import_options, opt.key_origin, opt.key_origin_url);
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
            rc = keyserver_export (ctrl, sl );
	else if( cmd == aRecvKeys )
            rc = keyserver_import (ctrl, sl );
	else
          {
            export_stats_t stats = export_new_stats ();
            rc = export_pubkeys (ctrl, sl, opt.export_options, stats);
            export_print_stats (stats);
            export_release_stats (stats);
          }
	if(rc)
	  {
	    if(cmd==aSendKeys)
              {
                write_status_failure ("send-keys", rc);
                log_error(_("keyserver send failed: %s\n"),gpg_strerror (rc));
              }
	    else if(cmd==aRecvKeys)
              {
                write_status_failure ("recv-keys", rc);
                log_error (_("keyserver receive failed: %s\n"),
                           gpg_strerror (rc));
              }
	    else
              {
                write_status_failure ("export", rc);
                log_error (_("key export failed: %s\n"), gpg_strerror (rc));
              }
	  }
	free_strlist(sl);
	break;

      case aExportSshKey:
        if (argc != 1)
          wrong_args ("--export-ssh-key <user-id>");
        rc = export_ssh_key (ctrl, argv[0]);
        if (rc)
          {
            write_status_failure ("export-ssh-key", rc);
            log_error (_("export as ssh key failed: %s\n"), gpg_strerror (rc));
          }
	break;

     case aSearchKeys:
	sl = NULL;
	for (; argc; argc--, argv++)
	  append_to_strlist2 (&sl, *argv, utf8_strings);
	rc = keyserver_search (ctrl, sl);
	if (rc)
          {
            write_status_failure ("search-keys", rc);
            log_error (_("keyserver search failed: %s\n"), gpg_strerror (rc));
          }
	free_strlist (sl);
	break;

      case aRefreshKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	rc = keyserver_refresh (ctrl, sl);
	if(rc)
          {
            write_status_failure ("refresh-keys", rc);
            log_error (_("keyserver refresh failed: %s\n"),gpg_strerror (rc));
          }
	free_strlist(sl);
	break;

      case aFetchKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	rc = keyserver_fetch (ctrl, sl, opt.key_origin);
	if(rc)
          {
            write_status_failure ("fetch-keys", rc);
            log_error ("key fetch failed: %s\n",gpg_strerror (rc));
          }
	free_strlist(sl);
	break;

      case aExportSecret:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
        {
          export_stats_t stats = export_new_stats ();
          export_seckeys (ctrl, sl, opt.export_options, stats);
          export_print_stats (stats);
          export_release_stats (stats);
        }
	free_strlist(sl);
	break;

      case aExportSecretSub:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
        {
          export_stats_t stats = export_new_stats ();
          export_secsubkeys (ctrl, sl, opt.export_options, stats);
          export_print_stats (stats);
          export_release_stats (stats);
        }
	free_strlist(sl);
	break;

      case aGenRevoke:
	if( argc != 1 )
	    wrong_args("--generate-revocation user-id");
	username =  make_username(*argv);
	gen_revoke (ctrl, username );
	xfree( username );
	break;

      case aDesigRevoke:
	if (argc != 1)
	    wrong_args ("--generate-designated-revocation user-id");
	username = make_username (*argv);
	gen_desig_revoke (ctrl, username, locusr);
	xfree (username);
	break;

      case aDeArmor:
	if( argc > 1 )
	    wrong_args("--dearmor [file]");
	rc = dearmor_file( argc? *argv: NULL );
	if( rc )
          {
            write_status_failure ("dearmor", rc);
            log_error (_("dearmoring failed: %s\n"), gpg_strerror (rc));
          }
	break;

      case aEnArmor:
	if( argc > 1 )
	    wrong_args("--enarmor [file]");
	rc = enarmor_file( argc? *argv: NULL );
	if( rc )
          {
            write_status_failure ("enarmor", rc);
	    log_error (_("enarmoring failed: %s\n"), gpg_strerror (rc));
          }
	break;


      case aPrimegen:
#if 0 /*FIXME*/
	{   int mode = argc < 2 ? 0 : atoi(*argv);

	    if( mode == 1 && argc == 2 ) {
		mpi_print (es_stdout,
                           generate_public_prime( atoi(argv[1]) ), 1);
	    }
	    else if( mode == 2 && argc == 3 ) {
		mpi_print (es_stdout, generate_elg_prime(
					     0, atoi(argv[1]),
					     atoi(argv[2]), NULL,NULL ), 1);
	    }
	    else if( mode == 3 && argc == 3 ) {
		MPI *factors;
		mpi_print (es_stdout, generate_elg_prime(
					     1, atoi(argv[1]),
					     atoi(argv[2]), NULL,&factors ), 1);
		es_putc ('\n', es_stdout);
		mpi_print (es_stdout, factors[0], 1 ); /* print q */
	    }
	    else if( mode == 4 && argc == 3 ) {
		MPI g = mpi_alloc(1);
		mpi_print (es_stdout, generate_elg_prime(
						 0, atoi(argv[1]),
						 atoi(argv[2]), g, NULL ), 1);
		es_putc ('\n', es_stdout);
		mpi_print (es_stdout, g, 1 );
		mpi_free (g);
	    }
	    else
		wrong_args("--gen-prime mode bits [qbits] ");
	    es_putc ('\n', es_stdout);
	}
#endif
        wrong_args("--gen-prime not yet supported ");
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

		p = gcry_random_bytes (n, level);
#ifdef HAVE_DOSISH_SYSTEM
		setmode ( fileno(stdout), O_BINARY );
#endif
                if (opt.armor) {
                    char *tmp = make_radix64_string (p, n);
                    es_fputs (tmp, es_stdout);
                    xfree (tmp);
                    if (n%3 == 1)
                      es_putc ('=', es_stdout);
                    if (n%3)
                      es_putc ('=', es_stdout);
                } else {
                    es_fwrite( p, n, 1, es_stdout );
                }
		xfree(p);
		if( !endless )
		    count -= n;
	    }
            if (opt.armor)
              es_putc ('\n', es_stdout);
	}
	break;

      case aPrintMD:
	if( argc < 1)
	    wrong_args("--print-md algo [files]");
	{
	    int all_algos = (**argv=='*' && !(*argv)[1]);
	    int algo = all_algos? 0 : gcry_md_map_name (*argv);

	    if( !algo && !all_algos )
		log_error(_("invalid hash algorithm '%s'\n"), *argv );
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

#ifndef NO_TRUST_MODELS
      case aListTrustDB:
	if( !argc )
          list_trustdb (ctrl, es_stdout, NULL);
	else {
	    for( ; argc; argc--, argv++ )
              list_trustdb (ctrl, es_stdout, *argv );
	}
	break;

      case aUpdateTrustDB:
	if( argc )
	    wrong_args("--update-trustdb");
	update_trustdb (ctrl);
	break;

      case aCheckTrustDB:
        /* Old versions allowed for arguments - ignore them */
        check_trustdb (ctrl);
	break;

      case aFixTrustDB:
        how_to_fix_the_trustdb ();
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
	export_ownertrust (ctrl);
	break;

      case aImportOwnerTrust:
	if( argc > 1 )
	    wrong_args("--import-ownertrust [file]");
	import_ownertrust (ctrl, argc? *argv:NULL );
	break;
#endif /*!NO_TRUST_MODELS*/

      case aRebuildKeydbCaches:
        if (argc)
            wrong_args ("--rebuild-keydb-caches");
        keydb_rebuild_caches (ctrl, 1);
        break;

#ifdef ENABLE_CARD_SUPPORT
      case aCardStatus:
        if (argc == 0)
            card_status (ctrl, es_stdout, NULL);
        else if (argc == 1)
            card_status (ctrl, es_stdout, *argv);
        else
            wrong_args ("--card-status [serialno]");
        break;

      case aCardEdit:
        if (argc) {
            sl = NULL;
            for (argc--, argv++ ; argc; argc--, argv++)
                append_to_strlist (&sl, *argv);
            card_edit (ctrl, sl);
            free_strlist (sl);
	}
        else
          card_edit (ctrl, NULL);
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

      case aListGcryptConfig:
        /* Fixme: It would be nice to integrate that with
           --list-config but unfortunately there is no way yet to have
           libgcrypt print it to an estream for further parsing.  */
        gcry_control (GCRYCTL_PRINT_CONFIG, stdout);
        break;

      case aTOFUPolicy:
#ifdef USE_TOFU
	{
	  int policy;
	  int i;
	  KEYDB_HANDLE hd;

	  if (argc < 2)
	    wrong_args ("--tofu-policy POLICY KEYID [KEYID...]");

	  policy = parse_tofu_policy (argv[0]);

	  hd = keydb_new ();
	  if (! hd)
            {
              write_status_failure ("tofu-driver", gpg_error(GPG_ERR_GENERAL));
              g10_exit (1);
            }

          tofu_begin_batch_update (ctrl);

	  for (i = 1; i < argc; i ++)
	    {
	      KEYDB_SEARCH_DESC desc;
	      kbnode_t kb;

	      rc = classify_user_id (argv[i], &desc, 0);
	      if (rc)
		{
		  log_error (_("error parsing key specification '%s': %s\n"),
                             argv[i], gpg_strerror (rc));
                  write_status_failure ("tofu-driver", rc);
		  g10_exit (1);
		}

	      if (! (desc.mode == KEYDB_SEARCH_MODE_SHORT_KID
		     || desc.mode == KEYDB_SEARCH_MODE_LONG_KID
		     || desc.mode == KEYDB_SEARCH_MODE_FPR16
		     || desc.mode == KEYDB_SEARCH_MODE_FPR20
		     || desc.mode == KEYDB_SEARCH_MODE_FPR
		     || desc.mode == KEYDB_SEARCH_MODE_KEYGRIP))
		{
		  log_error (_("'%s' does not appear to be a valid"
			       " key ID, fingerprint or keygrip\n"),
			     argv[i]);
                  write_status_failure ("tofu-driver",
                                        gpg_error(GPG_ERR_GENERAL));
		  g10_exit (1);
		}

	      rc = keydb_search_reset (hd);
	      if (rc)
		{
                  /* This should not happen, thus no need to tranalate
                     the string.  */
                  log_error ("keydb_search_reset failed: %s\n",
                             gpg_strerror (rc));
                  write_status_failure ("tofu-driver", rc);
		  g10_exit (1);
		}

	      rc = keydb_search (hd, &desc, 1, NULL);
	      if (rc)
		{
		  log_error (_("key \"%s\" not found: %s\n"), argv[i],
                             gpg_strerror (rc));
                  write_status_failure ("tofu-driver", rc);
		  g10_exit (1);
		}

	      rc = keydb_get_keyblock (hd, &kb);
	      if (rc)
		{
		  log_error (_("error reading keyblock: %s\n"),
                             gpg_strerror (rc));
                  write_status_failure ("tofu-driver", rc);
		  g10_exit (1);
		}

	      merge_keys_and_selfsig (ctrl, kb);
	      if (tofu_set_policy (ctrl, kb, policy))
                {
                  write_status_failure ("tofu-driver", rc);
                  g10_exit (1);
                }

              release_kbnode (kb);
	    }

          tofu_end_batch_update (ctrl);

	  keydb_release (hd);
	}
#endif /*USE_TOFU*/
	break;

      default:
        if (!opt.quiet)
          log_info (_("WARNING: no command supplied."
                      "  Trying to guess what you mean ...\n"));
        /*FALLTHRU*/
      case aListPackets:
	if( argc > 1 )
	    wrong_args("[filename]");
	/* Issue some output for the unix newbie */
	if (!fname && !opt.outfile
            && gnupg_isatty (fileno (stdin))
            && gnupg_isatty (fileno (stdout))
            && gnupg_isatty (fileno (stderr)))
	    log_info(_("Go ahead and type your message ...\n"));

	a = iobuf_open(fname);
        if (a && is_secured_file (iobuf_get_fd (a)))
          {
            iobuf_close (a);
            a = NULL;
            gpg_err_set_errno (EPERM);
          }
	if( !a )
	    log_error(_("can't open '%s'\n"), print_fname_stdin(fname));
	else {

	    if( !opt.no_armor ) {
		if( use_armor_filter( a ) ) {
		    afx = new_armor_context ();
		    push_armor_filter (afx, a);
		}
	    }
	    if( cmd == aListPackets ) {
		opt.list_packets=1;
		set_packet_list_mode(1);
	    }
	    rc = proc_packets (ctrl, NULL, a );
	    if( rc )
              {
                write_status_failure ("-", rc);
                log_error ("processing message failed: %s\n",
                           gpg_strerror (rc));
              }
	    iobuf_close(a);
	}
	break;
      }

    /* cleanup */
    gpg_deinit_default_ctrl (ctrl);
    xfree (ctrl);
    release_armor_context (afx);
    FREE_STRLIST(remusr);
    FREE_STRLIST(locusr);
    g10_exit(0);
    return 8; /*NEVER REACHED*/
}


/* Note: This function is used by signal handlers!. */
static void
emergency_cleanup (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM );
}


void
g10_exit( int rc )
{
  /* If we had an error but not printed an error message, do it now.
   * Note that write_status_failure will never print a second failure
   * status line. */
  if (rc)
    write_status_failure ("gpg-exit", gpg_error (GPG_ERR_GENERAL));

  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE);
  if (DBG_CLOCK)
    log_clock ("stop");

  if ( (opt.debug & DBG_MEMSTAT_VALUE) )
    {
      keydb_dump_stats ();
      sig_check_dump_stats ();
      gcry_control (GCRYCTL_DUMP_MEMORY_STATS);
      gcry_control (GCRYCTL_DUMP_RANDOM_STATS);
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );

  emergency_cleanup ();

  rc = rc? rc : log_get_errorcount(0)? 2 : g10_errors_seen? 1 : 0;
  exit (rc);
}


/* Pretty-print hex hashes.  This assumes at least an 80-character
   display, but there are a few other similar assumptions in the
   display code. */
static void
print_hex (gcry_md_hd_t md, int algo, const char *fname)
{
  int i,n,count,indent=0;
  const byte *p;

  if (fname)
    indent = es_printf("%s: ",fname);

  if (indent>40)
    {
      es_printf ("\n");
      indent=0;
    }

  if (algo==DIGEST_ALGO_RMD160)
    indent += es_printf("RMD160 = ");
  else if (algo>0)
    indent += es_printf("%6s = ", gcry_md_algo_name (algo));
  else
    algo = abs(algo);

  count = indent;

  p = gcry_md_read (md, algo);
  n = gcry_md_get_algo_dlen (algo);

  count += es_printf ("%02X",*p++);

  for(i=1;i<n;i++,p++)
    {
      if(n==16)
	{
	  if(count+2>79)
	    {
	      es_printf ("\n%*s",indent," ");
	      count = indent;
	    }
	  else
	    count += es_printf(" ");

	  if (!(i%8))
	    count += es_printf(" ");
	}
      else if (n==20)
	{
	  if(!(i%2))
	    {
	      if(count+4>79)
		{
		  es_printf ("\n%*s",indent," ");
		  count=indent;
		}
	      else
		count += es_printf(" ");
	    }

	  if (!(i%10))
	    count += es_printf(" ");
	}
      else
	{
	  if(!(i%4))
	    {
	      if (count+8>79)
		{
		  es_printf ("\n%*s",indent," ");
		  count=indent;
		}
	      else
		count += es_printf(" ");
	    }
	}

      count += es_printf("%02X",*p);
    }

  es_printf ("\n");
}

static void
print_hashline( gcry_md_hd_t md, int algo, const char *fname )
{
  int i, n;
  const byte *p;

  if ( fname )
    {
      for (p = fname; *p; p++ )
        {
          if ( *p <= 32 || *p > 127 || *p == ':' || *p == '%' )
            es_printf ("%%%02X", *p );
          else
            es_putc (*p, es_stdout);
        }
    }
  es_putc (':', es_stdout);
  es_printf ("%d:", algo);
  p = gcry_md_read (md, algo);
  n = gcry_md_get_algo_dlen (algo);
  for(i=0; i < n ; i++, p++ )
    es_printf ("%02X", *p);
  es_fputs (":\n", es_stdout);
}


static void
print_mds( const char *fname, int algo )
{
  estream_t fp;
  char buf[1024];
  size_t n;
  gcry_md_hd_t md;

  if (!fname)
    {
      fp = es_stdin;
      es_set_binary (fp);
    }
  else
    {
      fp = es_fopen (fname, "rb" );
      if (fp && is_secured_file (es_fileno (fp)))
        {
          es_fclose (fp);
          fp = NULL;
          gpg_err_set_errno (EPERM);
        }
    }
  if (!fp)
    {
      log_error("%s: %s\n", fname?fname:"[stdin]", strerror(errno) );
      return;
    }

  gcry_md_open (&md, 0, 0);
  if (algo)
    gcry_md_enable (md, algo);
  else
    {
      if (!gcry_md_test_algo (GCRY_MD_MD5))
        gcry_md_enable (md, GCRY_MD_MD5);
      gcry_md_enable (md, GCRY_MD_SHA1);
      if (!gcry_md_test_algo (GCRY_MD_RMD160))
        gcry_md_enable (md, GCRY_MD_RMD160);
      if (!gcry_md_test_algo (GCRY_MD_SHA224))
        gcry_md_enable (md, GCRY_MD_SHA224);
      if (!gcry_md_test_algo (GCRY_MD_SHA256))
        gcry_md_enable (md, GCRY_MD_SHA256);
      if (!gcry_md_test_algo (GCRY_MD_SHA384))
        gcry_md_enable (md, GCRY_MD_SHA384);
      if (!gcry_md_test_algo (GCRY_MD_SHA512))
        gcry_md_enable (md, GCRY_MD_SHA512);
    }

  while ((n=es_fread (buf, 1, DIM(buf), fp)))
    gcry_md_write (md, buf, n);

  if (es_ferror(fp))
    log_error ("%s: %s\n", fname?fname:"[stdin]", strerror(errno));
  else
    {
      gcry_md_final (md);
      if (opt.with_colons)
        {
          if ( algo )
            print_hashline (md, algo, fname);
          else
            {
              if (!gcry_md_test_algo (GCRY_MD_MD5))
                print_hashline( md, GCRY_MD_MD5, fname );
              print_hashline( md, GCRY_MD_SHA1, fname );
              if (!gcry_md_test_algo (GCRY_MD_RMD160))
                print_hashline( md, GCRY_MD_RMD160, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA224))
                print_hashline (md, GCRY_MD_SHA224, fname);
              if (!gcry_md_test_algo (GCRY_MD_SHA256))
                print_hashline( md, GCRY_MD_SHA256, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA384))
                print_hashline ( md, GCRY_MD_SHA384, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA512))
                print_hashline ( md, GCRY_MD_SHA512, fname );
            }
        }
      else
        {
          if (algo)
            print_hex (md, -algo, fname);
          else
            {
              if (!gcry_md_test_algo (GCRY_MD_MD5))
                print_hex (md, GCRY_MD_MD5, fname);
              print_hex (md, GCRY_MD_SHA1, fname );
              if (!gcry_md_test_algo (GCRY_MD_RMD160))
                print_hex (md, GCRY_MD_RMD160, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA224))
                print_hex (md, GCRY_MD_SHA224, fname);
              if (!gcry_md_test_algo (GCRY_MD_SHA256))
                print_hex (md, GCRY_MD_SHA256, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA384))
                print_hex (md, GCRY_MD_SHA384, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA512))
                print_hex (md, GCRY_MD_SHA512, fname );
            }
        }
    }
  gcry_md_close (md);

  if (fp != es_stdin)
    es_fclose (fp);
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
  strlist_t sl;

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
  strlist_t sl;

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


static void
read_sessionkey_from_fd (int fd)
{
  int i, len;
  char *line;

  if (! gnupg_fd_valid (fd))
    log_fatal ("override-session-key-fd is invalid: %s\n", strerror (errno));

  for (line = NULL, i = len = 100; ; i++ )
    {
      if (i >= len-1 )
        {
          char *tmp = line;
          len += 100;
          line = xmalloc_secure (len);
          if (tmp)
            {
              memcpy (line, tmp, i);
              xfree (tmp);
            }
          else
            i=0;
	}
      if (read (fd, line + i, 1) != 1 || line[i] == '\n')
        break;
    }
  line[i] = 0;
  log_debug ("seskey: %s\n", line);
  gpgrt_annotate_leaked_object (line);
  opt.override_session_key = line;
}
