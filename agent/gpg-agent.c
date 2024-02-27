/* gpg-agent.c  -  The GnuPG Agent
 * Copyright (C) 2000-2020 Free Software Foundation, Inc.
 * Copyright (C) 2000-2019 Werner Koch
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
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_W32_SYSTEM
# ifndef WINVER
#  define WINVER 0x0500  /* Same as in common/sysutils.c */
# endif
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <aclapi.h>
# include <sddl.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/socket.h>
# include <sys/un.h>
#endif /*!HAVE_W32_SYSTEM*/
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <npth.h>

#define INCLUDED_BY_MAIN_MODULE 1
#define GNUPG_COMMON_NEED_AFLOCAL
#include "agent.h"
#include <assuan.h> /* Malloc hooks  and socket wrappers. */

#include "../common/i18n.h"
#include "../common/sysutils.h"
#include "../common/gc-opt-flags.h"
#include "../common/exechelp.h"
#include "../common/asshelp.h"
#include "../common/comopt.h"
#include "../common/init.h"


enum cmd_and_opt_values
{ aNull = 0,
  oCsh		  = 'c',
  oQuiet	  = 'q',
  oSh		  = 's',
  oVerbose	  = 'v',

  oNoVerbose = 500,
  aGPGConfList,
  aGPGConfTest,
  aUseStandardSocketP,
  oOptions,
  oDebug,
  oDebugAll,
  oDebugLevel,
  oDebugWait,
  oDebugQuickRandom,
  oDebugPinentry,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oGrab,
  oNoGrab,
  oLogFile,
  oServer,
  oDaemon,
  oSupervised,
  oBatch,

  oPinentryProgram,
  oPinentryTouchFile,
  oPinentryInvisibleChar,
  oPinentryTimeout,
  oPinentryFormattedPassphrase,
  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,
  oXauthority,
  oScdaemonProgram,
  oTpm2daemonProgram,
  oDefCacheTTL,
  oDefCacheTTLSSH,
  oMaxCacheTTL,
  oMaxCacheTTLSSH,
  oEnforcePassphraseConstraints,
  oMinPassphraseLen,
  oMinPassphraseNonalpha,
  oCheckPassphrasePattern,
  oCheckSymPassphrasePattern,
  oMaxPassphraseDays,
  oEnablePassphraseHistory,
  oStealSocket,
  oUseStandardSocket,
  oNoUseStandardSocket,
  oExtraSocket,
  oBrowserSocket,
  oFakedSystemTime,

  oIgnoreCacheForSigning,
  oAllowMarkTrusted,
  oNoAllowMarkTrusted,
  oNoUserTrustlist,
  oSysTrustlistName,
  oAllowPresetPassphrase,
  oAllowLoopbackPinentry,
  oNoAllowLoopbackPinentry,
  oNoAllowExternalCache,
  oAllowEmacsPinentry,
  oKeepTTY,
  oKeepDISPLAY,
  oSSHSupport,
  oSSHFingerprintDigest,
  oPuttySupport,
  oWin32OpenSSHSupport,
  oDisableScdaemon,
  oDisableCheckOwnSocket,
  oS2KCount,
  oS2KCalibration,
  oAutoExpandSecmem,
  oListenBacklog,
  oInactivityTimeout,

  oWriteEnvFile,

  oNoop
};


#ifndef ENAMETOOLONG
# define ENAMETOOLONG EINVAL
#endif

static gpgrt_opt_t opts[] = {

  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),
  ARGPARSE_c (aUseStandardSocketP, "use-standard-socket-p", "@"),


  ARGPARSE_header (NULL, N_("Options used for startup")),

  ARGPARSE_s_n (oDaemon,  "daemon", N_("run in daemon mode (background)")),
  ARGPARSE_s_n (oServer,  "server", N_("run in server mode (foreground)")),
#ifndef HAVE_W32_SYSTEM
  ARGPARSE_s_n (oSupervised,  "supervised", "@"),
#endif
  ARGPARSE_s_n (oNoDetach,  "no-detach", N_("do not detach from the console")),
  ARGPARSE_s_n (oSh,	  "sh",        N_("sh-style command output")),
  ARGPARSE_s_n (oCsh,	  "csh",       N_("csh-style command output")),
  ARGPARSE_s_n (oStealSocket, "steal-socket", "@"),
  ARGPARSE_s_s (oDisplay,    "display",     "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname",     "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype",     "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",    "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages", "@"),
  ARGPARSE_s_s (oXauthority, "xauthority",  "@"),
  ARGPARSE_s_s (oHomedir,    "homedir",      "@"),
  ARGPARSE_conffile (oOptions, "options", N_("|FILE|read options from FILE")),
  ARGPARSE_noconffile (oNoOptions, "no-options", "@"),
  ARGPARSE_s_i (oInactivityTimeout, "inactivity-timeout", "@"),

  ARGPARSE_header ("Monitor", N_("Options controlling the diagnostic output")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	  "quiet",     N_("be somewhat more quiet")),
  ARGPARSE_s_s (oDebug,	     "debug",       "@"),
  ARGPARSE_s_n (oDebugAll,   "debug-all",   "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level", "@"),
  ARGPARSE_s_i (oDebugWait,  "debug-wait",  "@"),
  ARGPARSE_s_n (oDebugQuickRandom, "debug-quick-random", "@"),
  ARGPARSE_s_n (oDebugPinentry, "debug-pinentry", "@"),
  ARGPARSE_s_s (oLogFile,   "log-file",
                /* */       N_("|FILE|write server mode logs to FILE")),


  ARGPARSE_header ("Configuration",
                   N_("Options controlling the configuration")),

  ARGPARSE_s_n (oDisableScdaemon, "disable-scdaemon",
                /* */             N_("do not use the SCdaemon") ),
  ARGPARSE_s_s (oScdaemonProgram, "scdaemon-program",
                /* */             N_("|PGM|use PGM as the SCdaemon program") ),
  ARGPARSE_s_s (oTpm2daemonProgram, "tpm2daemon-program",
		/* */             N_("|PGM|use PGM as the tpm2daemon program") ),
  ARGPARSE_s_n (oDisableCheckOwnSocket, "disable-check-own-socket", "@"),

  ARGPARSE_s_s (oExtraSocket, "extra-socket",
                /* */       N_("|NAME|accept some commands via NAME")),

  ARGPARSE_s_s (oBrowserSocket, "browser-socket", "@"),
  ARGPARSE_s_n (oKeepTTY,    "keep-tty",
                /* */        N_("ignore requests to change the TTY")),
  ARGPARSE_s_n (oKeepDISPLAY, "keep-display",
                /* */        N_("ignore requests to change the X display")),
  ARGPARSE_s_n (oSSHSupport,   "enable-ssh-support", N_("enable ssh support")),
  ARGPARSE_s_s (oSSHFingerprintDigest, "ssh-fingerprint-digest",
                N_("|ALGO|use ALGO to show ssh fingerprints")),
  ARGPARSE_s_n (oPuttySupport, "enable-putty-support",
#ifdef HAVE_W32_SYSTEM
                /* */           N_("enable putty support")
#else
                /* */           "@"
#endif
                ),
  ARGPARSE_o_s (oWin32OpenSSHSupport, "enable-win32-openssh-support",
#ifdef HAVE_W32_SYSTEM
                /* */           N_("enable Win32-OpenSSH support")
#else
                /* */           "@"
#endif
                ),
  ARGPARSE_s_i (oListenBacklog, "listen-backlog", "@"),
  ARGPARSE_op_u (oAutoExpandSecmem, "auto-expand-secmem", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),


  ARGPARSE_header ("Security", N_("Options controlling the security")),

  ARGPARSE_s_u (oDefCacheTTL,    "default-cache-ttl",
                                 N_("|N|expire cached PINs after N seconds")),
  ARGPARSE_s_u (oDefCacheTTLSSH, "default-cache-ttl-ssh",
                /* */            N_("|N|expire SSH keys after N seconds")),
  ARGPARSE_s_u (oMaxCacheTTL,    "max-cache-ttl",
                /* */     N_("|N|set maximum PIN cache lifetime to N seconds")),
  ARGPARSE_s_u (oMaxCacheTTLSSH, "max-cache-ttl-ssh",
                /* */     N_("|N|set maximum SSH key lifetime to N seconds")),
  ARGPARSE_s_n (oIgnoreCacheForSigning, "ignore-cache-for-signing",
                /* */    N_("do not use the PIN cache when signing")),
  ARGPARSE_s_n (oNoAllowExternalCache,  "no-allow-external-cache",
                /* */    N_("disallow the use of an external password cache")),
  ARGPARSE_s_n (oNoAllowMarkTrusted, "no-allow-mark-trusted",
                /* */    N_("disallow clients to mark keys as \"trusted\"")),
  ARGPARSE_s_n (oAllowMarkTrusted,   "allow-mark-trusted", "@"),
  ARGPARSE_s_n (oNoUserTrustlist,    "no-user-trustlist", "@"),
  ARGPARSE_s_s (oSysTrustlistName,   "sys-trustlist-name", "@"),
  ARGPARSE_s_n (oAllowPresetPassphrase, "allow-preset-passphrase",
                /* */                    N_("allow presetting passphrase")),
  ARGPARSE_s_u (oS2KCount, "s2k-count", "@"),
  ARGPARSE_s_u (oS2KCalibration, "s2k-calibration", "@"),

  ARGPARSE_header ("Passphrase policy",
                   N_("Options enforcing a passphrase policy")),

  ARGPARSE_s_n (oEnforcePassphraseConstraints, "enforce-passphrase-constraints",
                N_("do not allow bypassing the passphrase policy")),
  ARGPARSE_s_u (oMinPassphraseLen,        "min-passphrase-len",
                N_("|N|set minimal required length for new passphrases to N")),
  ARGPARSE_s_u (oMinPassphraseNonalpha,   "min-passphrase-nonalpha",
                N_("|N|require at least N non-alpha"
                   " characters for a new passphrase")),
  ARGPARSE_s_s (oCheckPassphrasePattern,  "check-passphrase-pattern",
                N_("|FILE|check new passphrases against pattern in FILE")),
  ARGPARSE_s_s (oCheckSymPassphrasePattern,  "check-sym-passphrase-pattern",
                "@"),
  ARGPARSE_s_u (oMaxPassphraseDays,       "max-passphrase-days",
                N_("|N|expire the passphrase after N days")),
  ARGPARSE_s_n (oEnablePassphraseHistory, "enable-passphrase-history",
                N_("do not allow the reuse of old passphrases")),


  ARGPARSE_header ("Pinentry", N_("Options controlling the PIN-Entry")),

  ARGPARSE_s_n (oBatch,  "batch",  N_("never use the PIN-entry")),
  ARGPARSE_s_n (oNoAllowLoopbackPinentry, "no-allow-loopback-pinentry",
                N_("disallow caller to override the pinentry")),
  ARGPARSE_s_n (oAllowLoopbackPinentry, "allow-loopback-pinentry", "@"),
  ARGPARSE_s_n (oGrab,   "grab",   N_("let PIN-Entry grab keyboard and mouse")),
  ARGPARSE_s_n (oNoGrab, "no-grab",   "@"),
  ARGPARSE_s_s (oPinentryProgram, "pinentry-program",
                N_("|PGM|use PGM as the PIN-Entry program")),
  ARGPARSE_s_s (oPinentryTouchFile, "pinentry-touch-file", "@"),
  ARGPARSE_s_s (oPinentryInvisibleChar, "pinentry-invisible-char", "@"),
  ARGPARSE_s_u (oPinentryTimeout, "pinentry-timeout",
                N_("|N|set the Pinentry timeout to N seconds")),
  ARGPARSE_s_n (oPinentryFormattedPassphrase, "pinentry-formatted-passphrase",
                "@"),
  ARGPARSE_s_n (oAllowEmacsPinentry,  "allow-emacs-pinentry",
                N_("allow passphrase to be prompted through Emacs")),


  /* Dummy options for backward compatibility.  */
  ARGPARSE_o_s (oWriteEnvFile, "write-env-file", "@"),
  ARGPARSE_s_n (oUseStandardSocket, "use-standard-socket", "@"),
  ARGPARSE_s_n (oNoUseStandardSocket, "no-use-standard-socket", "@"),

  /* Dummy options.  */
  ARGPARSE_s_n (oNoop, "disable-extended-key-format", "@"),
  ARGPARSE_s_n (oNoop, "enable-extended-key-format", "@"),

  ARGPARSE_end () /* End of list */
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_IPC_VALUE    , "ipc"     },
    { 77, NULL } /* 77 := Do not exit on "help" or "?".  */
  };



#define DEFAULT_CACHE_TTL     (10*60)  /* 10 minutes */
#define DEFAULT_CACHE_TTL_SSH (30*60)  /* 30 minutes */
#define MAX_CACHE_TTL         (120*60) /* 2 hours */
#define MAX_CACHE_TTL_SSH     (120*60) /* 2 hours */
#define MIN_PASSPHRASE_LEN    (8)
#define MIN_PASSPHRASE_NONALPHA (1)
#define MAX_PASSPHRASE_DAYS   (0)

/* The timer tick used for housekeeping stuff.  Note that on Windows
 * we use a SetWaitableTimer seems to signal earlier than about 2
 * seconds.  Thus we use 4 seconds on all platforms.
 * CHECK_OWN_SOCKET_INTERVAL defines how often we check
 * our own socket in standard socket mode.  If that value is 0 we
 * don't check at all.  All values are in seconds. */
#define TIMERTICK_INTERVAL          (4)
#define CHECK_OWN_SOCKET_INTERVAL  (60)


/* Flag indicating that the ssh-agent subsystem has been enabled.  */
static int ssh_support;

#ifdef HAVE_W32_SYSTEM
/* Flag indicating that support for Putty has been enabled.  */
static int putty_support;
/* A magic value used with WM_COPYDATA.  */
#define PUTTY_IPC_MAGIC 0x804e50ba
/* To avoid surprises we limit the size of the mapped IPC file to this
   value.  Putty currently (0.62) uses 8k, thus 16k should be enough
   for the foreseeable future.  */
#define PUTTY_IPC_MAXLEN 16384

/* Path to the pipe, which handles requests from Win32-OpenSSH.  */
static const char *win32_openssh_support;
#define W32_DEFAULT_AGENT_PIPE_NAME "\\\\.\\pipe\\openssh-ssh-agent"
#endif /*HAVE_W32_SYSTEM*/

/* The list of open file descriptors at startup.  Note that this list
 * has been allocated using the standard malloc.  */
#ifndef HAVE_W32_SYSTEM
static int *startup_fd_list;
#endif

/* The signal mask at startup and a flag telling whether it is valid.  */
#ifdef HAVE_SIGPROCMASK
static sigset_t startup_signal_mask;
static int startup_signal_mask_valid;
#endif

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* Counter for the currently running own socket checks.  */
static int check_own_socket_running;

/* Flags to indicate that check_own_socket shall not be called.  */
static int disable_check_own_socket;

/* Flag indicating that we are in supervised mode.  */
static int is_supervised;

/* Flag indicating to start the daemon even if one already runs.  */
static int steal_socket;

/* Flag to inhibit socket removal in cleanup.  */
static int inhibit_socket_removal;

/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Name of the communication socket used for native gpg-agent
   requests. The second variable is either NULL or a malloced string
   with the real socket name in case it has been redirected.  */
static char *socket_name;
static char *redir_socket_name;

/* Name of the optional extra socket used for native gpg-agent requests.  */
static char *socket_name_extra;
static char *redir_socket_name_extra;

/* Name of the optional browser socket used for native gpg-agent requests.  */
static char *socket_name_browser;
static char *redir_socket_name_browser;

/* Name of the communication socket used for ssh-agent protocol.  */
static char *socket_name_ssh;
static char *redir_socket_name_ssh;

/* We need to keep track of the server's nonces (these are dummies for
   POSIX systems). */
static assuan_sock_nonce_t socket_nonce;
static assuan_sock_nonce_t socket_nonce_extra;
static assuan_sock_nonce_t socket_nonce_browser;
static assuan_sock_nonce_t socket_nonce_ssh;

/* Value for the listen() backlog argument.  We use the same value for
 * all sockets - 64 is on current Linux half of the default maximum.
 * Let's try this as default.  Change at runtime with --listen-backlog.  */
static int listen_backlog = 64;

/* Default values for options passed to the pinentry. */
static char *default_display;
static char *default_ttyname;
static char *default_ttytype;
static char *default_lc_ctype;
static char *default_lc_messages;
static char *default_xauthority;

/* Name of a config file which was last read on startup or if missing
 * the name of the standard config file.  Any value here enabled the
 * rereading of the standard config files on SIGHUP. */
static char *config_filename;

/* Helper to implement --debug-level */
static const char *debug_level;

/* Keep track of the current log file so that we can avoid updating
   the log file after a SIGHUP if it didn't changed. Malloced. */
static char *current_logfile;

/* The handle_tick() function may test whether a parent is still
 * running.  We record the PID of the parent here or -1 if it should
 * be watched.  */
static pid_t parent_pid = (pid_t)(-1);

/* This flag is true if the inotify mechanism for detecting the
 * removal of the homedir is active.  This flag is used to disable the
 * alternative but portable stat based check.  */
static int have_homedir_inotify;

/* Depending on how gpg-agent was started, the homedir inotify watch
 * may not be reliable.  This flag is set if we assume that inotify
 * works reliable.  */
static int reliable_homedir_inotify;

/* Number of active connections.  */
static int active_connections;

/* This object is used to dispatch progress messages from Libgcrypt to
 * the right thread.  Given that we will have at max only a few dozen
 * connections at a time, using a linked list is the easiest way to
 * handle this. */
struct progress_dispatch_s
{
  struct progress_dispatch_s *next;
  /* The control object of the connection.  If this is NULL no
   * connection is associated with this item and it is free for reuse
   * by new connections.  */
  ctrl_t ctrl;

  /* The thread id of (npth_self) of the connection.  */
  npth_t tid;

  /* The callback set by the connection.  This is similar to the
   * Libgcrypt callback but with the control object passed as the
   * first argument.  */
  void (*cb)(ctrl_t ctrl,
             const char *what, int printchar,
             int current, int total);
};
struct progress_dispatch_s *progress_dispatch_list;




/*
   Local prototypes.
 */

static char *create_socket_name (char *standard_name, int with_homedir);
static gnupg_fd_t create_server_socket (char *name, int primary, int cygwin,
                                        char **r_redir_name,
                                        assuan_sock_nonce_t *nonce);
static void create_directories (void);

static void agent_libgcrypt_progress_cb (void *data, const char *what,
                                         int printchar,
                                         int current, int total);
static void agent_init_default_ctrl (ctrl_t ctrl);
static void agent_deinit_default_ctrl (ctrl_t ctrl);

static void handle_connections (gnupg_fd_t listen_fd,
                                gnupg_fd_t listen_fd_extra,
                                gnupg_fd_t listen_fd_browser,
                                gnupg_fd_t listen_fd_ssh);
static void check_own_socket (void);
static int check_for_running_agent (int silent);

/* Pth wrapper function definitions. */
ASSUAN_SYSTEM_NPTH_IMPL;


/*
   Functions.
 */

/* Allocate a string describing a library version by calling a GETFNC.
   This function is expected to be called only once.  GETFNC is
   expected to have a semantic like gcry_check_version ().  */
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

/* Return strings describing this program.  The case values are
   described in common/argparse.c:strusage.  The values here override
   the default values given by strusage.  */
static const char *
my_strusage (int level)
{
  static char *ver_gcry;
  const char *p;

  switch (level)
    {
    case  9: p = "GPL-3.0-or-later"; break;
    case 11: p = "@GPG_AGENT@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 14: p = GNUPG_DEF_COPYRIGHT_LINE; break;
    case 17: p = PRINTABLE_OS_NAME; break;
      /* TRANSLATORS: @EMAIL@ will get replaced by the actual bug
         reporting address.  This is so that we can change the
         reporting address without breaking the translations.  */
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;

    case 1:
    case 40: p =  _("Usage: @GPG_AGENT@ [options] (-h for help)");
      break;
    case 41: p =  _("Syntax: @GPG_AGENT@ [options] [command [args]]\n"
                    "Secret key management for @GNUPG@\n");
    break;

    default: p = NULL;
    }
  return p;
}



/* Setup the debugging.  With the global variable DEBUG_LEVEL set to NULL
   only the active debug flags are propagated to the subsystems.  With
   DEBUG_LEVEL set, a specific set of debug flags is set; thus overriding
   all flags already set. Note that we don't fail here, because it is
   important to keep gpg-agent running even after re-reading the
   options due to a SIGHUP. */
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
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp (debug_level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE | DBG_CACHE_VALUE);
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
      opt.debug = 0; /* Reset debugging, so that prior debug
                        statements won't have an undesired effect. */
    }

  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug && opt.quiet)
    opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}


/* Helper for cleanup to remove one socket with NAME.  REDIR_NAME is
   the corresponding real name if the socket has been redirected.  */
static void
remove_socket (char *name, char *redir_name)
{
  if (name && *name)
    {
      if (redir_name)
        name = redir_name;

      gnupg_remove (name);
      *name = 0;
    }
}


/* Discover which inherited file descriptors correspond to which
 * services/sockets offered by gpg-agent, using the LISTEN_FDS and
 * LISTEN_FDNAMES convention.  The understood labels are "ssh",
 * "extra", and "browser".  "std" or other labels will be interpreted
 * as the standard socket.
 *
 * This function is designed to log errors when the expected file
 * descriptors don't make sense, but to do its best to continue to
 * work even in the face of minor misconfigurations.
 *
 * For more information on the LISTEN_FDS convention, see
 * sd_listen_fds(3) on certain Linux distributions.
 */
#ifndef HAVE_W32_SYSTEM
static void
map_supervised_sockets (gnupg_fd_t *r_fd,
                        gnupg_fd_t *r_fd_extra,
                        gnupg_fd_t *r_fd_browser,
                        gnupg_fd_t *r_fd_ssh)
{
  struct {
    const char *label;
    int **fdaddr;
    char **nameaddr;
  } tbl[] = {
    { "ssh",     &r_fd_ssh,     &socket_name_ssh },
    { "browser", &r_fd_browser, &socket_name_browser },
    { "extra",   &r_fd_extra,   &socket_name_extra },
    { "std",     &r_fd,         &socket_name }  /* (Must be the last item.)  */
  };
  const char *envvar;
  char **fdnames;
  int nfdnames;
  int fd_count;

  *r_fd = *r_fd_extra = *r_fd_browser = *r_fd_ssh = -1;

  /* Print a warning if LISTEN_PID does not match outr pid.  */
  envvar = getenv ("LISTEN_PID");
  if (!envvar)
    log_error ("no LISTEN_PID environment variable found in "
               "--supervised mode (ignoring)\n");
  else if (strtoul (envvar, NULL, 10) != (unsigned long)getpid ())
    log_error ("environment variable LISTEN_PID (%lu) does not match"
               " our pid (%lu) in --supervised mode (ignoring)\n",
               (unsigned long)strtoul (envvar, NULL, 10),
               (unsigned long)getpid ());

  /* Parse LISTEN_FDNAMES into the array FDNAMES.  */
  envvar = getenv ("LISTEN_FDNAMES");
  if (envvar)
    {
      fdnames = strtokenize (envvar, ":");
      if (!fdnames)
        {
          log_error ("strtokenize failed: %s\n",
                     gpg_strerror (gpg_error_from_syserror ()));
          agent_exit (1);
        }
      for (nfdnames=0; fdnames[nfdnames]; nfdnames++)
        ;
    }
  else
    {
      fdnames = NULL;
      nfdnames = 0;
    }

  /* Parse LISTEN_FDS into fd_count or provide a replacement.  */
  envvar = getenv ("LISTEN_FDS");
  if (envvar)
    fd_count = atoi (envvar);
  else if (fdnames)
    {
      log_error ("no LISTEN_FDS environment variable found in --supervised"
                 " mode (relying on LISTEN_FDNAMES instead)\n");
      fd_count = nfdnames;
    }
  else
    {
      log_error ("no LISTEN_FDS or LISTEN_FDNAMES environment variables "
                "found in --supervised mode"
                " (assuming 1 active descriptor)\n");
      fd_count = 1;
    }

  if (fd_count < 1)
    {
      log_error ("--supervised mode expects at least one file descriptor"
                 " (was told %d, carrying on as though it were 1)\n",
                 fd_count);
      fd_count = 1;
    }

  /* Assign the descriptors to the return values.  */
  if (!fdnames)
    {
      struct stat statbuf;

      if (fd_count != 1)
        log_error ("no LISTEN_FDNAMES and LISTEN_FDS (%d) != 1"
                   " in --supervised mode."
                   " (ignoring all sockets but the first one)\n",
                   fd_count);
      if (fstat (3, &statbuf) == -1 && errno ==EBADF)
        log_fatal ("file descriptor 3 must be valid in --supervised mode"
                   " if LISTEN_FDNAMES is not set\n");
      *r_fd = 3;
      socket_name = gnupg_get_socket_name (3);
    }
  else if (fd_count != nfdnames)
    {
      log_fatal ("number of items in LISTEN_FDNAMES (%d) does not match "
                 "LISTEN_FDS (%d) in --supervised mode\n",
                 nfdnames, fd_count);
    }
  else
    {
      int i, j, fd;
      char *name;

      for (i = 0; i < nfdnames; i++)
        {
          for (j = 0; j < DIM (tbl); j++)
            {
              if (!strcmp (fdnames[i], tbl[j].label) || j == DIM(tbl)-1)
                {
                  fd = 3 + i;
                  if (**tbl[j].fdaddr == -1)
                    {
                      name = gnupg_get_socket_name (fd);
                      if (name)
                        {
                          **tbl[j].fdaddr = fd;
                          *tbl[j].nameaddr = name;
                          log_info ("using fd %d for %s socket (%s)\n",
                                    fd, tbl[j].label, name);
                        }
                      else
                        {
                          log_error ("cannot listen on fd %d for %s socket\n",
                                     fd, tbl[j].label);
                          close (fd);
                        }
                    }
                  else
                    {
                      log_error ("cannot listen on more than one %s socket\n",
                                 tbl[j].label);
                      close (fd);
                    }
                  break;
                }
            }
        }
    }

  xfree (fdnames);
}
#endif /*!HAVE_W32_SYSTEM*/


/* Cleanup code for this program.  This is either called has an atexit
   handler or directly.  */
static void
cleanup (void)
{
  static int done;

  if (done)
    return;
  done = 1;
  deinitialize_module_cache ();
  if (!is_supervised && !inhibit_socket_removal)
    {
      remove_socket (socket_name, redir_socket_name);
      if (opt.extra_socket > 1)
        remove_socket (socket_name_extra, redir_socket_name_extra);
      if (opt.browser_socket > 1)
        remove_socket (socket_name_browser, redir_socket_name_browser);
      remove_socket (socket_name_ssh, redir_socket_name_ssh);
    }
}



/* Handle options which are allowed to be reset after program start.
   Return true when the current option in PARGS could be handled and
   false if not.  As a special feature, passing a value of NULL for
   PARGS, resets the options to the default.  REREAD should be set
   true if it is not the initial option parsing. */
static int
parse_rereadable_options (gpgrt_argparse_t *pargs, int reread)
{
  int i;

  if (!pargs)
    { /* reset mode */
      opt.quiet = 0;
      opt.verbose = 0;
      opt.debug = 0;
      opt.no_grab = 1;
      opt.debug_pinentry = 0;
      xfree (opt.pinentry_program);
      opt.pinentry_program = NULL;
      opt.pinentry_touch_file = NULL;
      xfree (opt.pinentry_invisible_char);
      opt.pinentry_invisible_char = NULL;
      opt.pinentry_timeout = 0;
      opt.pinentry_formatted_passphrase = 0;
      memset (opt.daemon_program, 0, sizeof opt.daemon_program);
      opt.def_cache_ttl = DEFAULT_CACHE_TTL;
      opt.def_cache_ttl_ssh = DEFAULT_CACHE_TTL_SSH;
      opt.max_cache_ttl = MAX_CACHE_TTL;
      opt.max_cache_ttl_ssh = MAX_CACHE_TTL_SSH;
      opt.enforce_passphrase_constraints = 0;
      opt.min_passphrase_len = MIN_PASSPHRASE_LEN;
      opt.min_passphrase_nonalpha = MIN_PASSPHRASE_NONALPHA;
      opt.check_passphrase_pattern = NULL;
      opt.check_sym_passphrase_pattern = NULL;
      opt.max_passphrase_days = MAX_PASSPHRASE_DAYS;
      opt.enable_passphrase_history = 0;
      opt.ignore_cache_for_signing = 0;
      opt.allow_mark_trusted = 1;
      opt.sys_trustlist_name = NULL;
      opt.allow_external_cache = 1;
      opt.allow_loopback_pinentry = 1;
      opt.allow_emacs_pinentry = 0;
      memset (opt.disable_daemon, 0, sizeof opt.disable_daemon);
      disable_check_own_socket = 0;
      /* Note: When changing the next line, change also gpgconf_list.  */
      opt.ssh_fingerprint_digest = GCRY_MD_SHA256;
      opt.s2k_count = 0;
      set_s2k_calibration_time (0);  /* Set to default.  */
      return 1;
    }

  switch (pargs->r_opt)
    {
    case oQuiet: opt.quiet = 1; break;
    case oVerbose: opt.verbose++; break;

    case oDebug:
      parse_debug_flag (pargs->r.ret_str, &opt.debug, debug_flags);
      break;
    case oDebugAll: opt.debug = ~0; break;
    case oDebugLevel: debug_level = pargs->r.ret_str; break;
    case oDebugPinentry: opt.debug_pinentry = 1; break;

    case oLogFile:
      if (!reread)
        return 0; /* not handled */
      if (!current_logfile || !pargs->r.ret_str
          || strcmp (current_logfile, pargs->r.ret_str))
        {
          log_set_file (pargs->r.ret_str);
          xfree (current_logfile);
          current_logfile = xtrystrdup (pargs->r.ret_str);
        }
      break;

    case oNoGrab: opt.no_grab |= 1; break;
    case oGrab: opt.no_grab |= 2; break;

    case oPinentryProgram:
      xfree (opt.pinentry_program);
      opt.pinentry_program = make_filename_try (pargs->r.ret_str, NULL);
      break;
    case oPinentryTouchFile: opt.pinentry_touch_file = pargs->r.ret_str; break;
    case oPinentryInvisibleChar:
      xfree (opt.pinentry_invisible_char);
      opt.pinentry_invisible_char = xtrystrdup (pargs->r.ret_str); break;
      break;
    case oPinentryTimeout: opt.pinentry_timeout = pargs->r.ret_ulong; break;
    case oPinentryFormattedPassphrase:
      opt.pinentry_formatted_passphrase = 1;
      break;

    case oTpm2daemonProgram:
      opt.daemon_program[DAEMON_TPM2D] = pargs->r.ret_str;
      break;

    case oScdaemonProgram:
      opt.daemon_program[DAEMON_SCD] = pargs->r.ret_str;
      break;
    case oDisableScdaemon: opt.disable_daemon[DAEMON_SCD] = 1; break;
    case oDisableCheckOwnSocket: disable_check_own_socket = 1; break;

    case oDefCacheTTL: opt.def_cache_ttl = pargs->r.ret_ulong; break;
    case oDefCacheTTLSSH: opt.def_cache_ttl_ssh = pargs->r.ret_ulong; break;
    case oMaxCacheTTL: opt.max_cache_ttl = pargs->r.ret_ulong; break;
    case oMaxCacheTTLSSH: opt.max_cache_ttl_ssh = pargs->r.ret_ulong; break;

    case oEnforcePassphraseConstraints:
      opt.enforce_passphrase_constraints=1;
      break;
    case oMinPassphraseLen: opt.min_passphrase_len = pargs->r.ret_ulong; break;
    case oMinPassphraseNonalpha:
      opt.min_passphrase_nonalpha = pargs->r.ret_ulong;
      break;
    case oCheckPassphrasePattern:
      opt.check_passphrase_pattern = pargs->r.ret_str;
      break;
    case oCheckSymPassphrasePattern:
      opt.check_sym_passphrase_pattern = pargs->r.ret_str;
      break;
    case oMaxPassphraseDays:
      opt.max_passphrase_days = pargs->r.ret_ulong;
      break;
    case oEnablePassphraseHistory:
      opt.enable_passphrase_history = 1;
      break;

    case oIgnoreCacheForSigning: opt.ignore_cache_for_signing = 1; break;

    case oAllowMarkTrusted: opt.allow_mark_trusted = 1; break;
    case oNoAllowMarkTrusted: opt.allow_mark_trusted = 0; break;
    case oNoUserTrustlist: opt.no_user_trustlist = 1; break;
    case oSysTrustlistName: opt.sys_trustlist_name = pargs->r.ret_str; break;

    case oAllowPresetPassphrase: opt.allow_preset_passphrase = 1; break;

    case oAllowLoopbackPinentry: opt.allow_loopback_pinentry = 1; break;
    case oNoAllowLoopbackPinentry: opt.allow_loopback_pinentry = 0; break;

    case oNoAllowExternalCache: opt.allow_external_cache = 0;
      break;

    case oAllowEmacsPinentry: opt.allow_emacs_pinentry = 1;
      break;

    case oSSHFingerprintDigest:
      i = gcry_md_map_name (pargs->r.ret_str);
      if (!i)
        log_error (_("selected digest algorithm is invalid\n"));
      else
        opt.ssh_fingerprint_digest = i;
      break;

    case oS2KCount:
      opt.s2k_count = pargs->r.ret_ulong;
      break;

    case oS2KCalibration:
      set_s2k_calibration_time (pargs->r.ret_ulong);
      break;

    case oNoop: break;

    default:
      return 0; /* not handled */
    }

  return 1; /* handled */
}


/* Fixup some options after all have been processed.  */
static void
finalize_rereadable_options (void)
{
  /* Hack to allow --grab to override --no-grab.  */
  if ((opt.no_grab & 2))
    opt.no_grab = 0;

  /* With --no-user-trustlist it does not make sense to allow the mark
   * trusted feature.  */
  if (opt.no_user_trustlist)
    opt.allow_mark_trusted = 0;
}


static void
thread_init_once (void)
{
  static int npth_initialized = 0;

  if (!npth_initialized)
    {
      npth_initialized++;
      npth_init ();
    }
  gpgrt_set_syscall_clamp (npth_unprotect, npth_protect);
  /* Now that we have set the syscall clamp we need to tell Libgcrypt
   * that it should get them from libgpg-error.  Note that Libgcrypt
   * has already been initialized but at that point nPth was not
   * initialized and thus Libgcrypt could not set its system call
   * clamp.  */
  gcry_control (GCRYCTL_REINIT_SYSCALL_CLAMP, 0, 0);
}


static void
initialize_modules (void)
{
  thread_init_once ();
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  initialize_module_cache ();
  initialize_module_call_pinentry ();
  initialize_module_daemon ();
  initialize_module_trustlist ();
}


/* The main entry point.  */
int
main (int argc, char **argv)
{
  gpgrt_argparse_t pargs;
  int orig_argc;
  char **orig_argv;
  char *last_configname = NULL;
  const char *configname = NULL;
  int debug_argparser = 0;
  const char *shell;
  int pipe_server = 0;
  int is_daemon = 0;
  int nodetach = 0;
  int csh_style = 0;
  char *logfile = NULL;
  int debug_wait = 0;
  int gpgconf_list = 0;
  gpg_error_t err;
  struct assuan_malloc_hooks malloc_hooks;

  early_system_init ();

  /* Before we do anything else we save the list of currently open
     file descriptors and the signal mask.  This info is required to
     do the exec call properly.  We don't need it on Windows.  */
#ifndef HAVE_W32_SYSTEM
  startup_fd_list = get_all_open_fds ();
#endif /*!HAVE_W32_SYSTEM*/
#ifdef HAVE_SIGPROCMASK
  if (!sigprocmask (SIG_UNBLOCK, NULL, &startup_signal_mask))
    startup_signal_mask_valid = 1;
#endif /*HAVE_SIGPROCMASK*/

  /* Set program name etc.  */
  gpgrt_set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix (GPG_AGENT_NAME, GPGRT_LOG_WITH_PREFIX|GPGRT_LOG_WITH_PID);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks (&malloc_hooks);
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  assuan_sock_init ();
  assuan_sock_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  setup_libassuan_logging (&opt.debug, NULL);

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);
  gcry_set_progress_handler (agent_libgcrypt_progress_cb, NULL);

  disable_core_dumps ();

  /* Set default options.  */
  parse_rereadable_options (NULL, 0); /* Reset them to default values. */

  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;

  /* Record some of the original environment strings. */
  {
    const char *s;
    int idx;
    static const char *names[] =
      { "DISPLAY", "TERM", "XAUTHORITY", "PINENTRY_USER_DATA", NULL };

    err = 0;
    opt.startup_env = session_env_new ();
    if (!opt.startup_env)
      err = gpg_error_from_syserror ();
    for (idx=0; !err && names[idx]; idx++)
      {
        s = getenv (names[idx]);
        if (s)
          err = session_env_setenv (opt.startup_env, names[idx], s);
      }
    if (!err)
      {
        s = gnupg_ttyname (0);
        if (s)
          err = session_env_setenv (opt.startup_env, "GPG_TTY", s);
      }
    if (err)
      log_fatal ("error recording startup environment: %s\n",
                 gpg_strerror (err));

    /* Fixme: Better use the locale function here.  */
    opt.startup_lc_ctype = getenv ("LC_CTYPE");
    if (opt.startup_lc_ctype)
      opt.startup_lc_ctype = xstrdup (opt.startup_lc_ctype);
    opt.startup_lc_messages = getenv ("LC_MESSAGES");
    if (opt.startup_lc_messages)
      opt.startup_lc_messages = xstrdup (opt.startup_lc_messages);
  }

  /* Check whether we have a config file on the commandline */
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

        case oHomedir:
          gnupg_set_homedir (pargs.r.ret_str);
          break;

        case oDebugQuickRandom:
          gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
          break;
        }
    }
  /* Reset the flags.  */
  pargs.flags &= ~(ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_BUFFER_SIZE, 0);
  maybe_setuid = 0;

  /*
   *  Now we are now working under our real uid
   */

  /* The configuraton directories for use by gpgrt_argparser.  */
  gpgrt_set_confdir (GPGRT_CONFDIR_SYS, gnupg_sysconfdir ());
  gpgrt_set_confdir (GPGRT_CONFDIR_USER, gnupg_homedir ());

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  /* We are re-using the struct, thus the reset flag.  We OR the
   * flags so that the internal intialized flag won't be cleared. */
  pargs.flags |= (ARGPARSE_FLAG_RESET
                  | ARGPARSE_FLAG_KEEP
                  | ARGPARSE_FLAG_SYS
                  | ARGPARSE_FLAG_USER);

  while (gpgrt_argparser (&pargs, opts, GPG_AGENT_NAME EXTSEP_S "conf"))
    {
      if (pargs.r_opt == ARGPARSE_CONFFILE)
        {
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
          continue;
        }
      if (parse_rereadable_options (&pargs, 0))
        continue; /* Already handled */
      switch (pargs.r_opt)
        {
        case aGPGConfList: gpgconf_list = 1; break;
        case aGPGConfTest: gpgconf_list = 2; break;
        case aUseStandardSocketP: gpgconf_list = 3; break;
        case oBatch: opt.batch=1; break;

        case oDebugWait: debug_wait = pargs.r.ret_int; break;

        case oNoVerbose: opt.verbose = 0; break;
        case oHomedir: gnupg_set_homedir (pargs.r.ret_str); break;
        case oNoDetach: nodetach = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oCsh: csh_style = 1; break;
        case oSh: csh_style = 0; break;
        case oServer: pipe_server = 1; break;
        case oDaemon: is_daemon = 1; break;
        case oStealSocket: steal_socket = 1; break;
        case oSupervised: is_supervised = 1; break;

        case oDisplay: default_display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: default_ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: default_ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: default_lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: default_lc_messages = xstrdup (pargs.r.ret_str);
          break;
        case oXauthority: default_xauthority = xstrdup (pargs.r.ret_str);
          break;

        case oUseStandardSocket:
        case oNoUseStandardSocket:
          obsolete_option (configname, pargs.lineno, "use-standard-socket");
          break;

        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oKeepTTY: opt.keep_tty = 1; break;
        case oKeepDISPLAY: opt.keep_display = 1; break;

	case oSSHSupport:
          ssh_support = 1;
          break;

        case oPuttySupport:
#        ifdef HAVE_W32_SYSTEM
          putty_support = 1;
#        endif
          break;

        case oWin32OpenSSHSupport:
#        ifdef HAVE_W32_SYSTEM
          if (pargs.r_type)
            win32_openssh_support = pargs.r.ret_str;
          else
            win32_openssh_support = W32_DEFAULT_AGENT_PIPE_NAME;
#        endif
          break;

        case oExtraSocket:
          opt.extra_socket = 1;  /* (1 = points into argv)  */
          socket_name_extra = pargs.r.ret_str;
          break;

        case oBrowserSocket:
          opt.browser_socket = 1;  /* (1 = points into argv)  */
          socket_name_browser = pargs.r.ret_str;
          break;

        case oAutoExpandSecmem:
          /* Try to enable this option.  It will officially only be
           * supported by Libgcrypt 1.9 but 1.8.2 already supports it
           * on the quiet and thus we use the numeric value value.  */
          gcry_control (78 /*GCRYCTL_AUTO_EXPAND_SECMEM*/,
                        (unsigned int)pargs.r.ret_ulong,  0);
          break;

        case oListenBacklog:
          listen_backlog = pargs.r.ret_int;
          break;

        case oDebugQuickRandom:
          /* Only used by the first stage command line parser.  */
          break;

        case oWriteEnvFile:
          obsolete_option (configname, pargs.lineno, "write-env-file");
          break;

        default:
          if (configname)
            pargs.err = ARGPARSE_PRINT_WARNING;
          else
            pargs.err = ARGPARSE_PRINT_ERROR;
          break;
	}
    }

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }

  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */

  if (!last_configname)
    config_filename = gpgrt_fnameconcat (gnupg_homedir (),
                                         GPG_AGENT_NAME EXTSEP_S "conf",
                                         NULL);
  else
    {
      config_filename = last_configname;
      last_configname = NULL;
    }

  if (log_get_errorcount(0))
    exit(2);

  finalize_rereadable_options ();

  /* Get a default log file from common.conf.  */
  if (!logfile && !parse_comopt (GNUPG_MODULE_NAME_AGENT, debug_argparser))
    {
      logfile = comopt.logfile;
      comopt.logfile = NULL;
    }

#ifdef ENABLE_NLS
  /* gpg-agent usually does not output any messages because it runs in
     the background.  For log files it is acceptable to have messages
     always encoded in utf-8.  We switch here to utf-8, so that
     commands like --help still give native messages.  It is far
     easier to switch only once instead of for every message and it
     actually helps when more then one thread is active (avoids an
     extra copy step). */
    bind_textdomain_codeset (PACKAGE_GT, "UTF-8");
#endif

  if (!pipe_server && !is_daemon && !gpgconf_list && !is_supervised)
    {
     /* We have been called without any command and thus we merely
        check whether an agent is already running.  We do this right
        here so that we don't clobber a logfile with this check but
        print the status directly to stderr. */
      opt.debug = 0;
      set_debug ();
      check_for_running_agent (0);
      agent_exit (0);
    }

  if (is_supervised && !opt.quiet)
    log_info(_("WARNING: \"%s\" is a deprecated option\n"), "--supervised");

  if (is_supervised)
    ;
  else if (!opt.extra_socket)
    opt.extra_socket = 1;
  else if (socket_name_extra
           && (!strcmp (socket_name_extra, "none")
               || !strcmp (socket_name_extra, "/dev/null")))
    {
      /* User requested not to create this socket.  */
      opt.extra_socket = 0;
      socket_name_extra = NULL;
    }

  if (is_supervised)
    ;
  else if (!opt.browser_socket)
    opt.browser_socket = 1;
  else if (socket_name_browser
           && (!strcmp (socket_name_browser, "none")
               || !strcmp (socket_name_browser, "/dev/null")))
    {
      /* User requested not to create this socket.  */
      opt.browser_socket = 0;
      socket_name_browser = NULL;
    }

  set_debug ();

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  /* Try to create missing directories. */
  if (!gpgconf_list)
    create_directories ();

  if (debug_wait && pipe_server)
    {
      thread_init_once ();
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      gnupg_sleep (debug_wait);
      log_debug ("... okay\n");
    }

  if (gpgconf_list == 3)
    {
      /* We now use the standard socket always - return true for
         backward compatibility.  */
      agent_exit (0);
    }
  else if (gpgconf_list == 2)
    agent_exit (0);
  else if (gpgconf_list)
    {
      /* Note: If an option is runtime changeable, please set the
       * respective flag in the gpgconf-comp.c table.  */
      es_printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
      es_printf ("default-cache-ttl:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, DEFAULT_CACHE_TTL );
      es_printf ("default-cache-ttl-ssh:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, DEFAULT_CACHE_TTL_SSH );
      es_printf ("max-cache-ttl:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, MAX_CACHE_TTL );
      es_printf ("max-cache-ttl-ssh:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, MAX_CACHE_TTL_SSH );
      es_printf ("min-passphrase-len:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, MIN_PASSPHRASE_LEN );
      es_printf ("min-passphrase-nonalpha:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, MIN_PASSPHRASE_NONALPHA);
      es_printf ("check-passphrase-pattern:%lu:\n",
                 GC_OPT_FLAG_DEFAULT);
      es_printf ("check-sym-passphrase-pattern:%lu:\n",
                 GC_OPT_FLAG_DEFAULT);
      es_printf ("max-passphrase-days:%lu:%d:\n",
                 GC_OPT_FLAG_DEFAULT, MAX_PASSPHRASE_DAYS);
      es_printf ("ssh-fingerprint-digest:%lu:\"%s:\n",
                 GC_OPT_FLAG_DEFAULT, "sha256");

      agent_exit (0);
    }

  /* Now start with logging to a file if this is desired. */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (GPGRT_LOG_WITH_PREFIX
                             | GPGRT_LOG_WITH_TIME
                             | GPGRT_LOG_WITH_PID));
      current_logfile = xstrdup (logfile);
    }

  /* Make sure that we have a default ttyname. */
  if (!default_ttyname && gnupg_ttyname (1))
    default_ttyname = xstrdup (gnupg_ttyname (1));
  if (!default_ttytype && getenv ("TERM"))
    default_ttytype = xstrdup (getenv ("TERM"));


  if (pipe_server)
    {
      /* This is the simple pipe based server */
      ctrl_t ctrl;

      initialize_modules ();

      ctrl = xtrycalloc (1, sizeof *ctrl);
      if (!ctrl)
        {
          log_error ("error allocating connection control data: %s\n",
                     strerror (errno) );
          agent_exit (1);
        }
      ctrl->session_env = session_env_new ();
      if (!ctrl->session_env)
        {
          log_error ("error allocating session environment block: %s\n",
                     strerror (errno) );
          xfree (ctrl);
          agent_exit (1);
        }
      agent_init_default_ctrl (ctrl);
      start_command_handler (ctrl, GNUPG_INVALID_FD, GNUPG_INVALID_FD);
      agent_deinit_default_ctrl (ctrl);
      xfree (ctrl);
    }
  else if (is_supervised && comopt.no_autostart)
    {
      /* If we are running on a server and the user has set
       * no-autostart for gpg or gpgsm.  gpg-agent would anyway be
       * started by the supervisor which has the bad effect that it
       * will steal the socket from a remote server.  Note that
       * systemd has no knowledge about the lock files we take during
       * the start operation.  */
      log_info ("%s %s not starting in supervised mode due to no-autostart.\n",
                gpgrt_strusage(11), gpgrt_strusage(13) );
    }
  else if (is_supervised)
    {
#ifndef HAVE_W32_SYSTEM
      gnupg_fd_t fd, fd_extra, fd_browser, fd_ssh;

      initialize_modules ();

      /* when supervised and sending logs to stderr, the process
         supervisor should handle log entry metadata (pid, name,
         timestamp) */
      if (!logfile)
        log_set_prefix (NULL, 0);

      log_info ("%s %s starting in supervised mode.\n",
                gpgrt_strusage(11), gpgrt_strusage(13) );

      /* See below in "regular server mode" on why we remove certain
       * envvars.  */
      if (!opt.keep_display)
        gnupg_unsetenv ("DISPLAY");
      gnupg_unsetenv ("INSIDE_EMACS");

      /* Virtually create the sockets.  Note that we use -1 here
       * because the whole thing works only on Unix. */
      map_supervised_sockets (&fd, &fd_extra, &fd_browser, &fd_ssh);
      if (fd == -1)
        log_fatal ("no standard socket provided\n");

#ifdef HAVE_SIGPROCMASK
      if (startup_signal_mask_valid)
        {
          if (sigprocmask (SIG_SETMASK, &startup_signal_mask, NULL))
            log_error ("error restoring signal mask: %s\n",
                       strerror (errno));
        }
      else
        log_info ("no saved signal mask\n");
#endif /*HAVE_SIGPROCMASK*/

      log_info ("listening on: std=%d extra=%d browser=%d ssh=%d\n",
                fd, fd_extra, fd_browser, fd_ssh);
      handle_connections (fd, fd_extra, fd_browser, fd_ssh);
#endif /*!HAVE_W32_SYSTEM*/
    }
  else if (!is_daemon)
    ; /* NOTREACHED */
  else
    { /* Regular server mode */
      gnupg_fd_t fd;
      gnupg_fd_t fd_extra = GNUPG_INVALID_FD;
      gnupg_fd_t fd_browser = GNUPG_INVALID_FD;
      gnupg_fd_t fd_ssh = GNUPG_INVALID_FD;
#ifndef HAVE_W32_SYSTEM
      pid_t pid;
#endif

      /* Remove the DISPLAY variable so that a pinentry does not
         default to a specific display.  There is still a default
         display when gpg-agent was started using --display or a
         client requested this using an OPTION command.  Note, that we
         don't do this when running in reverse daemon mode (i.e. when
         exec the program given as arguments). */
#ifndef HAVE_W32_SYSTEM
      if (!opt.keep_display && !argc)
        gnupg_unsetenv ("DISPLAY");
#endif

      /* Remove the INSIDE_EMACS variable so that a pinentry does not
         always try to interact with Emacs.  The variable is set when
         a client requested this using an OPTION command.  */
      gnupg_unsetenv ("INSIDE_EMACS");

      /* Create the sockets.  */
      socket_name = create_socket_name (GPG_AGENT_SOCK_NAME, 1);
      fd = create_server_socket (socket_name, 1, 0,
                                 &redir_socket_name, &socket_nonce);

      if (opt.extra_socket)
        {
          if (socket_name_extra)
            socket_name_extra = create_socket_name (socket_name_extra, 0);
          else
            socket_name_extra = create_socket_name
              /**/                (GPG_AGENT_EXTRA_SOCK_NAME, 1);
          opt.extra_socket = 2; /* Indicate that it has been malloced.  */
          fd_extra = create_server_socket (socket_name_extra, 0, 0,
                                           &redir_socket_name_extra,
                                           &socket_nonce_extra);
        }

      if (opt.browser_socket)
        {
          if (socket_name_browser)
            socket_name_browser = create_socket_name (socket_name_browser, 0);
          else
            socket_name_browser= create_socket_name
              /**/                 (GPG_AGENT_BROWSER_SOCK_NAME, 1);
          opt.browser_socket = 2; /* Indicate that it has been malloced.  */
          fd_browser = create_server_socket (socket_name_browser, 0, 0,
                                             &redir_socket_name_browser,
                                             &socket_nonce_browser);
        }

      socket_name_ssh = create_socket_name (GPG_AGENT_SSH_SOCK_NAME, 1);
      fd_ssh = create_server_socket (socket_name_ssh, 0, 1,
                                     &redir_socket_name_ssh,
                                     &socket_nonce_ssh);

      /* If we are going to exec a program in the parent, we record
         the PID, so that the child may check whether the program is
         still alive. */
      if (argc)
        parent_pid = getpid ();

      fflush (NULL);

#ifdef HAVE_W32_SYSTEM

      (void)csh_style;
      (void)nodetach;
      initialize_modules ();

#else /*!HAVE_W32_SYSTEM*/

      pid = fork ();
      if (pid == (pid_t)-1)
        {
          log_fatal ("fork failed: %s\n", strerror (errno) );
          exit (1);
        }
      else if (pid)
        { /* We are the parent */
          char *infostr_ssh_sock, *infostr_ssh_valid;

          /* Close the socket FD. */
          close (fd);

          /* The signal mask might not be correct right now and thus
             we restore it.  That is not strictly necessary but some
             programs falsely assume a cleared signal mask.  */

#ifdef HAVE_SIGPROCMASK
          if (startup_signal_mask_valid)
            {
              if (sigprocmask (SIG_SETMASK, &startup_signal_mask, NULL))
                log_error ("error restoring signal mask: %s\n",
                           strerror (errno));
            }
          else
            log_info ("no saved signal mask\n");
#endif /*HAVE_SIGPROCMASK*/

          /* Create the SSH info string if enabled. */
	  if (ssh_support)
	    {
	      if (asprintf (&infostr_ssh_sock, "SSH_AUTH_SOCK=%s",
			    socket_name_ssh) < 0)
		{
		  log_error ("out of core\n");
		  kill (pid, SIGTERM);
		  exit (1);
		}
	      if (asprintf (&infostr_ssh_valid, "gnupg_SSH_AUTH_SOCK_by=%lu",
			    (unsigned long)getpid()) < 0)
		{
		  log_error ("out of core\n");
		  kill (pid, SIGTERM);
		  exit (1);
		}
	    }

          *socket_name = 0; /* Don't let cleanup() remove the socket -
                               the child should do this from now on */
	  if (opt.extra_socket)
	    *socket_name_extra = 0;
	  if (opt.browser_socket)
	    *socket_name_browser = 0;
          *socket_name_ssh = 0;

          if (argc)
            { /* Run the program given on the commandline.  */
              if (ssh_support && (putenv (infostr_ssh_sock)
                                  || putenv (infostr_ssh_valid)))
                {
                  log_error ("failed to set environment: %s\n",
                             strerror (errno) );
                  kill (pid, SIGTERM );
                  exit (1);
                }

              /* Close all the file descriptors except the standard
                 ones and those open at startup.  We explicitly don't
                 close 0,1,2 in case something went wrong collecting
                 them at startup.  */
              close_all_fds (3, startup_fd_list);

              /* Run the command.  */
              execvp (argv[0], argv);
              log_error ("failed to run the command: %s\n", strerror (errno));
              kill (pid, SIGTERM);
              exit (1);
            }
          else
            {
              /* Print the environment string, so that the caller can use
                 shell's eval to set it */
              if (csh_style)
                {
		  if (ssh_support)
		    {
		      *strchr (infostr_ssh_sock, '=') = ' ';
		      es_printf ("setenv %s;\n", infostr_ssh_sock);
		    }
                }
              else
                {
		  if (ssh_support)
		    {
		      es_printf ("%s; export SSH_AUTH_SOCK;\n",
                                 infostr_ssh_sock);
		    }
                }
	      if (ssh_support)
		{
		  xfree (infostr_ssh_sock);
		  xfree (infostr_ssh_valid);
		}
              exit (0);
            }
          /*NOTREACHED*/
        } /* End parent */

      /*
         This is the child
       */

      initialize_modules ();

      /* Detach from tty and put process into a new session */
      if (!nodetach )
        {
          int i;
          unsigned int oldflags;

          /* Close stdin, stdout and stderr unless it is the log stream */
          for (i=0; i <= 2; i++)
            {
              if (!log_test_fd (i) && i != fd )
                {
                  if ( ! close (i)
                       && open ("/dev/null", i? O_WRONLY : O_RDONLY) == -1)
                    {
                      log_error ("failed to open '%s': %s\n",
                                 "/dev/null", strerror (errno));
                      cleanup ();
                      exit (1);
                    }
                }
            }
          if (setsid() == -1)
            {
              log_error ("setsid() failed: %s\n", strerror(errno) );
              cleanup ();
              exit (1);
            }

          log_get_prefix (&oldflags);
          log_set_prefix (NULL, oldflags | GPGRT_LOG_RUN_DETACHED);
          opt.running_detached = 1;

          /* Unless we are running with a program given on the command
           * line we can assume that the inotify things works and thus
           * we can avoid the regular stat calls.  */
          if (!argc)
            reliable_homedir_inotify = 1;
        }

      {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction (SIGPIPE, &sa, NULL);
      }
#endif /*!HAVE_W32_SYSTEM*/

      if (gnupg_chdir (gnupg_daemon_rootdir ()))
        {
          log_error ("chdir to '%s' failed: %s\n",
                     gnupg_daemon_rootdir (), strerror (errno));
          exit (1);
        }

      log_info ("%s %s started\n", gpgrt_strusage(11), gpgrt_strusage(13) );
      handle_connections (fd, fd_extra, fd_browser, fd_ssh);
      assuan_sock_close (fd);
    }

  return 0;
}


/* Exit entry point.  This function should be called instead of a
   plain exit.  */
void
agent_exit (int rc)
{
  /*FIXME: update_random_seed_file();*/

  /* We run our cleanup handler because that may close cipher contexts
     stored in secure memory and thus this needs to be done before we
     explicitly terminate secure memory.  */
  cleanup ();

#if 1
  /* at this time a bit annoying */
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
#endif
  gcry_control (GCRYCTL_TERM_SECMEM );
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


/* This is our callback function for gcrypt progress messages.  It is
   set once at startup and dispatches progress messages to the
   corresponding threads of the agent.  */
static void
agent_libgcrypt_progress_cb (void *data, const char *what, int printchar,
                             int current, int total)
{
  struct progress_dispatch_s *dispatch;
  npth_t mytid = npth_self ();

  (void)data;

  for (dispatch = progress_dispatch_list; dispatch; dispatch = dispatch->next)
    if (dispatch->ctrl && dispatch->tid == mytid)
      break;
  if (dispatch && dispatch->cb)
    dispatch->cb (dispatch->ctrl, what, printchar, current, total);
}


/* If a progress dispatcher callback has been associated with the
 * current connection unregister it.  */
static void
unregister_progress_cb (void)
{
  struct progress_dispatch_s *dispatch;
  npth_t mytid = npth_self ();

  for (dispatch = progress_dispatch_list; dispatch; dispatch = dispatch->next)
    if (dispatch->ctrl && dispatch->tid == mytid)
      break;
  if (dispatch)
    {
      dispatch->ctrl = NULL;
      dispatch->cb = NULL;
    }
}


/* Setup a progress callback CB for the current connection.  Using a
 * CB of NULL disables the callback.  */
void
agent_set_progress_cb (void (*cb)(ctrl_t ctrl, const char *what,
                                  int printchar, int current, int total),
                       ctrl_t ctrl)
{
  struct progress_dispatch_s *dispatch, *firstfree;
  npth_t mytid = npth_self ();

  firstfree = NULL;
  for (dispatch = progress_dispatch_list; dispatch; dispatch = dispatch->next)
    {
      if (dispatch->ctrl && dispatch->tid == mytid)
        break;
      if (!dispatch->ctrl && !firstfree)
        firstfree = dispatch;
    }
  if (!dispatch) /* None allocated: Reuse or allocate a new one.  */
    {
      if (firstfree)
        {
          dispatch = firstfree;
        }
      else if ((dispatch = xtrycalloc (1, sizeof *dispatch)))
        {
          dispatch->next = progress_dispatch_list;
          progress_dispatch_list = dispatch;
        }
      else
        {
          log_error ("error allocating new progress dispatcher slot: %s\n",
                     gpg_strerror (gpg_error_from_syserror ()));
          return;
        }
      dispatch->ctrl = ctrl;
      dispatch->tid = mytid;
    }

  dispatch->cb = cb;
}


/* Each thread has its own local variables conveyed by a control
   structure usually identified by an argument named CTRL.  This
   function is called immediately after allocating the control
   structure.  Its purpose is to setup the default values for that
   structure.  Note that some values may have already been set.  */
static void
agent_init_default_ctrl (ctrl_t ctrl)
{
  log_assert (ctrl->session_env);

  /* Note we ignore malloc errors because we can't do much about it
     and the request will fail anyway shortly after this
     initialization. */
  session_env_setenv (ctrl->session_env, "DISPLAY", default_display);
  session_env_setenv (ctrl->session_env, "GPG_TTY", default_ttyname);
  session_env_setenv (ctrl->session_env, "TERM", default_ttytype);
  session_env_setenv (ctrl->session_env, "XAUTHORITY", default_xauthority);
  session_env_setenv (ctrl->session_env, "PINENTRY_USER_DATA", NULL);

  if (ctrl->lc_ctype)
    xfree (ctrl->lc_ctype);
  ctrl->lc_ctype = default_lc_ctype? xtrystrdup (default_lc_ctype) : NULL;

  if (ctrl->lc_messages)
    xfree (ctrl->lc_messages);
  ctrl->lc_messages = default_lc_messages? xtrystrdup (default_lc_messages)
                                    /**/ : NULL;
  ctrl->cache_ttl_opt_preset = CACHE_TTL_OPT_PRESET;
}


/* Release all resources allocated by default in the control
   structure.  This is the counterpart to agent_init_default_ctrl.  */
static void
agent_deinit_default_ctrl (ctrl_t ctrl)
{
  unregister_progress_cb ();
  session_env_release (ctrl->session_env);
  clear_ephemeral_keys (ctrl);

  xfree (ctrl->digest.data);
  ctrl->digest.data = NULL;
  if (ctrl->lc_ctype)
    xfree (ctrl->lc_ctype);
  if (ctrl->lc_messages)
    xfree (ctrl->lc_messages);
}


/* Because the ssh protocol does not send us information about the
   current TTY setting, we use this function to use those from startup
   or those explicitly set.  This is also used for the restricted mode
   where we ignore requests to change the environment.  */
gpg_error_t
agent_copy_startup_env (ctrl_t ctrl)
{
  gpg_error_t err = 0;
  int iterator = 0;
  const char *name, *value;

  while (!err && (name = session_env_list_stdenvnames (&iterator, NULL)))
    {
      if ((value = session_env_getenv (opt.startup_env, name)))
        err = session_env_setenv (ctrl->session_env, name, value);
    }

  if (!err && !ctrl->lc_ctype && opt.startup_lc_ctype)
    if (!(ctrl->lc_ctype = xtrystrdup (opt.startup_lc_ctype)))
      err = gpg_error_from_syserror ();

  if (!err && !ctrl->lc_messages && opt.startup_lc_messages)
    if (!(ctrl->lc_messages = xtrystrdup (opt.startup_lc_messages)))
      err = gpg_error_from_syserror ();

  if (err)
    log_error ("error setting default session environment: %s\n",
               gpg_strerror (err));

  return err;
}


/* Reread parts of the configuration.  Note, that this function is
   obviously not thread-safe and should only be called from the PTH
   signal handler.

   Fixme: Due to the way the argument parsing works, we create a
   memory leak here for all string type arguments.  There is currently
   no clean way to tell whether the memory for the argument has been
   allocated or points into the process's original arguments.  Unless
   we have a mechanism to tell this, we need to live on with this. */
static void
reread_configuration (void)
{
  gpgrt_argparse_t pargs;
  char *twopart;
  int dummy;
  int logfile_seen = 0;

  if (!config_filename)
    return; /* No config file. */

  twopart = strconcat (GPG_AGENT_NAME EXTSEP_S "conf" PATHSEP_S,
                       config_filename, NULL);
  if (!twopart)
    return;  /* Out of core.  */

  parse_rereadable_options (NULL, 1); /* Start from the default values. */

  memset (&pargs, 0, sizeof pargs);
  dummy = 0;
  pargs.argc = &dummy;
  pargs.flags = (ARGPARSE_FLAG_KEEP
                 |ARGPARSE_FLAG_SYS
                 |ARGPARSE_FLAG_USER);
  while (gpgrt_argparser (&pargs, opts, twopart) )
    {
      if (pargs.r_opt == ARGPARSE_CONFFILE)
        {
          log_info (_("reading options from '%s'\n"),
                    pargs.r_type? pargs.r.ret_str: "[cmdline]");
        }
      else if (pargs.r_opt < -1)
        pargs.err = ARGPARSE_PRINT_WARNING;
      else /* Try to parse this option - ignore unchangeable ones. */
        {
          if (pargs.r_opt == oLogFile)
            logfile_seen = 1;
          parse_rereadable_options (&pargs, 1);
        }
    }
  gpgrt_argparse (NULL, &pargs, NULL);  /* Release internal state.  */
  xfree (twopart);

  finalize_rereadable_options ();
  set_debug ();

  /* Get a default log file from common.conf.  */
  if (!logfile_seen && !parse_comopt (GNUPG_MODULE_NAME_AGENT, !!opt.debug))
    {
      if (!current_logfile || !comopt.logfile
          || strcmp (current_logfile, comopt.logfile))
        {
          log_set_file (comopt.logfile);
          xfree (current_logfile);
          current_logfile = comopt.logfile? xtrystrdup (comopt.logfile) : NULL;
        }
    }
}


/* Return the file name of the socket we are using for native
   requests.  */
const char *
get_agent_socket_name (void)
{
  const char *s = socket_name;

  return (s && *s)? s : NULL;
}

/* Return the file name of the socket we are using for SSH
   requests.  */
const char *
get_agent_ssh_socket_name (void)
{
  const char *s = socket_name_ssh;

  return (s && *s)? s : NULL;
}


/* Return the number of active connections. */
int
get_agent_active_connection_count (void)
{
  return active_connections;
}


/* Under W32, this function returns the handle of the scdaemon
   notification event.  Calling it the first time creates that
   event.  */
#if defined(HAVE_W32_SYSTEM)
void *
get_agent_daemon_notify_event (void)
{
  static HANDLE the_event = INVALID_HANDLE_VALUE;

  if (the_event == INVALID_HANDLE_VALUE)
    {
      HANDLE h, h2;
      SECURITY_ATTRIBUTES sa = { sizeof (SECURITY_ATTRIBUTES), NULL, TRUE};

      /* We need to use a manual reset event object due to the way our
         w32-pth wait function works: If we would use an automatic
         reset event we are not able to figure out which handle has
         been signaled because at the time we single out the signaled
         handles using WFSO the event has already been reset due to
         the WFMO.  */
      h = CreateEvent (&sa, TRUE, FALSE, NULL);
      if (!h)
        log_error ("can't create scd notify event: %s\n", w32_strerror (-1) );
      else if (!DuplicateHandle (GetCurrentProcess(), h,
                                 GetCurrentProcess(), &h2,
                                 EVENT_MODIFY_STATE|SYNCHRONIZE, TRUE, 0))
        {
          log_error ("setting synchronize for scd notify event failed: %s\n",
                     w32_strerror (-1) );
          CloseHandle (h);
        }
      else
        {
          CloseHandle (h);
          the_event = h2;
        }
    }

  return the_event;
}
#endif /*HAVE_W32_SYSTEM*/



/* Create a name for the socket in the home directory as using
   STANDARD_NAME.  We also check for valid characters as well as
   against a maximum allowed length for a unix domain socket is done.
   The function terminates the process in case of an error.  Returns:
   Pointer to an allocated string with the absolute name of the socket
   used.  */
static char *
create_socket_name (char *standard_name, int with_homedir)
{
  char *name;

  if (with_homedir)
    name = make_filename (gnupg_socketdir (), standard_name, NULL);
  else
    name = make_filename (standard_name, NULL);
  if (strchr (name, PATHSEP_C))
    {
      log_error (("'%s' are not allowed in the socket name\n"), PATHSEP_S);
      agent_exit (2);
    }
  return name;
}



/* Create a Unix domain socket with NAME.  Returns the file descriptor
   or terminates the process in case of an error.  Note that this
   function needs to be used for the regular socket first (indicated
   by PRIMARY) and only then for the extra and the ssh sockets.  If
   the socket has been redirected the name of the real socket is
   stored as a malloced string at R_REDIR_NAME.  If CYGWIN is set a
   Cygwin compatible socket is created (Windows only). */
static gnupg_fd_t
create_server_socket (char *name, int primary, int cygwin,
                      char **r_redir_name, assuan_sock_nonce_t *nonce)
{
  struct sockaddr *addr;
  struct sockaddr_un *unaddr;
  socklen_t len;
  gnupg_fd_t fd;
  int rc;

  xfree (*r_redir_name);
  *r_redir_name = NULL;

  fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0);
  if (fd == ASSUAN_INVALID_FD)
    {
      log_error (_("can't create socket: %s\n"), strerror (errno));
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      agent_exit (2);
    }

  if (cygwin)
    assuan_sock_set_flag (fd, "cygwin", 1);

  unaddr = xmalloc (sizeof *unaddr);
  addr = (struct sockaddr*)unaddr;

  {
    int redirected;

    if (assuan_sock_set_sockaddr_un (name, addr, &redirected))
      {
        if (errno == ENAMETOOLONG)
          log_error (_("socket name '%s' is too long\n"), name);
        else
          log_error ("error preparing socket '%s': %s\n",
                     name, gpg_strerror (gpg_error_from_syserror ()));
        *name = 0; /* Inhibit removal of the socket by cleanup(). */
        xfree (unaddr);
        agent_exit (2);
      }
    if (redirected)
      {
        *r_redir_name = xstrdup (unaddr->sun_path);
        if (opt.verbose)
          log_info ("redirecting socket '%s' to '%s'\n", name, *r_redir_name);
      }
  }

  len = SUN_LEN (unaddr);
  rc = assuan_sock_bind (fd, addr, len);

  /* At least our error code mapping on Windows-CE used to return
   * EEXIST thus we better test for this on Windows . */
  if (rc == -1
      && (errno == EADDRINUSE
#ifdef HAVE_W32_SYSTEM
          || errno == EEXIST
#endif
          ))
    {
      /* Check whether a gpg-agent is already running.  We do this
         test only if this is the primary socket.  For secondary
         sockets we assume that a test for gpg-agent has already been
         done and reuse the requested socket.  Testing the ssh-socket
         is not possible because at this point, though we know the new
         Assuan socket, the Assuan server and thus the ssh-agent
         server is not yet operational; this would lead to a hang.  */
      if (primary && !check_for_running_agent (1))
        {
          if (steal_socket)
            log_info (N_("trying to steal socket from running %s\n"),
                      "gpg-agent");
          else
            {
              log_set_prefix (NULL, GPGRT_LOG_WITH_PREFIX);
              log_set_file (NULL);
              log_error (_("a gpg-agent is already running - "
                           "not starting a new one\n"));
              *name = 0; /* Inhibit removal of the socket by cleanup(). */
              assuan_sock_close (fd);
              xfree (unaddr);
              agent_exit (2);
            }
        }
      gnupg_remove (unaddr->sun_path);
      rc = assuan_sock_bind (fd, addr, len);
    }
  if (rc != -1 && (rc=assuan_sock_get_nonce (addr, len, nonce)))
    log_error (_("error getting nonce for the socket\n"));
  if (rc == -1)
    {
      /* We use gpg_strerror here because it allows us to get strings
         for some W32 socket error codes.  */
      log_error (_("error binding socket to '%s': %s\n"),
                 unaddr->sun_path,
                 gpg_strerror (gpg_error_from_syserror ()));

      assuan_sock_close (fd);
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      xfree (unaddr);
      agent_exit (2);
    }

  if (gnupg_chmod (unaddr->sun_path, "-rwx"))
    log_error (_("can't set permissions of '%s': %s\n"),
               unaddr->sun_path, strerror (errno));

  if (listen (FD2INT(fd), listen_backlog ) == -1)
    {
      log_error ("listen(fd,%d) failed: %s\n",
                 listen_backlog, strerror (errno));
      *name = 0; /* Inhibit removal of the socket by cleanup(). */
      assuan_sock_close (fd);
      xfree (unaddr);
      agent_exit (2);
    }

  if (opt.verbose)
    log_info (_("listening on socket '%s'\n"), unaddr->sun_path);

  xfree (unaddr);
  return fd;
}


/* Check that the directory for storing the private keys exists and
   create it if not.  This function won't fail as it is only a
   convenience function and not strictly necessary.  */
static void
create_private_keys_directory (const char *home)
{
  char *fname;
  struct stat statbuf;

  fname = make_filename (home, GNUPG_PRIVATE_KEYS_DIR, NULL);
  if (gnupg_stat (fname, &statbuf) && errno == ENOENT)
    {
      if (gnupg_mkdir (fname, "-rwx"))
        log_error (_("can't create directory '%s': %s\n"),
                   fname, strerror (errno) );
      else if (!opt.quiet)
        log_info (_("directory '%s' created\n"), fname);

      if (gnupg_chmod (fname, "-rwx"))
        log_error (_("can't set permissions of '%s': %s\n"),
                   fname, strerror (errno));
    }
  else
    {
      /* The file exists or another error.  Make sure we have sensible
       * permissions.  We enforce rwx for user but keep existing group
       * permissions.  Permissions for other are always cleared.  */
      if (gnupg_chmod (fname, "-rwx...---"))
        log_error (_("can't set permissions of '%s': %s\n"),
                   fname, strerror (errno));
    }
  xfree (fname);
}


/* Create the directory only if the supplied directory name is the
   same as the default one.  This way we avoid to create arbitrary
   directories when a non-default home directory is used.  To cope
   with HOME, we compare only the suffix if we see that the default
   homedir does start with a tilde.  We don't stop here in case of
   problems because other functions will throw an error anyway.*/
static void
create_directories (void)
{
  struct stat statbuf;
  const char *defhome = standard_homedir ();
  char *home;

  home = make_filename (gnupg_homedir (), NULL);
  if (gnupg_stat (home, &statbuf))
    {
      if (errno == ENOENT)
        {
          if (
#ifdef HAVE_W32_SYSTEM
              ( !compare_filenames (home, defhome) )
#else
              (*defhome == '~'
                && (strlen (home) >= strlen (defhome+1)
                    && !strcmp (home + strlen(home)
                                - strlen (defhome+1), defhome+1)))
               || (*defhome != '~' && !strcmp (home, defhome) )
#endif
               )
            {
              if (gnupg_mkdir (home, "-rwx"))
                log_error (_("can't create directory '%s': %s\n"),
                           home, strerror (errno) );
              else
                {
                  if (!opt.quiet)
                    log_info (_("directory '%s' created\n"), home);
                  create_private_keys_directory (home);
                }
            }
        }
      else
        log_error (_("stat() failed for '%s': %s\n"), home, strerror (errno));
    }
  else if ( !S_ISDIR(statbuf.st_mode))
    {
      log_error (_("can't use '%s' as home directory\n"), home);
    }
  else /* exists and is a directory. */
    {
      create_private_keys_directory (home);
    }
  xfree (home);
}



/* This is the worker for the ticker.  It is called every few seconds
   and may only do fast operations. */
static void
handle_tick (void)
{
  static time_t last_minute;
  struct stat statbuf;

  if (!last_minute)
    last_minute = time (NULL);

  /* If we are running as a child of another process, check whether
     the parent is still alive and shutdown if not. */
#ifndef HAVE_W32_SYSTEM
  if (parent_pid != (pid_t)(-1))
    {
      if (kill (parent_pid, 0))
        {
          shutdown_pending = 2;
          log_info ("parent process died - shutting down\n");
          log_info ("%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13));
          cleanup ();
          agent_exit (0);
        }
    }
#endif /*HAVE_W32_SYSTEM*/

  /* Code to be run from time to time.  */
#if CHECK_OWN_SOCKET_INTERVAL > 0
  if (last_minute + CHECK_OWN_SOCKET_INTERVAL <= time (NULL))
    {
      check_own_socket ();
      last_minute = time (NULL);
    }
#endif

  /* Need to check for expired cache entries.  */
  agent_cache_housekeeping ();

  /* Check whether the homedir is still available.  */
  if (!shutdown_pending
      && (!have_homedir_inotify || !reliable_homedir_inotify)
      && gnupg_stat (gnupg_homedir (), &statbuf) && errno == ENOENT)
    {
      shutdown_pending = 1;
      log_info ("homedir has been removed - shutting down\n");
    }
}


/* A global function which allows us to call the reload stuff from
   other places too.  This is only used when build for W32.  */
void
agent_sighup_action (void)
{
  log_info ("SIGHUP received - "
            "re-reading configuration and flushing cache\n");

  agent_flush_cache (0);
  reread_configuration ();
  agent_reload_trustlist ();
  /* We flush the module name cache so that after installing a
     "pinentry" binary that one can be used in case the
     "pinentry-basic" fallback was in use.  */
  gnupg_module_name_flush_some ();

  if (opt.disable_daemon[DAEMON_SCD])
    agent_kill_daemon (DAEMON_SCD);
}


/* A helper function to handle SIGUSR2.  */
static void
agent_sigusr2_action (void)
{
  if (opt.verbose)
    log_info ("SIGUSR2 received - updating card event counter\n");
  /* Nothing to check right now.  We only increment a counter.  */
  bump_card_eventcounter ();
}


#ifndef HAVE_W32_SYSTEM
/* The signal handler for this program.  It is expected to be run in
   its own thread and not in the context of a signal handler.  */
static void
handle_signal (int signo)
{
  switch (signo)
    {
#ifndef HAVE_W32_SYSTEM
    case SIGHUP:
      agent_sighup_action ();
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      /* Fixme: We need to see how to integrate pth dumping into our
         logging system.  */
      /* pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ()); */
      agent_query_dump_state ();
      agent_daemon_dump_state ();
      break;

    case SIGUSR2:
      agent_sigusr2_action ();
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %i open connections\n",
		  active_connections);
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          log_info ("%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13));
          cleanup ();
          agent_exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", gpgrt_strusage(11), gpgrt_strusage(13));
      cleanup ();
      agent_exit (0);
      break;
#endif
    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}
#endif

/* Check the nonce on a new connection.  This is a NOP unless we
   are using our Unix domain socket emulation under Windows.  */
static int
check_nonce (ctrl_t ctrl, assuan_sock_nonce_t *nonce)
{
  if (assuan_sock_check_nonce (ctrl->thread_startup.fd, nonce))
    {
      log_info (_("error reading nonce on fd %d: %s\n"),
                FD2INT(ctrl->thread_startup.fd), strerror (errno));
      assuan_sock_close (ctrl->thread_startup.fd);
      xfree (ctrl);
      return -1;
    }
  else
    return 0;
}


#ifdef HAVE_W32_SYSTEM
/* The window message processing function for Putty.  Warning: This
   code runs as a native Windows thread.  Use of our own functions
   needs to be bracket with pth_leave/pth_enter. */
static LRESULT CALLBACK
putty_message_proc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  int ret = 0;
  int w32rc;
  COPYDATASTRUCT *cds;
  const char *mapfile;
  HANDLE maphd;
  PSID mysid = NULL;
  PSID mapsid = NULL;
  void *data = NULL;
  PSECURITY_DESCRIPTOR psd = NULL;
  ctrl_t ctrl = NULL;

  if (msg != WM_COPYDATA)
    {
      return DefWindowProc (hwnd, msg, wparam, lparam);
    }

  cds = (COPYDATASTRUCT*)lparam;
  if (cds->dwData != PUTTY_IPC_MAGIC)
    return 0;  /* Ignore data with the wrong magic.  */
  mapfile = cds->lpData;
  if (!cds->cbData || mapfile[cds->cbData - 1])
    return 0;  /* Ignore empty and non-properly terminated strings.  */

  if (DBG_IPC)
    {
      npth_protect ();
      log_debug ("ssh map file '%s'", mapfile);
      npth_unprotect ();
    }

  maphd = OpenFileMapping (FILE_MAP_ALL_ACCESS, FALSE, mapfile);
  if (DBG_IPC)
    {
      npth_protect ();
      log_debug ("ssh map handle %p\n", maphd);
      npth_unprotect ();
    }

  if (!maphd || maphd == INVALID_HANDLE_VALUE)
    return 0;

  npth_protect ();

  mysid = w32_get_user_sid ();
  if (!mysid)
    {
      log_error ("error getting my sid\n");
      goto leave;
    }

  w32rc = GetSecurityInfo (maphd, SE_KERNEL_OBJECT,
                           OWNER_SECURITY_INFORMATION,
                           &mapsid, NULL, NULL, NULL,
                           &psd);
  if (w32rc)
    {
      log_error ("error getting sid of ssh map file: rc=%d", w32rc);
      goto leave;
    }

  if (DBG_IPC)
    {
      char *sidstr;

      if (!ConvertSidToStringSid (mysid, &sidstr))
        sidstr = NULL;
      log_debug ("          my sid: '%s'", sidstr? sidstr: "[error]");
      LocalFree (sidstr);
      if (!ConvertSidToStringSid (mapsid, &sidstr))
        sidstr = NULL;
      log_debug ("ssh map file sid: '%s'", sidstr? sidstr: "[error]");
      LocalFree (sidstr);
    }

  if (!EqualSid (mysid, mapsid))
    {
      log_error ("ssh map file has a non-matching sid\n");
      goto leave;
    }

  data = MapViewOfFile (maphd, FILE_MAP_ALL_ACCESS, 0, 0, 0);
  if (DBG_IPC)
    log_debug ("ssh IPC buffer at %p\n", data);
  if (!data)
    goto leave;

  /* log_printhex ("request:", data, 20); */

  ctrl = xtrycalloc (1, sizeof *ctrl);
  if (!ctrl)
    {
      log_error ("error allocating connection control data: %s\n",
                 strerror (errno) );
      goto leave;
    }
  ctrl->session_env = session_env_new ();
  if (!ctrl->session_env)
    {
      log_error ("error allocating session environment block: %s\n",
                 strerror (errno) );
      goto leave;
    }

  agent_init_default_ctrl (ctrl);
  if (!serve_mmapped_ssh_request (ctrl, data, PUTTY_IPC_MAXLEN))
    ret = 1; /* Valid ssh message has been constructed.  */
  agent_deinit_default_ctrl (ctrl);
  /* log_printhex ("  reply:", data, 20); */

 leave:
  xfree (ctrl);
  if (data)
    UnmapViewOfFile (data);
  xfree (mapsid);
  if (psd)
    LocalFree (psd);
  xfree (mysid);
  CloseHandle (maphd);

  npth_unprotect ();

  return ret;
}
#endif /*HAVE_W32_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
/* The thread handling Putty's IPC requests.  */
static void *
putty_message_thread (void *arg)
{
  WNDCLASS wndwclass = {0, putty_message_proc, 0, 0,
                        NULL, NULL, NULL, NULL, NULL, "Pageant"};
  HWND hwnd;
  MSG msg;

  (void)arg;

  if (opt.verbose)
    log_info ("putty message loop thread started\n");

  /* The message loop runs as thread independent from our nPth system.
     This also means that we need to make sure that we switch back to
     our system before calling any no-windows function.  */
  npth_unprotect ();

  /* First create a window to make sure that a message queue exists
     for this thread.  */
  if (!RegisterClass (&wndwclass))
    {
      npth_protect ();
      log_error ("error registering Pageant window class");
      return NULL;
    }
  hwnd = CreateWindowEx (0, "Pageant", "Pageant", 0,
                         0, 0, 0, 0,
                         HWND_MESSAGE,  /* hWndParent */
                         NULL,          /* hWndMenu   */
                         NULL,          /* hInstance  */
                         NULL);         /* lpParm     */
  if (!hwnd)
    {
      npth_protect ();
      log_error ("error creating Pageant window");
      return NULL;
    }

  while (GetMessage(&msg, NULL, 0, 0))
    {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }

  /* Back to nPth.  */
  npth_protect ();

  if (opt.verbose)
    log_info ("putty message loop thread stopped\n");
  return NULL;
}

#define BUFSIZE (5 * 1024)

/* The thread handling Win32-OpenSSH requests through NamedPipe.  */
static void *
win32_openssh_thread (void *arg)
{
  HANDLE pipe;

  (void)arg;

  if (opt.verbose)
    log_info ("Win32-OpenSSH thread started\n");

  while (1)
    {
      ctrl_t ctrl = NULL;
      estream_t ssh_stream = NULL;
      es_syshd_t syshd;

      npth_unprotect ();
      pipe = CreateNamedPipeA (win32_openssh_support, PIPE_ACCESS_DUPLEX,
                               (PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
                                | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS),
                               PIPE_UNLIMITED_INSTANCES,
                               BUFSIZE, BUFSIZE, 0, NULL);

      if (pipe == INVALID_HANDLE_VALUE)
        {
          npth_protect ();
          log_error ("cannot create pipe: %ld\n", GetLastError ());
          break;
        }

      if (ConnectNamedPipe (pipe, NULL) == 0)
        {
          npth_protect ();
          CloseHandle (pipe);
          log_error ("Error at ConnectNamedPipe: %ld\n", GetLastError ());
          break;
        }

      npth_protect ();
      ctrl = xtrycalloc (1, sizeof *ctrl);
      if (!ctrl)
        {
          CloseHandle (pipe);
          log_error ("error allocating connection control data: %s\n",
                     strerror (errno));
          break;
        }

#if _WIN32_WINNT >= 0x600
      if (!GetNamedPipeClientProcessId (pipe, &ctrl->client_pid))
        log_info ("failed to get client process id: %ld\n", GetLastError ());
      else
        ctrl->client_uid = -1;
#endif

      ctrl->session_env = session_env_new ();
      if (!ctrl->session_env)
        {
          log_error ("error allocating session environment block: %s\n",
                     strerror (errno));
          agent_deinit_default_ctrl (ctrl);
          xfree (ctrl);
          CloseHandle (pipe);
          break;
        }
      agent_init_default_ctrl (ctrl);

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = pipe;
      ssh_stream = es_sysopen (&syshd, "r+b");
      if (!ssh_stream)
        {
          agent_deinit_default_ctrl (ctrl);
          xfree (ctrl);
          CloseHandle (pipe);
          break;
        }

      start_command_handler_ssh_stream (ctrl, ssh_stream);

      agent_deinit_default_ctrl (ctrl);
      xfree (ctrl);
      CloseHandle (pipe);
    }

  if (opt.verbose)
    log_info ("Win32-OpenSSH thread stopped\n");
  return NULL;
}
#endif /*HAVE_W32_SYSTEM*/


static void *
do_start_connection_thread (ctrl_t ctrl)
{
  active_connections++;
  agent_init_default_ctrl (ctrl);
  if (opt.verbose > 1 && !DBG_IPC)
    log_info (_("handler 0x%lx for fd %d started\n"),
              (unsigned long) npth_self(), FD2INT(ctrl->thread_startup.fd));

  start_command_handler (ctrl, GNUPG_INVALID_FD, ctrl->thread_startup.fd);
  if (opt.verbose > 1 && !DBG_IPC)
    log_info (_("handler 0x%lx for fd %d terminated\n"),
              (unsigned long) npth_self(), FD2INT(ctrl->thread_startup.fd));

  agent_deinit_default_ctrl (ctrl);
  xfree (ctrl);
  active_connections--;
  return NULL;
}


/* This is the standard connection thread's main function.  */
static void *
start_connection_thread_std (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce))
    {
      log_error ("handler 0x%lx nonce check FAILED\n",
                 (unsigned long) npth_self());
      return NULL;
    }

  return do_start_connection_thread (ctrl);
}


/* This is the extra socket connection thread's main function.  */
static void *
start_connection_thread_extra (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce_extra))
    {
      log_error ("handler 0x%lx nonce check FAILED\n",
                 (unsigned long) npth_self());
      return NULL;
    }

  ctrl->restricted = 1;
  return do_start_connection_thread (ctrl);
}


/* This is the browser socket connection thread's main function.  */
static void *
start_connection_thread_browser (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce_browser))
    {
      log_error ("handler 0x%lx nonce check FAILED\n",
                 (unsigned long) npth_self());
      return NULL;
    }

  ctrl->restricted = 2;
  return do_start_connection_thread (ctrl);
}


/* This is the ssh connection thread's main function.  */
static void *
start_connection_thread_ssh (void *arg)
{
  ctrl_t ctrl = arg;

  if (check_nonce (ctrl, &socket_nonce_ssh))
    return NULL;

  active_connections++;
  agent_init_default_ctrl (ctrl);
  if (opt.verbose)
    log_info (_("ssh handler 0x%lx for fd %d started\n"),
              (unsigned long) npth_self(), FD2INT(ctrl->thread_startup.fd));

  start_command_handler_ssh (ctrl, ctrl->thread_startup.fd);
  if (opt.verbose)
    log_info (_("ssh handler 0x%lx for fd %d terminated\n"),
              (unsigned long) npth_self(), FD2INT(ctrl->thread_startup.fd));

  agent_deinit_default_ctrl (ctrl);
  xfree (ctrl);
  active_connections--;
  return NULL;
}


/* Connection handler loop.  Wait for connection requests and spawn a
   thread after accepting a connection.  */
static void
handle_connections (gnupg_fd_t listen_fd,
                    gnupg_fd_t listen_fd_extra,
                    gnupg_fd_t listen_fd_browser,
                    gnupg_fd_t listen_fd_ssh)
{
  gpg_error_t err;
  npth_attr_t tattr;
  struct sockaddr_un paddr;
  socklen_t plen;
  fd_set fdset, read_fdset;
  int ret;
  gnupg_fd_t fd;
  int nfd;
  int saved_errno;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
#ifdef HAVE_W32_SYSTEM
  HANDLE events[2];
  unsigned int events_set;
#endif
  int sock_inotify_fd = -1;
  int home_inotify_fd = -1;
  struct {
    const char *name;
    void *(*func) (void *arg);
    gnupg_fd_t l_fd;
  } listentbl[] = {
    { "std",     start_connection_thread_std   },
    { "extra",   start_connection_thread_extra },
    { "browser", start_connection_thread_browser },
    { "ssh",    start_connection_thread_ssh   }
  };


  ret = npth_attr_init(&tattr);
  if (ret)
    log_fatal ("error allocating thread attributes: %s\n",
	       strerror (ret));
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

#ifndef HAVE_W32_SYSTEM
  npth_sigev_init ();
  npth_sigev_add (SIGHUP);
  npth_sigev_add (SIGUSR1);
  npth_sigev_add (SIGUSR2);
  npth_sigev_add (SIGINT);
  npth_sigev_add (SIGTERM);
  npth_sigev_fini ();
#else
  events[0] = get_agent_daemon_notify_event ();
  events[1] = INVALID_HANDLE_VALUE;
#endif

  if (disable_check_own_socket)
    sock_inotify_fd = -1;
  else if ((err = gnupg_inotify_watch_socket (&sock_inotify_fd, socket_name)))
    {
      if (gpg_err_code (err) != GPG_ERR_NOT_SUPPORTED)
        log_info ("error enabling daemon termination by socket removal: %s\n",
                  gpg_strerror (err));
    }

  if (disable_check_own_socket)
    home_inotify_fd = -1;
  else if ((err = gnupg_inotify_watch_delete_self (&home_inotify_fd,
                                                   gnupg_homedir ())))
    {
      if (gpg_err_code (err) != GPG_ERR_NOT_SUPPORTED)
        log_info ("error enabling daemon termination by homedir removal: %s\n",
                  gpg_strerror (err));
    }
  else
    have_homedir_inotify = 1;

  /* On Windows we need to fire up a separate thread to listen for
     requests from Putty (an SSH client), so we can replace Putty's
     Pageant (its ssh-agent implementation). */
#ifdef HAVE_W32_SYSTEM
  if (putty_support)
    {
      npth_t thread;

      ret = npth_create (&thread, &tattr, putty_message_thread, NULL);
      if (ret)
        log_error ("error spawning putty message loop: %s\n", strerror (ret));
    }

  if (win32_openssh_support)
    {
      npth_t thread;

      ret = npth_create (&thread, &tattr, win32_openssh_thread, NULL);
      if (ret)
        log_error ("error spawning Win32-OpenSSH loop: %s\n", strerror (ret));
    }
#endif /*HAVE_W32_SYSTEM*/

  /* Set a flag to tell call-scd.c that it may enable event
     notifications.  */
  opt.sigusr2_enabled = 1;

  FD_ZERO (&fdset);
  FD_SET (FD2INT (listen_fd), &fdset);
  nfd = FD2INT (listen_fd);
  if (listen_fd_extra != GNUPG_INVALID_FD)
    {
      FD_SET ( FD2INT(listen_fd_extra), &fdset);
      if (FD2INT (listen_fd_extra) > nfd)
        nfd = FD2INT (listen_fd_extra);
    }
  if (listen_fd_browser != GNUPG_INVALID_FD)
    {
      FD_SET ( FD2INT(listen_fd_browser), &fdset);
      if (FD2INT (listen_fd_browser) > nfd)
        nfd = FD2INT (listen_fd_browser);
    }
  if (listen_fd_ssh != GNUPG_INVALID_FD)
    {
      FD_SET ( FD2INT(listen_fd_ssh), &fdset);
      if (FD2INT (listen_fd_ssh) > nfd)
        nfd = FD2INT (listen_fd_ssh);
    }
  if (sock_inotify_fd != -1)
    {
      FD_SET (sock_inotify_fd, &fdset);
      if (sock_inotify_fd > nfd)
        nfd = sock_inotify_fd;
    }
  if (home_inotify_fd != -1)
    {
      FD_SET (home_inotify_fd, &fdset);
      if (home_inotify_fd > nfd)
        nfd = home_inotify_fd;
    }

  listentbl[0].l_fd = listen_fd;
  listentbl[1].l_fd = listen_fd_extra;
  listentbl[2].l_fd = listen_fd_browser;
  listentbl[3].l_fd = listen_fd_ssh;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  for (;;)
    {
      /* Shutdown test.  */
      if (shutdown_pending)
        {
          if (active_connections == 0)
            break; /* ready */

          /* Do not accept new connections but keep on running the
           * loop to cope with the timer events.
           *
           * Note that we do not close the listening socket because a
           * client trying to connect to that socket would instead
           * restart a new dirmngr instance - which is unlikely the
           * intention of a shutdown. */
          FD_ZERO (&fdset);
          nfd = -1;
          if (sock_inotify_fd != -1)
            {
              FD_SET (sock_inotify_fd, &fdset);
              nfd = sock_inotify_fd;
            }
          if (home_inotify_fd != -1)
            {
              FD_SET (home_inotify_fd, &fdset);
              if (home_inotify_fd > nfd)
                nfd = home_inotify_fd;
            }
	}

      /* POSIX says that fd_set should be implemented as a structure,
         thus a simple assignment is fine to copy the entire set.  */
      read_fdset = fdset;

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Timeout.  */
	  handle_tick ();
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL;
	}
      npth_timersub (&abstime, &curtime, &timeout);

#ifndef HAVE_W32_SYSTEM
      ret = npth_pselect (nfd+1, &read_fdset, NULL, NULL, &timeout,
                          npth_sigev_sigmask ());
      saved_errno = errno;

      {
        int signo;
        while (npth_sigev_get_pending (&signo))
          handle_signal (signo);
      }
#else
      ret = npth_eselect (nfd+1, &read_fdset, NULL, NULL, &timeout,
                          events, &events_set);
      saved_errno = errno;

      /* This is valid even if npth_eselect returns an error.  */
      if (events_set & 1)
	agent_sigusr2_action ();
#endif

      if (ret == -1 && saved_errno != EINTR)
	{
          log_error (_("npth_pselect failed: %s - waiting 1s\n"),
                     strerror (saved_errno));
          gnupg_sleep (1);
          continue;
	}
      if (ret <= 0)
	/* Interrupt or timeout.  Will be handled when calculating the
	   next timeout.  */
	continue;

      /* The inotify fds are set even when a shutdown is pending (see
       * above).  So we must handle them in any case.  To avoid that
       * they trigger a second time we close them immediately.  */
      if (sock_inotify_fd != -1
          && FD_ISSET (sock_inotify_fd, &read_fdset)
          && gnupg_inotify_has_name (sock_inotify_fd, GPG_AGENT_SOCK_NAME))
        {
          shutdown_pending = 1;
          close (sock_inotify_fd);
          sock_inotify_fd = -1;
          log_info ("socket file has been removed - shutting down\n");
        }

      if (home_inotify_fd != -1
          && FD_ISSET (home_inotify_fd, &read_fdset))
        {
          shutdown_pending = 1;
          close (home_inotify_fd);
          home_inotify_fd = -1;
          log_info ("homedir has been removed - shutting down\n");
        }

      if (!shutdown_pending)
        {
          int idx;
          ctrl_t ctrl;
          npth_t thread;

          for (idx=0; idx < DIM(listentbl); idx++)
            {
              if (listentbl[idx].l_fd == GNUPG_INVALID_FD)
                continue;
              if (!FD_ISSET (FD2INT (listentbl[idx].l_fd), &read_fdset))
                continue;

              plen = sizeof paddr;
              fd = INT2FD (npth_accept (FD2INT(listentbl[idx].l_fd),
                                        (struct sockaddr *)&paddr, &plen));
              if (fd == GNUPG_INVALID_FD)
                {
                  log_error ("accept failed for %s: %s\n",
                             listentbl[idx].name, strerror (errno));
                }
              else if ( !(ctrl = xtrycalloc (1, sizeof *ctrl)))
                {
                  log_error ("error allocating connection data for %s: %s\n",
                             listentbl[idx].name, strerror (errno) );
                  assuan_sock_close (fd);
                }
              else if ( !(ctrl->session_env = session_env_new ()))
                {
                  log_error ("error allocating session env block for %s: %s\n",
                             listentbl[idx].name, strerror (errno) );
                  xfree (ctrl);
                  assuan_sock_close (fd);
                }
              else
                {
                  ctrl->thread_startup.fd = fd;
                  ret = npth_create (&thread, &tattr,
                                     listentbl[idx].func, ctrl);
                  if (ret)
                    {
                      log_error ("error spawning connection handler for %s:"
                                 " %s\n", listentbl[idx].name, strerror (ret));
                      assuan_sock_close (fd);
                      xfree (ctrl);
                    }
                }
            }
        }
    }

  if (sock_inotify_fd != -1)
    close (sock_inotify_fd);
  if (home_inotify_fd != -1)
    close (home_inotify_fd);
  cleanup ();
  log_info (_("%s %s stopped\n"), gpgrt_strusage(11), gpgrt_strusage(13));
  npth_attr_destroy (&tattr);
}



/* Helper for check_own_socket.  */
static gpg_error_t
check_own_socket_pid_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *mb = opaque;
  put_membuf (mb, buffer, length);
  return 0;
}


/* The thread running the actual check.  We need to run this in a
   separate thread so that check_own_thread can be called from the
   timer tick.  */
static void *
check_own_socket_thread (void *arg)
{
  int rc;
  char *sockname = arg;
  assuan_context_t ctx = NULL;
  membuf_t mb;
  char *buffer;

  check_own_socket_running++;

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (rc));
      goto leave;
    }
  assuan_set_flag (ctx, ASSUAN_NO_LOGGING, 1);

  rc = assuan_socket_connect (ctx, sockname, (pid_t)(-1), 0);
  if (rc)
    {
      log_error ("can't connect my own socket: %s\n", gpg_strerror (rc));
      goto leave;
    }

  init_membuf (&mb, 100);
  rc = assuan_transact (ctx, "GETINFO pid", check_own_socket_pid_cb, &mb,
                        NULL, NULL, NULL, NULL);
  put_membuf (&mb, "", 1);
  buffer = get_membuf (&mb, NULL);
  if (rc || !buffer)
    {
      log_error ("sending command \"%s\" to my own socket failed: %s\n",
                 "GETINFO pid", gpg_strerror (rc));
      rc = 1;
    }
  else if ( (pid_t)strtoul (buffer, NULL, 10) != getpid ())
    {
      log_error ("socket is now serviced by another server\n");
      rc = 1;
    }
  else if (opt.verbose > 1)
    log_error ("socket is still served by this server\n");

  xfree (buffer);

 leave:
  xfree (sockname);
  if (ctx)
    assuan_release (ctx);
  if (rc)
    {
      /* We may not remove the socket as it is now in use by another
         server. */
      inhibit_socket_removal = 1;
      shutdown_pending = 2;
      log_info ("this process is useless - shutting down\n");
    }
  check_own_socket_running--;
  return NULL;
}


/* Check whether we are still listening on our own socket.  In case
   another gpg-agent process started after us has taken ownership of
   our socket, we would linger around without any real task.  Thus we
   better check once in a while whether we are really needed.  */
static void
check_own_socket (void)
{
  char *sockname;
  npth_t thread;
  npth_attr_t tattr;
  int err;

  if (disable_check_own_socket)
    return;

  if (check_own_socket_running || shutdown_pending)
    return;  /* Still running or already shutting down.  */

  sockname = make_filename_try (gnupg_socketdir (), GPG_AGENT_SOCK_NAME, NULL);
  if (!sockname)
    return; /* Out of memory.  */

  err = npth_attr_init (&tattr);
  if (err)
    {
      xfree (sockname);
      return;
    }
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);
  err = npth_create (&thread, &tattr, check_own_socket_thread, sockname);
  if (err)
    log_error ("error spawning check_own_socket_thread: %s\n", strerror (err));
  npth_attr_destroy (&tattr);
}



/* Figure out whether an agent is available and running. Prints an
   error if not.  If SILENT is true, no messages are printed.
   Returns 0 if the agent is running. */
static int
check_for_running_agent (int silent)
{
  gpg_error_t err;
  char *sockname;
  assuan_context_t ctx = NULL;

  sockname = make_filename_try (gnupg_socketdir (), GPG_AGENT_SOCK_NAME, NULL);
  if (!sockname)
    return gpg_error_from_syserror ();

  err = assuan_new (&ctx);
  if (!err)
    err = assuan_socket_connect (ctx, sockname, (pid_t)(-1), 0);
  xfree (sockname);
  if (err)
    {
      if (!silent)
        log_error (_("no gpg-agent running in this session\n"));

      if (ctx)
	assuan_release (ctx);
      return -1;
    }

  if (!opt.quiet && !silent)
    log_info ("gpg-agent running and available\n");

  assuan_release (ctx);
  return 0;
}
