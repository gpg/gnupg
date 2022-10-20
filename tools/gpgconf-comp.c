/* gpgconf-comp.c - Configuration utility for GnuPG.
 * Copyright (C) 2004, 2007-2011 Free Software Foundation, Inc.
 * Copyright (C) 2016 Werner Koch
 * Copyright (C) 2020, 2021 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuPG; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <ctype.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN 1
# include <windows.h>
#else
# include <pwd.h>
# include <grp.h>
#endif

#include "../common/util.h"
#include "../common/i18n.h"
#include "../common/exechelp.h"
#include "../common/sysutils.h"
#include "../common/status.h"

#include "../common/gc-opt-flags.h"
#include "gpgconf.h"




#if (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 ))
void gc_error (int status, int errnum, const char *fmt, ...) \
  __attribute__ ((format (printf, 3, 4)));
#endif

/* Output a diagnostic message.  If ERRNUM is not 0, then the output
   is followed by a colon, a white space, and the error string for the
   error number ERRNUM.  In any case the output is finished by a
   newline.  The message is prepended by the program name, a colon,
   and a whitespace.  The output may be further formatted or
   redirected by the jnlib logging facility.  */
void
gc_error (int status, int errnum, const char *fmt, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, fmt);
  log_logv (GPGRT_LOGLVL_ERROR, fmt, arg_ptr);
  va_end (arg_ptr);

  if (errnum)
    log_printf (": %s\n", strerror (errnum));
  else
    log_printf ("\n");

  if (status)
    {
      log_printf (NULL);
      log_printf ("fatal error (exit status %i)\n", status);
      gpgconf_failure (gpg_error_from_errno (errnum));
    }
}


/* Forward declaration.  */
static void gpg_agent_runtime_change (int killflag);
static void scdaemon_runtime_change (int killflag);
#ifdef BUILD_WITH_TPM2D
static void tpm2daemon_runtime_change (int killflag);
#endif
static void dirmngr_runtime_change (int killflag);
static void keyboxd_runtime_change (int killflag);



/* STRING_ARRAY is a malloced array with malloced strings.  It is used
 * a space to store strings so that other objects may point to these
 * strings. It shall never be shrinked or any items changes.
 * STRING_ARRAY itself may be reallocated to increase the size of the
 * table.  STRING_ARRAY_USED is the number of items currently used,
 * STRING_ARRAY_SIZE is the number of calloced slots. */
static char  **string_array;
static size_t string_array_used;
static size_t string_array_size;



/* Option configuration.  */

/* An option might take an argument, or not.  Argument types can be
   basic or complex.  Basic types are generic and easy to validate.
   Complex types provide more specific information about the intended
   use, but can be difficult to validate.  If you add to this enum,
   don't forget to update GC_ARG_TYPE below.  YOU MUST NOT CHANGE THE
   NUMBERS OF THE EXISTING ENTRIES, AS THEY ARE PART OF THE EXTERNAL
   INTERFACE.  */
typedef enum
  {
    /* Basic argument types.  */

    /* No argument.  */
    GC_ARG_TYPE_NONE = 0,

    /* A String argument.  */
    GC_ARG_TYPE_STRING = 1,

    /* A signed integer argument.  */
    GC_ARG_TYPE_INT32 = 2,

    /* An unsigned integer argument.  */
    GC_ARG_TYPE_UINT32 = 3,

    /* ADD NEW BASIC TYPE ENTRIES HERE.  */

    /* Complex argument types.  */

    /* A complete filename.  */
    GC_ARG_TYPE_FILENAME = 32,

    /* An LDAP server in the format
       HOSTNAME:PORT:USERNAME:PASSWORD:BASE_DN.  */
    GC_ARG_TYPE_LDAP_SERVER = 33,

    /* A 40 character fingerprint.  */
    GC_ARG_TYPE_KEY_FPR = 34,

    /* A user ID or key ID or fingerprint for a certificate.  */
    GC_ARG_TYPE_PUB_KEY = 35,

    /* A user ID or key ID or fingerprint for a certificate with a key.  */
    GC_ARG_TYPE_SEC_KEY = 36,

    /* A alias list made up of a key, an equal sign and a space
       separated list of values.  */
    GC_ARG_TYPE_ALIAS_LIST = 37,

    /* ADD NEW COMPLEX TYPE ENTRIES HERE.  */

    /* The number of the above entries.  */
    GC_ARG_TYPE_NR
  } gc_arg_type_t;


/* For every argument, we record some information about it in the
   following struct.  */
static const struct
{
  /* For every argument type exists a basic argument type that can be
     used as a fallback for input and validation purposes.  */
  gc_arg_type_t fallback;

  /* Human-readable name of the type.  */
  const char *name;
} gc_arg_type[GC_ARG_TYPE_NR] =
  {
    /* The basic argument types have their own types as fallback.  */
    { GC_ARG_TYPE_NONE, "none" },
    { GC_ARG_TYPE_STRING, "string" },
    { GC_ARG_TYPE_INT32, "int32" },
    { GC_ARG_TYPE_UINT32, "uint32" },

    /* Reserved basic type entries for future extension.  */
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },
    { GC_ARG_TYPE_NR, NULL }, { GC_ARG_TYPE_NR, NULL },

    /* The complex argument types have a basic type as fallback.  */
    { GC_ARG_TYPE_STRING, "filename" },
    { GC_ARG_TYPE_STRING, "ldap server" },
    { GC_ARG_TYPE_STRING, "key fpr" },
    { GC_ARG_TYPE_STRING, "pub key" },
    { GC_ARG_TYPE_STRING, "sec key" },
    { GC_ARG_TYPE_STRING, "alias list" },
  };


/* Every option has an associated expert level, than can be used to
   hide advanced and expert options from beginners.  If you add to
   this list, don't forget to update GC_LEVEL below.  YOU MUST NOT
   CHANGE THE NUMBERS OF THE EXISTING ENTRIES, AS THEY ARE PART OF THE
   EXTERNAL INTERFACE.  */
typedef enum
  {
    /* The basic options should always be displayed.  */
    GC_LEVEL_BASIC,

    /* The advanced options may be hidden from beginners.  */
    GC_LEVEL_ADVANCED,

    /* The expert options should only be displayed to experts.  */
    GC_LEVEL_EXPERT,

    /* The invisible options should normally never be displayed.  */
    GC_LEVEL_INVISIBLE,

    /* The internal options are never exported, they mark options that
       are recorded for internal use only.  */
    GC_LEVEL_INTERNAL,

    /* ADD NEW ENTRIES HERE.  */

    /* The number of the above entries.  */
    GC_LEVEL_NR
  } gc_expert_level_t;

/* A description for each expert level.  */
static const struct
{
  const char *name;
} gc_level[] =
  {
    { "basic" },
    { "advanced" },
    { "expert" },
    { "invisible" },
    { "internal" }
  };


/* Option flags.  The flags which are used by the components are defined
   by gc-opt-flags.h, included above.

   YOU MUST NOT CHANGE THE NUMBERS OF THE EXISTING FLAGS, AS THEY ARE
   PART OF THE EXTERNAL INTERFACE.  */

/* Some entries in the emitted option list are not options, but mark
   the beginning of a new group of options.  These entries have the
   GROUP flag set.  Note that this is internally also known as a
   header line. */
#define GC_OPT_FLAG_GROUP	(1UL << 0)
/* The ARG_OPT flag for an option indicates that the argument is
   optional.  This is never set for GC_ARG_TYPE_NONE options.  */
#define GC_OPT_FLAG_ARG_OPT	(1UL << 1)
/* The LIST flag for an option indicates that the option can occur
   several times.  A comma separated list of arguments is used as the
   argument value.  */
#define GC_OPT_FLAG_LIST	(1UL << 2)
/* The RUNTIME flag for an option indicates that the option can be
   changed at runtime.  */
#define GC_OPT_FLAG_RUNTIME	(1UL << 3)


/* A human-readable description for each flag.  */
static const struct
{
  const char *name;
} gc_flag[] =
  {
    { "group" },
    { "optional arg" },
    { "list" },
    { "runtime" },
    { "default" },
    { "default desc" },
    { "no arg desc" },
    { "no change" }
  };



/* Each option we want to support in gpgconf has the needed
 * information in a static list per componenet.  This struct describes
 * the info for a single option.  */
struct known_option_s
{
  /* If this is NULL, then this is a terminator in an array of unknown
   * length.  Otherwise it is the name of the option described by this
   * entry.  The name must not contain a colon.  */
  const char *name;

  /* The option flags.  */
  unsigned long flags;

  /* The expert level.  */
  gc_expert_level_t level;

  /* The complex type of the option argument; the default of 0 is used
   * for a standard type as returned by --dump-option-table.  */
  gc_arg_type_t arg_type;
};
typedef struct known_option_s known_option_t;


/* The known options of the GC_COMPONENT_GPG_AGENT component.  */
static known_option_t known_options_gpg_agent[] =
  {
   { "verbose", GC_OPT_FLAG_LIST|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "quiet", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "disable-scdaemon", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "enable-ssh-support", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "ssh-fingerprint-digest", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "enable-putty-support", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "enable-extended-key-format", GC_OPT_FLAG_RUNTIME, GC_LEVEL_INVISIBLE },
   { "debug-level", GC_OPT_FLAG_ARG_OPT|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED},
   { "log-file", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     /**/        GC_ARG_TYPE_FILENAME },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },

   { "default-cache-ttl", GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "default-cache-ttl-ssh", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "max-cache-ttl", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "max-cache-ttl-ssh", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "ignore-cache-for-signing", GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "allow-emacs-pinentry", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "grab", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "no-allow-external-cache", GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "no-allow-mark-trusted", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "no-allow-loopback-pinentry", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },

   { "enforce-passphrase-constraints", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "min-passphrase-len", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "min-passphrase-nonalpha", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "check-passphrase-pattern", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT,
     /**/                        GC_ARG_TYPE_FILENAME },
   { "check-sym-passphrase-pattern", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT,
     /**/                        GC_ARG_TYPE_FILENAME },
   { "max-passphrase-days", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "enable-passphrase-history", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "pinentry-timeout", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },

   { NULL }
 };


/* The known options of the GC_COMPONENT_SCDAEMON component.  */
static known_option_t known_options_scdaemon[] =
  {
   { "verbose", GC_OPT_FLAG_LIST|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "reader-port",  GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "ctapi-driver", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "pcsc-driver",  GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "disable-ccid", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT },
   { "disable-pinpad", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "enable-pinpad-varlen", GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "card-timeout",         GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "application-priority", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },
   { "debug-level", GC_OPT_FLAG_ARG_OPT|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED},
   { "log-file",    GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     GC_ARG_TYPE_FILENAME },
   { "deny-admin",  GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },

   { NULL }
 };

#ifdef BUILD_WITH_TPM2D
/* The known options of the GC_COMPONENT_TPM2DAEMON component.  */
static known_option_t known_options_tpm2daemon[] =
  {
   { "verbose", GC_OPT_FLAG_LIST|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "debug-level", GC_OPT_FLAG_ARG_OPT|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED},
   { "log-file",    GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     GC_ARG_TYPE_FILENAME },
   { "deny-admin",  GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC },
   { "parent",  GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED },

   { NULL }
 };
#endif


/* The known options of the GC_COMPONENT_GPG component.  */
static known_option_t known_options_gpg[] =
  {
   { "verbose",              GC_OPT_FLAG_LIST, GC_LEVEL_BASIC },
   { "quiet",                GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "no-greeting",          GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "default-key",          GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "encrypt-to",           GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "group",                GC_OPT_FLAG_LIST, GC_LEVEL_ADVANCED,
     GC_ARG_TYPE_ALIAS_LIST},
   { "compliance",           GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "default-new-key-algo", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "trust-model",          GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "debug-level",          GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED },
   { "log-file",             GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     GC_ARG_TYPE_FILENAME },
   { "keyserver",            GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "auto-key-locate",      GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "auto-key-import",      GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "auto-key-retrieve",    GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "include-key-block",    GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "disable-dirmngr",      GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "max-cert-depth",       GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "completes-needed",     GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "marginals-needed",     GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },

   /* The next items are pseudo options which we read via --gpgconf-list.
    * The meta information is taken from the table below.  */
   { "default_pubkey_algo",  GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "compliance_de_vs",     GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "use_keyboxd",          GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },

   { NULL }
 };
static const char *known_pseudo_options_gpg[] =
  {/*                     v-- ARGPARSE_TYPE_STRING */
   "default_pubkey_algo:0:2:@:",
   /* A basic compliance check for gpg.  We use gpg here but the
    * result is valid for all components.
    *                  v-- ARGPARSE_TYPE_INT */
   "compliance_de_vs:0:1:@:",
   /* True is use_keyboxd is enabled.  That option can be set in
    * common.conf but is not direcly supported by gpgconf.  Thus we
    * only allow to read it out.
    *                  v-- ARGPARSE_TYPE_INT */
   "use_keyboxd:0:1:@:",
   NULL
 };


/* The known options of the GC_COMPONENT_GPGSM component.  */
static known_option_t known_options_gpgsm[] =
 {
   { "verbose",           GC_OPT_FLAG_LIST, GC_LEVEL_BASIC },
   { "quiet",             GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "no-greeting",       GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "default-key",       GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "encrypt-to",        GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "disable-dirmngr",   GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "p12-charset",       GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "keyserver",         GC_OPT_FLAG_LIST, GC_LEVEL_INVISIBLE,
                          GC_ARG_TYPE_LDAP_SERVER },
   { "compliance",        GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "debug-level",       GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED },
   { "log-file",          GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
                          GC_ARG_TYPE_FILENAME },
   { "faked-system-time",              GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "disable-crl-checks",             GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "enable-crl-checks",              GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "enable-ocsp",                    GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "include-certs",                  GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "disable-policy-checks",          GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "auto-issuer-key-retrieve",       GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "cipher-algo",                    GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "disable-trusted-cert-crl-check", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },

   /* Pseudo option follows.  See also table below. */
   { "default_pubkey_algo",            GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },

   { NULL }
 };
static const char *known_pseudo_options_gpgsm[] =
  {/*                     v-- ARGPARSE_TYPE_STRING */
   "default_pubkey_algo:0:2:@:",
   NULL
 };


/* The known options of the GC_COMPONENT_DIRMNGR component.  */
static known_option_t known_options_dirmngr[] =
 {
   { "verbose",           GC_OPT_FLAG_LIST, GC_LEVEL_BASIC },
   { "quiet",             GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "no-greeting",       GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "resolver-timeout",  GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "nameserver",        GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "debug-level",       GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED },
   { "log-file",          GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
                          GC_ARG_TYPE_FILENAME },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },
   { "batch",             GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "force",             GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "use-tor",           GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "keyserver",         GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "ldapserver",        GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
                          GC_ARG_TYPE_LDAP_SERVER },
   { "disable-http",      GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "ignore-http-dp",    GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "http-proxy",        GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "honor-http-proxy",  GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "disable-ldap",      GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "ignore-ldap-dp",    GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "ldap-proxy",        GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "only-ldap-proxy",   GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "add-servers",       GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT },
   { "ldaptimeout",       GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "max-replies",       GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "allow-ocsp",        GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "ocsp-responder",    GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "ocsp-signer",       GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },
   { "allow-version-check",     GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "ignore-ocsp-service-url", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED },


   { NULL }
 };

/* The known options of the GC_COMPONENT_KEYBOXD component.  */
static known_option_t known_options_keyboxd[] =
 {
   { "verbose",           GC_OPT_FLAG_LIST, GC_LEVEL_BASIC },
   { "quiet",             GC_OPT_FLAG_NONE, GC_LEVEL_BASIC },
   { "log-file",          GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
                          GC_ARG_TYPE_FILENAME },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE },

   { NULL }
 };


/* The known options of the GC_COMPONENT_PINENTRY component.  */
static known_option_t known_options_pinentry[] =
 {
  { NULL }
 };



/* Our main option info object.  We copy all required information from the
 * gpgrt_opt_t items but convert the flags value to bit flags.  */
struct gc_option_s
{
  const char *name;            /* The same as gpgrt_opt_t.long_opt.     */
  const char *desc;            /* The same as gpgrt_opt_t.description.  */

  unsigned int is_header:1;    /* This is a header item.   */
  unsigned int is_list:1;      /* This is a list style option.  */
  unsigned int opt_arg:1;      /* The option's argument is optional.    */
  unsigned int runtime:1;      /* The option is runtime changeable.  */

  unsigned int gpgconf_list:1; /* Mentioned by --gpgconf-list.  */

  unsigned int has_default:1;  /* The option has a default value.  */
  unsigned int def_in_desc:1;  /* The default is in the descrition.  */
  unsigned int no_arg_desc:1;  /* The argument has a default  ???.  */
  unsigned int no_change:1;    /* User shall not change the option.   */

  unsigned int attr_ignore:1;  /* The ARGPARSE_ATTR_IGNORE.  */
  unsigned int attr_force:1;   /* The ARGPARSE_ATTR_FORCE.  */

  /* The expert level - copied from known_options.  */
  gc_expert_level_t level;

  /* The complex type - copied from known_options.  */
  gc_arg_type_t arg_type;

  /* The default value for this option.  This is NULL if the option is
     not present in the component, the empty string if no default is
     available, and otherwise a quoted string.  This is currently
     malloced.*/
  char *default_value;

  /* The current value of this option. */
  char *value;

  /* The new flags for this option.  The only defined flag is actually
     GC_OPT_FLAG_DEFAULT, and it means that the option should be
     deleted.  In this case, NEW_VALUE is NULL.  */
  unsigned long new_flags;

  /* The new value of this option.  */
  char *new_value;
};
typedef struct gc_option_s gc_option_t;



/* The information associated with each component.  */
static struct
{
  /* The name of the component.  Some components don't have an
   * associated program, but are implemented directly by GPGConf.  In
   * this case, PROGRAM is NULL.  */
  char *program;

  /* The displayed name of this component.  Must not contain a colon
   * (':') character.  */
  const char *name;

  /* The gettext domain for the description DESC.  If this is NULL,
     then the description is not translated.  */
  const char *desc_domain;

  /* The description of this component.  */
  const char *desc;

  /* The module name (GNUPG_MODULE_NAME_foo) as defined by
   * ../common/util.h.  This value is used to get the actual installed
   * path of the program.  0 is used if no program for the component
   * is available. */
  char module_name;

  /* The name for the configuration filename of this component.  */
  const char *option_config_filename;

  /* The static table of known options for this component.  */
  known_option_t *known_options;

  /* The static table of known pseudo options for this component or NULL.  */
  const char **known_pseudo_options;

  /* The runtime change callback.  If KILLFLAG is true the component
     is killed and not just reloaded.  */
  void (*runtime_change) (int killflag);

  /* The table of known options as read from the component including
   * header lines and such.  This is suitable to be passed to
   * gpgrt_argparser.  Will be filled in by
   * retrieve_options_from_program. */
  gpgrt_opt_t *opt_table;

  /* The full table including data from OPT_TABLE.  The end of the
   * table is marked by NULL entry for NAME.  Will be filled in by
   * retrieve_options_from_program.  */
  gc_option_t *options;

} gc_component[GC_COMPONENT_NR] =
  {
   /* Note: The order of the items must match the order given in the
    * gc_component_id_t enumeration.  The order is often used by
    * frontends to display the backend options thus do not change the
    * order without considering the user experience.  */
   { NULL },   /* DUMMY for GC_COMPONENT_ANY */

   { GPG_NAME,  GPG_DISP_NAME,     "gnupg",  N_("OpenPGP"),
     GNUPG_MODULE_NAME_GPG, GPG_NAME ".conf",
     known_options_gpg, known_pseudo_options_gpg },

   { GPGSM_NAME, GPGSM_DISP_NAME,  "gnupg",  N_("S/MIME"),
     GNUPG_MODULE_NAME_GPGSM, GPGSM_NAME ".conf",
     known_options_gpgsm, known_pseudo_options_gpgsm },

   { KEYBOXD_NAME, KEYBOXD_DISP_NAME, "gnupg", N_("Public Keys"),
     GNUPG_MODULE_NAME_KEYBOXD, KEYBOXD_NAME ".conf",
     known_options_keyboxd, NULL, keyboxd_runtime_change },

   { GPG_AGENT_NAME, GPG_AGENT_DISP_NAME, "gnupg", N_("Private Keys"),
     GNUPG_MODULE_NAME_AGENT, GPG_AGENT_NAME ".conf",
     known_options_gpg_agent, NULL, gpg_agent_runtime_change },

   { SCDAEMON_NAME, SCDAEMON_DISP_NAME, "gnupg", N_("Smartcards"),
     GNUPG_MODULE_NAME_SCDAEMON, SCDAEMON_NAME ".conf",
     known_options_scdaemon, NULL, scdaemon_runtime_change},

#ifdef BUILD_WITH_TPM2D
   { TPM2DAEMON_NAME, TPM2DAEMON_DISP_NAME, "gnupg", N_("TPM"),
     GNUPG_MODULE_NAME_TPM2DAEMON, TPM2DAEMON_NAME ".conf",
     known_options_tpm2daemon, NULL, tpm2daemon_runtime_change},
#else
   { NULL },  /* DUMMY to keep the table in-sync with enums */
#endif

   { DIRMNGR_NAME, DIRMNGR_DISP_NAME, "gnupg",   N_("Network"),
     GNUPG_MODULE_NAME_DIRMNGR, DIRMNGR_NAME ".conf",
     known_options_dirmngr, NULL, dirmngr_runtime_change },

   { "pinentry", "Pinentry", "gnupg", N_("Passphrase Entry"),
     GNUPG_MODULE_NAME_PINENTRY, NULL,
     known_options_pinentry }
  };



/* Structure used to collect error output of the component programs.  */
struct error_line_s;
typedef struct error_line_s *error_line_t;
struct error_line_s
{
  error_line_t next;   /* Link to next item.  */
  const char *fname;   /* Name of the config file (points into BUFFER).  */
  unsigned int lineno; /* Line number of the config file.  */
  const char *errtext; /* Text of the error message (points into BUFFER).  */
  char buffer[1];  /* Helper buffer.  */
};




/* Initialization and finalization.  */

static void
gc_option_free (gc_option_t *o)
{
  if (o == NULL || o->name == NULL)
    return;

  xfree (o->value);
  gc_option_free (o + 1);
}

static void
gc_components_free (void)
{
  int i;
  for (i = 0; i < DIM (gc_component); i++)
    gc_option_free (gc_component[i].options);
}

void
gc_components_init (void)
{
  atexit (gc_components_free);
}



/* Engine specific support.  */
static void
gpg_agent_runtime_change (int killflag)
{
  gpg_error_t err = 0;
  const char *pgmname;
  const char *argv[5];
  pid_t pid = (pid_t)(-1);
  int i = 0;
  int cmdidx;

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  if (!gnupg_default_homedir_p ())
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  argv[i++] = "--no-autostart";
  cmdidx = i;
  argv[i++] = killflag? "KILLAGENT" : "RELOADAGENT";
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  if (!err)
    err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, 1, NULL);
  if (err)
    gc_error (0, 0, "error running '%s %s': %s",
              pgmname, argv[cmdidx], gpg_strerror (err));
  gnupg_release_process (pid);
}


static void
scdaemon_runtime_change (int killflag)
{
  gpg_error_t err = 0;
  const char *pgmname;
  const char *argv[9];
  pid_t pid = (pid_t)(-1);
  int i = 0;
  int cmdidx;

  (void)killflag;  /* For scdaemon kill and reload are synonyms.  */

  /* We use "GETINFO app_running" to see whether the agent is already
     running and kill it only in this case.  This avoids an explicit
     starting of the agent in case it is not yet running.  There is
     obviously a race condition but that should not harm too much.  */

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  if (!gnupg_default_homedir_p ())
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  argv[i++] = "-s";
  argv[i++] = "--no-autostart";
  argv[i++] = "GETINFO scd_running";
  argv[i++] = "/if ${! $?}";
  cmdidx = i;
  argv[i++] = "scd killscd";
  argv[i++] = "/end";
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  if (!err)
    err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, 1, NULL);
  if (err)
    gc_error (0, 0, "error running '%s %s': %s",
              pgmname, argv[cmdidx], gpg_strerror (err));
  gnupg_release_process (pid);
}


#ifdef BUILD_WITH_TPM2D
static void
tpm2daemon_runtime_change (int killflag)
{
  gpg_error_t err = 0;
  const char *pgmname;
  const char *argv[9];
  pid_t pid = (pid_t)(-1);
  int i = 0;
  int cmdidx;

  (void)killflag;  /* For scdaemon kill and reload are synonyms.  */

  /* We use "GETINFO app_running" to see whether the agent is already
     running and kill it only in this case.  This avoids an explicit
     starting of the agent in case it is not yet running.  There is
     obviously a race condition but that should not harm too much.  */

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  if (!gnupg_default_homedir_p ())
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  argv[i++] = "-s";
  argv[i++] = "--no-autostart";
  argv[i++] = "GETINFO tpm2d_running";
  argv[i++] = "/if ${! $?}";
  cmdidx = i;
  argv[i++] = "scd killtpm2cd";
  argv[i++] = "/end";
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  if (!err)
    err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, 1, NULL);
  if (err)
    gc_error (0, 0, "error running '%s %s': %s",
              pgmname, argv[cmdidx], gpg_strerror (err));
  gnupg_release_process (pid);
}
#endif


static void
dirmngr_runtime_change (int killflag)
{
  gpg_error_t err = 0;
  const char *pgmname;
  const char *argv[6];
  pid_t pid = (pid_t)(-1);
  int i = 0;
  int cmdidx;

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  if (!gnupg_default_homedir_p ())
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  argv[i++] = "--no-autostart";
  argv[i++] = "--dirmngr";
  cmdidx = i;
  argv[i++] = killflag? "KILLDIRMNGR" : "RELOADDIRMNGR";
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  if (!err)
    err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, 1, NULL);
  if (err)
    gc_error (0, 0, "error running '%s %s': %s",
              pgmname, argv[cmdidx], gpg_strerror (err));
  gnupg_release_process (pid);
}


static void
keyboxd_runtime_change (int killflag)
{
  gpg_error_t err = 0;
  const char *pgmname;
  const char *argv[6];
  pid_t pid = (pid_t)(-1);
  int i = 0;
  int cmdidx;

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  argv[i++] = "--no-autostart";
  argv[i++] = "--keyboxd";
  cmdidx = i;
  argv[i++] = killflag? "KILLKEYBOXD" : "RELOADKEYBOXD";
  if (!gnupg_default_homedir_p ())
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  if (!err)
    err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, 1, NULL);
  if (err)
    gc_error (0, 0, "error running '%s %s': %s",
              pgmname, argv[cmdidx], gpg_strerror (err));
  gnupg_release_process (pid);
}


/* Launch the gpg-agent or the dirmngr if not already running.  */
gpg_error_t
gc_component_launch (int component)
{
  gpg_error_t err;
  const char *pgmname;
  const char *argv[6];
  int i;
  pid_t pid;

  if (component < 0)
    {
      err = gc_component_launch (GC_COMPONENT_GPG_AGENT);
      if (!err)
        err = gc_component_launch (GC_COMPONENT_KEYBOXD);
      if (!err)
        err = gc_component_launch (GC_COMPONENT_DIRMNGR);
      return err;
    }

  if (!(component == GC_COMPONENT_GPG_AGENT
        || component == GC_COMPONENT_KEYBOXD
        || component == GC_COMPONENT_DIRMNGR))
    {
      log_error ("%s\n", _("Component not suitable for launching"));
      gpgconf_failure (0);
    }

  if (gc_component_check_options (component, NULL, NULL))
    {
      log_error (_("Configuration file of component %s is broken\n"),
                 gc_component[component].name);
      if (!opt.quiet)
        log_info (_("Note: Use the command \"%s%s\" to get details.\n"),
                  gc_component[component].program
                  ? gc_component[component].program
                  : gc_component[component].name,
                  " --gpgconf-test");
      gpgconf_failure (0);
    }

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  i = 0;
  if (!gnupg_default_homedir_p ())
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  if (component == GC_COMPONENT_DIRMNGR)
    argv[i++] = "--dirmngr";
  else if (component == GC_COMPONENT_KEYBOXD)
    argv[i++] = "--keyboxd";
  argv[i++] = "NOP";
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, 1, NULL);
  if (err)
    gc_error (0, 0, "error running '%s%s%s': %s",
              pgmname,
              component == GC_COMPONENT_DIRMNGR? " --dirmngr"
              : component == GC_COMPONENT_KEYBOXD? " --keyboxd":"",
              " NOP",
              gpg_strerror (err));
  gnupg_release_process (pid);
  return err;
}


static void
do_runtime_change (int component, int killflag)
{
  int runtime[GC_COMPONENT_NR] =  { 0 };

  if (component < 0)
    {
      for (component = 0; component < GC_COMPONENT_NR; component++)
        runtime [component] = 1;
    }
  else
    {
      log_assert (component >= 0 && component < GC_COMPONENT_NR);
      runtime [component] = 1;
    }

  /* Do the restart for the selected components.  */
  for (component = GC_COMPONENT_NR-1; component >= 0; component--)
    {
      if (runtime[component] && gc_component[component].runtime_change)
        (*gc_component[component].runtime_change) (killflag);
    }
}


/* Unconditionally restart COMPONENT.  */
void
gc_component_kill (int component)
{
  do_runtime_change (component, 1);
}


/* Unconditionally reload COMPONENT or all components if COMPONENT is -1.  */
void
gc_component_reload (int component)
{
  do_runtime_change (component, 0);
}



/* More or less Robust version of dgettext.  It has the side effect of
   switching the codeset to utf-8 because this is what we want to
   output.  In theory it is possible to keep the original code set and
   switch back for regular diagnostic output (redefine "_(" for that)
   but given the nature of this tool, being something invoked from
   other programs, it does not make much sense.  */
static const char *
my_dgettext (const char *domain, const char *msgid)
{
  if (!msgid || !*msgid)
    return msgid;  /* Shortcut form "" which has the PO files meta data.  */

#ifdef USE_SIMPLE_GETTEXT
  if (domain)
    {
      static int switched_codeset;
      char *text;

      if (!switched_codeset)
        {
          switched_codeset = 1;
          gettext_use_utf8 (1);
        }

      if (!strcmp (domain, "gnupg"))
        domain = PACKAGE_GT;

      /* FIXME: we have no dgettext, thus we can't switch.  */

      text = (char*)gettext (msgid);
      return text ? text : msgid;
    }
  else
    return msgid;
#elif defined(ENABLE_NLS)
  if (domain)
    {
      static int switched_codeset;
      char *text;

      if (!switched_codeset)
        {
          switched_codeset = 1;
          bind_textdomain_codeset (PACKAGE_GT, "utf-8");

          bindtextdomain (DIRMNGR_NAME, gnupg_localedir ());
          bind_textdomain_codeset (DIRMNGR_NAME, "utf-8");

        }

      /* Note: This is a hack to actually use the gnupg2 domain as
         long we are in a transition phase where gnupg 1.x and 1.9 may
         coexist. */
      if (!strcmp (domain, "gnupg"))
        domain = PACKAGE_GT;

      text = dgettext (domain, msgid);
      return text ? text : msgid;
    }
  else
    return msgid;
#else
  (void)domain;
  return msgid;
#endif
}


/* Percent-Escape special characters.  The string is valid until the
   next invocation of the function.  */
char *
gc_percent_escape (const char *src)
{
  static char *esc_str;
  static int esc_str_len;
  int new_len = 3 * strlen (src) + 1;
  char *dst;

  if (esc_str_len < new_len)
    {
      char *new_esc_str = xrealloc (esc_str, new_len);
      esc_str = new_esc_str;
      esc_str_len = new_len;
    }

  dst = esc_str;
  while (*src)
    {
      if (*src == '%')
	{
	  *(dst++) = '%';
	  *(dst++) = '2';
	  *(dst++) = '5';
	}
      else if (*src == ':')
	{
	  /* The colon is used as field separator.  */
	  *(dst++) = '%';
	  *(dst++) = '3';
	  *(dst++) = 'a';
	}
      else if (*src == ',')
	{
	  /* The comma is used as list separator.  */
	  *(dst++) = '%';
	  *(dst++) = '2';
	  *(dst++) = 'c';
	}
      else if (*src == '\n')
	{
	  /* The newline is problematic in a line-based format.  */
	  *(dst++) = '%';
	  *(dst++) = '0';
	  *(dst++) = 'a';
	}
      else
	*(dst++) = *(src);
      src++;
    }
  *dst = '\0';
  return esc_str;
}



/* Percent-Deescape special characters.  The string is valid until the
   next invocation of the function.  */
static char *
percent_deescape (const char *src)
{
  static char *str;
  static int str_len;
  int new_len = 3 * strlen (src) + 1;
  char *dst;

  if (str_len < new_len)
    {
      char *new_str = xrealloc (str, new_len);
      str = new_str;
      str_len = new_len;
    }

  dst = str;
  while (*src)
    {
      if (*src == '%')
	{
	  int val = hextobyte (src + 1);

	  if (val < 0)
	    gc_error (1, 0, "malformed end of string %s", src);

	  *(dst++) = (char) val;
	  src += 3;
	}
      else
	*(dst++) = *(src++);
    }
  *dst = '\0';
  return str;
}


/* List all components that are available.  */
void
gc_component_list_components (estream_t out)
{
  gc_component_id_t component;
  const char *desc;
  const char *pgmname;

  for (component = 0; component < GC_COMPONENT_NR; component++)
    {
      if (!gc_component[component].program)
        continue;
      if (gc_component[component].module_name)
        pgmname = gnupg_module_name (gc_component[component].module_name);
      else
        pgmname = "";

      desc = gc_component[component].desc;
      desc = my_dgettext (gc_component[component].desc_domain, desc);
      es_fprintf (out, "%s:%s:",
                  gc_component[component].program, gc_percent_escape (desc));
      es_fprintf (out, "%s\n",  gc_percent_escape (pgmname));
    }
}



static int
all_digits_p (const char *p, size_t len)
{
  if (!len)
    return 0; /* No. */
  for (; len; len--, p++)
    if (!isascii (*p) || !isdigit (*p))
      return 0; /* No.  */
  return 1; /* Yes.  */
}


/* Collect all error lines from stream FP. Only lines prefixed with
   TAG are considered.  Returns a list of error line items (which may
   be empty).  There is no error return.  */
static error_line_t
collect_error_output (estream_t fp, const char *tag)
{
  char buffer[1024];
  char *p, *p2, *p3;
  int c, cont_line;
  unsigned int pos;
  error_line_t eitem, errlines, *errlines_tail;
  size_t taglen = strlen (tag);

  errlines = NULL;
  errlines_tail = &errlines;
  pos = 0;
  cont_line = 0;
  while ((c=es_getc (fp)) != EOF)
    {
      buffer[pos++] = c;
      if (pos >= sizeof buffer - 5 || c == '\n')
        {
          buffer[pos - (c == '\n')] = 0;
          if (cont_line)
            ; /*Ignore continuations of previous line. */
          else if (!strncmp (buffer, tag, taglen) && buffer[taglen] == ':')
            {
              /* "gpgsm: foo:4: bla" */
              /* Yep, we are interested in this line.  */
              p = buffer + taglen + 1;
              while (*p == ' ' || *p == '\t')
                p++;
              trim_trailing_spaces (p); /* Get rid of extra CRs.  */
              if (!*p)
                ; /* Empty lines are ignored.  */
              else if ( (p2 = strchr (p, ':')) && (p3 = strchr (p2+1, ':'))
                        && all_digits_p (p2+1, p3 - (p2+1)))
                {
                  /* Line in standard compiler format.  */
                  p3++;
                  while (*p3 == ' ' || *p3 == '\t')
                    p3++;
                  eitem = xmalloc (sizeof *eitem + strlen (p));
                  eitem->next = NULL;
                  strcpy (eitem->buffer, p);
                  eitem->fname = eitem->buffer;
                  eitem->buffer[p2-p] = 0;
                  eitem->errtext = eitem->buffer + (p3 - p);
                  /* (we already checked that there are only ascii
                     digits followed by a colon) */
                  eitem->lineno = 0;
                  for (p2++; isdigit (*p2); p2++)
                    eitem->lineno = eitem->lineno*10 + (*p2 - '0');
                  *errlines_tail = eitem;
                  errlines_tail = &eitem->next;
                }
              else
                {
                  /* Other error output.  */
                  eitem = xmalloc (sizeof *eitem + strlen (p));
                  eitem->next = NULL;
                  strcpy (eitem->buffer, p);
                  eitem->fname = NULL;
                  eitem->errtext = eitem->buffer;
                  eitem->lineno = 0;
                  *errlines_tail = eitem;
                  errlines_tail = &eitem->next;
                }
            }
          pos = 0;
          /* If this was not a complete line mark that we are in a
             continuation.  */
          cont_line = (c != '\n');
        }
    }

  /* We ignore error lines not terminated by a LF.  */
  return errlines;
}


/* Check the options of a single component.  If CONF_FILE is NULL the
 * standard config file is used.  If OUT is not NULL the output is
 * written to that stream.  Returns 0 if everything is OK.  */
int
gc_component_check_options (int component, estream_t out, const char *conf_file)
{
  gpg_error_t err;
  unsigned int result;
  const char *pgmname;
  const char *argv[6];
  int i;
  pid_t pid;
  int exitcode;
  estream_t errfp;
  error_line_t errlines;

  log_assert (component >= 0 && component < GC_COMPONENT_NR);

  if (!gc_component[component].program)
    return 0;
  if (!gc_component[component].module_name)
    return 0;

  pgmname = gnupg_module_name (gc_component[component].module_name);
  i = 0;
  if (!gnupg_default_homedir_p ()
      && component != GC_COMPONENT_PINENTRY)
    {
      argv[i++] = "--homedir";
      argv[i++] = gnupg_homedir ();
    }
  if (conf_file)
    {
      argv[i++] = "--options";
      argv[i++] = conf_file;
    }
  if (component == GC_COMPONENT_PINENTRY)
    argv[i++] = "--version";
  else
    argv[i++] = "--gpgconf-test";
  argv[i] = NULL;
  log_assert (i < DIM(argv));

  result = 0;
  errlines = NULL;
  err = gnupg_spawn_process (pgmname, argv, NULL, 0,
                             NULL, NULL, &errfp, &pid);
  if (err)
    result |= 1; /* Program could not be run.  */
  else
    {
      errlines = collect_error_output (errfp,
				       gc_component[component].name);
      if (gnupg_wait_process (pgmname, pid, 1, &exitcode))
	{
	  if (exitcode == -1)
	    result |= 1; /* Program could not be run or it
			    terminated abnormally.  */
	  result |= 2; /* Program returned an error.  */
	}
      gnupg_release_process (pid);
      es_fclose (errfp);
    }

  /* If the program could not be run, we can't tell whether
     the config file is good.  */
  if (result & 1)
    result |= 2;

  if (out)
    {
      const char *desc;
      error_line_t errptr;

      desc = gc_component[component].desc;
      desc = my_dgettext (gc_component[component].desc_domain, desc);
      es_fprintf (out, "%s:%s:",
                  gc_component[component].program, gc_percent_escape (desc));
      es_fputs (gc_percent_escape (pgmname), out);
      es_fprintf (out, ":%d:%d:", !(result & 1), !(result & 2));
      for (errptr = errlines; errptr; errptr = errptr->next)
	{
	  if (errptr != errlines)
	    es_fputs ("\n:::::", out); /* Continuation line.  */
	  if (errptr->fname)
	    es_fputs (gc_percent_escape (errptr->fname), out);
	  es_putc (':', out);
	  if (errptr->fname)
	    es_fprintf (out, "%u", errptr->lineno);
	  es_putc (':', out);
	  es_fputs (gc_percent_escape (errptr->errtext), out);
	  es_putc (':', out);
	}
      es_putc ('\n', out);
    }

  while (errlines)
    {
      error_line_t tmp = errlines->next;
      xfree (errlines);
      errlines = tmp;
    }

  return result;
}



/* Check all components that are available.  */
void
gc_check_programs (estream_t out)
{
  gc_component_id_t component;

  for (component = 0; component < GC_COMPONENT_NR; component++)
    gc_component_check_options (component, out, NULL);
}



/* Find the component with the name NAME.  Returns -1 if not
   found.  */
int
gc_component_find (const char *name)
{
  gc_component_id_t idx;

  for (idx = 0; idx < GC_COMPONENT_NR; idx++)
    {
      if (gc_component[idx].program
          && !strcmp (name, gc_component[idx].program))
	return idx;
    }
  return -1;
}


/* List the option OPTION.  */
static void
list_one_option (gc_component_id_t component,
                 const gc_option_t *option, estream_t out)
{
  const char *desc = NULL;
  char *arg_name = NULL;
  unsigned long flags;
  const char *desc_domain = gc_component[component].desc_domain;

  /* Don't show options with the ignore attribute.  */
  if (option->attr_ignore && !option->attr_force)
    return;

  if (option->desc)
    {
      desc = my_dgettext (desc_domain, option->desc);

      if (*desc == '|')
	{
	  const char *arg_tail = strchr (&desc[1], '|');

	  if (arg_tail)
	    {
	      int arg_len = arg_tail - &desc[1];
	      arg_name = xmalloc (arg_len + 1);
	      memcpy (arg_name, &desc[1], arg_len);
	      arg_name[arg_len] = '\0';
	      desc = arg_tail + 1;
	    }
	}
    }


  /* YOU MUST NOT REORDER THE FIELDS IN THIS OUTPUT, AS THEIR ORDER IS
     PART OF THE EXTERNAL INTERFACE.  YOU MUST NOT REMOVE ANY
     FIELDS.  */

  /* The name field.  */
  es_fprintf (out, "%s", option->name);

  /* The flags field.  */
  flags = 0;
  if (option->is_header)   flags |= GC_OPT_FLAG_GROUP;
  if (option->is_list)     flags |= GC_OPT_FLAG_LIST;
  if (option->runtime)     flags |= GC_OPT_FLAG_RUNTIME;
  if (option->has_default) flags |= GC_OPT_FLAG_DEFAULT;
  if (option->def_in_desc) flags |= GC_OPT_FLAG_DEF_DESC;
  if (option->no_arg_desc) flags |= GC_OPT_FLAG_NO_ARG_DESC;
  if (option->no_change)   flags |= GC_OPT_FLAG_NO_CHANGE;
  if (option->attr_force)  flags |= GC_OPT_FLAG_NO_CHANGE;
  es_fprintf (out, ":%lu", flags);
  if (opt.verbose)
    {
      es_putc (' ', out);

      if (!flags)
	es_fprintf (out, "none");
      else
	{
	  unsigned long flag = 0;
	  unsigned long first = 1;

	  while (flags)
	    {
	      if (flags & 1)
		{
		  if (first)
		    first = 0;
		  else
		    es_putc (',', out);
		  es_fprintf (out, "%s", gc_flag[flag].name);
		}
	      flags >>= 1;
	      flag++;
	    }
	}
    }

  /* The level field.  */
  es_fprintf (out, ":%u", option->level);
  if (opt.verbose)
    es_fprintf (out, " %s", gc_level[option->level].name);

  /* The description field.  */
  es_fprintf (out, ":%s", desc ? gc_percent_escape (desc) : "");

  /* The type field.  */
  es_fprintf (out, ":%u", option->arg_type);
  if (opt.verbose)
    es_fprintf (out, " %s", gc_arg_type[option->arg_type].name);

  /* The alternate type field.  */
  es_fprintf (out, ":%u", gc_arg_type[option->arg_type].fallback);
  if (opt.verbose)
    es_fprintf (out, " %s",
                gc_arg_type[gc_arg_type[option->arg_type].fallback].name);

  /* The argument name field.  */
  es_fprintf (out, ":%s", arg_name ? gc_percent_escape (arg_name) : "");
  xfree (arg_name);

  /* The default value field.  */
  es_fprintf (out, ":%s", option->default_value ? option->default_value : "");

  /* The default argument field.  This was never used and is thus empty.  */
  es_fprintf (out, ":");

  /* The value field.  */
  if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_NONE
      && option->is_list && option->value)
    {
      /* The special format "1,1,1,1,...,1" is converted to a number
         here.  */
      es_fprintf (out, ":%u", (unsigned int)((strlen (option->value) + 1) / 2));
    }
  else
    es_fprintf (out, ":%s", option->value ? option->value : "");

  /* ADD NEW FIELDS HERE.  */

  es_putc ('\n', out);
}


/* List all options of the component COMPONENT.  */
void
gc_component_list_options (int component, estream_t out)
{
  const gc_option_t *option = gc_component[component].options;

  for ( ; option && option->name; option++)
    {
      /* Do not output unknown or internal options.  */
      if (!option->is_header
	  && option->level == GC_LEVEL_INTERNAL)
	  continue;

      if (option->is_header)
	{
	  const gc_option_t *group_option = option + 1;
	  gc_expert_level_t level = GC_LEVEL_NR;

	  /* The manual states that the group level is always the
	     minimum of the levels of all contained options.  Due to
	     different active options, and because it is hard to
	     maintain manually, we calculate it here.  The value in
	     the global static table is ignored.  */

	  for ( ; group_option->name; group_option++)
	    {
	      if (group_option->is_header)
		break;
	      if (group_option->level < level)
		level = group_option->level;
	    }

	  /* Check if group is empty.  */
	  if (level != GC_LEVEL_NR)
	    {
	      gc_option_t opt_copy;

	      /* Fix up the group level.  */
	      opt_copy = *option;
	      opt_copy.level = level;
	      list_one_option (component, &opt_copy, out);
	    }
	}
      else
	list_one_option (component, option, out);
    }
}


/* Return true if the option NAME is known and that we want it as
 * gpgconf managed option.  */
static known_option_t *
is_known_option (gc_component_id_t component, const char *name)
{
  known_option_t *option = gc_component[component].known_options;
  if (option)
    {
      for (; option->name; option++)
        if (!strcmp (option->name, name))
          break;
    }
  return (option && option->name)? option : NULL;
}


/* Find the option NAME in component COMPONENT.  Returns pointer to
 * the option descriptor or NULL if not found.  */
static gc_option_t *
find_option (gc_component_id_t component, const char *name)
{
  gc_option_t *option = gc_component[component].options;

  if (option)
    {
      for (; option->name; option++)
        {
          if (!option->is_header
              && !strcmp (option->name, name))
            return option;
        }
    }
  return NULL;
}




struct read_line_wrapper_parm_s
{
  const char *pgmname;
  estream_t fp;
  char *line;
  size_t line_len;
  const char **extra_lines;
  int extra_lines_idx;
  char *extra_line_buffer;
};


/* Helper for retrieve_options_from_program.  */
static ssize_t
read_line_wrapper (struct read_line_wrapper_parm_s *parm)
{
  ssize_t length;
  const char *extra_line;

  if (parm->fp)
    {
      length = es_read_line (parm->fp, &parm->line, &parm->line_len, NULL);
      if (length > 0)
        return length;
      if (length < 0 || es_ferror (parm->fp))
        gc_error (1, errno, "error reading from %s", parm->pgmname);
      if (es_fclose (parm->fp))
        gc_error (1, errno, "error closing %s", parm->pgmname);
      /* EOF seen.  */
      parm->fp = NULL;
    }
  /* Return the made up lines.  */
  if (!parm->extra_lines
      || !(extra_line = parm->extra_lines[parm->extra_lines_idx]))
    return -1;  /* This is really the EOF.  */
  parm->extra_lines_idx++;
  xfree (parm->extra_line_buffer);
  parm->extra_line_buffer = xstrdup (extra_line);
  return strlen (parm->extra_line_buffer);
}

/* Retrieve the options for the component COMPONENT.  With
 * ONLY_INSTALLED set components which are not installed are silently
 * ignored. */
static void
retrieve_options_from_program (gc_component_id_t component, int only_installed)
{
  gpg_error_t err;
  const char *pgmname;
  const char *argv[2];
  estream_t outfp;
  int exitcode;
  pid_t pid;
  known_option_t *known_option;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len;
  ssize_t length;
  const char *config_name;
  gpgrt_argparse_t pargs;
  int dummy_argc;
  char *twopartconfig_name = NULL;
  gpgrt_opt_t *opt_table = NULL;      /* A malloced option table.    */
  size_t opt_table_used = 0;          /* Its current length.         */
  size_t opt_table_size = 0;          /* Its allocated length.       */
  gc_option_t *opt_info = NULL;       /* A malloced options table.  */
  size_t opt_info_used = 0;           /* Its current length.         */
  size_t opt_info_size = 0;           /* Its allocated length.       */
  int i;
  struct read_line_wrapper_parm_s read_line_parm;
  int pseudo_count;

  pgmname = (gc_component[component].module_name
             ? gnupg_module_name (gc_component[component].module_name)
             : gc_component[component].program );

  if (only_installed && gnupg_access (pgmname, X_OK))
    {
      return;  /* The component is not installed.  */
    }


  /* First we need to read the option table from the program.  */
  argv[0] = "--dump-option-table";
  argv[1] = NULL;
  err = gnupg_spawn_process (pgmname, argv, NULL, 0,
                             NULL, &outfp, NULL, &pid);
  if (err)
    {
      gc_error (1, 0, "could not gather option table from '%s': %s",
                pgmname, gpg_strerror (err));
    }

  read_line_parm.pgmname = pgmname;
  read_line_parm.fp = outfp;
  read_line_parm.line = line;
  read_line_parm.line_len = line_len = 0;
  read_line_parm.extra_line_buffer = NULL;
  read_line_parm.extra_lines = gc_component[component].known_pseudo_options;
  read_line_parm.extra_lines_idx = 0;
  pseudo_count = 0;
  while ((length = read_line_wrapper (&read_line_parm)) > 0)
    {
      const char *fields[4];
      const char *optname, *optdesc;
      unsigned int optflags;
      int short_opt;
      gc_arg_type_t arg_type;
      int pseudo = 0;


      if (read_line_parm.extra_line_buffer)
        {
          line = read_line_parm.extra_line_buffer;
          pseudo = 1;
          pseudo_count++;
        }
      else
        line = read_line_parm.line;

      /* Strip newline and carriage return, if present.  */
      while (length > 0
	     && (line[length - 1] == '\n' || line[length - 1] == '\r'))
	line[--length] = '\0';

      if (split_fields_colon (line, fields, DIM (fields)) < 4)
        {
          gc_error (0,0, "WARNING: invalid line in option table of '%s'\n",
                    pgmname);
          continue;
        }

      optname = fields[0];
      short_opt = atoi (fields[1]);
      if (short_opt < 1 && !pseudo)
        {
          gc_error (0,0, "WARNING: bad short option in option table of '%s'\n",
                    pgmname);
          continue;
        }

      optflags = strtoul (fields[2], NULL, 10);
      if ((optflags & ARGPARSE_OPT_HEADER))
        known_option = NULL; /* We want all header-only options.  */
      else if ((known_option = is_known_option (component, optname)))
        ; /* Yes we want this one.  */
      else
        continue; /* No need to store this option description.  */

      /* The +1 here is to make sure that we will have a zero item at
       * the end of the table.  */
      if (opt_table_used + 1 >= opt_table_size)
        {
          /* Note that this also does the initial allocation.  */
          opt_table_size += 128;
          opt_table = xreallocarray (opt_table,
                                     opt_table_used,
                                     opt_table_size,
                                     sizeof *opt_table);
        }
      /* The +1 here is to make sure that we will have a zero item at
       * the end of the table.  */
      if (opt_info_used + 1 >= opt_info_size)
        {
          /* Note that this also does the initial allocation.  */
          opt_info_size += 128;
          opt_info = xreallocarray (opt_info,
                                    opt_info_used,
                                    opt_info_size,
                                    sizeof *opt_info);
        }
       /* The +1 here accounts for the two items we are going to add to
        * the global string table.  */
      if (string_array_used + 1 >= string_array_size)
        {
          string_array_size += 256;
          string_array = xreallocarray (string_array,
                                        string_array_used,
                                        string_array_size,
                                        sizeof *string_array);
        }
      optname = string_array[string_array_used++] = xstrdup (fields[0]);
      optdesc = string_array[string_array_used++] = xstrdup (fields[3]);

      /* Create an option table which can then be supplied to
       * gpgrt_parser.  Unfortunately there is no private pointer in
       * the public option table struct so that we can't add extra
       * data we need here.  Thus we need to build up another table
       * for such info and for ease of use we also copy the tehre the
       * data from the option table.  It is not possible to use the
       * known_option_s for this because that one does not carry
       * header lines and it might also be problematic to use such
       * static tables for caching options and default values.  */
      if (!pseudo)
        {
          opt_table[opt_table_used].long_opt = optname;
          opt_table[opt_table_used].short_opt = short_opt;
          opt_table[opt_table_used].description = optdesc;
          opt_table[opt_table_used].flags = optflags;
          opt_table_used++;
        }

      /* Note that as per argparser specs the opt_table uses "@" to
       * specifify an empty description.  In the DESC script of
       * options (opt_info_t) we want to have a real empty string.  */
      opt_info[opt_info_used].name = optname;
      if (*optdesc == '@' && !optdesc[1])
        opt_info[opt_info_used].desc = optdesc+1;
      else
        opt_info[opt_info_used].desc = optdesc;

      /* Unfortunately we need to remap the types.  */
      switch ((optflags & ARGPARSE_TYPE_MASK))
        {
        case ARGPARSE_TYPE_INT:    arg_type = GC_ARG_TYPE_INT32;  break;
        case ARGPARSE_TYPE_LONG:   arg_type = GC_ARG_TYPE_INT32;  break;
        case ARGPARSE_TYPE_ULONG:  arg_type = GC_ARG_TYPE_UINT32; break;
        case ARGPARSE_TYPE_STRING: arg_type = GC_ARG_TYPE_STRING; break;
        default:                   arg_type = GC_ARG_TYPE_NONE;   break;
        }
      opt_info[opt_info_used].arg_type = arg_type;
      if (pseudo) /* Pseudo options are always no_change.  */
        opt_info[opt_info_used].no_change = 1;


      if ((optflags & ARGPARSE_OPT_HEADER))
        opt_info[opt_info_used].is_header = 1;
      if (known_option)
        {
          if ((known_option->flags & GC_OPT_FLAG_LIST))
            opt_info[opt_info_used].is_list = 1;
          /* FIXME: The next can also be taken from opt_table->flags.
           * We need to check the code whether both specifications match.  */
          if ((known_option->flags & GC_OPT_FLAG_ARG_OPT))
            opt_info[opt_info_used].opt_arg = 1;

          if ((known_option->flags & GC_OPT_FLAG_RUNTIME))
            opt_info[opt_info_used].runtime = 1;

          opt_info[opt_info_used].level = known_option->level;
          /* Override the received argtype by a complex type.  */
          if (known_option->arg_type)
            opt_info[opt_info_used].arg_type = known_option->arg_type;
        }
      opt_info_used++;
    }
  xfree (read_line_parm.extra_line_buffer);
  line = read_line_parm.line;
  line_len = read_line_parm.line_len;
  log_assert (opt_table_used + pseudo_count == opt_info_used);


  err = gnupg_wait_process (pgmname, pid, 1, &exitcode);
  if (err)
    gc_error (1, 0, "running %s failed (exitcode=%d): %s",
              pgmname, exitcode, gpg_strerror (err));
  gnupg_release_process (pid);

  /* Make the gpgrt option table and the internal option table available.  */
  gc_component[component].opt_table = opt_table;
  gc_component[component].options = opt_info;


  /* Now read the default options.  */
  argv[0] = "--gpgconf-list";
  argv[1] = NULL;
  err = gnupg_spawn_process (pgmname, argv, NULL, 0,
                             NULL, &outfp, NULL, &pid);
  if (err)
    {
      gc_error (1, 0, "could not gather active options from '%s': %s",
                pgmname, gpg_strerror (err));
    }

  while ((length = es_read_line (outfp, &line, &line_len, NULL)) > 0)
    {
      char *linep;
      unsigned long flags = 0;
      char *default_value = NULL;

      /* Strip newline and carriage return, if present.  */
      while (length > 0
	     && (line[length - 1] == '\n' || line[length - 1] == '\r'))
	line[--length] = '\0';

      linep = strchr (line, ':');
      if (linep)
	*(linep++) = '\0';

      /* Extract additional flags.  Default to none.  */
      if (linep)
	{
	  char *end;
	  char *tail;

	  end = strchr (linep, ':');
	  if (end)
	    *(end++) = '\0';

	  gpg_err_set_errno (0);
	  flags = strtoul (linep, &tail, 0);
	  if (errno)
	    gc_error (1, errno, "malformed flags in option %s from %s",
                      line, pgmname);
	  if (!(*tail == '\0' || *tail == ':' || *tail == ' '))
	    gc_error (1, 0, "garbage after flags in option %s from %s",
                      line, pgmname);

	  linep = end;
	}

      /* Extract default value, if present.  Default to empty if
	 not.  */
      if (linep)
	{
	  char *end;

	  end = strchr (linep, ':');
	  if (end)
	    *(end++) = '\0';

	  if ((flags & GC_OPT_FLAG_DEFAULT))
	    default_value = linep;

	  linep = end;
	}

      /* Look up the option in the component and install the
	 configuration data.  */
      option = find_option (component, line);
      if (option)
	{
	  if (option->gpgconf_list)
	    gc_error (1, errno,
                      "option %s returned twice from \"%s --gpgconf-list\"",
		      line, pgmname);
	  option->gpgconf_list = 1;

          if ((flags & GC_OPT_FLAG_DEFAULT))
            option->has_default = 1;
          if ((flags & GC_OPT_FLAG_DEF_DESC))
            option->def_in_desc = 1;
          if ((flags & GC_OPT_FLAG_NO_ARG_DESC))
            option->no_arg_desc = 1;
          if ((flags & GC_OPT_FLAG_NO_CHANGE))
            option->no_change = 1;

	  if (default_value && *default_value)
	    option->default_value = xstrdup (default_value);
	}
    }
  if (length < 0 || es_ferror (outfp))
    gc_error (1, errno, "error reading from %s", pgmname);
  if (es_fclose (outfp))
    gc_error (1, errno, "error closing %s", pgmname);

  err = gnupg_wait_process (pgmname, pid, 1, &exitcode);
  if (err)
    gc_error (1, 0, "running %s failed (exitcode=%d): %s",
              pgmname, exitcode, gpg_strerror (err));
  gnupg_release_process (pid);


  /* At this point, we can parse the configuration file.  */
  config_name = gc_component[component].option_config_filename;
  if (!config_name)
    gc_error (1, 0, "name of config file for %s is not known\n", pgmname);

  if (!gnupg_default_homedir_p ())
    {
      /* This is not the default homedir.  We need to take an absolute
       * config name for the user config file; gpgrt_argparser
       * fortunately supports this.  */
      char *tmp = make_filename (gnupg_homedir (), config_name, NULL);
      twopartconfig_name = xstrconcat (config_name, PATHSEP_S, tmp, NULL);
      xfree (tmp);
      config_name = twopartconfig_name;
    }

  memset (&pargs, 0, sizeof pargs);
  dummy_argc = 0;
  pargs.argc = &dummy_argc;
  pargs.flags = (ARGPARSE_FLAG_KEEP
                 | ARGPARSE_FLAG_SYS
                 | ARGPARSE_FLAG_USER
                 | ARGPARSE_FLAG_WITHATTR);
  if (opt.verbose)
    pargs.flags |= ARGPARSE_FLAG_VERBOSE;

  while (gpgrt_argparser (&pargs, opt_table, config_name))
    {
      char *opt_value;

      if (pargs.r_opt == ARGPARSE_CONFFILE)
        {
          /* log_debug ("current conffile='%s'\n", */
          /*            pargs.r_type? pargs.r.ret_str: "[cmdline]"); */
          continue;
        }
      if ((pargs.r_type & ARGPARSE_OPT_IGNORE))
        continue;

      /* We only have the short option.  Search in the option table
       * for the long option name.  */
      for (i=0; opt_table[i].short_opt; i++)
        if (opt_table[i].short_opt == pargs.r_opt)
          break;
      if (!opt_table[i].short_opt || !opt_table[i].long_opt)
        continue;  /* No or only a short option - ignore.  */

      /* Look up the option from the config file in our list of
       * supported options.  */
      option= find_option (component, opt_table[i].long_opt);
      if (!option)
        continue;  /* We don't want to handle this option.  */

      /* Set the force and ignore attributes.  The idea is that there
       * is no way to clear them again, thus we set them when first
       * encountered.  */
      if ((pargs.r_type & ARGPARSE_ATTR_FORCE))
        option->attr_force  = 1;
      if ((pargs.r_type & ARGPARSE_ATTR_IGNORE))
        option->attr_ignore = 1;

      /* If an option has been ignored, there is no need to return
       * that option with gpgconf --list-options.  */
      if (option->attr_ignore)
        continue;

      switch ((pargs.r_type & ARGPARSE_TYPE_MASK))
        {
        case ARGPARSE_TYPE_INT:
          opt_value = xasprintf ("%d", pargs.r.ret_int);
          break;
        case ARGPARSE_TYPE_LONG:
          opt_value = xasprintf ("%ld", pargs.r.ret_long);
          break;
        case ARGPARSE_TYPE_ULONG:
          opt_value = xasprintf ("%lu", pargs.r.ret_ulong);
          break;
        case ARGPARSE_TYPE_STRING:
          if (!pargs.r.ret_str)
            opt_value = xstrdup ("\"(none)"); /* We should not see this.  */
          else
            opt_value = xasprintf ("\"%s", gc_percent_escape (pargs.r.ret_str));
          break;
        default: /* ARGPARSE_TYPE_NONE or any unknown type.  */
          opt_value = xstrdup ("1");  /* Make sure we have some value.  */
          break;
        }

      /* Now enter the value read from the config file into the table.  */
      if (!option->is_list)
        {
          xfree (option->value);
          option->value = opt_value;
        }
      else if (!option->value)  /* LIST but first item.  */
        option->value = opt_value;
      else
        {
          char *old = option->value;
          option->value = xstrconcat (old, ",", opt_value, NULL);
          xfree (old);
          xfree (opt_value);
        }
    }

  xfree (line);
  xfree (twopartconfig_name);
}



/* Retrieve the currently active options and their defaults for this
   component.  Using -1 for component will retrieve all options from
   all installed components. */
void
gc_component_retrieve_options (int component)
{
  int process_all = 0;

  if (component == -1)
    {
      process_all = 1;
      component = 0;
    }

  do
    {
      if (component == GC_COMPONENT_PINENTRY)
        continue; /* Skip this dummy component.  */

      if (gc_component[component].program)
        retrieve_options_from_program (component, process_all);
    }
  while (process_all && ++component < GC_COMPONENT_NR);

}



/* Perform a simple validity check based on the type.  Return in
 * NEW_VALUE_NR the value of the number in NEW_VALUE if OPTION is of
 * type GC_ARG_TYPE_NONE.  If VERBATIM is set the profile parsing mode
 * is used. */
static void
option_check_validity (gc_component_id_t component,
                       gc_option_t *option, unsigned long flags,
		       char *new_value, unsigned long *new_value_nr,
                       int verbatim)
{
  char *arg;

  (void)component;

  if (option->new_flags || option->new_value)
    gc_error (1, 0, "option %s already changed", option->name);

  if (flags & GC_OPT_FLAG_DEFAULT)
    {
      if (*new_value)
	gc_error (1, 0, "argument %s provided for deleted option %s",
		  new_value, option->name);

      return;
    }

  /* GC_ARG_TYPE_NONE options have special list treatment.  */
  if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_NONE)
    {
      char *tail;

      gpg_err_set_errno (0);
      *new_value_nr = strtoul (new_value, &tail, 0);

      if (errno)
	gc_error (1, errno, "invalid argument for option %s",
		  option->name);
      if (*tail)
	gc_error (1, 0, "garbage after argument for option %s",
		      option->name);

      if (!option->is_list)
	{
	  if (*new_value_nr != 1)
	    gc_error (1, 0, "argument for non-list option %s of type 0 "
		      "(none) must be 1", option->name);
	}
      else
	{
	  if (*new_value_nr == 0)
	    gc_error (1, 0, "argument for option %s of type 0 (none) "
		      "must be positive", option->name);
	}

      return;
    }

  arg = new_value;
  do
    {
      if (*arg == '\0' || (*arg == ',' && !verbatim))
	{
	  if (!option->opt_arg)
	    gc_error (1, 0, "argument required for option %s", option->name);

	  if (*arg == ',' && !verbatim && !option->is_list)
	    gc_error (1, 0, "list found for non-list option %s", option->name);
	}
      else if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_STRING)
	{
	  if (*arg != '"' && !verbatim)
	    gc_error (1, 0, "string argument for option %s must begin "
		      "with a quote (\") character", option->name);

	  /* FIXME: We do not allow empty string arguments for now, as
	     we do not quote arguments in configuration files, and
	     thus no argument is indistinguishable from the empty
	     string.  */
	  if (arg[1] == '\0' || (arg[1] == ',' && !verbatim))
	    gc_error (1, 0, "empty string argument for option %s is "
		      "currently not allowed.  Please report this!",
		      option->name);
	}
      else if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_INT32)
	{
	  long res;

	  gpg_err_set_errno (0);
	  res = strtol (arg, &arg, 0);
	  (void) res;

	  if (errno)
	    gc_error (1, errno, "invalid argument for option %s",
		      option->name);

	  if (*arg != '\0' && (*arg != ',' || verbatim))
	    gc_error (1, 0, "garbage after argument for option %s",
		      option->name);
	}
      else if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_UINT32)
	{
	  unsigned long res;

	  gpg_err_set_errno (0);
	  res = strtoul (arg, &arg, 0);
	  (void) res;

	  if (errno)
	    gc_error (1, errno, "invalid argument for option %s",
		      option->name);

	  if (*arg != '\0' && (*arg != ',' || verbatim))
	    gc_error (1, 0, "garbage after argument for option %s",
		      option->name);
	}
      arg = verbatim? strchr (arg, ',') : NULL;
      if (arg)
	arg++;
    }
  while (arg && *arg);
}

#ifdef HAVE_W32_SYSTEM
int
copy_file (const char *src_name, const char *dst_name)
{
#define BUF_LEN 4096
  char buffer[BUF_LEN];
  int len;
  gpgrt_stream_t src;
  gpgrt_stream_t dst;

  src = gpgrt_fopen (src_name, "r");
  if (src == NULL)
    return -1;

  dst = gpgrt_fopen (dst_name, "w");
  if (dst == NULL)
    {
      int saved_err = errno;
      gpgrt_fclose (src);
      gpg_err_set_errno (saved_err);
      return -1;
    }

  do
    {
      int written;

      len = gpgrt_fread (buffer, 1, BUF_LEN, src);
      if (len == 0)
	break;
      written = gpgrt_fwrite (buffer, 1, len, dst);
      if (written != len)
	break;
    }
  while (! gpgrt_feof (src) && ! gpgrt_ferror (src) && ! gpgrt_ferror (dst));

  if (gpgrt_ferror (src) || gpgrt_ferror (dst) || ! gpgrt_feof (src))
    {
      int saved_errno = errno;
      gpgrt_fclose (src);
      gpgrt_fclose (dst);
      unlink (dst_name);
      gpg_err_set_errno (saved_errno);
      return -1;
    }

  if (gpgrt_fclose (dst))
    gc_error (1, errno, "error closing %s", dst_name);
  if (gpgrt_fclose (src))
    gc_error (1, errno, "error closing %s", src_name);

  return 0;
}
#endif /* HAVE_W32_SYSTEM */


/* Create and verify the new configuration file for the specified
 *  component.  Returns 0 on success and -1 on error.  If
 * VERBATIM is set the profile mode is used.  This function may store
 * pointers to malloced strings in SRC_FILENAMEP, DEST_FILENAMEP, and
 * ORIG_FILENAMEP.  Those must be freed by the caller.  The strings
 * refer to three versions of the configuration file:
 *
 * SRC_FILENAME:  The updated configuration is written to this file.
 * DEST_FILENAME: Name of the configuration file read by the
 *                component.
 * ORIG_FILENAME: A backup of the previous configuration file.
 *
 * To apply the configuration change, rename SRC_FILENAME to
 * DEST_FILENAME.  To revert to the previous configuration, rename
 * ORIG_FILENAME to DEST_FILENAME.  */
static int
change_options_program (gc_component_id_t component,
			char **src_filenamep, char **dest_filenamep,
			char **orig_filenamep,
                        int verbatim)
{
  static const char marker[] = "###+++--- " GPGCONF_DISP_NAME " ---+++###";
  /* True if we are within the marker in the config file.  */
  int in_marker = 0;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len;
  ssize_t length;
  int res;
  int fd;
  gpgrt_stream_t src_file = NULL;
  gpgrt_stream_t dest_file = NULL;
  char *src_filename;
  char *dest_filename;
  char *orig_filename;
  /* Special hack for gpg, see below.  */
  int utf8strings_seen = 0;


  /* FIXME.  Throughout the function, do better error reporting.  */
  if (!gc_component[component].option_config_filename)
    gc_error (1, 0, "name of config file for %s is not known\n",
              gc_component[component].name);

  dest_filename = make_absfilename
    (gnupg_homedir (), gc_component[component].option_config_filename, NULL);
  src_filename = xasprintf ("%s.%s.%i.new",
                            dest_filename, GPGCONF_NAME, (int)getpid ());
  orig_filename = xasprintf ("%s.%s.%i.bak",
                             dest_filename, GPGCONF_NAME, (int)getpid ());

#ifdef HAVE_W32_SYSTEM
  res = copy_file (dest_filename, orig_filename);
#else
  res = link (dest_filename, orig_filename);
#endif
  if (res < 0 && errno != ENOENT)
    {
      xfree (dest_filename);
      xfree (src_filename);
      xfree (orig_filename);
      return -1;
    }
  if (res < 0)
    {
      xfree (orig_filename);
      orig_filename = NULL;
    }

  /* We now initialize the return strings, so the caller can do the
     cleanup for us.  */
  *src_filenamep = src_filename;
  *dest_filenamep = dest_filename;
  *orig_filenamep = orig_filename;

  /* Use open() so that we can use O_EXCL.
   * FIXME: gpgrt has an x flag for quite some time now - use that.  */
  fd = gnupg_open (src_filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (fd < 0)
    return -1;
  src_file = gpgrt_fdopen (fd, "w");
  res = errno;
  if (!src_file)
    {
      gpg_err_set_errno (res);
      return -1;
    }

  /* Only if ORIG_FILENAME is not NULL did the configuration file
     exist already.  In this case, we will copy its content into the
     new configuration file, changing it to our liking in the
     process.  */
  if (orig_filename)
    {
      dest_file = gpgrt_fopen (dest_filename, "r");
      if (!dest_file)
	goto change_one_err;

      while ((length = gpgrt_read_line (dest_file, &line, &line_len, NULL)) > 0)
	{
	  int disable = 0;
	  char *start;

	  if (!strncmp (marker, line, sizeof (marker) - 1))
	    {
	      if (!in_marker)
		in_marker = 1;
	      else
		break;
	    }
	  else if (component == GC_COMPONENT_GPG && in_marker
		   && ! strcmp ("utf8-strings\n", line))
	    {
	      /* Strip duplicated entries.  */
	      if (utf8strings_seen)
		disable = 1;
	      else
		utf8strings_seen = 1;
	    }

	  start = line;
	  while (*start == ' ' || *start == '\t')
	    start++;
	  if (*start && *start != '\r' && *start != '\n' && *start != '#')
	    {
	      char *end;
	      char saved_end;

	      end = start;
	      while (*end && *end != ' ' && *end != '\t'
		     && *end != '\r' && *end != '\n' && *end != '#')
		end++;
	      saved_end = *end;
	      *end = '\0';

	      option = find_option (component, start);
	      *end = saved_end;
	      if (option && ((option->new_flags & GC_OPT_FLAG_DEFAULT)
			     || option->new_value))
		disable = 1;
	    }
	  if (disable)
	    {
	      if (!in_marker)
		{
		  gpgrt_fprintf (src_file,
			   "# %s disabled this option here at %s\n",
			   GPGCONF_DISP_NAME, asctimestamp (gnupg_get_time ()));
		  if (gpgrt_ferror (src_file))
		    goto change_one_err;
		  gpgrt_fprintf (src_file, "# %s", line);
		  if (gpgrt_ferror (src_file))
		    goto change_one_err;
		}
	    }
	  else
	    {
	      gpgrt_fprintf (src_file, "%s", line);
	      if (gpgrt_ferror (src_file))
		goto change_one_err;
	    }
	}
      if (length < 0 || gpgrt_ferror (dest_file))
	goto change_one_err;
    }

  if (!in_marker)
    {
      /* There was no marker.  This is the first time we edit the
	 file.  We add our own marker at the end of the file and
	 proceed.  Note that we first write a newline, this guards us
	 against files which lack the newline at the end of the last
	 line, while it doesn't hurt us in all other cases.  */
      gpgrt_fprintf (src_file, "\n%s\n", marker);
      if (gpgrt_ferror (src_file))
	goto change_one_err;
    }
  /* At this point, we have copied everything up to the end marker
     into the new file, except for the options we are going to change.
     Now, dump the changed options (except for those we are going to
     revert to their default), and write the end marker, possibly
     followed by the rest of the original file.  */

  /* We have to turn on UTF8 strings for GnuPG.  */
  if (component == GC_COMPONENT_GPG && ! utf8strings_seen)
    gpgrt_fprintf (src_file, "utf8-strings\n");

  option = gc_component[component].options;
  for ( ; option->name; option++)
    {
      if (!option->is_header && option->new_value)
	{
	  char *arg = option->new_value;

	  do
	    {
	      if (*arg == '\0' || *arg == ',')
		{
		  gpgrt_fprintf (src_file, "%s\n", option->name);
		  if (gpgrt_ferror (src_file))
		    goto change_one_err;
		}
	      else if (gc_arg_type[option->arg_type].fallback
		       == GC_ARG_TYPE_NONE)
		{
		  log_assert (*arg == '1');
		  gpgrt_fprintf (src_file, "%s\n", option->name);
		  if (gpgrt_ferror (src_file))
		    goto change_one_err;

		  arg++;
		}
	      else if (gc_arg_type[option->arg_type].fallback
		       == GC_ARG_TYPE_STRING)
		{
		  char *end;

                  if (!verbatim)
                    {
                      log_assert (*arg == '"');
                      arg++;

                      end = strchr (arg, ',');
                      if (end)
                        *end = '\0';
                    }
                  else
                    end = NULL;

		  gpgrt_fprintf (src_file, "%s %s\n", option->name,
			   verbatim? arg : percent_deescape (arg));
		  if (gpgrt_ferror (src_file))
		    goto change_one_err;

		  if (end)
		    *end = ',';
		  arg = end;
		}
	      else
		{
		  char *end;

		  end = strchr (arg, ',');
		  if (end)
		    *end = '\0';

		  gpgrt_fprintf (src_file, "%s %s\n", option->name, arg);
		  if (gpgrt_ferror (src_file))
		    goto change_one_err;

		  if (end)
		    *end = ',';
		  arg = end;
		}

	      log_assert (arg == NULL || *arg == '\0' || *arg == ',');
	      if (arg && *arg == ',')
		arg++;
	    }
	  while (arg && *arg);
	}
    }

  gpgrt_fprintf (src_file, "%s %s\n", marker, asctimestamp (gnupg_get_time ()));
  if (gpgrt_ferror (src_file))
    goto change_one_err;

  if (!in_marker)
    {
      gpgrt_fprintf (src_file, "# %s edited this configuration file.\n",
               GPGCONF_DISP_NAME);
      if (gpgrt_ferror (src_file))
	goto change_one_err;
      gpgrt_fprintf (src_file, "# It will disable options before this marked "
	       "block, but it will\n");
      if (gpgrt_ferror (src_file))
	goto change_one_err;
      gpgrt_fprintf (src_file, "# never change anything below these lines.\n");
      if (gpgrt_ferror (src_file))
	goto change_one_err;
    }
  if (dest_file)
    {
      while ((length = gpgrt_read_line (dest_file, &line, &line_len, NULL)) > 0)
	{
	  gpgrt_fprintf (src_file, "%s", line);
	  if (gpgrt_ferror (src_file))
	    goto change_one_err;
	}
      if (length < 0 || gpgrt_ferror (dest_file))
	goto change_one_err;
    }
  xfree (line);
  line = NULL;

  res = gpgrt_fclose (src_file);
  if (res)
    {
      res = errno;
      close (fd);
      if (dest_file)
	gpgrt_fclose (dest_file);
      gpg_err_set_errno (res);
      return -1;
    }
  close (fd);
  if (dest_file)
    {
      res = gpgrt_fclose (dest_file);
      if (res)
	return -1;
    }
  return 0;

 change_one_err:
  xfree (line);
  res = errno;
  if (src_file)
    {
      gpgrt_fclose (src_file);
      close (fd);
    }
  if (dest_file)
    gpgrt_fclose (dest_file);
  gpg_err_set_errno (res);
  return -1;
}


/* Common code for gc_component_change_options and
 * gc_process_gpgconf_conf.  If VERBATIM is set the profile parsing
 * mode is used.  */
static void
change_one_value (gc_component_id_t component,
                  gc_option_t *option, int *r_runtime,
                  unsigned long flags, char *new_value, int verbatim)
{
  unsigned long new_value_nr = 0;

  option_check_validity (component, option,
                         flags, new_value, &new_value_nr, verbatim);

  if (option->runtime)
    *r_runtime = 1;

  option->new_flags = flags;
  if (!(flags & GC_OPT_FLAG_DEFAULT))
    {
      if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_NONE
          && option->is_list)
        {
          char *str;

          /* We convert the number to a list of 1's for convenient
             list handling.  */
          log_assert (new_value_nr > 0);
          option->new_value = xmalloc ((2 * (new_value_nr - 1) + 1) + 1);
          str = option->new_value;
          *(str++) = '1';
          while (--new_value_nr > 0)
            {
              *(str++) = ',';
              *(str++) = '1';
            }
          *(str++) = '\0';
        }
      else
        option->new_value = xstrdup (new_value);
    }
}


/* Read the modifications from IN and apply them.  If IN is NULL the
   modifications are expected to already have been set to the global
   table.  If VERBATIM is set the profile mode is used.  */
void
gc_component_change_options (int component, estream_t in, estream_t out,
                             int verbatim)
{
  int err = 0;
  int block = 0;
  int runtime = 0;
  char *src_filename = NULL;
  char *dest_filename = NULL;
  char *orig_filename = NULL;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;

  if (component == GC_COMPONENT_PINENTRY)
    return; /* Dummy component for now.  */

  if (in)
    {
      /* Read options from the file IN.  */
      while ((length = es_read_line (in, &line, &line_len, NULL)) > 0)
        {
          char *linep;
          unsigned long flags = 0;
          char *new_value = "";

          /* Strip newline and carriage return, if present.  */
          while (length > 0
                 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';

          linep = strchr (line, ':');
          if (linep)
            *(linep++) = '\0';

          /* Extract additional flags.  Default to none.  */
          if (linep)
            {
              char *end;
              char *tail;

              end = strchr (linep, ':');
              if (end)
                *(end++) = '\0';

              gpg_err_set_errno (0);
              flags = strtoul (linep, &tail, 0);
              if (errno)
                gc_error (1, errno, "malformed flags in option %s", line);
              if (!(*tail == '\0' || *tail == ':' || *tail == ' '))
                gc_error (1, 0, "garbage after flags in option %s", line);

              linep = end;
            }

          /* Don't allow setting of the no change flag.  */
          flags &= ~GC_OPT_FLAG_NO_CHANGE;

          /* Extract default value, if present.  Default to empty if not.  */
          if (linep)
            {
              char *end;
              end = strchr (linep, ':');
              if (end)
                *(end++) = '\0';
              new_value = linep;
              linep = end;
            }

          option = find_option (component, line);
          if (!option)
            gc_error (1, 0, "unknown option %s", line);

          if (option->no_change)
            {
              gc_error (0, 0, "ignoring new value for option %s",
                        option->name);
              continue;
            }

          change_one_value (component, option, &runtime, flags, new_value, 0);
        }
      if (length < 0 || gpgrt_ferror (in))
	gc_error (1, errno, "error reading stream 'in'");
    }

  /* Now that we have collected and locally verified the changes,
     write them out to new configuration files, verify them
     externally, and then commit them.  */
  option = gc_component[component].options;
  while (option && option->name)
    {
      /* Go on if there is nothing to do.  */
      if (src_filename || !(option->new_flags || option->new_value))
	{
	  option++;
	  continue;
	}

      if (gc_component[component].program)
	{
	  err = change_options_program (component,
					&src_filename,
					&dest_filename,
					&orig_filename,
                                        verbatim);
	  if (! err)
	    {
	      /* External verification.  */
	      err = gc_component_check_options (component, out, src_filename);
	      if (err)
		{
		  gc_error (0, 0,
			    _("External verification of component %s failed"),
			    gc_component[component].name);
		  gpg_err_set_errno (EINVAL);
		}
	    }

	}
      if (err)
	break;

      option++;
    }

  /* We are trying to atomically commit all changes.  Unfortunately,
     we cannot rely on gnupg_rename_file to manage the signals for us,
     doing so would require us to pass NULL as BLOCK to any subsequent
     call to it.  Instead, we just manage the signal handling
     manually.  */
  block = 1;
  gnupg_block_all_signals ();

  if (!err && !opt.dry_run)
    {
      if (src_filename)
        {
          /* FIXME: Make a verification here.  */

          log_assert (dest_filename);

          if (orig_filename)
            err = gnupg_rename_file (src_filename, dest_filename, NULL);
          else
            {
#ifdef HAVE_W32_SYSTEM
              /* We skip the unlink if we expect the file not to be
               * there.  */
              err = gnupg_rename_file (src_filename, dest_filename, NULL);
#else /* HAVE_W32_SYSTEM */
              /* This is a bit safer than rename() because we expect
               * DEST_FILENAME not to be there.  If it happens to be
               * there, this will fail.  */
              err = link (src_filename, dest_filename);
              if (!err)
                err = unlink (src_filename);
#endif /* !HAVE_W32_SYSTEM */
            }
          if (!err)
            {
              xfree (src_filename);
              src_filename = NULL;
            }
        }
    }

  if (err || opt.dry_run)
    {
      int saved_errno = errno;

      /* An error occurred or a dry-run is requested.  */
      if (src_filename)
        {
          /* The change was not yet committed.  */
          unlink (src_filename);
          if (orig_filename)
            unlink (orig_filename);
        }
      else
        {
          /* The changes were already committed.  FIXME: This is a tad
             dangerous, as we don't know if we don't overwrite a
             version of the file that is even newer than the one we
             just installed.  */
          if (orig_filename)
            gnupg_rename_file (orig_filename, dest_filename, NULL);
          else
            unlink (dest_filename);
        }
      if (err)
	gc_error (1, saved_errno, "could not commit changes");

      /* Fall-through for dry run.  */
      goto leave;
    }

  /* If it all worked, notify the daemons of the changes.  */
  if (opt.runtime)
    do_runtime_change (component, 0);


  /* Move the per-process backup file into its place.  */
  if (orig_filename)
    {
      char *backup_filename;

      log_assert (dest_filename);

      backup_filename = xasprintf ("%s.%s.bak",
                                   dest_filename, GPGCONF_NAME);
      gnupg_rename_file (orig_filename, backup_filename, NULL);
      xfree (backup_filename);
    }

 leave:
  if (block)
    gnupg_unblock_all_signals ();
  xfree (line);
  xfree (src_filename);
  xfree (dest_filename);
  xfree (orig_filename);
}


/* Check whether USER matches the current user or one of its group.
   This function may change USER.  Returns true is there is a
   match.  */
static int
key_matches_user_or_group (char *user)
{
  char *group;

  if (*user == '*' && user[1] == 0)
    return 1; /* A single asterisk matches all users.  */

  group = strchr (user, ':');
  if (group)
    *group++ = 0;

#ifdef HAVE_W32_SYSTEM
  /* Under Windows we don't support groups. */
  if (group && *group)
    gc_error (0, 0, _("Note that group specifications are ignored\n"));

  if (*user)
    {
      static char *my_name;

      if (!my_name)
        {
          char tmp[1];
          DWORD size = 1;

          GetUserNameA (tmp, &size);
          my_name = xmalloc (size);
          if (!GetUserNameA (my_name, &size))
            gc_error (1,0, "error getting current user name: %s",
                      w32_strerror (-1));
        }

      if (!strcmp (user, my_name))
        return 1; /* Found.  */
    }

#else /*!HAVE_W32_SYSTEM*/

  /* First check whether the user matches.  */
  if (*user)
    {
      static char *my_name;

      if (!my_name)
        {
          struct passwd *pw = getpwuid ( getuid () );
          if (!pw)
            gc_error (1, errno, "getpwuid failed for current user");
          my_name = xstrdup (pw->pw_name);
        }
      if (!strcmp (user, my_name))
        return 1; /* Found.  */
    }

  /* If that failed, check whether a group matches.  */
  if (group && *group)
    {
      static char *my_group;
      static char **my_supgroups;
      int n;

      if (!my_group)
        {
          struct group *gr = getgrgid ( getgid () );
          if (!gr)
            gc_error (1, errno, "getgrgid failed for current user");
          my_group = xstrdup (gr->gr_name);
        }
      if (!strcmp (group, my_group))
        return 1; /* Found.  */

      if (!my_supgroups)
        {
          int ngids;
          gid_t *gids;

          ngids = getgroups (0, NULL);
          gids  = xcalloc (ngids+1, sizeof *gids);
          ngids = getgroups (ngids, gids);
          if (ngids < 0)
            gc_error (1, errno, "getgroups failed for current user");
          my_supgroups = xcalloc (ngids+1, sizeof *my_supgroups);
          for (n=0; n < ngids; n++)
            {
              struct group *gr = getgrgid ( gids[n] );
              if (!gr)
                gc_error (1, errno, "getgrgid failed for supplementary group");
              my_supgroups[n] = xstrdup (gr->gr_name);
            }
          xfree (gids);
        }

      for (n=0; my_supgroups[n]; n++)
        if (!strcmp (group, my_supgroups[n]))
          return 1; /* Found.  */
    }

#endif /*!HAVE_W32_SYSTEM*/

  return 0; /* No match.  */
}



/* Read and process the global configuration file for gpgconf.  This
   optional file is used to update our internal tables at runtime and
   may also be used to set new default values.  If FNAME is NULL the
   default name will be used.  With UPDATE set to true the internal
   tables are actually updated; if not set, only a syntax check is
   done.  If DEFAULTS is true the global options are written to the
   configuration files.  If LISTFP is set, no changes are done but the
   configuration file is printed to LISTFP in a colon separated format.

   Returns 0 on success or if the config file is not present; -1 is
   returned on error. */
int
gc_process_gpgconf_conf (const char *fname_arg, int update, int defaults,
                         estream_t listfp)
{
  int result = 0;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  gpgrt_stream_t config;
  int lineno = 0;
  int in_rule = 0;
  int got_match = 0;
  int runtime[GC_COMPONENT_NR] = { 0 };
  int component_id;
  char *fname;

  if (fname_arg)
    fname = xstrdup (fname_arg);
  else
    fname = make_filename (gnupg_sysconfdir (), GPGCONF_NAME EXTSEP_S "conf",
                           NULL);

  config = gpgrt_fopen (fname, "r");
  if (!config)
    {
      /* Do not print an error if the file is not available, except
         when running in syntax check mode.  */
      if (errno != ENOENT || !update)
        {
          gc_error (0, errno, "can't open global config file '%s'", fname);
          result = -1;
        }
      xfree (fname);
      return result;
    }

  while ((length = gpgrt_read_line (config, &line, &line_len, NULL)) > 0)
    {
      char *key, *compname, *option, *flags, *value;
      char *empty;
      gc_option_t *option_info = NULL;
      char *p;
      int is_continuation;

      lineno++;
      key = line;
      while (*key == ' ' || *key == '\t')
        key++;
      if (!*key || *key == '#' || *key == '\r' || *key == '\n')
        continue;

      is_continuation = (key != line);

      /* Parse the key field.  */
      if (!is_continuation && got_match)
        break;  /* Finish after the first match.  */
      else if (!is_continuation)
        {
          in_rule = 0;
          for (p=key+1; *p && !strchr (" \t\r\n", *p); p++)
            ;
          if (!*p)
            {
              gc_error (0, 0, "missing rule at '%s', line %d", fname, lineno);
              result = -1;
              gpgconf_write_status (STATUS_WARNING,
                                    "gpgconf.conf %d file '%s' line %d "
                                    "missing rule",
                                    GPG_ERR_SYNTAX, fname, lineno);
              continue;
            }
          *p++ = 0;
          compname = p;
        }
      else if (!in_rule)
        {
          gc_error (0, 0, "continuation but no rule at '%s', line %d",
                    fname, lineno);
          result = -1;
          continue;
        }
      else
        {
          compname = key;
          key = NULL;
        }

      in_rule = 1;

      /* Parse the component.  */
      while (*compname == ' ' || *compname == '\t')
        compname++;
      for (p=compname; *p && !strchr (" \t\r\n", *p); p++)
        ;
      if (p == compname)
        {
          gc_error (0, 0, "missing component at '%s', line %d",
                    fname, lineno);
          gpgconf_write_status (STATUS_WARNING,
                                "gpgconf.conf %d file '%s' line %d "
                                " missing component",
                                GPG_ERR_NO_NAME, fname, lineno);
          result = -1;
          continue;
        }
      empty = p;
      *p++ = 0;
      option = p;
      component_id = gc_component_find (compname);
      if (component_id < 0)
        {
          gc_error (0, 0, "unknown component at '%s', line %d",
                    fname, lineno);
          gpgconf_write_status (STATUS_WARNING,
                                "gpgconf.conf %d file '%s' line %d "
                                "unknown component",
                                GPG_ERR_UNKNOWN_NAME, fname, lineno);
          result = -1;
        }

      /* Parse the option name.  */
      while (*option == ' ' || *option == '\t')
        option++;
      for (p=option; *p && !strchr (" \t\r\n", *p); p++)
        ;
      if (p == option)
        {
          gc_error (0, 0, "missing option at '%s', line %d",
                    fname, lineno);
          gpgconf_write_status (STATUS_WARNING,
                                "gpgconf.conf %d file '%s' line %d "
                                "missing option",
                                GPG_ERR_INV_NAME, fname, lineno);
          result = -1;
          continue;
        }
      *p++ = 0;
      flags = p;
      if ( component_id != -1)
        {
          /* We need to make sure that we got the option list for the
           * component.  */
          if (!gc_component[component_id].options)
            gc_component_retrieve_options (component_id);
          option_info = find_option (component_id, option);
          if (!option_info)
            {
              gc_error (0, 0, "unknown option '%s' at '%s', line %d",
                        option, fname, lineno);
              gpgconf_write_status (STATUS_WARNING,
                                    "gpgconf.conf %d file '%s' line %d "
                                    "unknown option",
                                    GPG_ERR_UNKNOWN_OPTION, fname, lineno);
              result = -1;
            }
        }


      /* Parse the optional flags.  */
      while (*flags == ' ' || *flags == '\t')
        flags++;
      if (*flags == '[')
        {
          flags++;
          p = strchr (flags, ']');
          if (!p)
            {
              gc_error (0, 0, "syntax error in rule at '%s', line %d",
                        fname, lineno);
              gpgconf_write_status (STATUS_WARNING,
                                    "gpgconf.conf %d file '%s' line %d "
                                    "syntax error in rule",
                                    GPG_ERR_SYNTAX, fname, lineno);
              result = -1;
              continue;
            }
          *p++ = 0;
          value = p;
        }
      else  /* No flags given.  */
        {
          value = flags;
          flags = NULL;
        }

      /* Parse the optional value.  */
      while (*value == ' ' || *value == '\t')
       value++;
      for (p=value; *p && !strchr ("\r\n", *p); p++)
        ;
      if (p == value)
        value = empty; /* No value given; let it point to an empty string.  */
      else
        {
          /* Strip trailing white space.  */
          *p = 0;
          for (p--; p > value && (*p == ' ' || *p == '\t'); p--)
            *p = 0;
        }

      /* Check flag combinations.  */
      if (!flags)
        ;
      else if (!strcmp (flags, "default"))
        {
          if (*value)
            {
              gc_error (0, 0, "flag \"default\" may not be combined "
                        "with a value at '%s', line %d",
                        fname, lineno);
              result = -1;
            }
        }
      else if (!strcmp (flags, "change"))
        ;
      else if (!strcmp (flags, "no-change"))
        ;
      else
        {
          gc_error (0, 0, "unknown flag at '%s', line %d",
                    fname, lineno);
          result = -1;
        }

      /* In list mode we print out all records.  */
      if (listfp && !result)
        {
          /* If this is a new ruleset, print a key record.  */
          if (!is_continuation)
            {
              char *group = strchr (key, ':');
              if (group)
                {
                  *group++ = 0;
                  if ((p = strchr (group, ':')))
                    *p = 0; /* We better strip any extra stuff. */
                }

              es_fprintf (listfp, "k:%s:", gc_percent_escape (key));
              es_fprintf (listfp, "%s\n", group? gc_percent_escape (group):"");
            }

          /* All other lines are rule records.  */
          es_fprintf (listfp, "r:::%s:%s:%s:",
                      gc_component[component_id].name,
                      option_info->name? option_info->name : "",
                      flags? flags : "");
          if (value != empty)
            es_fprintf (listfp, "\"%s", gc_percent_escape (value));

          es_putc ('\n', listfp);
        }

      /* Check whether the key matches but do this only if we are not
         running in syntax check mode. */
      if ( update
           && !result && !listfp
           && (got_match || (key && key_matches_user_or_group (key))) )
        {
          int newflags = 0;

          got_match = 1;

          /* Apply the flags from gpgconf.conf.  */
          if (!flags)
            ;
          else if (!strcmp (flags, "default"))
            newflags |= GC_OPT_FLAG_DEFAULT;
          else if (!strcmp (flags, "no-change"))
            option_info->no_change = 1;
          else if (!strcmp (flags, "change"))
            option_info->no_change = 0;

          if (defaults)
            {
              /* Here we explicitly allow updating the value again.  */
              if (newflags)
                {
                  option_info->new_flags = 0;
                }
              if (*value)
                {
                  xfree (option_info->new_value);
                  option_info->new_value = NULL;
                }
              change_one_value (component_id, option_info,
                                runtime, newflags, value, 0);
            }
        }
    }

  if (length < 0 || gpgrt_ferror (config))
    {
      gc_error (0, errno, "error reading from '%s'", fname);
      result = -1;
    }
  if (gpgrt_fclose (config))
    gc_error (0, errno, "error closing '%s'", fname);

  xfree (line);

  /* If it all worked, process the options. */
  if (!result && update && defaults && !listfp)
    {
      /* We need to switch off the runtime update, so that we can do
         it later all at once. */
      int save_opt_runtime = opt.runtime;
      opt.runtime = 0;

      for (component_id = 0; component_id < GC_COMPONENT_NR; component_id++)
        {
          gc_component_change_options (component_id, NULL, NULL, 0);
        }
      opt.runtime = save_opt_runtime;

      if (opt.runtime)
        {
          for (component_id = 0; component_id < GC_COMPONENT_NR; component_id++)
            if (runtime[component_id]
                && gc_component[component_id].runtime_change)
              (*gc_component[component_id].runtime_change) (0);
        }
    }

  xfree (fname);
  return result;
}


/*
 * Apply the profile FNAME to all known configure files.
 */
gpg_error_t
gc_apply_profile (const char *fname)
{
  gpg_error_t err;
  char *fname_buffer = NULL;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  estream_t fp;
  int lineno = 0;
  int runtime[GC_COMPONENT_NR] =  { 0 };
  int component_id = -1;
  int skip_section = 0;
  int error_count = 0;
  int newflags;

  if (!fname)
    fname = "-";


  if (!(!strcmp (fname, "-")
        || strchr (fname, '/')
#ifdef HAVE_W32_SYSTEM
        || strchr (fname, '\\')
#endif
        || strchr (fname, '.')))
    {
      /* FNAME looks like a standard profile name.  Check whether one
       * is installed and use that instead of the given file name.  */
      fname_buffer = xstrconcat (gnupg_datadir (), DIRSEP_S,
                                 fname, ".prf", NULL);
      if (!gnupg_access (fname_buffer, F_OK))
        fname = fname_buffer;
    }

  fp = !strcmp (fname, "-")? es_stdin : es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("can't open '%s': %s\n", fname, gpg_strerror (err));
      return err;
    }

  if (opt.verbose)
    log_info ("applying profile '%s'\n", fname);

  err = 0;
  while ((length = es_read_line (fp, &line, &line_len, NULL)) > 0)
    {
      char *name, *flags, *value;
      gc_option_t *option_info = NULL;
      char *p;

      lineno++;
      name = line;
      while (*name == ' ' || *name == '\t')
        name++;
      if (!*name || *name == '#' || *name == '\r' || *name == '\n')
        continue;
      trim_trailing_spaces (name);

      /* Check whether this is a new section.  */
      if (*name == '[')
        {
          name++;
          skip_section = 0;
          /* New section: Get the name of the component.  */
          p = strchr (name, ']');
          if (!p)
            {
              error_count++;
              log_info ("%s:%d:%d: error: syntax error in section tag\n",
                        fname, lineno, (int)(name - line));
              skip_section = 1;
              continue;
            }
          *p++ = 0;
          if (*p)
            log_info ("%s:%d:%d: warning: garbage after section tag\n",
                      fname, lineno, (int)(p - line));

          trim_spaces (name);
          component_id = gc_component_find (name);
          if (component_id < 0)
            {
              log_info ("%s:%d:%d: warning: skipping unknown section '%s'\n",
                        fname, lineno, (int)(name - line), name );
              skip_section = 1;
            }
          continue;
        }

      if (skip_section)
        continue;
      if (component_id < 0)
        {
          error_count++;
          log_info ("%s:%d:%d: error: not in a valid section\n",
                    fname, lineno, (int)(name - line));
          skip_section = 1;
          continue;
        }

      /* Parse the option name.  */
      for (p = name; *p && !spacep (p); p++)
        ;
      *p++ = 0;
      value = p;

      option_info = find_option (component_id, name);
      if (!option_info)
        {
          error_count++;
          log_info ("%s:%d:%d: error: unknown option '%s' in section '%s'\n",
                    fname, lineno, (int)(name - line),
                    name, gc_component[component_id].name);
          continue;
        }

      /* Parse the optional flags. */
      trim_spaces (value);
      flags = value;
      if (*flags == '[')
        {
          flags++;
          p = strchr (flags, ']');
          if (!p)
            {
              log_info ("%s:%d:%d: warning: invalid flag specification\n",
                        fname, lineno, (int)(p - line));
              continue;
            }
          *p++ = 0;
          value = p;
          trim_spaces (value);
        }
      else /* No flags given.  */
        flags = NULL;

      /* Set required defaults.  */
      if (gc_arg_type[option_info->arg_type].fallback == GC_ARG_TYPE_NONE
          && !*value)
        value = "1";

      /* Check and save this option.  */
      newflags = 0;
      if (flags && !strcmp (flags, "default"))
        newflags |= GC_OPT_FLAG_DEFAULT;

      if (newflags)
        option_info->new_flags = 0;
      if (*value)
        {
          xfree (option_info->new_value);
          option_info->new_value = NULL;
        }
      change_one_value (component_id, option_info, runtime, newflags, value, 1);
    }

  if (length < 0 || es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      error_count++;
      log_error (_("%s:%u: read error: %s\n"),
                 fname, lineno, gpg_strerror (err));
    }
  if (es_fclose (fp))
    log_error (_("error closing '%s'\n"), fname);
  if (error_count)
    log_error (_("error parsing '%s'\n"), fname);

  xfree (line);

  /* If it all worked, process the options. */
  if (!err)
    {
      /* We need to switch off the runtime update, so that we can do
         it later all at once. */
      int save_opt_runtime = opt.runtime;
      opt.runtime = 0;

      for (component_id = 0; component_id < GC_COMPONENT_NR; component_id++)
        {
          gc_component_change_options (component_id, NULL, NULL, 1);
        }
      opt.runtime = save_opt_runtime;

      if (opt.runtime)
        {
          for (component_id = 0; component_id < GC_COMPONENT_NR; component_id++)
            if (runtime[component_id]
                && gc_component[component_id].runtime_change)
              (*gc_component[component_id].runtime_change) (0);
        }
    }

  xfree (fname_buffer);
  return err;
}
