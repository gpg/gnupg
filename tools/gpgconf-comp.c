/* gpgconf-comp.c - Configuration utility for GnuPG.
 * Copyright (C) 2004, 2007, 2008, 2009 Free Software Foundation, Inc.
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
 * along with GnuPG; if not, see <http://www.gnu.org/licenses/>.
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
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN 1
# include <windows.h>
#else
# include <pwd.h>
# include <grp.h>
#endif

/* For log_logv(), asctimestamp(), gnupg_get_time ().  */
#define JNLIB_NEED_LOG_LOGV
#include "util.h"
#include "i18n.h"
#include "exechelp.h"

#include "gc-opt-flags.h"
#include "gpgconf.h"


/* There is a problem with gpg 1.4 under Windows: --gpgconf-list
   returns a plain filename without escaping.  As long as we have not
   fixed that we need to use gpg2 - it might actually be better to use
   gpg2 in any case.  */
#ifdef HAVE_W32_SYSTEM
#define GPGNAME "gpg2"
#else
#define GPGNAME "gpg"
#endif


/* TODO:
   Components: Add more components and their options.
   Robustness: Do more validation.  Call programs to do validation for us.
   Add options to change backend binary path.
   Extract binary path for some backends from gpgsm/gpg config.
*/


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
  log_logv (JNLIB_LOG_ERROR, fmt, arg_ptr);
  va_end (arg_ptr);

  if (errnum)
    log_printf (": %s\n", strerror (errnum));
  else
    log_printf ("\n");

  if (status)
    {
      log_printf (NULL);
      log_printf ("fatal error (exit status %i)\n", status);
      exit (status);
    }
}


/* Forward declaration.  */
static void gpg_agent_runtime_change (void);
static void scdaemon_runtime_change (void);

/* Backend configuration.  Backends are used to decide how the default
   and current value of an option can be determined, and how the
   option can be changed.  To every option in every component belongs
   exactly one backend that controls and determines the option.  Some
   backends are programs from the GPG system.  Others might be
   implemented by GPGConf itself.  If you change this enum, don't
   forget to update GC_BACKEND below.  */
typedef enum
  {
    /* Any backend, used for find_option ().  */
    GC_BACKEND_ANY,

    /* The Gnu Privacy Guard.  */
    GC_BACKEND_GPG,

    /* The Gnu Privacy Guard for S/MIME.  */
    GC_BACKEND_GPGSM,

    /* The GPG Agent.  */
    GC_BACKEND_GPG_AGENT,

    /* The GnuPG SCDaemon.  */
    GC_BACKEND_SCDAEMON,

    /* The Aegypten directory manager.  */
    GC_BACKEND_DIRMNGR,

    /* The LDAP server list file for the Aegypten director manager.  */
    GC_BACKEND_DIRMNGR_LDAP_SERVER_LIST,

    /* The number of the above entries.  */
    GC_BACKEND_NR
  } gc_backend_t;


/* To be able to implement generic algorithms for the various
   backends, we collect all information about them in this struct.  */
static struct
{
  /* The name of the backend.  */
  const char *name;

  /* The name of the program that acts as the backend.  Some backends
     don't have an associated program, but are implemented directly by
     GPGConf.  In this case, PROGRAM is NULL.  */
  char *program;

  /* The module name (GNUPG_MODULE_NAME_foo) as defined by
     ../common/util.h.  This value is used to get the actual installed
     path of the program.  0 is used if no backedn program is
     available. */
  char module_name;

  /* The runtime change callback.  */
  void (*runtime_change) (void);

  /* The option name for the configuration filename of this backend.
     This must be an absolute filename.  It can be an option from a
     different backend (but then ordering of the options might
     matter).  Note: This must be unique among all components.  */
  const char *option_config_filename;

  /* If this is a file backend rather than a program backend, then
     this is the name of the option associated with the file.  */
  const char *option_name;
} gc_backend[GC_BACKEND_NR] =
  {
    { NULL },		/* GC_BACKEND_ANY dummy entry.  */
    { "GnuPG", GPGNAME, GNUPG_MODULE_NAME_GPG,
      NULL, "gpgconf-gpg.conf" },
    { "GPGSM", "gpgsm", GNUPG_MODULE_NAME_GPGSM,
      NULL, "gpgconf-gpgsm.conf" },
    { "GPG Agent", "gpg-agent", GNUPG_MODULE_NAME_AGENT,
      gpg_agent_runtime_change, "gpgconf-gpg-agent.conf" },
    { "SCDaemon", "scdaemon", GNUPG_MODULE_NAME_SCDAEMON,
      scdaemon_runtime_change, "gpgconf-scdaemon.conf" },
    { "DirMngr", "dirmngr", GNUPG_MODULE_NAME_DIRMNGR,
      NULL, "gpgconf-dirmngr.conf" },
    { "DirMngr LDAP Server List", NULL, 0,
      NULL, "ldapserverlist-file", "LDAP Server" },
  };


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
static struct
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
static struct
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


/* Option flags.  The flags which are used by the backends are defined
   by gc-opt-flags.h, included above.

   YOU MUST NOT CHANGE THE NUMBERS OF THE EXISTING FLAGS, AS THEY ARE
   PART OF THE EXTERNAL INTERFACE.  */

/* Some entries in the option list are not options, but mark the
   beginning of a new group of options.  These entries have the GROUP
   flag set.  */
#define GC_OPT_FLAG_GROUP	(1UL << 0)
/* The ARG_OPT flag for an option indicates that the argument is
   optional.  This is never set for GC_ARG_TYPE_NONE options.  */
#define GC_OPT_FLAG_ARG_OPT	(1UL << 1)
/* The LIST flag for an option indicates that the option can occur
   several times.  A comma separated list of arguments is used as the
   argument value.  */
#define GC_OPT_FLAG_LIST	(1UL << 2)
/* The NO_CHANGE flag for an option indicates that the user should not
   be allowed to change this option using the standard gpgconf method.
   Frontends using gpgconf should grey out such options, so that only
   the current value is displayed.  */
#define GC_OPT_FLAG_NO_CHANGE   (1UL <<7)


/* A human-readable description for each flag.  */
static struct
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


/* To each option, or group marker, the information in the GC_OPTION
   struct is provided.  If you change this, don't forget to update the
   option list of each component.  */
struct gc_option
{
  /* If this is NULL, then this is a terminator in an array of unknown
     length.  Otherwise, if this entry is a group marker (see FLAGS),
     then this is the name of the group described by this entry.
     Otherwise it is the name of the option described by this
     entry.  The name must not contain a colon.  */
  const char *name;

  /* The option flags.  If the GROUP flag is set, then this entry is a
     group marker, not an option, and only the fields LEVEL,
     DESC_DOMAIN and DESC are valid.  In all other cases, this entry
     describes a new option and all fields are valid.  */
  unsigned long flags;

  /* The expert level.  This field is valid for options and groups.  A
     group has the expert level of the lowest-level option in the
     group.  */
  gc_expert_level_t level;

  /* A gettext domain in which the following description can be found.
     If this is NULL, then DESC is not translated.  Valid for groups
     and options.

     Note that we try to keep the description of groups within the
     gnupg domain.

     IMPORTANT: If you add a new domain please make sure to add a code
     set switching call to the function my_dgettext further below.  */
  const char *desc_domain;

  /* A gettext description for this group or option.  If it starts
     with a '|', then the string up to the next '|' describes the
     argument, and the description follows the second '|'.

     In general enclosing these description in N_() is not required
     because the description should be identical to the one in the
     help menu of the respective program. */
  const char *desc;

  /* The following fields are only valid for options.  */

  /* The type of the option argument.  */
  gc_arg_type_t arg_type;

  /* The backend that implements this option.  */
  gc_backend_t backend;

  /* The following fields are set to NULL at startup (because all
     option's are declared as static variables).  They are at the end
     of the list so that they can be omitted from the option
     declarations.  */

  /* This is true if the option is supported by this version of the
     backend.  */
  int active;

  /* The default value for this option.  This is NULL if the option is
     not present in the backend, the empty string if no default is
     available, and otherwise a quoted string.  */
  char *default_value;

  /* The default argument is only valid if the "optional arg" flag is
     set, and specifies the default argument (value) that is used if
     the argument is omitted.  */
  char *default_arg;

  /* The current value of this option.  */
  char *value;

  /* The new flags for this option.  The only defined flag is actually
     GC_OPT_FLAG_DEFAULT, and it means that the option should be
     deleted.  In this case, NEW_VALUE is NULL.  */
  unsigned long new_flags;

  /* The new value of this option.  */
  char *new_value;
};
typedef struct gc_option gc_option_t;

/* Use this macro to terminate an option list.  */
#define GC_OPTION_NULL { NULL }


/* The options of the GC_COMPONENT_GPG_AGENT component.  */
static gc_option_t gc_options_gpg_agent[] =
 {
   /* The configuration file to which we write the changes.  */
   { "gpgconf-gpg-agent.conf", GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     NULL, NULL, GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG_AGENT },

   { "Monitor",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the diagnostic output") },
   { "verbose", GC_OPT_FLAG_LIST|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "verbose",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },
   { "quiet", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "be somewhat more quiet",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },

   { "Configuration",
     GC_OPT_FLAG_GROUP, GC_LEVEL_EXPERT,
     "gnupg", N_("Options controlling the configuration") },
   { "options", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", "|FILE|read options from FILE",
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG_AGENT },
   { "disable-scdaemon", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", "do not use the SCdaemon",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },

   { "Debug",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Options useful for debugging") },
   { "debug-level", GC_OPT_FLAG_ARG_OPT|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     "gnupg", "|LEVEL|set the debugging level to LEVEL",
     GC_ARG_TYPE_STRING, GC_BACKEND_GPG_AGENT },
   { "log-file", GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     "gnupg", N_("|FILE|write server mode logs to FILE"),
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG_AGENT },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },

   { "Security",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the security") },
   { "default-cache-ttl", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_BASIC, "gnupg",
     "|N|expire cached PINs after N seconds",
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "default-cache-ttl-ssh", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_ADVANCED, "gnupg",
     N_("|N|expire SSH keys after N seconds"),
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "max-cache-ttl", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT, "gnupg",
     N_("|N|set maximum PIN cache lifetime to N seconds"),
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "max-cache-ttl-ssh", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT, "gnupg",
     N_("|N|set maximum SSH key lifetime to N seconds"),
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "ignore-cache-for-signing", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_BASIC, "gnupg", "do not use the PIN cache when signing",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },
   { "allow-mark-trusted", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_ADVANCED, "gnupg", "allow clients to mark keys as \"trusted\"",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },
   { "no-grab", GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT,
     "gnupg", "do not grab keyboard and mouse",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },

   { "Passphrase policy",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Options enforcing a passphrase policy") },
   { "enforce-passphrase-constraints", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT, "gnupg",
     N_("do not allow to bypass the passphrase policy"),
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },
   { "min-passphrase-len", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_ADVANCED, "gnupg",
     N_("|N|set minimal required length for new passphrases to N"),
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "min-passphrase-nonalpha", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT, "gnupg",
     N_("|N|require at least N non-alpha characters for a new passphrase"),
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "check-passphrase-pattern", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT,
     "gnupg", N_("|FILE|check new passphrases against pattern in FILE"),
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG_AGENT },
   { "max-passphrase-days", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT, "gnupg",
     N_("|N|expire the passphrase after N days"),
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPG_AGENT },
   { "enable-passphrase-history", GC_OPT_FLAG_RUNTIME,
     GC_LEVEL_EXPERT, "gnupg",
     N_("do not allow the reuse of old passphrases"),
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG_AGENT },

   GC_OPTION_NULL
 };


/* The options of the GC_COMPONENT_SCDAEMON component.  */
static gc_option_t gc_options_scdaemon[] =
 {
   /* The configuration file to which we write the changes.  */
   { "gpgconf-scdaemon.conf", GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     NULL, NULL, GC_ARG_TYPE_FILENAME, GC_BACKEND_SCDAEMON },

   { "Monitor",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the diagnostic output") },
   { "verbose", GC_OPT_FLAG_LIST|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "verbose",
     GC_ARG_TYPE_NONE, GC_BACKEND_SCDAEMON },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", "be somewhat more quiet",
     GC_ARG_TYPE_NONE, GC_BACKEND_SCDAEMON },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_NONE, GC_BACKEND_SCDAEMON },

   { "Configuration",
     GC_OPT_FLAG_GROUP, GC_LEVEL_EXPERT,
     "gnupg", N_("Options controlling the configuration") },
   { "options", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", "|FILE|read options from FILE",
     GC_ARG_TYPE_FILENAME, GC_BACKEND_SCDAEMON },
   { "reader-port", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "|N|connect to reader at port N",
     GC_ARG_TYPE_STRING, GC_BACKEND_SCDAEMON },
   { "ctapi-driver", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     "gnupg", "|NAME|use NAME as ct-API driver",
     GC_ARG_TYPE_STRING, GC_BACKEND_SCDAEMON },
   { "pcsc-driver", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     "gnupg", "|NAME|use NAME as PC/SC driver",
     GC_ARG_TYPE_STRING, GC_BACKEND_SCDAEMON },
   { "disable-ccid", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_EXPERT,
     "gnupg", "do not use the internal CCID driver",
     GC_ARG_TYPE_NONE, GC_BACKEND_SCDAEMON },
   { "disable-keypad", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "do not use a reader's keypad",
     GC_ARG_TYPE_NONE, GC_BACKEND_SCDAEMON },
   { "card-timeout", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "|N|disconnect the card after N seconds of inactivity",
     GC_ARG_TYPE_UINT32, GC_BACKEND_SCDAEMON },

   { "Debug",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Options useful for debugging") },
   { "debug-level", GC_OPT_FLAG_ARG_OPT|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     "gnupg", "|LEVEL|set the debugging level to LEVEL",
     GC_ARG_TYPE_STRING, GC_BACKEND_SCDAEMON },
   { "log-file", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_ADVANCED,
     "gnupg", N_("|FILE|write a log to FILE"),
     GC_ARG_TYPE_FILENAME, GC_BACKEND_SCDAEMON },

   { "Security",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the security") },
   { "deny-admin", GC_OPT_FLAG_NONE|GC_OPT_FLAG_RUNTIME, GC_LEVEL_BASIC,
     "gnupg", "deny the use of admin card commands",
     GC_ARG_TYPE_NONE, GC_BACKEND_SCDAEMON },


   GC_OPTION_NULL
 };


/* The options of the GC_COMPONENT_GPG component.  */
static gc_option_t gc_options_gpg[] =
 {
   /* The configuration file to which we write the changes.  */
   { "gpgconf-gpg.conf", GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     NULL, NULL, GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG },

   { "Monitor",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the diagnostic output") },
   { "verbose", GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
     "gnupg", "verbose",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", "be somewhat more quiet",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG },

   { "Configuration",
     GC_OPT_FLAG_GROUP, GC_LEVEL_EXPERT,
     "gnupg", N_("Options controlling the configuration") },
   { "default-key", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", N_("|NAME|use NAME as default secret key"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPG },
   { "encrypt-to", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", N_("|NAME|encrypt to user ID NAME as well"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPG },
   { "group", GC_OPT_FLAG_LIST, GC_LEVEL_ADVANCED,
     "gnupg", N_("|SPEC|set up email aliases"),
     GC_ARG_TYPE_ALIAS_LIST, GC_BACKEND_GPG },
   { "options", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", "|FILE|read options from FILE",
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG },

   { "Debug",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Options useful for debugging") },
   { "debug-level", GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED,
     "gnupg", "|LEVEL|set the debugging level to LEVEL",
     GC_ARG_TYPE_STRING, GC_BACKEND_GPG },
   { "log-file", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", N_("|FILE|write server mode logs to FILE"),
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPG },
/*    { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE, */
/*      NULL, NULL, */
/*      GC_ARG_TYPE_UINT32, GC_BACKEND_GPG }, */

   { "Keyserver",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Configuration for Keyservers") },
   { "keyserver", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", N_("|URL|use keyserver at URL"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPG },
   { "allow-pka-lookup", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", N_("allow PKA lookups (DNS requests)"),
     GC_ARG_TYPE_NONE, GC_BACKEND_GPG },
   { "auto-key-locate", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", N_("|MECHANISMS|use MECHANISMS to locate keys by mail address"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPG },


   GC_OPTION_NULL
 };



/* The options of the GC_COMPONENT_GPGSM component.  */
static gc_option_t gc_options_gpgsm[] =
 {
   /* The configuration file to which we write the changes.  */
   { "gpgconf-gpgsm.conf", GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     NULL, NULL, GC_ARG_TYPE_FILENAME, GC_BACKEND_GPGSM },

   { "Monitor",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the diagnostic output") },
   { "verbose", GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
     "gnupg", "verbose",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", "be somewhat more quiet",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },

   { "Configuration",
     GC_OPT_FLAG_GROUP, GC_LEVEL_EXPERT,
     "gnupg", N_("Options controlling the configuration") },
   { "default-key", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", N_("|NAME|use NAME as default secret key"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPGSM },
   { "encrypt-to", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", N_("|NAME|encrypt to user ID NAME as well"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPGSM },
   { "options", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", "|FILE|read options from FILE",
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPGSM },
   { "prefer-system-dirmngr", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", "use system's dirmngr if available",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "disable-dirmngr", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", N_("disable all access to the dirmngr"),
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "p12-charset", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", N_("|NAME|use encoding NAME for PKCS#12 passphrases"),
     GC_ARG_TYPE_STRING, GC_BACKEND_GPGSM },
   { "keyserver", GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
     "gnupg", N_("|SPEC|use this keyserver to lookup keys"),
     GC_ARG_TYPE_LDAP_SERVER, GC_BACKEND_GPGSM },

   { "Debug",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Options useful for debugging") },
   { "debug-level", GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED,
     "gnupg", "|LEVEL|set the debugging level to LEVEL",
     GC_ARG_TYPE_STRING, GC_BACKEND_GPGSM },
   { "log-file", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", N_("|FILE|write server mode logs to FILE"),
     GC_ARG_TYPE_FILENAME, GC_BACKEND_GPGSM },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_UINT32, GC_BACKEND_GPGSM },

   { "Security",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the security") },
   { "disable-crl-checks", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", "never consult a CRL",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "disable-trusted-cert-crl-check", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", N_("do not check CRLs for root certificates"),
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "enable-ocsp", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", "check validity using OCSP",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "include-certs", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "gnupg", "|N|number of certificates to include",
     GC_ARG_TYPE_INT32, GC_BACKEND_GPGSM },
   { "disable-policy-checks", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", "do not check certificate policies",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "auto-issuer-key-retrieve", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "gnupg", "fetch missing issuer certificates",
     GC_ARG_TYPE_NONE, GC_BACKEND_GPGSM },
   { "cipher-algo", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", "|NAME|use cipher algorithm NAME",
     GC_ARG_TYPE_STRING, GC_BACKEND_GPGSM },

   GC_OPTION_NULL
 };


/* The options of the GC_COMPONENT_DIRMNGR component.  */
static gc_option_t gc_options_dirmngr[] =
 {
   /* The configuration file to which we write the changes.  */
   { "gpgconf-dirmngr.conf", GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     NULL, NULL, GC_ARG_TYPE_FILENAME, GC_BACKEND_DIRMNGR },

   { "Monitor",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the diagnostic output") },
   { "verbose", GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
     "dirmngr", "verbose",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "quiet", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "be somewhat more quiet",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "no-greeting", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },

   { "Format",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the format of the output") },
   { "sh", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "sh-style command output",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "csh", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "csh-style command output",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },

   { "Configuration",
     GC_OPT_FLAG_GROUP, GC_LEVEL_EXPERT,
     "gnupg", N_("Options controlling the configuration") },
   { "options", GC_OPT_FLAG_NONE, GC_LEVEL_EXPERT,
     "dirmngr", "|FILE|read options from FILE",
     GC_ARG_TYPE_FILENAME, GC_BACKEND_DIRMNGR },

   { "Debug",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Options useful for debugging") },
   { "debug-level", GC_OPT_FLAG_ARG_OPT, GC_LEVEL_ADVANCED,
     "dirmngr", "|LEVEL|set the debugging level to LEVEL",
     GC_ARG_TYPE_STRING, GC_BACKEND_DIRMNGR },
   { "no-detach", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "do not detach from the console",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "log-file", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", N_("|FILE|write server mode logs to FILE"),
     GC_ARG_TYPE_FILENAME, GC_BACKEND_DIRMNGR },
   { "debug-wait", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },
   { "faked-system-time", GC_OPT_FLAG_NONE, GC_LEVEL_INVISIBLE,
     NULL, NULL,
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },

   { "Enforcement",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Options controlling the interactivity and enforcement") },
   { "batch", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "run without asking a user",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "force", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "force loading of outdated CRLs",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },

   { "HTTP",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Configuration for HTTP servers") },
   { "disable-http", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "inhibit the use of HTTP",
      GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ignore-http-dp", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "ignore HTTP CRL distribution points",
      GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "http-proxy", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "|URL|redirect all HTTP requests to URL",
     GC_ARG_TYPE_STRING, GC_BACKEND_DIRMNGR },
   { "honor-http-proxy", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "gnupg", N_("use system's HTTP proxy setting"),
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },

   { "LDAP",
     GC_OPT_FLAG_GROUP, GC_LEVEL_BASIC,
     "gnupg", N_("Configuration of LDAP servers to use") },
   { "disable-ldap", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "inhibit the use of LDAP",
      GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ignore-ldap-dp", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "ignore LDAP CRL distribution points",
      GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ldap-proxy", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "|HOST|use HOST for LDAP queries",
     GC_ARG_TYPE_STRING, GC_BACKEND_DIRMNGR },
   { "only-ldap-proxy", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "do not use fallback hosts with --ldap-proxy",
      GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "add-servers", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "add new servers discovered in CRL distribution points"
     " to serverlist", GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ldaptimeout", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "|N|set LDAP timeout to N seconds",
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },
   /* The following entry must not be removed, as it is required for
      the GC_BACKEND_DIRMNGR_LDAP_SERVER_LIST.  */
   { "ldapserverlist-file",
     GC_OPT_FLAG_NONE, GC_LEVEL_INTERNAL,
     "dirmngr", "|FILE|read LDAP server list from FILE",
     GC_ARG_TYPE_FILENAME, GC_BACKEND_DIRMNGR },
   /* This entry must come after at least one entry for
      GC_BACKEND_DIRMNGR in this component, so that the entry for
      "ldapserverlist-file will be initialized before this one.  */
   { "LDAP Server", GC_OPT_FLAG_ARG_OPT|GC_OPT_FLAG_LIST, GC_LEVEL_BASIC,
     "gnupg", N_("LDAP server list"),
     GC_ARG_TYPE_LDAP_SERVER, GC_BACKEND_DIRMNGR_LDAP_SERVER_LIST },
   { "max-replies", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "|N|do not return more than N items in one query",
     GC_ARG_TYPE_UINT32, GC_BACKEND_DIRMNGR },

   { "OCSP",
     GC_OPT_FLAG_GROUP, GC_LEVEL_ADVANCED,
     "gnupg", N_("Configuration for OCSP") },
   { "allow-ocsp", GC_OPT_FLAG_NONE, GC_LEVEL_BASIC,
     "dirmngr", "allow sending OCSP requests",
     GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ignore-ocsp-service-url", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "ignore certificate contained OCSP service URLs",
      GC_ARG_TYPE_NONE, GC_BACKEND_DIRMNGR },
   { "ocsp-responder", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "|URL|use OCSP responder at URL",
     GC_ARG_TYPE_STRING, GC_BACKEND_DIRMNGR },
   { "ocsp-signer", GC_OPT_FLAG_NONE, GC_LEVEL_ADVANCED,
     "dirmngr", "|FPR|OCSP response signed by FPR",
     GC_ARG_TYPE_STRING, GC_BACKEND_DIRMNGR },


   GC_OPTION_NULL
 };


/* Component system.  Each component is a set of options that can be
   configured at the same time.  If you change this, don't forget to
   update GC_COMPONENT below.  */
typedef enum
  {
    /* The classic GPG for OpenPGP.  */
    GC_COMPONENT_GPG,

    /* The GPG Agent.  */
    GC_COMPONENT_GPG_AGENT,

    /* The Smardcard Daemon.  */
    GC_COMPONENT_SCDAEMON,

    /* GPG for S/MIME.  */
    GC_COMPONENT_GPGSM,

    /* The LDAP Directory Manager for CRLs.  */
    GC_COMPONENT_DIRMNGR,

    /* The number of components.  */
    GC_COMPONENT_NR
  } gc_component_t;


/* The information associated with each component.  */
static struct
{
  /* The name of this component.  Must not contain a colon (':')
     character.  */
  const char *name;

  /* The gettext domain for the description DESC.  If this is NULL,
     then the description is not translated.  */
  const char *desc_domain;

  /* The description for this domain.  */
  const char *desc;

  /* The list of options for this component, terminated by
     GC_OPTION_NULL.  */
  gc_option_t *options;
} gc_component[] =
  {
    { "gpg", NULL,   "GPG for OpenPGP", gc_options_gpg },
    { "gpg-agent", NULL, "GPG Agent", gc_options_gpg_agent },
    { "scdaemon", NULL, "Smartcard Daemon", gc_options_scdaemon },
    { "gpgsm", NULL, "GPG for S/MIME", gc_options_gpgsm },
    { "dirmngr", NULL, "Directory Manager", gc_options_dirmngr }
  };



/* Structure used to collect error output of the backend programs.  */
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



/* Engine specific support.  */
static void
gpg_agent_runtime_change (void)
{
#ifndef HAVE_W32_SYSTEM
  char *agent = getenv ("GPG_AGENT_INFO");
  char *pid_str;
  unsigned long pid_long;
  char *tail;
  pid_t pid;

  if (!agent)
    return;

  pid_str = strchr (agent, ':');
  if (!pid_str)
    return;

  pid_str++;
  errno = 0;
  pid_long = strtoul (pid_str, &tail, 0);
  if (errno || (*tail != ':' && *tail != '\0'))
    return;

  pid = (pid_t) pid_long;

  /* Check for overflow.  */
  if (pid_long != (unsigned long) pid)
    return;

  /* Ignore any errors here.  */
  kill (pid, SIGHUP);
#else
  gpg_error_t err;
  const char *pgmname;
  const char *argv[2];
  pid_t pid;

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  argv[0] = "reloadagent";
  argv[1] = NULL;

  err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, NULL);
  if (err)
    gc_error (0, 0, "error running `%s%s': %s",
              pgmname, " reloadagent", gpg_strerror (err));
#endif /*!HAVE_W32_SYSTEM*/
}


static void
scdaemon_runtime_change (void)
{
  gpg_error_t err;
  const char *pgmname;
  const char *argv[6];
  pid_t pid;

  /* We use "GETINFO app_running" to see whether the agent is already
     running and kill it only in this case.  This avoids an explicit
     starting of the agent in case it is not yet running.  There is
     obviously a race condition but that should not harm too much.  */

  pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CONNECT_AGENT);
  argv[0] = "-s";
  argv[1] = "GETINFO scd_running";
  argv[2] = "/if ${! $?}";
  argv[3] = "scd killscd";
  argv[4] = "/end";
  argv[5] = NULL;

  err = gnupg_spawn_process_fd (pgmname, argv, -1, -1, -1, &pid);
  if (!err)
    err = gnupg_wait_process (pgmname, pid, NULL);
  if (err)
    gc_error (0, 0, "error running `%s%s': %s",
              pgmname, " scd killscd", gpg_strerror (err));
}


/* Unconditionally reload COMPONENT or all components if COMPONENT is -1.  */
void
gc_component_reload (int component)
{
  int runtime[GC_BACKEND_NR];
  gc_option_t *option;
  gc_backend_t backend;

  /* Set a flag for the backends to be reloaded.  */
  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    runtime[backend] = 0;

  if (component == -1)
    {
      for (component = 0; component < GC_COMPONENT_NR; component++)
        {
          option = gc_component[component].options;
          for (; option && option->name; option++)
            runtime[option->backend] = 1;
        }
    }
  else
    {
      assert (component < GC_COMPONENT_NR);
      option = gc_component[component].options;
      for (; option && option->name; option++)
        runtime[option->backend] = 1;
    }

  /* Do the reload for all selected backends.  */
  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    {
      if (runtime[backend] && gc_backend[backend].runtime_change)
        (*gc_backend[backend].runtime_change) ();
    }
}



/* More or less Robust version of dgettext.  It has the side effect of
   switching the codeset to utf-8 because this is what we want to
   output.  In theory it is posible to keep the orginal code set and
   switch back for regular disgnostic output (redefine "_(" for that)
   but given the natur of this tool, being something invoked from
   other pograms, it does not make much sense.  */
static const char *
my_dgettext (const char *domain, const char *msgid)
{
#ifdef USE_SIMPLE_GETTEXT
  if (domain)
    {
      static int switched_codeset;
      char *text;

      if (!switched_codeset)
        {
          switched_codeset = 1;
          gettext_select_utf8 (1);
        }

      if (!strcmp (domain, "gnupg"))
        domain = PACKAGE_GT;

      /* FIXME: we have no dgettext, thus we can't switch.  */

      text = (char*)gettext (msgid);
      return text ? text : msgid;
    }
#elif defined(ENABLE_NLS)
  if (domain)
    {
      static int switched_codeset;
      char *text;

      if (!switched_codeset)
        {
          switched_codeset = 1;
          bind_textdomain_codeset (PACKAGE_GT, "utf-8");

          bindtextdomain ("dirmngr", LOCALEDIR);
          bind_textdomain_codeset ("dirmngr", "utf-8");

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
#endif
    return msgid;
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
      char *new_esc_str = realloc (esc_str, new_len);
      if (!new_esc_str)
	gc_error (1, errno, "can not escape string");
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
      char *new_str = realloc (str, new_len);
      if (!new_str)
	gc_error (1, errno, "can not deescape string");
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
gc_component_list_components (FILE *out)
{
  gc_component_t component;
  gc_option_t *option;
  gc_backend_t backend;
  int backend_seen[GC_BACKEND_NR];
  const char *desc;
  const char *pgmname;

  for (component = 0; component < GC_COMPONENT_NR; component++)
    {
      option = gc_component[component].options;
      if (option)
        {
          for (backend = 0; backend < GC_BACKEND_NR; backend++)
            backend_seen[backend] = 0;

          pgmname = "";
          for (; option && option->name; option++)
            {
              if ((option->flags & GC_OPT_FLAG_GROUP))
                continue;
              backend = option->backend;
              if (backend_seen[backend])
                continue;
              backend_seen[backend] = 1;
              assert (backend != GC_BACKEND_ANY);
              if (gc_backend[backend].program
                  && !gc_backend[backend].module_name)
                continue;
              pgmname = gnupg_module_name (gc_backend[backend].module_name);
              break;
            }

          desc = gc_component[component].desc;
          desc = my_dgettext (gc_component[component].desc_domain, desc);
          fprintf (out, "%s:%s:",
                   gc_component[component].name,  gc_percent_escape (desc));
          fprintf (out, "%s\n",  gc_percent_escape (pgmname));
        }
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


/* Collect all error lines from file descriptor FD. Only lines
   prefixed with TAG are considered.  Close that file descriptor
   then.  Returns a list of error line items (which may be empty).
   There is no error return.  */
static error_line_t
collect_error_output (int fd, const char *tag)
{
  FILE *fp;
  char buffer[1024];
  char *p, *p2, *p3;
  int c, cont_line;
  unsigned int pos;
  error_line_t eitem, errlines, *errlines_tail;
  size_t taglen = strlen (tag);

  fp = fdopen (fd, "r");
  if (!fp)
    gc_error (1, errno, "can't fdopen pipe for reading");

  errlines = NULL;
  errlines_tail = &errlines;
  pos = 0;
  cont_line = 0;
  while ((c=getc (fp)) != EOF)
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

  fclose (fp);
  return errlines;
}


/* Check the options of a single component.  Returns 0 if everything
   is OK.  */
int
gc_component_check_options (int component, FILE *out, const char *conf_file)
{
  gpg_error_t err;
  unsigned int result;
  int backend_seen[GC_BACKEND_NR];
  gc_backend_t backend;
  gc_option_t *option;
  const char *pgmname;
  const char *argv[4];
  int i;
  pid_t pid;
  int exitcode;
  int filedes[2];
  error_line_t errlines;

  /* We use a temporary file to collect the error output.  It would be
     better to use a pipe here but as of now we have no suitable
     fucntion to create a portable pipe outside of exechelp.  Thus it
     is easier to use the tempfile approach.  */

  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    backend_seen[backend] = 0;

  option = gc_component[component].options;
  for (; option && option->name; option++)
    {
      if ((option->flags & GC_OPT_FLAG_GROUP))
	continue;
      backend = option->backend;
      if (backend_seen[backend])
	continue;
      backend_seen[backend] = 1;
      assert (backend != GC_BACKEND_ANY);
      if (!gc_backend[backend].program)
	continue;
      if (!gc_backend[backend].module_name)
	continue;

      break;
    }
  if (! option || ! option->name)
    return 0;

  pgmname = gnupg_module_name (gc_backend[backend].module_name);
  i = 0;
  if (conf_file)
    {
      argv[i++] = "--options";
      argv[i++] = conf_file;
    }
  argv[i++] = "--gpgconf-test";
  argv[i++] = NULL;

  err = gnupg_create_inbound_pipe (filedes);
  if (err)
    gc_error (1, 0, _("error creating a pipe: %s\n"),
	      gpg_strerror (err));

  result = 0;
  errlines = NULL;
  if (gnupg_spawn_process_fd (pgmname, argv, -1, -1, filedes[1], &pid))
    {
      close (filedes[0]);
      close (filedes[1]);
      result |= 1; /* Program could not be run.  */
    }
  else
    {
      close (filedes[1]);
      errlines = collect_error_output (filedes[0],
				       gc_component[component].name);
      if (gnupg_wait_process (pgmname, pid, &exitcode))
	{
	  if (exitcode == -1)
	    result |= 1; /* Program could not be run or it
			    terminated abnormally.  */
	  result |= 2; /* Program returned an error.  */
	}
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
      fprintf (out, "%s:%s:",
	       gc_component[component].name, gc_percent_escape (desc));
      fputs (gc_percent_escape (pgmname), out);
      fprintf (out, ":%d:%d:", !(result & 1), !(result & 2));
      for (errptr = errlines; errptr; errptr = errptr->next)
	{
	  if (errptr != errlines)
	    fputs ("\n:::::", out); /* Continuation line.  */
	  if (errptr->fname)
	    fputs (gc_percent_escape (errptr->fname), out);
	  putc (':', out);
	  if (errptr->fname)
	    fprintf (out, "%u", errptr->lineno);
	  putc (':', out);
	  fputs (gc_percent_escape (errptr->errtext), out);
	  putc (':', out);
	}
      putc ('\n', out);
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
gc_check_programs (FILE *out)
{
  gc_component_t component;

  for (component = 0; component < GC_COMPONENT_NR; component++)
    gc_component_check_options (component, out, NULL);
}



/* Find the component with the name NAME.  Returns -1 if not
   found.  */
int
gc_component_find (const char *name)
{
  gc_component_t idx;

  for (idx = 0; idx < GC_COMPONENT_NR; idx++)
    {
      if (gc_component[idx].options
          && !strcmp (name, gc_component[idx].name))
	return idx;
    }
  return -1;
}


/* List the option OPTION.  */
static void
list_one_option (const gc_option_t *option, FILE *out)
{
  const char *desc = NULL;
  char *arg_name = NULL;

  if (option->desc)
    {
      desc = my_dgettext (option->desc_domain, option->desc);

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
  fprintf (out, "%s", option->name);

  /* The flags field.  */
  fprintf (out, ":%lu", option->flags);
  if (opt.verbose)
    {
      putc (' ', out);

      if (!option->flags)
	fprintf (out, "none");
      else
	{
	  unsigned long flags = option->flags;
	  unsigned long flag = 0;
	  unsigned long first = 1;

	  while (flags)
	    {
	      if (flags & 1)
		{
		  if (first)
		    first = 0;
		  else
		    putc (',', out);
		  fprintf (out, "%s", gc_flag[flag].name);
		}
	      flags >>= 1;
	      flag++;
	    }
	}
    }

  /* The level field.  */
  fprintf (out, ":%u", option->level);
  if (opt.verbose)
    fprintf (out, " %s", gc_level[option->level].name);

  /* The description field.  */
  fprintf (out, ":%s", desc ? gc_percent_escape (desc) : "");

  /* The type field.  */
  fprintf (out, ":%u", option->arg_type);
  if (opt.verbose)
    fprintf (out, " %s", gc_arg_type[option->arg_type].name);

  /* The alternate type field.  */
  fprintf (out, ":%u", gc_arg_type[option->arg_type].fallback);
  if (opt.verbose)
    fprintf (out, " %s",
	     gc_arg_type[gc_arg_type[option->arg_type].fallback].name);

  /* The argument name field.  */
  fprintf (out, ":%s", arg_name ? gc_percent_escape (arg_name) : "");
  if (arg_name)
    xfree (arg_name);

  /* The default value field.  */
  fprintf (out, ":%s", option->default_value ? option->default_value : "");

  /* The default argument field.  */
  fprintf (out, ":%s", option->default_arg ? option->default_arg : "");

  /* The value field.  */
  if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_NONE
      && (option->flags & GC_OPT_FLAG_LIST)
      && option->value)
    /* The special format "1,1,1,1,...,1" is converted to a number
       here.  */
    fprintf (out, ":%u", (unsigned int)((strlen (option->value) + 1) / 2));
  else
    fprintf (out, ":%s", option->value ? option->value : "");

  /* ADD NEW FIELDS HERE.  */

  putc ('\n', out);
}


/* List all options of the component COMPONENT.  */
void
gc_component_list_options (int component, FILE *out)
{
  const gc_option_t *option = gc_component[component].options;

  while (option && option->name)
    {
      /* Do not output unknown or internal options.  */
      if (!(option->flags & GC_OPT_FLAG_GROUP)
	  && (!option->active || option->level == GC_LEVEL_INTERNAL))
	{
	  option++;
	  continue;
	}

      if (option->flags & GC_OPT_FLAG_GROUP)
	{
	  const gc_option_t *group_option = option + 1;
	  gc_expert_level_t level = GC_LEVEL_NR;

	  /* The manual states that the group level is always the
	     minimum of the levels of all contained options.  Due to
	     different active options, and because it is hard to
	     maintain manually, we calculate it here.  The value in
	     the global static table is ignored.  */

	  while (group_option->name)
	    {
	      if (group_option->flags & GC_OPT_FLAG_GROUP)
		break;
	      if (group_option->level < level)
		level = group_option->level;
	      group_option++;
	    }

	  /* Check if group is empty.  */
	  if (level != GC_LEVEL_NR)
	    {
	      gc_option_t opt_copy;

	      /* Fix up the group level.  */
	      memcpy (&opt_copy, option, sizeof (opt_copy));
	      opt_copy.level = level;
	      list_one_option (&opt_copy, out);
	    }
	}
      else
	list_one_option (option, out);

      option++;
    }
}


/* Find the option NAME in component COMPONENT, for the backend
   BACKEND.  If BACKEND is GC_BACKEND_ANY, any backend will match.  */
static gc_option_t *
find_option (gc_component_t component, const char *name,
	     gc_backend_t backend)
{
  gc_option_t *option = gc_component[component].options;
  while (option->name)
    {
      if (!(option->flags & GC_OPT_FLAG_GROUP)
	  && !strcmp (option->name, name)
	  && (backend == GC_BACKEND_ANY || option->backend == backend))
	break;
      option++;
    }
  return option->name ? option : NULL;
}


/* Determine the configuration filename for the component COMPONENT
   and backend BACKEND.  */
static char *
get_config_filename (gc_component_t component, gc_backend_t backend)
{
  char *filename = NULL;
  gc_option_t *option = find_option
    (component, gc_backend[backend].option_config_filename, GC_BACKEND_ANY);
  assert (option);
  assert (option->arg_type == GC_ARG_TYPE_FILENAME);
  assert (!(option->flags & GC_OPT_FLAG_LIST));

  if (!option->active || !option->default_value)
    gc_error (1, 0, "Option %s, needed by backend %s, was not initialized",
	      gc_backend[backend].option_config_filename,
	      gc_backend[backend].name);

  if (option->value && *option->value)
    filename = percent_deescape (&option->value[1]);
  else if (option->default_value && *option->default_value)
    filename = percent_deescape (&option->default_value[1]);
  else
    filename = "";

#ifdef HAVE_DOSISH_SYSTEM
  if (!(filename[0]
        && filename[1] == ':'
        && (filename[2] == '/' || filename[2] == '\\')))
#else
  if (filename[0] != '/')
#endif
    gc_error (1, 0, "Option %s, needed by backend %s, is not absolute",
	      gc_backend[backend].option_config_filename,
	      gc_backend[backend].name);

  return filename;
}


/* Retrieve the options for the component COMPONENT from backend
   BACKEND, which we already know is a program-type backend.  */
static void
retrieve_options_from_program (gc_component_t component, gc_backend_t backend)
{
  gpg_error_t err;
  int filedes[2];
  const char *pgmname;
  const char *argv[2];
  int exitcode;
  pid_t pid;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  FILE *config;
  char *config_filename;

  err = gnupg_create_inbound_pipe (filedes);
  if (err)
    gc_error (1, 0, _("error creating a pipe: %s\n"), gpg_strerror (err));

  pgmname = (gc_backend[backend].module_name
             ? gnupg_module_name (gc_backend[backend].module_name)
             : gc_backend[backend].program );
  argv[0] = "--gpgconf-list";
  argv[1] = NULL;

  err = gnupg_spawn_process_fd (pgmname, argv, -1, filedes[1], -1, &pid);
  if (err)
    {
      close (filedes[0]);
      close (filedes[1]);
      gc_error (1, 0, "could not gather active options from `%s': %s",
                pgmname, gpg_strerror (err));
    }
  close (filedes[1]);
  config = fdopen (filedes[0], "r");
  if (!config)
    gc_error (1, errno, "can't fdopen pipe for reading");

  while ((length = read_line (config, &line, &line_len, NULL)) > 0)
    {
      gc_option_t *option;
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

	  errno = 0;
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

	  if (flags & GC_OPT_FLAG_DEFAULT)
	    default_value = linep;

	  linep = end;
	}

      /* Look up the option in the component and install the
	 configuration data.  */
      option = find_option (component, line, backend);
      if (option)
	{
	  if (option->active)
	    gc_error (1, errno, "option %s returned twice from %s",
		      line, pgmname);
	  option->active = 1;

	  option->flags |= flags;
	  if (default_value && *default_value)
	    option->default_value = xstrdup (default_value);
	}
    }
  if (length < 0 || ferror (config))
    gc_error (1, errno, "error reading from %s",pgmname);
  if (fclose (config))
    gc_error (1, errno, "error closing %s", pgmname);

  err = gnupg_wait_process (pgmname, pid, &exitcode);
  if (err)
    gc_error (1, 0, "running %s failed (exitcode=%d): %s",
              pgmname, exitcode, gpg_strerror (err));


  /* At this point, we can parse the configuration file.  */
  config_filename = get_config_filename (component, backend);

  config = fopen (config_filename, "r");
  if (!config)
    gc_error (0, errno, "warning: can not open config file %s",
	      config_filename);
  else
    {
      while ((length = read_line (config, &line, &line_len, NULL)) > 0)
	{
	  char *name;
	  char *value;
	  gc_option_t *option;

	  name = line;
	  while (*name == ' ' || *name == '\t')
	    name++;
	  if (!*name || *name == '#' || *name == '\r' || *name == '\n')
	    continue;

	  value = name;
	  while (*value && *value != ' ' && *value != '\t'
		 && *value != '#' && *value != '\r' && *value != '\n')
	    value++;
	  if (*value == ' ' || *value == '\t')
	    {
	      char *end;

	      *(value++) = '\0';
	      while (*value == ' ' || *value == '\t')
		value++;

	      end = value;
	      while (*end && *end != '#' && *end != '\r' && *end != '\n')
		end++;
	      while (end > value && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	      *end = '\0';
	    }
	  else
	    *value = '\0';

	  /* Look up the option in the component and install the
	     configuration data.  */
	  option = find_option (component, line, backend);
	  if (option)
	    {
	      char *opt_value;

	      if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_NONE)
		{
		  if (*value)
		    gc_error (0, 0,
			      "warning: ignoring argument %s for option %s",
			      value, name);
		  opt_value = xstrdup ("1");
		}
	      else if (gc_arg_type[option->arg_type].fallback
		       == GC_ARG_TYPE_STRING)
		opt_value = xasprintf ("\"%s", gc_percent_escape (value));
	      else
		{
		  /* FIXME: Verify that the number is sane.  */
		  opt_value = xstrdup (value);
		}

	      /* Now enter the option into the table.  */
	      if (!(option->flags & GC_OPT_FLAG_LIST))
		{
		  if (option->value)
		    free (option->value);
		  option->value = opt_value;
		}
	      else
		{
		  if (!option->value)
		    option->value = opt_value;
		  else
		    {
		      char *opt_val = opt_value;

		      option->value = xasprintf ("%s,%s", option->value,
						 opt_val);
		      xfree (opt_value);
		    }
		}
	    }
	}

      if (length < 0 || ferror (config))
	gc_error (1, errno, "error reading from %s", config_filename);
      if (fclose (config))
	gc_error (1, errno, "error closing %s", config_filename);
    }

  xfree (line);
}


/* Retrieve the options for the component COMPONENT from backend
   BACKEND, which we already know is of type file list.  */
static void
retrieve_options_from_file (gc_component_t component, gc_backend_t backend)
{
  gc_option_t *list_option;
  gc_option_t *config_option;
  char *list_filename;
  FILE *list_file;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  char *list = NULL;

  list_option = find_option (component,
			     gc_backend[backend].option_name, GC_BACKEND_ANY);
  assert (list_option);
  assert (!list_option->active);

  list_filename = get_config_filename (component, backend);
  list_file = fopen (list_filename, "r");
  if (!list_file)
    gc_error (0, errno, "warning: can not open list file %s", list_filename);
  else
    {

      while ((length = read_line (list_file, &line, &line_len, NULL)) > 0)
	{
	  char *start;
	  char *end;
	  char *new_list;

	  start = line;
	  while (*start == ' ' || *start == '\t')
	    start++;
	  if (!*start || *start == '#' || *start == '\r' || *start == '\n')
	    continue;

	  end = start;
	  while (*end && *end != '#' && *end != '\r' && *end != '\n')
	    end++;
	  /* Walk back to skip trailing white spaces.  Looks evil, but
	     works because of the conditions on START and END imposed
	     at this point (END is at least START + 1, and START is
	     not a whitespace character).  */
	  while (*(end - 1) == ' ' || *(end - 1) == '\t')
	    end--;
	  *end = '\0';
	  /* FIXME: Oh, no!  This is so lame!  Should use realloc and
	     really append.  */
	  if (list)
	    {
	      new_list = xasprintf ("%s,\"%s", list, gc_percent_escape (start));
	      xfree (list);
	      list = new_list;
	    }
	  else
	    list = xasprintf ("\"%s", gc_percent_escape (start));
	}
      if (length < 0 || ferror (list_file))
	gc_error (1, errno, "can not read list file %s", list_filename);
    }

  list_option->active = 1;
  list_option->value = list;

  /* Fix up the read-only flag.  */
  config_option = find_option
    (component, gc_backend[backend].option_config_filename, GC_BACKEND_ANY);
  if (config_option->flags & GC_OPT_FLAG_NO_CHANGE)
    list_option->flags |= GC_OPT_FLAG_NO_CHANGE;

  if (list_file && fclose (list_file))
    gc_error (1, errno, "error closing %s", list_filename);
  xfree (line);
}


/* Retrieve the currently active options and their defaults from all
   involved backends for this component.  Using -1 for component will
   retrieve all options from all components. */
void
gc_component_retrieve_options (int component)
{
  int process_all = 0;
  int backend_seen[GC_BACKEND_NR];
  gc_backend_t backend;
  gc_option_t *option;

  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    backend_seen[backend] = 0;

  if (component == -1)
    {
      process_all = 1;
      component = 0;
      assert (component < GC_COMPONENT_NR);
    }

  do
    {
      option = gc_component[component].options;

      while (option && option->name)
        {
          if (!(option->flags & GC_OPT_FLAG_GROUP))
            {
              backend = option->backend;

              if (backend_seen[backend])
                {
                  option++;
                  continue;
                }
              backend_seen[backend] = 1;

              assert (backend != GC_BACKEND_ANY);

              if (gc_backend[backend].program)
                retrieve_options_from_program (component, backend);
              else
                retrieve_options_from_file (component, backend);
            }
          option++;
        }
    }
  while (process_all && ++component < GC_COMPONENT_NR);

}



/* Perform a simple validity check based on the type.  Return in
   NEW_VALUE_NR the value of the number in NEW_VALUE if OPTION is of
   type GC_ARG_TYPE_NONE.  */
static void
option_check_validity (gc_option_t *option, unsigned long flags,
		       char *new_value, unsigned long *new_value_nr)
{
  char *arg;

  if (!option->active)
    gc_error (1, 0, "option %s not supported by backend %s",
              option->name, gc_backend[option->backend].name);

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

      errno = 0;
      *new_value_nr = strtoul (new_value, &tail, 0);

      if (errno)
	gc_error (1, errno, "invalid argument for option %s",
		  option->name);
      if (*tail)
	gc_error (1, 0, "garbage after argument for option %s",
		      option->name);

      if (!(option->flags & GC_OPT_FLAG_LIST))
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
      if (*arg == '\0' || *arg == ',')
	{
	  if (!(option->flags & GC_OPT_FLAG_ARG_OPT))
	    gc_error (1, 0, "argument required for option %s", option->name);

	  if (*arg == ',' && !(option->flags & GC_OPT_FLAG_LIST))
	    gc_error (1, 0, "list found for non-list option %s", option->name);
	}
      else if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_STRING)
	{
	  if (*arg != '"')
	    gc_error (1, 0, "string argument for option %s must begin "
		      "with a quote (\") character", option->name);

	  /* FIXME: We do not allow empty string arguments for now, as
	     we do not quote arguments in configuration files, and
	     thus no argument is indistinguishable from the empty
	     string.  */
	  if (arg[1] == '\0' || arg[1] == ',')
	    gc_error (1, 0, "empty string argument for option %s is "
		      "currently not allowed.  Please report this!",
		      option->name);
	}
      else if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_INT32)
	{
	  errno = 0;
	  (void) strtol (arg, &arg, 0);

	  if (errno)
	    gc_error (1, errno, "invalid argument for option %s",
		      option->name);

	  if (*arg != '\0' && *arg != ',')
	    gc_error (1, 0, "garbage after argument for option %s",
		      option->name);
	}
      else if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_INT32)
	{
	  errno = 0;
	  (void) strtoul (arg, &arg, 0);

	  if (errno)
	    gc_error (1, errno, "invalid argument for option %s",
		      option->name);

	  if (*arg != '\0' && *arg != ',')
	    gc_error (1, 0, "garbage after argument for option %s",
		      option->name);
	}
      arg = strchr (arg, ',');
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
  FILE *src;
  FILE *dst;

  src = fopen (src_name, "r");
  if (src == NULL)
    return -1;

  dst = fopen (dst_name, "w");
  if (dst == NULL)
    {
      int saved_err = errno;
      fclose (src);
      errno = saved_err;
      return -1;
    }

  do
    {
      int written;

      len = fread (buffer, 1, BUF_LEN, src);
      if (len == 0)
	break;
      written = fwrite (buffer, 1, len, dst);
      if (written != len)
	break;
    }
  while (!feof (src) && !ferror (src) && !ferror (dst));

  if (ferror (src) || ferror (dst) || !feof (src))
    {
      int saved_errno = errno;
      fclose (src);
      fclose (dst);
      unlink (dst_name);
      errno = saved_errno;
      return -1;
    }

  if (fclose (dst))
    gc_error (1, errno, "error closing %s", dst_name);
  if (fclose (src))
    gc_error (1, errno, "error closing %s", src_name);

  return 0;
}
#endif /* HAVE_W32_SYSTEM */


/* Create and verify the new configuration file for the specified
   backend and component.  Returns 0 on success and -1 on error.  */
static int
change_options_file (gc_component_t component, gc_backend_t backend,
		     char **src_filenamep, char **dest_filenamep,
		     char **orig_filenamep)
{
  static const char marker[] = "###+++--- GPGConf ---+++###";
  /* True if we are within the marker in the config file.  */
  int in_marker = 0;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len;
  ssize_t length;
  int res;
  int fd;
  FILE *src_file = NULL;
  FILE *dest_file = NULL;
  char *src_filename;
  char *dest_filename;
  char *orig_filename;
  char *arg;
  char *cur_arg = NULL;

  option = find_option (component,
			gc_backend[backend].option_name, GC_BACKEND_ANY);
  assert (option);
  assert (option->active);
  assert (gc_arg_type[option->arg_type].fallback != GC_ARG_TYPE_NONE);

  /* FIXME.  Throughout the function, do better error reporting.  */
  /* Note that get_config_filename() calls percent_deescape(), so we
     call this before processing the arguments.  */
  dest_filename = xstrdup (get_config_filename (component, backend));
  src_filename = xasprintf ("%s.gpgconf.%i.new", dest_filename, getpid ());
  orig_filename = xasprintf ("%s.gpgconf.%i.bak", dest_filename, getpid ());

  arg = option->new_value;
  if (arg && arg[0] == '\0')
    arg = NULL;
  else if (arg)
    {
      char *end;

      arg++;
      end = strchr (arg, ',');
      if (end)
	*end = '\0';

      cur_arg = percent_deescape (arg);
      if (end)
	{
	  *end = ',';
	  arg = end + 1;
	}
      else
	arg = NULL;
    }

#ifdef HAVE_W32_SYSTEM
  res = copy_file (dest_filename, orig_filename);
#else
  res = link (dest_filename, orig_filename);
#endif
  if (res < 0 && errno != ENOENT)
    return -1;
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

  /* Use open() so that we can use O_EXCL.  */
  fd = open (src_filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (fd < 0)
    return -1;
  src_file = fdopen (fd, "w");
  res = errno;
  if (!src_file)
    {
      errno = res;
      return -1;
    }

  /* Only if ORIG_FILENAME is not NULL did the configuration file
     exist already.  In this case, we will copy its content into the
     new configuration file, changing it to our liking in the
     process.  */
  if (orig_filename)
    {
      dest_file = fopen (dest_filename, "r");
      if (!dest_file)
	goto change_file_one_err;

      while ((length = read_line (dest_file, &line, &line_len, NULL)) > 0)
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

	  start = line;
	  while (*start == ' ' || *start == '\t')
	    start++;
	  if (*start && *start != '\r' && *start != '\n' && *start != '#')
	    {
	      char *end;
	      char *endp;
	      char saved_end;

	      endp = start;
	      end = endp;

	      /* Search for the end of the line.  */
	      while (*endp && *endp != '#' && *endp != '\r' && *endp != '\n')
		{
		  endp++;
		  if (*endp && *endp != ' ' && *endp != '\t'
		      && *endp != '\r' && *endp != '\n' && *endp != '#')
		    end = endp + 1;
		}
	      saved_end = *end;
	      *end = '\0';

	      if ((option->new_flags & GC_OPT_FLAG_DEFAULT)
		  || !cur_arg || strcmp (start, cur_arg))
		disable = 1;
	      else
		{
		  /* Find next argument.  */
		  if (arg)
		    {
		      char *arg_end;

		      arg++;
		      arg_end = strchr (arg, ',');
		      if (arg_end)
			*arg_end = '\0';

		      cur_arg = percent_deescape (arg);
		      if (arg_end)
			{
			  *arg_end = ',';
			  arg = arg_end + 1;
			}
		      else
			arg = NULL;
		    }
		  else
		    cur_arg = NULL;
		}

	      *end = saved_end;
	    }

	  if (disable)
	    {
	      if (!in_marker)
		{
		  fprintf (src_file,
			   "# GPGConf disabled this option here at %s\n",
			   asctimestamp (gnupg_get_time ()));
		  if (ferror (src_file))
		    goto change_file_one_err;
		  fprintf (src_file, "# %s", line);
		  if (ferror (src_file))
		    goto change_file_one_err;
		}
	    }
	  else
	    {
	      fprintf (src_file, "%s", line);
	      if (ferror (src_file))
		goto change_file_one_err;
	    }
	}
      if (length < 0 || ferror (dest_file))
	goto change_file_one_err;
    }

  if (!in_marker)
    {
      /* There was no marker.  This is the first time we edit the
	 file.  We add our own marker at the end of the file and
	 proceed.  Note that we first write a newline, this guards us
	 against files which lack the newline at the end of the last
	 line, while it doesn't hurt us in all other cases.  */
      fprintf (src_file, "\n%s\n", marker);
      if (ferror (src_file))
	goto change_file_one_err;
    }

  /* At this point, we have copied everything up to the end marker
     into the new file, except for the arguments we are going to add.
     Now, dump the new arguments and write the end marker, possibly
     followed by the rest of the original file.  */
  while (cur_arg)
    {
      fprintf (src_file, "%s\n", cur_arg);

      /* Find next argument.  */
      if (arg)
	{
	  char *end;

	  arg++;
	  end = strchr (arg, ',');
	  if (end)
	    *end = '\0';

	  cur_arg = percent_deescape (arg);
	  if (end)
	    {
	      *end = ',';
	      arg = end + 1;
	    }
	  else
	    arg = NULL;
	}
      else
	cur_arg = NULL;
    }

  fprintf (src_file, "%s %s\n", marker, asctimestamp (gnupg_get_time ()));
  if (ferror (src_file))
    goto change_file_one_err;

  if (!in_marker)
    {
      fprintf (src_file, "# GPGConf edited this configuration file.\n");
      if (ferror (src_file))
	goto change_file_one_err;
      fprintf (src_file, "# It will disable options before this marked "
	       "block, but it will\n");
      if (ferror (src_file))
	goto change_file_one_err;
      fprintf (src_file, "# never change anything below these lines.\n");
      if (ferror (src_file))
	goto change_file_one_err;
    }
  if (dest_file)
    {
      while ((length = read_line (dest_file, &line, &line_len, NULL)) > 0)
	{
	  fprintf (src_file, "%s", line);
	  if (ferror (src_file))
	    goto change_file_one_err;
	}
      if (length < 0 || ferror (dest_file))
	goto change_file_one_err;
    }
  xfree (line);
  line = NULL;

  res = fclose (src_file);
  if (res)
    {
      res = errno;
      close (fd);
      if (dest_file)
	fclose (dest_file);
      errno = res;
      return -1;
    }
  close (fd);
  if (dest_file)
    {
      res = fclose (dest_file);
      if (res)
	return -1;
    }
  return 0;

 change_file_one_err:
  xfree (line);
  res = errno;
  if (src_file)
    {
      fclose (src_file);
      close (fd);
    }
  if (dest_file)
    fclose (dest_file);
  errno = res;
  return -1;
}


/* Create and verify the new configuration file for the specified
   backend and component.  Returns 0 on success and -1 on error.  */
static int
change_options_program (gc_component_t component, gc_backend_t backend,
			char **src_filenamep, char **dest_filenamep,
			char **orig_filenamep)
{
  static const char marker[] = "###+++--- GPGConf ---+++###";
  /* True if we are within the marker in the config file.  */
  int in_marker = 0;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len;
  ssize_t length;
  int res;
  int fd;
  FILE *src_file = NULL;
  FILE *dest_file = NULL;
  char *src_filename;
  char *dest_filename;
  char *orig_filename;
  /* Special hack for gpg, see below.  */
  int utf8strings_seen = 0;

  /* FIXME.  Throughout the function, do better error reporting.  */
  dest_filename = xstrdup (get_config_filename (component, backend));
  src_filename = xasprintf ("%s.gpgconf.%i.new", dest_filename, getpid ());
  orig_filename = xasprintf ("%s.gpgconf.%i.bak", dest_filename, getpid ());

#ifdef HAVE_W32_SYSTEM
  res = copy_file (dest_filename, orig_filename);
#else
  res = link (dest_filename, orig_filename);
#endif
  if (res < 0 && errno != ENOENT)
    return -1;
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

  /* Use open() so that we can use O_EXCL.  */
  fd = open (src_filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (fd < 0)
    return -1;
  src_file = fdopen (fd, "w");
  res = errno;
  if (!src_file)
    {
      errno = res;
      return -1;
    }

  /* Only if ORIG_FILENAME is not NULL did the configuration file
     exist already.  In this case, we will copy its content into the
     new configuration file, changing it to our liking in the
     process.  */
  if (orig_filename)
    {
      dest_file = fopen (dest_filename, "r");
      if (!dest_file)
	goto change_one_err;

      while ((length = read_line (dest_file, &line, &line_len, NULL)) > 0)
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
	  else if (backend == GC_BACKEND_GPG && in_marker
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

	      option = find_option (component, start, backend);
	      *end = saved_end;
	      if (option && ((option->new_flags & GC_OPT_FLAG_DEFAULT)
			     || option->new_value))
		disable = 1;
	    }
	  if (disable)
	    {
	      if (!in_marker)
		{
		  fprintf (src_file,
			   "# GPGConf disabled this option here at %s\n",
			   asctimestamp (gnupg_get_time ()));
		  if (ferror (src_file))
		    goto change_one_err;
		  fprintf (src_file, "# %s", line);
		  if (ferror (src_file))
		    goto change_one_err;
		}
	    }
	  else
	    {
	      fprintf (src_file, "%s", line);
	      if (ferror (src_file))
		goto change_one_err;
	    }
	}
      if (length < 0 || ferror (dest_file))
	goto change_one_err;
    }

  if (!in_marker)
    {
      /* There was no marker.  This is the first time we edit the
	 file.  We add our own marker at the end of the file and
	 proceed.  Note that we first write a newline, this guards us
	 against files which lack the newline at the end of the last
	 line, while it doesn't hurt us in all other cases.  */
      fprintf (src_file, "\n%s\n", marker);
      if (ferror (src_file))
	goto change_one_err;
    }
  /* At this point, we have copied everything up to the end marker
     into the new file, except for the options we are going to change.
     Now, dump the changed options (except for those we are going to
     revert to their default), and write the end marker, possibly
     followed by the rest of the original file.  */

  /* We have to turn on UTF8 strings for GnuPG.  */
  if (backend == GC_BACKEND_GPG && ! utf8strings_seen)
    fprintf (src_file, "utf8-strings\n");

  option = gc_component[component].options;
  while (option->name)
    {
      if (!(option->flags & GC_OPT_FLAG_GROUP)
	  && option->backend == backend
	  && option->new_value)
	{
	  char *arg = option->new_value;

	  do
	    {
	      if (*arg == '\0' || *arg == ',')
		{
		  fprintf (src_file, "%s\n", option->name);
		  if (ferror (src_file))
		    goto change_one_err;
		}
	      else if (gc_arg_type[option->arg_type].fallback
		       == GC_ARG_TYPE_NONE)
		{
		  assert (*arg == '1');
		  fprintf (src_file, "%s\n", option->name);
		  if (ferror (src_file))
		    goto change_one_err;

		  arg++;
		}
	      else if (gc_arg_type[option->arg_type].fallback
		       == GC_ARG_TYPE_STRING)
		{
		  char *end;

		  assert (*arg == '"');
		  arg++;

		  end = strchr (arg, ',');
		  if (end)
		    *end = '\0';

		  fprintf (src_file, "%s %s\n", option->name,
			   percent_deescape (arg));
		  if (ferror (src_file))
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

		  fprintf (src_file, "%s %s\n", option->name, arg);
		  if (ferror (src_file))
		    goto change_one_err;

		  if (end)
		    *end = ',';
		  arg = end;
		}

	      assert (arg == NULL || *arg == '\0' || *arg == ',');
	      if (arg && *arg == ',')
		arg++;
	    }
	  while (arg && *arg);
	}
      option++;
    }

  fprintf (src_file, "%s %s\n", marker, asctimestamp (gnupg_get_time ()));
  if (ferror (src_file))
    goto change_one_err;

  if (!in_marker)
    {
      fprintf (src_file, "# GPGConf edited this configuration file.\n");
      if (ferror (src_file))
	goto change_one_err;
      fprintf (src_file, "# It will disable options before this marked "
	       "block, but it will\n");
      if (ferror (src_file))
	goto change_one_err;
      fprintf (src_file, "# never change anything below these lines.\n");
      if (ferror (src_file))
	goto change_one_err;
    }
  if (dest_file)
    {
      while ((length = read_line (dest_file, &line, &line_len, NULL)) > 0)
	{
	  fprintf (src_file, "%s", line);
	  if (ferror (src_file))
	    goto change_one_err;
	}
      if (length < 0 || ferror (dest_file))
	goto change_one_err;
    }
  xfree (line);
  line = NULL;

  res = fclose (src_file);
  if (res)
    {
      res = errno;
      close (fd);
      if (dest_file)
	fclose (dest_file);
      errno = res;
      return -1;
    }
  close (fd);
  if (dest_file)
    {
      res = fclose (dest_file);
      if (res)
	return -1;
    }
  return 0;

 change_one_err:
  xfree (line);
  res = errno;
  if (src_file)
    {
      fclose (src_file);
      close (fd);
    }
  if (dest_file)
    fclose (dest_file);
  errno = res;
  return -1;
}


/* Common code for gc_component_change_options and
   gc_process_gpgconf_conf.  */
static void
change_one_value (gc_option_t *option, int *runtime,
                  unsigned long flags, char *new_value)
{
  unsigned long new_value_nr = 0;

  option_check_validity (option, flags, new_value, &new_value_nr);

  if (option->flags & GC_OPT_FLAG_RUNTIME)
    runtime[option->backend] = 1;

  option->new_flags = flags;
  if (!(flags & GC_OPT_FLAG_DEFAULT))
    {
      if (gc_arg_type[option->arg_type].fallback == GC_ARG_TYPE_NONE
          && (option->flags & GC_OPT_FLAG_LIST))
        {
          char *str;

          /* We convert the number to a list of 1's for convenient
             list handling.  */
          assert (new_value_nr > 0);
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
   table. */
void
gc_component_change_options (int component, FILE *in, FILE *out)
{
  int err = 0;
  int runtime[GC_BACKEND_NR];
  char *src_filename[GC_BACKEND_NR];
  char *dest_filename[GC_BACKEND_NR];
  char *orig_filename[GC_BACKEND_NR];
  gc_backend_t backend;
  gc_option_t *option;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;

  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    {
      runtime[backend] = 0;
      src_filename[backend] = NULL;
      dest_filename[backend] = NULL;
      orig_filename[backend] = NULL;
    }

  if (in)
    {
      /* Read options from the file IN.  */
      while ((length = read_line (in, &line, &line_len, NULL)) > 0)
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

              errno = 0;
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

          option = find_option (component, line, GC_BACKEND_ANY);
          if (!option)
            gc_error (1, 0, "unknown option %s", line);

          if ((option->flags & GC_OPT_FLAG_NO_CHANGE))
            {
              gc_error (0, 0, "ignoring new value for option %s",
                        option->name);
              continue;
            }

          change_one_value (option, runtime, flags, new_value);
        }
    }

  /* Now that we have collected and locally verified the changes,
     write them out to new configuration files, verify them
     externally, and then commit them.  */
  option = gc_component[component].options;
  while (option && option->name)
    {
      /* Go on if we have already seen this backend, or if there is
	 nothing to do.  */
      if (src_filename[option->backend]
	  || !(option->new_flags || option->new_value))
	{
	  option++;
	  continue;
	}

      if (gc_backend[option->backend].program)
	{
	  err = change_options_program (component, option->backend,
					&src_filename[option->backend],
					&dest_filename[option->backend],
					&orig_filename[option->backend]);
	  if (! err)
	    {
	      /* External verification.  */
	      err = gc_component_check_options (component, out,
						src_filename[option->backend]);
	      if (err)
		{
		  gc_error (0, 0,
			    _("External verification of component %s failed"),
			    gc_component[component].name);
		  errno = EINVAL;
		}
	    }

	}
      else
	err = change_options_file (component, option->backend,
				   &src_filename[option->backend],
				   &dest_filename[option->backend],
				   &orig_filename[option->backend]);

      if (err)
	break;

      option++;
    }

  if (! err && ! opt.dry_run)
    {
      int i;

      for (i = 0; i < GC_BACKEND_NR; i++)
	{
	  if (src_filename[i])
	    {
	      /* FIXME: Make a verification here.  */

	      assert (dest_filename[i]);

	      if (orig_filename[i])
		{
#ifdef HAVE_W32_SYSTEM
		  /* There is no atomic update on W32.  */
		  err = unlink (dest_filename[i]);
#endif /* HAVE_W32_SYSTEM */
		  if (!err)
		    err = rename (src_filename[i], dest_filename[i]);
		}
	      else
		{
#ifdef HAVE_W32_SYSTEM
		  /* We skip the unlink if we expect the file not to
		     be there.  */
                  err = rename (src_filename[i], dest_filename[i]);
#else /* HAVE_W32_SYSTEM */
		  /* This is a bit safer than rename() because we
		     expect DEST_FILENAME not to be there.  If it
		     happens to be there, this will fail.  */
		  err = link (src_filename[i], dest_filename[i]);
		  if (!err)
		    err = unlink (src_filename[i]);
#endif /* !HAVE_W32_SYSTEM */
		}
	      if (err)
		break;
	      src_filename[i] = NULL;
	    }
	}
    }

  if (err || opt.dry_run)
    {
      int i;
      int saved_errno = errno;

      /* An error occured or a dry-run is requested.  */
      for (i = 0; i < GC_BACKEND_NR; i++)
	{
	  if (src_filename[i])
	    {
	      /* The change was not yet committed.  */
	      unlink (src_filename[i]);
	      if (orig_filename[i])
		unlink (orig_filename[i]);
	    }
	  else
	    {
	      /* The changes were already committed.  FIXME: This is a
		 tad dangerous, as we don't know if we don't overwrite
		 a version of the file that is even newer than the one
		 we just installed.  */
	      if (orig_filename[i])
		{
#ifdef HAVE_W32_SYSTEM
		  /* There is no atomic update on W32.  */
		  unlink (dest_filename[i]);
#endif /* HAVE_W32_SYSTEM */
		  rename (orig_filename[i], dest_filename[i]);
		}
	      else
		unlink (dest_filename[i]);
	    }
	}
      if (err)
	gc_error (1, saved_errno, "could not commit changes");

      /* Fall-through for dry run.  */
      goto leave;
    }

  /* If it all worked, notify the daemons of the changes.  */
  if (opt.runtime)
    for (backend = 0; backend < GC_BACKEND_NR; backend++)
      {
	if (runtime[backend] && gc_backend[backend].runtime_change)
	  (*gc_backend[backend].runtime_change) ();
      }

  /* Move the per-process backup file into its place.  */
  for (backend = 0; backend < GC_BACKEND_NR; backend++)
    if (orig_filename[backend])
      {
	char *backup_filename;

	assert (dest_filename[backend]);

	backup_filename = xasprintf ("%s.gpgconf.bak", dest_filename[backend]);

#ifdef HAVE_W32_SYSTEM
	/* There is no atomic update on W32.  */
	unlink (backup_filename);
#endif /* HAVE_W32_SYSTEM */
	rename (orig_filename[backend], backup_filename);
      }

 leave:
  xfree (line);
}


/* Check whether USER matches the current user of one of its group.
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
                         FILE *listfp)
{
  int result = 0;
  char *line = NULL;
  size_t line_len = 0;
  ssize_t length;
  FILE *config;
  int lineno = 0;
  int in_rule = 0;
  int got_match = 0;
  int runtime[GC_BACKEND_NR];
  int backend_id, component_id;
  char *fname;

  if (fname_arg)
    fname = xstrdup (fname_arg);
  else
    fname = make_filename (gnupg_sysconfdir (), "gpgconf.conf", NULL);

  for (backend_id = 0; backend_id < GC_BACKEND_NR; backend_id++)
    runtime[backend_id] = 0;

  config = fopen (fname, "r");
  if (!config)
    {
      /* Do not print an error if the file is not available, except
         when running in syntax check mode.  */
      if (errno != ENOENT || !update)
        {
          gc_error (0, errno, "can not open global config file `%s'", fname);
          result = -1;
        }
      xfree (fname);
      return result;
    }

  while ((length = read_line (config, &line, &line_len, NULL)) > 0)
    {
      char *key, *component, *option, *flags, *value;
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
              gc_error (0, 0, "missing rule at `%s', line %d", fname, lineno);
              result = -1;
              continue;
            }
          *p++ = 0;
          component = p;
        }
      else if (!in_rule)
        {
          gc_error (0, 0, "continuation but no rule at `%s', line %d",
                    fname, lineno);
          result = -1;
          continue;
        }
      else
        {
          component = key;
          key = NULL;
        }

      in_rule = 1;

      /* Parse the component.  */
      while (*component == ' ' || *component == '\t')
        component++;
      for (p=component; *p && !strchr (" \t\r\n", *p); p++)
        ;
      if (p == component)
        {
          gc_error (0, 0, "missing component at `%s', line %d",
                    fname, lineno);
          result = -1;
          continue;
        }
      empty = p;
      *p++ = 0;
      option = p;
      component_id = gc_component_find (component);
      if (component_id < 0)
        {
          gc_error (0, 0, "unknown component at `%s', line %d",
                    fname, lineno);
          result = -1;
        }

      /* Parse the option name.  */
      while (*option == ' ' || *option == '\t')
        option++;
      for (p=option; *p && !strchr (" \t\r\n", *p); p++)
        ;
      if (p == option)
        {
          gc_error (0, 0, "missing option at `%s', line %d",
                    fname, lineno);
          result = -1;
          continue;
        }
      *p++ = 0;
      flags = p;
      if ( component_id != -1)
        {
          option_info = find_option (component_id, option, GC_BACKEND_ANY);
          if (!option_info)
            {
              gc_error (0, 0, "unknown option at `%s', line %d",
                        fname, lineno);
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
              gc_error (0, 0, "syntax error in rule at `%s', line %d",
                        fname, lineno);
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
                        "with a value at `%s', line %d",
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
          gc_error (0, 0, "unknown flag at `%s', line %d",
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

              fprintf (listfp, "k:%s:", gc_percent_escape (key));
              fprintf (listfp, "%s\n", group? gc_percent_escape (group):"");
            }

          /* All other lines are rule records.  */
          fprintf (listfp, "r:::%s:%s:%s:",
                   gc_component[component_id].name,
                   option_info->name? option_info->name : "",
                   flags? flags : "");
          if (value != empty)
            fprintf (listfp, "\"%s", gc_percent_escape (value));

          putc ('\n', listfp);
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
            option_info->flags |= GC_OPT_FLAG_NO_CHANGE;
          else if (!strcmp (flags, "change"))
            option_info->flags &= ~GC_OPT_FLAG_NO_CHANGE;

          if (defaults)
            {
              assert (component_id >= 0 && component_id < GC_COMPONENT_NR);

              /* Here we explicitly allow to update the value again.  */
              if (newflags)
                {
                  option_info->new_flags = 0;
                }
              if (*value)
                {
                  xfree (option_info->new_value);
                  option_info->new_value = NULL;
                }
              change_one_value (option_info, runtime, newflags, value);
            }
        }
    }

  if (length < 0 || ferror (config))
    {
      gc_error (0, errno, "error reading from `%s'", fname);
      result = -1;
    }
  if (fclose (config) && ferror (config))
    gc_error (0, errno, "error closing `%s'", fname);

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
          gc_component_change_options (component_id, NULL, NULL);
        }
      opt.runtime = save_opt_runtime;

      if (opt.runtime)
        {
          for (backend_id = 0; backend_id < GC_BACKEND_NR; backend_id++)
            if (runtime[backend_id] && gc_backend[backend_id].runtime_change)
              (*gc_backend[backend_id].runtime_change) ();
        }
    }

  xfree (fname);
  return result;
}
