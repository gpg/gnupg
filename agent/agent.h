/* agent.h - Global definitions for the agent
 * Copyright (C) 2001, 2002, 2003, 2005, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH.
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
 */

#ifndef AGENT_H
#define AGENT_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_GPGAGENT
#include <gpg-error.h>
#define map_assuan_err(a) \
        map_assuan_err_with_source (GPG_ERR_SOURCE_DEFAULT, (a))
#include <errno.h>

#include <gcrypt.h>
#include "../common/util.h"
#include "../common/membuf.h"
#include "../common/sysutils.h" /* (gnupg_fd_t) */
#include "../common/session-env.h"
#include "../common/shareddefs.h"
#include "../common/name-value.h"

/* To convey some special hash algorithms we use algorithm numbers
   reserved for application use. */
#ifndef GCRY_MODULE_ID_USER
#define GCRY_MODULE_ID_USER 1024
#endif
#define MD_USER_TLS_MD5SHA1 (GCRY_MODULE_ID_USER+1)

/* Maximum length of a digest.  */
#define MAX_DIGEST_LEN 64

/* The maximum length of a passphrase (in bytes).  Note: this is
   further contrained by the Assuan line length (and any other text on
   the same line).  However, the Assuan line length is 1k bytes so
   this shouldn't be a problem in practice.  */
#define MAX_PASSPHRASE_LEN 255


/* A large struct name "opt" to keep global flags */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  unsigned int debug;  /* Debug flags (DBG_foo_VALUE) */
  int verbose;         /* Verbosity level */
  int quiet;           /* Be as quiet as possible */
  int dry_run;         /* Don't change any persistent data */
  int batch;           /* Batch mode */

  /* True if we handle sigusr2.  */
  int sigusr2_enabled;

  /* Environment settings gathered at program start or changed using the
     Assuan command UPDATESTARTUPTTY. */
  session_env_t startup_env;
  char *startup_lc_ctype;
  char *startup_lc_messages;

  /* Enable pinentry debugging (--debug 1024 should also be used).  */
  int debug_pinentry;

  /* Filename of the program to start as pinentry.  */
  const char *pinentry_program;

  /* Filename of the program to handle smartcard tasks.  */
  const char *scdaemon_program;

  int disable_scdaemon;         /* Never use the SCdaemon. */

  int no_grab;         /* Don't let the pinentry grab the keyboard */

  /* The name of the file pinentry shall touch before exiting.  If
     this is not set the file name of the standard socket is used. */
  const char *pinentry_touch_file;

  /* A string where the first character is used by the pinentry as a
     custom invisible character.  */
  char *pinentry_invisible_char;

  /* The timeout value for the Pinentry in seconds.  This is passed to
     the pinentry if it is not 0.  It is up to the pinentry to act
     upon this timeout value.  */
  unsigned long pinentry_timeout;

  /* If set, then passphrase formatting is enabled in pinentry.  */
  int pinentry_formatted_passphrase;

  /* The default and maximum TTL of cache entries. */
  unsigned long def_cache_ttl;     /* Default. */
  unsigned long def_cache_ttl_ssh; /* for SSH. */
  unsigned long max_cache_ttl;     /* Default. */
  unsigned long max_cache_ttl_ssh; /* for SSH. */

  /* Flag disallowing bypassing of the warning.  */
  int enforce_passphrase_constraints;

  /* The require minmum length of a passphrase. */
  unsigned int min_passphrase_len;

  /* The minimum number of non-alpha characters in a passphrase.  */
  unsigned int min_passphrase_nonalpha;

  /* File name with a patternfile or NULL if not enabled.  If the
   * second one is set, it is used for symmetric only encryption
   * instead of the former. */
  const char *check_passphrase_pattern;
  const char *check_sym_passphrase_pattern;

  /* If not 0 the user is asked to change his passphrase after these
     number of days.  */
  unsigned int max_passphrase_days;

  /* If set, a passphrase history will be written and checked at each
     passphrase change.  */
  int enable_passphrase_history;

  int running_detached; /* We are running detached from the tty. */

  /* If this global option is true, the passphrase cache is ignored
     for signing operations.  */
  int ignore_cache_for_signing;

  /* If this global option is true, the user is allowed to
     interactively mark certificate in trustlist.txt as trusted. */
  int allow_mark_trusted;

  /* Only use the system trustlist.  */
  int no_user_trustlist;

  /* The standard system trustlist is SYSCONFDIR/trustlist.txt.  This
   * option can be used to change the name.  */
  const char *sys_trustlist_name;

  /* If this global option is true, the Assuan command
     PRESET_PASSPHRASE is allowed.  */
  int allow_preset_passphrase;

  /* If this global option is true, the Assuan option
     pinentry-mode=loopback is allowed.  */
  int allow_loopback_pinentry;

  /* Allow the use of an external password cache.  If this option is
     enabled (which is the default) we send an option to Pinentry
     to allow it to enable such a cache.  */
  int allow_external_cache;

  /* If this global option is true, the Assuan option of Pinentry
     allow-emacs-prompt is allowed.  */
  int allow_emacs_pinentry;

  int keep_tty;      /* Don't switch the TTY (for pinentry) on request */
  int keep_display;  /* Don't switch the DISPLAY (for pinentry) on request */

  /* This global option indicates the use of an extra socket. Note
     that we use a hack for cleanup handling in gpg-agent.c: If the
     value is less than 2 the name has not yet been malloced. */
  int extra_socket;

  /* This global option indicates the use of an extra socket for web
     browsers. Note that we use a hack for cleanup handling in
     gpg-agent.c: If the value is less than 2 the name has not yet
     been malloced. */
  int browser_socket;

  /* The digest algorithm to use for ssh fingerprints when
   * communicating with the user.  */
  int ssh_fingerprint_digest;

  /* The value of the option --s2k-count.  If this option is not given
   * or 0 an auto-calibrated value is used.  */
  unsigned long s2k_count;
} opt;


/* Bit values for the --debug option.  */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024  /* Enable Assuan debugging.  */

/* Test macros for the debug option.  */
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)

/* Forward reference for local definitions in command.c.  */
struct server_local_s;

/* Declaration of objects from command-ssh.c.  */
struct ssh_control_file_s;
typedef struct ssh_control_file_s *ssh_control_file_t;

/* Forward reference for local definitions in call-scd.c.  */
struct scd_local_s;

/* Collection of data per session (aka connection). */
struct server_control_s
{
  /* Private data used to fire up the connection thread.  We use this
     structure do avoid an extra allocation for only a few bytes while
     spawning a new connection thread.  */
  struct {
    gnupg_fd_t fd;
  } thread_startup;

  /* Flag indicating the connection is run in restricted mode.
     A value of 1 if used for --extra-socket,
     a value of 2 is used for --browser-socket.  */
  int restricted;

  /* Private data of the server (command.c). */
  struct server_local_s *server_local;

  /* Private data of the SCdaemon (call-scd.c). */
  struct scd_local_s *scd_local;

  /* Environment settings for the connection.  */
  session_env_t session_env;
  char *lc_ctype;
  char *lc_messages;
  unsigned long client_pid;

  /* The current pinentry mode.  */
  pinentry_mode_t pinentry_mode;

  /* The TTL used for the --preset option of certain commands.  */
  int cache_ttl_opt_preset;

  /* Information on the currently used digest (for signing commands).  */
  struct {
    int algo;
    unsigned char value[MAX_DIGEST_LEN];
    int valuelen;
    int raw_value: 1;
  } digest;
  unsigned char keygrip[20];
  int have_keygrip;

  /* A flag to enable a hack to send the PKAUTH command instead of the
     PKSIGN command to the scdaemon.  */
  int use_auth_call;

  /* A flag to inhibit enforced passphrase change during an explicit
     passwd command.  */
  int in_passwd;

  /* The current S2K which might be different from the calibrated
     count. */
  unsigned long s2k_count;

  /* If pinentry is active for this thread.  It can be more than 1,
     when pinentry is called recursively.  */
  int pinentry_active;
};


/* Status of pinentry.  */
enum
  {
    PINENTRY_STATUS_CLOSE_BUTTON = 1 << 0,
    PINENTRY_STATUS_PIN_REPEATED = 1 << 8,
    PINENTRY_STATUS_PASSWORD_FROM_CACHE = 1 << 9,
    PINENTRY_STATUS_PASSWORD_GENERATED = 1 << 10
  };

/* Information pertaining to pinentry requests.  */
struct pin_entry_info_s
{
  int min_digits; /* min. number of digits required or 0 for freeform entry */
  int max_digits; /* max. number of allowed digits allowed*/
  int max_tries;  /* max. number of allowed tries.  */
  unsigned int constraints_flags;  /* CHECK_CONSTRAINTS_... */
  int failed_tries; /* Number of tries so far failed.  */
  int with_qualitybar; /* Set if the quality bar should be displayed.  */
  int with_repeat;  /* Request repetition of the passphrase.  */
  int repeat_okay;  /* Repetition worked.  */
  unsigned int status; /* Status.  */
  gpg_error_t (*check_cb)(struct pin_entry_info_s *); /* CB used to check
                                                         the PIN */
  void *check_cb_arg;  /* optional argument which might be of use in the CB */
  const char *cb_errtext; /* used by the cb to display a specific error */
  size_t max_length;   /* Allocated length of the buffer PIN. */
  char pin[1];         /* The buffer to hold the PIN or passphrase.
                          It's actual allocated length is given by
                          MAX_LENGTH (above).  */
};


/* Types of the private keys.  */
enum
  {
    PRIVATE_KEY_UNKNOWN = 0,      /* Type of key is not known.  */
    PRIVATE_KEY_CLEAR = 1,        /* The key is not protected.  */
    PRIVATE_KEY_PROTECTED = 2,    /* The key is protected.  */
    PRIVATE_KEY_SHADOWED = 3,     /* The key is a stub for a smartcard
                                     based key.  */
    PROTECTED_SHARED_SECRET = 4,  /* RFU.  */
    PRIVATE_KEY_OPENPGP_NONE = 5  /* openpgp-native with protection "none". */
  };


/* Values for the cache_mode arguments. */
typedef enum
  {
    CACHE_MODE_IGNORE = 0, /* Special mode to bypass the cache. */
    CACHE_MODE_ANY,        /* Any mode except ignore matches. */
    CACHE_MODE_NORMAL,     /* Normal cache (gpg-agent). */
    CACHE_MODE_USER,       /* GET_PASSPHRASE related cache. */
    CACHE_MODE_SSH,        /* SSH related cache. */
    CACHE_MODE_NONCE       /* This is a non-predictable nonce.  */
  }
cache_mode_t;

/* The TTL is seconds used for adding a new nonce mode cache item.  */
#define CACHE_TTL_NONCE 120

/* The TTL in seconds used by the --preset option of some commands.
   This is the default value changeable by an OPTION command.  */
#define CACHE_TTL_OPT_PRESET 900


/* The type of a function to lookup a TTL by a keygrip.  */
typedef int (*lookup_ttl_t)(const char *hexgrip);


/* This is a special version of the usual _() gettext macro.  It
   assumes a server connection control variable with the name "ctrl"
   and uses that to translate a string according to the locale set for
   the connection.  The macro LunderscoreIMPL is used by i18n to
   actually define the inline function when needed.  */
#if defined (ENABLE_NLS) || defined (USE_SIMPLE_GETTEXT)
#define L_(a) agent_Lunderscore (ctrl, (a))
#define LunderscorePROTO                                            \
  static inline const char *agent_Lunderscore (ctrl_t ctrl,         \
                                               const char *string)  \
    GNUPG_GCC_ATTR_FORMAT_ARG(2);
#define LunderscoreIMPL                                         \
  static inline const char *                                    \
  agent_Lunderscore (ctrl_t ctrl, const char *string)           \
  {                                                             \
    return ctrl? i18n_localegettext (ctrl->lc_messages, string) \
      /*     */: gettext (string);                              \
  }
#else
#define L_(a) (a)
#endif


/*-- gpg-agent.c --*/
void agent_exit (int rc)
                GPGRT_ATTR_NORETURN; /* Also implemented in other tools */
void agent_set_progress_cb (void (*cb)(ctrl_t ctrl, const char *what,
                                       int printchar, int current, int total),
                            ctrl_t ctrl);
gpg_error_t agent_copy_startup_env (ctrl_t ctrl);
const char *get_agent_socket_name (void);
const char *get_agent_ssh_socket_name (void);
int get_agent_active_connection_count (void);
#ifdef HAVE_W32_SYSTEM
void *get_agent_scd_notify_event (void);
#endif
void agent_sighup_action (void);
int map_pk_openpgp_to_gcry (int openpgp_algo);

/*-- command.c --*/
gpg_error_t agent_inq_pinentry_launched (ctrl_t ctrl, unsigned long pid,
                                         const char *extra);
gpg_error_t agent_write_status (ctrl_t ctrl, const char *keyword, ...)
     GPGRT_ATTR_SENTINEL(0);
gpg_error_t agent_print_status (ctrl_t ctrl, const char *keyword,
                                const char *format, ...)
     GPGRT_ATTR_PRINTF(3,4);
void bump_key_eventcounter (void);
void bump_card_eventcounter (void);
void start_command_handler (ctrl_t, gnupg_fd_t, gnupg_fd_t);
gpg_error_t pinentry_loopback (ctrl_t, const char *keyword,
	                       unsigned char **buffer, size_t *size,
			       size_t max_length);

#ifdef HAVE_W32_SYSTEM
int serve_mmapped_ssh_request (ctrl_t ctrl,
                               unsigned char *request, size_t maxreqlen);
#endif /*HAVE_W32_SYSTEM*/

/*-- command-ssh.c --*/
ssh_control_file_t ssh_open_control_file (void);
void ssh_close_control_file (ssh_control_file_t cf);
gpg_error_t ssh_read_control_file (ssh_control_file_t cf,
                                   char *r_hexgrip, int *r_disabled,
                                   int *r_ttl, int *r_confirm);
gpg_error_t ssh_search_control_file (ssh_control_file_t cf,
                                     const char *hexgrip,
                                     int *r_disabled,
                                     int *r_ttl, int *r_confirm);

void start_command_handler_ssh (ctrl_t, gnupg_fd_t);

/*-- findkey.c --*/
gpg_error_t agent_modify_description (const char *in, const char *comment,
                                      const gcry_sexp_t key, char **result);
int agent_write_private_key (const unsigned char *grip,
                             const void *buffer, size_t length,
                             int force, int reallyforce,
                             const char *serialno, const char *keyref,
                             const char *dispserialno, time_t timestamp);
gpg_error_t agent_key_from_file (ctrl_t ctrl,
                                 const char *cache_nonce,
                                 const char *desc_text,
                                 const unsigned char *grip,
                                 unsigned char **shadow_info,
                                 cache_mode_t cache_mode,
                                 lookup_ttl_t lookup_ttl,
                                 gcry_sexp_t *result,
                                 char **r_passphrase,
                                 uint64_t *r_timestamp);
gpg_error_t agent_raw_key_from_file (ctrl_t ctrl, const unsigned char *grip,
                                     gcry_sexp_t *result);
gpg_error_t agent_keymeta_from_file (ctrl_t ctrl, const unsigned char *grip,
                                     nvc_t *r_keymeta);
gpg_error_t agent_public_key_from_file (ctrl_t ctrl,
                                        const unsigned char *grip,
                                        gcry_sexp_t *result);
int agent_is_dsa_key (gcry_sexp_t s_key);
int agent_is_eddsa_key (gcry_sexp_t s_key);
int agent_key_available (const unsigned char *grip);
gpg_error_t agent_key_info_from_file (ctrl_t ctrl, const unsigned char *grip,
                                      int *r_keytype,
                                      unsigned char **r_shadow_info);
gpg_error_t agent_delete_key (ctrl_t ctrl, const char *desc_text,
                              const unsigned char *grip,
                              int force, int only_stubs);

/*-- call-pinentry.c --*/
void initialize_module_call_pinentry (void);
void agent_query_dump_state (void);
void agent_reset_query (ctrl_t ctrl);
int pinentry_active_p (ctrl_t ctrl, int waitseconds);
gpg_error_t agent_askpin (ctrl_t ctrl,
                          const char *desc_text, const char *prompt_text,
                          const char *inital_errtext,
                          struct pin_entry_info_s *pininfo,
                          const char *keyinfo, cache_mode_t cache_mode);
int agent_get_passphrase (ctrl_t ctrl, char **retpass,
                          const char *desc, const char *prompt,
                          const char *errtext, int with_qualitybar,
			  const char *keyinfo, cache_mode_t cache_mode,
                          struct pin_entry_info_s *pininfo);
int agent_get_confirmation (ctrl_t ctrl, const char *desc, const char *ok,
			    const char *notokay, int with_cancel);
int agent_show_message (ctrl_t ctrl, const char *desc, const char *ok_btn);
int agent_popup_message_start (ctrl_t ctrl,
                               const char *desc, const char *ok_btn);
void agent_popup_message_stop (ctrl_t ctrl);
int agent_clear_passphrase (ctrl_t ctrl,
			    const char *keyinfo, cache_mode_t cache_mode);

/*-- cache.c --*/
void initialize_module_cache (void);
void deinitialize_module_cache (void);
void agent_cache_housekeeping (void);
void agent_flush_cache (void);
int agent_put_cache (ctrl_t ctrl, const char *key, cache_mode_t cache_mode,
                     const char *data, int ttl);
char *agent_get_cache (ctrl_t ctrl, const char *key, cache_mode_t cache_mode);
void agent_store_cache_hit (const char *key);


/*-- pksign.c --*/
gpg_error_t agent_pksign_do (ctrl_t ctrl, const char *cache_nonce,
                             const char *desc_text,
                             gcry_sexp_t *signature_sexp,
                             cache_mode_t cache_mode, lookup_ttl_t lookup_ttl,
                             const void *overridedata, size_t overridedatalen);
gpg_error_t agent_pksign (ctrl_t ctrl, const char *cache_nonce,
                          const char *desc_text,
                          membuf_t *outbuf, cache_mode_t cache_mode);

/*-- pkdecrypt.c --*/
int agent_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                     const unsigned char *ciphertext, size_t ciphertextlen,
                     membuf_t *outbuf, int *r_padding);

/*-- genkey.c --*/
#define CHECK_CONSTRAINTS_NOT_EMPTY  1
#define CHECK_CONSTRAINTS_NEW_SYMKEY 2

int check_passphrase_constraints (ctrl_t ctrl, const char *pw,
                                  unsigned int flags,
				  char **failed_constraint);
gpg_error_t agent_ask_new_passphrase (ctrl_t ctrl, const char *prompt,
                                      char **r_passphrase);
int agent_genkey (ctrl_t ctrl, const char *cache_nonce, time_t timestamp,
                  const char *keyparam, size_t keyparmlen,
                  int no_protection, const char *override_passphrase,
                  int preset, membuf_t *outbuf);
gpg_error_t agent_protect_and_store (ctrl_t ctrl, gcry_sexp_t s_skey,
                                     char **passphrase_addr);

/*-- protect.c --*/
void set_s2k_calibration_time (unsigned int milliseconds);
unsigned long get_calibrated_s2k_count (void);
unsigned long get_standard_s2k_count (void);
unsigned char get_standard_s2k_count_rfc4880 (void);
unsigned long get_standard_s2k_time (void);
int agent_protect (const unsigned char *plainkey, const char *passphrase,
                   unsigned char **result, size_t *resultlen,
		   unsigned long s2k_count);
gpg_error_t agent_unprotect (ctrl_t ctrl,
                     const unsigned char *protectedkey, const char *passphrase,
                     gnupg_isotime_t protected_at,
                     unsigned char **result, size_t *resultlen);
int agent_private_key_type (const unsigned char *privatekey);
unsigned char *make_shadow_info (const char *serialno, const char *idstring);
int agent_shadow_key (const unsigned char *pubkey,
                      const unsigned char *shadow_info,
                      unsigned char **result);
gpg_error_t agent_get_shadow_info (const unsigned char *shadowkey,
                                   unsigned char const **shadow_info);
gpg_error_t parse_shadow_info (const unsigned char *shadow_info,
                               char **r_hexsn, char **r_idstr, int *r_pinlen);
gpg_error_t s2k_hash_passphrase (const char *passphrase, int hashalgo,
                                 int s2kmode,
                                 const unsigned char *s2ksalt,
                                 unsigned int s2kcount,
                                 unsigned char *key, size_t keylen);
gpg_error_t agent_write_shadow_key (const unsigned char *grip,
                                    const char *serialno, const char *keyid,
                                    const unsigned char *pkbuf, int force,
                                    int reallyforce,
                                    const char *dispserialno);


/*-- trustlist.c --*/
void initialize_module_trustlist (void);
gpg_error_t agent_istrusted (ctrl_t ctrl, const char *fpr, int *r_disabled);
gpg_error_t agent_listtrusted (ctrl_t ctrl, void *assuan_context,
                               int status_mode);
gpg_error_t agent_marktrusted (ctrl_t ctrl, const char *name,
                               const char *fpr, int flag);
void agent_reload_trustlist (void);


/*-- divert-scd.c --*/
int divert_pksign (ctrl_t ctrl, const char *desc_text,
                   const unsigned char *digest, size_t digestlen, int algo,
                   const unsigned char *grip,
                   const unsigned char *shadow_info, unsigned char **r_sig,
                   size_t *r_siglen);
int divert_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                      const unsigned char *cipher,
                      const unsigned char *grip,
                      const unsigned char *shadow_info,
                      char **r_buf, size_t *r_len, int *r_padding);
int divert_generic_cmd (ctrl_t ctrl,
                        const char *cmdline, void *assuan_context);
int divert_writekey (ctrl_t ctrl, int force, const char *serialno,
                     const char *id, const char *keydata, size_t keydatalen);


/*-- call-scd.c --*/
void initialize_module_call_scd (void);
void agent_scd_dump_state (void);
int agent_scd_check_running (void);
void agent_scd_check_aliveness (void);
int agent_reset_scd (ctrl_t ctrl);
int agent_card_learn (ctrl_t ctrl,
                      void (*kpinfo_cb)(void*, const char *),
                      void *kpinfo_cb_arg,
                      void (*certinfo_cb)(void*, const char *),
                      void *certinfo_cb_arg,
                      void (*sinfo_cb)(void*, const char *,
                                       size_t, const char *),
                      void *sinfo_cb_arg);
int agent_card_serialno (ctrl_t ctrl, char **r_serialno, const char *demand);
int agent_card_pksign (ctrl_t ctrl,
                       const char *keyid,
                       int (*getpin_cb)(void *, const char *,
                                        const char *, char*, size_t),
                       void *getpin_cb_arg,
                       const char *desc_text,
                       int mdalgo,
                       const unsigned char *indata, size_t indatalen,
                       unsigned char **r_buf, size_t *r_buflen);
int agent_card_pkdecrypt (ctrl_t ctrl,
                          const char *keyid,
                          int (*getpin_cb)(void *, const char *,
                                           const char *, char*,size_t),
                          void *getpin_cb_arg,
                          const char *desc_text,
                          const unsigned char *indata, size_t indatalen,
                          char **r_buf, size_t *r_buflen, int *r_padding);
int agent_card_readcert (ctrl_t ctrl,
                         const char *id, char **r_buf, size_t *r_buflen);
int agent_card_readkey (ctrl_t ctrl, const char *id, unsigned char **r_buf);
int agent_card_writekey (ctrl_t ctrl, int force, const char *serialno,
                         const char *id, const char *keydata,
                         size_t keydatalen,
                         int (*getpin_cb)(void *, const char *,
                                          const char *, char*, size_t),
                         void *getpin_cb_arg);
gpg_error_t agent_card_getattr (ctrl_t ctrl, const char *name, char **result);
gpg_error_t agent_card_cardlist (ctrl_t ctrl, strlist_t *result);
int agent_card_scd (ctrl_t ctrl, const char *cmdline,
                    int (*getpin_cb)(void *, const char *,
                                     const char *, char*, size_t),
                    void *getpin_cb_arg, void *assuan_context);
void agent_card_killscd (void);


/*-- learncard.c --*/
int agent_handle_learn (ctrl_t ctrl, int send, void *assuan_context,
                        int force, int reallyforce);


/*-- cvt-openpgp.c --*/
gpg_error_t
extract_private_key (gcry_sexp_t s_key, int req_private_key_data,
                     const char **r_algoname, int *r_npkey, int *r_nskey,
                     const char **r_format,
                     gcry_mpi_t *mpi_array, int arraysize,
                     gcry_sexp_t *r_curve, gcry_sexp_t *r_flags);

#endif /*AGENT_H*/
