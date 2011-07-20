/* agent.h - Global definitions for the agent
 *	Copyright (C) 2001, 2002, 2003, 2005 Free Software Foundation, Inc.
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

/* To convey some special hash algorithms we use algorithm numbers
   reserved for application use. */
#ifndef GCRY_MODULE_ID_USER
#define GCRY_MODULE_ID_USER 1024
#endif
#define MD_USER_TLS_MD5SHA1 (GCRY_MODULE_ID_USER+1)

/* Maximum length of a digest.  */
#define MAX_DIGEST_LEN 64

/* A large struct name "opt" to keep global flags */
struct
{
  unsigned int debug;  /* Debug flags (DBG_foo_VALUE) */
  int verbose;         /* Verbosity level */
  int quiet;           /* Be as quiet as possible */
  int dry_run;         /* Don't change any persistent data */
  int batch;           /* Batch mode */
  const char *homedir; /* Configuration directory name */

  /* Environment setting gathered at program start or changed using the
     Assuan command UPDATESTARTUPTTY. */
  session_env_t startup_env;
  char *startup_lc_ctype;
  char *startup_lc_messages;

  /* True if we are listening on the standard socket.  */
  int use_standard_socket;

  /* True if we handle sigusr2.  */
  int sigusr2_enabled;

  const char *pinentry_program; /* Filename of the program to start as
                                   pinentry.  */
  const char *scdaemon_program; /* Filename of the program to handle
                                   smartcard tasks.  */
  int disable_scdaemon;         /* Never use the SCdaemon. */
  int no_grab;         /* Don't let the pinentry grab the keyboard */

  /* The name of the file pinentry shall tocuh before exiting.  If
     this is not set the filoe name of the standard socket is used. */
  const char *pinentry_touch_file;

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
  /* File name with a patternfile or NULL if not enabled.  */
  const char *check_passphrase_pattern;
  /* If not 0 the user is asked to change his passphrase after these
     number of days.  */
  unsigned int max_passphrase_days;
  /* If set, a passphrase history will be written and checked at each
     passphrase change.  */
  int enable_passhrase_history;

  int running_detached; /* We are running detached from the tty. */

  int ignore_cache_for_signing;
  int allow_mark_trusted;
  int allow_preset_passphrase;
  int keep_tty;      /* Don't switch the TTY (for pinentry) on request */
  int keep_display;  /* Don't switch the DISPLAY (for pinentry) on request */
  int ssh_support;   /* Enable ssh-agent emulation.  */
} opt;


#define DBG_COMMAND_VALUE 1	/* debug commands i/o */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_ASSUAN_VALUE 1024

#define DBG_COMMAND (opt.debug & DBG_COMMAND_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_ASSUAN  (opt.debug & DBG_ASSUAN_VALUE)

struct server_local_s;
struct scd_local_s;

/* Collection of data per session (aka connection). */
struct server_control_s
{
  /* Private data used to fire up the connection thread.  We use this
     structure do avoid an extra allocation for just a few bytes. */
  struct {
    gnupg_fd_t fd;
  } thread_startup;

  /* Private data of the server (command.c). */
  struct server_local_s *server_local;

  /* Private data of the SCdaemon (call-scd.c). */
  struct scd_local_s *scd_local;

  session_env_t session_env;
  char *lc_ctype;
  char *lc_messages;

  struct {
    int algo;
    unsigned char value[MAX_DIGEST_LEN];
    int valuelen;
    int raw_value: 1;
  } digest;
  unsigned char keygrip[20];
  int have_keygrip;

  int use_auth_call; /* Hack to send the PKAUTH command instead of the
                        PKSIGN command to the scdaemon.  */
  int in_passwd;     /* Hack to inhibit enforced passphrase change
                        during an explicit passwd command.  */
};


struct pin_entry_info_s
{
  int min_digits; /* min. number of digits required or 0 for freeform entry */
  int max_digits; /* max. number of allowed digits allowed*/
  int max_tries;
  int failed_tries;
  int with_qualitybar; /* Set if the quality bar should be displayed.  */
  int (*check_cb)(struct pin_entry_info_s *); /* CB used to check the PIN */
  void *check_cb_arg;  /* optional argument which might be of use in the CB */
  const char *cb_errtext; /* used by the cb to displaye a specific error */
  size_t max_length; /* allocated length of the buffer */
  char pin[1];
};


enum
  {
    PRIVATE_KEY_UNKNOWN = 0,
    PRIVATE_KEY_CLEAR = 1,
    PRIVATE_KEY_PROTECTED = 2,
    PRIVATE_KEY_SHADOWED = 3
  };


/* Values for the cache_mode arguments. */
typedef enum
  {
    CACHE_MODE_IGNORE = 0, /* Special mode to bypass the cache. */
    CACHE_MODE_ANY,        /* Any mode except ignore matches. */
    CACHE_MODE_NORMAL,     /* Normal cache (gpg-agent). */
    CACHE_MODE_USER,       /* GET_PASSPHRASE related cache. */
    CACHE_MODE_SSH         /* SSH related cache. */
  }
cache_mode_t;


/* The type of a function to lookup a TTL by a keygrip.  */
typedef int (*lookup_ttl_t)(const char *hexgrip);


/*-- gpg-agent.c --*/
void agent_exit (int rc) JNLIB_GCC_A_NR; /* Also implemented in other tools */
const char *get_agent_socket_name (void);
const char *get_agent_ssh_socket_name (void);
#ifdef HAVE_W32_SYSTEM
void *get_agent_scd_notify_event (void);
#endif
void agent_sighup_action (void);

/*-- command.c --*/
gpg_error_t agent_inq_pinentry_launched (ctrl_t ctrl, unsigned long pid);
gpg_error_t agent_write_status (ctrl_t ctrl, const char *keyword, ...)
     GNUPG_GCC_A_SENTINEL(0);
void bump_key_eventcounter (void);
void bump_card_eventcounter (void);
void start_command_handler (ctrl_t, gnupg_fd_t, gnupg_fd_t);

/*-- command-ssh.c --*/
void start_command_handler_ssh (ctrl_t, gnupg_fd_t);

/*-- findkey.c --*/
int agent_write_private_key (const unsigned char *grip,
                             const void *buffer, size_t length, int force);
gpg_error_t agent_key_from_file (ctrl_t ctrl,
                                 const char *desc_text,
                                 const unsigned char *grip,
                                 unsigned char **shadow_info,
                                 cache_mode_t cache_mode,
                                 lookup_ttl_t lookup_ttl,
                                 gcry_sexp_t *result);
gpg_error_t agent_raw_key_from_file (ctrl_t ctrl, const unsigned char *grip,
                                     gcry_sexp_t *result);
gpg_error_t agent_public_key_from_file (ctrl_t ctrl,
                                        const unsigned char *grip,
                                        gcry_sexp_t *result);
int agent_key_available (const unsigned char *grip);
gpg_error_t agent_key_info_from_file (ctrl_t ctrl, const unsigned char *grip,
                                      int *r_keytype,
                                      unsigned char **r_shadow_info);

/*-- call-pinentry.c --*/
void initialize_module_call_pinentry (void);
void agent_query_dump_state (void);
void agent_reset_query (ctrl_t ctrl);
int pinentry_active_p (ctrl_t ctrl, int waitseconds);
int agent_askpin (ctrl_t ctrl,
                  const char *desc_text, const char *prompt_text,
                  const char *inital_errtext,
                  struct pin_entry_info_s *pininfo);
int agent_get_passphrase (ctrl_t ctrl, char **retpass,
                          const char *desc, const char *prompt,
                          const char *errtext, int with_qualitybar);
int agent_get_confirmation (ctrl_t ctrl, const char *desc, const char *ok,
			    const char *notokay, int with_cancel);
int agent_show_message (ctrl_t ctrl, const char *desc, const char *ok_btn);
int agent_popup_message_start (ctrl_t ctrl,
                               const char *desc, const char *ok_btn);
void agent_popup_message_stop (ctrl_t ctrl);


/*-- cache.c --*/
void agent_flush_cache (void);
int agent_put_cache (const char *key, cache_mode_t cache_mode,
                     const char *data, int ttl);
const char *agent_get_cache (const char *key, cache_mode_t cache_mode,
                             void **cache_id);
void agent_unlock_cache_entry (void **cache_id);


/*-- pksign.c --*/
int agent_pksign_do (ctrl_t ctrl, const char *desc_text,
		     gcry_sexp_t *signature_sexp,
                     cache_mode_t cache_mode, lookup_ttl_t lookup_ttl);
int agent_pksign (ctrl_t ctrl, const char *desc_text,
                  membuf_t *outbuf, cache_mode_t cache_mode);

/*-- pkdecrypt.c --*/
int agent_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                     const unsigned char *ciphertext, size_t ciphertextlen,
                     membuf_t *outbuf);

/*-- genkey.c --*/
int check_passphrase_constraints (ctrl_t ctrl, const char *pw, int silent);
int agent_genkey (ctrl_t ctrl,
                  const char *keyparam, size_t keyparmlen, membuf_t *outbuf);
int agent_protect_and_store (ctrl_t ctrl, gcry_sexp_t s_skey);

/*-- protect.c --*/
unsigned long get_standard_s2k_count (void);
int agent_protect (const unsigned char *plainkey, const char *passphrase,
                   unsigned char **result, size_t *resultlen);
int agent_unprotect (const unsigned char *protectedkey, const char *passphrase,
                     gnupg_isotime_t protected_at,
                     unsigned char **result, size_t *resultlen);
int agent_private_key_type (const unsigned char *privatekey);
unsigned char *make_shadow_info (const char *serialno, const char *idstring);
int agent_shadow_key (const unsigned char *pubkey,
                      const unsigned char *shadow_info,
                      unsigned char **result);
int agent_get_shadow_info (const unsigned char *shadowkey,
                           unsigned char const **shadow_info);
gpg_error_t parse_shadow_info (const unsigned char *shadow_info,
                               char **r_hexsn, char **r_idstr);


/*-- trustlist.c --*/
void initialize_module_trustlist (void);
gpg_error_t agent_istrusted (ctrl_t ctrl, const char *fpr, int *r_disabled);
gpg_error_t agent_listtrusted (void *assuan_context);
gpg_error_t agent_marktrusted (ctrl_t ctrl, const char *name,
                               const char *fpr, int flag);
void agent_reload_trustlist (void);


/*-- divert-scd.c --*/
int divert_pksign (ctrl_t ctrl,
                   const unsigned char *digest, size_t digestlen, int algo,
                   const unsigned char *shadow_info, unsigned char **r_sig);
int divert_pkdecrypt (ctrl_t ctrl,
                      const unsigned char *cipher,
                      const unsigned char *shadow_info,
                      char **r_buf, size_t *r_len);
int divert_generic_cmd (ctrl_t ctrl,
                        const char *cmdline, void *assuan_context);


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
int agent_card_serialno (ctrl_t ctrl, char **r_serialno);
int agent_card_pksign (ctrl_t ctrl,
                       const char *keyid,
                       int (*getpin_cb)(void *, const char *, char*, size_t),
                       void *getpin_cb_arg,
                       const unsigned char *indata, size_t indatalen,
                       unsigned char **r_buf, size_t *r_buflen);
int agent_card_pkdecrypt (ctrl_t ctrl,
                          const char *keyid,
                          int (*getpin_cb)(void *, const char *, char*,size_t),
                          void *getpin_cb_arg,
                          const unsigned char *indata, size_t indatalen,
                          char **r_buf, size_t *r_buflen);
int agent_card_readcert (ctrl_t ctrl,
                         const char *id, char **r_buf, size_t *r_buflen);
int agent_card_readkey (ctrl_t ctrl, const char *id, unsigned char **r_buf);
gpg_error_t agent_card_getattr (ctrl_t ctrl, const char *name, char **result);
int agent_card_scd (ctrl_t ctrl, const char *cmdline,
                    int (*getpin_cb)(void *, const char *, char*, size_t),
                    void *getpin_cb_arg, void *assuan_context);


/*-- learncard.c --*/
int agent_handle_learn (ctrl_t ctrl, void *assuan_context);


#endif /*AGENT_H*/
