/* agent.h - Global definitions for the agent
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

#ifndef AGENT_H
#define AGENT_H

#include <gcrypt.h>
#include "../common/util.h"
#include "../common/errors.h"

#define MAX_DIGEST_LEN 24 

/* A large struct name "opt" to keep global flags */
struct {
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int verbose;      /* verbosity level */
  int quiet;        /* be as quiet as possible */
  int dry_run;      /* don't change any persistent data */
  int batch;        /* batch mode */
  const char *homedir; /* configuration directory name */
  const char *pinentry_program; 
  char *display;
  char *ttyname;
  char *ttytype;
  char *lc_ctype;
  char *lc_messages;
  const char *scdaemon_program; 
  int no_grab;      /* don't let the pinentry grab the keyboard */
  unsigned long def_cache_ttl;

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

struct server_control_s {
  struct server_local_s *server_local;
  struct {
    int algo;
    unsigned char value[MAX_DIGEST_LEN];
    int valuelen;
  } digest;
  char keygrip[20];
  int have_keygrip;

};
typedef struct server_control_s *CTRL;


struct pin_entry_info_s {
  int min_digits; /* min. number of digits required or 0 for freeform entry */
  int max_digits; /* max. number of allowed digits allowed*/
  int max_tries;
  int failed_tries;
  int (*check_cb)(struct pin_entry_info_s *); /* CB used to check the PIN */
  void *check_cb_arg;  /* optional argument which might be of use in the CB */
  const char *cb_errtext; /* used by the cb to displaye a specific error */
  size_t max_length; /* allocated length of the buffer */
  char pin[1];
};


enum {
  PRIVATE_KEY_UNKNOWN = 0,
  PRIVATE_KEY_CLEAR = 1,
  PRIVATE_KEY_PROTECTED = 2,
  PRIVATE_KEY_SHADOWED = 3
};

/*-- gpg-agent.c --*/
void agent_exit (int rc); /* also implemented in other tools */

/*-- trans.c --*/
const char *trans (const char *text);

/*-- command.c --*/
void start_command_handler (int, int);

/*-- findkey.c --*/
int agent_write_private_key (const unsigned char *grip,
                             const void *buffer, size_t length, int force);
GCRY_SEXP agent_key_from_file (const unsigned char *grip,
                               unsigned char **shadow_info);
int agent_key_available (const unsigned char *grip);

/*-- query.c --*/
int agent_askpin (const char *desc_text, struct pin_entry_info_s *pininfo);
int agent_get_passphrase (char **retpass,
                          const char *desc, const char *prompt,
                          const char *errtext);
int agent_get_confirmation (const char *desc, const char *ok,
			    const char *cancel);

/*-- cache.c --*/
int agent_put_cache (const char *key, const char *data, int ttl);
const char *agent_get_cache (const char *key, void **cache_id);
void agent_unlock_cache_entry (void **cache_id);


/*-- pksign.c --*/
int agent_pksign (CTRL ctrl, FILE *outfp);

/*-- pkdecrypt.c --*/
int agent_pkdecrypt (CTRL ctrl, const char *ciphertext, size_t ciphertextlen,
                     FILE *outfp);

/*-- genkey.c --*/
int agent_genkey (CTRL ctrl,
                  const char *keyparam, size_t keyparmlen, FILE *outfp);

/*-- protect.c --*/
int agent_protect (const unsigned char *plainkey, const char *passphrase,
                   unsigned char **result, size_t *resultlen);
int agent_unprotect (const unsigned char *protectedkey, const char *passphrase,
                     unsigned char **result, size_t *resultlen);
int agent_private_key_type (const unsigned char *privatekey);
int agent_shadow_key (const unsigned char *pubkey,
                      const unsigned char *shadow_info,
                      unsigned char **result);
int agent_get_shadow_info (const unsigned char *shadowkey,
                           unsigned char const **shadow_info);


/*-- trustlist.c --*/
int agent_istrusted (const char *fpr);
int agent_listtrusted (void *assuan_context);
int agent_marktrusted (const char *name, const char *fpr, int flag);


/*-- divert-scd.c --*/
int divert_pksign (const unsigned char *digest, size_t digestlen, int algo,
                   const unsigned char *shadow_info, unsigned char **r_sig);
int divert_pkdecrypt (const unsigned char *cipher,
                      const unsigned char *shadow_info,
                      char **r_buf, size_t *r_len);

/*-- call-scd.c --*/
int agent_card_learn (void (*kpinfo_cb)(void*, const char *),
                      void *kpinfo_cb_arg);
int agent_card_serialno (char **r_serialno);
int agent_card_pksign (const char *keyid,
                       int (*getpin_cb)(void *, const char *, char*, size_t),
                       void *getpin_cb_arg,
                       const unsigned char *indata, size_t indatalen,
                       char **r_buf, size_t *r_buflen);
int agent_card_pkdecrypt (const char *keyid,
                          int (*getpin_cb)(void *, const char *, char*,size_t),
                          void *getpin_cb_arg,
                          const unsigned char *indata, size_t indatalen,
                          char **r_buf, size_t *r_buflen);
int agent_card_readcert (const char *id, char **r_buf, size_t *r_buflen);
int agent_card_readkey (const char *id, unsigned char **r_buf);


/*-- learncard.c --*/
int agent_handle_learn (void *assuan_context);


#endif /*AGENT_H*/
