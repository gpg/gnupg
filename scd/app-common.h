/* app-common.h - Common declarations for all card applications
 * Copyright (C) 2003, 2005, 2008 Free Software Foundation, Inc.
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
 *
 * $Id$
 */

#ifndef GNUPG_SCD_APP_COMMON_H
#define GNUPG_SCD_APP_COMMON_H

#if GNUPG_MAJOR_VERSION == 1
# ifdef ENABLE_AGENT_SUPPORT
# include "assuan.h"
# endif 
#else
# include <ksba.h>
#endif


#define APP_CHANGE_FLAG_RESET    1
#define APP_CHANGE_FLAG_NULLPIN  2


struct app_local_s;  /* Defined by all app-*.c.  */

struct app_ctx_s {
  /* Number of connections currently using this application context.
     If this is not 0 the application has been initialized and the
     function pointers may be used.  Note that for unsupported
     operations the particular function pointer is set to NULL */
  unsigned int ref_count;

  /* Flag indicating that a reset has been done for that application
     and that this context is merely lingering and just should not be
     reused.  */
  int no_reuse;            

  /* Used reader slot. */
  int slot;     

  /* If this is used by GnuPG 1.4 we need to know the assuan context
     in case we need to divert the operation to an already running
     agent.  This if ASSUAN_CTX is not NULL we take this as indication
     that all operations are diverted to gpg-agent. */
#if GNUPG_MAJOR_VERSION == 1
  assuan_context_t assuan_ctx;
#endif /*GNUPG_MAJOR_VERSION == 1*/

  unsigned char *serialno; /* Serialnumber in raw form, allocated. */
  size_t serialnolen;      /* Length in octets of serialnumber. */
  const char *apptype;
  unsigned int card_version;
  int did_chv1;
  int force_chv1;   /* True if the card does not cache CHV1. */
  int did_chv2;
  int did_chv3;
  struct app_local_s *app_local;  /* Local to the application. */
  struct {
    void (*deinit) (app_t app);
    gpg_error_t (*learn_status) (app_t app, ctrl_t ctrl, unsigned int flags);
    gpg_error_t (*readcert) (app_t app, const char *certid,
                     unsigned char **cert, size_t *certlen);
    gpg_error_t (*readkey) (app_t app, const char *certid,
                    unsigned char **pk, size_t *pklen);
    gpg_error_t (*getattr) (app_t app, ctrl_t ctrl, const char *name);
    gpg_error_t (*setattr) (app_t app, const char *name,
                    gpg_error_t (*pincb)(void*, const char *, char **),
                    void *pincb_arg,
                    const unsigned char *value, size_t valuelen);
    gpg_error_t (*sign) (app_t app,
                 const char *keyidstr, int hashalgo,
                 gpg_error_t (*pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const void *indata, size_t indatalen,
                 unsigned char **outdata, size_t *outdatalen );
    gpg_error_t (*auth) (app_t app, const char *keyidstr,
                 gpg_error_t (*pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const void *indata, size_t indatalen,
                 unsigned char **outdata, size_t *outdatalen);
    gpg_error_t (*decipher) (app_t app, const char *keyidstr,
                     gpg_error_t (*pincb)(void*, const char *, char **),
                     void *pincb_arg,
                     const void *indata, size_t indatalen,
                     unsigned char **outdata, size_t *outdatalen);
    gpg_error_t (*writecert) (app_t app, ctrl_t ctrl,
                              const char *certid,
                              gpg_error_t (*pincb)(void*,const char *,char **),
                              void *pincb_arg,
                              const unsigned char *data, size_t datalen);
    gpg_error_t (*writekey) (app_t app, ctrl_t ctrl,
                             const char *keyid, unsigned int flags,
                             gpg_error_t (*pincb)(void*,const char *,char **),
                             void *pincb_arg,
                             const unsigned char *pk, size_t pklen);
    gpg_error_t (*genkey) (app_t app, ctrl_t ctrl,
                           const char *keynostr, unsigned int flags,
                           time_t createtime,
                           gpg_error_t (*pincb)(void*, const char *, char **),
                           void *pincb_arg);
    gpg_error_t (*change_pin) (app_t app, ctrl_t ctrl,
                       const char *chvnostr, unsigned int flags,
                       gpg_error_t (*pincb)(void*, const char *, char **),
                       void *pincb_arg);
    gpg_error_t (*check_pin) (app_t app, const char *keyidstr,
                      gpg_error_t (*pincb)(void*, const char *, char **),
                      void *pincb_arg);
  } fnc;

};

#if GNUPG_MAJOR_VERSION == 1
gpg_error_t app_select_openpgp (app_t app);
gpg_error_t app_get_serial_and_stamp (app_t app, char **serial, time_t *stamp);
gpg_error_t app_openpgp_storekey (app_t app, int keyno,
                          unsigned char *template, size_t template_len,
                          time_t created_at,
                          const unsigned char *m, size_t mlen,
                          const unsigned char *e, size_t elen,
                          gpg_error_t (*pincb)(void*, const char *, char **),
                          void *pincb_arg);
#else
/*-- app-help.c --*/
unsigned int app_help_count_bits (const unsigned char *a, size_t len);
gpg_error_t app_help_get_keygrip_string (ksba_cert_t cert, char *hexkeygrip);
size_t app_help_read_length_of_cert (int slot, int fid, size_t *r_certoff);


/*-- app.c --*/
void app_dump_state (void);
void application_notify_card_reset (int slot);
gpg_error_t check_application_conflict (ctrl_t ctrl, const char *name);
gpg_error_t select_application (ctrl_t ctrl, int slot, const char *name,
                                app_t *r_app);
char *get_supported_applications (void);
void release_application (app_t app);
gpg_error_t app_munge_serialno (app_t app);
gpg_error_t app_get_serial_and_stamp (app_t app, char **serial, time_t *stamp);
gpg_error_t app_write_learn_status (app_t app, ctrl_t ctrl, 
                                    unsigned int flags);
gpg_error_t app_readcert (app_t app, const char *certid,
                  unsigned char **cert, size_t *certlen);
gpg_error_t app_readkey (app_t app, const char *keyid,
                 unsigned char **pk, size_t *pklen);
gpg_error_t app_getattr (app_t app, ctrl_t ctrl, const char *name);
gpg_error_t app_setattr (app_t app, const char *name,
                 gpg_error_t (*pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const unsigned char *value, size_t valuelen);
gpg_error_t app_sign (app_t app, const char *keyidstr, int hashalgo,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              unsigned char **outdata, size_t *outdatalen );
gpg_error_t app_auth (app_t app, const char *keyidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              unsigned char **outdata, size_t *outdatalen);
gpg_error_t app_decipher (app_t app, const char *keyidstr,
                  gpg_error_t (*pincb)(void*, const char *, char **),
                  void *pincb_arg,
                  const void *indata, size_t indatalen,
                  unsigned char **outdata, size_t *outdatalen );
gpg_error_t app_writecert (app_t app, ctrl_t ctrl,
                           const char *certidstr,
                           gpg_error_t (*pincb)(void*, const char *, char **),
                           void *pincb_arg,
                           const unsigned char *keydata, size_t keydatalen);
gpg_error_t app_writekey (app_t app, ctrl_t ctrl,
                          const char *keyidstr, unsigned int flags,
                          gpg_error_t (*pincb)(void*, const char *, char **),
                          void *pincb_arg,
                          const unsigned char *keydata, size_t keydatalen);
gpg_error_t app_genkey (app_t app, ctrl_t ctrl,
                        const char *keynostr, unsigned int flags,
                        time_t createtime,
                        gpg_error_t (*pincb)(void*, const char *, char **),
                        void *pincb_arg);
gpg_error_t app_get_challenge (app_t app, size_t nbytes,
                               unsigned char *buffer);
gpg_error_t app_change_pin (app_t app, ctrl_t ctrl,
                    const char *chvnostr, int reset_mode,
                    gpg_error_t (*pincb)(void*, const char *, char **),
                    void *pincb_arg);
gpg_error_t app_check_pin (app_t app, const char *keyidstr,
                   gpg_error_t (*pincb)(void*, const char *, char **),
                   void *pincb_arg);


/*-- app-openpgp.c --*/
gpg_error_t app_select_openpgp (app_t app);

/*-- app-nks.c --*/
gpg_error_t app_select_nks (app_t app);

/*-- app-dinsig.c --*/
gpg_error_t app_select_dinsig (app_t app);

/*-- app-p15.c --*/
gpg_error_t app_select_p15 (app_t app);

/*-- app-geldkarte.c --*/
gpg_error_t app_select_geldkarte (app_t app);


#endif



#endif /*GNUPG_SCD_APP_COMMON_H*/



