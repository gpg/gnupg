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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * $Id$
 */

#ifndef GNUPG_SCD_APP_COMMON_H
#define GNUPG_SCD_APP_COMMON_H

#include <npth.h>
#include <ksba.h>


#define APP_CHANGE_FLAG_RESET    1
#define APP_CHANGE_FLAG_NULLPIN  2

/* Bit flags set by the decipher function into R_INFO.  */
#define APP_DECIPHER_INFO_NOPAD  1  /* Padding has been removed.  */


struct app_local_s;  /* Defined by all app-*.c.  */

struct app_ctx_s {
  struct app_ctx_s *next;

  npth_mutex_t lock;

  /* Number of connections currently using this application context.
     If this is not 0 the application has been initialized and the
     function pointers may be used.  Note that for unsupported
     operations the particular function pointer is set to NULL */
  unsigned int ref_count;

  /* Used reader slot. */
  int slot;

  unsigned char *serialno; /* Serialnumber in raw form, allocated. */
  size_t serialnolen;      /* Length in octets of serialnumber. */
  const char *apptype;
  unsigned int card_version;
  unsigned int card_status;
  unsigned int reset_requested:1;
  unsigned int periodical_check_needed:1;
  unsigned int did_chv1:1;
  unsigned int force_chv1:1;   /* True if the card does not cache CHV1. */
  unsigned int did_chv2:1;
  unsigned int did_chv3:1;
  struct app_local_s *app_local;  /* Local to the application. */
  struct {
    void (*deinit) (app_t app);
    gpg_error_t (*learn_status) (app_t app, ctrl_t ctrl, unsigned int flags);
    gpg_error_t (*readcert) (app_t app, const char *certid,
                     unsigned char **cert, size_t *certlen);
    gpg_error_t (*readkey) (app_t app, int advanced, const char *certid,
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
                             unsigned char **outdata, size_t *outdatalen,
                             unsigned int *r_info);
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

/*-- app-help.c --*/
unsigned int app_help_count_bits (const unsigned char *a, size_t len);
gpg_error_t app_help_get_keygrip_string (ksba_cert_t cert, char *hexkeygrip);
size_t app_help_read_length_of_cert (int slot, int fid, size_t *r_certoff);


/*-- app.c --*/
void app_send_card_list (ctrl_t ctrl);
char *app_get_serialno (app_t app);

void app_dump_state (void);
void application_notify_card_reset (int slot);
gpg_error_t check_application_conflict (const char *name, app_t app);
gpg_error_t app_reset (app_t app, ctrl_t ctrl, int send_reset);
gpg_error_t select_application (ctrl_t ctrl, const char *name, app_t *r_app,
                                int scan, const unsigned char *serialno_bin,
                                size_t serialno_bin_len);
char *get_supported_applications (void);
void release_application (app_t app, int locked_already);
gpg_error_t app_munge_serialno (app_t app);
gpg_error_t app_write_learn_status (app_t app, ctrl_t ctrl,
                                    unsigned int flags);
gpg_error_t app_readcert (app_t app, ctrl_t ctrl, const char *certid,
                  unsigned char **cert, size_t *certlen);
gpg_error_t app_readkey (app_t app, ctrl_t ctrl, int advanced,
                 const char *keyid, unsigned char **pk, size_t *pklen);
gpg_error_t app_getattr (app_t app, ctrl_t ctrl, const char *name);
gpg_error_t app_setattr (app_t app, ctrl_t ctrl, const char *name,
                 gpg_error_t (*pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const unsigned char *value, size_t valuelen);
gpg_error_t app_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              unsigned char **outdata, size_t *outdatalen );
gpg_error_t app_auth (app_t app, ctrl_t ctrl, const char *keyidstr,
                      gpg_error_t (*pincb)(void*, const char *, char **),
                      void *pincb_arg,
                      const void *indata, size_t indatalen,
                      unsigned char **outdata, size_t *outdatalen);
gpg_error_t app_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
                          gpg_error_t (*pincb)(void*, const char *, char **),
                          void *pincb_arg,
                          const void *indata, size_t indatalen,
                          unsigned char **outdata, size_t *outdatalen,
                          unsigned int *r_info);
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
gpg_error_t app_get_challenge (app_t app, ctrl_t ctrl, size_t nbytes,
                               unsigned char *buffer);
gpg_error_t app_change_pin (app_t app, ctrl_t ctrl,
                    const char *chvnostr, int reset_mode,
                    gpg_error_t (*pincb)(void*, const char *, char **),
                    void *pincb_arg);
gpg_error_t app_check_pin (app_t app, ctrl_t ctrl, const char *keyidstr,
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

/*-- app-sc-hsm.c --*/
gpg_error_t app_select_sc_hsm (app_t app);


#endif /*GNUPG_SCD_APP_COMMON_H*/
