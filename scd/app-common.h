/* app-common.h - Common declarations for all card applications
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef GNUPG_SCD_APP_COMMON_H
#define GNUPG_SCD_APP_COMMON_H

struct app_ctx_s {
  int initialized;  /* The application has been initialied and the
                       function pointers may be used.  Note that for
                       unsupported operations the particular
                       function pointer is set to NULL */
  int slot;         /* Used reader. */
  unsigned char *serialno; /* Serialnumber in raw form, allocated. */
  size_t serialnolen;      /* Length in octets of serialnumber. */
  int did_chv1;
  int did_chv2;
  int did_chv3;
  struct {
    int (*learn_status) (APP app, CTRL ctrl);
    int (*setattr) (APP app, const char *name,
                    int (*pincb)(void*, const char *, char **),
                    void *pincb_arg,
                    const unsigned char *value, size_t valuelen);
    int (*sign) (APP app,
                 const char *keyidstr, int hashalgo,
                 int (pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const void *indata, size_t indatalen,
                 void **outdata, size_t *outdatalen );
    int (*decipher) (APP app, const char *keyidstr,
                     int (pincb)(void*, const char *, char **),
                     void *pincb_arg,
                     const void *indata, size_t indatalen,
                     void **outdata, size_t *outdatalen);
    int (*genkey) (APP app, CTRL ctrl,
                   const char *keynostr, unsigned int flags,
                   int (*pincb)(void*, const char *, char **),
                   void *pincb_arg);
  } fnc;


};

/*-- app.c --*/
APP select_application (void);
int app_get_serial_and_stamp (APP app, char **serial, time_t *stamp);
int app_write_learn_status (APP app, CTRL ctrl);
int app_setattr (APP app, const char *name,
                 int (*pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const unsigned char *value, size_t valuelen);
int app_sign (APP app, const char *keyidstr, int hashalgo,
              int (pincb)(void*, const char *, char **),
              void *pincb_arg,
              const void *indata, size_t indatalen,
              void **outdata, size_t *outdatalen );
int app_decipher (APP app, const char *keyidstr,
                  int (pincb)(void*, const char *, char **),
                  void *pincb_arg,
                  const void *indata, size_t indatalen,
                  void **outdata, size_t *outdatalen );
int app_genkey (APP app, CTRL ctrl, const char *keynostr, unsigned int flags,
                int (*pincb)(void*, const char *, char **),
                void *pincb_arg);

/*-- app-openpgp.c --*/
int app_select_openpgp (APP app, unsigned char **sn, size_t *snlen);


#endif /*GNUPG_SCD_APP_COMMON_H*/



