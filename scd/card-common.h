/* card-common.h - Common declarations for all card types
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

#ifndef CARD_COMMON_H
#define CARD_COMMON_H

/* Declaration of private data structure used by card-p15.c */
struct p15private_s;


struct card_ctx_s {
  int reader;   /* used reader */
  struct sc_context *ctx;
  struct sc_card *scard;
  struct sc_pkcs15_card *p15card; /* only if there is a pkcs15 application */
  struct p15private_s *p15priv;   /* private data used by card-p15.c */

  struct {
    int initialized;  /* the card has been initialied and the function
                         pointers may be used.  However for
                         unsupported operations the particular
                         function pointer is set to NULL */

    int (*enum_keypairs) (CARD card, int idx,
                          unsigned char *keygrip, char **keyid);
    int (*enum_certs) (CARD card, int idx, char **certid, int *certtype);
    int (*read_cert) (CARD card, const char *certidstr,
                      unsigned char **cert, size_t *ncert);
    int (*sign) (CARD card,
                 const char *keyidstr, int hashalgo,
                 int (pincb)(void*, const char *, char **),
                 void *pincb_arg,
                 const void *indata, size_t indatalen,
                 unsigned char **outdata, size_t *outdatalen );
    int (*decipher) (CARD card, const char *keyidstr,
                     int (pincb)(void*, const char *, char **),
                     void *pincb_arg,
                     const void *indata, size_t indatalen,
                     unsigned char **outdata, size_t *outdatalen);
  } fnc;
  
};

/*-- card.c --*/
gpg_error_t map_sc_err (int rc);
int card_help_get_keygrip (ksba_cert_t cert, unsigned char *array);

/*-- card-15.c --*/
void p15_release_private_data (CARD card);

/* constructors */
void card_p15_bind (CARD card);
void card_dinsig_bind (CARD card);


#endif /*CARD_COMMON_H*/
