/* crlfetch.h - LDAP access
 *      Copyright (C) 2002 Klarälvdalens Datakonsult AB
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CRLFETCH_H
#define CRLFETCH_H

#include "dirmngr.h"


struct cert_fetch_context_s;
typedef struct cert_fetch_context_s *cert_fetch_context_t;


/* Fetch CRL from URL. */
gpg_error_t crl_fetch (ctrl_t ctrl, const char* url, ksba_reader_t *reader);

/* Fetch CRL for ISSUER using default server. */
gpg_error_t crl_fetch_default (ctrl_t ctrl,
                               const char* issuer, ksba_reader_t *reader);


/* Fetch cert for DN. */
gpg_error_t ca_cert_fetch (ctrl_t ctrl, cert_fetch_context_t *context,
                           const char *dn);


/* Query the server for certs matching patterns. */
gpg_error_t start_cert_fetch (ctrl_t ctrl,
                              cert_fetch_context_t *context,
                              strlist_t patterns,
                              const ldap_server_t server);
gpg_error_t fetch_next_cert(cert_fetch_context_t context,
                            unsigned char **value, size_t *valuelen);
gpg_error_t fetch_next_ksba_cert (cert_fetch_context_t context,
                                  ksba_cert_t *r_cert);
void end_cert_fetch (cert_fetch_context_t context);

/* Lookup a cert by it's URL.  */
gpg_error_t fetch_cert_by_url (ctrl_t ctrl, const char *url,
			       unsigned char **value, size_t *valuelen);

/* Close a reader object. */
void crl_close_reader (ksba_reader_t reader);



/*-- ldap.c --*/
gpg_error_t url_fetch_ldap (ctrl_t ctrl,
                            const char *url, ksba_reader_t *reader);
gpg_error_t attr_fetch_ldap (ctrl_t ctrl,
                             const char *dn, const char *attr,
                             ksba_reader_t *reader);


gpg_error_t start_cacert_fetch_ldap (ctrl_t ctrl,
                                     cert_fetch_context_t *context,
                                     const char *dn);
gpg_error_t start_cert_fetch_ldap( ctrl_t ctrl,
                                   cert_fetch_context_t *context,
                                   strlist_t patterns,
                                   const ldap_server_t server );
gpg_error_t fetch_next_cert_ldap (cert_fetch_context_t context,
                                  unsigned char **value, size_t *valuelen );
void end_cert_fetch_ldap (cert_fetch_context_t context);






#endif /* CRLFETCH_H */
