/* ks-engine.h - Keyserver engines definitions
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Copyright (C) 2015  g10 Code GmbH
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

#ifndef DIRMNGR_KS_ENGINE_H
#define DIRMNGR_KS_ENGINE_H 1

#include "http.h"

/* Flags for engine functions.  */
#define KS_GET_FLAG_ONLY_LDAP 1
#define KS_GET_FLAG_FIRST     2
#define KS_GET_FLAG_NEXT      4


/*-- ks-action.c --*/
gpg_error_t ks_print_help (ctrl_t ctrl, const char *text);
gpg_error_t ks_printf_help (ctrl_t ctrl, const char *format,
                            ...) GPGRT_ATTR_PRINTF(2,3);

/*-- ks-engine-hkp.c --*/
gpg_error_t ks_hkp_resolve (ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_hkp_mark_host (ctrl_t ctrl, const char *name, int alive);
gpg_error_t ks_hkp_print_hosttable (ctrl_t ctrl);
gpg_error_t ks_hkp_help (ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_hkp_search (ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
                           estream_t *r_fp, unsigned int *r_http_status);
gpg_error_t ks_hkp_get (ctrl_t ctrl, parsed_uri_t uri,
                        const char *keyspec, estream_t *r_fp);
gpg_error_t ks_hkp_put (ctrl_t ctrl, parsed_uri_t uri,
                        const void *data, size_t datalen);

/*-- ks-engine-http.c --*/

/* Flags for the ks_http_fetch.  */
#define KS_HTTP_FETCH_NOCACHE         1  /* Request no caching.  */
#define KS_HTTP_FETCH_TRUST_CFG       2  /* Requests HTTP_FLAG_TRUST_CFG.  */
#define KS_HTTP_FETCH_NO_CRL          4  /* Requests HTTP_FLAG_NO_CRL.     */
#define KS_HTTP_FETCH_ALLOW_DOWNGRADE 8  /* Allow redirect https -> http.  */

gpg_error_t ks_http_help (ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_http_fetch (ctrl_t ctrl, const char *url, unsigned int flags,
                           estream_t *r_fp);


/*-- ks-engine-finger.c --*/
gpg_error_t ks_finger_help (ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_finger_fetch (ctrl_t ctrl, parsed_uri_t uri, estream_t *r_fp);

/*-- ks-engine-kdns.c --*/
gpg_error_t ks_kdns_help (ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_kdns_fetch (ctrl_t ctrl, parsed_uri_t uri, estream_t *r_fp);

/*-- ks-engine-ldap.c --*/
gpg_error_t ks_ldap_help (ctrl_t ctrl, parsed_uri_t uri);
void ks_ldap_free_state (struct ks_engine_ldap_local_s *state);
gpg_error_t ks_ldap_search (ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
			    estream_t *r_fp);
gpg_error_t ks_ldap_get (ctrl_t ctrl, parsed_uri_t uri,
			 const char *keyspec, unsigned int ks_get_flags,
                         estream_t *r_fp);
gpg_error_t ks_ldap_put (ctrl_t ctrl, parsed_uri_t uri,
			 void *data, size_t datalen,
			 void *info, size_t infolen);


#endif /*DIRMNGR_KS_ENGINE_H*/
