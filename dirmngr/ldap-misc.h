/* ldap-misc.h - Miscellaneous helpers for LDAP functions
 * Copyright (C) 2015, 2021 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef DIRMNGR_LDAP_MISC_H
#define DIRMNGR_LDAP_MISC_H

#ifdef _WIN32
# include <winsock2.h>
# include <winldap.h>
#else
# ifdef NEED_LBER_H
#  include <lber.h>
# endif
/* For OpenLDAP, to enable the API that we're using. */
# define LDAP_DEPRECATED 1
# include <ldap.h>
#endif


gpg_err_code_t ldap_err_to_gpg_err (int code);
gpg_err_code_t ldap_to_gpg_err (LDAP *ld);
gpg_error_t ldap_parse_extfilter (const char *string, int silent,
                                  char **r_base, int *r_scope, char **r_filter);
char *isotime2rfc4517 (const char *string);
gpg_error_t rfc4517toisotime (gnupg_isotime_t timebuf, const char *string);


#endif /*DIRMNGR_LDAP_MISC_H*/
