/* ldap-wrapper.h - Interface to an LDAP access wrapper.
 * Copyright (C) 2010 Free Software Foundation, Inc.
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

#ifndef LDAP_WRAPPER_H
#define LDAP_WRAPPER_H

#include <ksba.h>

/* ldap-wrapper.c or ldap-wrapper-ce.c */
void ldap_wrapper_launch_thread (void);
void ldap_wrapper_wait_connections (void);
void ldap_wrapper_release_context (ksba_reader_t reader);
void ldap_wrapper_connection_cleanup (ctrl_t);
gpg_error_t ldap_wrapper (ctrl_t ctrl, ksba_reader_t *reader,
                          const char *argv[]);


#endif /*LDAP_WRAPPER_H*/
