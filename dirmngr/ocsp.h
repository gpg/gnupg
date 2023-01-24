/* ocsp.h - OCSP management
 *      Copyright (C) 2003 g10 Code GmbH
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifndef OCSP_H
#define OCSP_H

gpg_error_t ocsp_isvalid (ctrl_t ctrl, ksba_cert_t cert, const char *cert_fpr,
                          int force_default_responder,
                          gnupg_isotime_t r_revoked_at,
                          const char **r_reason);

/* Release the list of OCSP certificates hold in the CTRL object. */
void release_ctrl_ocsp_certs (ctrl_t ctrl);

#endif /*OCSP_H*/
