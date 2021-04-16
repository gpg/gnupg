/* call-dirmngr.h - GPG operations to the Dirmngr
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#ifndef GNUPG_G10_CALL_DIRMNGR_H
#define GNUPG_G10_CALL_DIRMNGR_H

void gpg_dirmngr_deinit_session_data (ctrl_t ctrl);

gpg_error_t gpg_dirmngr_ks_list (ctrl_t ctrl, char **r_keyserver);
gpg_error_t gpg_dirmngr_ks_search (ctrl_t ctrl, const char *searchstr,
                                   gpg_error_t (*cb)(void*, int, char *),
                                   void *cb_value);
gpg_error_t gpg_dirmngr_ks_get (ctrl_t ctrl, char *pattern[],
                                keyserver_spec_t override_keyserver,
                                unsigned int flags,
                                estream_t *r_fp, char **r_source);
gpg_error_t gpg_dirmngr_ks_fetch (ctrl_t ctrl,
                                  const char *url, estream_t *r_fp);
gpg_error_t gpg_dirmngr_ks_put (ctrl_t ctrl, void *data, size_t datalen,
                                kbnode_t keyblock);
gpg_error_t gpg_dirmngr_dns_cert (ctrl_t ctrl,
                                  const char *name, const char *certtype,
                                  estream_t *r_key,
                                  unsigned char **r_fpr, size_t *r_fprlen,
                                  char **r_url);
gpg_error_t gpg_dirmngr_wkd_get (ctrl_t ctrl, const char *name, int quick,
                                 estream_t *r_key, char **r_url);


#endif /*GNUPG_G10_CALL_DIRMNGR_H*/
