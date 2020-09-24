/* kbx-client-util.c - Defs for utility functions for a keyboxd client
 * Copyright (C) 2020  g10 Code GmbH
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

#ifndef GNUPG_KBX_CLIENT_UTIL_H
#define GNUPG_KBX_CLIENT_UTIL_H 1


struct kbx_client_data_s;
typedef struct kbx_client_data_s *kbx_client_data_t;

gpg_error_t kbx_client_data_new (kbx_client_data_t *r_kcd,
                                 assuan_context_t ctx, int dlines);
void kbx_client_data_release (kbx_client_data_t kcd);
gpg_error_t kbx_client_data_simple (kbx_client_data_t kcd, const char *command);
gpg_error_t kbx_client_data_cmd (kbx_client_data_t kcd, const char *command,
                                 gpg_error_t (*status_cb)(void *opaque,
                                                          const char *line),
                                 void *status_cb_value);
gpg_error_t kbx_client_data_wait (kbx_client_data_t kcd,
                                  char **r_data, size_t *r_datalen);




#endif /*GNUPG_KBX_CLIENT_UTIL_H*/
