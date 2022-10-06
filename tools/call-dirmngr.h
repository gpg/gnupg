/* call-dirmngr.h - Interact with the Dirmngr.
 * Copyright (C) 2016 g10 Code GmbH
 * Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_TOOLS_CALL_DIRMNGR_H
#define GNUPG_TOOLS_CALL_DIRMNGR_H

void set_dirmngr_options (int verbose, int debug_ipc, int autostart);

gpg_error_t wkd_get_submission_address (const char *addrspec,
                                        char **r_addrspec);
gpg_error_t wkd_get_policy_flags (const char *addrspec, estream_t *r_buffer);

gpg_error_t wkd_get_key (const char *addrspec, estream_t *r_key);

gpg_error_t wkd_dirmngr_ks_get (const char *domain,
                                gpg_error_t cb (estream_t key));


#endif /*GNUPG_TOOLS_CALL_DIRMNGR_H*/
