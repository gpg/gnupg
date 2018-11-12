/* mbox-util.h - Defs for mail address helper functions
 * Copyright (C) 2015 Werner Koch
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
#ifndef GNUPG_COMMON_MBOX_UTIL_H
#define GNUPG_COMMON_MBOX_UTIL_H

int has_invalid_email_chars (const void *buffer, size_t length);
int is_valid_mailbox (const char *name);
int is_valid_mailbox_mem (const void *buffer, size_t length);
char *mailbox_from_userid (const char *userid, int subaddress);
int is_valid_user_id (const char *uid);
int is_valid_domain_name (const char *string);


#endif /*GNUPG_COMMON_MBOX_UTIL_H*/
