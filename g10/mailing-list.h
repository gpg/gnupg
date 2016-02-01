/* mailing-list.h - Manage an encrypted mailing list.
 * Copyright (C) 2015 Neal H. Walfield <neal@walfield.org>
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

#ifndef G10_MAILING_LIST_H
#define G10_MAILING_LIST_H

#include "types.h"
#include "util.h"
#include "dek.h"

void kbnode_dump (KBNODE kb);

/* Get a copy of all the session keys and store them in *DEKS and the
   total count in *NDEKS.  On success, the caller must xfree
   deksp.  */
gpg_error_t mailing_list_get_subscriber_list_session_keys (
              ctrl_t ctrl, KBNODE kb, DEK **deksp, int *ndeksp);

gpg_error_t mailing_list_add_subscriber (ctrl_t ctrl,
                                         KBNODE ml_kb, const char *sub);

gpg_error_t mailing_list_rm_subscriber (ctrl_t ctrl, KBNODE ml_kb,
                                        const char *sub_orig);

gpg_error_t mailing_list_subscribers (ctrl_t ctrl, KBNODE kb,
                                      PK_LIST *pklistp);

#endif
