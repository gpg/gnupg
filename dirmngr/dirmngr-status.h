/* dirmngr-status.h - Status code helper functions for dirmnmgr.
 * Copyright (C) 2004, 2014, 2015, 2018 g10 Code GmbH
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
 *
 * SPDX-License-Identifier: GPL-3.0+
 */

/* We keep them separate so that we don't always need to include the
 * entire dirmngr.h */

#ifndef DIRMNGR_STATUS_H
#define DIRMNGR_STATUS_H


/*-- server.c --*/
gpg_error_t dirmngr_status (ctrl_t ctrl, const char *keyword, ...);
gpg_error_t dirmngr_status_help (ctrl_t ctrl, const char *text);
gpg_error_t dirmngr_status_helpf (ctrl_t ctrl, const char *format,
                                  ...) GPGRT_ATTR_PRINTF(2,3);
gpg_error_t dirmngr_status_printf (ctrl_t ctrl, const char *keyword,
                                   const char *format,
                                   ...) GPGRT_ATTR_PRINTF(3,4);


#endif /* DIRMNGR_STATUS_H */
