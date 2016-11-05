/* passphrase.h -  Get a passphrase
 * Copyright (C) 2016 g10 Code GmbH
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

#ifndef	GPGSM_PASSPHRASE_H
#define	GPGSM_PASSPHRASE_H

int have_static_passphrase (void);
const char *get_static_passphrase (void);
void read_passphrase_from_fd (int fd);

#endif	/* GPGSM_PASSPHRASE_H */
