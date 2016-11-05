/* create.h - Defs to create a new crypto container
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#ifndef G13_CREATE_H
#define G13_CREATE_H

gpg_error_t g13_encrypt_keyblob (ctrl_t ctrl,
                                 void *keyblob, size_t keybloblen,
                                 void **r_encblob, size_t *r_encbloblen);
gpg_error_t g13_create_container (ctrl_t ctrl, const char *filename);


#endif /*G13_CREATE_H*/
