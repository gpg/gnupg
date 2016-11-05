/* zb32.h - z-base-32 functions
 * Copyright (C) 2014  Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_ZB32_H
#define GNUPG_COMMON_ZB32_H

/* Encode DATA which has a length of DATABITS (bits!) using the
   zbase32 encoder and return a malloced string.  Returns NULL on
   error and sets ERRNO.  */
char *zb32_encode (const void *data, unsigned int databits);

#endif /*GNUPG_COMMON_ZB32_H*/
