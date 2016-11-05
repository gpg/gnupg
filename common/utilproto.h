/* utilproto.h - Some prototypes for inclusion by util.h
 * Copyright (C) 2016 Werner Koch
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

/* This file is in general included via util.h but sometimes we do not
 * want all stuff from util.h and instead use this file with its
 * simple prototypes.  */

#ifndef GNUPG_COMMON_UTILPROTO_H
#define GNUPG_COMMON_UTILPROTO_H

/*-- signal.c --*/
void gnupg_init_signals (int mode, void (*fast_cleanup)(void));
void gnupg_block_all_signals (void);
void gnupg_unblock_all_signals (void);



#endif /*GNUPG_COMMON_UTILPROTO_H*/
