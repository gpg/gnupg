/* mountinfo.h - Track infos about mounts
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

#ifndef G13_MOUNTINFO_H
#define G13_MOUNTINFO_H

struct mounttable_s;
typedef struct mounttable_s *mtab_t;

gpg_error_t mountinfo_add_mount (const char *container,
                                 const char *mountpoint,
                                 int conttype, unsigned int rid,
                                 int remove_flag);
gpg_error_t mountinfo_del_mount (const char *container,
                                 const char *mountpoint,
                                 unsigned int rid);
gpg_error_t mountinfo_find_mount (const char *container,
                                  const char *mountpoint,
                                  unsigned int *r_rid);

void mountinfo_dump_all (void);


#endif /*G13_MOUNTINFO_H*/
