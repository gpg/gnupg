/* mount.h - Defs to mount a crypto container
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

#ifndef G13_MOUNT_H
#define G13_MOUNT_H

gpg_error_t g13_mount_container (ctrl_t ctrl,
                                 const char *filename,
                                 const char *mountpoint);
gpg_error_t g13_umount_container (ctrl_t ctrl,
                                  const char *filename,
                                  const char *mountpoint);


#endif /*G13_MOUNT_H*/
