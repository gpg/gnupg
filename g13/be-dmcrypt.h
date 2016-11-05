/* be-dmcrypt.h - Public defs for the DM-Crypt based backend
 * Copyright (C) 2015 Werner Koch
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

#ifndef G13_BE_DMCRYPT_H
#define G13_BE_DMCRYPT_H

#include "backend.h"

gpg_error_t be_dmcrypt_create_container (ctrl_t ctrl);
gpg_error_t be_dmcrypt_mount_container (ctrl_t ctrl,
                                        const char *fname,
                                        const char *mountpoint,
                                        tupledesc_t tuples);
gpg_error_t be_dmcrypt_umount_container (ctrl_t ctrl, const char *fname);
gpg_error_t be_dmcrypt_suspend_container (ctrl_t ctrl, const char *fname);
gpg_error_t be_dmcrypt_resume_container (ctrl_t ctrl, const char *fname,
                                         tupledesc_t tuples);


#endif /*G13_BE_DMCRYPT_H*/
