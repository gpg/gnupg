/* call-syshelp.h - Communication with g13-syshelp
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

#ifndef GNUPG_G13_CALL_SYSHELP_H
#define GNUPG_G13_CALL_SYSHELP_H

#include "g13tuple.h"

void call_syshelp_release (ctrl_t ctrl);
gpg_error_t call_syshelp_find_device (ctrl_t ctrl,
                                      const char *name, char **r_blockdev);
gpg_error_t call_syshelp_get_keyblob (ctrl_t ctrl,
                                      void **r_enckeyblob,
                                      size_t *r_enckeybloblen);
gpg_error_t call_syshelp_set_device (ctrl_t ctrl, const char *fname);
gpg_error_t call_syshelp_run_create (ctrl_t ctrl, int conttype);
gpg_error_t call_syshelp_run_mount (ctrl_t ctrl, int conttype,
                                    const char *mountpoint,
                                    tupledesc_t tuples);
gpg_error_t call_syshelp_run_umount (ctrl_t ctrl, int conttype);
gpg_error_t call_syshelp_run_suspend (ctrl_t ctrl, int conttype);
gpg_error_t call_syshelp_run_resume (ctrl_t ctrl, int conttype,
                                     tupledesc_t tuples);


#endif /*GNUPG_G13_CALL_SYSHELP_H*/
