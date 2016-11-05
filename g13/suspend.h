/* suspend.h - Suspend/Resume a crypto container.
 * Copyright (C) 2016 Werner Koch
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

#ifndef G13_SUSPEND_H
#define G13_SUSPEND_H

gpg_error_t g13_suspend_container (ctrl_t ctrl, const char *filename);
gpg_error_t g13_resume_container (ctrl_t ctrl, const char *filename);

#endif /*G13_SUSPEND_H*/
