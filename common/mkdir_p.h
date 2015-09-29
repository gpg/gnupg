/* mkdir_p.h - Create a directory and any missing parents.
 * Copyright (C) 2015 g10 Code GmbH
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MKDIR_P_H
#define MKDIR_P_H

#include "types.h"

/* Create a directory as well as any missing parents.

   The arguments must be NULL termianted.  If DIRECTORY_COMPONENTS...
   consists of two elements, "foo/bar" and "xyzzy", this function will
   first try to create the directory "foo/bar" and then the directory
   "foo/bar/xyzzy".  On success returns 0, otherwise an error code is
   returned.  */
int mkdir_p (char *directory_component, ...) GPGRT_ATTR_SENTINEL(0);

/* Like mkdir_p, but DIRECTORY_COMPONENTS is a NULL terminated
   array, e.g.:

     char **dirs = { "foo", "bar", NULL };
     amkdir_p (dirs);
 */
int amkdir_p (char **directory_components);

#endif
