/* gpgconf.h - Global definitions for gpgconf
 *	Copyright (C) 2003 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GPGCONF_H
#define GPGCONF_H

#include "../common/util.h"

/* We keep all global options in the structure OPT. */
struct {
  int verbose;         /* Verbosity level. */
  int quiet;           /* Be as quiet as possible. */
  int dry_run;         /* Don't change any persistent data. */
  const char *homedir; /* Configuration directory name. */
  char *outfile;       /* Name of output file. */
} opt;



/*-- gpgconf-list.c --*/
void gpgconf_list_standard_options (void);


#endif /*GPGCONF_H*/
