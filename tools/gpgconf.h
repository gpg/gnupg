/* gpgconf.h - Global definitions for gpgconf
 *	Copyright (C) 2003 Free Software Foundation, Inc.
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

#ifndef GPGCONF_H
#define GPGCONF_H

#include "../common/util.h"

/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;		/* Verbosity level.  */
  int quiet;		/* Be extra quiet.  */
  int dry_run;		/* Don't change any persistent data.  */
  int runtime;		/* Make changes active at runtime.  */
  int null;             /* Option -0 active.  */
  char *outfile;	/* Name of output file.  */

  int component;	/* The active component.  */
} opt;



/*-- gpgconf-comp.c --*/

/* Initialize the components.  */
void gc_components_init (void);

/* Percent-Escape special characters.  The string is valid until the
   next invocation of the function.  */
char *gc_percent_escape (const char *src);


void gc_error (int status, int errnum, const char *fmt, ...);

/* Launch given component.  */
gpg_error_t gc_component_launch (int component);

/* Kill given component.  */
void gc_component_kill (int component);

/* Reload given component.  */
void gc_component_reload (int component);

/* List all components that are available.  */
void gc_component_list_components (estream_t out);

/* List all programs along with their status.  */
void gc_check_programs (estream_t out);

/* Find the component with the name NAME.  Returns -1 if not
   found.  */
int gc_component_find (const char *name);

/* Retrieve the currently active options and their defaults from all
   involved backends for this component.  */
void gc_component_retrieve_options (int component);

/* List all options of the component COMPONENT.  */
void gc_component_list_options (int component, estream_t out);

/* Read the modifications from IN and apply them.  */
void gc_component_change_options (int component, estream_t in, estream_t out,
                                  int verbatim);

/* Check the options of a single component.  Returns 0 if everything
   is OK.  */
int gc_component_check_options (int component, estream_t out,
				const char *conf_file);

/* Process global configuration file.  */
int gc_process_gpgconf_conf (const char *fname, int update, int defaults,
                             estream_t listfp);

/* Apply a profile.  */
gpg_error_t gc_apply_profile (const char *fname);


#endif /*GPGCONF_H*/
