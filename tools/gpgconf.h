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
  int quiet;	       /* Be extra quiet.  */
  int dry_run;         /* Don't change any persistent data. */
  char *outfile;       /* Name of output file. */

  int component;	/* The active component.  */
} opt;



/*-- gpgconf-comp.c --*/
/* List all components that are available.  */
void gc_component_list_components (FILE *out);

/* Find the component with the name NAME.  Returns -1 if not
   found.  */
int gc_component_find (const char *name);

/* Retrieve the currently active options and their defaults from all
   involved backends for this component.  */
void gc_component_retrieve_options (int component);

/* List all options of the component COMPONENT.  */
void gc_component_list_options (int component, FILE *out);

/* Read the modifications from IN and apply them.  */
void gc_component_change_options (int component, FILE *in);

#endif /*GPGCONF_H*/
