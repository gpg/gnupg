/* assuan-defs.c - Internal definitions to Assuan
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef ASSUAN_DEFS_H
#define ASSUAN_DEFS_H

#include "assuan.h"


struct assuan_context_s {
  AssuanError err_no;
  const char *err_str;

  struct {
    int fd;
  } inbound;

  struct {
    int fd;
  } outbound;

  int input_fd;   /* set by INPUT command */
  int output_fd;  /* set by OUTPUT command */



};


/*-- assuan-handler.c --*/
int _assuan_register_std_commands (ASSUAN_CONTEXT ctx);


/*-- assuan-util.c --*/
void *_assuan_malloc (size_t n);
void *_assuan_calloc (size_t n, size_t m);
void *_assuan_realloc (void *p, size_t n);
void  _assuan_free (void *p);

#define xtrymalloc(a)    _assuan_malloc ((a))
#define xtrycalloc(a,b)  _assuan_calloc ((a),(b))
#define xtryrealloc(a,b) _assuan_realloc((a),(b))
#define xfree(a)         _assuan_free ((a))

int _assuan_set_error (ASSUAN_CONTEXT ctx, int err, const char *text);
#define set_error(c,e,t) _assuan_set_error ((c), ASSUAN_ ## e, (t))


#endif /*ASSUAN_DEFS_H*/







