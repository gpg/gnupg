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

#include <sys/types.h>
#include "assuan.h"

#define LINELENGTH ASSUAN_LINELENGTH

struct cmdtbl_s {
  const char *name;
  int cmd_id;
  int (*handler)(ASSUAN_CONTEXT, char *line);
};

struct assuan_context_s {
  AssuanError err_no;
  const char *err_str;

  int is_server;  /* set if this is context belongs to a server */
  int in_inquire;
  char *hello_line;
  
  void *user_pointer;  /* for assuan_[gs]et_pointer () */

  struct {
    int fd;
    int eof;
    char line[LINELENGTH];
    int linelen;  /* w/o CR, LF - might not be the same as
                     strlen(line) due to embedded nuls. However a nul
                     is always written at this pos */
    struct {
      char line[LINELENGTH];
      int linelen ;
      int pending; /* i.e. at least one line is available in the attic */
    } attic;
  } inbound;

  struct {
    int fd;
    struct {
      FILE *fp;
      char line[LINELENGTH];
      int linelen; 
      int error;
    } data; 
  } outbound;

  int pipe_mode;  /* We are in pipe mode, i.e. we can handle just one
                     connection and must terminate then */
  pid_t pid;	/* In pipe mode, the pid of the child server process.  */

  struct cmdtbl_s *cmdtbl;
  size_t cmdtbl_used; /* used entries */
  size_t cmdtbl_size; /* allocated size of table */

  void (*bye_notify_fnc)(ASSUAN_CONTEXT);
  void (*reset_notify_fnc)(ASSUAN_CONTEXT);
  void (*cancel_notify_fnc)(ASSUAN_CONTEXT);
  void (*input_notify_fnc)(ASSUAN_CONTEXT, const char *);
  void (*output_notify_fnc)(ASSUAN_CONTEXT, const char *);


  int input_fd;   /* set by INPUT command */
  int output_fd;  /* set by OUTPUT command */



};


/*-- assuan-handler.c --*/
int _assuan_register_std_commands (ASSUAN_CONTEXT ctx);

/*-- assuan-buffer.c --*/
int _assuan_read_line (ASSUAN_CONTEXT ctx);
int _assuan_cookie_write_data (void *cookie, const char *buffer, size_t size);
int _assuan_cookie_write_flush (void *cookie);

/*-- assuan-client.c --*/
AssuanError _assuan_read_from_server (ASSUAN_CONTEXT ctx, int *okay, int *off);


/*-- assuan-util.c --*/
void *_assuan_malloc (size_t n);
void *_assuan_calloc (size_t n, size_t m);
void *_assuan_realloc (void *p, size_t n);
void  _assuan_free (void *p);

#define xtrymalloc(a)    _assuan_malloc ((a))
#define xtrycalloc(a,b)  _assuan_calloc ((a),(b))
#define xtryrealloc(a,b) _assuan_realloc((a),(b))
#define xfree(a)         _assuan_free ((a))

#define set_error(c,e,t) assuan_set_error ((c), ASSUAN_ ## e, (t))


#endif /*ASSUAN_DEFS_H*/







