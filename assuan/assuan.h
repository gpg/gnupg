/* assuan.c - Definitions for the Assuna protocol
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

#ifndef ASSUAN_H
#define ASSUAN_H

#ifdef __cplusplus
extern "C" { 
#if 0
 }
#endif
#endif

typedef enum {
  ASSUAN_No_Error = 0,
  ASSUAN_General_Error = 1,
  ASSUAN_Out_Of_Core = 2,
  ASSUAN_Invalid_Value = 3,

  /* error codes above 99 are meant as status codes */
  ASSUAN_Unknown_Command = 100,
  ASSUAN_Not_Implemented = 101,
  ASSUAN_Server_Fault    = 102,
  ASSUAN_Syntax_Error    = 103,
  ASSUAN_Parameter_Error = 104,
  ASSUAN_Parameter_Conflict = 105,


  ASSUAN_Cert_Revoked = 301,
  ASSUAN_No_CRL_For_Cert = 302,
  ASSUNA_CRL_Too_Old = 303,

} AssuanError;

/* This is a list of pre-registered ASSUAN commands */
typedef enum {
  ASSUAN_CMD_NOP = 0,
  ASSUAN_CMD_CANCEL,    /* cancel the current request */
  ASSUAN_CMD_BYE,
  ASSUAN_CMD_AUTH,
  ASSUAN_CMD_RESET,
  ASSUAN_CMD_DATA,
  ASSUAN_CMD_END,
  ASSUAN_CMD_INPUT,
  ASSUAN_CMD_OUTPUT,

  ASSUAN_CMD_USER = 256  /* Other commands should be used with this offset*/
} AssuanCommand;


struct assuan_context_s;
typedef struct assuan_context_s *ASSUAN_CONTEXT;

/*-- assuan-handler --*/
int assuan_register_command (ASSUAN_CONTEXT ctx,
                             int cmd_id, const char *cmd_string,
                             int (*handler)(ASSUAN_CONTEXT, char *));



/*-- assuan-pipe-server.c --*/




/*-- assuan-util.c --*/
void assuan_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                               void *(*new_realloc_func)(void *p, size_t n),
                               void (*new_free_func)(void*) );



#ifdef __cplusplus
}
#endif
#endif /*ASSUAN_H*/
