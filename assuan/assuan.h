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

#include <stdio.h>
#include <sys/types.h>

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
  ASSUAN_Timeout = 4,  
  ASSUAN_Read_Error = 5,
  ASSUAN_Write_Error = 6,

  /* error codes above 99 are meant as status codes */
  ASSUAN_Not_Implemented = 100,
  ASSUAN_Server_Fault    = 101,
  ASSUAN_Invalid_Command = 102,
  ASSUAN_Unknown_Command = 103,
  ASSUAN_Syntax_Error    = 104,
  ASSUAN_Parameter_Error = 105,
  ASSUAN_Parameter_Conflict = 106,
  ASSUAN_Line_Too_Long = 107,
  ASSUAN_Line_Not_Terminated = 108,
  ASSUAN_No_Input = 109,
  ASSUAN_No_Output = 110,
  ASSUAN_Canceled = 111,

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

/*-- assuan-handler.c --*/
int assuan_register_command (ASSUAN_CONTEXT ctx,
                             int cmd_id, const char *cmd_string,
                             int (*handler)(ASSUAN_CONTEXT, char *));
int assuan_process (ASSUAN_CONTEXT ctx);
FILE *assuan_get_data_fp (ASSUAN_CONTEXT ctx);
void assuan_write_status (ASSUAN_CONTEXT ctx,
                          const char *keyword, const char *text);


/*-- assuan-listen.c --*/
int assuan_accept (ASSUAN_CONTEXT ctx);
int assuan_get_input_fd (ASSUAN_CONTEXT ctx);
int assuan_get_output_fd (ASSUAN_CONTEXT ctx);


/*-- assuan-pipe-server.c --*/
int assuan_init_pipe_server (ASSUAN_CONTEXT *r_ctx, int filedes[2]);
void assuan_deinit_pipe_server (ASSUAN_CONTEXT ctx);


/*-- assuan-connect.c --*/
AssuanError assuan_pipe_connect (ASSUAN_CONTEXT *ctx, const char *name,
                                 char *const argv[]);
void assuan_pipe_disconnect (ASSUAN_CONTEXT ctx);
pid_t assuan_get_pid (ASSUAN_CONTEXT ctx);

/*-- assuan-util.c --*/
void assuan_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                               void *(*new_realloc_func)(void *p, size_t n),
                               void (*new_free_func)(void*) );
int assuan_set_error (ASSUAN_CONTEXT ctx, int err, const char *text);
void assuan_set_pointer (ASSUAN_CONTEXT ctx, void *pointer);
void *assuan_get_pointer (ASSUAN_CONTEXT ctx);


/*-- assuan-errors.c (built) --*/
const char *assuan_strerror (AssuanError err);


#ifdef __cplusplus
}
#endif
#endif /*ASSUAN_H*/
