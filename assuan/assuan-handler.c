/* assuan-handler.c - dispatch commands 
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "assuan-defs.h"

#define digitp(a) ((a) >= '0' && (a) <= '9')


static int
dummy_handler (ASSUAN_CONTEXT ctx, char *line)
{
  return set_error (ctx, Server_Fault, "no handler registered");
}


static int
std_handler_nop (ASSUAN_CONTEXT ctx, char *line)
{
  return 0; /* okay */
}
  
static int
std_handler_cancel (ASSUAN_CONTEXT ctx, char *line)
{
  if (ctx->cancel_notify_fnc)
    ctx->cancel_notify_fnc (ctx);
  return set_error (ctx, Not_Implemented, NULL); 
}
  
static int
std_handler_bye (ASSUAN_CONTEXT ctx, char *line)
{
  if (ctx->bye_notify_fnc)
    ctx->bye_notify_fnc (ctx);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return -1; /* pretty simple :-) */
}
  
static int
std_handler_auth (ASSUAN_CONTEXT ctx, char *line)
{
  return set_error (ctx, Not_Implemented, NULL); 
}
  
static int
std_handler_reset (ASSUAN_CONTEXT ctx, char *line)
{
  if (ctx->reset_notify_fnc)
    ctx->reset_notify_fnc (ctx);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return 0;
}
  
static int
std_handler_end (ASSUAN_CONTEXT ctx, char *line)
{
  return set_error (ctx, Not_Implemented, NULL); 
}

static int
parse_cmd_input_output (ASSUAN_CONTEXT ctx, char *line, int *rfd)
{
  char *endp;

  if (strncmp (line, "FD=", 3))
    return set_error (ctx, Syntax_Error, "FD=<n> expected");
  line += 3;
  if (!digitp (*line))
    return set_error (ctx, Syntax_Error, "number required");
  *rfd = strtoul (line, &endp, 10);
  /* remove that argument so that a notify handler won't see it */
  memset (line, ' ', endp? (endp-line):strlen(line));

  if (*rfd == ctx->inbound.fd)
    return set_error (ctx, Parameter_Conflict, "fd same as inbound fd");
  if (*rfd == ctx->outbound.fd)
    return set_error (ctx, Parameter_Conflict, "fd same as outbound fd");
  return 0;
}

/* Format is INPUT FD=<n> */
static int
std_handler_input (ASSUAN_CONTEXT ctx, char *line)
{
  int rc, fd;

  rc = parse_cmd_input_output (ctx, line, &fd);
  if (rc)
    return rc;
  ctx->input_fd = fd;
  if (ctx->input_notify_fnc)
    ctx->input_notify_fnc (ctx, line);
  return 0;
}

/* Format is OUTPUT FD=<n> */
static int
std_handler_output (ASSUAN_CONTEXT ctx, char *line)
{
  int rc, fd;

  rc = parse_cmd_input_output (ctx, line, &fd);
  if (rc)
    return rc;
  ctx->output_fd = fd;
  if (ctx->output_notify_fnc)
    ctx->output_notify_fnc (ctx, line);
  return 0;
}



  

/* This is a table with the standard commands and handler for them.
   The table is used to initialize a new context and assuciate strings
   and handlers with cmd_ids */
static struct {
  const char *name;
  int cmd_id;
  int (*handler)(ASSUAN_CONTEXT, char *line);
  int always; /* always initialize this command */
} std_cmd_table[] = {
  { "NOP",    ASSUAN_CMD_NOP,    std_handler_nop, 1 },
  { "CANCEL", ASSUAN_CMD_CANCEL, std_handler_cancel, 1 },
  { "BYE",    ASSUAN_CMD_BYE,    std_handler_bye, 1 },
  { "AUTH",   ASSUAN_CMD_AUTH,   std_handler_auth, 1 },
  { "RESET",  ASSUAN_CMD_RESET,  std_handler_reset, 1 },
  { "END",    ASSUAN_CMD_END,    std_handler_end, 1 },

  { "INPUT",  ASSUAN_CMD_INPUT,  std_handler_input },
  { "OUTPUT", ASSUAN_CMD_OUTPUT, std_handler_output },
  { NULL }
};


/**
 * assuan_register_command:
 * @ctx: the server context
 * @cmd_id: An ID value for the command
 * @cmd_name: A string with the command name
 * @handler: The handler function to be called
 * 
 * Register a handler to be used for a given command.
 * 
 * The @cmd_name must be %NULL or an empty string for all @cmd_ids
 * below %ASSUAN_CMD_USER because predefined values are used.
 * 
 * Return value: 
 **/
int
assuan_register_command (ASSUAN_CONTEXT ctx,
                         int cmd_id, const char *cmd_name,
                         int (*handler)(ASSUAN_CONTEXT, char *))
{
  int i;

  if (cmd_name && !*cmd_name)
    cmd_name = NULL;

  if (cmd_id < ASSUAN_CMD_USER)
    { 
      if (cmd_name)
        return ASSUAN_Invalid_Value; /* must be NULL for these values*/

      for (i=0; std_cmd_table[i].name; i++)
        {
          if (std_cmd_table[i].cmd_id == cmd_id)
            {
              cmd_name = std_cmd_table[i].name;
              if (!handler)
                handler = std_cmd_table[i].handler;
              break;
            }
        }
      if (!std_cmd_table[i].name)
        return ASSUAN_Invalid_Value; /* not a pre-registered one */
    }
  
  if (!handler)
    handler = dummy_handler;

  if (!cmd_name)
    return ASSUAN_Invalid_Value;

/*    fprintf (stderr, "DBG-assuan: registering %d as `%s'\n", cmd_id, cmd_name); */

  if (!ctx->cmdtbl)
    {
      ctx->cmdtbl_size = 50;
      ctx->cmdtbl = xtrycalloc ( ctx->cmdtbl_size, sizeof *ctx->cmdtbl);
      if (!ctx->cmdtbl)
        return ASSUAN_Out_Of_Core;
      ctx->cmdtbl_used = 0;
    }
  else if (ctx->cmdtbl_used >= ctx->cmdtbl_size)
    {
      struct cmdtbl_s *x;

      x = xtryrealloc ( ctx->cmdtbl, (ctx->cmdtbl_size+10) * sizeof *x);
      if (!x)
        return ASSUAN_Out_Of_Core;
      ctx->cmdtbl = x;
      ctx->cmdtbl_size += 50;
    }

  ctx->cmdtbl[ctx->cmdtbl_used].name = cmd_name;
  ctx->cmdtbl[ctx->cmdtbl_used].cmd_id = cmd_id;
  ctx->cmdtbl[ctx->cmdtbl_used].handler = handler;
  ctx->cmdtbl_used++;
  return 0;
}

int
assuan_register_bye_notify (ASSUAN_CONTEXT ctx, void (*fnc)(ASSUAN_CONTEXT))
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  ctx->bye_notify_fnc = fnc;
  return 0;
}

int
assuan_register_reset_notify (ASSUAN_CONTEXT ctx, void (*fnc)(ASSUAN_CONTEXT))
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  ctx->reset_notify_fnc = fnc;
  return 0;
}

int
assuan_register_cancel_notify (ASSUAN_CONTEXT ctx, void (*fnc)(ASSUAN_CONTEXT))
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  ctx->cancel_notify_fnc = fnc;
  return 0;
}

int
assuan_register_input_notify (ASSUAN_CONTEXT ctx,
                              void (*fnc)(ASSUAN_CONTEXT, const char *))
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  ctx->input_notify_fnc = fnc;
  return 0;
}

int
assuan_register_output_notify (ASSUAN_CONTEXT ctx,
                              void (*fnc)(ASSUAN_CONTEXT, const char *))
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  ctx->output_notify_fnc = fnc;
  return 0;
}


/* Helper to register the standards commands */
int
_assuan_register_std_commands (ASSUAN_CONTEXT ctx)
{
  int i, rc;

  for (i=0; std_cmd_table[i].name; i++)
    {
      if (std_cmd_table[i].always)
        {
          rc = assuan_register_command (ctx, std_cmd_table[i].cmd_id,
                                        NULL, NULL);
          if (rc)
            return rc;
        }
    } 
  return 0;
}



/* Process the special data lines.  The "D " has already been removed
   from the line.  As all handlers this function may modify the line.  */
static int
handle_data_line (ASSUAN_CONTEXT ctx, char *line, int linelen)
{
  return set_error (ctx, Not_Implemented, NULL);
}


/* Parse the line, break out the command, find it in the command
   table, remove leading and white spaces from the arguments, all the
   handler with the argument line and return the error */
static int 
dispatch_command (ASSUAN_CONTEXT ctx, char *line, int linelen)
{
  char *p;
  const char *s;
  int shift, i;

  if (*line == 'D' && line[1] == ' ') /* divert to special handler */
    return handle_data_line (ctx, line+2, linelen-2);

  for (p=line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  if (p==line)
    return set_error (ctx, Invalid_Command, "leading white-space"); 
  if (*p) 
    { /* Skip over leading WS after the keyword */
      *p++ = 0;
      while ( *p == ' ' || *p == '\t')
        p++;
    }
  shift = p - line;

  for (i=0; (s=ctx->cmdtbl[i].name); i++)
    if (!strcmp (line, s))
      break;
  if (!s)
    return set_error (ctx, Unknown_Command, NULL);
  line += shift;
  linelen -= shift;

/*    fprintf (stderr, "DBG-assuan: processing %s `%s'\n", s, line); */
  return ctx->cmdtbl[i].handler (ctx, line);
}




static int
process_request (ASSUAN_CONTEXT ctx)
{
  int rc;

  if (ctx->in_inquire)
    return ASSUAN_Nested_Commands;

  rc = _assuan_read_line (ctx);
  if (rc)
    return rc;
  if (*ctx->inbound.line == '#' || !ctx->inbound.linelen)
    return 0; /* comment line - ignore */

  ctx->outbound.data.error = 0;
  ctx->outbound.data.linelen = 0;
  /* dispatch command and return reply */
  rc = dispatch_command (ctx, ctx->inbound.line, ctx->inbound.linelen);
  /* check from data write errors */
  if (ctx->outbound.data.fp)
    { /* Flush the data lines */
      fclose (ctx->outbound.data.fp);
      ctx->outbound.data.fp = NULL;
      if (!rc && ctx->outbound.data.error)
        rc = ctx->outbound.data.error;
    }
  /* Error handling */
  if (!rc)
    {
      rc = assuan_write_line (ctx, "OK");
    }
  else if (rc == -1)
    { /* No error checking because the peer may have already disconnect */ 
      assuan_write_line (ctx, "OK closing connection");
    }
  else 
    {
      char errline[256];

      if (rc < 100)
        sprintf (errline, "ERR %d server fault (%.50s)",
                 ASSUAN_Server_Fault, assuan_strerror (rc));
      else
        {
          const char *text = ctx->err_no == rc? ctx->err_str:NULL;

          sprintf (errline, "ERR %d %.50s%s%.100s",
                   rc, assuan_strerror (rc), text? " - ":"", text?text:"");
        }
      rc = assuan_write_line (ctx, errline);
    }

  return rc;
}

/**
 * assuan_process:
 * @ctx: assuan context
 * 
 * This fucntion is used to handle the assuan protocol after a
 * connection has been established using assuan_accept().  This is the
 * main protocol handler.
 * 
 * Return value: 0 on success or an error code if the assuan operation
 * failed.  Note, that no error is returned for operational errors.
 **/
int
assuan_process (ASSUAN_CONTEXT ctx)
{
  int rc;

  do {
    rc = process_request (ctx);
  } while (!rc);

  if (rc == -1)
    rc = 0;

  return rc;
}


/**
 * assuan_process_next:
 * @ctx: Assuan context
 * 
 * Same as assuan_process() but the user has to provide the outer
 * loop.  He should loop as long as the return code is zero and stop
 * otherwise; -1 is regular end.
 * 
 * See also: assuan_get_active_fds()
 * Return value: -1 for end of server, 0 on success or an error code
 **/
int 
assuan_process_next (ASSUAN_CONTEXT ctx)
{
  return process_request (ctx);
}


/**
 * assuan_get_active_fds:
 * @ctx: Assuan context
 * @what: 0 for read fds, 1 for write fds
 * @fdarray: Caller supplied array to store the FDs
 * @fdarraysize: size of that array
 * 
 * Return all active filedescriptors for the given context.  This
 * function can be used to select on the fds and call
 * assuan_process_next() if there is an active one.  The first fd in
 * the array is the one used for the command connection.
 *
 * Note, that write FDs are not yet supported.
 * 
 * Return value: number of FDs active and put into @fdarray or -1 on
 * error which is most likely a too small fdarray.
 **/
int 
assuan_get_active_fds (ASSUAN_CONTEXT ctx, int what,
                       int *fdarray, int fdarraysize)
{
  int n = 0;

  if (!ctx || fdarraysize < 2 || what < 0 || what > 1)
    return -1;

  if (!what)
    {
      if (ctx->inbound.fd != -1)
        fdarray[n++] = ctx->inbound.fd;
    }
  else
    {
      if (ctx->outbound.fd != -1)
        fdarray[n++] = ctx->outbound.fd;
      if (ctx->outbound.data.fp)
        fdarray[n++] = fileno (ctx->outbound.data.fp);
    }

  return n;
}

/* Return a FP to be used for data output.  The FILE pointer is valid
   until the end of a handler.  So a close is not needed.  Assuan does
   all the buffering needed to insert the status line as well as the
   required line wappping and quoting for data lines.

   We use GNU's custom streams here.  There should be an alternative
   implementaion for systems w/o a glibc, a simple implementation
   could use a child process */
FILE *
assuan_get_data_fp (ASSUAN_CONTEXT ctx)
{
  cookie_io_functions_t cookie_fnc;

  if (ctx->outbound.data.fp)
    return ctx->outbound.data.fp;
  
  cookie_fnc.read = NULL; 
  cookie_fnc.write = _assuan_cookie_write_data;
  cookie_fnc.seek = NULL;
  cookie_fnc.close = _assuan_cookie_write_flush;

  ctx->outbound.data.fp = fopencookie (ctx, "wb", cookie_fnc);
  ctx->outbound.data.error = 0;
  return ctx->outbound.data.fp;
}


void
assuan_write_status (ASSUAN_CONTEXT ctx, const char *keyword, const char *text)
{
  char buffer[256];
  char *helpbuf;
  size_t n;

  if ( !ctx || !keyword)
    return;
  if (!text)
    text = "";

  n = 2 + strlen (keyword) + 1 + strlen (text) + 1;
  if (n < sizeof (buffer))
    {
      strcpy (buffer, "S ");
      strcat (buffer, keyword);
      if (*text)
        {
          strcat (buffer, " ");
          strcat (buffer, text);
        }
      assuan_write_line (ctx, buffer);
    }
  else if ( (helpbuf = xtrymalloc (n)) )
    {
      strcpy (helpbuf, "S ");
      strcat (helpbuf, keyword);
      if (*text)
        {
          strcat (helpbuf, " ");
          strcat (helpbuf, text);
        }
      assuan_write_line (ctx, helpbuf);
      xfree (helpbuf);
    }
}
