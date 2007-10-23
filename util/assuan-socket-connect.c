/* assuan-socket-connect.c - Assuan socket based client
 *	Copyright (C) 2002, 2003, 2004 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Please note that this is a stripped down and modified version of
   the orginal Assuan code from libassuan. */

#include <config.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <windows.h>
#endif

#include "assuan-defs.h"

/* Hacks for Slowaris.  */
#ifndef PF_LOCAL
# ifdef PF_UNIX
#  define PF_LOCAL PF_UNIX
# else
#  define PF_LOCAL AF_UNIX
# endif
#endif
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif

#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) \
	               + strlen ((ptr)->sun_path))
#endif

 
static int
do_finish (assuan_context_t ctx)
{
  if (ctx->inbound.fd != -1)
    {
      _assuan_close (ctx->inbound.fd);
    }
  ctx->inbound.fd = -1;
  ctx->outbound.fd = -1;
  return 0;
}

static void
do_deinit (assuan_context_t ctx)
{
  do_finish (ctx);
}


static ssize_t
simple_read (assuan_context_t ctx, void *buffer, size_t size)
{
#ifndef HAVE_W32_SYSTEM
  return read (ctx->inbound.fd, buffer, size);
#else
  return recv (ctx->inbound.fd, buffer, size, 0);
#endif
}

static ssize_t
simple_write (assuan_context_t ctx, const void *buffer, size_t size)
{
#ifndef HAVE_W32_SYSTEM
  return write (ctx->outbound.fd, buffer, size);
#else
  return send (ctx->outbound.fd, buffer, size, 0);
#endif
}


/* Make a connection to the Unix domain socket NAME and return a new
   Assuan context in CTX.  SERVER_PID is currently not used but may
   become handy in the future.  */
assuan_error_t
assuan_socket_connect (assuan_context_t *r_ctx,
                       const char *name, pid_t server_pid)
{
  static struct assuan_io io = { simple_read, simple_write };

  assuan_error_t err;
  assuan_context_t ctx;
  int fd;
  struct sockaddr_un srvr_addr;
  size_t len;
  const char *s;

  if (!r_ctx || !name)
    return ASSUAN_Invalid_Value;
  *r_ctx = NULL;

  /* We require that the name starts with a slash, so that we can
     alter reuse this function for other socket types.  To make things
     easier we allow an optional dirver prefix.  */
  s = name;
  if (*s && s[1] == ':')
    s += 2;
  if (*s != DIRSEP_C && *s != '/')
    return ASSUAN_Invalid_Value;

  if (strlen (name)+1 >= sizeof srvr_addr.sun_path)
    return ASSUAN_Invalid_Value;

  err = _assuan_new_context (&ctx); 
  if (err)
      return err;
  ctx->deinit_handler = do_deinit;
  ctx->finish_handler = do_finish;


  fd = _assuan_sock_new (PF_LOCAL, SOCK_STREAM, 0);
  if (fd == -1)
    {
      _assuan_log_printf ("can't create socket: %s\n", strerror (errno));
      _assuan_release_context (ctx);
      return ASSUAN_General_Error;
    }

  memset (&srvr_addr, 0, sizeof srvr_addr);
  srvr_addr.sun_family = AF_LOCAL;
  strncpy (srvr_addr.sun_path, name, sizeof (srvr_addr.sun_path) - 1);
  srvr_addr.sun_path[sizeof (srvr_addr.sun_path) - 1] = 0;
  len = SUN_LEN (&srvr_addr);


  if (_assuan_sock_connect (fd, (struct sockaddr *) &srvr_addr, len) == -1)
    {
      _assuan_log_printf ("can't connect to `%s': %s\n",
                          name, strerror (errno));
      _assuan_release_context (ctx);
      _assuan_close (fd);
      return ASSUAN_Connect_Failed;
    }

  ctx->inbound.fd = fd;
  ctx->outbound.fd = fd;
  ctx->io = &io;

  /* initial handshake */
  {
    int okay, off;

    err = _assuan_read_from_server (ctx, &okay, &off);
    if (err)
      _assuan_log_printf ("can't connect to server: %s\n",
                          assuan_strerror (err));
    else if (okay != 1)
      {
        /*LOG ("can't connect to server: `");*/
	_assuan_log_sanitized_string (ctx->inbound.line);
	fprintf (assuan_get_assuan_log_stream (), "'\n");
	err = ASSUAN_Connect_Failed;
      }
  }

  if (err)
    {
      assuan_disconnect (ctx); 
    }
  else
    *r_ctx = ctx;
  return 0;
}
