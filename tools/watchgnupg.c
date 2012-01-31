/* watchgnupg.c - Socket server for GnuPG logs
 *	Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <time.h>

#define PGM "watchgnupg"

/* Allow for a standalone build on most systems. */
#ifdef VERSION
#define MYVERSION_LINE PGM " (GnuPG) " VERSION
#define BUGREPORT_LINE "\nReport bugs to <bug-gnupg@gnu.org>.\n"
#else
#define MYVERSION_LINE PGM
#define BUGREPORT_LINE ""
#endif
#if !defined(SUN_LEN) || !defined(PF_LOCAL) || !defined(AF_LOCAL)
#define JNLIB_NEED_AFLOCAL
#include "../jnlib/mischelp.h"
#endif


static int verbose;


static void
die (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);

  exit (1);
}


/* static void */
/* err (const char *format, ...) */
/* { */
/*   va_list arg_ptr; */

/*   fflush (stdout); */
/*   fprintf (stderr, "%s: ", PGM); */

/*   va_start (arg_ptr, format); */
/*   vfprintf (stderr, format, arg_ptr); */
/*   va_end (arg_ptr); */
/*   putc ('\n', stderr); */
/* } */

static void *
xmalloc (size_t n)
{
  void *p = malloc (n);
  if (!p)
    die ("out of core");
  return p;
}

static void *
xcalloc (size_t n, size_t m)
{
  void *p = calloc (n, m);
  if (!p)
    die ("out of core");
  return p;
}

static void *
xrealloc (void *old, size_t n)
{
  void *p = realloc (old, n);
  if (!p)
    die ("out of core");
  return p;
}


struct client_s {
  struct client_s *next;
  int fd;
  size_t size;  /* Allocated size of buffer. */
  size_t len;   /* Current length of buffer. */
  unsigned char *buffer; /* Buffer to with data already read. */

};
typedef struct client_s *client_t;



static void
print_fd_and_time (int fd)
{
  struct tm *tp;
  time_t atime = time (NULL);

  tp = localtime (&atime);
  printf ("%3d - %04d-%02d-%02d %02d:%02d:%02d ",
          fd,
          1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
          tp->tm_hour, tp->tm_min, tp->tm_sec );
}


/* Print LINE for the client identified by C.  Calling this function
   witgh LINE set to NULL, will flush the internal buffer. */
static void
print_line (client_t c, const char *line)
{
  const char *s;
  size_t n;

  if (!line)
    {
      if (c->buffer && c->len)
        {
          print_fd_and_time (c->fd);
          fwrite (c->buffer, c->len, 1, stdout);
          putc ('\n', stdout);
          c->len = 0;
        }
      return;
    }

  while ((s = strchr (line, '\n')))
    {
      print_fd_and_time (c->fd);
      if (c->buffer && c->len)
        {
          fwrite (c->buffer, c->len, 1, stdout);
          c->len = 0;
        }
      fwrite (line, s - line + 1, 1, stdout);
      line = s + 1;
    }
  n = strlen (line);
  if (n)
    {
      if (c->len + n >= c->size)
        {
          c->size += ((n + 255) & ~255);
          c->buffer = (c->buffer
                       ? xrealloc (c->buffer, c->size)
                       : xmalloc (c->size));
        }
      memcpy (c->buffer + c->len, line, n);
      c->len += n;
    }
}


static void
print_version (int with_help)
{
  fputs (MYVERSION_LINE "\n"
         "Copyright (C) 2012 Free Software Foundation, Inc.\n"
         "This program comes with ABSOLUTELY NO WARRANTY.\n"
         "This is free software, and you are welcome to redistribute it\n"
         "under certain conditions. See the file COPYING for details.\n",
         stdout);

  if (with_help)
    fputs ("\n"
          "Usage: " PGM " [OPTIONS] SOCKETNAME\n"
          "Open the local socket SOCKETNAME and display log messages\n"
          "\n"
          "  --force     delete an already existing socket file\n"
          "  --verbose   enable extra informational output\n"
          "  --version   print version of the program and exit\n"
          "  --help      display this help and exit\n"
          BUGREPORT_LINE, stdout );

  exit (0);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;
  int force = 0;

  struct sockaddr_un srvr_addr;
  socklen_t addrlen;
  int server;
  int flags;
  client_t client_list = NULL;

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--version"))
        print_version (0);
      else if (!strcmp (*argv, "--help"))
        print_version (1);
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--force"))
        {
          force = 1;
          argc--; argv++;
        }
    }

  if (argc != 1)
    {
      fprintf (stderr, "usage: " PGM " socketname\n");
      exit (1);
    }


  if (verbose)
    fprintf (stderr, "opening socket `%s'\n", *argv);

  setvbuf (stdout, NULL, _IOLBF, 0);

  server = socket (PF_LOCAL, SOCK_STREAM, 0);
  if (server == -1)
    die ("socket() failed: %s\n", strerror (errno));

  /* We better set the listening socket to non-blocking so that we
     don't get bitten by race conditions in accept.  The should not
     happen for Unix Domain sockets but well, shit happens. */
  flags = fcntl (server, F_GETFL, 0);
  if (flags == -1)
    die ("fcntl (F_GETFL) failed: %s\n", strerror (errno));
  if ( fcntl (server, F_SETFL, (flags | O_NONBLOCK)) == -1)
    die ("fcntl (F_SETFL) failed: %s\n", strerror (errno));


  memset (&srvr_addr, 0, sizeof srvr_addr);
  srvr_addr.sun_family = AF_LOCAL;
  strncpy (srvr_addr.sun_path, *argv, sizeof (srvr_addr.sun_path) - 1);
  srvr_addr.sun_path[sizeof (srvr_addr.sun_path) - 1] = 0;
  addrlen = SUN_LEN (&srvr_addr);


 again:
  if (bind (server, (struct sockaddr *) &srvr_addr, addrlen))
    {
      if (errno == EADDRINUSE && force)
        {
          force = 0;
          remove (srvr_addr.sun_path);
          goto again;
        }
      die ("bind to `%s' failed: %s\n", *argv, strerror (errno));
    }

  if (listen (server, 5))
    die ("listen failed: %s\n", strerror (errno));

  for (;;)
    {
      fd_set rfds;
      int max_fd;
      client_t client;

      /* Usually we don't have that many connections, thus it is okay
         to set them allways from scratch and don't maintain an active
         fd_set. */
      FD_ZERO (&rfds);
      FD_SET (server, &rfds);
      max_fd = server;
      for (client = client_list; client; client = client->next)
        if (client->fd != -1)
          {
            FD_SET (client->fd, &rfds);
            if (client->fd > max_fd)
              max_fd = client->fd;
          }

      if (select (max_fd + 1, &rfds, NULL, NULL, NULL) <= 0)
        continue;  /* Ignore any errors. */

      if (FD_ISSET (server, &rfds)) /* New connection. */
        {
          struct sockaddr_un clnt_addr;
          int fd;

          addrlen = sizeof clnt_addr;
          fd = accept (server, (struct sockaddr *) &clnt_addr, &addrlen);
          if (fd == -1)
            {
              printf ("[accepting connection failed: %s]\n", strerror (errno));
            }
          else if (fd >= FD_SETSIZE)
            {
              close (fd);
              printf ("[connection request denied: too many connections]\n");
            }
          else
            {
              for (client = client_list; client && client->fd != -1;
                   client = client->next)
                ;
              if (!client)
                {
                  client = xcalloc (1, sizeof *client);
                  client->next = client_list;
                  client_list = client;
                }
              client->fd = fd;
              printf ("[client at fd %d connected]\n", client->fd);
            }
        }
      for (client = client_list; client; client = client->next)
        if (client->fd != -1 && FD_ISSET (client->fd, &rfds))
          {
            char line[256];
            int n;

            n = read (client->fd, line, sizeof line - 1);
            if (n < 0)
              {
                int save_errno = errno;
                print_line (client, NULL); /* flush */
                printf ("[client at fd %d read error: %s]\n",
                        client->fd, strerror (save_errno));
                close (client->fd);
                client->fd = -1;
              }
            else if (!n)
              {
                print_line (client, NULL); /* flush */
                close (client->fd);
                printf ("[client at fd %d disconnected]\n", client->fd);
                client->fd = -1;
              }
            else
              {
                line[n] = 0;
                print_line (client, line);
              }
          }
    }

  return 0;
}


/*
Local Variables:
compile-command: "gcc -Wall -g -o watchgnupg watchgnupg.c"
End:
*/
