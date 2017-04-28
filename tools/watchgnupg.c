/* watchgnupg.c - Socket server for GnuPG logs
 *	Copyright (C) 2003, 2004, 2010 Free Software Foundation, Inc.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#define PGM "watchgnupg"

/* Allow for a standalone build on most systems. */
#ifdef VERSION
#define MYVERSION_LINE PGM " ("GNUPG_NAME") " VERSION
#define BUGREPORT_LINE "\nReport bugs to <bug-gnupg@gnu.org>.\n"
#else
#define MYVERSION_LINE PGM " (standalone build) " __DATE__
#define BUGREPORT_LINE ""
#endif
#if !defined(SUN_LEN) || !defined(PF_LOCAL) || !defined(AF_LOCAL)
#define GNUPG_COMMON_NEED_AFLOCAL
#include "../common/mischelp.h"
#endif


static int verbose;
static int time_only;

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


static void
err (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
  fprintf (stderr, "%s: ", PGM);

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  putc ('\n', stderr);
}

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

/* The list of all connected peers.  */
static client_t client_list;




static void
print_fd_and_time (int fd)
{
  struct tm *tp;
  time_t atime = time (NULL);

  tp = localtime (&atime);
  if (time_only)
    printf ("%3d - %02d:%02d:%02d ",
            fd,
            tp->tm_hour, tp->tm_min, tp->tm_sec );
  else
    printf ("%3d - %04d-%02d-%02d %02d:%02d:%02d ",
            fd,
            1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
            tp->tm_hour, tp->tm_min, tp->tm_sec );
}


/* Print LINE for the client identified by C.  Calling this function
   with LINE set to NULL, will flush the internal buffer. */
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
setup_client (int server_fd, int is_un)
{
  struct sockaddr_un addr_un;
  struct sockaddr_in addr_in;
  struct sockaddr *addr;
  socklen_t addrlen;
  int fd;
  client_t client;

  if (is_un)
    {
      addr = (struct sockaddr *)&addr_un;
      addrlen = sizeof addr_un;
    }
  else
    {
      addr = (struct sockaddr *)&addr_in;
      addrlen = sizeof addr_in;
    }

  fd = accept (server_fd, addr, &addrlen);
  if (fd == -1)
    {
      printf ("[accepting %s connection failed: %s]\n",
              is_un? "local":"tcp", strerror (errno));
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
      printf ("[client at fd %d connected (%s)]\n",
              client->fd, is_un? "local":"tcp");
    }
}



static void
print_version (int with_help)
{
  fputs (MYVERSION_LINE "\n"
         "Copyright (C) 2017 Free Software Foundation, Inc.\n"
         "License GPLv3+: "
         "GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>\n"
         "This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n",
         stdout);
  if (with_help)
    fputs
      ("\n"
       "Usage: " PGM " [OPTIONS] SOCKETNAME\n"
       "       " PGM " [OPTIONS] PORT [SOCKETNAME]\n"
       "Open the local socket SOCKETNAME (or the TCP port PORT)\n"
       "and display log messages\n"
       "\n"
       "  --tcp       listen on a TCP port and optionally on a local socket\n"
       "  --force     delete an already existing socket file\n"
       "  --verbose   enable extra informational output\n"
       "  --time-only print only the time; not a full timestamp\n"
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
  int tcp = 0;

  struct sockaddr_un srvr_addr_un;
  struct sockaddr_in srvr_addr_in;
  struct sockaddr *addr_in = NULL;
  struct sockaddr *addr_un = NULL;
  socklen_t addrlen_in, addrlen_un;
  unsigned short port;
  int server_un, server_in;
  int flags;

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
      else if (!strcmp (*argv, "--time-only"))
        {
          time_only = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--force"))
        {
          force = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--tcp"))
        {
          tcp = 1;
          argc--; argv++;
        }
    }

  if (!((!tcp && argc == 1) || (tcp && (argc == 1 || argc == 2))))
    {
      fprintf (stderr, "usage: " PGM " socketname\n"
                       "       " PGM " --tcp port [socketname]\n");
      exit (1);
    }

  if (tcp)
    {
      port = atoi (*argv);
      argc--; argv++;
    }
  else
    {
      port = 0;
    }

  setvbuf (stdout, NULL, _IOLBF, 0);

  if (tcp)
    {
      int i = 1;
      server_in = socket (PF_INET, SOCK_STREAM, 0);
      if (server_in == -1)
        die ("socket(PF_INET) failed: %s\n", strerror (errno));
      if (setsockopt (server_in, SOL_SOCKET, SO_REUSEADDR,
                      (unsigned char *)&i, sizeof (i)))
        err ("setsockopt(SO_REUSEADDR) failed: %s\n", strerror (errno));
      if (verbose)
        fprintf (stderr, "listening on port %hu\n", port);
    }
  else
    server_in = -1;

  if (argc)
    {
      server_un = socket (PF_LOCAL, SOCK_STREAM, 0);
      if (server_un == -1)
        die ("socket(PF_LOCAL) failed: %s\n", strerror (errno));
      if (verbose)
        fprintf (stderr, "listening on socket '%s'\n", *argv);
    }
  else
    server_un = -1;

  /* We better set the listening socket to non-blocking so that we
     don't get bitten by race conditions in accept.  The should not
     happen for Unix Domain sockets but well, shit happens. */
  if (server_in != -1)
    {
      flags = fcntl (server_in, F_GETFL, 0);
      if (flags == -1)
        die ("fcntl (F_GETFL) failed: %s\n", strerror (errno));
      if ( fcntl (server_in, F_SETFL, (flags | O_NONBLOCK)) == -1)
        die ("fcntl (F_SETFL) failed: %s\n", strerror (errno));
    }
  if (server_un != -1)
    {
      flags = fcntl (server_un, F_GETFL, 0);
      if (flags == -1)
        die ("fcntl (F_GETFL) failed: %s\n", strerror (errno));
      if ( fcntl (server_un, F_SETFL, (flags | O_NONBLOCK)) == -1)
        die ("fcntl (F_SETFL) failed: %s\n", strerror (errno));
    }

  if (tcp)
    {
      memset (&srvr_addr_in, 0, sizeof srvr_addr_in);
      srvr_addr_in.sin_family = AF_INET;
      srvr_addr_in.sin_port = htons (port);
      srvr_addr_in.sin_addr.s_addr = htonl (INADDR_ANY);
      addr_in = (struct sockaddr *)&srvr_addr_in;
      addrlen_in = sizeof srvr_addr_in;
    }
  if (argc)
    {
      memset (&srvr_addr_un, 0, sizeof srvr_addr_un);
      srvr_addr_un.sun_family = AF_LOCAL;
      strncpy (srvr_addr_un.sun_path, *argv, sizeof (srvr_addr_un.sun_path)-1);
      srvr_addr_un.sun_path[sizeof (srvr_addr_un.sun_path) - 1] = 0;
      addr_un = (struct sockaddr *)&srvr_addr_un;
      addrlen_un = SUN_LEN (&srvr_addr_un);
    }
  else
    addrlen_un = 0;  /* Silent gcc.  */

  if (server_in != -1 && bind (server_in, addr_in, addrlen_in))
    die ("bind to port %hu failed: %s\n", port, strerror (errno));

 again:
  if (server_un != -1 && bind (server_un, addr_un, addrlen_un))
    {
      if (errno == EADDRINUSE && force)
        {
          force = 0;
          remove (srvr_addr_un.sun_path);
          goto again;
        }
      else
        die ("bind to '%s' failed: %s\n", *argv, strerror (errno));
    }

  if (server_in != -1 && listen (server_in, 5))
    die ("listen on inet failed: %s\n", strerror (errno));
  if (server_un != -1 && listen (server_un, 5))
    die ("listen on local failed: %s\n", strerror (errno));

  for (;;)
    {
      fd_set rfds;
      int max_fd;
      client_t client;

      /* Usually we don't have that many connections, thus it is okay
         to set them always from scratch and don't maintain an active
         fd_set. */
      FD_ZERO (&rfds);
      max_fd = -1;
      if (server_in != -1)
        {
          FD_SET (server_in, &rfds);
          max_fd = server_in;
        }
      if (server_un != -1)
        {
          FD_SET (server_un, &rfds);
          if (server_un > max_fd)
            max_fd = server_un;
        }
      for (client = client_list; client; client = client->next)
        if (client->fd != -1)
          {
            FD_SET (client->fd, &rfds);
            if (client->fd > max_fd)
              max_fd = client->fd;
          }

      if (select (max_fd + 1, &rfds, NULL, NULL, NULL) <= 0)
        continue;  /* Ignore any errors. */

      if (server_in != -1 && FD_ISSET (server_in, &rfds))
        setup_client (server_in, 0);
      if (server_un != -1 && FD_ISSET (server_un, &rfds))
        setup_client (server_un, 1);

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
