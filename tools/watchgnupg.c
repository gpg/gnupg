/* watchgnupg.c - Socket server for GnuPG logs
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


#define PGM "watchgnupg"

static int verbose;
static int debug;


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
          printf ("%3d - ", c->fd);
          fwrite (c->buffer, c->len, 1, stdout); 
          putc ('\n', stdout);
          c->len = 0;
        }
      return;
    }

  while ((s = strchr (line, '\n')))
    {
      printf ("%3d - ", c->fd);
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



int 
main (int argc, char **argv)
{
  int last_argc = -1;
  int force = 0;

  struct sockaddr_un srvr_addr;
  int addrlen;
  int server;
  client_t client_list = NULL;
 
  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts (
                "usage: " PGM " [options] socketname\n"
                "\n"
                "       Options are --verbose, --debug and --force");
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
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
      die ("usage: " PGM " socketname\n");
    }


  if (verbose)
    fprintf (stderr, "opening socket `%s'\n", *argv);

  setvbuf (stdout, NULL, _IOLBF, 0);

  server = socket (PF_LOCAL, SOCK_STREAM, 0);
  if (server == -1)
    die ("socket() failed: %s\n", strerror (errno));

  memset (&srvr_addr, 0, sizeof srvr_addr);
  srvr_addr.sun_family = AF_LOCAL;
  strncpy (srvr_addr.sun_path, *argv, sizeof (srvr_addr.sun_path) - 1);
  srvr_addr.sun_path[sizeof (srvr_addr.sun_path) - 1] = 0;
  addrlen = (offsetof (struct sockaddr_un, sun_path)
             + strlen (srvr_addr.sun_path) + 1);

  
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
         to set them al the time from scratch and don't maintain an
         active fd_set. */
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
              printf ("accepting connection failed: %s\n", strerror (errno));
            }
          else if (fd >= FD_SETSIZE)
            {
              close (fd);
              printf ("[connection request denied: too many connections\n");
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
        if (client->fd != -1)
          {
            char line[256];
            int n;
            
            n = read (client->fd, line, sizeof line - 1);
            if (n == 1)
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
