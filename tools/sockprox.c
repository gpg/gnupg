/* sockprox - Proxy for local sockets with logging facilities
 *	Copyright (C) 2007 g10 Code GmbH.
 *
 * sockprox is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * sockprox is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* Hacked by Moritz Schulte <moritz@g10code.com>.

   Usage example:

   Run a server which binds to a local socket.  For example,
   gpg-agent.  gpg-agent's local socket is specified with --server.
   sockprox opens a new local socket (here "mysock"); the whole
   traffic between server and client is written to "/tmp/prot" in this
   case.

     ./sockprox --server /tmp/gpg-PKdD8r/S.gpg-agent.ssh \
                --listen mysock --protocol /tmp/prot

   Then, redirect your ssh-agent client to sockprox by setting
   SSH_AUTH_SOCK to "mysock".
*/



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>

struct opt
{
  char *protocol_file;
  char *server_spec;
  char *listen_spec;
  int verbose;
};

struct opt opt = { NULL, NULL, NULL, 0 };

struct thread_data
{
  int client_sock;
  FILE *protocol_file;
};



static int
create_server_socket (const char *filename, int *new_sock)
{
  struct sockaddr_un name;
  size_t size;
  int sock;
  int ret;
  int err;

  /* Create the socket. */
  sock = socket (PF_LOCAL, SOCK_STREAM, 0);
  if (sock < 0)
    {
      err = errno;
      goto out;
    }

  /* Bind a name to the socket. */
  name.sun_family = AF_LOCAL;
  strncpy (name.sun_path, filename, sizeof (name.sun_path));
  name.sun_path[sizeof (name.sun_path) - 1] = '\0';
  size = SUN_LEN (&name);

  remove (filename);

  ret = bind (sock, (struct sockaddr *) &name, size);
  if (ret < 0)
    {
      err = errno;
      goto out;
    }

  ret = listen (sock, 2);
  if (ret < 0)
    {
      err = errno;
      goto out;
    }

  *new_sock = sock;
  err = 0;

 out:

  return err;
}

static int
connect_to_socket (const char *filename, int *new_sock)
{
  struct sockaddr_un srvr_addr;
  size_t len;
  int sock;
  int ret;
  int err;

  sock = socket (PF_LOCAL, SOCK_STREAM, 0);
  if (sock == -1)
    {
      err = errno;
      goto out;
    }

  memset (&srvr_addr, 0, sizeof srvr_addr);
  srvr_addr.sun_family = AF_LOCAL;
  strncpy (srvr_addr.sun_path, filename, sizeof (srvr_addr.sun_path) - 1);
  srvr_addr.sun_path[sizeof (srvr_addr.sun_path) - 1] = 0;
  len = SUN_LEN (&srvr_addr);

  ret = connect (sock, (struct sockaddr *) &srvr_addr, len);
  if (ret == -1)
    {
      close (sock);
      err = errno;
      goto out;
    }

  *new_sock = sock;
  err = 0;

 out:

  return err;
}



static int
log_data (unsigned char *data, size_t length,
	  FILE *from, FILE *to, FILE *protocol)
{
  unsigned int i;
  int ret;
  int err;

  flockfile (protocol);
  fprintf (protocol, "%i -> %i: ", fileno (from), fileno (to));
  for (i = 0; i < length; i++)
    fprintf (protocol, "%02X", data[i]);
  fprintf (protocol, "\n");
  funlockfile (protocol);

  ret = fflush (protocol);
  if (ret == EOF)
    err = errno;
  else
    err = 0;

  return err;
}

static int
transfer_data (FILE *from, FILE *to, FILE *protocol)
{
  unsigned char buffer[BUFSIZ];
  size_t len, written;
  int err;
  int ret;

  err = 0;

  while (1)
    {
      len = fread (buffer, 1, sizeof (buffer), from);
      if (len == 0)
	break;

      err = log_data (buffer, len, from, to, protocol);
      if (err)
	break;

      written = fwrite (buffer, 1, len, to);
      if (written != len)
	{
	  err = errno;
	  break;
	}

      ret = fflush (to);
      if (ret == EOF)
	{
	  err = errno;
	  break;
	}

      if (ferror (from))
	break;
    }

  return err;
}


static int
io_loop (FILE *client, FILE *server, FILE *protocol)
{
  fd_set active_fd_set, read_fd_set;
  int ret;
  int err;

  FD_ZERO (&active_fd_set);
  FD_SET (fileno (client), &active_fd_set);
  FD_SET (fileno (server), &active_fd_set);

  err = 0;

  while (1)
    {
      read_fd_set = active_fd_set;

      /* FIXME: eof?  */

      ret = select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
      if (ret < 0)
	{
	  err = errno;
	  break;
	}

      if (FD_ISSET (fileno (client), &read_fd_set))
	{
	  if (feof (client))
	    break;

	  /* Forward data from client to server.  */
	  err = transfer_data (client, server, protocol);
	}
      else if (FD_ISSET (fileno (server), &read_fd_set))
	{
	  if (feof (server))
	    break;

	  /* Forward data from server to client.  */
	  err = transfer_data (server, client, protocol);
	}

      if (err)
	break;
    }

  return err;
}




/* Set the 'O_NONBLOCK' flag of DESC if VALUE is nonzero,
   or clear the flag if VALUE is 0.
   Return 0 on success, or -1 on error with 'errno' set. */

int
set_nonblock_flag (int desc, int value)
{
  int oldflags = fcntl (desc, F_GETFL, 0);
  int err;
  int ret;

  /* If reading the flags failed, return error indication now. */
  if (oldflags == -1)
    return -1;
  /* Set just the flag we want to set. */
  if (value != 0)
    oldflags |= O_NONBLOCK;
  else
    oldflags &= ~O_NONBLOCK;
  /* Store modified flag word in the descriptor. */

  ret = fcntl (desc, F_SETFL, oldflags);
  if (ret == -1)
    err = errno;
  else
    err = 0;

  return err;
}



void *
serve_client (void *data)
{
  struct thread_data *thread_data = data;
  int client_sock = thread_data->client_sock;
  int server_sock;
  FILE *protocol = thread_data->protocol_file;
  FILE *client;
  FILE *server;
  int err;

  client = NULL;
  server = NULL;

  /* Connect to server.  */
  err = connect_to_socket (opt.server_spec, &server_sock);
  if (err)
    goto out;

  /* Set IO mode to nonblicking.  */
  err = set_nonblock_flag (server_sock, 1);
  if (err)
    goto out;

  client = fdopen (client_sock, "r+");
  if (! client)
    {
      err = errno;
      goto out;
    }

  server = fdopen (server_sock, "r+");
  if (! server)
    {
      err = errno;
      goto out;
    }

  err = io_loop (client, server, protocol);

 out:

  if (client)
    fclose (client);
  else
    close (client_sock);

  if (server)
    fclose (server);
  else
    close (server_sock);

  free (data);

  return NULL;
}

static int
run_proxy (void)
{
  int client_sock;
  int my_sock;
  int err;
  struct sockaddr_un clientname;
  size_t size;
  pthread_t  mythread;
  struct thread_data *thread_data;
  FILE *protocol_file;
  pthread_attr_t thread_attr;

  protocol_file = NULL;

  err = pthread_attr_init (&thread_attr);
  if (err)
    goto out;

  err = pthread_attr_setdetachstate (&thread_attr, PTHREAD_CREATE_DETACHED);
  if (err)
    goto out;

  if (opt.protocol_file)
    {
      protocol_file = fopen (opt.protocol_file, "a");
      if (! protocol_file)
	{
	  err = errno;
	  goto out;
	}
    }
  else
    protocol_file = stdout;

  err = create_server_socket (opt.listen_spec, &my_sock);
  if (err)
    goto out;

  while (1)
    {
      /* Accept new client.  */
      size = sizeof (clientname);
      client_sock = accept (my_sock,
			    (struct sockaddr *) &clientname,
			    &size);
      if (client_sock < 0)
	{
	  err = errno;
	  break;
	}

      /* Set IO mode to nonblicking.  */
      err = set_nonblock_flag (client_sock, 1);
      if (err)
	{
	  close (client_sock);
	  break;
	}

      /* Got new client -> handle in new process.  */

      thread_data = malloc (sizeof (*thread_data));
      if (! thread_data)
	{
	  err = errno;
	  break;
	}
      thread_data->client_sock = client_sock;
      thread_data->protocol_file = protocol_file;

      err = pthread_create (&mythread, &thread_attr, serve_client, thread_data);
      if (err)
	break;
    }
  if (err)
    goto out;

  /* ? */

 out:

  pthread_attr_destroy (&thread_attr);
  if (protocol_file)
    fclose (protocol_file);	/* FIXME, err checking.  */

  return err;
}



static int
print_help (int ret)
{
  printf ("Usage: sockprox [options] "
	  "--server SERVER-SOCKET --listen PROXY-SOCKET\n");
  exit (ret);
}

int
main (int argc, char **argv)
{
  struct option long_options[] =
    {
      { "help",     no_argument,       0,            'h' },
      { "verbose",  no_argument,       &opt.verbose, 1   },
      { "protocol", required_argument, 0,            'p' },
      { "server",   required_argument, 0,            's' },
      { "listen",   required_argument, 0,            'l' },
      { 0, 0, 0, 0 }
    };
  int ret;
  int err;
  int c;

  while (1)
    {
      int opt_idx = 0;
      c = getopt_long (argc, argv, "hvp:s:l:",
		       long_options, &opt_idx);

      if (c == -1)
	break;

      switch (c)
	{
	case 0:
	  if (long_options[opt_idx].flag)
	    break;
	  printf ("option %s", long_options[opt_idx].name);
	  if (optarg)
	    printf (" with arg %s", optarg);
	  printf ("\n");
	  break;

	case 'p':
	  opt.protocol_file = optarg;
	  break;

	case 's':
	  opt.server_spec = optarg;
	  break;

	case 'l':
	  opt.listen_spec = optarg;
	  break;

	case 'v':
	  opt.verbose = 1;
	  break;

	case 'h':
	  print_help (EXIT_SUCCESS);
	  break;

	default:
	  abort ();
	}
    }

  if (opt.verbose)
    {
      printf ("server: %s\n", opt.server_spec ? opt.server_spec : "");
      printf ("listen: %s\n", opt.listen_spec ? opt.listen_spec : "");
      printf ("protocol: %s\n", opt.protocol_file ? opt.protocol_file : "");
    }

  if (! (opt.server_spec && opt.listen_spec))
    print_help (EXIT_FAILURE);

  err = run_proxy ();
  if (err)
    {
      fprintf (stderr, "run_proxy() failed: %s\n", strerror (err));
      ret = EXIT_FAILURE;
    }
  else
    /* ? */
    ret = EXIT_SUCCESS;

  return ret;
}


/*
Local Variables:
compile-command: "cc -Wall -g -o sockprox sockprox.c -lpthread"
End:
*/
