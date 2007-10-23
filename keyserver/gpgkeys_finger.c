/* gpgkeys_finger.c - fetch a key via finger
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "util.h"
#include "keyserver.h"
#include "ksutil.h"

#ifdef _WIN32
#define sock_close(a)  closesocket(a)
#else
#define sock_close(a)  close(a)
#endif

extern char *optarg;
extern int optind;

static FILE *input,*output,*console;
static struct ks_options *opt;

#ifdef _WIN32
static void
deinit_sockets (void)
{
  WSACleanup();
}

static void
init_sockets (void)
{
  static int initialized;
  static WSADATA wsdata;

  if (initialized)
    return;

  if (WSAStartup (0x0101, &wsdata) )
    {
      fprintf (console, "error initializing socket library: ec=%d\n", 
               (int)WSAGetLastError () );
      return;
    }
  if (wsdata.wVersion < 0x0001)
    {
      fprintf (console, "socket library version is %x.%x - but 1.1 needed\n",
               LOBYTE(wsdata.wVersion), HIBYTE(wsdata.wVersion));
      WSACleanup();
      return;
    }
  atexit  (deinit_sockets);
  initialized = 1;
}
#endif /*_WIN32*/


/* Connect to SERVER at PORT and return a file descriptor or -1 on
   error. */
static int
connect_server (const char *server, unsigned short port)
{
  int sock = -1;

#ifdef _WIN32
  struct hostent *hp;
  struct sockaddr_in addr;
  unsigned long l;

  init_sockets ();

  memset (&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);

  /* Win32 gethostbyname doesn't handle IP addresses internally, so we
     try inet_addr first on that platform only. */
  if ((l = inet_addr (server)) != INADDR_NONE) 
    memcpy (&addr.sin_addr, &l, sizeof l);
  else if ((hp = gethostbyname (server))) 
    {
      if (hp->h_addrtype != AF_INET)
        {
          fprintf (console, "gpgkeys: unknown address family for `%s'\n",
                   server);
          return -1;
        }
      if (hp->h_length != 4)
        {
          fprintf (console, "gpgkeys: illegal address length for `%s'\n",
                   server);
          return -1;
        }
      memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);
    }
  else
    {
      fprintf (console, "gpgkeys: host `%s' not found: ec=%d\n",
               server, (int)WSAGetLastError ());
      return -1;
    }

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET)
    {
      fprintf (console, "gpgkeys: error creating socket: ec=%d\n", 
               (int)WSAGetLastError ());
      return -1;
    }

  if (connect (sock, (struct sockaddr *)&addr, sizeof addr))
    {
      fprintf (console, "gpgkeys: error connecting `%s': ec=%d\n", 
               server, (int)WSAGetLastError ());
      sock_close (sock);
      return -1;
    }

#else

  struct sockaddr_in addr;
  struct hostent *host;

  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  host = gethostbyname ((char*)server);
  if (!host)
    {
      fprintf (console, "gpgkeys: host `%s' not found: %s\n",
               server, strerror (errno));
      return -1;
    }
  
  addr.sin_addr = *(struct in_addr*)host->h_addr;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    {
      fprintf (console, "gpgkeys: error creating socket: %s\n", 
               strerror (errno));
      return -1;
    }
  
  if (connect (sock, (struct sockaddr *)&addr, sizeof addr) == -1)
    {
      fprintf (console, "gpgkeys: error connecting `%s': %s\n", 
               server, strerror (errno));
      close (sock);
      return -1;
    }
#endif
    
  return sock;
}

static int
write_server (int sock, const char *data, size_t length)
{
  int nleft;

  nleft = length;
  while (nleft > 0) 
    {
      int nwritten;
      
#ifdef _WIN32  
      nwritten = send (sock, data, nleft, 0);
      if ( nwritten == SOCKET_ERROR )
        {
          fprintf (console, "gpgkeys: write failed: ec=%d\n",
                   (int)WSAGetLastError ());
          return -1;
        }
#else
      nwritten = write (sock, data, nleft);
      if (nwritten == -1)
        {
          if (errno == EINTR)
            continue;
          if (errno == EAGAIN)
            {
              struct timeval tv;
              
              tv.tv_sec =  0;
              tv.tv_usec = 50000;
              select(0, NULL, NULL, NULL, &tv);
              continue;
	    }
          fprintf (console, "gpgkeys: write failed: %s\n", strerror(errno));
          return -1;
	}
#endif
      nleft -=nwritten;
      data += nwritten;
    }
  
  return 0;
}


/* Send the finger REQUEST to the server.  Returns 0 and a file descriptor
   in R_SOCK if the request was sucessful. */
static int
send_request (const char *request, int *r_sock)
{
  char *server;
  char *name;
  int sock;

  *r_sock = -1;
  name = strdup (request);
  if (!name)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return KEYSERVER_NO_MEMORY;
    }

  server = strchr (name, '@');
  if (!server)
    {
      fprintf (console, "gpgkeys: no name included in request\n");
      free (name);
      return KEYSERVER_GENERAL_ERROR;
    }
  *server++ = 0;
  
  sock = connect_server (server, 79);
  if (sock == -1)
    {
      free (name);
      return KEYSERVER_UNREACHABLE;
    }

  if (write_server (sock, name, strlen (name))
      || write_server (sock, "\r\n", 2))
    {
      free (name);
      sock_close (sock);
      return KEYSERVER_GENERAL_ERROR;
    }
  free (name);
  *r_sock = sock;
  return 0;
}



static int
get_key (char *getkey)
{
  int rc;
  int sock;
  IOBUF fp_read;
  unsigned int maxlen, buflen, gotit=0;
  byte *line = NULL;

  if (strncmp (getkey,"0x",2)==0)
    getkey+=2;

  /* Frankly we don't know what keys the server will return; we
     indicated the requested key anyway. */
  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  rc=send_request(opt->opaque,&sock);
  if(rc)
    {
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey, rc);
      sock_close (sock);
      return KEYSERVER_OK;
    }
  
  /* Hmmm, we use iobuf here only to cope with Windows socket
     peculiarities (we can't used fdopen).  */
  fp_read = iobuf_sockopen (sock , "r");
  if (!fp_read)
    {
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey, KEYSERVER_INTERNAL_ERROR);
      sock_close (sock);
      return KEYSERVER_OK;
    }

  while ( iobuf_read_line ( fp_read, &line, &buflen, &maxlen))
    {
      maxlen=1024;
      
      if(gotit)
        {
	  print_nocr (output, (const char*)line);
          if (!strncmp((char*)line,END,strlen(END)))
            break;
        }
      else if(!strncmp((char*)line,BEGIN,strlen(BEGIN)))
        {
	  print_nocr(output, (const char*)line);
          gotit=1;
        }
    }
  
  if(gotit)
    fprintf (output,"KEY 0x%s END\n", getkey);
  else
    {
      fprintf(console,"gpgkeys: no key data found for finger:%s\n",
	      opt->opaque);
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,KEYSERVER_KEY_NOT_FOUND);
    }

  xfree(line);
  iobuf_close (fp_read);

  return KEYSERVER_OK;
}


static void 
show_help (FILE *fp)
{
  fprintf (fp,"-h\thelp\n");
  fprintf (fp,"-V\tversion\n");
  fprintf (fp,"-o\toutput to this file\n");
}

int
main(int argc,char *argv[])
{
  int arg,ret=KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE];
  char *thekey=NULL;

  console=stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      fputs ("gpgkeys_finger (GnuPG) " VERSION"\n", stdout);
      return 0;
    }
  else if (argc > 1 && !strcmp (argv[1], "--help"))
    {
      show_help (stdout);
      return 0;
    }

  while((arg=getopt(argc,argv,"hVo:"))!=-1)
    switch(arg)
      {
      default:
      case 'h':
        show_help (console);
	return KEYSERVER_OK;

      case 'V':
	fprintf(stdout,"%d\n%s\n",KEYSERVER_PROTO_VERSION,VERSION);
	return KEYSERVER_OK;

      case 'o':
	output=fopen(optarg,"w");
	if(output==NULL)
	  {
	    fprintf(console,"gpgkeys: Cannot open output file `%s': %s\n",
		    optarg,strerror(errno));
	    return KEYSERVER_INTERNAL_ERROR;
	  }

	break;
      }

  if(argc>optind)
    {
      input=fopen(argv[optind],"r");
      if(input==NULL)
	{
	  fprintf(console,"gpgkeys: Cannot open input file `%s': %s\n",
		  argv[optind],strerror(errno));
	  return KEYSERVER_INTERNAL_ERROR;
	}
    }

  if(input==NULL)
    input=stdin;

  if(output==NULL)
    output=stdout;

  opt=init_ks_options();
  if(!opt)
    return KEYSERVER_NO_MEMORY;

  /* Get the command and info block */

  while(fgets(line,MAX_LINE,input)!=NULL)
    {
      int err;

      if(line[0]=='\n')
	break;

      err=parse_ks_options(line,opt);
      if(err>0)
	{
	  ret=err;
	  goto fail;
	}
      else if(err==0)
	continue;
    }

  if(opt->host)
    {
      fprintf(console,"gpgkeys: finger://relay/user syntax is not"
	      " supported.  Use finger:user instead.\n");
      ret=KEYSERVER_NOT_SUPPORTED;
      goto fail;
    }

  if(opt->timeout && register_timeout()==-1)
    {
      fprintf(console,"gpgkeys: unable to register timeout handler\n");
      return KEYSERVER_INTERNAL_ERROR;
    }

  /* If it's a GET or a SEARCH, the next thing to come in is the
     keyids.  If it's a SEND, then there are no keyids. */

  if(opt->action==KS_GET)
    {
      /* Eat the rest of the file */
      for(;;)
	{
	  if(fgets(line,MAX_LINE,input)==NULL)
	    break;
	  else
	    {
	      if(line[0]=='\n' || line[0]=='\0')
		break;

	      if(!thekey)
		{
		  thekey=strdup(line);
		  if(!thekey)
		    {
		      fprintf(console,"gpgkeys: out of memory while "
			      "building key list\n");
		      ret=KEYSERVER_NO_MEMORY;
		      goto fail;
		    }

		  /* Trim the trailing \n */
		  thekey[strlen(line)-1]='\0';
		}
	    }
	}
    }
  else
    {
      fprintf(console,
	      "gpgkeys: this keyserver type only supports key retrieval\n");
      goto fail;
    }

  if(!thekey || !opt->opaque)
    {
      fprintf(console,"gpgkeys: invalid keyserver instructions\n");
      goto fail;
    }

  /* Send the response */

  fprintf(output,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(output,"PROGRAM %s\n\n",VERSION);

  if(opt->verbose>1)
    {
      fprintf(console,"User:\t\t%s\n",opt->opaque);
      fprintf(console,"Command:\tGET\n");
    }

  set_timeout(opt->timeout);

  ret=get_key(thekey);

 fail:

  free(thekey);

  if(input!=stdin)
    fclose(input);

  if(output!=stdout)
    fclose(output);

  free_ks_options(opt);

  return ret;
}
