/* gpgkeys_http.c - fetch a key via HTTP
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
#define INCLUDED_BY_MAIN_MODULE 1
#include "util.h"
#include "http.h"
#include "keyserver.h"
#include "ksutil.h"

#define GET    0

extern char *optarg;
extern int optind;

static int verbose=0;
static unsigned int http_flags=0;
static char auth[MAX_AUTH+1];
static char host[MAX_HOST+1];
static char proxy[MAX_PROXY+1];
static char port[MAX_PORT+1];
static char path[URLMAX_PATH+1];
static FILE *input,*output,*console;

static int
get_key(char *getkey)
{
  int rc;
  char *request;
  struct http_context hd;

  if(strncmp(getkey,"0x",2)==0)
    getkey+=2;

  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  request=malloc(4+3+strlen(host)+1+strlen(port)+1+strlen(path)+50);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return KEYSERVER_NO_MEMORY;
    }

  sprintf(request,"http://%s%s%s%s%s",host,
	  port[0]?":":"",port[0]?port:"",path[0]?"":"/",path);

  rc=http_open_document(&hd,request,auth[0]?auth:NULL,
			http_flags,proxy[0]?proxy:NULL);
  if(rc!=0)
    {
      fprintf(console,"gpgkeys: HTTP fetch error: %s\n",
	      rc==G10ERR_NETWORK?strerror(errno):g10_errstr(rc));
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,
	    rc==G10ERR_NETWORK?KEYSERVER_UNREACHABLE:KEYSERVER_INTERNAL_ERROR);
    }
  else
    {
      unsigned int maxlen=1024,buflen,gotit=0;
      byte *line=NULL;

      while(iobuf_read_line(hd.fp_read,&line,&buflen,&maxlen))
	{
	  maxlen=1024;

	  if(gotit)
	    {
	      print_nocr(output,line);
	      if(strncmp(line,END,strlen(END))==0)
		break;
	    }
	  else
	    if(strncmp(line,BEGIN,strlen(BEGIN))==0)
	      {
		print_nocr(output,line);
		gotit=1;
	      }
	}

      if(gotit)
	fprintf(output,"KEY 0x%s END\n",getkey);
      else
	{
	  fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
	  fprintf(output,"KEY 0x%s FAILED %d\n",
		  getkey,KEYSERVER_KEY_NOT_FOUND);
	}

      m_free(line);
      http_close(&hd);
    }

  free(request);

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
  int arg,action=-1,ret=KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE];
  char *thekey=NULL;
  unsigned int timeout=DEFAULT_KEYSERVER_TIMEOUT;

  console=stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      fputs ("gpgkeys_http (GnuPG) " VERSION"\n", stdout);
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

  /* Get the command and info block */

  while(fgets(line,MAX_LINE,input)!=NULL)
    {
      int version;
      char command[MAX_COMMAND+1];
      char option[MAX_OPTION+1];
      char hash;

      if(line[0]=='\n')
	break;

      if(sscanf(line,"%c",&hash)==1 && hash=='#')
	continue;

      if(sscanf(line,"COMMAND %" MKSTRING(MAX_COMMAND) "s\n",command)==1)
	{
	  command[MAX_COMMAND]='\0';

	  if(strcasecmp(command,"get")==0)
	    action=GET;

	  continue;
	}

      if(sscanf(line,"AUTH %" MKSTRING(MAX_AUTH) "s\n",auth)==1)
	{
	  auth[MAX_AUTH]='\0';
	  continue;
	}

      if(sscanf(line,"HOST %" MKSTRING(MAX_HOST) "s\n",host)==1)
	{
	  host[MAX_HOST]='\0';
	  continue;
	}

      if(sscanf(line,"PORT %" MKSTRING(MAX_PORT) "s\n",port)==1)
	{
	  port[MAX_PORT]='\0';
	  continue;
	}

      if(sscanf(line,"PATH %" MKSTRING(URLMAX_PATH) "s\n",path)==1)
	{
	  path[URLMAX_PATH]='\0';
	  continue;
	}

      if(sscanf(line,"VERSION %d\n",&version)==1)
	{
	  if(version!=KEYSERVER_PROTO_VERSION)
	    {
	      ret=KEYSERVER_VERSION_ERROR;
	      goto fail;
	    }

	  continue;
	}

      if(sscanf(line,"OPTION %" MKSTRING(MAX_OPTION) "s\n",option)==1)
	{
	  int no=0;
	  char *start=&option[0];

	  option[MAX_OPTION]='\0';

	  if(strncasecmp(option,"no-",3)==0)
	    {
	      no=1;
	      start=&option[3];
	    }

	  if(strcasecmp(start,"verbose")==0)
	    {
	      if(no)
		verbose--;
	      else
		verbose++;
	    }
	  else if(strncasecmp(start,"http-proxy",10)==0)
	    {
	      if(no)
		proxy[0]='\0';
	      else if(start[10]=='=')
		{
		  strncpy(proxy,&start[11],79);
		  proxy[79]='\0';
		}
	      else if(start[10]=='\0')
		{
		  char *http_proxy=getenv(HTTP_PROXY_ENV);
		  if(http_proxy)
		    {
		      strncpy(proxy,http_proxy,79);
		      proxy[79]='\0';
		    }
		}
	    }
	  else if(strcasecmp(start,"broken-http-proxy")==0)
	    {
	      if(no)
		http_flags&=~HTTP_FLAG_NO_SHUTDOWN;
	      else
		http_flags|=HTTP_FLAG_NO_SHUTDOWN;
	    }
	  else if(strcasecmp(start,"try-dns-srv")==0)
	    {
	      if(no)
		http_flags&=~HTTP_FLAG_TRY_SRV;
	      else
		http_flags|=HTTP_FLAG_TRY_SRV;
	    }
	  else if(strncasecmp(start,"timeout",7)==0)
	    {
	      if(no)
		timeout=0;
	      else if(start[7]=='=')
		timeout=atoi(&start[8]);
	      else if(start[7]=='\0')
		timeout=DEFAULT_KEYSERVER_TIMEOUT;
	    }

	  continue;
	}
    }

  if(timeout && register_timeout()==-1)
    {
      fprintf(console,"gpgkeys: unable to register timeout handler\n");
      return KEYSERVER_INTERNAL_ERROR;
    }

  /* By suggested convention, if the user gives a :port, then disable
     SRV. */
  if(port[0])
    http_flags&=~HTTP_FLAG_TRY_SRV;

  /* If it's a GET or a SEARCH, the next thing to come in is the
     keyids.  If it's a SEND, then there are no keyids. */

  if(action==GET)
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

  if(!thekey || !host[0])
    {
      fprintf(console,"gpgkeys: invalid keyserver instructions\n");
      goto fail;
    }

  /* Send the response */

  fprintf(output,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(output,"PROGRAM %s\n\n",VERSION);

  if(verbose>1)
    {
      fprintf(console,"Host:\t\t%s\n",host);
      if(port[0])
	fprintf(console,"Port:\t\t%s\n",port);
      if(path[0])
	fprintf(console,"Path:\t\t%s\n",path);
      fprintf(console,"Command:\tGET\n");
    }

  set_timeout(timeout);

  ret=get_key(thekey);

 fail:

  free(thekey);

  if(input!=stdin)
    fclose(input);

  if(output!=stdout)
    fclose(output);

  return ret;
}
