/* gpgkeys_curl.c - fetch a key via libcurl
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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
#include <curl/curl.h>
#include "keyserver.h"
#include "ksutil.h"

extern char *optarg;
extern int optind;

static int verbose=0;
static char scheme[MAX_SCHEME+1],auth[MAX_AUTH+1],host[MAX_HOST+1]={'\0'},port[MAX_PORT+1]={'\0'},path[MAX_PATH+1]={'\0'},proxy[MAX_PROXY+1]={'\0'};
static FILE *input=NULL,*output=NULL,*console=NULL;
static CURL *curl;
static char request[MAX_URL]={'\0'};

static int
curl_err_to_gpg_err(CURLcode error)
{
  switch(error)
    {
    case CURLE_FTP_COULDNT_RETR_FILE: return KEYSERVER_KEY_NOT_FOUND;
    default: return KEYSERVER_INTERNAL_ERROR;
    }
}

/* We wrap fwrite so to avoid DLL problems on Win32 (see curl faq for
   more). */
static size_t
writer(const void *ptr,size_t size,size_t nmemb,void *stream)
{
  return fwrite(ptr,size,nmemb,stream);
}

static int
get_key(char *getkey)
{
  CURLcode res;
  char errorbuffer[CURL_ERROR_SIZE];

  if(strncmp(getkey,"0x",2)==0)
    getkey+=2;

  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  sprintf(request,"%s://%s%s%s%s%s%s%s",scheme,auth[0]?auth:"",auth[0]?"@":"",
	  host,port[0]?":":"",port[0]?port:"",path[0]?"":"/",path);

  curl_easy_setopt(curl,CURLOPT_URL,request);
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,writer);
  curl_easy_setopt(curl,CURLOPT_FILE,output);
  curl_easy_setopt(curl,CURLOPT_ERRORBUFFER,errorbuffer);

  if(verbose>1)
    {
      curl_easy_setopt(curl,CURLOPT_STDERR,console);
      curl_easy_setopt(curl,CURLOPT_VERBOSE,1);
    }

  res=curl_easy_perform(curl);
  if(res!=0)
    {
      fprintf(console,"gpgkeys: %s fetch error %d: %s\n",scheme,
	      res,errorbuffer);
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,curl_err_to_gpg_err(res));
    }
  else
    fprintf(output,"KEY 0x%s END\n",getkey);

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
  long follow_redirects=5;

  console=stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      fputs ("gpgkeys_curl (GnuPG) " VERSION"\n", stdout);
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
	output=fopen(optarg,"wb");
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

      if(sscanf(line,"SCHEME %" MKSTRING(MAX_SCHEME) "s\n",scheme)==1)
	{
	  scheme[MAX_SCHEME]='\0';
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

      if(sscanf(line,"PATH %" MKSTRING(MAX_PATH) "s\n",path)==1)
	{
	  path[MAX_PATH]='\0';
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
		  strncpy(proxy,&start[11],MAX_PROXY);
		  proxy[MAX_PROXY]='\0';
		}
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
	  else if(strncasecmp(start,"follow-redirects",16)==0)
	    {
	      if(no)
		follow_redirects=0;
	      else if(start[16]=='=')
		follow_redirects=atoi(&start[17]);
	      else if(start[16]=='\0')
		follow_redirects=-1;
	    }

	  continue;
	}
    }

  if(scheme[0]=='\0')
    {
      fprintf(console,"gpgkeys: no scheme supplied!\n");
      return KEYSERVER_SCHEME_NOT_FOUND;
    }
#ifndef HTTP_VIA_LIBCURL
  else if(strcasecmp(scheme,"http")==0)
    {
      fprintf(console,"gpgkeys: scheme `%s' not supported\n",scheme);
      return KEYSERVER_SCHEME_NOT_FOUND;
    }
#endif /* HTTP_VIA_LIBCURL */
#ifndef FTP_VIA_LIBCURL
  else if(strcasecmp(scheme,"ftp")==0)
    {
      fprintf(console,"gpgkeys: scheme `%s' not supported\n",scheme);
      return KEYSERVER_SCHEME_NOT_FOUND;
    }
#endif /* FTP_VIA_LIBCURL */

  if(timeout && register_timeout()==-1)
    {
      fprintf(console,"gpgkeys: unable to register timeout handler\n");
      return KEYSERVER_INTERNAL_ERROR;
    }

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl=curl_easy_init();
  if(!curl)
    {
      fprintf(console,"gpgkeys: unable to initialize curl\n");
      ret=KEYSERVER_INTERNAL_ERROR;
      goto fail;
    }

  if(follow_redirects)
    {
      curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1);
      if(follow_redirects>0)
	curl_easy_setopt(curl,CURLOPT_MAXREDIRS,follow_redirects);
    }

  if(proxy[0])
    curl_easy_setopt(curl,CURLOPT_PROXY,proxy);

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

  if(verbose)
    {
      fprintf(console,"Scheme:\t\t%s\n",scheme);
      fprintf(console,"Host:\t\t%s\n",host);
      if(port[0])
	fprintf(console,"Port:\t\t%s\n",port);
      if(path[0])
	fprintf(console,"Path:\t\t%s\n",path);
      fprintf(console,"Command:\tGET\n");
    }

  set_timeout(timeout);

  ret=get_key(thekey);

  curl_easy_cleanup(curl);

 fail:

  free(thekey);

  if(input!=stdin)
    fclose(input);

  if(output!=stdout)
    fclose(output);

  curl_global_cleanup();

  return ret;
}
