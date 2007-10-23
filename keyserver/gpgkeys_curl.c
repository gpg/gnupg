/* gpgkeys_curl.c - fetch a key via libcurl
 * Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation, Inc.
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
 *
 * In addition, as a special exception, the Free Software Foundation
 * gives permission to link the code of the keyserver helper tools:
 * gpgkeys_ldap, gpgkeys_curl and gpgkeys_hkp with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables.  You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".  If
 * you modify this file, you may extend this exception to your version
 * of the file, but you are not obligated to do so.  If you do not
 * wish to do so, delete this exception statement from your version.
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
#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#else
#include "curl-shim.h"
#endif
#include "compat.h"
#include "keyserver.h"
#include "ksutil.h"

extern char *optarg;
extern int optind;

static FILE *input,*output,*console;
static CURL *curl;
static struct ks_options *opt;

static int
get_key(char *getkey)
{
  CURLcode res;
  char errorbuffer[CURL_ERROR_SIZE];
  char request[MAX_URL];
  struct curl_writer_ctx ctx;

  memset(&ctx,0,sizeof(ctx));

  if(strncmp(getkey,"0x",2)==0)
    getkey+=2;

  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  sprintf(request,"%s://%s%s%s%s",opt->scheme,opt->host,
	  opt->port?":":"",opt->port?opt->port:"",opt->path?opt->path:"/");

  curl_easy_setopt(curl,CURLOPT_URL,request);
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_writer);
  ctx.stream=output;
  curl_easy_setopt(curl,CURLOPT_FILE,&ctx);
  curl_easy_setopt(curl,CURLOPT_ERRORBUFFER,errorbuffer);

  res=curl_easy_perform(curl);
  if(res!=CURLE_OK)
    {
      fprintf(console,"gpgkeys: %s fetch error %d: %s\n",opt->scheme,
	      res,errorbuffer);
      fprintf(output,"\nKEY 0x%s FAILED %d\n",getkey,curl_err_to_gpg_err(res));
    }
  else
    {
      curl_writer_finalize(&ctx);
      if(!ctx.flags.done)
	{
	  fprintf(console,"gpgkeys: no key data found for %s\n",request);
	  fprintf(output,"\nKEY 0x%s FAILED %d\n",
		  getkey,KEYSERVER_KEY_NOT_FOUND);
	}
      else
	fprintf(output,"\nKEY 0x%s END\n",getkey);
    }

  return curl_err_to_gpg_err(res);
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
  int arg,ret=KEYSERVER_INTERNAL_ERROR,i;
  char line[MAX_LINE];
  char *thekey=NULL;
  long follow_redirects=5;
  char *proxy=NULL;
  curl_version_info_data *curldata;

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

  opt=init_ks_options();
  if(!opt)
    return KEYSERVER_NO_MEMORY;

  /* Get the command and info block */

  while(fgets(line,MAX_LINE,input)!=NULL)
    {
      int err;
      char option[MAX_OPTION+1];

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

      if(sscanf(line,"OPTION %" MKSTRING(MAX_OPTION) "s\n",option)==1)
	{
	  int no=0;
	  char *start=&option[0];

	  option[MAX_OPTION]='\0';

	  if(ascii_strncasecmp(option,"no-",3)==0)
	    {
	      no=1;
	      start=&option[3];
	    }

	  if(ascii_strncasecmp(start,"http-proxy",10)==0)
	    {
	      /* Safe to not check the return code of strdup() here.
		 If it fails, we simply won't use a proxy. */
	      if(no)
		{
		  free(proxy);
		  proxy=strdup("");
		}
	      else if(start[10]=='=')
		{
		  if(strlen(&start[11])<MAX_PROXY)
		    {
		      free(proxy);
		      proxy=strdup(&start[11]);
		    }
		}
	    }
	  else if(ascii_strncasecmp(start,"follow-redirects",16)==0)
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

  if(!opt->scheme)
    {
      fprintf(console,"gpgkeys: no scheme supplied!\n");
      ret=KEYSERVER_SCHEME_NOT_FOUND;
      goto fail;
    }

  if(!opt->host)
    {
      fprintf(console,"gpgkeys: no keyserver host provided\n");
      goto fail;
    }

  if(opt->timeout && register_timeout()==-1)
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

  /* Make sure we have the protocol the user is asking for so we can
     print a nicer error message. */
  curldata=curl_version_info(CURLVERSION_NOW);
  for(i=0;curldata->protocols[i];i++)
    if(ascii_strcasecmp(curldata->protocols[i],opt->scheme)==0)
      break;

  if(curldata->protocols[i]==NULL)
    {
      fprintf(console,"gpgkeys: protocol `%s' not supported\n",opt->scheme);
      ret=KEYSERVER_SCHEME_NOT_FOUND;
      goto fail;
    }

  if(follow_redirects)
    {
      curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1);
      if(follow_redirects>0)
	curl_easy_setopt(curl,CURLOPT_MAXREDIRS,follow_redirects);
    }

  if(opt->auth)
    curl_easy_setopt(curl,CURLOPT_USERPWD,opt->auth);

  if(opt->debug)
    {
      fprintf(console,"gpgkeys: curl version = %s\n",curl_version());
      curl_easy_setopt(curl,CURLOPT_STDERR,console);
      curl_easy_setopt(curl,CURLOPT_VERBOSE,1);
    }

  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,opt->flags.check_cert);
  curl_easy_setopt(curl,CURLOPT_CAINFO,opt->ca_cert_file);

  if(proxy)
    curl_easy_setopt(curl,CURLOPT_PROXY,proxy);

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

  if(!thekey)
    {
      fprintf(console,"gpgkeys: invalid keyserver instructions\n");
      goto fail;
    }

  /* Send the response */

  fprintf(output,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(output,"PROGRAM %s\n\n",VERSION);

  if(opt->verbose)
    {
      fprintf(console,"Scheme:\t\t%s\n",opt->scheme);
      fprintf(console,"Host:\t\t%s\n",opt->host);
      if(opt->port)
	fprintf(console,"Port:\t\t%s\n",opt->port);
      if(opt->path)
	fprintf(console,"Path:\t\t%s\n",opt->path);
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

  if(curl)
    curl_easy_cleanup(curl);

  free(proxy);

  curl_global_cleanup();

  return ret;
}
