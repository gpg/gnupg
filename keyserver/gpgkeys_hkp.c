/* gpgkeys_hkp.c - talk to an HKP keyserver
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
 *               2009 Free Software Foundation, Inc.
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
#include "util.h"
#ifdef USE_DNS_SRV
#include "srv.h"
#endif
#include "keyserver.h"
#include "ksutil.h"

extern char *optarg;
extern int optind;

static FILE *input,*output,*console;
static CURL *curl;
static struct ks_options *opt;
static char errorbuffer[CURL_ERROR_SIZE];
static char *proto,*port;

static size_t
curl_mrindex_writer(const void *ptr,size_t size,size_t nmemb,void *stream)
{
  static int checked=0,swallow=0;

  if(!checked)
    {
      /* If the document begins with a '<', assume it's a HTML
	 response, which we don't support.  Discard the whole message
	 body.  GPG can handle it, but this is an optimization to deal
	 with it on this side of the pipe.  */
      const char *buf=ptr;
      if(buf[0]=='<')
	swallow=1;

      checked=1;
    }

  if(swallow || fwrite(ptr,size,nmemb,stream)==nmemb)
    return size*nmemb;
  else
    return 0;
}

/* Append but avoid creating a double slash // in the path. */
static char *
append_path(char *dest,const char *src)
{
  size_t n=strlen(dest);

  if(src[0]=='/' && n>0 && dest[n-1]=='/')
    dest[n-1]='\0';

  return strcat(dest,src);
}

/* Return a pointer into STRING so that appending PATH to STRING will
   not yield a duplicated slash. */
static const char *
appendable_path (const char *string, const char *path)
{
  size_t n;

  if (path[0] == '/' && (n=strlen (string)) && string[n-1] == '/')
    return path+1;
  else
    return path;
}


int
send_key(int *r_eof)
{
  CURLcode res;
  char request[MAX_URL+15];
  int begin=0,end=0,ret=KEYSERVER_INTERNAL_ERROR;
  char keyid[17],state[6];
  char line[MAX_LINE];
  char *key=NULL,*encoded_key=NULL;
  size_t keylen=0,keymax=0;

  /* Read and throw away input until we see the BEGIN */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"KEY%*[ ]%16s%*[ ]%5s\n",keyid,state)==2
       && strcmp(state,"BEGIN")==0)
      {
	begin=1;
	break;
      }

  if(!begin)
    {
      /* i.e. eof before the KEY BEGIN was found.  This isn't an
	 error. */
      *r_eof=1;
      ret=KEYSERVER_OK;
      goto fail;
    }

  /* Now slurp up everything until we see the END */

  while(fgets(line,MAX_LINE,input))
    if(sscanf(line,"KEY%*[ ]%16s%*[ ]%3s\n",keyid,state)==2
       && strcmp(state,"END")==0)
      {
	end=1;
	break;
      }
    else
      {
	if(strlen(line)+keylen>keymax)
	  {
	    char *tmp;

	    keymax+=200;
	    tmp=realloc(key,keymax+1);
	    if(!tmp)
	      {
		free(key);
		fprintf(console,"gpgkeys: out of memory\n");
		ret=KEYSERVER_NO_MEMORY;
		goto fail;
	      }

	    key=tmp;
	  }

	strcpy(&key[keylen],line);
	keylen+=strlen(line);
      }

  if(!end)
    {
      fprintf(console,"gpgkeys: no KEY %s END found\n",keyid);
      *r_eof=1;
      ret=KEYSERVER_KEY_INCOMPLETE;
      goto fail;
    }

  encoded_key=curl_escape(key,keylen);
  if(!encoded_key)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  free(key);

  key = strconcat ("keytext=", encoded_key, NULL);
  if(!key)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  strcpy(request,proto);
  strcat(request,"://");
  strcat(request,opt->host);
  strcat(request,":");
  strcat(request,port);
  strcat(request,opt->path);
  /* request is MAX_URL+15 bytes long - MAX_URL covers the whole URL,
     including any supplied path.  The 15 covers /pks/add. */
  append_path(request,"/pks/add");

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  curl_easy_setopt(curl,CURLOPT_URL,request);
  curl_easy_setopt(curl,CURLOPT_POST,1L);
  curl_easy_setopt(curl,CURLOPT_POSTFIELDS,key);
  curl_easy_setopt(curl,CURLOPT_FAILONERROR,1L);

  res=curl_easy_perform(curl);
  if(res!=0)
    {
      fprintf(console,"gpgkeys: HTTP post error %d: %s\n",res,errorbuffer);
      ret=curl_err_to_gpg_err(res);
      goto fail;
    }
  else
    fprintf(output,"\nKEY %s SENT\n",keyid);

  ret=KEYSERVER_OK;

 fail:
  xfree (key);
  curl_free(encoded_key);

  if(ret!=0 && begin)
    fprintf(output,"KEY %s FAILED %d\n",keyid,ret);

  return ret;
}

static int
get_key(char *getkey)
{
  CURLcode res;
  char request[MAX_URL+92];
  char *offset;
  struct curl_writer_ctx ctx;
  size_t keylen;

  memset(&ctx,0,sizeof(ctx));

  /* Build the search string.  HKP only uses the short key IDs. */

  if(strncmp(getkey,"0x",2)==0)
    getkey+=2;

  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  if(strlen(getkey)==32)
    {
      fprintf(console,
	      "gpgkeys: HKP keyservers do not support v3 fingerprints\n");
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,KEYSERVER_NOT_SUPPORTED);
      return KEYSERVER_NOT_SUPPORTED;
    }

  strcpy(request,proto);
  strcat(request,"://");
  strcat(request,opt->host);
  strcat(request,":");
  strcat(request,port);
  strcat(request,opt->path);
  /* request is MAX_URL+55 bytes long - MAX_URL covers the whole URL,
     including any supplied path.  The 92 overcovers this /pks/... etc
     string plus the 8, 16, or 40 bytes of key id/fingerprint */
  append_path(request,"/pks/lookup?op=get&options=mr&search=0x");

  /* send only fingerprint, long key id, or short keyid.  see:
     https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.1.1.1 */
  keylen = strlen(getkey);
  if(keylen >= 40)
    offset=&getkey[keylen-40];
  else if(keylen >= 16)
    offset=&getkey[keylen-16];
  else if(keylen >= 8)
    offset=&getkey[keylen-8];
  else
    offset=getkey;

  strcat(request,offset);

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  curl_easy_setopt(curl,CURLOPT_URL,request);
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_writer);
  ctx.stream=output;
  curl_easy_setopt(curl,CURLOPT_FILE,&ctx);

  res=curl_easy_perform(curl);
  if(res!=CURLE_OK)
    {
      fprintf(console,"gpgkeys: HTTP fetch error %d: %s\n",res,errorbuffer);
      fprintf(output,"\nKEY 0x%s FAILED %d\n",getkey,curl_err_to_gpg_err(res));
    }
  else
    {
      curl_writer_finalize(&ctx);
      if(!ctx.flags.done)
	{
	  fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
	  fprintf(output,"\nKEY 0x%s FAILED %d\n",
		  getkey,KEYSERVER_KEY_NOT_FOUND);
	}
      else
	fprintf(output,"\nKEY 0x%s END\n",getkey);
    }

  return KEYSERVER_OK;
}

static int
get_name(const char *getkey)
{
  CURLcode res;
  char *request=NULL;
  char *searchkey_encoded;
  int ret=KEYSERVER_INTERNAL_ERROR;
  struct curl_writer_ctx ctx;

  memset(&ctx,0,sizeof(ctx));

  searchkey_encoded=curl_escape((char *)getkey,0);
  if(!searchkey_encoded)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  request = strconcat
    (proto,
     "://",
     opt->host,
     ":",
     port,
     opt->path,
     appendable_path (opt->path,"/pks/lookup?op=get&options=mr&search="),
     searchkey_encoded,
     opt->action == KS_GETNAME? "&exact=on":"",
     NULL);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }
  
  fprintf(output,"NAME %s BEGIN\n",getkey);

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  curl_easy_setopt(curl,CURLOPT_URL,request);
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_writer);
  ctx.stream=output;
  curl_easy_setopt(curl,CURLOPT_FILE,&ctx);

  res=curl_easy_perform(curl);
  if(res!=CURLE_OK)
    {
      fprintf(console,"gpgkeys: HTTP fetch error %d: %s\n",res,errorbuffer);
      ret=curl_err_to_gpg_err(res);
    }
  else
    {
      curl_writer_finalize(&ctx);
      if(!ctx.flags.done)
	{
	  fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
	  ret=KEYSERVER_KEY_NOT_FOUND;
	}
      else
	{
	  fprintf(output,"\nNAME %s END\n",getkey);
	  ret=KEYSERVER_OK;
	}
    }

 fail:
  curl_free(searchkey_encoded);
  xfree (request);

  if(ret!=KEYSERVER_OK)
    fprintf(output,"\nNAME %s FAILED %d\n",getkey,ret);

  return ret;
}

static int
search_key(const char *searchkey)
{
  CURLcode res;
  char *request=NULL;
  char *searchkey_encoded;
  int ret=KEYSERVER_INTERNAL_ERROR;
  enum ks_search_type search_type;
  const char *hexprefix;

  search_type=classify_ks_search(&searchkey);

  if(opt->debug)
    fprintf(console,"gpgkeys: search type is %d, and key is \"%s\"\n",
	    search_type,searchkey);

  searchkey_encoded=curl_escape((char *)searchkey,0);
  if(!searchkey_encoded)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  /* HKP keyservers like the 0x to be present when searching by
     keyid.  */
  hexprefix = (search_type==KS_SEARCH_KEYID_SHORT
               || search_type==KS_SEARCH_KEYID_LONG)? "0x":"";

  request = strconcat
    (proto,
     "://",
     opt->host,
     ":",
     port,
     opt->path,
     appendable_path (opt->path, "/pks/lookup?op=index&options=mr&search="),
     hexprefix,
     searchkey_encoded,
     opt->action == KS_GETNAME? "&exact=on":"",
     NULL);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  fprintf(output,"SEARCH %s BEGIN\n",searchkey);

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  curl_easy_setopt(curl,CURLOPT_URL,request);
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_mrindex_writer);
  curl_easy_setopt(curl,CURLOPT_FILE,output);

  res=curl_easy_perform(curl);
  if(res!=0)
    {
      fprintf(console,"gpgkeys: HTTP search error %d: %s\n",res,errorbuffer);
      ret=curl_err_to_gpg_err(res);
    }
  else
    {
      fprintf(output,"\nSEARCH %s END\n",searchkey);
      ret=KEYSERVER_OK;
    }

 fail:
  curl_free(searchkey_encoded);
  xfree (request);

  if(ret!=KEYSERVER_OK)
    fprintf(output,"\nSEARCH %s FAILED %d\n",searchkey,ret);

  return ret;
}

void
fail_all(struct keylist *keylist,int err)
{
  if(!keylist)
    return;

  if(opt->action==KS_SEARCH)
    {
      fprintf(output,"SEARCH ");
      while(keylist)
	{
	  fprintf(output,"%s ",keylist->str);
	  keylist=keylist->next;
	}
      fprintf(output,"FAILED %d\n",err);
    }
  else
    while(keylist)
      {
	fprintf(output,"KEY %s FAILED %d\n",keylist->str,err);
	keylist=keylist->next;
      }
}

#ifdef HAVE_LIBCURL
/* If there is a SRV record, take the highest ranked possibility.
   This is a hack, as we don't proceed downwards. */
static void
srv_replace(const char *srvtag)
{
#ifdef USE_DNS_SRV
  struct srventry *srvlist=NULL;
  int srvcount;

  if(!srvtag)
    return;

  if(1+strlen(srvtag)+6+strlen(opt->host)+1<=MAXDNAME)
    {
      char srvname[MAXDNAME];

      strcpy(srvname,"_");
      strcat(srvname,srvtag);
      strcat(srvname,"._tcp.");
      strcat(srvname,opt->host);
      srvcount=getsrv(srvname,&srvlist);
    }

  if(srvlist)
    {
      char *newname,*newport;

      newname=strdup(srvlist->target);
      newport=malloc(MAX_PORT);
      if(newname && newport)
	{
	  free(opt->host);
	  free(opt->port);
	  opt->host=newname;
	  snprintf(newport,MAX_PORT,"%u",srvlist->port);
	  opt->port=newport;
	}
      else
	{
	  free(newname);
	  free(newport);
	}
    }
#endif
}
#endif

static void 
show_help (FILE *fp)
{
  fprintf (fp,"-h, --help\thelp\n");
  fprintf (fp,"-V\t\tmachine readable version\n");
  fprintf (fp,"--version\thuman readable version\n");
  fprintf (fp,"-o\t\toutput to this file\n");
}

int
main(int argc,char *argv[])
{
  int arg,ret=KEYSERVER_INTERNAL_ERROR,try_srv=1;
  char line[MAX_LINE];
  int failed=0;
  struct keylist *keylist=NULL,*keyptr=NULL;
  char *proxy=NULL;
  struct curl_slist *headers=NULL;

  console=stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      printf ("gpgkeys_hkp (GnuPG) %s\n", VERSION);
      printf ("Uses: %s\n", curl_version());
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

	  if(strncasecmp(option,"no-",3)==0)
	    {
	      no=1;
	      start=&option[3];
	    }

	  if(strncasecmp(start,"http-proxy",10)==0)
	    {
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
	  else if(strcasecmp(start,"try-dns-srv")==0)
	    {
	      if(no)
		try_srv=0;
	      else
		try_srv=1;
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

  if(ks_strcasecmp(opt->scheme,"hkps")==0)
    {
      proto="https";
      port="443";
    }
  else
    {
      proto="http";
      port="11371";
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

  /* If the user gives a :port, then disable SRV.  The semantics of a
     specified port and SRV do not play well together. */
  if(opt->port)
    port=opt->port;
  else if(try_srv)
    {
      char *srvtag;

      if(ks_strcasecmp(opt->scheme,"hkp")==0)
	srvtag="pgpkey-http";
      else if(ks_strcasecmp(opt->scheme,"hkps")==0)
	srvtag="pgpkey-https";
      else
	srvtag=NULL;

#ifdef HAVE_LIBCURL
      /* We're using libcurl, so fake SRV support via our wrapper.
	 This isn't as good as true SRV support, as we do not try all
	 possible targets at one particular level and work our way
	 down the list, but it's better than nothing. */      
      srv_replace(srvtag);
#else
      /* We're using our internal curl shim, so we can use its (true)
	 SRV support.  Obviously, CURLOPT_SRVTAG_GPG_HACK isn't a real
	 libcurl option.  It's specific to our shim. */
      curl_easy_setopt(curl,CURLOPT_SRVTAG_GPG_HACK,srvtag);
#endif
    }

  curl_easy_setopt(curl,CURLOPT_ERRORBUFFER,errorbuffer);

  if(opt->auth)
    curl_easy_setopt(curl,CURLOPT_USERPWD,opt->auth);

  if(opt->debug)
    {
      fprintf(console,"gpgkeys: curl version = %s\n",curl_version());
      curl_easy_setopt(curl,CURLOPT_STDERR,console);
      curl_easy_setopt(curl,CURLOPT_VERBOSE,1L);
    }

  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,(long)opt->flags.check_cert);
  curl_easy_setopt(curl,CURLOPT_CAINFO,opt->ca_cert_file);

  /* Avoid caches to get the most recent copy of the key.  This is bug
     #1061.  In pre-curl versions of the code, we didn't do it.  Then
     we did do it (as a curl default) until curl changed the default.
     Now we're doing it again, but in such a way that changing
     defaults in the future won't impact us.  We set both the Pragma
     and Cache-Control versions of the header, so we're good with both
     HTTP 1.0 and 1.1. */
  headers=curl_slist_append(headers,"Pragma: no-cache");
  if(headers)
    headers=curl_slist_append(headers,"Cache-Control: no-cache");

  if(!headers)
    {
      fprintf(console,"gpgkeys: out of memory when building HTTP headers\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);

  if(proxy)
    curl_easy_setopt(curl,CURLOPT_PROXY,proxy);

  /* If it's a GET or a SEARCH, the next thing to come in is the
     keyids.  If it's a SEND, then there are no keyids. */

  if(opt->action==KS_SEND)
    while(fgets(line,MAX_LINE,input)!=NULL && line[0]!='\n');
  else if(opt->action==KS_GET
	  || opt->action==KS_GETNAME || opt->action==KS_SEARCH)
    {
      for(;;)
	{
	  struct keylist *work;

	  if(fgets(line,MAX_LINE,input)==NULL)
	    break;
	  else
	    {
	      if(line[0]=='\n' || line[0]=='\0')
		break;

	      work=malloc(sizeof(struct keylist));
	      if(work==NULL)
		{
		  fprintf(console,"gpgkeys: out of memory while "
			  "building key list\n");
		  ret=KEYSERVER_NO_MEMORY;
		  goto fail;
		}

	      strcpy(work->str,line);

	      /* Trim the trailing \n */
	      work->str[strlen(line)-1]='\0';

	      work->next=NULL;

	      /* Always attach at the end to keep the list in proper
                 order for searching */
	      if(keylist==NULL)
		keylist=work;
	      else
		keyptr->next=work;

	      keyptr=work;
	    }
	}
    }
  else
    {
      fprintf(console,"gpgkeys: no keyserver command specified\n");
      goto fail;
    }

  /* Send the response */

  fprintf(output,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(output,"PROGRAM %s\n\n",VERSION);

  if(opt->verbose>1)
    {
      fprintf(console,"Host:\t\t%s\n",opt->host);
      if(opt->port)
	fprintf(console,"Port:\t\t%s\n",opt->port);
      if(strcmp(opt->path,"/")!=0)
	fprintf(console,"Path:\t\t%s\n",opt->path);
      fprintf(console,"Command:\t%s\n",ks_action_to_string(opt->action));
    }

  if(opt->action==KS_GET)
    {
      keyptr=keylist;

      while(keyptr!=NULL)
	{
	  set_timeout(opt->timeout);

	  if(get_key(keyptr->str)!=KEYSERVER_OK)
	    failed++;

	  keyptr=keyptr->next;
	}
    }
  else if(opt->action==KS_GETNAME)
    {
      keyptr=keylist;

      while(keyptr!=NULL)
	{
	  set_timeout(opt->timeout);

	  if(get_name(keyptr->str)!=KEYSERVER_OK)
	    failed++;

	  keyptr=keyptr->next;
	}
    }
  else if(opt->action==KS_SEND)
    {
      int myeof=0;

      do
	{
	  set_timeout(opt->timeout);

	  if(send_key(&myeof)!=KEYSERVER_OK)
	    failed++;
	}
      while(!myeof);
    }
  else if(opt->action==KS_SEARCH)
    {
      char *searchkey=NULL;
      int len=0;

      set_timeout(opt->timeout);

      /* To search, we stick a space in between each key to search
	 for. */

      keyptr=keylist;
      while(keyptr!=NULL)
	{
	  len+=strlen(keyptr->str)+1;
	  keyptr=keyptr->next;
	}

      searchkey=malloc(len+1);
      if(searchkey==NULL)
	{
	  ret=KEYSERVER_NO_MEMORY;
	  fail_all(keylist,KEYSERVER_NO_MEMORY);
	  goto fail;
	}

      searchkey[0]='\0';

      keyptr=keylist;
      while(keyptr!=NULL)
	{
	  strcat(searchkey,keyptr->str);
	  strcat(searchkey," ");
	  keyptr=keyptr->next;
	}

      /* Nail that last space */
      if(*searchkey)
	searchkey[strlen(searchkey)-1]='\0';

      if(search_key(searchkey)!=KEYSERVER_OK)
	failed++;

      free(searchkey);
    }
  else
    abort();

  if(!failed)
    ret=KEYSERVER_OK;

 fail:
  while(keylist!=NULL)
    {
      struct keylist *current=keylist;
      keylist=keylist->next;
      free(current);
    }

  if(input!=stdin)
    fclose(input);

  if(output!=stdout)
    fclose(output);

  free_ks_options(opt);

  curl_slist_free_all(headers);

  if(curl)
    curl_easy_cleanup(curl);

  free(proxy);

  return ret;
}
