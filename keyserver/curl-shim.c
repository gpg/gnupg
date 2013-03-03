/* curl-shim.c - Implement a small subset of the curl API in terms of
 * the iobuf HTTP API
 *
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2012,
 *               2013 Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "util.h"
#include "http.h"
#include "ksutil.h"
#include "curl-shim.h"

static CURLcode
handle_error(CURL *curl,CURLcode err,const char *str)
{
  if(curl->errorbuffer)
    {
      /* Make sure you never exceed CURL_ERROR_SIZE, currently set to
	 256 in curl-shim.h */
      switch(err)
	{
	case CURLE_OK:
	  strcpy(curl->errorbuffer,"okay");
	  break;

	case CURLE_UNSUPPORTED_PROTOCOL:
	  strcpy(curl->errorbuffer,"unsupported protocol");
	  break;

	case CURLE_COULDNT_CONNECT:
	  strcpy(curl->errorbuffer,"couldn't connect");
	  break;

	case CURLE_WRITE_ERROR:
	  strcpy(curl->errorbuffer,"write error");
	  break;

	case CURLE_HTTP_RETURNED_ERROR:
	  sprintf(curl->errorbuffer,"url returned error %u",curl->status);
	  break;

	default:
	  strcpy(curl->errorbuffer,"generic error");
	  break;
	}

      if(str && (strlen(curl->errorbuffer)+2+strlen(str)+1)<=CURL_ERROR_SIZE)
	{
	  strcat(curl->errorbuffer,": ");
	  strcat(curl->errorbuffer,str);
	}
    }

  return err;
}

CURLcode
curl_global_init(long flags)
{
  (void)flags;
  return CURLE_OK;
}

void
curl_global_cleanup(void) {}

CURL *
curl_easy_init(void)
{
  CURL *handle;

#ifdef HAVE_W32_SYSTEM
  w32_init_sockets ();
#endif

  handle=calloc(1,sizeof(CURL));
  if(handle)
    handle->errors=stderr;

  return handle;
}

void
curl_easy_cleanup(CURL *curl)
{
  if (curl)
    {
      http_close (curl->hd, 0);
      free(curl);
    }
}

CURLcode
curl_easy_setopt(CURL *curl,CURLoption option,...)
{
  va_list ap;

  va_start(ap,option);

  switch(option)
    {
    case CURLOPT_URL:
      curl->url=va_arg(ap,char *);
      break;
    case CURLOPT_USERPWD:
      curl->auth=va_arg(ap,char *);
      break;
    case CURLOPT_WRITEFUNCTION:
      curl->writer=va_arg(ap,write_func);
      break;
    case CURLOPT_FILE:
      curl->file=va_arg(ap,void *);
      break;
    case CURLOPT_ERRORBUFFER:
      curl->errorbuffer=va_arg(ap,char *);
      break;
    case CURLOPT_PROXY:
      curl->proxy=va_arg(ap,char *);
      break;
    case CURLOPT_POST:
      curl->flags.post=va_arg(ap,long)?1:0;
      break;
    case CURLOPT_POSTFIELDS:
      curl->postfields=va_arg(ap,char *);
      break;
    case CURLOPT_SRVTAG_GPG_HACK:
      curl->srvtag=va_arg(ap,char *);
      break;
    case CURLOPT_FAILONERROR:
      curl->flags.failonerror=va_arg(ap,long)?1:0;
      break;
    case CURLOPT_VERBOSE:
      curl->flags.verbose=va_arg(ap,long)?1:0;
      break;
    case CURLOPT_STDERR:
      curl->errors=va_arg(ap,FILE *);
      break;
    case CURLOPT_HTTPHEADER:
      curl->headers=va_arg(ap,struct curl_slist *);
      break;
    default:
      /* We ignore the huge majority of curl options */
      break;
    }

  return handle_error(curl,CURLE_OK,NULL);
}

CURLcode
curl_easy_perform(CURL *curl)
{
  int rc;
  CURLcode err=CURLE_OK;
  const char *errstr=NULL;
  char *proxy=NULL;
  struct http_srv srv;

  memset(&srv,0,sizeof(srv));

  /* Emulate the libcurl proxy behavior.  If the calling program set a
     proxy, use it.  If it didn't set a proxy or set it to NULL, check
     for one in the environment.  If the calling program explicitly
     set a null-string proxy the http code doesn't use a proxy at
     all. */

  if(curl->proxy)
    proxy=curl->proxy;
  else
    proxy=getenv(HTTP_PROXY_ENV);

  if(curl->srvtag)
    srv.srvtag=curl->srvtag;

  if(curl->flags.verbose)
    {
      fprintf(curl->errors,"* HTTP proxy is \"%s\"\n",proxy?proxy:"null");
      fprintf(curl->errors,"* HTTP URL is \"%s\"\n",curl->url);
      if(srv.srvtag)
	fprintf(curl->errors,
		"* SRV tag is \"%s\": host and port may be overridden\n",
		srv.srvtag);
      fprintf(curl->errors,"* HTTP auth is \"%s\"\n",
	      curl->auth?curl->auth:"null");
      fprintf(curl->errors,"* HTTP method is %s\n",
	      curl->flags.post?"POST":"GET");
    }

  if(curl->flags.post)
    {
      rc = http_open (&curl->hd, HTTP_REQ_POST, curl->url, curl->auth,
                      0, proxy, NULL, &srv,
		      curl->headers?curl->headers->list:NULL);
      if (!rc)
	{
	  unsigned int post_len = strlen(curl->postfields);

	  if(curl->flags.verbose && srv.used_server && srv.used_port)
	    fprintf (curl->errors, "* HTTP host:port post-SRV is \"%s:%hu\"\n",
		     srv.used_server, srv.used_port);

	  es_fprintf (http_get_write_ptr (curl->hd),
                      "Content-Type: application/x-www-form-urlencoded\r\n"
                      "Content-Length: %u\r\n", post_len);
	  http_start_data (curl->hd);
	  es_write (http_get_write_ptr (curl->hd),
                    curl->postfields, post_len, NULL);

	  rc = http_wait_response (curl->hd);
          curl->status = http_get_status_code (curl->hd);
	  if (!rc && curl->flags.failonerror && curl->status>=300)
	    err = CURLE_HTTP_RETURNED_ERROR;
          http_close (curl->hd, 0);
          curl->hd = NULL;
	}
    }
  else
    {
      rc = http_open (&curl->hd, HTTP_REQ_GET, curl->url, curl->auth,
                      0, proxy, NULL, &srv,
		      curl->headers?curl->headers->list:NULL);
      if (!rc)
	{
	  if(curl->flags.verbose && srv.used_server && srv.used_port)
	    fprintf (curl->errors, "* HTTP host:port post-SRV is \"%s:%hu\"\n",
		     srv.used_server, srv.used_port);

	  rc = http_wait_response (curl->hd);
          curl->status = http_get_status_code (curl->hd);
	  if (!rc)
	    {
	      if (curl->flags.failonerror && curl->status>=300)
		err = CURLE_HTTP_RETURNED_ERROR;
	      else
		{
		  size_t maxlen = 1024;
                  size_t buflen;
                  unsigned int len;
		  char *line = NULL;

		  while ((len = es_read_line (http_get_read_ptr (curl->hd),
                                              &line, &buflen, &maxlen)))
		    {
		      size_t ret;

		      maxlen=1024;

		      ret=(curl->writer)(line,len,1,curl->file);
		      if(ret!=len)
			{
			  err=CURLE_WRITE_ERROR;
			  break;
			}
		    }

		  es_free (line);
		  http_close(curl->hd, 0);
                  curl->hd = NULL;
		}
	    }
	  else
            {
              http_close (curl->hd, 0);
              curl->hd = NULL;
            }
	}
    }

  xfree(srv.used_server);

  switch(gpg_err_code (rc))
    {
    case 0:
      break;

    case GPG_ERR_INV_URI:
      err=CURLE_UNSUPPORTED_PROTOCOL;
      break;

    default:
      errstr=gpg_strerror (rc);
      err=CURLE_COULDNT_CONNECT;
      break;
    }
      
  return handle_error(curl,err,errstr);
}

CURLcode
curl_easy_getinfo(CURL *curl, CURLINFO info, ... )
{
  va_list ap;
  long *var;

  va_start(ap,info);

  switch(info)
    {
    case CURLINFO_RESPONSE_CODE:
      var=va_arg(ap,long *);
      *var=curl->status;
      break;
    default:
      break;
    }

  return handle_error(curl,CURLE_OK,NULL);
}

/* This is not the same exact set that is allowed according to
   RFC-2396, but it is what the real curl uses. */
#define VALID_URI_CHARS "abcdefghijklmnopqrstuvwxyz" \
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                        "0123456789"

char *
curl_escape(char *str,int length)
{
  int len,max,idx,enc_idx=0;
  char *enc;

  if(length)
    len=length;
  else
    len=strlen(str);

  enc=malloc(len+1);
  if(!enc)
    return enc;

  max=len;

  for(idx=0;idx<len;idx++)
    {
      if(enc_idx+3>max)
	{
	  char *tmp;

	  max+=100;

	  tmp=realloc(enc,max+1);
	  if(!tmp)
	    {
	      free(enc);
	      return NULL;
	    }

	  enc=tmp;
	}

      if(strchr(VALID_URI_CHARS,str[idx]))
	enc[enc_idx++]=str[idx];
      else
	{
	  char numbuf[5];
	  sprintf(numbuf,"%%%02X",str[idx]);
	  strcpy(&enc[enc_idx],numbuf);
	  enc_idx+=3;
	}
    }

  enc[enc_idx]='\0';

  return enc;
}

curl_version_info_data *
curl_version_info(int type)
{
  static curl_version_info_data data;
  static const char *protocols[]={"http",NULL};

  (void)type;

  data.protocols=protocols;

  return &data;
}

struct curl_slist *
curl_slist_append(struct curl_slist *list,const char *string)
{
  if(!list)
    {
      list=calloc(1,sizeof(*list));
      if(!list)
	return NULL;
    }

  add_to_strlist(&list->list,string);

  return list;
}

void
curl_slist_free_all(struct curl_slist *list)
{
  if(list)
    {
      free_strlist(list->list);
      free(list);
    }
}
