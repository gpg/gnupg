/* curl-shim.c - Implement a small subset of the curl API in terms of
 * the iobuf HTTP API
 *
 * Copyright (C) 2005 Free Software Foundation, Inc.
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "http.h"
#include "util.h"
#include "curl-shim.h"

static CURLcode handle_error(CURL *curl,CURLcode err,const char *str)
{
  if(curl->errorbuffer)
    {
      switch(err)
	{
	case CURLE_OK:
	  strcpy(curl->errorbuffer,"okay");
	  break;

	case CURLE_COULDNT_CONNECT:
	  strcpy(curl->errorbuffer,"couldn't connect");
	  break;

	case CURLE_WRITE_ERROR:
	  strcpy(curl->errorbuffer,"write error");
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

CURLcode curl_global_init(long flags)
{
  return CURLE_OK;
}

void curl_global_cleanup(void) {}

CURL *curl_easy_init(void)
{
  return calloc(1,sizeof(CURL));
}

void curl_easy_cleanup(CURL *curl)
{
  free(curl);
}

CURLcode curl_easy_setopt(CURL *curl,CURLoption option,...)
{
  va_list ap;

  va_start(ap,option);

  switch(option)
    {
    case CURLOPT_URL:
      curl->url=va_arg(ap,char *);
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
    default:
      /* We ignore the huge majority of curl options */
      break;
    }

  return handle_error(curl,CURLE_OK,NULL);
}

CURLcode curl_easy_perform(CURL *curl)
{
  int rc;
  CURLcode err=CURLE_OK;
  const char *errstr=NULL;

  rc=http_open_document(&curl->hd,curl->url,0,curl->proxy);
  if(rc!=0)
    {
      if(rc==G10ERR_NETWORK)
	errstr=strerror(errno);
      else
	errstr=g10_errstr(rc);

      err=CURLE_COULDNT_CONNECT;
    }
  else
    {
      size_t maxlen=1024,buflen,len;
      byte *line=NULL;

      while((len=iobuf_read_line(curl->hd.fp_read,&line,&buflen,&maxlen)))
	{
	  maxlen=1024;
	  size_t ret;

	  ret=(curl->writer)(line,len,1,curl->file);
	  if(ret!=len)
	    {
	      err=CURLE_WRITE_ERROR;
	      break;
	    }
	}

      m_free(line);
      http_close(&curl->hd);
    }

  return handle_error(curl,err,errstr);
}
