/* hkp.c  -  Horrowitz Keyserver Protocol
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include "errors.h"
#include "util.h"
#include "ttyio.h"
#include "i18n.h"
#include "options.h"
#include "filter.h"
#include "http.h"
#include "main.h"
#include "keyserver-internal.h"

static int urlencode_filter( void *opaque, int control,
			     IOBUF a, byte *buf, size_t *ret_len);

/****************
 * Try to import the key with KEYID from a keyserver but ask the user
 * before doing so.
 * Returns: 0 the key was successfully imported
 *	    -1 key not found on server or user does not want to
 *	       import the key
 *	    or other error codes.
 */
int
hkp_ask_import( u32 *keyid, void *stats_handle)
{
    struct http_context hd;
    char *request;
    int rc;
    unsigned int hflags = opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY : 0;

    log_info(_("requesting key %08lX from HKP keyserver %s\n"),
	     (ulong)keyid[1],opt.keyserver_host );
    request = m_alloc( strlen( opt.keyserver_host ) + 100 );
    /* hkp does not accept the long keyid - we should really write a
     * nicer one :-)
     * FIXME: request binary mode - need to pass no_armor mode
     * down to the import function.  Marc told that there is such a
     * binary mode ... how?
     */

    if(strcasecmp(opt.keyserver_scheme,"x-broken-hkp")==0)
      hflags |= HTTP_FLAG_NO_SHUTDOWN;

    sprintf(request,"x-hkp://%s%s%s/pks/lookup?op=get&search=0x%08lX",
	    opt.keyserver_host,
	    atoi(opt.keyserver_port)>0?":":"",
	    atoi(opt.keyserver_port)>0?opt.keyserver_port:"",
	    (ulong)keyid[1] );

  if(opt.keyserver_options.verbose>2)
    log_info("request is \"%s\"\n",request);

    rc = http_open_document( &hd, request, hflags );
    if( rc ) {
	log_info(_("can't get key from keyserver: %s\n"),
			rc == G10ERR_NETWORK? strerror(errno)
					    : g10_errstr(rc) );
    }
    else {
      rc = import_keys_stream( hd.fp_read,
			       opt.keyserver_options.fast_import,stats_handle);
	http_close( &hd );
    }

    m_free( request );
    return rc;
}

int
hkp_export( STRLIST users )
{
    int rc;
    armor_filter_context_t afx;
    IOBUF temp = iobuf_temp();
    struct http_context hd;
    char *request;
    unsigned int status;
    unsigned int hflags = opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY : 0;

    iobuf_push_filter( temp, urlencode_filter, NULL );

    memset( &afx, 0, sizeof afx);
    afx.what = 1;
    iobuf_push_filter( temp, armor_filter, &afx );

    rc = export_pubkeys_stream( temp, users, 1 );
    if( rc == -1 ) {
	iobuf_close(temp);
	return 0;
    }

    iobuf_flush_temp( temp );

    request = m_alloc( strlen( opt.keyserver_host ) + 100 );

    if(strcasecmp(opt.keyserver_scheme,"x-broken-hkp")==0)
      hflags |= HTTP_FLAG_NO_SHUTDOWN;

    sprintf( request, "x-hkp://%s%s%s/pks/add",
	     opt.keyserver_host,
	     atoi(opt.keyserver_port)>0?":":"",
	     atoi(opt.keyserver_port)>0?opt.keyserver_port:"");

  if(opt.keyserver_options.verbose>2)
    log_info("request is \"%s\"\n",request);

    rc = http_open( &hd, HTTP_REQ_POST, request , hflags );
    if( rc ) {
	log_error(_("can't connect to `%s': %s\n"),
		   opt.keyserver_host,
			rc == G10ERR_NETWORK? strerror(errno)
					    : g10_errstr(rc) );
	iobuf_close(temp);
	m_free( request );
	return rc;
    }

    sprintf( request, "Content-Length: %u\n",
		      (unsigned)iobuf_get_temp_length(temp) + 9 );
    iobuf_writestr( hd.fp_write, request );
    m_free( request );
    http_start_data( &hd );

    iobuf_writestr( hd.fp_write, "keytext=" );
    iobuf_write( hd.fp_write, iobuf_get_temp_buffer(temp),
			      iobuf_get_temp_length(temp) );
    iobuf_put( hd.fp_write, '\n' );
    iobuf_flush_temp( temp );
    iobuf_close(temp);

    rc = http_wait_response( &hd, &status );
    if( rc ) {
	log_error(_("error sending to `%s': %s\n"),
		   opt.keyserver_host, g10_errstr(rc) );
    }
    else {
      #if 1
	if( opt.verbose ) {
	    int c;
	    while( (c=iobuf_get(hd.fp_read)) != EOF )
              if ( c >= 32 && c < 127 )
		putchar( c );
              else
                putchar ( '?' );
	}
      #endif
	if( (status/100) == 2 )
	    log_info(_("success sending to `%s' (status=%u)\n"),
					opt.keyserver_host, status  );
	else
	    log_error(_("failed sending to `%s': status=%u\n"),
					opt.keyserver_host, status  );
    }
    http_close( &hd );
    return rc;
}

static int
urlencode_filter( void *opaque, int control,
		  IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    int rc=0;

    if( control == IOBUFCTRL_FLUSH ) {
	const byte *p;
	for(p=buf; size; p++, size-- ) {
	    if( isalnum(*p) || *p == '-' )
		iobuf_put( a, *p );
	    else if( *p == ' ' )
		iobuf_put( a, '+' );
	    else {
		char numbuf[5];
		sprintf(numbuf, "%%%02X", *p );
		iobuf_writestr(a, numbuf );
	    }
	}
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "urlencode_filter";
    return rc;
}

/* pub  2048/<a href="/pks/lookup?op=get&search=0x3CB3B415">3CB3B415</a> 1998/04/03 David M. Shaw &lt;<a href="/pks/lookup?op=get&search=0x3CB3B415">dshaw@jabberwocky.com</a>&gt; */

/* Luckily enough, both the HKP server and NAI HKP interface to their
   LDAP server are close enough in output so the same function can
   parse them both. */

static int 
parse_hkp_index(IOBUF buffer,char *line)
{
  static int open=0,revoked=0;
  static char *key;
#ifdef __riscos__
  static char *uid;
#else
  static unsigned char *uid;
#endif
  static u32 bits,createtime;
  int ret=0;

  /* printf("Open %d, LINE: %s\n",open,line); */

  /* For multiple UIDs */
  if(open && uid!=NULL)
    {
      ret=0;

      if(!(revoked && !opt.keyserver_options.include_revoked))
	{
	  char intstr[11];

	  iobuf_writestr(buffer,key);
	  iobuf_writestr(buffer,":");
	  iobuf_writestr(buffer,uid);
	  iobuf_writestr(buffer,":");
	  iobuf_writestr(buffer,revoked?"1:":":");
	  sprintf(intstr,"%u",createtime);
	  iobuf_writestr(buffer,intstr);
	  iobuf_writestr(buffer,"::::");
	  sprintf(intstr,"%u",bits);
	  iobuf_writestr(buffer,intstr);
	  iobuf_writestr(buffer,"\n");

	  ret=1;
	}

      if(strncmp(line,"     ",5)!=0)
	{
	  m_free(key);
	  m_free(uid);
	  uid=NULL;
	  open=0;
	}
    }

  if(strncasecmp(line,"pub  ",5)==0)
    {
      char *tok,*temp;

      open=1;

      line+=4;

      tok=strsep(&line,"/");
      if(tok==NULL)
	return ret;

      bits=atoi(tok);

      tok=strsep(&line,">");
      if(tok==NULL)
	return ret;

      tok=strsep(&line,"<");
      if(tok==NULL)
	return ret;

      key=m_strdup(tok);

      tok=strsep(&line," ");
      if(tok==NULL)
	return ret;

      tok=strsep(&line," ");
      if(tok==NULL)
	return ret;
  
      /* The date parser wants '-' instead of '/', so... */
      temp=tok;
      while(*temp!='\0')
      	{
	  if(*temp=='/')
	    *temp='-';

	  temp++;
	}

      createtime=scan_isodatestr(tok);
    }

  if(open)
    {
      int uidindex=0;

      /* All that's left is the user name.  Strip off anything
	 <between brackets> and de-urlencode it. */

      while(*line==' ' && *line!='\0')
	line++;

      if(strncmp(line,"*** KEY REVOKED ***",19)==0)
	{
	  revoked=1;
	  return ret;
	}

      uid=m_alloc(strlen(line)+1);

      while(*line!='\0')
	{
	  switch(*line)
	    {
	    case '<':
	      while(*line!='>' && *line!='\0')
		line++;

	      if(*line!='\0')
		line++;
	      break;

	    case '&':
	      if((*(line+1)!='\0' && tolower(*(line+1))=='l') &&
		 (*(line+2)!='\0' && tolower(*(line+2))=='t') &&
		 (*(line+3)!='\0' && *(line+3)==';'))
		{
		  uid[uidindex++]='<';
		  line+=4;
		  break;
		}

	      if((*(line+1)!='\0' && tolower(*(line+1))=='g') &&
		 (*(line+2)!='\0' && tolower(*(line+2))=='t') &&
		 (*(line+3)!='\0' && *(line+3)==';'))
		{
		  uid[uidindex++]='>';
		  line+=4;
		  break;
		}

	    default:
	      uid[uidindex++]=*line;
	      line++;
	      break;
	    }
	}

      uid[uidindex]='\0';

      /* Chop off the trailing \r, \n, or both. This is fussy as the
         true HKP servers have \r\n, and the NAI HKP servers have just
         \n. */

      if(isspace(uid[uidindex-1]))
	uid[uidindex-1]='\0';

      if(isspace(uid[uidindex-2]))
	uid[uidindex-2]='\0';
    }

  return ret;
}

int hkp_search(STRLIST tokens)
{
  int rc=0,len=0,first=1;
  unsigned int maxlen=1024,buflen=0;
#ifndef __riscos__
  unsigned char *searchstr=NULL,*searchurl=NULL;
  unsigned char *request;
#else
  char *searchstr=NULL,*searchurl=NULL;
  char *request;
#endif
  struct http_context hd;
  unsigned int hflags=opt.honor_http_proxy?HTTP_FLAG_TRY_PROXY:0;
  byte *line=NULL;

  /* Glue the tokens together to make a search string */

  for(;tokens;tokens=tokens->next)
    {
      len+=strlen(tokens->d)+1;

      searchstr=m_realloc(searchstr,len+1);
      if(first)
	{
	  searchstr[0]='\0';
	  first=0;
	}

      strcat(searchstr,tokens->d);
      strcat(searchstr," ");
    }

  if(len<=1)
    {
      m_free(searchstr);
      return 0;
    }

  searchstr[len-1]='\0';

  log_info(_("searching for \"%s\" from HKP server %s\n"),
	   searchstr,opt.keyserver_host);

  /* Now make it url-ish */

  len=0;
  request=searchstr;
  while(*request!='\0')
    {
      if(isalnum(*request) || *request=='-')
	{
	  searchurl=m_realloc(searchurl,len+1);
	  searchurl[len++]=*request;
	}
      else if(*request==' ')
	{
	  searchurl=m_realloc(searchurl,len+1);
	  searchurl[len++]='+';
	}
      else
	{
	  searchurl=m_realloc(searchurl,len+3);
	  sprintf(&searchurl[len],"%%%02X",*request);
	  len+=3;
	}

      request++;
    }

  searchurl=m_realloc(searchurl,len+1);
  searchurl[len]='\0';

  request=m_alloc(strlen(opt.keyserver_host) + 100 + strlen(searchurl));

  if(strcasecmp(opt.keyserver_scheme,"x-broken-hkp")==0)
    hflags |= HTTP_FLAG_NO_SHUTDOWN;

  sprintf(request,"x-hkp://%s%s%s/pks/lookup?op=index&search=%s",
	  opt.keyserver_host,
	  atoi(opt.keyserver_port)>0?":":"",
	  atoi(opt.keyserver_port)>0?opt.keyserver_port:"",
	  searchurl);

  if(opt.keyserver_options.verbose>2)
    log_info("request is \"%s\"\n",request);

  rc=http_open_document(&hd,request,hflags);
  if(rc)
    {
      log_error(_("can't search keyserver: %s\n"),
	       rc==G10ERR_NETWORK?strerror(errno):g10_errstr(rc));
    }
  else
    {
      IOBUF buffer;
      int count=1;

      buffer=iobuf_temp();

      rc=1;
      while(rc!=0)
	{
	  /* This is a judgement call.  Is it better to slurp up all
             the results before prompting the user?  On the one hand,
             it probably makes the keyserver happier to not be blocked
             on sending for a long time while the user picks a key.
             On the other hand, it might be nice for the server to be
             able to stop sending before a large search result page is
             complete. */

	  rc=iobuf_read_line(hd.fp_read,&line,&buflen,&maxlen);

	  if(rc!=0)
	    count+=parse_hkp_index(buffer,line);
	}

      http_close(&hd);

      count--;

      keyserver_search_prompt(buffer,count,searchstr);

      iobuf_close(buffer);
      m_free(line);
    }

  m_free(request);
  m_free(searchurl);
  m_free(searchstr);

  return rc;
}
