/* hkp.c  -  Horowitz Keyserver Protocol
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
hkp_ask_import( KEYDB_SEARCH_DESC *desc, void *stats_handle)
{
    struct http_context hd;
    char *request;
    int rc;
    unsigned int hflags = opt.keyserver_options.honor_http_proxy? HTTP_FLAG_TRY_PROXY : 0;
    u32 key[2];

    if(desc->mode==KEYDB_SEARCH_MODE_FPR20)
      keyid_from_fingerprint(desc->u.fpr,MAX_FINGERPRINT_LEN,key);
    else if(desc->mode==KEYDB_SEARCH_MODE_LONG_KID ||
	    desc->mode==KEYDB_SEARCH_MODE_SHORT_KID)
      {
	key[0]=desc->u.kid[0];
	key[1]=desc->u.kid[1];
      }
    else
      return -1; /* HKP does not support v3 fingerprints */

    if(opt.keyserver_options.verbose)
      log_info(_("requesting key %08lX from %s\n"),
	       (ulong)key[1],opt.keyserver_uri);

    request = m_alloc( strlen( opt.keyserver_host ) + 100 );
    /* hkp does not accept the long keyid - we should really write a
     * nicer one :-)
     * FIXME: request binary mode - need to pass no_armor mode
     * down to the import function.  Marc told that there is such a
     * binary mode ... how?
     */

    if(opt.keyserver_options.broken_http_proxy)
      hflags |= HTTP_FLAG_NO_SHUTDOWN;

    sprintf(request,"x-hkp://%s%s%s/pks/lookup?op=get&search=0x%08lX",
	    opt.keyserver_host,
	    opt.keyserver_port?":":"",
	    opt.keyserver_port?opt.keyserver_port:"",
	    (ulong)key[1] );

  if(opt.keyserver_options.verbose>2)
    log_info("request is \"%s\"\n",request);

    rc = http_open_document( &hd, request, hflags );
    if( rc ) {
	log_info(_("can't get key from keyserver: %s\n"),
			rc == G10ERR_NETWORK? strerror(errno)
					    : g10_errstr(rc) );
    }
    else {
      rc = import_keys_stream( hd.fp_read, 0, stats_handle,
			       opt.keyserver_options.import_options);
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
    unsigned int hflags = opt.keyserver_options.honor_http_proxy? HTTP_FLAG_TRY_PROXY : 0;

    iobuf_push_filter( temp, urlencode_filter, NULL );

    memset( &afx, 0, sizeof afx);
    afx.what = 1;
    iobuf_push_filter( temp, armor_filter, &afx );

    rc = export_pubkeys_stream( temp, users,
				opt.keyserver_options.export_options );
    if( rc == -1 ) {
	iobuf_close(temp);
	return 0;
    }

    iobuf_flush_temp( temp );

    request = m_alloc( strlen( opt.keyserver_host ) + 100 );

    if(opt.keyserver_options.broken_http_proxy)
      hflags |= HTTP_FLAG_NO_SHUTDOWN;

    sprintf( request, "x-hkp://%s%s%s/pks/add",
	     opt.keyserver_host,
	     opt.keyserver_port?":":"",
	     opt.keyserver_port?opt.keyserver_port:"");

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

    sprintf( request, "Content-Length: %u\r\n",
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

static int
write_quoted(IOBUF a, const char *buf, char delim)
{
  char quoted[5];

  sprintf(quoted,"\\x%02X",delim);

  while(*buf)
    {
      if(*buf==delim)
	{
	  if(iobuf_writestr(a,quoted))
	    return -1;
	}
      else if(*buf=='\\')
	{
	  if(iobuf_writestr(a,"\\x5c"))
	    return -1;
	}
      else
	{
	  if(iobuf_writebyte(a,*buf))
	    return -1;
	}

      buf++;
    }

  return 0;
}

/* Remove anything <between brackets> and de-urlencode in place.  Note
   that this requires all brackets to be closed on the same line.  It
   also means that the result is never larger than the input. */
static void
dehtmlize(char *line)
{
  int parsedindex=0;
  char *parsed=line;

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
	  if((*(line+1)!='\0' && ascii_tolower(*(line+1))=='l') &&
	     (*(line+2)!='\0' && ascii_tolower(*(line+2))=='t') &&
	     (*(line+3)!='\0' && *(line+3)==';'))
	    {
	      parsed[parsedindex++]='<';
	      line+=4;
	      break;
	    }
	  else if((*(line+1)!='\0' && ascii_tolower(*(line+1))=='g') &&
		  (*(line+2)!='\0' && ascii_tolower(*(line+2))=='t') &&
		  (*(line+3)!='\0' && *(line+3)==';'))
	    {
	      parsed[parsedindex++]='>';
	      line+=4;
	      break;
	    }
	  else if((*(line+1)!='\0' && ascii_tolower(*(line+1))=='a') &&
		  (*(line+2)!='\0' && ascii_tolower(*(line+2))=='m') &&
		  (*(line+3)!='\0' && ascii_tolower(*(line+3))=='p') &&
		  (*(line+4)!='\0' && *(line+4)==';'))
	    {
	      parsed[parsedindex++]='&';
	      line+=5;
	      break;
	    }

	default:
	  parsed[parsedindex++]=*line;
	  line++;
	  break;
	}
    }

  parsed[parsedindex]='\0';

  /* Chop off any trailing whitespace.  Note that the HKP servers have
     \r\n as line endings, and the NAI HKP servers have just \n. */

  if(parsedindex>0)
    {
      parsedindex--;
      while(isspace(((unsigned char*)parsed)[parsedindex]))
	{
	  parsed[parsedindex]='\0';
	  parsedindex--;
	}
    }
}

/* pub  2048/<a href="/pks/lookup?op=get&search=0x3CB3B415">3CB3B415</a> 1998/04/03 David M. Shaw &lt;<a href="/pks/lookup?op=get&search=0x3CB3B415">dshaw@jabberwocky.com</a>&gt; */

/* Luckily enough, both the HKP server and NAI HKP interface to their
   LDAP server are close enough in output so the same function can
   parse them both. */

static int 
parse_hkp_index(IOBUF buffer,char *line)
{
  static int open=0,revoked=0;
  static char *key=NULL,*type=NULL;
#ifdef __riscos__
  static char *uid=NULL;
#else
  static unsigned char *uid=NULL;
#endif
  static u32 bits,createtime;
  int ret=0;

  /*  printf("Open %d, LINE: \"%s\", uid: %s\n",open,line,uid); */

  dehtmlize(line);

  /*  printf("Now open %d, LINE: \"%s\", uid: %s\n",open,line,uid); */

  /* Try and catch some bastardization of HKP.  If we don't have
     certain unchanging landmarks, we can't reliably parse the
     response.  This only complains about problems within the key
     section itself.  Headers and footers should not matter. */
  if(open && line[0]!='\0' &&
     ascii_strncasecmp(line,"pub ",4)!=0 &&
     ascii_strncasecmp(line,"    ",4)!=0)
    {
      m_free(key);
      m_free(uid);
      log_error(_("this keyserver is not fully HKP compatible\n"));
      return -1;
    }

  /* For multiple UIDs */
  if(open && uid!=NULL)
    {
      ret=0;

      if(!(revoked && !opt.keyserver_options.include_revoked))
	{
	  char intstr[11];

	  if(key)
	    write_quoted(buffer,key,':');
	  iobuf_writestr(buffer,":");
	  write_quoted(buffer,uid,':');
	  iobuf_writestr(buffer,":");
	  iobuf_writestr(buffer,revoked?"1:":":");
	  sprintf(intstr,"%u",createtime);
	  write_quoted(buffer,intstr,':');
	  iobuf_writestr(buffer,":::");
	  if(type)
	    write_quoted(buffer,type,':');
	  iobuf_writestr(buffer,":");
	  sprintf(intstr,"%u",bits);
	  write_quoted(buffer,intstr,':');
	  iobuf_writestr(buffer,"\n");

	  ret=1;
	}

      if(strncmp(line,"    ",4)!=0)
	{
	  revoked=0;
	  m_free(key);
	  m_free(uid);
	  uid=NULL;
	  open=0;
	}
    }

  if(ascii_strncasecmp(line,"pub ",4)==0)
    {
      char *tok,*temp;

      open=1;

      line+=4;

      tok=strsep(&line,"/");
      if(tok==NULL)
	return ret;

      if(tok[strlen(tok)-1]=='R')
	type="RSA";
      else if(tok[strlen(tok)-1]=='D')
	type="DSA";
      else
	type=NULL;

      bits=atoi(tok);

      tok=strsep(&line," ");
      if(tok==NULL)
	return ret;

      key=m_strdup(tok);

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
      if(line==NULL)
	{
	  uid=m_strdup("Key index corrupted");
	  return ret;
	}

      while(*line==' ' && *line!='\0')
	line++;

      if(*line=='\0')
	return ret;

      if(strncmp(line,"*** KEY REVOKED ***",19)==0)
	{
	  revoked=1;
	  return ret;
	}

      uid=m_strdup(line);
    }

  return ret;
}

int hkp_search(STRLIST tokens)
{
  int rc=0,len=0,max,first=1;
#ifndef __riscos__
  unsigned char *searchstr=NULL,*searchurl;
  unsigned char *request;
#else
  char *searchstr=NULL,*searchurl;
  char *request;
#endif
  struct http_context hd;
  unsigned int hflags=opt.keyserver_options.honor_http_proxy?HTTP_FLAG_TRY_PROXY:0;

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

  max=0;
  len=0;
  searchurl=NULL;
  request=searchstr;

  while(*request!='\0')
    {
      if(max-len<3)
	{
	  max+=100;
	  searchurl=m_realloc(searchurl,max+1); /* Note +1 for \0 */
	}

      if(isalnum(*request) || *request=='-')
	searchurl[len++]=*request;
      else if(*request==' ')
	searchurl[len++]='+';
      else
	{
	  sprintf(&searchurl[len],"%%%02X",*request);
	  len+=3;
	}

      request++;
    }

  searchurl[len]='\0';

  request=m_alloc(strlen(opt.keyserver_host) + 100 + strlen(searchurl));

  if(opt.keyserver_options.broken_http_proxy)
    hflags |= HTTP_FLAG_NO_SHUTDOWN;

  sprintf(request,"x-hkp://%s%s%s/pks/lookup?op=index&search=%s",
	  opt.keyserver_host,
	  opt.keyserver_port?":":"",
	  opt.keyserver_port?opt.keyserver_port:"",
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
      int ret=0; /* gcc wants me to initialize this */
      unsigned int buflen;
      byte *line=NULL;

      buffer=iobuf_temp();

      rc=1;
      while(rc!=0)
	{
	  unsigned int maxlen=1024;

	  /* This is a judgement call.  Is it better to slurp up all
             the results before prompting the user?  On the one hand,
             it probably makes the keyserver happier to not be blocked
             on sending for a long time while the user picks a key.
             On the other hand, it might be nice for the server to be
             able to stop sending before a large search result page is
             complete. */

	  rc=iobuf_read_line(hd.fp_read,&line,&buflen,&maxlen);

	  ret=parse_hkp_index(buffer,line);
	  if(ret==-1)
	    break;

	  if(rc!=0)
	    count+=ret;
	}

      http_close(&hd);

      count--;

      if(ret>-1)
	keyserver_search_prompt(buffer,count,searchstr);

      iobuf_close(buffer);
      m_free(line);
    }

  m_free(request);
  m_free(searchurl);
  m_free(searchstr);

  return rc;
}
