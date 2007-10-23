/* ksutil.c - general keyserver utility functions
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
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#else
#include "curl-shim.h"
#endif
#include "compat.h"
#include "keyserver.h"
#include "ksutil.h"

#ifdef HAVE_DOSISH_SYSTEM

unsigned int set_timeout(unsigned int seconds) {return 0;}
int register_timeout(void) {return 0;}

#else

static void
catch_alarm(int foo)
{
  (void)foo;
  _exit(KEYSERVER_TIMEOUT);
}

unsigned int
set_timeout(unsigned int seconds)
{
  return alarm(seconds);
}

int
register_timeout(void)
{
#if defined(HAVE_SIGACTION) && defined(HAVE_STRUCT_SIGACTION)
  struct sigaction act;

  act.sa_handler=catch_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags=0;
  return sigaction(SIGALRM,&act,NULL);
#else 
  if(signal(SIGALRM,catch_alarm)==SIG_ERR)
    return -1;
  else
    return 0;
#endif
}

#endif /* !HAVE_DOSISH_SYSTEM */

struct ks_options *
init_ks_options(void)
{
  struct ks_options *opt;

  opt=calloc(1,sizeof(struct ks_options));

  if(opt)
    {
      opt->action=KS_UNKNOWN;
      opt->flags.include_revoked=1;
      opt->flags.include_subkeys=1;
      opt->flags.check_cert=1;
      opt->timeout=DEFAULT_KEYSERVER_TIMEOUT;
      opt->path=strdup("/");
      if(!opt->path)
	{
	  free(opt);
	  opt=NULL;
	}
    }

  return opt;
}

void
free_ks_options(struct ks_options *opt)
{
  if(opt)
    {
      free(opt->host);
      free(opt->port);
      free(opt->scheme);
      free(opt->auth);
      free(opt->path);
      free(opt->opaque);
      free(opt->ca_cert_file);
      free(opt);
    }
}

/* Returns 0 if we "ate" the line.  Returns >0, a KEYSERVER_ error
   code if that error applies.  Returns -1 if we did not match the
   line at all. */
int
parse_ks_options(char *line,struct ks_options *opt)
{
  int version;
  char command[MAX_COMMAND+1];
  char host[MAX_HOST+1];
  char port[MAX_PORT+1];
  char scheme[MAX_SCHEME+1];
  char auth[MAX_AUTH+1];
  char path[URLMAX_PATH+1];
  char opaque[MAX_OPAQUE+1];
  char option[MAX_OPTION+1];

  if(line[0]=='#')
    return 0;

  if(sscanf(line,"COMMAND %" MKSTRING(MAX_COMMAND) "s\n",command)==1)
    {
      command[MAX_COMMAND]='\0';

      if(ascii_strcasecmp(command,"get")==0)
	opt->action=KS_GET;
      else if(ascii_strcasecmp(command,"getname")==0)
	opt->action=KS_GETNAME;
      else if(ascii_strcasecmp(command,"send")==0)
	opt->action=KS_SEND;
      else if(ascii_strcasecmp(command,"search")==0)
	opt->action=KS_SEARCH;

      return 0;
    }

  if(sscanf(line,"HOST %" MKSTRING(MAX_HOST) "s\n",host)==1)
    {
      host[MAX_HOST]='\0';
      free(opt->host);
      opt->host=strdup(host);
      if(!opt->host)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"PORT %" MKSTRING(MAX_PORT) "s\n",port)==1)
    {
      port[MAX_PORT]='\0';
      free(opt->port);
      opt->port=strdup(port);
      if(!opt->port)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"SCHEME %" MKSTRING(MAX_SCHEME) "s\n",scheme)==1)
    {
      scheme[MAX_SCHEME]='\0';
      free(opt->scheme);
      opt->scheme=strdup(scheme);
      if(!opt->scheme)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"AUTH %" MKSTRING(MAX_AUTH) "s\n",auth)==1)
    {
      auth[MAX_AUTH]='\0';
      free(opt->auth);
      opt->auth=strdup(auth);
      if(!opt->auth)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"PATH %" MKSTRING(URLMAX_PATH) "s\n",path)==1)
    {
      path[URLMAX_PATH]='\0';
      free(opt->path);
      opt->path=strdup(path);
      if(!opt->path)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"OPAQUE %" MKSTRING(MAX_OPAQUE) "s\n",opaque)==1)
    {
      opaque[MAX_OPAQUE]='\0';
      free(opt->opaque);
      opt->opaque=strdup(opaque);
      if(!opt->opaque)
	return KEYSERVER_NO_MEMORY;
      return 0;
    }

  if(sscanf(line,"VERSION %d\n",&version)==1)
    {
      if(version!=KEYSERVER_PROTO_VERSION)
	return KEYSERVER_VERSION_ERROR;

      return 0;
    }

  if(sscanf(line,"OPTION %" MKSTRING(MAX_OPTION) "[^\n]\n",option)==1)
    {
      int no=0;
      char *start=&option[0];

      option[MAX_OPTION]='\0';

      if(ascii_strncasecmp(option,"no-",3)==0)
	{
	  no=1;
	  start=&option[3];
	}

      if(ascii_strncasecmp(start,"verbose",7)==0)
	{
	  if(no)
	    opt->verbose=0;
	  else if(start[7]=='=')
	    opt->verbose=atoi(&start[8]);
	  else
	    opt->verbose++;
	}
      else if(ascii_strcasecmp(start,"include-disabled")==0)
	{
	  if(no)
	    opt->flags.include_disabled=0;
	  else
	    opt->flags.include_disabled=1;
	}
      else if(ascii_strcasecmp(start,"include-revoked")==0)
	{
	  if(no)
	    opt->flags.include_revoked=0;
	  else
	    opt->flags.include_revoked=1;
	}
      else if(ascii_strcasecmp(start,"include-subkeys")==0)
	{
	  if(no)
	    opt->flags.include_subkeys=0;
	  else
	    opt->flags.include_subkeys=1;
	}
      else if(ascii_strcasecmp(start,"check-cert")==0)
	{
	  if(no)
	    opt->flags.check_cert=0;
	  else
	    opt->flags.check_cert=1;
	}
      else if(ascii_strncasecmp(start,"debug",5)==0)
	{
	  if(no)
	    opt->debug=0;
	  else if(start[5]=='=')
	    opt->debug=atoi(&start[6]);
	  else if(start[5]=='\0')
	    opt->debug=1;
	}
      else if(ascii_strncasecmp(start,"timeout",7)==0)
	{
	  if(no)
	    opt->timeout=0;
	  else if(start[7]=='=')
	    opt->timeout=atoi(&start[8]);
	  else if(start[7]=='\0')
	    opt->timeout=DEFAULT_KEYSERVER_TIMEOUT;
	}
      else if(ascii_strncasecmp(start,"ca-cert-file",12)==0)
	{
	  if(no)
	    {
	      free(opt->ca_cert_file);
	      opt->ca_cert_file=NULL;
	    }
	  else if(start[12]=='=')
	    {
	      free(opt->ca_cert_file);
	      opt->ca_cert_file=strdup(&start[13]);
	      if(!opt->ca_cert_file)
		return KEYSERVER_NO_MEMORY;
	    }
	}
    }

  return -1;
}

const char *
ks_action_to_string(enum ks_action action)
{
  switch(action)
    {
    case KS_UNKNOWN: return "UNKNOWN";
    case KS_GET:     return "GET";
    case KS_GETNAME: return "GETNAME";
    case KS_SEND:    return "SEND";
    case KS_SEARCH:  return "SEARCH";
    }

  return "?";
}

/* Canonicalize CRLF to just LF by stripping CRs.  This actually makes
   sense, since on Unix-like machines LF is correct, and on win32-like
   machines, our output buffer is opened in textmode and will
   re-canonicalize line endings back to CRLF.  Since we only need to
   handle armored keys, we don't have to worry about odd cases like
   CRCRCR and the like. */

void
print_nocr(FILE *stream,const char *str)
{
  while(*str)
    {
      if(*str!='\r')
	fputc(*str,stream);
      str++;
    }
}

#define HEX "abcdefABCDEF1234567890"

/* Return what sort of item is being searched for.  *search is
   permuted to remove any special indicators of a search type. */
enum ks_search_type
classify_ks_search(const char **search)
{
  switch(**search)
    {
    case '*':
      (*search)++;
      return KS_SEARCH_SUBSTR;
    case '=':
      (*search)++;
      return KS_SEARCH_EXACT;
    case '<':
      (*search)++;
      return KS_SEARCH_MAIL;
    case '@':
      (*search)++;
      return KS_SEARCH_MAILSUB;
    case '0':
      if((*search)[1]=='x')
	{
	  if(strlen(*search)==10 && strspn(*search,HEX"x")==10)
	    {
	      (*search)+=2;
	      return KS_SEARCH_KEYID_SHORT;
	    }
	  else if(strlen(*search)==18 && strspn(*search,HEX"x")==18)
	    {
	      (*search)+=2;
	      return KS_SEARCH_KEYID_LONG;
	    }
	}
      /* fall through */
    default:
      /* Try and recognize a key ID.  This isn't exact (it's possible
	 that a user ID string happens to be 8 or 16 digits of hex),
	 but it's extremely unlikely.  Plus the main GPG program does
	 this also, and consistency is good. */

      if(strlen(*search)==8 && strspn(*search,HEX)==8)
	return KS_SEARCH_KEYID_SHORT;
      else if(strlen(*search)==16 && strspn(*search,HEX)==16)
	return KS_SEARCH_KEYID_LONG;

      /* Last resort */
      return KS_SEARCH_SUBSTR;
    }
}

int
curl_err_to_gpg_err(CURLcode error)
{
  switch(error)
    {
    case CURLE_OK:                    return KEYSERVER_OK;
    case CURLE_UNSUPPORTED_PROTOCOL:  return KEYSERVER_SCHEME_NOT_FOUND;
    case CURLE_COULDNT_CONNECT:       return KEYSERVER_UNREACHABLE;
    case CURLE_FTP_COULDNT_RETR_FILE: return KEYSERVER_KEY_NOT_FOUND;
    default: return KEYSERVER_INTERNAL_ERROR;
    }
}

#define B64 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static void
curl_armor_writer(const unsigned char *buf,size_t size,void *cw_ctx)
{
  struct curl_writer_ctx *ctx=cw_ctx;
  size_t idx=0;

  while(idx<size)
    {
      for(;ctx->armor_remaining<3 && idx<size;ctx->armor_remaining++,idx++)
	ctx->armor_ctx[ctx->armor_remaining]=buf[idx];

      if(ctx->armor_remaining==3)
	{
	  /* Top 6 bytes of ctx->armor_ctx[0] */
	  fputc(B64[(ctx->armor_ctx[0]>>2)&0x3F],ctx->stream);
	  /* Bottom 2 bytes of ctx->armor_ctx[0] and top 4 bytes of
	     ctx->armor_ctx[1] */
	  fputc(B64[(((ctx->armor_ctx[0]<<4)&0x30)
		     |((ctx->armor_ctx[1]>>4)&0x0F))&0x3F],ctx->stream);
	  /* Bottom 4 bytes of ctx->armor_ctx[1] and top 2 bytes of
	     ctx->armor_ctx[2] */
	  fputc(B64[(((ctx->armor_ctx[1]<<2)&0x3C)
		     |((ctx->armor_ctx[2]>>6)&0x03))&0x3F],ctx->stream);
	  /* Bottom 6 bytes of ctx->armor_ctx[2] */
	  fputc(B64[(ctx->armor_ctx[2]&0x3F)],ctx->stream);

	  ctx->linelen+=4;
	  if(ctx->linelen>=70)
	    {
	      fputc('\n',ctx->stream);
	      ctx->linelen=0;
	    }

	  ctx->armor_remaining=0;
	}
    }

}

size_t
curl_writer(const void *ptr,size_t size,size_t nmemb,void *cw_ctx)
{
  struct curl_writer_ctx *ctx=cw_ctx;
  const char *buf=ptr;
  size_t i;

  if(!ctx->flags.initialized)
    {
      if(size*nmemb==0)
	return 0;

      /* The object we're fetching is in binary form */
      if(*buf&0x80)
	{
	  ctx->flags.armor=1;
	  fprintf(ctx->stream,BEGIN"\n\n");
	}
      else
	ctx->marker=BEGIN;

      ctx->flags.initialized=1;
    }

  if(ctx->flags.armor)
    curl_armor_writer(ptr,size*nmemb,cw_ctx);
  else
    {
      /* scan the incoming data for our marker */
      for(i=0;!ctx->flags.done && i<(size*nmemb);i++)
	{
	  if(buf[i]==ctx->marker[ctx->markeridx])
	    {
	      ctx->markeridx++;
	      if(ctx->marker[ctx->markeridx]=='\0')
		{
		  if(ctx->flags.begun)
		    ctx->flags.done=1;
		  else
		    {
		      /* We've found the BEGIN marker, so now we're
			 looking for the END marker. */
		      ctx->flags.begun=1;
		      ctx->marker=END;
		      ctx->markeridx=0;
		      fprintf(ctx->stream,BEGIN);
		      continue;
		    }
		}
	    }
	  else
	    ctx->markeridx=0;

	  if(ctx->flags.begun)
	    {
	      /* Canonicalize CRLF to just LF by stripping CRs.  This
		 actually makes sense, since on Unix-like machines LF
		 is correct, and on win32-like machines, our output
		 buffer is opened in textmode and will re-canonicalize
		 line endings back to CRLF.  Since this code is just
		 for handling armored keys, we don't have to worry
		 about odd cases like CRCRCR and the like. */

	      if(buf[i]!='\r')
		fputc(buf[i],ctx->stream);
	    }
	}
    }

  return size*nmemb;
}

void
curl_writer_finalize(struct curl_writer_ctx *ctx)
{
  if(ctx->flags.armor)
    {
      if(ctx->armor_remaining==2)
	{
	  /* Top 6 bytes of ctx->armorctx[0] */
	  fputc(B64[(ctx->armor_ctx[0]>>2)&0x3F],ctx->stream);
	  /* Bottom 2 bytes of ctx->armor_ctx[0] and top 4 bytes of
	     ctx->armor_ctx[1] */
	  fputc(B64[(((ctx->armor_ctx[0]<<4)&0x30)
		     |((ctx->armor_ctx[1]>>4)&0x0F))&0x3F],ctx->stream);
	  /* Bottom 4 bytes of ctx->armor_ctx[1] */
	  fputc(B64[((ctx->armor_ctx[1]<<2)&0x3C)],ctx->stream);
	  /* Pad */
	  fputc('=',ctx->stream);
	}
      else if(ctx->armor_remaining==1)
	{
	  /* Top 6 bytes of ctx->armor_ctx[0] */
	  fputc(B64[(ctx->armor_ctx[0]>>2)&0x3F],ctx->stream);
	  /* Bottom 2 bytes of ctx->armor_ctx[0] */
	  fputc(B64[((ctx->armor_ctx[0]<<4)&0x30)],ctx->stream);
	  /* Pad */
	  fputc('=',ctx->stream);
	  /* Pad */
	  fputc('=',ctx->stream);
	}

      fprintf(ctx->stream,"\n"END);
      ctx->flags.done=1;
    }
}
