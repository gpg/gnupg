/* gpgkeys_oldhkp.c - talk to an HKP keyserver
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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

/* This is the original version that uses the iobuf library for
   communication. */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
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
#define SEND   1
#define SEARCH 2

extern char *optarg;
extern int optind;

static int verbose=0,include_revoked=0,include_disabled=0;
static unsigned int http_flags=0;
static char host[MAX_HOST+1]={'\0'},proxy[MAX_PROXY+1]={'\0'},
  port[MAX_PORT+1]={'\0'},path[URLMAX_PATH+1];
static FILE *input=NULL,*output=NULL,*console=NULL;

int
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

int
send_key(int *eof)
{
  int rc,begin=0,end=0,ret=KEYSERVER_INTERNAL_ERROR;
  char keyid[17];
  char *request;
  struct http_context hd;
  unsigned int status;
  IOBUF temp = iobuf_temp();
  char line[MAX_LINE];

  memset(&hd,0,sizeof(hd));

  request=malloc(strlen(host)+strlen(port)+strlen(path)+100);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return KEYSERVER_NO_MEMORY;
    }

  iobuf_push_filter(temp,urlencode_filter,NULL);

  /* Read and throw away input until we see the BEGIN */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"KEY %16s BEGIN\n",keyid)==1)
      {
	begin=1;
	break;
      }

  if(!begin)
    {
      /* i.e. eof before the KEY BEGIN was found.  This isn't an
	 error. */
      *eof=1;
      ret=KEYSERVER_OK;
      goto fail;
    }

  /* Now slurp up everything until we see the END */

  while(fgets(line,MAX_LINE,input))
    if(sscanf(line,"KEY %16s END\n",keyid)==1)
      {
	end=1;
	break;
      }
    else
      if(iobuf_writestr(temp,line))
	{
	  fprintf(console,"gpgkeys: internal iobuf error\n");
	  goto fail;
	}

  if(!end)
    {
      fprintf(console,"gpgkeys: no KEY %s END found\n",keyid);
      *eof=1;
      ret=KEYSERVER_KEY_INCOMPLETE;
      goto fail;
    }

  iobuf_flush_temp(temp);

  sprintf(request,"hkp://%s%s%s%s/pks/add",
	  host,port[0]?":":"",port[0]?port:"",path);

  if(verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  rc=http_open(&hd,HTTP_REQ_POST,request,NULL,http_flags,
	       proxy[0]?proxy:NULL);
  if(rc)
    {
      fprintf(console,"gpgkeys: unable to connect to `%s'\n",host);
      goto fail;
    }

  /* Some keyservers require this Content-Type (e.g. CryptoEx). */
  iobuf_writestr(hd.fp_write,
                 "Content-Type: application/x-www-form-urlencoded\r\n");

  sprintf(request,"Content-Length: %u\r\n",
	  (unsigned)iobuf_get_temp_length(temp)+9);
  iobuf_writestr(hd.fp_write,request);

  http_start_data(&hd);

  iobuf_writestr(hd.fp_write,"keytext=");
  iobuf_write(hd.fp_write,
	      iobuf_get_temp_buffer(temp),iobuf_get_temp_length(temp));
  iobuf_put(hd.fp_write,'\n');

  rc=http_wait_response(&hd,&status);
  if(rc)
    {
      fprintf(console,"gpgkeys: error sending to `%s': %s\n",
	      host,g10_errstr(rc));
      goto fail;
    }

  if((status/100)!=2)
    {
      fprintf(console,"gpgkeys: remote server returned error %d\n",status);
      goto fail;
    }

  fprintf(output,"KEY %s SENT\n",keyid);

  ret=KEYSERVER_OK;

 fail:
  free(request);
  iobuf_close(temp);
  http_close(&hd);

  if(ret!=0 && begin)
    fprintf(output,"KEY %s FAILED %d\n",keyid,ret);

  return ret;
}

int
get_key(char *getkey)
{
  int rc,gotit=0;
  char search[29];
  char *request;
  struct http_context hd;

  /* Build the search string.  HKP only uses the short key IDs. */

  if(strncmp(getkey,"0x",2)==0)
    getkey+=2;

  if(strlen(getkey)==32)
    {
      fprintf(console,
	      "gpgkeys: HKP keyservers do not support v3 fingerprints\n");
      fprintf(output,"KEY 0x%s BEGIN\n",getkey);
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,KEYSERVER_NOT_SUPPORTED);
      return KEYSERVER_NOT_SUPPORTED;
    }

 if(strlen(getkey)>8)
    {
      char *offset=&getkey[strlen(getkey)-8];

      /* fingerprint or long key id.  Take the last 8 characters and
         treat it like a short key id */

      sprintf(search,"0x%.8s",offset);
    }
 else
   {
      /* short key id */

      sprintf(search,"0x%.8s",getkey);
    }

  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  request=malloc(strlen(host)+strlen(port)+strlen(path)+100);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return KEYSERVER_NO_MEMORY;
    }

  sprintf(request,"hkp://%s%s%s%s/pks/lookup?op=get&options=mr&search=%s",
	  host,port[0]?":":"",port[0]?port:"",path,search);

  if(verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  rc=http_open_document(&hd,request,NULL,http_flags,proxy[0]?proxy:NULL);
  if(rc!=0)
    {
      fprintf(console,"gpgkeys: HKP fetch error: %s\n",
	      rc==G10ERR_NETWORK?strerror(errno):g10_errstr(rc));
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,
	    rc==G10ERR_NETWORK?KEYSERVER_UNREACHABLE:KEYSERVER_INTERNAL_ERROR);
    }
  else
    {
      unsigned int maxlen=1024,buflen;
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

/* Remove anything <between brackets> and de-urlencode in place.  Note
   that this requires all brackets to be closed on the same line.  It
   also means that the result is never larger than the input. */
void
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
	  else if((*(line+1)!='\0' && ascii_tolower(*(line+1))=='q') &&
		  (*(line+2)!='\0' && ascii_tolower(*(line+2))=='u') &&
		  (*(line+3)!='\0' && ascii_tolower(*(line+3))=='o') &&
		  (*(line+4)!='\0' && ascii_tolower(*(line+4))=='t') &&
		  (*(line+5)!='\0' && *(line+5)==';'))
	    {
	      parsed[parsedindex++]='"';
	      line+=6;
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
      while(isspace(((unsigned char *)parsed)[parsedindex]))
	{
	  parsed[parsedindex]='\0';
	  if(parsedindex==0)
	    break;
	  parsedindex--;
	}
    }
}

int
write_quoted(IOBUF a, const char *buf, char delim)
{
  while(*buf)
    {
      if(*buf==delim)
	{
	  char quoted[5];
	  sprintf(quoted,"%%%02X",delim);
	  if(iobuf_writestr(a,quoted))
	    return -1;
	}
      else if(*buf=='%')
	{
	  if(iobuf_writestr(a,"%25"))
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

/* pub  2048/<a href="/pks/lookup?op=get&search=0x3CB3B415">3CB3B415</a> 1998/04/03 David M. Shaw &lt;<a href="/pks/lookup?op=get&search=0x3CB3B415">dshaw@jabberwocky.com</a>&gt; */

/* Luckily enough, both the HKP server and NAI HKP interface to their
   LDAP server are close enough in output so the same function can
   parse them both. */

int
parse_hkp_index(IOBUF buffer,char *line)
{
  int ret=0;

  /* printf("Open %d, LINE: `%s'\n",open,line); */

  dehtmlize(line);

  /* printf("Now open %d, LINE: `%s'\n",open,line); */

  if(line[0]=='\0')
    return 0;
  else if(ascii_strncasecmp(line,"pub",3)==0)
    {
      char *tok,*keyid,*uid=NULL,number[15];
      int bits=0,type=0,disabled=0,revoked=0;
      u32 createtime=0;

      line+=3;

      if(*line=='-')
	{
	  disabled=1;
	  if(!include_disabled)
	    return 0;
	}

      line++;

      tok=strsep(&line,"/");
      if(tok==NULL || strlen(tok)==0)
	return ret;

      if(tok[strlen(tok)-1]=='R')
	type=1;
      else if(tok[strlen(tok)-1]=='D')
	type=17;

      bits=atoi(tok);

      keyid=strsep(&line," ");

      tok=strsep(&line," ");
      if(tok!=NULL)
	{
	  char *temp=tok;

	  /* The date parser wants '-' instead of '/', so... */
	  while(*temp!='\0')
	    {
	      if(*temp=='/')
		*temp='-';

	      temp++;
	    }

	  createtime=scan_isodatestr(tok);
	}

      if(line!=NULL)
	{
	  while(*line==' ' && *line!='\0')
	    line++;

	  if(*line!='\0')
	    {
	      if(strncmp(line,"*** KEY REVOKED ***",19)==0)
		{
		  revoked=1;
		  if(!include_revoked)
		    return 0;
		}
	      else
		uid=line;
	    }
	}

      if(keyid)
	{
	  iobuf_writestr(buffer,"pub:");

	  write_quoted(buffer,keyid,':');

	  iobuf_writestr(buffer,":");

	  if(type)
	    {
	      sprintf(number,"%d",type);
	      write_quoted(buffer,number,':');
	    }

	  iobuf_writestr(buffer,":");

	  if(bits)
	    {
	      sprintf(number,"%d",bits);
	      write_quoted(buffer,number,':');
	    }

	  iobuf_writestr(buffer,":");

	  if(createtime)
	    {
	      sprintf(number,"%d",createtime);
	      write_quoted(buffer,number,':');
	    }

	  iobuf_writestr(buffer,"::");

	  if(revoked)
	    write_quoted(buffer,"r",':');

	  if(disabled)
	    write_quoted(buffer,"d",':');

	  if(uid)
	    {
	      iobuf_writestr(buffer,"\nuid:");
	      write_quoted(buffer,uid,':');
	    }

	  iobuf_writestr(buffer,"\n");

	  ret=1;
	}
    }
  else if(ascii_strncasecmp(line,"   ",3)==0)
    {
      while(*line==' ' && *line!='\0')
	line++;

      if(*line!='\0')
	{
	  iobuf_writestr(buffer,"uid:");
	  write_quoted(buffer,line,':');
	  iobuf_writestr(buffer,"\n");
	}
    }

#if 0
  else if(open)
    {
      /* Try and catch some bastardization of HKP.  If we don't have
	 certain unchanging landmarks, we can't reliably parse the
	 response.  This only complains about problems within the key
	 section itself.  Headers and footers should not matter. */

      fprintf(console,"gpgkeys: this keyserver does not support searching\n");
      ret=-1;
    }
#endif

  return ret;
}

void
handle_old_hkp_index(IOBUF inp)
{
  int ret,rc,count=0;
  unsigned int buflen;
  byte *line=NULL;
  IOBUF buffer=iobuf_temp();

  do
    {
      unsigned int maxlen=1024;

      /* This is a judgement call.  Is it better to slurp up all the
	 results before prompting the user?  On the one hand, it
	 probably makes the keyserver happier to not be blocked on
	 sending for a long time while the user picks a key.  On the
	 other hand, it might be nice for the server to be able to
	 stop sending before a large search result page is
	 complete. */

      rc=iobuf_read_line(inp,&line,&buflen,&maxlen);

      ret=parse_hkp_index(buffer,line);
      if(ret==-1)
	break;

      if(rc!=0)
	count+=ret;
    }
  while(rc!=0);

  m_free(line);

  if(ret>-1)
    fprintf(output,"info:1:%d\n%s",count,iobuf_get_temp_buffer(buffer));

  iobuf_close(buffer);
}

int
search_key(char *searchkey)
{
  int max=0,len=0,ret=KEYSERVER_INTERNAL_ERROR,rc;
  struct http_context hd;
  char *search=NULL,*request=NULL;
  unsigned char *skey=(unsigned char*) searchkey;

  fprintf(output,"SEARCH %s BEGIN\n",searchkey);

  /* Build the search string.  It's going to need url-encoding. */

  while(*skey!='\0')
    {
      if(max-len<3)
	{
	  max+=100;
	  search=realloc(search,max+1); /* Note +1 for \0 */
          if (!search)
            {
              fprintf(console,"gpgkeys: out of memory\n");
              ret=KEYSERVER_NO_MEMORY;
	      goto fail;
            }
	}

      if(isalnum(*skey) || *skey=='-')
	search[len++]=*skey;
      else if(*skey==' ')
	search[len++]='+';
      else
	{
	  sprintf(&search[len],"%%%02X",*skey);
	  len+=3;
	}

      skey++;
    }

  if(!search)
    {
      fprintf(console,"gpgkeys: corrupt input?\n");
      return -1;
    }

  search[len]='\0';

  request=malloc(strlen(host)+strlen(port)+strlen(path)+100+strlen(search));
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  sprintf(request,"hkp://%s%s%s%s/pks/lookup?op=index&options=mr&search=%s",
	  host,port[0]?":":"",port[0]?port:"",path,search);

  if(verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is `%s'\n",request);

  rc=http_open_document(&hd,request,NULL,http_flags,proxy[0]?proxy:NULL);
  if(rc)
    {
      fprintf(console,"gpgkeys: can't search keyserver `%s': %s\n",
	      host,rc==G10ERR_NETWORK?strerror(errno):g10_errstr(rc));
    }
  else
    {
      unsigned int maxlen=1024,buflen;
      byte *line=NULL;

      /* Is it a pksd that knows how to handle machine-readable
         format? */

      rc=iobuf_read_line(hd.fp_read,&line,&buflen,&maxlen);
      if(line[0]=='<')
	handle_old_hkp_index(hd.fp_read);
      else
	do
	  {
	    fprintf(output,"%s",line);
	    maxlen=1024;
	    rc=iobuf_read_line(hd.fp_read,&line,&buflen,&maxlen);
	  }
	while(rc!=0);

      m_free(line);

      http_close(&hd);

      fprintf(output,"SEARCH %s END\n",searchkey);

      ret=KEYSERVER_OK;
    }

 fail:

  free(request);
  free(search);

  if(ret!=KEYSERVER_OK)
    fprintf(output,"SEARCH %s FAILED %d\n",searchkey,ret);

  return ret;
}

void
fail_all(struct keylist *keylist,int action,int err)
{
  if(!keylist)
    return;

  if(action==SEARCH)
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
  int failed=0;
  struct keylist *keylist=NULL,*keyptr=NULL;
  unsigned int timeout=DEFAULT_KEYSERVER_TIMEOUT;
  size_t n;

  console=stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      fputs ("gpgkeys_hkp (GnuPG) " VERSION"\n", stdout);
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
	  else if(strcasecmp(command,"send")==0)
	    action=SEND;
	  else if(strcasecmp(command,"search")==0)
	    action=SEARCH;

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
	  else if(strcasecmp(start,"include-revoked")==0)
	    {
	      if(no)
		include_revoked=0;
	      else
		include_revoked=1;
	    }
	  else if(strcasecmp(start,"include-disabled")==0)
	    {
	      if(no)
		include_disabled=0;
	      else
		include_disabled=1;
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
	      else if(start[10]=='\0')
		{
		  char *http_proxy=getenv(HTTP_PROXY_ENV);
		  if(http_proxy)
		    {
		      strncpy(proxy,http_proxy,MAX_PROXY);
		      proxy[MAX_PROXY]='\0';
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

  /* Avoid the double slash // in a path */
  n=strlen(path);
  if(n>0 && path[n-1]=='/')
    path[n-1]='\0';

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

  if(action==SEND)
    while(fgets(line,MAX_LINE,input)!=NULL && line[0]!='\n');
  else if(action==GET || action==SEARCH)
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

  if(verbose>1)
    {
      fprintf(console,"Host:\t\t%s\n",host);
      if(port[0])
	fprintf(console,"Port:\t\t%s\n",port);
      if(strcmp(path,"/")!=0)
	fprintf(console,"Path:\t\t%s\n",path);
      fprintf(console,"Command:\t%s\n",action==GET?"GET":
	      action==SEND?"SEND":"SEARCH");
    }

#if 0
  if(verbose>1)
    {
      vals=ldap_get_values(ldap,res,"software");
      if(vals!=NULL)
	{
	  fprintf(console,"Server: \t%s\n",vals[0]);
	  ldap_value_free(vals);
	}

      vals=ldap_get_values(ldap,res,"version");
      if(vals!=NULL)
	{
	  fprintf(console,"Version:\t%s\n",vals[0]);
	  ldap_value_free(vals);
	}
    }
#endif

  switch(action)
    {
    case GET:
      keyptr=keylist;

      while(keyptr!=NULL)
	{
	  set_timeout(timeout);

	  if(get_key(keyptr->str)!=KEYSERVER_OK)
	    failed++;

	  keyptr=keyptr->next;
	}
      break;

    case SEND:
      {
	int eof=0;

	do
	  {
	    set_timeout(timeout);

	    if(send_key(&eof)!=KEYSERVER_OK)
	      failed++;
	  }
	while(!eof);
      }
      break;

    case SEARCH:
      {
	char *searchkey=NULL;
	int len=0;

	set_timeout(timeout);

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
	    fail_all(keylist,action,KEYSERVER_NO_MEMORY);
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

      break;
    }

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

  return ret;
}
