/* gpgkeys_hkp.c - talk to an HKP keyserver
 * Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

extern char *optarg;
extern int optind;

#define GET    0
#define SEND   1
#define SEARCH 2
#define MAX_LINE 80

int verbose=0,include_revoked=0;
unsigned int http_flags=0;
char host[80]={'\0'},port[10]={'\0'};
FILE *input=NULL,*output=NULL,*console=NULL;

struct keylist
{
  char str[MAX_LINE];
  struct keylist *next;
};

#ifdef __riscos__
RISCOS_GLOBAL_STATICS("HKP Keyfetcher Heap")
#endif /* __riscos__ */

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

/* Returns 0 on success, -1 on failure, and 1 on eof */
int send_key(void)
{
  int rc,begin=0,end=0,ret=-1;
  char keyid[17];
  char *request;
  struct http_context hd;
  unsigned int status;
  IOBUF temp = iobuf_temp();
  char line[MAX_LINE];

  memset(&hd,0,sizeof(hd));

  request=malloc(strlen(host)+100);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return -1;
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
      /* i.e. eof before the KEY BEGIN was found */
      ret=1;
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
      goto fail;
    }

  iobuf_flush_temp(temp);

  sprintf(request,"x-hkp://%s%s%s/pks/add",
	  host,port[0]?":":"",port[0]?port:"");

  if(verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is \"%s\"\n",request);

  rc=http_open(&hd,HTTP_REQ_POST,request,http_flags);
  if(rc)
    {
      fprintf(console,"gpgkeys: unable to connect to `%s'\n",host);
      goto fail;
    }

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

  ret=0;

 fail:
  free(request);
  iobuf_close(temp);
  http_close(&hd);

  if(ret!=0 && begin)
    fprintf(output,"KEY %s FAILED\n",keyid);

  return ret;
}

int get_key(char *getkey)
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
      fprintf(output,"KEY 0x%s FAILED\n",getkey);
      return -1;
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

  if(verbose)
    fprintf(console,"gpgkeys: requesting key 0x%s from hkp://%s%s%s\n",
	    getkey,host,port[0]?":":"",port[0]?port:"");

  request=malloc(strlen(host)+100);
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return -1;
    }

  sprintf(request,"x-hkp://%s%s%s/pks/lookup?op=get&search=%s",
	  host,port[0]?":":"",port[0]?port:"", search);

  if(verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is \"%s\"\n",request);

  rc=http_open_document(&hd,request,http_flags);
  if(rc!=0)
    {
      fprintf(console,"gpgkeys: HKP fetch error: %s\n",
	      rc==G10ERR_NETWORK?strerror(errno):g10_errstr(rc));
      fprintf(output,"KEY 0x%s FAILED\n",getkey);
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
	      fputs (line, output);
	      if(strcmp(line,"-----END PGP PUBLIC KEY BLOCK-----\n")==0)
		break;
	    }
	  else
	    if(strcmp(line,"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")==0)
	      {
		fputs (line, output);
		gotit=1;
	      }
	}

      if(gotit)
	fprintf(output,"KEY 0x%s END\n",getkey);
      else
	{
	  fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
	  fprintf(output,"KEY 0x%s FAILED\n",getkey);
	}

      m_free(line);
    }

  free(request);

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
      while(isspace(((unsigned char *)parsed)[parsedindex]))
	{
	  parsed[parsedindex]='\0';
	  if(parsedindex==0)
	    break;
	  parsedindex--;
	}
    }
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

/* pub  2048/<a href="/pks/lookup?op=get&search=0x3CB3B415">3CB3B415</a> 1998/04/03 David M. Shaw &lt;<a href="/pks/lookup?op=get&search=0x3CB3B415">dshaw@jabberwocky.com</a>&gt; */

/* Luckily enough, both the HKP server and NAI HKP interface to their
   LDAP server are close enough in output so the same function can
   parse them both. */

static int 
parse_hkp_index(IOBUF buffer,char *line)
{
  static int open=0,revoked=0;
  static char *key=NULL,*type=NULL,*uid=NULL;
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
      free(key);
      free(uid);
      fprintf(console,"gpgkeys: this keyserver does not support searching\n");
      return -1;
    }

  /* For multiple UIDs */
  if(open && uid!=NULL)
    {
      ret=0;

      if(!(revoked && !include_revoked))
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
	  free(key);
	  free(uid);
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
      if(tok==NULL || strlen(tok)==0)
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

      key=strdup(tok);

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
	  uid=strdup("Key index corrupted");
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

      uid=strdup(line);
    }

  return ret;
}

int search_key(char *searchkey)
{
  int max=0,len=0,ret=-1,rc;
  struct http_context hd;
  char *search=NULL,*request=searchkey;

  fprintf(output,"SEARCH %s BEGIN\n",searchkey);

  /* Build the search string.  It's going to need url-encoding. */

  while(*request!='\0')
    {
      if(max-len<3)
	{
	  max+=100;
	  search=realloc(search,max+1); /* Note +1 for \0 */
          if (!search)
            {
              fprintf(console,"gpgkeys: out of memory\n");
              return -1;
            }
	}

      if(isalnum(*request) || *request=='-')
	search[len++]=*request;
      else if(*request==' ')
	search[len++]='+';
      else
	{
	  sprintf(&search[len],"%%%02X",*request);
	  len+=3;
	}

      request++;
    }

  if(!search)
    {
      fprintf(console,"gpgkeys: corrupt input?\n");
      return -1;
    }

  search[len]='\0';

  fprintf(console,("gpgkeys: searching for \"%s\" from HKP server %s\n"),
	  searchkey,host);

  request=malloc(strlen(host)+100+strlen(search));
  if(!request)
    {
      fprintf(console,"gpgkeys: out of memory\n");
      return -1;
    }

  sprintf(request,"x-hkp://%s%s%s/pks/lookup?op=index&search=%s",
	  host,port[0]?":":"",port[0]?port:"",search);

 if(verbose>2)
    fprintf(console,"gpgkeys: HTTP URL is \"%s\"\n",request);

  rc=http_open_document(&hd,request,http_flags);
  if(rc)
    {
      fprintf(console,"gpgkeys: can't search keyserver `%s': %s\n",
	      host,rc==G10ERR_NETWORK?strerror(errno):g10_errstr(rc));
    }
  else
    {
      unsigned int buflen;
      int count=1;
      IOBUF buffer;
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
	fprintf(output,"COUNT %d\n%s",count,iobuf_get_temp_buffer(buffer));

      fprintf(output,"SEARCH %s END\n",searchkey);

      iobuf_close(buffer);
      m_free(line);

      ret=0;
    }

  free(request);
  free(search);

  return ret;
}

int main(int argc,char *argv[])
{
  int arg,action=-1,ret=KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE];
  int failed=0;
  struct keylist *keylist=NULL,*keyptr=NULL;

#ifdef __riscos__
  riscos_global_defaults();
#endif

  console=stderr;

  fprintf(console,
	  "gpgkeys: WARNING: this is an *experimental* HKP interface!\n");

  while((arg=getopt(argc,argv,"hVo:"))!=-1)
    switch(arg)
      {
      default:
      case 'h':
	fprintf(console,"-h\thelp\n");
	fprintf(console,"-V\tversion\n");
	fprintf(console,"-o\toutput to this file\n");
	return KEYSERVER_OK;

      case 'V':
	fprintf(stdout,"0\n%s\n",VERSION);
	return KEYSERVER_OK;

      case 'o':
	output=fopen(optarg,"w");
	if(output==NULL)
	  {
	    fprintf(console,"gpgkeys: Cannot open output file \"%s\": %s\n",
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
	  fprintf(console,"gpgkeys: Cannot open input file \"%s\": %s\n",
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
      char commandstr[7];
      char optionstr[30];
      char hash;

      if(line[0]=='\n')
	break;

      if(sscanf(line,"%c",&hash)==1 && hash=='#')
	continue;

      if(sscanf(line,"COMMAND %6s\n",commandstr)==1)
	{
	  commandstr[6]='\0';

	  if(strcasecmp(commandstr,"get")==0)
	    action=GET;
	  else if(strcasecmp(commandstr,"send")==0)
	    action=SEND;
	  else if(strcasecmp(commandstr,"search")==0)
	    action=SEARCH;

	  continue;
	}

      if(sscanf(line,"HOST %79s\n",host)==1)
	{
	  host[79]='\0';
	  continue;
	}

      if(sscanf(line,"PORT %9s\n",port)==1)
	{
	  port[9]='\0';
	  continue;
	}

      if(sscanf(line,"VERSION %d\n",&version)==1)
	{
	  if(version!=0)
	    {
	      ret=KEYSERVER_VERSION_ERROR;
	      goto fail;
	    }

	  continue;
	}

      if(sscanf(line,"OPTION %29s\n",optionstr)==1)
	{
	  int no=0;
	  char *start=&optionstr[0];

	  optionstr[29]='\0';

	  if(strncasecmp(optionstr,"no-",3)==0)
	    {
	      no=1;
	      start=&optionstr[3];
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
	  else if(strcasecmp(start,"honor-http-proxy")==0)
	    {
	      if(no)
		http_flags&=~HTTP_FLAG_TRY_PROXY;
	      else
		http_flags|=HTTP_FLAG_TRY_PROXY;

	    }
	  else if(strcasecmp(start,"broken-http-proxy")==0)
	    {
	      if(no)
		http_flags&=~HTTP_FLAG_NO_SHUTDOWN;
	      else
		http_flags|=HTTP_FLAG_NO_SHUTDOWN;
	    }

	  continue;
	}
    }

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

  fprintf(output,"VERSION 0\n");
  fprintf(output,"PROGRAM %s\n\n",VERSION);

  if(verbose>1)
    {
      fprintf(console,"Host:\t\t%s\n",host);
      if(port[0])
	fprintf(console,"Port:\t\t%s\n",port);
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
	  if(get_key(keyptr->str)==-1)
	    failed++;

	  keyptr=keyptr->next;
	}
      break;

    case SEND:
      {
	int ret2;

	do
	  {
	    ret2=send_key();
	    if(ret2==-1)
	      failed++;
	  }
	while(ret2!=1);
      }
      break;

    case SEARCH:
      {
	char *searchkey=NULL;
	int len=0;

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
	  goto fail;

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

	if(search_key(searchkey)==-1)
	  {
	    fprintf(output,"SEARCH %s FAILED\n",searchkey);
	    failed++;
	  }

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
