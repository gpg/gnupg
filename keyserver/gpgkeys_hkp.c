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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include "keyserver.h"

#define GET    0
#define SEND   1
#define SEARCH 2
#define MAX_LINE 80

int verbose=0,include_disabled=0,include_revoked=0;
char *basekeyspacedn=NULL;
char host[80];
FILE *input=NULL,*output=NULL,*console=NULL,*server=NULL;

struct keylist
{
  char str[MAX_LINE];
  struct keylist *next;
};

int http_connect(const char *host,unsigned short port)
{
  int sock=-1;
  struct hostent *ent;
  struct sockaddr_in addr;

  sock=socket(AF_INET,SOCK_STREAM,0);
  if(sock==-1)
    {
      fprintf(console,"gpgkeys: internal socket error: %s\n",strerror(errno));
      goto fail;
    }

  ent=gethostbyname(host);
  if(ent==NULL)
    {
      fprintf(console,"gpgkeys: DNS error: %s\n",hstrerror(h_errno));
      goto fail;
    }

  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=*(int *)ent->h_addr_list[0];
  addr.sin_port=htons(port?port:11371);

  if(connect(sock,(struct sockaddr *)&addr,sizeof(addr))==-1)
    {
      fprintf(console,"gpgkeys: unable to contact keyserver: %s\n",
	      strerror(errno));
      goto fail;
    }

  server=fdopen(sock,"r+");
  if(server==NULL)
    {
      fprintf(console,"gpgkeys: unable to fdopen socket: %s\n",
	      strerror(errno));
      goto fail;
    }

  if(verbose>3)
    fprintf(console,"gpgkeys: HKP connect to %s:%d\n",host,port?port:11371);

  return 0;

 fail:
  if(sock>-1)
    close(sock);

  return -1;
}

void http_disconnect(void)
{
  if(verbose>3)
    fprintf(console,"gpgkeys: HKP disconnect from %s\n",host);

  fclose(server);
}

int http_get(const char *op,const char *search)
{
  fprintf(server,"GET /pks/lookup?op=%s&search=%s HTTP/1.0\n\n",op,search);

  if(verbose>2)
    fprintf(console,"gpgkeys: HTTP GET /pks/lookup?op=%s&search=%s HTTP/1.0\n",
	    op,search);

  return 0;
}

int http_post(const char *data)
{
  char line[MAX_LINE];
  int result;

  fprintf(server,
	  "POST /pks/add HTTP/1.0\n"
	  "Content-type: application/x-www-form-urlencoded\n"
	  "Content-Length: %d\n\n%s",strlen(data),data);

  if(verbose>2)
    fprintf(console,
	    "gpgkeys: HTTP POST /pks/add HTTP/1.0\n"
	    "gpgkeys: Content-type: application/x-www-form-urlencoded\n"
	    "gpgkeys: Content-Length: %d\n\n",strlen(data));

  /* Now wait for a response */

  while(fgets(line,MAX_LINE,server)!=NULL)
    if(sscanf(line,"HTTP/%*f %d OK",&result)==1)
      return result;

  return -1;
}

/* Returns 0 on success, -1 on failure, and 1 on eof */
int send_key(void)
{
  int err,gotit=0,keylen,maxlen,ret=-1;
  char keyid[17],line[MAX_LINE],*key;

  key=strdup("keytext=");
  if(key==NULL)
    {
      fprintf(console,"gpgkeys: unable to allocate for key\n");
      goto fail;
    }

  maxlen=keylen=strlen(key);

  /* Read and throw away stdin until we see the BEGIN */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"KEY %16s BEGIN\n",keyid)==1)
      {
	gotit=1;
	break;
      }

  if(!gotit)
    {
      /* i.e. eof before the KEY BEGIN was found */
      ret=1;
      goto fail;
    }

  gotit=0;

  /* Now slurp up everything until we see the END */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"KEY %16s END\n",keyid)==1)
      {
	gotit=1;
	break;
      }
    else
      {
	char *c=line;

	while(*c!='\0')
	  {
	    if(maxlen-keylen<4)
	      {
		maxlen+=1024;
		key=realloc(key,maxlen);
		if(key==NULL)
		  {
		    fprintf(console,"gpgkeys: unable to reallocate for key\n");
		    goto fail;
		  }
	      }

	    if(isalnum(*c) || *c=='-')
	      {
		key[keylen++]=*c;
		key[keylen]='\0';
	      }
	    else if(*c==' ')
	      {
		key[keylen++]='+';
		key[keylen]='\0';
	      }
	    else
	      {
		sprintf(&key[keylen],"%%%02X",*c);
		keylen+=3;
	      }

	    c++;
	  }
      }

  if(!gotit)
    {
      fprintf(console,"gpgkeys: no KEY %s END found\n",keyid);
      goto fail;
    }

  err=http_post(key);
  if(err!=200)
    {
      fprintf(console,"gpgkeys: remote server returned error %d\n",err);
      goto fail;
    }

  ret=0;

 fail:

  free(key);

  if(ret!=0)
    fprintf(output,"KEY %s FAILED\n",keyid);

  return ret;
}

int get_key(char *getkey)
{
  int err,gotit=0;
  char search[29],line[MAX_LINE];

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

  if(verbose>2)
    fprintf(console,"gpgkeys: HKP fetch for: %s\n",search);

  fprintf(console,"gpgkeys: requesting key 0x%s from HKP keyserver %s\n",
	  getkey,host);

  err=http_get("get",search);
  if(err!=0)
    {
      fprintf(console,"gpgkeys: HKP fetch error: %s\n",strerror(errno));
      fprintf(output,"KEY 0x%s FAILED\n",getkey);
      return -1;
    }

  while(fgets(line,MAX_LINE,server))
    {
      if(gotit)
	{
	  fprintf(output,line);
	  if(strcmp(line,"-----END PGP PUBLIC KEY BLOCK-----\n")==0)
	    {
	      gotit=0;
	      fprintf(output,"KEY 0x%s END\n",getkey);
	      break;
	    }
	}
      else
	if(strcmp(line,"-----BEGIN PGP PUBLIC KEY BLOCK-----\n")==0)
	  {
	    fprintf(output,line);
	    gotit=1;
	  }
    }

  return 0;
}

void print_quoted(FILE *stream,char *string,char delim)
{
  while(*string)
    {
      if(*string==delim)
	fprintf(stream,"\\x%02X",*string);
      else
	fputc(*string,stream);

      string++;
    }
}

void append_quoted(char *buffer,char *string,char delim)
{
  while(*buffer)
    buffer++;

  while(*string)
    {
      if(*string==delim)
	{
	  sprintf(buffer,"\\x%02X",*string);
	  buffer+=4;
	}
      else
	*buffer=*string;

      buffer++;
      string++;
    }

  *buffer='\0';
}

unsigned int scan_isodatestr( const char *string )
{
  int year, month, day;
  struct tm tmbuf;
  time_t stamp;
  int i;

  if( strlen(string) != 10 || string[4] != '-' || string[7] != '-' )
    return 0;
  for( i=0; i < 4; i++ )
    if( !isdigit(string[i]) )
      return 0;
  if( !isdigit(string[5]) || !isdigit(string[6]) )
    return 0;
  if( !isdigit(string[8]) || !isdigit(string[9]) )
    return 0;
  year = atoi(string);
  month = atoi(string+5);
  day = atoi(string+8);
  /* some basic checks */
  if( year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 )
    return 0;
  memset( &tmbuf, 0, sizeof tmbuf );
  tmbuf.tm_mday = day;
  tmbuf.tm_mon = month-1;
  tmbuf.tm_year = year - 1900;
  tmbuf.tm_isdst = -1;
  stamp = mktime( &tmbuf );
  if( stamp == (time_t)-1 )
    return 0;
  return stamp;
}

/* pub  2048/<a href="/pks/lookup?op=get&search=0x3CB3B415">3CB3B415</a> 1998/04/03 David M. Shaw &lt;<a href="/pks/lookup?op=get&search=0x3CB3B415">dshaw@jabberwocky.com</a>&gt; */

/* Luckily enough, both the HKP server and NAI HKP interface to their
   LDAP server are close enough in output so the same function can
   parse them both. */

int parse_hkp_index(char *line,char **buffer)
{
  static int open=0,revoked=0;
  static char *key,*uid;
  static unsigned int bits,createtime;
  int ret=0;

  /* printf("Open %d, LINE: %s\n",open,line); */

  /* For multiple UIDs */
  if(open && uid!=NULL)
    {
      ret=0;

      if(!(revoked && !include_revoked))
	{
	  char intstr[11],*buf;

	  buf=realloc(*buffer,
		      (*buffer?strlen(*buffer):0)+
		      (strlen(key)*4)+
		      1+
		      (strlen(uid)*4)
		      +1
		      +2
		      +10
		      +4
		      +10
		      +1
		      +1);

	  if(buf)
	    *buffer=buf;
	  else
	    return -1;

	  append_quoted(*buffer,key,':');
	  append_quoted(*buffer,":",0);
	  append_quoted(*buffer,uid,':');
	  append_quoted(*buffer,":",0);
	  append_quoted(*buffer,revoked?"1:":":",0);
	  sprintf(intstr,"%u",createtime);
	  append_quoted(*buffer,intstr,':');
	  append_quoted(*buffer,"::::",0);
	  sprintf(intstr,"%u",bits);
	  append_quoted(*buffer,intstr,':');
	  append_quoted(*buffer,"\n",0);

	  ret=1;
	}

      if(strncmp(line,"     ",5)!=0)
	{
	  revoked=0;
	  free(key);
	  free(uid);
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
	{
	  key=strdup("00000000");
	  return ret;
	}

      key=strdup(tok);

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

      if(line==NULL)
	{
	  uid=strdup("Key index corrupted");
	  return ret;
	}

      /* All that's left is the user name.  Strip off anything
	 <between brackets> and de-urlencode it. */

      while(*line==' ' && *line!='\0')
	line++;

      if(strncmp(line,"*** KEY REVOKED ***",19)==0)
	{
	  revoked=1;
	  return ret;
	}

      uid=malloc(strlen(line)+1);

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

int search_key(char *searchkey)
{
  int ret=-1,err,count=0;
  char *search,*request,*buffer=NULL;
  char line[1024];
  int max,len;

  fprintf(output,"SEARCH %s BEGIN\n",searchkey);

  /* Build the search string.  It's going to need url-encoding. */

  max=0;
  len=0;
  search=NULL;
  request=searchkey;

  while(*request!='\0')
    {
      if(max-len<3)
	{
	  max+=100;
	  search=realloc(search,max+1); /* Note +1 for \0 */
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

  search[len]='\0';

  if(verbose>2)
    fprintf(console,"gpgkeys: HKP search for: %s\n",search);

  fprintf(console,("gpgkeys: searching for \"%s\" from HKP server %s\n"),
	  searchkey,host);

  http_get("index",search);

  free(search);

  while(fgets(line,1024,server))
    {
      err=parse_hkp_index(line,&buffer);
      if(err==-1)
	goto fail;

      count+=err;
    }

  fprintf(output,"COUNT %d\n%s",count,buffer);
  //  fprintf(output,"COUNT -1\n%s",buffer);

  fprintf(output,"SEARCH %s END\n",searchkey);

  ret=0;

 fail:
  free(buffer);

  return ret;
}

int main(int argc,char *argv[])
{
  int port=0,arg,action=-1,ret=KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE];
  int version,failed=0;
  struct keylist *keylist=NULL,*keyptr=NULL;

  console=stderr;

  fprintf(console,
	  "gpgkeys: Warning: this is an *experimental* HKP interface!\n");

  while((arg=getopt(argc,argv,"ho:"))!=-1)
    switch(arg)
      {
      default:
      case 'h':
	fprintf(console,"-h\thelp\n");
	fprintf(console,"-o\toutput to this file\n");
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
      char commandstr[7];
      char portstr[10];
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

      if(sscanf(line,"PORT %9s\n",portstr)==1)
	{
	  portstr[9]='\0';
	  port=atoi(portstr);
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
	  else if(strcasecmp(start,"include-disabled")==0)
	    {
	      if(no)
		include_disabled=0;
	      else
		include_disabled=1;
	    }
	  else if(strcasecmp(start,"include-revoked")==0)
	    {
	      if(no)
		include_revoked=0;
	      else
		include_revoked=1;
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
	      if(line[0]=='\n')
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
      if(port)
	fprintf(console,"Port:\t\t%d\n",port);
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
	  http_connect(host,port);

	  if(get_key(keyptr->str)==-1)
	    failed++;

	  http_disconnect();

	  keyptr=keyptr->next;
	}
      break;

    case SEND:
      {
	int ret;

	do
	  {
	    http_connect(host,port);
	    ret=send_key();
	    if(ret==-1)
	      failed++;
	    http_disconnect();
	  }
	while(ret!=1);
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
	searchkey[strlen(searchkey)-1]='\0';

	http_connect(host,port);

	if(search_key(searchkey)==-1)
	  {
	    fprintf(output,"SEARCH %s FAILED\n",searchkey);
	    failed++;
	  }

	http_disconnect();

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
