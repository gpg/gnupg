/* gpgkeys_ldap.c - talk to a LDAP keyserver
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
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ldap.h>
#include "keyserver.h"

#ifdef __riscos__
#include <unixlib/local.h>
#endif

#define GET    0
#define SEND   1
#define SEARCH 2
#define MAX_LINE 80

int verbose=0,include_disabled=0,include_revoked=0;
char *basekeyspacedn=NULL;
char host[80];
FILE *input=NULL,*output=NULL,*console=NULL;

struct keylist
{
  char str[MAX_LINE];
  struct keylist *next;
};

/* Returns 0 on success, -1 on failure, and 1 on eof */
int send_key(LDAP *ldap,char *keyid)
{
  int err,gotit=0,keysize=1,ret=-1;
  char *dn=NULL;
  char line[MAX_LINE];
  char *key[2]={0,0};
#ifndef __riscos__
  LDAPMod mod={LDAP_MOD_ADD,"pgpKeyV2",{key}},*attrs[2]={&mod,NULL};
#else
  LDAPMod mod, *attrs[2];
  
  mod.mod_op      = LDAP_MOD_ADD;
  mod.mod_type    = "pgpKeyV2";
  mod.mod_values  = 0;
  mod.mod_bvalues = 0;
  
  attrs[0]    = &mod;
  attrs[1]    = NULL;
#endif

  dn=malloc(strlen("pgpCertid=virtual,")+strlen(basekeyspacedn)+1);
  if(dn==NULL)
    {
      fprintf(console,"gpgkeys: can't allocate memory for keyserver record\n");
      goto fail;
    }

  strcpy(dn,"pgpCertid=virtual,");
  strcat(dn,basekeyspacedn);

  key[0]=malloc(1);
  if(key[0]==NULL)
    {
      fprintf(console,"gpgkeys: unable to allocate memory for key\n");
      goto fail;
    }

  key[0][0]='\0';

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
	keysize+=strlen(line);
	key[0]=realloc(key[0],keysize);
	if(key[0]==NULL)
	  {
	    fprintf(console,"gpgkeys: unable to reallocate for key\n");
	    goto fail;
	  }

	strcat(key[0],line);
      }

  if(!gotit)
    {
      fprintf(console,"gpgkeys: no KEY %s END found\n",keyid);
      goto fail;
    }

  err=ldap_add_s(ldap,dn,attrs);
  if(err!=LDAP_SUCCESS)
    {
      fprintf(console,"gpgkeys: error adding key %s to keyserver: %s\n",
	      keyid,ldap_err2string(err));
      goto fail;
    }

  ret=0;

 fail:

  free(key[0]);
  free(dn);

  return ret;
}

int get_key(LDAP *ldap,char *getkey)
{
  char **vals;
  LDAPMessage *res,*each;
  int ret=-1,err,count;
  struct keylist *dupelist=NULL;
  char search[29];
  char *attrs[]={"pgpKeyV2","pgpuserid","pgpkeyid","pgpcertid","pgprevoked",
		 "pgpdisabled","pgpkeycreatetime","modifytimestamp",
		 "pgpkeysize","pgpkeytype",NULL};

  /* Build the search string */

  if(strncmp(getkey,"0x00000000",10)==0)
    {
      getkey+=10;
      sprintf(search,"(pgpkeyid=%.8s)",getkey);
    }
  else
    {
      getkey+=2;
      sprintf(search,"(pgpcertid=%.16s)",getkey);
    }

  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

  if(verbose>2)
    fprintf(console,"gpgkeys: LDAP fetch for: %s\n",search);

  if(!verbose)
    attrs[1]=NULL;

  fprintf(console,"gpgkeys: requesting key %s from LDAP keyserver %s\n",
	  getkey,host);

  err=ldap_search_s(ldap,basekeyspacedn,
		    LDAP_SCOPE_SUBTREE,search,attrs,0,&res);
  if(err!=0)
    {
      fprintf(console,"gpgkeys: LDAP search error: %s\n",ldap_err2string(err));
      fprintf(output,"KEY 0x%s FAILED\n",getkey);
      return -1;
    }

  count=ldap_count_entries(ldap,res);
  if(count<1)
    {
      fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
      fprintf(output,"KEY 0x%s FAILED\n",getkey);
      goto fail;
    }

  /* There may be more than one unique result for a given keyID, so we
     should fetch them all (test this by fetching short key id
     0xDEADBEEF). */

  each=ldap_first_entry(ldap,res);
  while(each!=NULL)
    {
      struct keylist *keyptr=dupelist;

      /* Use the long keyid to remove duplicates.  The LDAP server
	 returns the same keyid more than once if there are multiple
	 user IDs on the key. */

      vals=ldap_get_values(ldap,each,"pgpcertid");
      if(vals!=NULL)
	{
	  while(keyptr!=NULL)
	    {
	      if(strcasecmp(keyptr->str,vals[0])==0)
		break;

	      keyptr=keyptr->next;
	    }

	  if(!keyptr)
	    {
	      /* it's not a duplicate, so add it */

	      keyptr=malloc(sizeof(struct keylist));
	      if(keyptr==NULL)
		{
		  fprintf(console,"gpgkeys: out of memory when deduping "
			  "key list\n");
		  goto fail;
		}

	      strncpy(keyptr->str,vals[0],MAX_LINE);
	      keyptr->str[MAX_LINE-1]='\0';

	      keyptr->next=dupelist;
	      dupelist=keyptr;
	      keyptr=NULL;
	    }

	  ldap_value_free(vals);
	}

      if(!keyptr) /* it's not a duplicate */
	{
	  if(verbose)
	    {
	      vals=ldap_get_values(ldap,each,"pgpuserid");
	      if(vals!=NULL)
		{
		  /* This is wrong, as the user ID is UTF8.  A better way to
		     handle this would be to send it over to gpg and display
		     it on that side of the pipe. */
		  fprintf(console,"\nUser ID:\t%s\n",vals[0]);
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"pgprevoked");
	      if(vals!=NULL)
		{
		  if(atoi(vals[0])==1)
		    fprintf(console,"\t\t** KEY REVOKED **\n");
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"pgpdisabled");
	      if(vals!=NULL)
		{
		  if(atoi(vals[0])==1)
		    fprintf(console,"\t\t** KEY DISABLED **\n");
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"pgpkeyid");
	      if(vals!=NULL)
		{
		  fprintf(console,"Short key ID:\t%s\n",vals[0]);
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"pgpcertid");
	      if(vals!=NULL)
		{
		  fprintf(console,"Long key ID:\t%s\n",vals[0]);
		  ldap_value_free(vals);
		}

	      /* YYYYMMDDHHmmssZ */

	      vals=ldap_get_values(ldap,each,"pgpkeycreatetime");
	      if(vals!=NULL && strlen(vals[0])==15)
		{
		  fprintf(console,"Key created:\t%.2s/%.2s/%.4s\n",
			  &vals[0][4],&vals[0][6],vals[0]);
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"modifytimestamp");
	      if(vals!=NULL && strlen(vals[0])==15)
		{
		  fprintf(console,"Key modified:\t%.2s/%.2s/%.4s\n",
			  &vals[0][4],&vals[0][6],vals[0]);
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"pgpkeysize");
	      if(vals!=NULL)
		{
		  fprintf(console,"Key size:\t%d\n",atoi(vals[0]));
		  ldap_value_free(vals);
		}

	      vals=ldap_get_values(ldap,each,"pgpkeytype");
	      if(vals!=NULL)
		{
		  fprintf(console,"Key type:\t%s\n",vals[0]);
		  ldap_value_free(vals);
		}
	    }

	  vals=ldap_get_values(ldap,each,"pgpKeyV2");
	  if(vals==NULL)
	    {
	      fprintf(console,"gpgkeys: unable to retrieve key %s "
		      "from keyserver\n",getkey);
	      fprintf(output,"KEY 0x%s FAILED\n",getkey);
	    }
	  else
	    {
	      fprintf(output,"%sKEY 0x%s END\n",vals[0],getkey);

	      ldap_value_free(vals);
	    }
	}

      each=ldap_next_entry(ldap,each);
    }

  ret=0;

 fail:
  ldap_msgfree(res);

  /* free up the dupe checker */
  while(dupelist!=NULL)
    {
      struct keylist *keyptr=dupelist;

      dupelist=keyptr->next;
      free(keyptr);
    }

  return ret;
}

time_t ldap2epochtime(const char *timestr)
{
  struct tm pgptime;

  memset(&pgptime,0,sizeof(pgptime));

  /* YYYYMMDDHHmmssZ */

  sscanf(timestr,"%4d%2d%2d%2d%2d%2d",
	 &pgptime.tm_year,
	 &pgptime.tm_mon,
	 &pgptime.tm_mday,
	 &pgptime.tm_hour,
	 &pgptime.tm_min,
	 &pgptime.tm_sec);

  pgptime.tm_year-=1900;
  pgptime.tm_isdst=-1;
  pgptime.tm_mon--;

  return mktime(&pgptime);
}

void printquoted(FILE *stream,char *string,char delim)
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

int search_key(LDAP *ldap,char *searchkey)
{
  char **vals;
  LDAPMessage *res,*each;
  int err,count;
  /* The maxium size of the search, including the optional stuff and
     the trailing \0 */
  char search[2+12+MAX_LINE+2+15+14+1+1];
  char *attrs[]={"pgpcertid","pgpuserid","pgprevoked","pgpdisabled",
		 "pgpkeycreatetime","pgpkeyexpiretime","modifytimestamp",
		 "pgpkeysize","pgpkeytype",NULL};

  fprintf(output,"SEARCH %s BEGIN\n",searchkey);

  /* Build the search string */

  sprintf(search,"%s(pgpuserid=*%s*)%s%s%s",
	  (!(include_disabled&&include_revoked))?"(&":"",
	  searchkey,
	  include_disabled?"":"(pgpdisabled=0)",
	  include_revoked?"":"(pgprevoked=0)",
	  !(include_disabled&&include_revoked)?")":"");

  if(verbose>2)
    fprintf(console,"gpgkeys: LDAP search for: %s\n",search);

  fprintf(console,("gpgkeys: searching for \"%s\" from LDAP server %s\n"),
	  searchkey,host);

  err=ldap_search_s(ldap,basekeyspacedn,
		    LDAP_SCOPE_SUBTREE,search,attrs,0,&res);
  if(err!=0)
    {
      fprintf(console,"gpgkeys: LDAP search error: %s\n",ldap_err2string(err));
      return -1;
    }

  count=ldap_count_entries(ldap,res);

  if(count<1)
    fprintf(output,"COUNT 0\n");
  else
    {
      fprintf(output,"COUNT %d\n",count);

      each=ldap_first_entry(ldap,res);
      while(each!=NULL)
	{
	  int flags=0;

	  vals=ldap_get_values(ldap,each,"pgpcertid");
	  if(vals!=NULL)
	    {
	      fprintf(output,"%s:",vals[0]);
	      ldap_value_free(vals);
	    }
	  else
	    fputc(':',output);

	  vals=ldap_get_values(ldap,each,"pgpuserid");
	  if(vals!=NULL)
	    {
	      /* Need to escape any colons */
	      printquoted(output,vals[0],':');
	      fputc(':',output);
	      ldap_value_free(vals);
	    }
	  else
	    fputc(':',output);

	  vals=ldap_get_values(ldap,each,"pgprevoked");
	  if(vals!=NULL)
	    {
	      if(atoi(vals[0])==1)
		flags|=1;
	      ldap_value_free(vals);
	    }

	  vals=ldap_get_values(ldap,each,"pgpdisabled");
	  if(vals!=NULL)
	    {
	      if(atoi(vals[0])==1)
		flags|=2;
	      ldap_value_free(vals);
	    }

	  fprintf(output,"%d:",flags);

	  /* YYYYMMDDHHmmssZ */

	  vals=ldap_get_values(ldap,each,"pgpkeycreatetime");
	  if(vals!=NULL && strlen(vals[0])==15)
	    {
	      fprintf(output,"%u:",(unsigned int)ldap2epochtime(vals[0]));
	      ldap_value_free(vals);
	    }
	  else
	    fputc(':',output);

	  vals=ldap_get_values(ldap,each,"pgpkeyexpiretime");
	  if(vals!=NULL && strlen(vals[0])==15)
	    {
	      fprintf(output,"%u:",(unsigned int)ldap2epochtime(vals[0]));
	      ldap_value_free(vals);
	    }
	  else
	    fputc(':',output);

	  vals=ldap_get_values(ldap,each,"modifytimestamp");
	  if(vals!=NULL && strlen(vals[0])==15)
	    {
	      fprintf(output,"%u:",(unsigned int)ldap2epochtime(vals[0]));
	      ldap_value_free(vals);
	    }
	  else
	    fputc(':',output);

	  vals=ldap_get_values(ldap,each,"pgpkeytype");
	  if(vals!=NULL)
	    {
	      fprintf(output,"%s:",vals[0]);
	      ldap_value_free(vals);
	    }
	  else
	    fputc(':',output);

	  vals=ldap_get_values(ldap,each,"pgpkeysize");
	  if(vals!=NULL)
	    {
	      /* Not sure why, but some keys are listed with a key size of
		 0.  Treat that like an unknown. */
	      if(atoi(vals[0])>0)
		fprintf(output,"%d",atoi(vals[0]));
	      ldap_value_free(vals);
	    }

	  fputc('\n',output);

	  each=ldap_next_entry(ldap,each);
	}
    }

  ldap_msgfree(res);

  fprintf(output,"SEARCH %s END\n",searchkey);

  return 0;
}

int main(int argc,char *argv[])
{
  LDAP *ldap=NULL;
  int port=0,arg,err,action=-1,ret=KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE],**vals;
  int version;
  char *attrs[]={"basekeyspacedn","version","software",NULL};
  LDAPMessage *res;
  struct keylist *keylist=NULL,*keyptr=NULL;

#ifdef __riscos__
    __riscosify_control = __RISCOSIFY_NO_PROCESS;
#endif

  console=stderr;

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

  ldap=ldap_init(host,port);
  if(ldap==NULL)
    {
      fprintf(console,"gpgkeys: internal LDAP init error: %s\n",strerror(errno));
      goto fail;
    }

  err=ldap_simple_bind_s(ldap,NULL,NULL);
  if(err!=0)
    {
      fprintf(console,"gpgkeys: internal LDAP bind error: %s\n",
	      ldap_err2string(err));
      goto fail;
    }

  /* Get the magic info record */

  err=ldap_search_s(ldap,"cn=PGPServerInfo",LDAP_SCOPE_BASE,
		    "(objectclass=*)",attrs,0,&res);
  if(err==-1)
    {
      fprintf(console,"gpgkeys: error retrieving LDAP server info: %s\n",
	      ldap_err2string(err));
      goto fail;
    }

  if(ldap_count_entries(ldap,res)!=1)
    {
      fprintf(console,"gpgkeys: more than one serverinfo record\n");
      goto fail;
    }

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

  /* This is always "OU=ACTIVE,O=PGP KEYSPACE,C=US", but it might not
     be in the future. */

  vals=ldap_get_values(ldap,res,"basekeyspacedn");
  if(vals!=NULL)
    {
      basekeyspacedn=strdup(vals[0]);
      if(basekeyspacedn==NULL)
	{
	  fprintf(console,"gpgkeys: can't allocate string space "
		  "for LDAP base\n");
	  goto fail;
	}

      ldap_value_free(vals);
    }

  ldap_msgfree(res);

  switch(action)
    {
    case GET:
      keyptr=keylist;

      while(keyptr!=NULL)
	{
	  struct keylist *current=keyptr;

	  get_key(ldap,current->str);

	  keyptr=current->next;

	  /* Free it as we go */
	  free(current);
	}
      break;

    case SEND:
      {
	char keyid[17]="????";
	int ret;

	while((ret=send_key(ldap,keyid))!=1)
	  {
	    if(ret!=0)
	      fprintf(output,"KEY %s FAILED\n",keyid);
	  }
      }
      break;

    case SEARCH:
      {
	char *searchkey=NULL;
	int len=0;

	/* To search, we stick a * in between each key to search for.
	   This means that if the user enters words, they'll get
	   "enters*words".  If the user "enters words", they'll get
	   "enters words" */

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
	    struct keylist *current=keyptr;

	    strcat(searchkey,current->str);
	    strcat(searchkey,"*");
	    keyptr=current->next;

	    /* Free it as we go */
	    free(current);
	  }

	/* Nail that last "*" */
	searchkey[strlen(searchkey)-1]='\0';

	if(search_key(ldap,searchkey)==-1)
	  fprintf(output,"SEARCH %s FAILED\n",searchkey);

	free(searchkey);
      }

      break;
    }

  ret=KEYSERVER_OK;

 fail:

  if(input!=stdin)
    fclose(input);

  if(output!=stdout)
    fclose(output);

  if(ldap!=NULL)
    ldap_unbind_s(ldap);

  free(basekeyspacedn);

  return ret;
}
