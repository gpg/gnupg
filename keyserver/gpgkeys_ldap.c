/* gpgkeys_ldap.c - talk to a LDAP keyserver
 * Copyright (C) 2001, 2002, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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
#include <time.h>
#include <unistd.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <winldap.h>
#else
#ifdef NEED_LBER_H
#include <lber.h>
#endif
/* For OpenLDAP, to enable the API that we're using. */
#define LDAP_DEPRECATED 1
#include <ldap.h>
#endif

/* For mozldap */
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif

#include "compat.h"
#include "keyserver.h"
#include "ksutil.h"

#ifdef __riscos__
#include "util.h"
#endif

extern char *optarg;
extern int optind;

static int real_ldap=0;
static char *basekeyspacedn=NULL;
static char *pgpkeystr="pgpKey";
static FILE *input=NULL,*output=NULL,*console=NULL;
static LDAP *ldap=NULL;
static struct ks_options *opt;

#ifndef HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif

static int
ldap_err_to_gpg_err(int err)
{
  int ret;

  switch(err)
    {
    case LDAP_ALREADY_EXISTS:
      ret=KEYSERVER_KEY_EXISTS;
      break;

    case LDAP_SERVER_DOWN:
      ret=KEYSERVER_UNREACHABLE;
      break;

    default:
      ret=KEYSERVER_GENERAL_ERROR;
      break;
    }

  return ret;
}

static int
ldap_to_gpg_err(LDAP *ld)
{
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)

  int err;

  if(ldap_get_option(ld,LDAP_OPT_ERROR_NUMBER,&err)==0)
    return ldap_err_to_gpg_err(err);
  else
    return KEYSERVER_GENERAL_ERROR;

#elif defined(HAVE_LDAP_LD_ERRNO)

  return ldap_err_to_gpg_err(ld->ld_errno);

#else

  /* We should never get here since the LDAP library should always
     have either ldap_get_option or ld_errno, but just in case... */
  return KEYSERVER_GENERAL_ERROR;

#endif
}

static int
key_in_keylist(const char *key,struct keylist *list)
{
  struct keylist *keyptr=list;

  while(keyptr!=NULL)
    {
      if(ascii_strcasecmp(key,keyptr->str)==0)
	return 1;

      keyptr=keyptr->next;
    }

  return 0;
}

static int
add_key_to_keylist(const char *key,struct keylist **list)
{
  struct keylist *keyptr=malloc(sizeof(struct keylist));

  if(keyptr==NULL)
    {
      fprintf(console,"gpgkeys: out of memory when deduping "
	      "key list\n");
      return KEYSERVER_NO_MEMORY;
    }

  strncpy(keyptr->str,key,MAX_LINE);
  keyptr->str[MAX_LINE-1]='\0';
  keyptr->next=*list;
  *list=keyptr;

  return 0;
}

static void
free_keylist(struct keylist *list)
{
  while(list!=NULL)
    {
      struct keylist *keyptr=list;

      list=keyptr->next;
      free(keyptr);
    }
}

static time_t
ldap2epochtime(const char *timestr)
{
  struct tm pgptime;
  time_t answer;

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

  /* mktime() takes the timezone into account, so we use timegm() */

  answer=timegm(&pgptime);

  return answer;
}

/* Caller must free */
static char *
epoch2ldaptime(time_t stamp)
{
  struct tm *ldaptime;
  char buf[16];

  ldaptime=gmtime(&stamp);

  ldaptime->tm_year+=1900;
  ldaptime->tm_mon++;

  /* YYYYMMDDHHmmssZ */

  sprintf(buf,"%04d%02d%02d%02d%02d%02dZ",
	  ldaptime->tm_year,
	  ldaptime->tm_mon,
	  ldaptime->tm_mday,
	  ldaptime->tm_hour,
	  ldaptime->tm_min,
	  ldaptime->tm_sec);

  return strdup(buf);
}

/* Append two onto the end of one.  Two is not freed, but its pointers
   are now part of one.  Make sure you don't free them both! */
static int
join_two_modlists(LDAPMod ***one,LDAPMod **two)
{
  int i,one_count=0,two_count=0;
  LDAPMod **grow;

  for(grow=*one;*grow;grow++)
    one_count++;

  for(grow=two;*grow;grow++)
    two_count++;

  grow=realloc(*one,sizeof(LDAPMod *)*(one_count+two_count+1));
  if(!grow)
    return 0;

  for(i=0;i<two_count;i++)
    grow[one_count+i]=two[i];

  grow[one_count+i]=NULL;

  *one=grow;

  return 1;
}

/* Passing a NULL for value effectively deletes that attribute.  This
   doesn't mean "delete" in the sense of removing something from the
   modlist, but "delete" in the LDAP sense of adding a modlist item
   that specifies LDAP_MOD_REPLACE and a null attribute for the given
   attribute.  LDAP_MOD_DELETE doesn't work here as we don't know if
   the attribute in question exists or not. */

static int
make_one_attr(LDAPMod ***modlist,char *attr,const char *value)
{
  LDAPMod **m;
  int nummods=0;

  /* Search modlist for the attribute we're playing with. */
  for(m=*modlist;*m;m++)
    {
      if(ascii_strcasecmp((*m)->mod_type,attr)==0)
	{
	  char **ptr=(*m)->mod_values;
	  int numvalues=0;

	  /* We have this attribute already, so when the REPLACE
	     happens, the server attributes will be replaced
	     anyway. */
	  if(!value)
	    return 1;

	  if(ptr)
	    for(ptr=(*m)->mod_values;*ptr;ptr++)
	      {
		/* Duplicate value */
		if(strcmp(*ptr,value)==0)
		  return 1;
		numvalues++;
	      }

	  ptr=realloc((*m)->mod_values,sizeof(char *)*(numvalues+2));
	  if(!ptr)
	    return 0;

	  (*m)->mod_values=ptr;
	  ptr[numvalues]=strdup(value);
	  if(!ptr[numvalues])
	    return 0;

	  ptr[numvalues+1]=NULL;
	  break;
	}

      nummods++;
    }

  /* We didn't find the attr, so make one and add it to the end */
  if(!*m)
    {
      LDAPMod **grow;

      grow=realloc(*modlist,sizeof(LDAPMod *)*(nummods+2));
      if(!grow)
	return 0;

      *modlist=grow;
      grow[nummods]=malloc(sizeof(LDAPMod));
      if(!grow[nummods])
	return 0;
      grow[nummods]->mod_op=LDAP_MOD_REPLACE;
      grow[nummods]->mod_type=attr;
      if(value)
	{
	  grow[nummods]->mod_values=malloc(sizeof(char *)*2);
	  if(!grow[nummods]->mod_values)
	    {
	      grow[nummods]=NULL;
	      return 0;
	    }

	  /* Is this the right thing?  Can a UTF8-encoded user ID have
	     embedded nulls? */
	  grow[nummods]->mod_values[0]=strdup(value);
	  if(!grow[nummods]->mod_values[0])
	    {
	      free(grow[nummods]->mod_values);
	      grow[nummods]=NULL;
	      return 0;
	    }

	  grow[nummods]->mod_values[1]=NULL;
	}
      else
	grow[nummods]->mod_values=NULL;

      grow[nummods+1]=NULL;
    }

  return 1;
}

static void
build_attrs(LDAPMod ***modlist,char *line)
{
  char *record;
  int i;

  /* Remove trailing whitespace */
  for(i=strlen(line);i>0;i--)
    if(ascii_isspace(line[i-1]))
      line[i-1]='\0';
    else
      break;

  if((record=strsep(&line,":"))==NULL)
    return;

  if (strcmp("pub",record)==0)
    {
      char *tok;
      int disabled=0,revoked=0;

      /* The long keyid */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(strlen(tok)==16)
	{
	  make_one_attr(modlist,"pgpCertID",tok);
	  make_one_attr(modlist,"pgpKeyID",&tok[8]);
	}
      else
	return;

      /* The primary pubkey algo */
      if((tok=strsep(&line,":"))==NULL)
	return;

      switch(atoi(tok))
	{
	case 1:
	  make_one_attr(modlist,"pgpKeyType","RSA");
	  break;

	case 17:
	  make_one_attr(modlist,"pgpKeyType","DSS/DH");
	  break;
	}

      /* Size of primary key */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(atoi(tok)>0)
	{
	  char padded[6];
	  int val=atoi(tok);

	  /* We zero pad this on the left to make PGP happy. */

	  if(val<99999 && val>0)
	    {
	      sprintf(padded,"%05u",atoi(tok));
	      make_one_attr(modlist,"pgpKeySize",padded);
	    }
	}

      /* pk timestamp */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(atoi(tok)>0)
	{
	  char *stamp=epoch2ldaptime(atoi(tok));
	  if(stamp)
	    {
	      make_one_attr(modlist,"pgpKeyCreateTime",stamp);
	      free(stamp);
	    }
	}

      /* pk expire */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(atoi(tok)>0)
	{
	  char *stamp=epoch2ldaptime(atoi(tok));
	  if(stamp)
	    {
	      make_one_attr(modlist,"pgpKeyExpireTime",stamp);
	      free(stamp);
	    }
	}

      /* flags */
      if((tok=strsep(&line,":"))==NULL)
	return;

      while(*tok)
	switch(*tok++)
	  {
	  case 'r':
	  case 'R':
	    revoked=1;
	    break;
	    
	  case 'd':
	  case 'D':
	    disabled=1;
	    break;
	  }

      /*
	Note that we always create the pgpDisabled and pgpRevoked
	attributes, regardless of whether the key is disabled/revoked
	or not.  This is because a very common search is like
	"(&(pgpUserID=*isabella*)(pgpDisabled=0))"
      */

      make_one_attr(modlist,"pgpDisabled",disabled?"1":"0");
      make_one_attr(modlist,"pgpRevoked",revoked?"1":"0");
    }
  else if (strcmp("sub",record)==0)
    {
      char *tok;

      /* The long keyid */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(strlen(tok)==16)
	make_one_attr(modlist,"pgpSubKeyID",tok);
      else
	return;

      /* The subkey algo */
      if((tok=strsep(&line,":"))==NULL)
	return;

      /* Size of subkey */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(atoi(tok)>0)
	{
	  char padded[6];
	  int val=atoi(tok);

	  /* We zero pad this on the left to make PGP happy. */

	  if(val<99999 && val>0)
	    {
	      sprintf(padded,"%05u",atoi(tok));
	      make_one_attr(modlist,"pgpKeySize",padded);
	    }
	}

      /* Ignore the rest of the items for subkeys since the LDAP
	 schema doesn't store them. */
    }
  else if (strcmp("uid",record)==0)
    {
      char *userid,*tok;

      /* The user ID string */
      if((tok=strsep(&line,":"))==NULL)
	return;

      if(strlen(tok)==0)
	return;

      userid=tok;

      /* By definition, de-%-encoding is always smaller than the
         original string so we can decode in place. */

      i=0;

      while(*tok)
	if(tok[0]=='%' && tok[1] && tok[2])
	  {
            int c;

	    userid[i] = (c=hextobyte(&tok[1])) == -1 ? '?' : c;
	    i++;
	    tok+=3;
	  }
	else
	  userid[i++]=*tok++;

      userid[i]='\0';

      /* We don't care about the other info provided in the uid: line
	 since the LDAP schema doesn't need it. */

      make_one_attr(modlist,"pgpUserID",userid);
    }
  else if(strcmp("sig",record)==0)
    {
      char *tok;

      if((tok=strsep(&line,":"))==NULL)
	return;

      if(strlen(tok)==16)
	make_one_attr(modlist,"pgpSignerID",tok);
    }
}

static void
free_mod_values(LDAPMod *mod)
{
  char **ptr;

  if(!mod->mod_values)
    return;

  for(ptr=mod->mod_values;*ptr;ptr++)
    free(*ptr);

  free(mod->mod_values);
}

static int
send_key(int *eof)
{
  int err,begin=0,end=0,keysize=1,ret=KEYSERVER_INTERNAL_ERROR;
  char *dn=NULL,line[MAX_LINE],*key=NULL;
  char keyid[17],state[6];
  LDAPMod **modlist,**addlist,**ml;

  modlist=malloc(sizeof(LDAPMod *));
  if(!modlist)
    {
      fprintf(console,"gpgkeys: can't allocate memory for keyserver record\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  *modlist=NULL;

  addlist=malloc(sizeof(LDAPMod *));
  if(!addlist)
    {
      fprintf(console,"gpgkeys: can't allocate memory for keyserver record\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  *addlist=NULL;

  /* Start by nulling out all attributes.  We try and do a modify
     operation first, so this ensures that we don't leave old
     attributes lying around. */
  make_one_attr(&modlist,"pgpDisabled",NULL);
  make_one_attr(&modlist,"pgpKeyID",NULL);
  make_one_attr(&modlist,"pgpKeyType",NULL);
  make_one_attr(&modlist,"pgpUserID",NULL);
  make_one_attr(&modlist,"pgpKeyCreateTime",NULL);
  make_one_attr(&modlist,"pgpSignerID",NULL);
  make_one_attr(&modlist,"pgpRevoked",NULL);
  make_one_attr(&modlist,"pgpSubKeyID",NULL);
  make_one_attr(&modlist,"pgpKeySize",NULL);
  make_one_attr(&modlist,"pgpKeyExpireTime",NULL);
  make_one_attr(&modlist,"pgpCertID",NULL);

  /* Assemble the INFO stuff into LDAP attributes */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"INFO%*[ ]%16s%*[ ]%5s\n",keyid,state)==2
       && strcmp(state,"BEGIN")==0)
      {
	begin=1;
	break;
      }

  if(!begin)
    {
      /* i.e. eof before the INFO BEGIN was found.  This isn't an
	 error. */
      *eof=1;
      ret=KEYSERVER_OK;
      goto fail;
    }

  if(strlen(keyid)!=16)
    {
      *eof=1;
      ret=KEYSERVER_KEY_INCOMPLETE;
      goto fail;
    }

  dn=malloc(strlen("pgpCertID=")+16+1+strlen(basekeyspacedn)+1);
  if(dn==NULL)
    {
      fprintf(console,"gpgkeys: can't allocate memory for keyserver record\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  sprintf(dn,"pgpCertID=%s,%s",keyid,basekeyspacedn);

  key=malloc(1);
  if(!key)
    {
      fprintf(console,"gpgkeys: unable to allocate memory for key\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  key[0]='\0';

  /* Now parse each line until we see the END */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"INFO%*[ ]%16s%*[ ]%3s\n",keyid,state)==2
       && strcmp(state,"END")==0)
      {
	end=1;
	break;
      }
    else
      build_attrs(&addlist,line);

  if(!end)
    {
      fprintf(console,"gpgkeys: no INFO %s END found\n",keyid);
      *eof=1;
      ret=KEYSERVER_KEY_INCOMPLETE;
      goto fail;
    }

  begin=end=0;

  /* Read and throw away stdin until we see the BEGIN */

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
      *eof=1;
      ret=KEYSERVER_OK;
      goto fail;
    }

  /* Now slurp up everything until we see the END */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"KEY%*[ ]%16s%*[ ]%3s\n",keyid,state)==2
       && strcmp(state,"END")==0)
      {
	end=1;
	break;
      }
    else
      {
	char *tempkey;
	keysize+=strlen(line);
	tempkey=realloc(key,keysize);
	if(tempkey==NULL)
	  {
	    fprintf(console,"gpgkeys: unable to reallocate for key\n");
	    ret=KEYSERVER_NO_MEMORY;
	    goto fail;
	  }
	else
	  key=tempkey;

	strcat(key,line);
      }

  if(!end)
    {
      fprintf(console,"gpgkeys: no KEY %s END found\n",keyid);
      *eof=1;
      ret=KEYSERVER_KEY_INCOMPLETE;
      goto fail;
    }

  make_one_attr(&addlist,"objectClass","pgpKeyInfo");
  make_one_attr(&addlist,"pgpKey",key);

  /* Now append addlist onto modlist */
  if(!join_two_modlists(&modlist,addlist))
    {
      fprintf(console,"gpgkeys: unable to merge LDAP modification lists\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  /* Going on the assumption that modify operations are more frequent
     than adds, we try a modify first.  If it's not there, we just
     turn around and send an add command for the same key.  Otherwise,
     the modify brings the server copy into compliance with our copy.
     Note that unlike the LDAP keyserver (and really, any other
     keyserver) this does NOT merge signatures, but replaces the whole
     key.  This should make some people very happy. */

  err=ldap_modify_s(ldap,dn,modlist);
  if(err==LDAP_NO_SUCH_OBJECT)
    err=ldap_add_s(ldap,dn,addlist);

  if(err!=LDAP_SUCCESS)
    {
      fprintf(console,"gpgkeys: error adding key %s to keyserver: %s\n",
	      keyid,ldap_err2string(err));
      ret=ldap_err_to_gpg_err(err);
      goto fail;
    }

  ret=KEYSERVER_OK;

 fail:
  /* Unwind and free the whole modlist structure */
  for(ml=modlist;*ml;ml++)
    {
      free_mod_values(*ml);
      free(*ml);
    }

  free(modlist);
  free(addlist);
  free(dn);
  free(key);

  if(ret!=0 && begin)
    fprintf(output,"KEY %s FAILED %d\n",keyid,ret);

  return ret;
}

static int
send_key_keyserver(int *eof)
{
  int err,begin=0,end=0,keysize=1,ret=KEYSERVER_INTERNAL_ERROR;
  char *dn=NULL,line[MAX_LINE],*key[2]={NULL,NULL};
  char keyid[17],state[6];
  LDAPMod mod, *attrs[2];

  memset(&mod,0,sizeof(mod));
  mod.mod_op=LDAP_MOD_ADD;
  mod.mod_type=pgpkeystr;
  mod.mod_values=key;
  attrs[0]=&mod;
  attrs[1]=NULL;

  dn=malloc(strlen("pgpCertid=virtual,")+strlen(basekeyspacedn)+1);
  if(dn==NULL)
    {
      fprintf(console,"gpgkeys: can't allocate memory for keyserver record\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  strcpy(dn,"pgpCertid=virtual,");
  strcat(dn,basekeyspacedn);

  key[0]=malloc(1);
  if(key[0]==NULL)
    {
      fprintf(console,"gpgkeys: unable to allocate memory for key\n");
      ret=KEYSERVER_NO_MEMORY;
      goto fail;
    }

  key[0][0]='\0';

  /* Read and throw away stdin until we see the BEGIN */

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
      *eof=1;
      ret=KEYSERVER_OK;
      goto fail;
    }

  /* Now slurp up everything until we see the END */

  while(fgets(line,MAX_LINE,input)!=NULL)
    if(sscanf(line,"KEY%*[ ]%16s%*[ ]%3s\n",keyid,state)==2
       && strcmp(state,"END")==0)
      {
	end=1;
	break;
      }
    else
      {
	keysize+=strlen(line);
	key[0]=realloc(key[0],keysize);
	if(key[0]==NULL)
	  {
	    fprintf(console,"gpgkeys: unable to reallocate for key\n");
	    ret=KEYSERVER_NO_MEMORY;
	    goto fail;
	  }

	strcat(key[0],line);
      }

  if(!end)
    {
      fprintf(console,"gpgkeys: no KEY %s END found\n",keyid);
      *eof=1;
      ret=KEYSERVER_KEY_INCOMPLETE;
      goto fail;
    }

  err=ldap_add_s(ldap,dn,attrs);
  if(err!=LDAP_SUCCESS)
    {
      fprintf(console,"gpgkeys: error adding key %s to keyserver: %s\n",
	      keyid,ldap_err2string(err));
      ret=ldap_err_to_gpg_err(err);
      goto fail;
    }

  ret=KEYSERVER_OK;

 fail:

  free(key[0]);
  free(dn);

  if(ret!=0 && begin)
    fprintf(output,"KEY %s FAILED %d\n",keyid,ret);

  /* Not a fatal error */
  if(ret==KEYSERVER_KEY_EXISTS)
    ret=KEYSERVER_OK;

  return ret;
}

static void
build_info(const char *certid,LDAPMessage *each)
{
  char **vals;

  fprintf(output,"INFO %s BEGIN\n",certid);

  fprintf(output,"pub:%s:",certid);

  vals=ldap_get_values(ldap,each,"pgpkeytype");
  if(vals!=NULL)
    {
      if(strcmp(vals[0],"RSA")==0)
	fprintf(output,"1");
      else if(strcmp(vals[0],"DSS/DH")==0)
	fprintf(output,"17");
      ldap_value_free(vals);
    }

  fprintf(output,":");

  vals=ldap_get_values(ldap,each,"pgpkeysize");
  if(vals!=NULL)
    {
      if(atoi(vals[0])>0)
	fprintf(output,"%d",atoi(vals[0]));
      ldap_value_free(vals);
    }

  fprintf(output,":");

  vals=ldap_get_values(ldap,each,"pgpkeycreatetime");
  if(vals!=NULL)
    {
      if(strlen(vals[0])==15)
	fprintf(output,"%u",(unsigned int)ldap2epochtime(vals[0]));
      ldap_value_free(vals);
    }

  fprintf(output,":");

  vals=ldap_get_values(ldap,each,"pgpkeyexpiretime");
  if(vals!=NULL)
    {
      if(strlen(vals[0])==15)
	fprintf(output,"%u",(unsigned int)ldap2epochtime(vals[0]));
      ldap_value_free(vals);
    }

  fprintf(output,":");

  vals=ldap_get_values(ldap,each,"pgprevoked");
  if(vals!=NULL)
    {
      if(atoi(vals[0])==1)
	fprintf(output,"r");
      ldap_value_free(vals);
    }

  fprintf(output,"\n");

  vals=ldap_get_values(ldap,each,"pgpuserid");
  if(vals!=NULL)
    {
      int i;

      for(i=0;vals[i];i++)
	fprintf(output,"uid:%s\n",vals[i]);
      ldap_value_free(vals);
    }

  fprintf(output,"INFO %s END\n",certid);
}

/* Note that key-not-found is not a fatal error */
static int
get_key(char *getkey)
{
  LDAPMessage *res,*each;
  int ret=KEYSERVER_INTERNAL_ERROR,err,count;
  struct keylist *dupelist=NULL;
  char search[62];
  /* This ordering is significant - specifically, "pgpcertid" needs to
     be the second item in the list, since everything after it may be
     discarded if the user isn't in verbose mode. */
  char *attrs[]={"replaceme","pgpcertid","pgpuserid","pgpkeyid","pgprevoked",
		 "pgpdisabled","pgpkeycreatetime","modifytimestamp",
		 "pgpkeysize","pgpkeytype",NULL};
  attrs[0]=pgpkeystr; /* Some compilers don't like using variables as
                         array initializers. */

  /* Build the search string */

  /* GPG can send us a v4 fingerprint, a v3 or v4 long key id, or a v3
     or v4 short key id */

  if(strncmp(getkey,"0x",2)==0)
    getkey+=2;

  if(strlen(getkey)==32)
    {
      fprintf(console,
	      "gpgkeys: LDAP keyservers do not support v3 fingerprints\n");
      fprintf(output,"KEY 0x%s BEGIN\n",getkey);
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,KEYSERVER_NOT_SUPPORTED);
      return KEYSERVER_NOT_SUPPORTED;
    }

  if(strlen(getkey)>16)
    {
      char *offset=&getkey[strlen(getkey)-16];

      /* fingerprint.  Take the last 16 characters and treat it like a
         long key id */

      if(opt->flags.include_subkeys)
	sprintf(search,"(|(pgpcertid=%.16s)(pgpsubkeyid=%.16s))",
		offset,offset);
      else
	sprintf(search,"(pgpcertid=%.16s)",offset);
    }
  else if(strlen(getkey)>8)
    {
      /* long key id */

      if(opt->flags.include_subkeys)
	sprintf(search,"(|(pgpcertid=%.16s)(pgpsubkeyid=%.16s))",
		getkey,getkey);
      else
	sprintf(search,"(pgpcertid=%.16s)",getkey);
    }
  else
    {
      /* short key id */
    
      sprintf(search,"(pgpkeyid=%.8s)",getkey);
    }

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: LDAP fetch for: %s\n",search);

  if(!opt->verbose)
    attrs[2]=NULL; /* keep only pgpkey(v2) and pgpcertid */

  err=ldap_search_s(ldap,basekeyspacedn,
		    LDAP_SCOPE_SUBTREE,search,attrs,0,&res);
  if(err!=0)
    {
      int errtag=ldap_err_to_gpg_err(err);

      fprintf(console,"gpgkeys: LDAP search error: %s\n",ldap_err2string(err));
      fprintf(output,"KEY 0x%s BEGIN\n",getkey);
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,errtag);
      return errtag;
    }

  count=ldap_count_entries(ldap,res);
  if(count<1)
    {
      fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
      fprintf(output,"KEY 0x%s BEGIN\n",getkey);
      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,KEYSERVER_KEY_NOT_FOUND);
    }
  else
    {
      /* There may be more than one unique result for a given keyID,
	 so we should fetch them all (test this by fetching short key
	 id 0xDEADBEEF). */

      each=ldap_first_entry(ldap,res);
      while(each!=NULL)
	{
	  char **vals,**certid;

	  /* Use the long keyid to remove duplicates.  The LDAP server
	     returns the same keyid more than once if there are
	     multiple user IDs on the key.  Note that this does NOT
	     mean that a keyid that exists multiple times on the
	     keyserver will not be fetched.  It means that each KEY,
	     no matter how many user IDs share its keyid, will be
	     fetched only once.  If a keyid that belongs to more than
	     one key is fetched, the server quite properly responds
	     with all matching keys. -ds */

	  certid=ldap_get_values(ldap,each,"pgpcertid");
	  if(certid!=NULL)
	    {
	      if(!key_in_keylist(certid[0],dupelist))
		{
		  /* it's not a duplicate, so add it */

		  int rc=add_key_to_keylist(certid[0],&dupelist);
		  if(rc)
		    {
		      ret=rc;
		      goto fail;
		    }

		  build_info(certid[0],each);

		  fprintf(output,"KEY 0x%s BEGIN\n",getkey);

		  vals=ldap_get_values(ldap,each,pgpkeystr);
		  if(vals==NULL)
		    {
		      int errtag=ldap_to_gpg_err(ldap);

		      fprintf(console,"gpgkeys: unable to retrieve key %s "
			      "from keyserver\n",getkey);
		      fprintf(output,"KEY 0x%s FAILED %d\n",getkey,errtag);
		    }
		  else
		    {
		      print_nocr(output,vals[0]);
		      fprintf(output,"\nKEY 0x%s END\n",getkey);

		      ldap_value_free(vals);
		    }
		}

	      ldap_value_free(certid);
	    }

	  each=ldap_next_entry(ldap,each);
	}
    }

  ret=KEYSERVER_OK;

 fail:
  ldap_msgfree(res);
  free_keylist(dupelist);

  return ret;
}

#define LDAP_ESCAPE_CHARS "*()\\"

/* Append string to buffer in a LDAP-quoted way */
static void
ldap_quote(char *buffer,const char *string)
{
  /* Find the end of buffer */
  buffer+=strlen(buffer);

  for(;*string;string++)
    {
      if(strchr(LDAP_ESCAPE_CHARS,*string))
	{
	  sprintf(buffer,"\\%02X",*string);
	  buffer+=3;
	}
      else
	*buffer++=*string;
    }

  *buffer='\0';
}

/* Note that key-not-found is not a fatal error */
static int
get_name(char *getkey)
{
  LDAPMessage *res,*each;
  int ret=KEYSERVER_INTERNAL_ERROR,err,count;
  /* The maximum size of the search, including the optional stuff and
     the trailing \0 */
  char search[2+12+(MAX_LINE*3)+2+15+14+1+1+20];
  /* This ordering is significant - specifically, "pgpcertid" needs to
     be the second item in the list, since everything after it may be
     discarded if the user isn't in verbose mode. */
  char *attrs[]={"replaceme","pgpcertid","pgpuserid","pgpkeyid","pgprevoked",
		 "pgpdisabled","pgpkeycreatetime","modifytimestamp",
		 "pgpkeysize","pgpkeytype",NULL};
  attrs[0]=pgpkeystr; /* Some compilers don't like using variables as
                         array initializers. */

  /* Build the search string */

  search[0]='\0';

  if(!opt->flags.include_disabled || !opt->flags.include_revoked)
    strcat(search,"(&");

  strcat(search,"(pgpUserID=*");
  ldap_quote(search,getkey);
  strcat(search,"*)");

  if(!opt->flags.include_disabled)
    strcat(search,"(pgpDisabled=0)");

  if(!opt->flags.include_revoked)
    strcat(search,"(pgpRevoked=0)");

  if(!opt->flags.include_disabled || !opt->flags.include_revoked)
    strcat(search,")");

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: LDAP fetch for: %s\n",search);

  if(!opt->verbose)
    attrs[2]=NULL; /* keep only pgpkey(v2) and pgpcertid */

  err=ldap_search_s(ldap,basekeyspacedn,
		    LDAP_SCOPE_SUBTREE,search,attrs,0,&res);
  if(err!=0)
    {
      int errtag=ldap_err_to_gpg_err(err);

      fprintf(console,"gpgkeys: LDAP search error: %s\n",ldap_err2string(err));
      fprintf(output,"NAME %s BEGIN\n",getkey);
      fprintf(output,"NAME %s FAILED %d\n",getkey,errtag);
      return errtag;
    }

  count=ldap_count_entries(ldap,res);
  if(count<1)
    {
      fprintf(console,"gpgkeys: key %s not found on keyserver\n",getkey);
      fprintf(output,"NAME %s BEGIN\n",getkey);
      fprintf(output,"NAME %s FAILED %d\n",getkey,KEYSERVER_KEY_NOT_FOUND);
    }
  else
    {
      /* There may be more than one result, but we return them all. */

      each=ldap_first_entry(ldap,res);
      while(each!=NULL)
	{
	  char **vals,**certid;

	  certid=ldap_get_values(ldap,each,"pgpcertid");
	  if(certid!=NULL)
	    {
	      build_info(certid[0],each);

	      fprintf(output,"NAME %s BEGIN\n",getkey);

	      vals=ldap_get_values(ldap,each,pgpkeystr);
	      if(vals==NULL)
		{
		  int errtag=ldap_to_gpg_err(ldap);

		  fprintf(console,"gpgkeys: unable to retrieve key %s "
			  "from keyserver\n",getkey);
		  fprintf(output,"NAME %s FAILED %d\n",getkey,errtag);
		}
	      else
		{
		  print_nocr(output,vals[0]);
		  fprintf(output,"\nNAME %s END\n",getkey);

		  ldap_value_free(vals);
		}

	      ldap_value_free(certid);
	    }

	  each=ldap_next_entry(ldap,each);
	}
    }

  ret=KEYSERVER_OK;

  ldap_msgfree(res);

  return ret;
}

static void
printquoted(FILE *stream,char *string,char delim)
{
  while(*string)
    {
      if(*string==delim || *string=='%')
	fprintf(stream,"%%%02x",(unsigned char)*string);
      else
	fputc(*string,stream);

      string++;
    }
}

/* Returns 0 on success and -1 on error.  Note that key-not-found is
   not an error! */
static int
search_key(const char *searchkey)
{
  char **vals,*search;
  LDAPMessage *res,*each;
  int err,count=0;
  struct keylist *dupelist=NULL;
  /* The maximum size of the search, including the optional stuff and
     the trailing \0 */
  char *attrs[]={"pgpcertid","pgpuserid","pgprevoked","pgpdisabled",
		 "pgpkeycreatetime","pgpkeyexpiretime","modifytimestamp",
		 "pgpkeysize","pgpkeytype",NULL};
  enum ks_search_type search_type;

  search=malloc(2+1+9+1+3+strlen(searchkey)+3+1+15+14+1+1+20);
  if(!search)
    {
      fprintf(console,"gpgkeys: out of memory when building search list\n");
      fprintf(output,"SEARCH %s FAILED %d\n",searchkey,KEYSERVER_NO_MEMORY);
      return KEYSERVER_NO_MEMORY;
    }

  fprintf(output,"SEARCH %s BEGIN\n",searchkey);

  search_type=classify_ks_search(&searchkey);

  if(opt->debug)
    fprintf(console,"search type is %d, and key is \"%s\"\n",
	    search_type,searchkey);

  /* Build the search string */

  search[0]='\0';

  if(!opt->flags.include_disabled || !opt->flags.include_revoked)
    strcat(search,"(&");

  strcat(search,"(");

  switch(search_type)
    {
    case KS_SEARCH_KEYID_SHORT:
      strcat(search,"pgpKeyID");
      break;

    case KS_SEARCH_KEYID_LONG:
      strcat(search,"pgpCertID");
      break;

    default:
      strcat(search,"pgpUserID");
      break;
    }

  strcat(search,"=");

  switch(search_type)
    {
    case KS_SEARCH_SUBSTR:
      strcat(search,"*");
      break;

    case KS_SEARCH_MAIL:
      strcat(search,"*<");
      break;

    case KS_SEARCH_MAILSUB:
      strcat(search,"*<*");
      break;

    case KS_SEARCH_EXACT:
    case KS_SEARCH_KEYID_LONG:
    case KS_SEARCH_KEYID_SHORT:
      break;
    }

  strcat(search,searchkey);

  switch(search_type)
    {
    case KS_SEARCH_SUBSTR:
      strcat(search,"*");
      break;

    case KS_SEARCH_MAIL:
      strcat(search,">*");
      break;

    case KS_SEARCH_MAILSUB:
      strcat(search,"*>*");
      break;

    case KS_SEARCH_EXACT:
    case KS_SEARCH_KEYID_LONG:
    case KS_SEARCH_KEYID_SHORT:
      break;
    }

  strcat(search,")");

  if(!opt->flags.include_disabled)
    strcat(search,"(pgpDisabled=0)");

  if(!opt->flags.include_revoked)
    strcat(search,"(pgpRevoked=0)");

  if(!opt->flags.include_disabled || !opt->flags.include_revoked)
    strcat(search,")");

  if(opt->verbose>2)
    fprintf(console,"gpgkeys: LDAP search for: %s\n",search);

  err=ldap_search_s(ldap,basekeyspacedn,
		    LDAP_SCOPE_SUBTREE,search,attrs,0,&res);
  free(search);
  if(err!=LDAP_SUCCESS && err!=LDAP_SIZELIMIT_EXCEEDED)
    {
      int errtag=ldap_err_to_gpg_err(err);

      fprintf(output,"SEARCH %s FAILED %d\n",searchkey,errtag);
      fprintf(console,"gpgkeys: LDAP search error: %s\n",ldap_err2string(err));
      return errtag;
    }

  /* The LDAP server doesn't return a real count of unique keys, so we
     can't use ldap_count_entries here. */
  each=ldap_first_entry(ldap,res);
  while(each!=NULL)
    {
      char **certid=ldap_get_values(ldap,each,"pgpcertid");

      if(certid!=NULL)
	{
	  if(!key_in_keylist(certid[0],dupelist))
	    {
	      int rc=add_key_to_keylist(certid[0],&dupelist);
	      if(rc!=0)
		{
		  fprintf(output,"SEARCH %s FAILED %d\n",searchkey,rc);
		  free_keylist(dupelist);
		  return rc;
		}

	      count++;
	    }
	}

      each=ldap_next_entry(ldap,each);
    }

  if(err==LDAP_SIZELIMIT_EXCEEDED)
    {
      if(count==1)
	fprintf(console,"gpgkeys: search results exceeded server limit."
		"  First %d result shown.\n",count);
      else
	fprintf(console,"gpgkeys: search results exceeded server limit."
		"  First %d results shown.\n",count);
    }

  free_keylist(dupelist);
  dupelist=NULL;

  if(count<1)
    fprintf(output,"info:1:0\n");
  else
    {
      fprintf(output,"info:1:%d\n",count);

      each=ldap_first_entry(ldap,res);
      while(each!=NULL)
	{
	  char **certid;

	  certid=ldap_get_values(ldap,each,"pgpcertid");
	  if(certid!=NULL)
	    {
	      LDAPMessage *uids;

	      /* Have we seen this certid before? */
	      if(!key_in_keylist(certid[0],dupelist))
		{
		  int rc=add_key_to_keylist(certid[0],&dupelist);
		  if(rc)
		    {
		      fprintf(output,"SEARCH %s FAILED %d\n",searchkey,rc);
		      free_keylist(dupelist);
		      ldap_value_free(certid);
		      ldap_msgfree(res);
		      return rc;
		    }

		  fprintf(output,"pub:%s:",certid[0]);

		  vals=ldap_get_values(ldap,each,"pgpkeytype");
		  if(vals!=NULL)
		    {
		      /* The LDAP server doesn't exactly handle this
			 well. */
		      if(ascii_strcasecmp(vals[0],"RSA")==0)
			fprintf(output,"1");
		      else if(ascii_strcasecmp(vals[0],"DSS/DH")==0)
			fprintf(output,"17");
		      ldap_value_free(vals);
		    }

		  fputc(':',output);

		  vals=ldap_get_values(ldap,each,"pgpkeysize");
		  if(vals!=NULL)
		    {
		      /* Not sure why, but some keys are listed with a
			 key size of 0.  Treat that like an
			 unknown. */
		      if(atoi(vals[0])>0)
			fprintf(output,"%d",atoi(vals[0]));
		      ldap_value_free(vals);
		    }

		  fputc(':',output);

		  /* YYYYMMDDHHmmssZ */

		  vals=ldap_get_values(ldap,each,"pgpkeycreatetime");
		  if(vals!=NULL && strlen(vals[0])==15)
		    {
		      fprintf(output,"%u",
			      (unsigned int)ldap2epochtime(vals[0]));
		      ldap_value_free(vals);
		    }

		  fputc(':',output);

		  vals=ldap_get_values(ldap,each,"pgpkeyexpiretime");
		  if(vals!=NULL && strlen(vals[0])==15)
		    {
		      fprintf(output,"%u",
			      (unsigned int)ldap2epochtime(vals[0]));
		      ldap_value_free(vals);
		    }

		  fputc(':',output);

		  vals=ldap_get_values(ldap,each,"pgprevoked");
		  if(vals!=NULL)
		    {
		      if(atoi(vals[0])==1)
			fprintf(output,"r");
		      ldap_value_free(vals);
		    }

		  vals=ldap_get_values(ldap,each,"pgpdisabled");
		  if(vals!=NULL)
		    {
		      if(atoi(vals[0])==1)
			fprintf(output,"d");
		      ldap_value_free(vals);
		    }

#if 0
		  /* This is not yet specified in the keyserver
		     protocol, but may be someday. */
		  fputc(':',output);

		  vals=ldap_get_values(ldap,each,"modifytimestamp");
		  if(vals!=NULL && strlen(vals[0])==15)
		    {
		      fprintf(output,"%u",
			      (unsigned int)ldap2epochtime(vals[0]));
		      ldap_value_free(vals);
		    }
#endif

		  fprintf(output,"\n");

		  /* Now print all the uids that have this certid */
		  uids=ldap_first_entry(ldap,res);
		  while(uids!=NULL)
		    {
		      vals=ldap_get_values(ldap,uids,"pgpcertid");
		      if(vals!=NULL)
			{
			  if(ascii_strcasecmp(certid[0],vals[0])==0)
			    {
			      char **uidvals;

			      fprintf(output,"uid:");

			      uidvals=ldap_get_values(ldap,uids,"pgpuserid");
			      if(uidvals!=NULL)
				{
				  /* Need to escape any colons */
				  printquoted(output,uidvals[0],':');
				  ldap_value_free(uidvals);
				}

			      fprintf(output,"\n");
			    }

			  ldap_value_free(vals);
			}

		      uids=ldap_next_entry(ldap,uids);
		    }
		}

	      ldap_value_free(certid);
	    }

	  each=ldap_next_entry(ldap,each);
	}
    }

  ldap_msgfree(res);
  free_keylist(dupelist);

  fprintf(output,"SEARCH %s END\n",searchkey);

  return KEYSERVER_OK;
}

static void
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

static int
find_basekeyspacedn(void)
{
  int err,i;
  char *attr[]={"namingContexts",NULL,NULL,NULL};
  LDAPMessage *res;
  char **context;

  /* Look for namingContexts */
  err=ldap_search_s(ldap,"",LDAP_SCOPE_BASE,"(objectClass=*)",attr,0,&res);
  if(err==LDAP_SUCCESS)
    {
      context=ldap_get_values(ldap,res,"namingContexts");
      if(context)
	{
	  attr[0]="pgpBaseKeySpaceDN";
	  attr[1]="pgpVersion";
	  attr[2]="pgpSoftware";

	  real_ldap=1;

	  /* We found some, so try each namingContext as the search base
	     and look for pgpBaseKeySpaceDN.  Because we found this, we
	     know we're talking to a regular-ish LDAP server and not a
	     LDAP keyserver. */

	  for(i=0;context[i] && !basekeyspacedn;i++)
	    {
	      char **vals;
	      LDAPMessage *si_res;
	      char *object;

	      object=malloc(17+strlen(context[i])+1);
	      if(!object)
		return -1;

	      strcpy(object,"cn=pgpServerInfo,");
	      strcat(object,context[i]);

	      err=ldap_search_s(ldap,object,LDAP_SCOPE_BASE,
				"(objectClass=*)",attr,0,&si_res);
	      free(object);

	      if(err==LDAP_NO_SUCH_OBJECT)
		continue;
	      else if(err!=LDAP_SUCCESS)
		return err;

	      vals=ldap_get_values(ldap,si_res,"pgpBaseKeySpaceDN");
	      if(vals)
		{
		  basekeyspacedn=strdup(vals[0]);
		  ldap_value_free(vals);
		}

	      if(opt->verbose>1)
		{
		  vals=ldap_get_values(ldap,si_res,"pgpSoftware");
		  if(vals)
		    {
		      fprintf(console,"Server: \t%s\n",vals[0]);
		      ldap_value_free(vals);
		    }

		  vals=ldap_get_values(ldap,si_res,"pgpVersion");
		  if(vals)
		    {
		      fprintf(console,"Version:\t%s\n",vals[0]);
		      ldap_value_free(vals);
		    }
		}

	      ldap_msgfree(si_res);
	    }

	  ldap_value_free(context);
	}

      ldap_msgfree(res);
    }
  else
    {
      /* We don't have an answer yet, which means the server might be
	 a LDAP keyserver. */
      char **vals;
      LDAPMessage *si_res;

      attr[0]="pgpBaseKeySpaceDN";
      attr[1]="version";
      attr[2]="software";

      err=ldap_search_s(ldap,"cn=pgpServerInfo",LDAP_SCOPE_BASE,
			"(objectClass=*)",attr,0,&si_res);
      if(err!=LDAP_SUCCESS)
	return err;

      /* For the LDAP keyserver, this is always "OU=ACTIVE,O=PGP
	 KEYSPACE,C=US", but it might not be in the future. */

      vals=ldap_get_values(ldap,si_res,"baseKeySpaceDN");
      if(vals)
	{
	  basekeyspacedn=strdup(vals[0]);
	  ldap_value_free(vals);
	}

      if(opt->verbose>1)
	{
	  vals=ldap_get_values(ldap,si_res,"software");
	  if(vals)
	    {
	      fprintf(console,"Server: \t%s\n",vals[0]);
	      ldap_value_free(vals);
	    }
	}

      vals=ldap_get_values(ldap,si_res,"version");
      if(vals)
	{
	  if(opt->verbose>1)
	    fprintf(console,"Version:\t%s\n",vals[0]);

	  /* If the version is high enough, use the new pgpKeyV2
	     attribute.  This design if iffy at best, but it matches how
	     PGP does it.  I figure the NAI folks assumed that there would
	     never be a LDAP keyserver vendor with a different numbering
	     scheme. */
	  if(atoi(vals[0])>1)
	    pgpkeystr="pgpKeyV2";

	  ldap_value_free(vals);
	}

      ldap_msgfree(si_res);
    }   

  return LDAP_SUCCESS;
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
  int port=0,arg,err,ret=KEYSERVER_INTERNAL_ERROR;
  char line[MAX_LINE],*binddn=NULL,*bindpw=NULL;
  int failed=0,use_ssl=0,use_tls=0,bound=0;
  struct keylist *keylist=NULL,*keyptr=NULL;

  console=stderr;

  /* Kludge to implement standard GNU options.  */
  if (argc > 1 && !strcmp (argv[1], "--version"))
    {
      fputs ("gpgkeys_ldap (GnuPG) " VERSION"\n", stdout);
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
      char optionstr[MAX_OPTION+1];

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

      if(sscanf(line,"OPTION %" MKSTRING(MAX_OPTION) "[^\n]\n",optionstr)==1)
	{
	  int no=0;
	  char *start=&optionstr[0];

	  optionstr[MAX_OPTION]='\0';

	  if(ascii_strncasecmp(optionstr,"no-",3)==0)
	    {
	      no=1;
	      start=&optionstr[3];
	    }

	  if(ascii_strncasecmp(start,"tls",3)==0)
	    {
	      if(no)
		use_tls=0;
	      else if(start[3]=='=')
		{
		  if(ascii_strcasecmp(&start[4],"no")==0)
		    use_tls=0;
		  else if(ascii_strcasecmp(&start[4],"try")==0)
		    use_tls=1;
		  else if(ascii_strcasecmp(&start[4],"warn")==0)
		    use_tls=2;
		  else if(ascii_strcasecmp(&start[4],"require")==0)
		    use_tls=3;
		  else
		    use_tls=1;
		}
	      else if(start[3]=='\0')
		use_tls=1;
	    }
	  else if(ascii_strncasecmp(start,"basedn",6)==0)
	    {
	      if(no)
		{
		  free(basekeyspacedn);
		  basekeyspacedn=NULL;
		}
	      else if(start[6]=='=')
		{
		  free(basekeyspacedn);
		  basekeyspacedn=strdup(&start[7]);
		  if(!basekeyspacedn)
		    {
		      fprintf(console,"gpgkeys: out of memory while creating "
			      "base DN\n");
		      ret=KEYSERVER_NO_MEMORY;
		      goto fail;
		    }

		  real_ldap=1;
		}
	    }
	  else if(ascii_strncasecmp(start,"binddn",6)==0)
	    {
	      if(no)
		{
		  free(binddn);
		  binddn=NULL;
		}
	      else if(start[6]=='=')
		{
		  free(binddn);
		  binddn=strdup(&start[7]);
		  if(!binddn)
		    {
		      fprintf(console,"gpgkeys: out of memory while creating "
			      "bind DN\n");
		      ret=KEYSERVER_NO_MEMORY;
		      goto fail;
		    }

		  real_ldap=1;
		}
	    }
	  else if(ascii_strncasecmp(start,"bindpw",6)==0)
	    {
	      if(no)
		{
		  free(bindpw);
		  bindpw=NULL;
		}
	      else if(start[6]=='=')
		{
		  free(bindpw);
		  bindpw=strdup(&start[7]);
		  if(!bindpw)
		    {
		      fprintf(console,"gpgkeys: out of memory while creating "
			      "bind password\n");
		      ret=KEYSERVER_NO_MEMORY;
		      goto fail;
		    }

		  real_ldap=1;
		}
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

  if(ascii_strcasecmp(opt->scheme,"ldaps")==0)
    {
      port=636;
      use_ssl=1;
    }

  if(opt->port)
    port=atoi(opt->port);

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

#if defined(LDAP_OPT_X_TLS_CACERTFILE) && defined(HAVE_LDAP_SET_OPTION)

  if(opt->ca_cert_file)
    {
      err=ldap_set_option(NULL,LDAP_OPT_X_TLS_CACERTFILE,opt->ca_cert_file);
      if(err!=LDAP_SUCCESS)
	{
	  fprintf(console,"gpgkeys: unable to set ca-cert-file: %s\n",
		  ldap_err2string(err));
	  ret=KEYSERVER_INTERNAL_ERROR;
	  goto fail;
	}
    }
#endif /* LDAP_OPT_X_TLS_CACERTFILE && HAVE_LDAP_SET_OPTION */

  /* SSL trumps TLS */
  if(use_ssl)
    use_tls=0;

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
      if(port)
	fprintf(console,"Port:\t\t%d\n",port);
      fprintf(console,"Command:\t%s\n",ks_action_to_string(opt->action));
    }

  if(opt->debug)
    {
#if defined(LDAP_OPT_DEBUG_LEVEL) && defined(HAVE_LDAP_SET_OPTION)
      err=ldap_set_option(NULL,LDAP_OPT_DEBUG_LEVEL,&opt->debug);
      if(err!=LDAP_SUCCESS)
	fprintf(console,"gpgkeys: unable to set debug mode: %s\n",
		ldap_err2string(err));
      else
	fprintf(console,"gpgkeys: debug level %d\n",opt->debug);
#else
      fprintf(console,"gpgkeys: not built with debugging support\n");
#endif
    }

  /* We have a timeout set for the setup stuff since it could time out
     as well. */
  set_timeout(opt->timeout);

  /* Note that this tries all A records on a given host (or at least,
     OpenLDAP does). */
  ldap=ldap_init(opt->host,port);
  if(ldap==NULL)
    {
      fprintf(console,"gpgkeys: internal LDAP init error: %s\n",
	      strerror(errno));
      fail_all(keylist,KEYSERVER_INTERNAL_ERROR);
      goto fail;
    }

  if(use_ssl)
    {
#if defined(LDAP_OPT_X_TLS) && defined(HAVE_LDAP_SET_OPTION)
      int ssl=LDAP_OPT_X_TLS_HARD;

      err=ldap_set_option(ldap,LDAP_OPT_X_TLS,&ssl);
      if(err!=LDAP_SUCCESS)
	{
	  fprintf(console,"gpgkeys: unable to make SSL connection: %s\n",
		  ldap_err2string(err));
	  fail_all(keylist,ldap_err_to_gpg_err(err));
	  goto fail;
	}

      if(!opt->flags.check_cert)
	ssl=LDAP_OPT_X_TLS_NEVER;

      err=ldap_set_option(NULL,LDAP_OPT_X_TLS_REQUIRE_CERT,&ssl);
      if(err!=LDAP_SUCCESS)
	{
	  fprintf(console,
		  "gpgkeys: unable to set certificate validation: %s\n",
		  ldap_err2string(err));
	  fail_all(keylist,ldap_err_to_gpg_err(err));
	  goto fail;
	}
#else
      fprintf(console,"gpgkeys: unable to make SSL connection: %s\n",
	      "not built with LDAPS support");
      fail_all(keylist,KEYSERVER_INTERNAL_ERROR);
      goto fail;
#endif
    }

  if(!basekeyspacedn)
    if((err=find_basekeyspacedn()) || !basekeyspacedn)
      {
	fprintf(console,"gpgkeys: unable to retrieve LDAP base: %s\n",
		err?ldap_err2string(err):"not found");
	fail_all(keylist,ldap_err_to_gpg_err(err));
	goto fail;
      }

  /* use_tls: 0=don't use, 1=try silently to use, 2=try loudly to use,
     3=force use. */
  if(use_tls)
    {
      if(!real_ldap)
      	{
      	  if(use_tls>=2)
	    fprintf(console,"gpgkeys: unable to start TLS: %s\n",
		    "not supported by the NAI LDAP keyserver");
	  if(use_tls==3)
	    {
	      fail_all(keylist,KEYSERVER_INTERNAL_ERROR);
	      goto fail;
	    }
      	}
      else
	{
#if defined(HAVE_LDAP_START_TLS_S) && defined(HAVE_LDAP_SET_OPTION)
	  int ver=LDAP_VERSION3;

	  err=ldap_set_option(ldap,LDAP_OPT_PROTOCOL_VERSION,&ver);

#ifdef LDAP_OPT_X_TLS
	  if(err==LDAP_SUCCESS)
	    {
	      if(opt->flags.check_cert)
		ver=LDAP_OPT_X_TLS_HARD;
	      else
		ver=LDAP_OPT_X_TLS_NEVER;

	      err=ldap_set_option(NULL,LDAP_OPT_X_TLS_REQUIRE_CERT,&ver);
	    }
#endif

	  if(err==LDAP_SUCCESS)
	    err=ldap_start_tls_s(ldap,NULL,NULL);

	  if(err!=LDAP_SUCCESS)
	    {
	      if(use_tls>=2 || opt->verbose>2)
		fprintf(console,"gpgkeys: unable to start TLS: %s\n",
			ldap_err2string(err));
	      /* Are we forcing it? */
	      if(use_tls==3)
		{
		  fail_all(keylist,ldap_err_to_gpg_err(err));
		  goto fail;
		}
	    }
	  else if(opt->verbose>1)
	    fprintf(console,"gpgkeys: TLS started successfully.\n");
#else
	  if(use_tls>=2)
	    fprintf(console,"gpgkeys: unable to start TLS: %s\n",
		    "not built with TLS support");
	  if(use_tls==3)
	    {
	      fail_all(keylist,KEYSERVER_INTERNAL_ERROR);
	      goto fail;
	    }
#endif
	}
    }

  /* By default we don't bind as there is usually no need to.  For
     cases where the server needs some authentication, the user can
     use binddn and bindpw for auth. */

  if(binddn)
    {
#ifdef HAVE_LDAP_SET_OPTION
      int ver=LDAP_VERSION3;

      err=ldap_set_option(ldap,LDAP_OPT_PROTOCOL_VERSION,&ver);
      if(err!=LDAP_SUCCESS)
	{
	  fprintf(console,"gpgkeys: unable to go to LDAP 3: %s\n",
		  ldap_err2string(err));
	  fail_all(keylist,ldap_err_to_gpg_err(err));
	  goto fail;
	}
#endif

      if(opt->verbose>2)
	fprintf(console,"gpgkeys: LDAP bind to %s, pw %s\n",binddn,
		bindpw?">not shown<":">none<");
      err=ldap_simple_bind_s(ldap,binddn,bindpw);
      if(err!=LDAP_SUCCESS)
	{
	  fprintf(console,"gpgkeys: internal LDAP bind error: %s\n",
		  ldap_err2string(err));
	  fail_all(keylist,ldap_err_to_gpg_err(err));
	  goto fail;
	}
      else
	bound=1;
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
      int eof=0;

      do
	{
	  set_timeout(opt->timeout);

	  if(real_ldap)
	    {
	      if(send_key(&eof)!=KEYSERVER_OK)
		failed++;
	    }
	  else
	    {
	      if(send_key_keyserver(&eof)!=KEYSERVER_OK)
		failed++;
	    }
	}
      while(!eof);
    }
  else if(opt->action==KS_SEARCH)
    {
      char *searchkey=NULL;
      int len=0;

      set_timeout(opt->timeout);

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

      searchkey=malloc((len*3)+1);
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
	  ldap_quote(searchkey,keyptr->str);
	  strcat(searchkey,"*");
	  keyptr=keyptr->next;
	}

      /* Nail that last "*" */
      if(*searchkey)
	searchkey[strlen(searchkey)-1]='\0';

      if(search_key(searchkey)!=KEYSERVER_OK)
	failed++;

      free(searchkey);
    }
  else
    assert (!"invalid action");

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

  if(ldap!=NULL && bound)
    ldap_unbind_s(ldap);

  free(basekeyspacedn);

  return ret;
}
