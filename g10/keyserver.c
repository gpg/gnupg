/* keyserver.c - generic keyserver code
 * Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "filter.h"
#include "keydb.h"
#include "status.h"
#include "exec.h"
#include "main.h"
#include "i18n.h"
#include "hkp.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "packet.h"
#include "keyserver-internal.h"
#include "util.h"

#define KEYSERVER_PROTO_VERSION 0

#define GET    0
#define SEND   1
#define SEARCH 2

void 
parse_keyserver_options(char *options)
{
  char *tok="";

  do
    {
      if(strcasecmp(tok,"fast-import")==0)
	opt.keyserver_options.fast_import=1;
      else if(strcasecmp(tok,"no-fast-import")==0)
	opt.keyserver_options.fast_import=0;
      else if(strcasecmp(tok,"include-revoked")==0)
	opt.keyserver_options.include_revoked=1;
      else if(strcasecmp(tok,"no-include-revoked")==0)
	opt.keyserver_options.include_revoked=0;
      else if(strcasecmp(tok,"include-disabled")==0)
	opt.keyserver_options.include_disabled=1;
      else if(strcasecmp(tok,"no-include-disabled")==0)
	opt.keyserver_options.include_disabled=0;
#ifdef EXEC_TEMPFILE_ONLY
      else if(strcasecmp(tok,"use-temp-files")==0 ||
	      strcasecmp(tok,"no-use-temp-files")==0)
	log_info(_("Warning: keyserver option \"%s\" is not used "
		   "on this platform\n"),tok);
#else
      else if(strcasecmp(tok,"use-temp-files")==0)
	opt.keyserver_options.use_temp_files=1;
      else if(strcasecmp(tok,"no-use-temp-files")==0)
	opt.keyserver_options.use_temp_files=0;
#endif
      else if(strcasecmp(tok,"keep-temp-files")==0)
	opt.keyserver_options.keep_temp_files=1;
      else if(strcasecmp(tok,"no-keep-temp-files")==0)
	opt.keyserver_options.keep_temp_files=0;
      else if(strcasecmp(tok,"verbose")==0)
	opt.keyserver_options.verbose++;
      else if(strcasecmp(tok,"no-verbose")==0)
	opt.keyserver_options.verbose--;
      else if(strcasecmp(tok,"honor-http-proxy")==0)
	opt.honor_http_proxy=1;
      else if(strcasecmp(tok,"no-honor-http-proxy")==0)
	opt.honor_http_proxy=0;
      else if(strcasecmp(tok,"refresh-add-fake-v3-keyids")==0)
	opt.keyserver_options.refresh_add_fake_v3_keyids=1;
      else if(strcasecmp(tok,"no-refresh-add-fake-v3-keyids")==0)
	opt.keyserver_options.refresh_add_fake_v3_keyids=0;
      else if(strcasecmp(tok,"auto-key-retrieve")==0)
	opt.keyserver_options.refresh_add_fake_v3_keyids=1;
      else if(strcasecmp(tok,"no-auto-key-retrieve")==0)
	opt.keyserver_options.refresh_add_fake_v3_keyids=0;
      else if(strlen(tok)>0)
	add_to_strlist(&opt.keyserver_options.other,tok);

      tok=strsep(&options," ,");
    }
    while(tok!=NULL);
}

int 
parse_keyserver_uri(char *uri)
{
  /* Get the scheme */

  opt.keyserver_scheme=strsep(&uri,":");
  if(uri==NULL)
    {
      uri=opt.keyserver_scheme;
      opt.keyserver_scheme="x-hkp";
    }

  /* Skip the "//", if any */
  if(strlen(uri)>2 && uri[0]=='/' && uri[1]=='/')
    uri+=2;

  /* Get the host */
  opt.keyserver_host=strsep(&uri,":/");
  if(uri==NULL)
    opt.keyserver_port="0";
  else
    {
      char *ch;

      /* Get the port */
      opt.keyserver_port=strsep(&uri,"/");

      /* Ports are digits only */
      ch=opt.keyserver_port;
      while(*ch!='\0')
	{
	  if(!isdigit(*ch))
	    return G10ERR_BAD_URI;

	  ch++;
	}

      if(strlen(opt.keyserver_port)==0 ||
	 atoi(opt.keyserver_port)<1 || atoi(opt.keyserver_port)>65535)
	return G10ERR_BAD_URI;
    }

  /* (any path part of the URI is discarded for now as no keyserver
     uses it) */

  if(opt.keyserver_scheme[0]=='\0' || opt.keyserver_host[0]=='\0')
    return G10ERR_BAD_URI;

  return 0;
}

/* Unquote only the delimiter character and backslashes (\x5C) */
static void 
printunquoted(char *string,char delim)
{
  char *ch=string;

  while(*ch)
    {
      if(*ch=='\\')
	{
	  int c;

	  sscanf(ch,"\\x%02x",&c);
	  if(c==delim)
	    {
	      printf("%c",c);
	      ch+=3;
	    }
	  else if(c=='\\')
	    {
	      fputc('\\',stdout);
	      ch+=3;
	    }
	  else
	    fputc(*ch,stdout);
	}
      else
	fputc(*ch,stdout);

      ch++;
    }
}

static int 
print_keyinfo(int count,char *keystring,KEYDB_SEARCH_DESC *desc)
{
  char *certid,*userid,*keytype,*tok;
  int flags,keysize=0;
  time_t createtime=0,expiretime=0,modifytime=0;

  if((certid=strsep(&keystring,":"))==NULL)
    return -1;

  classify_user_id (certid, desc);
  if(desc->mode!=KEYDB_SEARCH_MODE_SHORT_KID &&
     desc->mode!=KEYDB_SEARCH_MODE_LONG_KID &&
     desc->mode!=KEYDB_SEARCH_MODE_FPR16 &&
     desc->mode!=KEYDB_SEARCH_MODE_FPR20)
    return -1;

  if((tok=strsep(&keystring,":"))==NULL)
    return -1;

  userid=utf8_to_native(tok,strlen(tok),0);

  if((tok=strsep(&keystring,":"))==NULL)
    return -1;

  flags=atoi(tok);

  if((tok=strsep(&keystring,":"))==NULL)
    return -1;

  createtime=atoi(tok);

  if((tok=strsep(&keystring,":"))==NULL)
    return -1;

  expiretime=atoi(tok);

  if((tok=strsep(&keystring,":"))==NULL)
    return -1;

  modifytime=atoi(tok);

  if((keytype=strsep(&keystring,":"))==NULL)
    return -1;

  /* The last one */
  if(keystring!=NULL)
    keysize=atoi(keystring);

  printf("(%d)\t",count);

  /* No need to check for control characters, as utf8_to_native does
     this for us. */
  printunquoted(userid,':');

  if(flags&1)
    printf(" (revoked)");
  if(flags&2)
    printf(" (disabled)");

  if(keytype[0])
    printf(" %s",keytype);

  if(keysize>0)
    printf(" %d",keysize);

  printf("\n\t  created %s,",strtimestamp(createtime));

  if(expiretime>0)
    printf(" expires %s,",strtimestamp(expiretime));

  printf(" key %s\n",certid);

  return 0;
}

#define KEYSERVER_ARGS_KEEP " -o \"%O\" \"%I\""
#define KEYSERVER_ARGS_NOKEEP " -o \"%o\" \"%i\""

static int 
keyserver_spawn(int action,STRLIST list,
		KEYDB_SEARCH_DESC *desc,int count,int *prog)
{
  int ret=0,i,gotversion=0,outofband=0;
  STRLIST temp;
  unsigned int maxlen=256,buflen;
  char *command=NULL,*searchstr=NULL;
  byte *line=NULL;
  struct exec_info *spawn;

#ifdef EXEC_TEMPFILE_ONLY
  opt.keyserver_options.use_temp_files=1;
#endif

  /* Build the filename for the helper to execute */

  command=m_alloc(strlen("gpgkeys_")+strlen(opt.keyserver_scheme)+1);
  strcpy(command,"gpgkeys_");
  strcat(command,opt.keyserver_scheme);

  if(opt.keyserver_options.use_temp_files)
    {
      if(opt.keyserver_options.keep_temp_files)
	{
	  command=m_realloc(command,strlen(command)+
			    strlen(KEYSERVER_ARGS_KEEP)+1);
	  strcat(command,KEYSERVER_ARGS_KEEP);
	}
      else
	{
	  command=m_realloc(command,strlen(command)+
			    strlen(KEYSERVER_ARGS_NOKEEP)+1);
	  strcat(command,KEYSERVER_ARGS_NOKEEP);  
	}

      ret=exec_write(&spawn,NULL,command,0,0);
    }
  else
    ret=exec_write(&spawn,command,NULL,0,0);

  if(ret)
    return ret;

  fprintf(spawn->tochild,"# This is a gpg keyserver communications file\n");
  fprintf(spawn->tochild,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(spawn->tochild,"PROGRAM %s\n",VERSION);
  fprintf(spawn->tochild,"HOST %s\n",opt.keyserver_host);

  if(atoi(opt.keyserver_port)>0)
    fprintf(spawn->tochild,"PORT %s\n",opt.keyserver_port);

  /* Write options */

  fprintf(spawn->tochild,"OPTION %sinclude-revoked\n",
	  opt.keyserver_options.include_revoked?"":"no-");

  fprintf(spawn->tochild,"OPTION %sinclude-disabled\n",
	  opt.keyserver_options.include_disabled?"":"no-");

  for(i=0;i<opt.keyserver_options.verbose;i++)
    fprintf(spawn->tochild,"OPTION verbose\n");

  temp=opt.keyserver_options.other;

  for(;temp;temp=temp->next)
    fprintf(spawn->tochild,"OPTION %s\n",temp->d);

  switch(action)
    {
    case GET:
      {
	fprintf(spawn->tochild,"COMMAND GET\n\n");

	/* Which keys do we want? */

	for(i=0;i<count;i++)
	  {
	    if(desc[i].mode==KEYDB_SEARCH_MODE_FPR20)
	      {
		int f;

		fprintf(spawn->tochild,"0x");

		for(f=0;f<MAX_FINGERPRINT_LEN;f++)
		  fprintf(spawn->tochild,"%02X",(byte)desc[i].u.fpr[f]);

		fprintf(spawn->tochild,"\n");
	      }
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_FPR16)
	      {
		int f;

		fprintf(spawn->tochild,"0x");

		for(f=0;f<16;f++)
		  fprintf(spawn->tochild,"%02X",(byte)desc[i].u.fpr[f]);

		fprintf(spawn->tochild,"\n");
	      }
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_LONG_KID)
	      fprintf(spawn->tochild,"0x%08lX%08lX\n",
		      (ulong)desc[i].u.kid[0],
		      (ulong)desc[i].u.kid[1]);
	    else
	      fprintf(spawn->tochild,"0x%08lX\n",
		      (ulong)desc[i].u.kid[1]);
	  }

	fprintf(spawn->tochild,"\n");

	break;
      }

    case SEND:
      {
	STRLIST key;

	/* Note the extra \n here to send an empty keylist block */
	fprintf(spawn->tochild,"COMMAND SEND\n\n\n");

	for(key=list;key!=NULL;key=key->next)
	  {
	    armor_filter_context_t afx;
	    IOBUF buffer=iobuf_temp();

	    temp=NULL;
	    add_to_strlist(&temp,key->d);

	    memset(&afx,0,sizeof(afx));
	    afx.what=1;
	    iobuf_push_filter(buffer,armor_filter,&afx);

	    if(export_pubkeys_stream(buffer,temp,1)==-1)
	      iobuf_close(buffer);
	    else
	      {
		iobuf_flush_temp(buffer);

		fprintf(spawn->tochild,"KEY %s BEGIN\n",key->d);
		fwrite(iobuf_get_temp_buffer(buffer),
		       iobuf_get_temp_length(buffer),1,spawn->tochild);
		fprintf(spawn->tochild,"KEY %s END\n",key->d);

		iobuf_close(buffer);
	      }

	    free_strlist(temp);
	  }

	break;
      }

    case SEARCH:
      {
	STRLIST key;

	fprintf(spawn->tochild,"COMMAND SEARCH\n\n");

	/* Which keys do we want?  Remember that the gpgkeys_ program
           is going to lump these together into a search string. */

	for(key=list;key!=NULL;key=key->next)
	  {
	    fprintf(spawn->tochild,"%s\n",key->d);
	    if(key!=list)
	      {
		searchstr=m_realloc(searchstr,
				    strlen(searchstr)+strlen(key->d)+2);
		strcat(searchstr," ");
	      }
	    else
	      {
		searchstr=m_alloc(strlen(key->d)+1);
		searchstr[0]='\0';
	      }

	    strcat(searchstr,key->d);
	  }

	fprintf(spawn->tochild,"\n");

	break;
      }

    default:
      log_fatal(_("no keyserver action!\n"));
      break;
    }

  /* Done sending, so start reading. */
  ret=exec_read(spawn);
  if(ret)
    goto fail;

  /* Now handle the response */

  do
    {
      if(iobuf_read_line(spawn->fromchild,&line,&buflen,&maxlen)==0)
	{
	  ret=G10ERR_READ_FILE;
	  goto fail; /* i.e. EOF */
	}

      if(strncasecmp(line,"VERSION ",8)==0)
	{
	  gotversion=1;

	  if(atoi(&line[8])!=KEYSERVER_PROTO_VERSION)
	    {
	      log_error(_("invalid keyserver protocol (us %d!=handler %d)\n"),
			KEYSERVER_PROTO_VERSION,atoi(&line[8]));
	      goto fail;
	    }
	}

      if(strncasecmp(line,"PROGRAM ",8)==0)
	{
	  line[strlen(line)-1]='\0';
	  if(strcasecmp(&line[8],VERSION)!=0)
	    log_info(_("Warning: keyserver handler from a different "
		       "version of GnuPG (%s)\n"),&line[8]);
	}

      /* Currently the only OPTION */
      if(strncasecmp(line,"OPTION OUTOFBAND",16)==0)
	outofband=1;
    }
  while(line[0]!='\n');

  if(!gotversion)
    {
      log_error(_("keyserver did not send VERSION\n"));
      goto fail;
    }

  if(!outofband)
    switch(action)
      {
      case GET:
	{
	  void *stats_handle;

	  stats_handle=import_new_stats_handle();

	  /* Slurp up all the key data.  In the future, it might be nice
	     to look for KEY foo OUTOFBAND and FAILED indicators.  It's
	     harmless to ignore them, but ignoring them does make gpg
	     complain about "no valid OpenPGP data found".  One way to
	     do this could be to continue parsing this line-by-line and
	     make a temp iobuf for each key. */

	  import_keys_stream(spawn->fromchild,
			     opt.keyserver_options.fast_import,stats_handle);

	  import_print_stats(stats_handle);
	  import_release_stats_handle(stats_handle);

	  break;
	}

	/* Nothing to do here */
      case SEND:
	break;

      case SEARCH:
	{
	  line=NULL;
	  buflen = 0;
	  maxlen = 80;
	  /* Look for the COUNT line */
	  do
	    {
	      if(iobuf_read_line(spawn->fromchild,&line,&buflen,&maxlen)==0)
		{
		  ret=G10ERR_READ_FILE;
		  goto fail; /* i.e. EOF */
		}
	    }
	  while(sscanf(line,"COUNT %d\n",&i)!=1);

	  keyserver_search_prompt(spawn->fromchild,i,searchstr);

	  break;
	}

      default:
	log_fatal(_("no keyserver action!\n"));
	break;
      }

 fail:
  *prog=exec_finish(spawn);

  return ret;
}

static int 
keyserver_work(int action,STRLIST list,KEYDB_SEARCH_DESC *desc,int count)
{
  int rc=0,ret=0;

  if(opt.keyserver_scheme==NULL ||
     opt.keyserver_host==NULL ||
     opt.keyserver_port==NULL)
    {
      log_error(_("no keyserver known (use option --keyserver)\n"));
      return G10ERR_BAD_URI;
    }

#ifndef USE_EXTERNAL_HKP
  /* Use the internal HKP code */
  if(strcasecmp(opt.keyserver_scheme,"x-hkp")==0 ||
     strcasecmp(opt.keyserver_scheme,"hkp")==0 ||
     strcasecmp(opt.keyserver_scheme,"x-broken-hkp")==0)
    {
      void *stats_handle = import_new_stats_handle ();

      switch(action)
	{
	case GET:
	  for(count--;count>=0;count--)
	    if(hkp_ask_import(&desc[count],stats_handle))
	      log_inc_errorcount();
	  break;
	case SEND:
	  return hkp_export(list);
	case SEARCH:
	  return hkp_search(list);
	}

      import_print_stats (stats_handle);
      import_release_stats_handle (stats_handle);

      return 0;
    }
#endif

  /* It's not the internal HKP code, so try and spawn a handler for it */

  rc=keyserver_spawn(action,list,desc,count,&ret);
  if(ret)
    {
      switch(ret)
	{
	case KEYSERVER_SCHEME_NOT_FOUND:
	  log_error(_("no handler for keyserver scheme \"%s\"\n"),
		    opt.keyserver_scheme);
	  break;

	case KEYSERVER_NOT_SUPPORTED:
	  log_error(_("action \"%s\" not supported with keyserver "
		      "scheme \"%s\"\n"),
		    action==GET?"get":action==SEND?"send":
		    action==SEARCH?"search":"unknown",
		    opt.keyserver_scheme);

	case KEYSERVER_INTERNAL_ERROR:
	default:
	  log_error(_("keyserver internal error\n"));
	  break;
	}

      return G10ERR_KEYSERVER;
    }

  if(rc)
    {
      log_error(_("keyserver communications error: %s\n"),g10_errstr(rc));

      return rc;
    }

  return 0;
}

int 
keyserver_export(STRLIST users)
{
  return keyserver_work(SEND,users,NULL,0);
}

int 
keyserver_import(STRLIST users)
{
  KEYDB_SEARCH_DESC *desc;
  int num=100,count=0;
  int rc=0;

  /* Build a list of key ids */
  desc=m_alloc(sizeof(KEYDB_SEARCH_DESC)*num);

  for(;users;users=users->next)
    {
      classify_user_id (users->d, &desc[count]);
      if(desc[count].mode!=KEYDB_SEARCH_MODE_SHORT_KID &&
	 desc[count].mode!=KEYDB_SEARCH_MODE_LONG_KID &&
	 desc[count].mode!=KEYDB_SEARCH_MODE_FPR16 &&
	 desc[count].mode!=KEYDB_SEARCH_MODE_FPR20)
	{
	  log_error(_("skipping invalid key ID \"%s\"\n"),users->d);
	  continue;
	}

      count++;
      if(count==num)
	{
	  num+=100;
	  desc=m_realloc(desc,sizeof(KEYDB_SEARCH_DESC)*num);
	}
    }

  if(count>0)
    rc=keyserver_work(GET,NULL,desc,count);

  m_free(desc);

  return rc;
}

int
keyserver_import_fprint(const byte *fprint,size_t fprint_len)
{
  KEYDB_SEARCH_DESC desc;

  memset(&desc,0,sizeof(desc));

  if(fprint_len==16)
    desc.mode=KEYDB_SEARCH_MODE_FPR16;
  else if(fprint_len==20)
    desc.mode=KEYDB_SEARCH_MODE_FPR20;
  else
    return -1;

  memcpy(desc.u.fpr,fprint,fprint_len);

  return keyserver_work(GET,NULL,&desc,1);
}

int 
keyserver_import_keyid(u32 *keyid)
{
  KEYDB_SEARCH_DESC desc;

  memset(&desc,0,sizeof(desc));

  desc.mode=KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0]=keyid[0];
  desc.u.kid[1]=keyid[1];

  return keyserver_work(GET,NULL,&desc,1);
}

/* code mostly stolen from do_export_stream */
static int 
keyidlist(STRLIST users,KEYDB_SEARCH_DESC **klist,int *count,int fakev3)
{
  int rc=0,ndesc,num=100;
  KBNODE keyblock=NULL,node;
  KEYDB_HANDLE kdbhd;
  KEYDB_SEARCH_DESC *desc;
  STRLIST sl;

  *count=0;

  *klist=m_alloc(sizeof(KEYDB_SEARCH_DESC)*num);

  kdbhd=keydb_new(0);

  if(!users)
    {
      ndesc = 1;
      desc = m_alloc_clear ( ndesc * sizeof *desc);
      desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
    }
  else
    {
      for (ndesc=0, sl=users; sl; sl = sl->next, ndesc++) 
	;
      desc = m_alloc ( ndesc * sizeof *desc);
        
      for (ndesc=0, sl=users; sl; sl = sl->next)
	{
	  if(classify_user_id (sl->d, desc+ndesc))
	    ndesc++;
	  else
	    log_error (_("key `%s' not found: %s\n"),
		       sl->d, g10_errstr (G10ERR_INV_USER_ID));
	}
    }

  while (!(rc = keydb_search (kdbhd, desc, ndesc)))
    {
      if (!users) 
	desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

      /* read the keyblock */
      rc = keydb_get_keyblock (kdbhd, &keyblock );
      if( rc )
	{
	  log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	  goto leave;
	}

      if((node=find_kbnode(keyblock,PKT_PUBLIC_KEY)))
	{
	  /* This is to work around a bug in some keyservers (pksd and
             OKS) that calculate v4 RSA keyids as if they were v3 RSA.
             The answer is to refresh both the correct v4 keyid
             (e.g. 99242560) and the fake v3 keyid (e.g. 68FDDBC7).
             This only happens for key refresh using the HKP scheme
             and if the refresh-add-fake-v3-keyids keyserver option is
             set. */
	  if(fakev3 && is_RSA(node->pkt->pkt.public_key->pubkey_algo) &&
	     node->pkt->pkt.public_key->version>=4)
	    {
	      (*klist)[*count].mode=KEYDB_SEARCH_MODE_LONG_KID;
	      mpi_get_keyid(node->pkt->pkt.public_key->pkey[0],
			    (*klist)[*count].u.kid);
	      (*count)++;

	      if(*count==num)
		{
		  num+=100;
		  *klist=m_realloc(*klist,sizeof(KEYDB_SEARCH_DESC)*num);
		}
	    }

	  /* v4 keys get full fingerprints.  v3 keys get long keyids.
             This is because it's easy to calculate any sort of key id
             from a v4 fingerprint, but not a v3 fingerprint. */

	  if(node->pkt->pkt.public_key->version<4)
	    {
	      (*klist)[*count].mode=KEYDB_SEARCH_MODE_LONG_KID;
	      keyid_from_pk(node->pkt->pkt.public_key,
			    (*klist)[*count].u.kid);
	    }
	  else
	    {
	      size_t dummy;

	      (*klist)[*count].mode=KEYDB_SEARCH_MODE_FPR20;
	      fingerprint_from_pk(node->pkt->pkt.public_key,
				  (*klist)[*count].u.fpr,&dummy);
	    }

	  (*count)++;

	  if(*count==num)
	    {
	      num+=100;
	      *klist=m_realloc(*klist,sizeof(KEYDB_SEARCH_DESC)*num);
	    }
	}
    }

  if(rc==-1)
    rc=0;
  
 leave:
  m_free(desc);
  keydb_release(kdbhd);
  release_kbnode(keyblock);

  return rc;
}

/* Note this is different than the original HKP refresh.  It allows
   usernames to refresh only part of the keyring. */

int 
keyserver_refresh(STRLIST users)
{
  int rc,count,fakev3=0;
  KEYDB_SEARCH_DESC *desc;

  /* If refresh_add_fake_v3_keyids is on and it's a HKP scheme, then
     enable fake v3 keyid generation. */
  if(opt.keyserver_options.refresh_add_fake_v3_keyids &&
     opt.keyserver_scheme &&
     (strcasecmp(opt.keyserver_scheme,"x-hkp")==0 ||
      strcasecmp(opt.keyserver_scheme,"hkp")==0 ||
      strcasecmp(opt.keyserver_scheme,"x-broken-hkp")==0))
    fakev3=1;

  rc=keyidlist(users,&desc,&count,fakev3);
  if(rc)
    return rc;

  if(count==1)
    log_info(_("%d key to refresh\n"),count);
  else
    log_info(_("%d keys to refresh\n"),count);

  if(count>0)
    rc=keyserver_work(GET,NULL,desc,count);

  m_free(desc);

  return 0;
}

int 
keyserver_search(STRLIST tokens)
{
  if(tokens)
    return keyserver_work(SEARCH,tokens,NULL,0);
  else
    return 0;
}

/* Count and searchstr are just for cosmetics.  If the count is too
   small, it will grow safely.  If negative it disables the "Key x-y
   of z" messages. */
void 
keyserver_search_prompt(IOBUF buffer,int count,const char *searchstr)
{
  int i=0,validcount=1;
  unsigned int maxlen=256,buflen=0;
  KEYDB_SEARCH_DESC *desc;
  byte *line=NULL;
  char *answer;

  if(count==0)
    goto notfound;

  if(count<0)
    {
      validcount=0;
      count=10;
    }

  desc=m_alloc(count*sizeof(KEYDB_SEARCH_DESC));

  /* Read each line and show it to the user */

  for(;;)
    {
      int rl;

      if(validcount && i%10==0)
	{
	  printf("Keys %d-%d of %d",i+1,(i+10<count)?i+10:count,count);
	  if(searchstr)
	    printf(" for \"%s\"",searchstr);
	  printf("\n");
	}

      maxlen=1024;
      rl=iobuf_read_line(buffer,&line,&buflen,&maxlen);
      if(rl>0)
	{
	  if(print_keyinfo(i+1,line,&desc[i])==0)
	    {
	      i++;

	      if(i==count)
		{
		  count+=10;
		  desc=m_realloc(desc,count*sizeof(KEYDB_SEARCH_DESC));
		  validcount=0;
		}
	    }
	  else
	    continue;
	}

      if(rl==0 && i==0)
	{
	  count=0;
	  break;
	}

      if(i%10==0 || rl==0)
	{
	  answer=cpr_get_no_help("keysearch.prompt",
				 _("Enter number(s), N)ext, or Q)uit > "));
	  /* control-d */
	  if(answer[0]=='\x04')
	    {
	      printf("Q\n");
	      answer[0]='q';
	    }

	  if(answer[0]=='q' || answer[0]=='Q')
	    {
	      m_free(answer);
	      break;
	    }
	  else if(atoi(answer)>=1 && atoi(answer)<=i)
	    {
	      char *split=answer,*num;

	      while((num=strsep(&split," ,"))!=NULL)
		if(atoi(num)>=1 && atoi(num)<=i)
		  keyserver_work(GET,NULL,&desc[atoi(num)-1],1);

	      m_free(answer);
	      break;
	    }
	}
    }

  m_free(desc);
  m_free(line);

 notfound:
  if(count==0)
    {
      if(searchstr)
	log_info(_("key \"%s\" not found on keyserver\n"),searchstr);
      else
	log_info(_("key not found on keyserver\n"));
      return;
    }
}
