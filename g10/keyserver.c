/* keyserver.c - generic keyserver code
 * Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
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
#include <assert.h>
#include "filter.h"
#include "keydb.h"
#include "status.h"
#include "exec.h"
#include "main.h"
#include "i18n.h"
#include "iobuf.h"
#include "memory.h"
#include "ttyio.h"
#include "options.h"
#include "packet.h"
#include "keyserver-internal.h"
#include "util.h"

#define GET    0
#define SEND   1
#define SEARCH 2

struct keyrec
{
  KEYDB_SEARCH_DESC desc;
  u32 createtime,expiretime;
  int size,flags;
  byte type;
  IOBUF uidbuf;
  unsigned int lines;
};

/* Tell remote processes about these options */
#define REMOTE_TELL (KEYSERVER_INCLUDE_REVOKED|KEYSERVER_INCLUDE_DISABLED|KEYSERVER_INCLUDE_SUBKEYS|KEYSERVER_TRY_DNS_SRV)

static struct parse_options keyserver_opts[]=
  {
    {"include-revoked",KEYSERVER_INCLUDE_REVOKED,NULL},      
    {"include-disabled",KEYSERVER_INCLUDE_DISABLED,NULL},
    {"include-subkeys",KEYSERVER_INCLUDE_SUBKEYS,NULL},
    {"keep-temp-files",KEYSERVER_KEEP_TEMP_FILES,NULL},
    {"refresh-add-fake-v3-keyids",KEYSERVER_ADD_FAKE_V3,NULL},
    {"auto-key-retrieve",KEYSERVER_AUTO_KEY_RETRIEVE,NULL},
    {"try-dns-srv",KEYSERVER_TRY_DNS_SRV,NULL},
    {"honor-keyserver-url",KEYSERVER_HONOR_KEYSERVER_URL,NULL},
    {NULL,0,NULL}
  };

static int keyserver_work(int action,STRLIST list,KEYDB_SEARCH_DESC *desc,
			  int count,struct keyserver_spec *keyserver);

int
parse_keyserver_options(char *options)
{
  int ret=1;
  char *tok;

  while((tok=optsep(&options)))
    {
      if(tok[0]=='\0')
	continue;

      /* We accept quite a few possible options here - some options to
	 handle specially, the keyserver_options list, and import and
	 export options that pertain to keyserver operations.  Note
	 that you must use strncasecmp here as there might be an
	 =argument attached which will foil the use of strcasecmp. */

      if(ascii_strncasecmp(tok,"verbose",7)==0)
	opt.keyserver_options.verbose++;
      else if(ascii_strncasecmp(tok,"no-verbose",10)==0)
	opt.keyserver_options.verbose--;
#ifdef EXEC_TEMPFILE_ONLY
      else if(ascii_strncasecmp(tok,"use-temp-files",14)==0 ||
	      ascii_strncasecmp(tok,"no-use-temp-files",17)==0)
	log_info(_("WARNING: keyserver option `%s' is not used"
		   " on this platform\n"),tok);
#else
      else if(ascii_strncasecmp(tok,"use-temp-files",14)==0)
	opt.keyserver_options.options|=KEYSERVER_USE_TEMP_FILES;
      else if(ascii_strncasecmp(tok,"no-use-temp-files",17)==0)
	opt.keyserver_options.options&=~KEYSERVER_USE_TEMP_FILES;
#endif
      else if(!parse_options(tok,&opt.keyserver_options.options,
			     keyserver_opts,0)
	 && !parse_import_options(tok,
				  &opt.keyserver_options.import_options,0)
	 && !parse_export_options(tok,
				  &opt.keyserver_options.export_options,0))
	{
	  /* All of the standard options have failed, so the option is
	     destined for a keyserver plugin. */
	  char *arg=argsplit(tok);

	  if(arg)
	    {
	      char *joined;

	      joined=m_alloc(strlen(tok)+1+strlen(arg)+1);
	      /* Make a canonical name=value form with no
		 spaces */
	      strcpy(joined,tok);
	      strcat(joined,"=");
	      strcat(joined,arg);
	      add_to_strlist(&opt.keyserver_options.other,joined);
	      m_free(joined);
	    }
	  else
	    add_to_strlist(&opt.keyserver_options.other,tok);
	}
    }

  return ret;
}

void
free_keyserver_spec(struct keyserver_spec *keyserver)
{
  m_free(keyserver->uri);
  m_free(keyserver->host);
  m_free(keyserver->port);
  m_free(keyserver->path);
  m_free(keyserver->opaque);
  m_free(keyserver);
}

struct keyserver_spec *
parse_keyserver_uri(const char *uri,int require_scheme,
		    const char *configname,unsigned int configlineno)
{
  int assume_hkp=0;
  struct keyserver_spec *keyserver;
  const char *idx;
  int count;

  assert(uri!=NULL);

  keyserver=m_alloc_clear(sizeof(struct keyserver_spec));

  keyserver->uri=m_strdup(uri);

  /* Get the scheme */

  for(idx=uri,count=0;*idx && *idx!=':';idx++)
    count++;

  if(count==0)
    goto fail;

  if(*idx=='\0')
    {
      if(require_scheme)
	return NULL;

      /* Assume HKP if there is no scheme */
      assume_hkp=1;
      keyserver->scheme=m_strdup("hkp");
    }
  else
    {
      int i;

      keyserver->scheme=m_alloc(count+1);

      /* Force to lowercase */
      for(i=0;i<count;i++)
	keyserver->scheme[i]=ascii_tolower(uri[i]);

      keyserver->scheme[i]='\0';

      /* Skip past the scheme and colon */
      uri+=count+1;
    }

  if(ascii_strcasecmp(keyserver->scheme,"x-broken-hkp")==0)
    {
      deprecated_warning(configname,configlineno,"x-broken-hkp",
			 "--keyserver-options ","broken-http-proxy");
      m_free(keyserver->scheme);
      keyserver->scheme=m_strdup("hkp");
      add_to_strlist(&opt.keyserver_options.other,"broken-http-proxy");
    }
  else if(ascii_strcasecmp(keyserver->scheme,"x-hkp")==0)
    {
      /* Canonicalize this to "hkp" so it works with both the internal
	 and external keyserver interface. */
      m_free(keyserver->scheme);
      keyserver->scheme=m_strdup("hkp");
    }

  if(assume_hkp || (uri[0]=='/' && uri[1]=='/'))
    {
      /* Two slashes means network path. */

      /* Skip over the "//", if any */
      if(!assume_hkp)
	uri+=2;

      for(idx=uri,count=0;*idx && *idx!=':' && *idx!='/';idx++)
	count++;

      if(count==0)
	goto fail;

      keyserver->host=m_alloc(count+1);
      strncpy(keyserver->host,uri,count);
      keyserver->host[count]='\0';

      /* Skip past the host */
      uri+=count;

      if(*uri==':')
	{
	  /* It would seem to be reasonable to limit the range of the
	     ports to values between 1-65535, but RFC 1738 and 1808
	     imply there is no limit.  Of course, the real world has
	     limits. */

	  for(idx=uri+1,count=0;*idx && *idx!='/';idx++)
	    {
	      count++;

	      /* Ports are digits only */
	      if(!digitp(idx))
		goto fail;
	    }

	  keyserver->port=m_alloc(count+1);
	  strncpy(keyserver->port,uri+1,count);
	  keyserver->port[count]='\0';

	  /* Skip past the colon and port number */
	  uri+=1+count;
	}

      /* Everything else is the path */
      if(*uri)
	keyserver->path=m_strdup(uri);
      else
	keyserver->path=m_strdup("/");
    }
  else if(uri[0]!='/')
    {
      /* No slash means opaque.  Just record the opaque blob and get
	 out. */
      keyserver->opaque=m_strdup(uri);
    }
  else
    {
      /* One slash means absolute path.  We don't need to support that
	 yet. */
      goto fail;
    }

  return keyserver;

 fail:
  free_keyserver_spec(keyserver);

  return NULL;
}

struct keyserver_spec *
parse_preferred_keyserver(PKT_signature *sig)
{
  struct keyserver_spec *spec=NULL;
  const byte *p;
  size_t plen;

  p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_PREF_KS,&plen);
  if(p && plen)
    {
      byte *dupe=m_alloc(plen+1);

      memcpy(dupe,p,plen);
      dupe[plen]='\0';
      spec=parse_keyserver_uri(dupe,0,NULL,0);
      m_free(dupe);
    }

  return spec;
}

static void
print_keyrec(int number,struct keyrec *keyrec)
{
  int i;

  iobuf_writebyte(keyrec->uidbuf,0);
  iobuf_flush_temp(keyrec->uidbuf);
  printf("(%d)\t%s  ",number,iobuf_get_temp_buffer(keyrec->uidbuf));

  if(keyrec->size>0)
    printf("%d bit ",keyrec->size);

  if(keyrec->type)
    {
      const char *str=pubkey_algo_to_string(keyrec->type);

      if(str)
	printf("%s ",str);
      else
	printf("unknown ");
    }

  switch(keyrec->desc.mode)
    {
      /* If the keyserver helper gave us a short keyid, we have no
	 choice but to use it.  Do check --keyid-format to add a 0x if
	 needed. */
    case KEYDB_SEARCH_MODE_SHORT_KID:
      printf("key %s%08lX",
	     (opt.keyid_format==KF_0xSHORT
	      || opt.keyid_format==KF_0xLONG)?"0x":"",
	     (ulong)keyrec->desc.u.kid[1]);
      break;

      /* However, if it gave us a long keyid, we can honor
	 --keyid-format */
    case KEYDB_SEARCH_MODE_LONG_KID:
      printf("key %s",keystr(keyrec->desc.u.kid));
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      printf("key ");
      for(i=0;i<16;i++)
	printf("%02X",keyrec->desc.u.fpr[i]);
      break;

    case KEYDB_SEARCH_MODE_FPR20:
      printf("key ");
      for(i=0;i<20;i++)
	printf("%02X",keyrec->desc.u.fpr[i]);
      break;

    default:
      BUG();
      break;
    }

  if(keyrec->createtime>0)
    printf(", created %s",strtimestamp(keyrec->createtime));

  if(keyrec->expiretime>0)
    printf(", expires %s",strtimestamp(keyrec->expiretime));

  if(keyrec->flags&1)
    printf(" (%s)",("revoked"));
  if(keyrec->flags&2)
    printf(" (%s)",("disabled"));
  if(keyrec->flags&4)
    printf(" (%s)",("expired"));

  printf("\n");
}

/* Returns a keyrec (which must be freed) once a key is complete, and
   NULL otherwise.  Call with a NULL keystring once key parsing is
   complete to return any unfinished keys. */
static struct keyrec *
parse_keyrec(char *keystring)
{
  static struct keyrec *work=NULL;
  struct keyrec *ret=NULL;
  char *record;
  int i;

  if(keystring==NULL)
    {
      if(work==NULL)
	return NULL;
      else if(work->desc.mode==KEYDB_SEARCH_MODE_NONE)
	{
	  m_free(work);
	  return NULL;
	}
      else
	{
	  ret=work;
	  work=NULL;
	  return ret;
	}
    }

  if(work==NULL)
    {
      work=m_alloc_clear(sizeof(struct keyrec));
      work->uidbuf=iobuf_temp();
    }

  /* Remove trailing whitespace */
  for(i=strlen(keystring);i>0;i--)
    if(ascii_isspace(keystring[i-1]))
      keystring[i-1]='\0';
    else
      break;

  if((record=strsep(&keystring,":"))==NULL)
    return ret;

  if(ascii_strcasecmp("pub",record)==0)
    {
      char *tok;

      if(work->desc.mode)
	{
	  ret=work;
	  work=m_alloc_clear(sizeof(struct keyrec));
	  work->uidbuf=iobuf_temp();
	}

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      classify_user_id(tok,&work->desc);
      if(work->desc.mode!=KEYDB_SEARCH_MODE_SHORT_KID
	 && work->desc.mode!=KEYDB_SEARCH_MODE_LONG_KID
	 && work->desc.mode!=KEYDB_SEARCH_MODE_FPR16
	 && work->desc.mode!=KEYDB_SEARCH_MODE_FPR20)
	{
	  work->desc.mode=KEYDB_SEARCH_MODE_NONE;
	  return ret;
	}

      /* Note all items after this are optional.  This allows us to
         have a pub line as simple as pub:keyid and nothing else. */

      work->lines++;

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      work->type=atoi(tok);

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      work->size=atoi(tok);

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      if(atoi(tok)<=0)
	work->createtime=0;
      else
	work->createtime=atoi(tok);

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      if(atoi(tok)<=0)
	work->expiretime=0;
      else
	{
	  work->expiretime=atoi(tok);
	  /* Force the 'e' flag on if this key is expired. */
	  if(work->expiretime<=make_timestamp())
	    work->flags|=4;
	}

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      while(*tok)
	switch(*tok++)
	  {
	  case 'r':
	  case 'R':
	    work->flags|=1;
	    break;
	    
	  case 'd':
	  case 'D':
	    work->flags|=2;
	    break;

	  case 'e':
	  case 'E':
	    work->flags|=4;
	    break;
	  }
    }
  else if(ascii_strcasecmp("uid",record)==0 && work->desc.mode)
    {
      char *userid,*tok,*decoded;

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      if(strlen(tok)==0)
	return ret;

      userid=tok;

      /* By definition, de-%-encoding is always smaller than the
         original string so we can decode in place. */

      i=0;

      while(*tok)
	if(tok[0]=='%' && tok[1] && tok[2])
	  {
	    if((userid[i]=hextobyte(&tok[1]))==-1)
	      userid[i]='?';

	    i++;
	    tok+=3;
	  }
	else
	  userid[i++]=*tok++;

      /* We don't care about the other info provided in the uid: line
         since no keyserver supports marking userids with timestamps
         or revoked/expired/disabled yet. */

      /* No need to check for control characters, as utf8_to_native
	 does this for us. */

      decoded=utf8_to_native(userid,i,0);
      if(strlen(decoded)>opt.screen_columns-10)
	decoded[opt.screen_columns-10]='\0';
      iobuf_writestr(work->uidbuf,decoded);
      m_free(decoded);
      iobuf_writestr(work->uidbuf,"\n\t");
      work->lines++;
    }

  /* Ignore any records other than "pri" and "uid" for easy future
     growth. */

  return ret;
}

/* TODO: do this as a list sent to keyserver_work rather than calling
   it once for each key to get the correct counts after the import
   (cosmetics, really) and to better take advantage of the keyservers
   that can do multiple fetches in one go (LDAP). */
static int
show_prompt(KEYDB_SEARCH_DESC *desc,int numdesc,int count,const char *search)
{
  char *answer;

  if(count && opt.command_fd==-1)
    {
      static int from=1;
      tty_printf("Keys %d-%d of %d for \"%s\".  ",from,numdesc,count,search);
      from=numdesc+1;
    }

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
      return 1;
    }
  else if(atoi(answer)>=1 && atoi(answer)<=numdesc)
    {
      char *split=answer,*num;

      while((num=strsep(&split," ,"))!=NULL)
	if(atoi(num)>=1 && atoi(num)<=numdesc)
	  keyserver_work(GET,NULL,&desc[atoi(num)-1],1,opt.keyserver);

      m_free(answer);
      return 1;
    }

  return 0;
}

/* Count and searchstr are just for cosmetics.  If the count is too
   small, it will grow safely.  If negative it disables the "Key x-y
   of z" messages.  searchstr should be UTF-8 (rather than native). */
static void
keyserver_search_prompt(IOBUF buffer,const char *searchstr)
{
  int i=0,validcount=0,started=0,header=0,count=1;
  unsigned int maxlen,buflen,numlines=0;
  KEYDB_SEARCH_DESC *desc;
  byte *line=NULL;
  char *localstr=NULL;

  if(searchstr)
    localstr=utf8_to_native(searchstr,strlen(searchstr),0);

  desc=m_alloc(count*sizeof(KEYDB_SEARCH_DESC));

  for(;;)
    {
      struct keyrec *keyrec;
      int rl;

      maxlen=1024;
      rl=iobuf_read_line(buffer,&line,&buflen,&maxlen);

      if(opt.with_colons)
	{
	  if(!header && ascii_strncasecmp("SEARCH ",line,7)==0
	     && ascii_strncasecmp(" BEGIN",&line[strlen(line)-7],6)==0)
	    {
	      header=1;
	      continue;
	    }
	  else if(ascii_strncasecmp("SEARCH ",line,7)==0
		  && ascii_strncasecmp(" END",&line[strlen(line)-5],4)==0)
	    continue;

	  printf("%s",line);
	}

      /* Look for an info: line.  The only current info: values
	 defined are the version and key count. */
      if(!started && rl>0 && ascii_strncasecmp("info:",line,5)==0)
	{
	  char *tok,*str=&line[5];

	  if((tok=strsep(&str,":"))!=NULL)
	    {
	      int version;

	      if(sscanf(tok,"%d",&version)!=1)
		version=1;

	      if(version!=1)
		{
		  log_error(_("invalid keyserver protocol "
			      "(us %d!=handler %d)\n"),1,version);
		  break;
		}
	    }

	  if((tok=strsep(&str,":"))!=NULL && sscanf(tok,"%d",&count)==1)
	    {
	      if(count==0)
		goto notfound;
	      else if(count<0)
		count=10;
	      else
		validcount=1;

	      desc=m_realloc(desc,count*sizeof(KEYDB_SEARCH_DESC));
	    }

	  started=1;
	  continue;
	}

      if(rl==0)
	{
	  keyrec=parse_keyrec(NULL);

	  if(keyrec==NULL)
	    {
	      if(i==0)
		{
		  count=0;
		  break;
		}

	      if(i!=count)
		validcount=0;

	      for(;;)
		{
		  if(show_prompt(desc,i,validcount?count:0,localstr))
		    break;
		  validcount=0;
		}

	      break;
	    }
	}
      else
	keyrec=parse_keyrec(line);

      if(i==count)
	{
	  /* keyserver helper sent more keys than they claimed in the
	     info: line. */
	  count+=10;
	  desc=m_realloc(desc,count*sizeof(KEYDB_SEARCH_DESC));
	  validcount=0;
	}

      if(keyrec)
	{
	  desc[i]=keyrec->desc;

	  if(!opt.with_colons)
	    {
	      /* screen_lines - 1 for the prompt. */
	      if(numlines+keyrec->lines>opt.screen_lines-1)
		{
		  if(show_prompt(desc,i,validcount?count:0,localstr))
		    break;
		  else
		    numlines=0;
		}

	      print_keyrec(i+1,keyrec);
	    }

	  numlines+=keyrec->lines;
	  iobuf_close(keyrec->uidbuf);
	  m_free(keyrec);

	  started=1;
	  i++;
	}
    }

 notfound:
  if(count==0)
    {
      if(localstr)
	log_info(_("key \"%s\" not found on keyserver\n"),localstr);
      else
	log_info(_("key not found on keyserver\n"));
    }

  m_free(localstr);
  m_free(desc);
  m_free(line);
}

#define KEYSERVER_ARGS_KEEP " -o \"%O\" \"%I\""
#define KEYSERVER_ARGS_NOKEEP " -o \"%o\" \"%i\""

static int 
keyserver_spawn(int action,STRLIST list,KEYDB_SEARCH_DESC *desc,
		int count,int *prog,struct keyserver_spec *keyserver)
{
  int ret=0,i,gotversion=0,outofband=0;
  STRLIST temp;
  unsigned int maxlen,buflen;
  char *command=NULL,*searchstr=NULL;
  byte *line=NULL;
  struct parse_options *kopts;
  struct exec_info *spawn;

  assert(keyserver);

#ifdef EXEC_TEMPFILE_ONLY
  opt.keyserver_options.options|=KEYSERVER_USE_TEMP_FILES;
#endif

  /* Push the libexecdir into path.  If DISABLE_KEYSERVER_PATH is set,
     use the 0 arg to replace the path. */
#ifdef DISABLE_KEYSERVER_PATH
  set_exec_path(GNUPG_LIBEXECDIR,0);
#else
  set_exec_path(GNUPG_LIBEXECDIR,opt.exec_path_set);
#endif

  /* Build the filename for the helper to execute */
  command=m_alloc(strlen("gpgkeys_")+strlen(keyserver->scheme)+1);
  strcpy(command,"gpgkeys_");
  strcat(command,keyserver->scheme);

  if(opt.keyserver_options.options&KEYSERVER_USE_TEMP_FILES)
    {
      if(opt.keyserver_options.options&KEYSERVER_KEEP_TEMP_FILES)
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

      ret=exec_write(&spawn,NULL,command,NULL,0,0);
    }
  else
    ret=exec_write(&spawn,command,NULL,NULL,0,0);

  if(ret)
    return ret;

  fprintf(spawn->tochild,
	  "# This is a GnuPG %s keyserver communications file\n",VERSION);
  fprintf(spawn->tochild,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(spawn->tochild,"PROGRAM %s\n",VERSION);
  fprintf(spawn->tochild,"SCHEME %s\n",keyserver->scheme);

  if(keyserver->opaque)
    fprintf(spawn->tochild,"OPAQUE %s\n",keyserver->opaque);
  else
    {
      if(keyserver->host)
	fprintf(spawn->tochild,"HOST %s\n",keyserver->host);

      if(keyserver->port)
	fprintf(spawn->tochild,"PORT %s\n",keyserver->port);

      if(keyserver->path)
	fprintf(spawn->tochild,"PATH %s\n",keyserver->path);
    }

  /* Write options */

  for(i=0,kopts=keyserver_opts;kopts[i].name;i++)
    if(opt.keyserver_options.options & kopts[i].bit & REMOTE_TELL)
      fprintf(spawn->tochild,"OPTION %s\n",kopts[i].name);

  for(i=0;i<opt.keyserver_options.verbose;i++)
    fprintf(spawn->tochild,"OPTION verbose\n");

  for(temp=opt.keyserver_options.other;temp;temp=temp->next)
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
		  fprintf(spawn->tochild,"%02X",desc[i].u.fpr[f]);

		fprintf(spawn->tochild,"\n");
	      }
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_FPR16)
	      {
		int f;

		fprintf(spawn->tochild,"0x");

		for(f=0;f<16;f++)
		  fprintf(spawn->tochild,"%02X",desc[i].u.fpr[f]);

		fprintf(spawn->tochild,"\n");
	      }
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_LONG_KID)
	      fprintf(spawn->tochild,"0x%08lX%08lX\n",
		      (ulong)desc[i].u.kid[0],
		      (ulong)desc[i].u.kid[1]);
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_SHORT_KID)
	      fprintf(spawn->tochild,"0x%08lX\n",
		      (ulong)desc[i].u.kid[1]);

	    log_info(_("requesting key %s from %s server %s\n"),
		     keystr_from_desc(&desc[i]),
		     keyserver->scheme,keyserver->host);
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
	    KBNODE block;

	    temp=NULL;
	    add_to_strlist(&temp,key->d);

	    memset(&afx,0,sizeof(afx));
	    afx.what=1;
	    iobuf_push_filter(buffer,armor_filter,&afx);

	    /* TODO: Remove Comment: lines from keys exported this
	       way? */

	    if(export_pubkeys_stream(buffer,temp,&block,
				     opt.keyserver_options.export_options)==-1)
	      iobuf_close(buffer);
	    else
	      {
		KBNODE node;

		iobuf_flush_temp(buffer);

		merge_keys_and_selfsig(block);

		fprintf(spawn->tochild,"INFO %08lX%08lX BEGIN\n",
			(ulong)block->pkt->pkt.public_key->keyid[0],
			(ulong)block->pkt->pkt.public_key->keyid[1]);

		for(node=block;node;node=node->next)
		  {
		    switch(node->pkt->pkttype)
		      {
		      default:
			continue;

		      case PKT_PUBLIC_KEY:
		      case PKT_PUBLIC_SUBKEY:
			{
			  PKT_public_key *pk=node->pkt->pkt.public_key;

			  keyid_from_pk(pk,NULL);

			  fprintf(spawn->tochild,"%sb:%08lX%08lX:%u:%u:%u:%u:",
				  node->pkt->pkttype==PKT_PUBLIC_KEY?"pu":"su",
				  (ulong)pk->keyid[0],(ulong)pk->keyid[1],
				  pk->pubkey_algo,
				  nbits_from_pk(pk),
				  pk->timestamp,
				  pk->expiredate);

			  if(pk->is_revoked)
			    fprintf(spawn->tochild,"r");
			  if(pk->has_expired)
			    fprintf(spawn->tochild,"e");

			  fprintf(spawn->tochild,"\n");
			}
			break;

		      case PKT_USER_ID:
			{
			  PKT_user_id *uid=node->pkt->pkt.user_id;
			  int r;

			  if(uid->attrib_data)
			    continue;

			  fprintf(spawn->tochild,"uid:");

			  /* Quote ':', '%', and any 8-bit
			     characters */
			  for(r=0;r<uid->len;r++)
			    {
			      if(uid->name[r]==':' || uid->name[r]=='%'
				 || uid->name[r]&0x80)
				fprintf(spawn->tochild,"%%%02X",
					(byte)uid->name[r]);
			      else
				fprintf(spawn->tochild,"%c",uid->name[r]);
			    }

			  fprintf(spawn->tochild,":%u:%u:",
				  uid->created,uid->expiredate);

			  if(uid->is_revoked)
			    fprintf(spawn->tochild,"r");
			  if(uid->is_expired)
			    fprintf(spawn->tochild,"e");

			  fprintf(spawn->tochild,"\n");
			}
			break;

			/* This bit is really for the benefit of
			   people who store their keys in LDAP
			   servers.  It makes it easy to do queries
			   for things like "all keys signed by
			   Isabella". */
		      case PKT_SIGNATURE:
			{
			  PKT_signature *sig=node->pkt->pkt.signature;

			  if(!IS_UID_SIG(sig))
			    continue;

			  fprintf(spawn->tochild,"sig:%08lX%08lX:%X:%u:%u\n",
				  (ulong)sig->keyid[0],(ulong)sig->keyid[1],
				  sig->sig_class,sig->timestamp,
				  sig->expiredate);
			}
			break;
		      }
		  }

		fprintf(spawn->tochild,"INFO %08lX%08lX END\n",
			(ulong)block->pkt->pkt.public_key->keyid[0],
			(ulong)block->pkt->pkt.public_key->keyid[1]);

		fprintf(spawn->tochild,"KEY %s BEGIN\n",key->d);
		fwrite(iobuf_get_temp_buffer(buffer),
		       iobuf_get_temp_length(buffer),1,spawn->tochild);
		fprintf(spawn->tochild,"KEY %s END\n",key->d);

		iobuf_close(buffer);

		log_info(_("sending key %s to %s server %s\n"),
			 keystr(block->pkt->pkt.public_key->keyid),
			 keyserver->scheme,keyserver->host);

		release_kbnode(block);
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

	log_info(_("searching for \"%s\" from %s server %s\n"),
		 searchstr,keyserver->scheme,keyserver->host);

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

  for(;;)
    {
      int plen;
      char *ptr;

      maxlen=1024;
      if(iobuf_read_line(spawn->fromchild,&line,&buflen,&maxlen)==0)
	{
	  ret=G10ERR_READ_FILE;
	  goto fail; /* i.e. EOF */
	}

      ptr=line;

      /* remove trailing whitespace */
      plen=strlen(ptr);
      while(plen>0 && ascii_isspace(ptr[plen-1]))
	plen--;
      plen[ptr]='\0';

      if(*ptr=='\0')
	break;

      if(ascii_strncasecmp(ptr,"VERSION ",8)==0)
	{
	  gotversion=1;

	  if(atoi(&ptr[8])!=KEYSERVER_PROTO_VERSION)
	    {
	      log_error(_("invalid keyserver protocol (us %d!=handler %d)\n"),
			KEYSERVER_PROTO_VERSION,atoi(&ptr[8]));
	      goto fail;
	    }
	}
      else if(ascii_strncasecmp(ptr,"PROGRAM ",8)==0)
	{
	  if(ascii_strncasecmp(&ptr[8],VERSION,strlen(VERSION))!=0)
	    log_info(_("WARNING: keyserver handler from a different"
		       " version of GnuPG (%s)\n"),&ptr[8]);
	}
      else if(ascii_strncasecmp(ptr,"OPTION OUTOFBAND",16)==0)
	outofband=1; /* Currently the only OPTION */
    }

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

	  /* Slurp up all the key data.  In the future, it might be
	     nice to look for KEY foo OUTOFBAND and FAILED indicators.
	     It's harmless to ignore them, but ignoring them does make
	     gpg complain about "no valid OpenPGP data found".  One
	     way to do this could be to continue parsing this
	     line-by-line and make a temp iobuf for each key. */

	  import_keys_stream(spawn->fromchild,stats_handle,
			     opt.keyserver_options.import_options);

	  import_print_stats(stats_handle);
	  import_release_stats_handle(stats_handle);

	  break;
	}

	/* Nothing to do here */
      case SEND:
	break;

      case SEARCH:
	keyserver_search_prompt(spawn->fromchild,searchstr);
	break;

      default:
	log_fatal(_("no keyserver action!\n"));
	break;
      }

 fail:
  m_free(line);
  m_free(searchstr);

  *prog=exec_finish(spawn);

  return ret;
}

static int 
keyserver_work(int action,STRLIST list,KEYDB_SEARCH_DESC *desc,
	       int count,struct keyserver_spec *keyserver)
{
  int rc=0,ret=0;

  if(!keyserver)
    {
      log_error(_("no keyserver known (use option --keyserver)\n"));
      return G10ERR_BAD_URI;
    }

#ifdef DISABLE_KEYSERVER_HELPERS

  log_error(_("external keyserver calls are not supported in this build\n"));
  return G10ERR_KEYSERVER;

#else
  /* Spawn a handler */

  rc=keyserver_spawn(action,list,desc,count,&ret,keyserver);
  if(ret)
    {
      switch(ret)
	{
	case KEYSERVER_SCHEME_NOT_FOUND:
	  log_error(_("no handler for keyserver scheme `%s'\n"),
		    keyserver->scheme);
	  break;

	case KEYSERVER_NOT_SUPPORTED:
	  log_error(_("action `%s' not supported with keyserver "
		      "scheme `%s'\n"),
		    action==GET?"get":action==SEND?"send":
		    action==SEARCH?"search":"unknown",
		    keyserver->scheme);
	  break;

	case KEYSERVER_VERSION_ERROR:
	  log_error(_("gpgkeys_%s does not support handler version %d\n"),
		    keyserver->scheme,KEYSERVER_PROTO_VERSION);
	  break;

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
#endif /* ! DISABLE_KEYSERVER_HELPERS*/
}

int 
keyserver_export(STRLIST users)
{
  STRLIST sl=NULL;
  KEYDB_SEARCH_DESC desc;
  int rc=0;

  /* Weed out descriptors that we don't support sending */
  for(;users;users=users->next)
    {
      classify_user_id (users->d, &desc);
      if(desc.mode!=KEYDB_SEARCH_MODE_SHORT_KID &&
	 desc.mode!=KEYDB_SEARCH_MODE_LONG_KID &&
	 desc.mode!=KEYDB_SEARCH_MODE_FPR16 &&
	 desc.mode!=KEYDB_SEARCH_MODE_FPR20)
	{
	  log_error(_("\"%s\" not a key ID: skipping\n"),users->d);
	  continue;
	}
      else
	append_to_strlist(&sl,users->d);
    }

  if(sl)
    {
      rc=keyserver_work(SEND,sl,NULL,0,opt.keyserver);
      free_strlist(sl);
    }

  return rc;
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
	  log_error(_("\"%s\" not a key ID: skipping\n"),users->d);
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
    rc=keyserver_work(GET,NULL,desc,count,opt.keyserver);

  m_free(desc);

  return rc;
}

int
keyserver_import_fprint(const byte *fprint,size_t fprint_len,
			struct keyserver_spec *keyserver)
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

  return keyserver_work(GET,NULL,&desc,1,keyserver);
}

int 
keyserver_import_keyid(u32 *keyid,struct keyserver_spec *keyserver)
{
  KEYDB_SEARCH_DESC desc;

  memset(&desc,0,sizeof(desc));

  desc.mode=KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0]=keyid[0];
  desc.u.kid[1]=keyid[1];

  return keyserver_work(GET,NULL,&desc,1,keyserver);
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
	    log_error (_("key \"%s\" not found: %s\n"),
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
             This is because it's easy to calculate any sort of keyid
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

	  /* This is a little hackish, using the skipfncvalue as a
	     void* pointer to the keyserver spec, but we don't need
	     the skipfnc here, and it saves having an additional field
	     for this (which would be wasted space most of the
	     time). */

	  (*klist)[*count].skipfncvalue=NULL;

	  /* Are we honoring preferred keyservers? */
	  if(opt.keyserver_options.options&KEYSERVER_HONOR_KEYSERVER_URL)
	    {
	      PKT_user_id *uid=NULL;
	      PKT_signature *sig=NULL;

	      merge_keys_and_selfsig(keyblock);

	      for(node=node->next;node;node=node->next)
		{
		  if(node->pkt->pkttype==PKT_USER_ID
		     && node->pkt->pkt.user_id->is_primary)
		    uid=node->pkt->pkt.user_id;
		  else if(node->pkt->pkttype==PKT_SIGNATURE
			  && node->pkt->pkt.signature->
			  flags.chosen_selfsig && uid)
		    {
		      sig=node->pkt->pkt.signature;
		      break;
		    }
		}

	      /* Try and parse the keyserver URL.  If it doesn't work,
		 then we end up writing NULL which indicates we are
		 the same as any other key. */
	      if(uid && sig)
		(*klist)[*count].skipfncvalue=parse_preferred_keyserver(sig);
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
  if(rc)
    m_free(*klist);
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
  int rc,count,numdesc,fakev3=0;
  KEYDB_SEARCH_DESC *desc;

  /* We switch merge_only on during a refresh, as 'refresh' should
     never import new keys, even if their keyids match.  Is it worth
     preserving the old merge_only value here? */
  opt.import_options|=IMPORT_MERGE_ONLY;

  /* If refresh_add_fake_v3_keyids is on and it's a HKP or MAILTO
     scheme, then enable fake v3 keyid generation. */
  if((opt.keyserver_options.options&KEYSERVER_ADD_FAKE_V3) && opt.keyserver
     && (ascii_strcasecmp(opt.keyserver->scheme,"hkp")==0 ||
	 ascii_strcasecmp(opt.keyserver->scheme,"mailto")==0))
    fakev3=1;

  rc=keyidlist(users,&desc,&numdesc,fakev3);
  if(rc)
    return rc;

  count=numdesc;
  if(count>0)
    {
      int i;

      /* Try to handle preferred keyserver keys first */
      for(i=0;i<count;i++)
	{
	  if(desc[i].skipfncvalue)
	    {
	      struct keyserver_spec *keyserver=desc[i].skipfncvalue;

	      /* We use the keyserver structure we parsed out before.
		 Note that a preferred keyserver without a scheme://
		 will be interpreted as hkp:// */

	      rc=keyserver_work(GET,NULL,&desc[i],1,keyserver);
	      if(rc)
		log_info(_("WARNING: unable to refresh key %s"
			   " via %s: %s\n"),keystr_from_desc(&desc[i]),
			 keyserver->uri,g10_errstr(rc));
	      else
		{
		  /* We got it, so mark it as NONE so we don't try and
		     get it again from the regular keyserver. */

		  desc[i].mode=KEYDB_SEARCH_MODE_NONE;
		  count--;
		}

	      free_keyserver_spec(keyserver);
	    }
	}
    }

  if(count>0)
    {
      if(opt.keyserver)
	{
	  if(count==1)
	    log_info(_("refreshing 1 key from %s\n"),opt.keyserver->uri);
	  else
	    log_info(_("refreshing %d keys from %s\n"),
		     count,opt.keyserver->uri);
	}

      rc=keyserver_work(GET,NULL,desc,numdesc,opt.keyserver);
    }

  m_free(desc);

  return rc;
}

int
keyserver_search(STRLIST tokens)
{
  if(tokens)
    return keyserver_work(SEARCH,tokens,NULL,0,opt.keyserver);
  else
    return 0;
}
