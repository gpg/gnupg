/* keyserver.c - generic keyserver code
 * Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
  time_t createtime,expiretime;
  int size,flags;
  byte type;
  IOBUF uidbuf;
  int lines;
};

struct kopts
{
  char *name;
  int tell; /* tell remote process about this one */
  int *flag;
} keyserver_opts[]=
{
  {"include-revoked",1,&opt.keyserver_options.include_revoked},
  {"include-disabled",1,&opt.keyserver_options.include_disabled},
  {"include-subkeys",1,&opt.keyserver_options.include_subkeys},
  {"keep-temp-files",0,&opt.keyserver_options.keep_temp_files},
  {"honor-http-proxy",1,&opt.keyserver_options.honor_http_proxy},
  {"broken-http-proxy",1,&opt.keyserver_options.broken_http_proxy},
  {"refresh-add-fake-v3-keyids",0,&opt.keyserver_options.fake_v3_keyids},
  {"auto-key-retrieve",0,&opt.keyserver_options.auto_key_retrieve},
  {"try-dns-srv",1,&opt.keyserver_options.try_dns_srv},
  {NULL}
};

static int keyserver_work(int action,STRLIST list,
			  KEYDB_SEARCH_DESC *desc,int count);

static void
strip_leading_space(char **stringp)
{
  while(**stringp)
    {
      if(ascii_isspace(**stringp))
	(*stringp)++;
      else
	return;
    }
}

static char *
get_arg(char **stringp)
{
  strip_leading_space(stringp);

  if(**stringp=='=')
    {
      (*stringp)++;
      strip_leading_space(stringp);
      return strsep(stringp," ,");
    }

  return NULL;
}

void 
parse_keyserver_options(char *options)
{
  char *tok;

  while((tok=strsep(&options," ,")))
    {
      int i,hit=0;

      if(tok[0]=='\0')
	continue;

      for(i=0;keyserver_opts[i].name;i++)
	{
	  if(ascii_strcasecmp(tok,keyserver_opts[i].name)==0)
	    {
	      *(keyserver_opts[i].flag)=1;
	      hit=1;
	      break;
	    }
	  else if(ascii_strncasecmp("no-",tok,3)==0 &&
		  ascii_strcasecmp(&tok[3],keyserver_opts[i].name)==0)
	    {
	      *(keyserver_opts[i].flag)=0;
	      hit=1;
	      break;
	    }
	}

      /* These options need more than just a flag */
      if(!hit)
	{
	  if(ascii_strcasecmp(tok,"verbose")==0)
	    opt.keyserver_options.verbose++;
	  else if(ascii_strcasecmp(tok,"no-verbose")==0)
	    opt.keyserver_options.verbose--;
#ifdef EXEC_TEMPFILE_ONLY
	  else if(ascii_strcasecmp(tok,"use-temp-files")==0 ||
		  ascii_strcasecmp(tok,"no-use-temp-files")==0)
	    log_info(_("WARNING: keyserver option \"%s\" is not used "
		       "on this platform\n"),tok);
#else
	  else if(ascii_strcasecmp(tok,"use-temp-files")==0)
	    opt.keyserver_options.use_temp_files=1;
	  else if(ascii_strcasecmp(tok,"no-use-temp-files")==0)
	    opt.keyserver_options.use_temp_files=0;
#endif
	  else
	    if(!parse_import_options(tok,
				     &opt.keyserver_options.import_options,0)
	       &&
	       !parse_export_options(tok,
				     &opt.keyserver_options.export_options,0))
	      {
		char *arg;
		if(options && (arg=get_arg(&options)))
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
    }
}

int 
parse_keyserver_uri(char *uri,const char *configname,unsigned int configlineno)
{
  int assume_hkp=0;

  assert(uri!=NULL);

  opt.keyserver_host=NULL;
  opt.keyserver_port=NULL;
  opt.keyserver_opaque=NULL;

  /* Get the scheme */

  opt.keyserver_scheme=strsep(&uri,":");
  if(uri==NULL)
    {
      /* Assume HKP if there is no scheme */
      assume_hkp=1;
      uri=opt.keyserver_scheme;
      opt.keyserver_scheme="hkp";
    }
  else
    {
      /* Force to lowercase */
      char *i;

      for(i=opt.keyserver_scheme;*i!='\0';i++)
	*i=ascii_tolower(*i);
    }

  if(ascii_strcasecmp(opt.keyserver_scheme,"x-broken-hkp")==0)
    {
      deprecated_warning(configname,configlineno,"x-broken-hkp",
			 "--keyserver-options ","broken-http-proxy");
      opt.keyserver_scheme="hkp";
      opt.keyserver_options.broken_http_proxy=1;
    }
  else if(ascii_strcasecmp(opt.keyserver_scheme,"x-hkp")==0
	  || ascii_strcasecmp(opt.keyserver_scheme,"http")==0)
    {
      /* Canonicalize this to "hkp" so it works with both the internal
	 and external keyserver interface. */
      opt.keyserver_scheme="hkp";
    }

  if(assume_hkp || (uri[0]=='/' && uri[1]=='/'))
    {
      /* Two slashes means network path. */

      /* Skip over the "//", if any */
      if(!assume_hkp)
	uri+=2;

      /* Get the host */
      opt.keyserver_host=strsep(&uri,":/");
      if(opt.keyserver_host[0]=='\0')
	return G10ERR_BAD_URI;

      if(uri==NULL || uri[0]=='\0')
	opt.keyserver_port=NULL;
      else
	{
	  char *ch;

	  /* Get the port */
	  opt.keyserver_port=strsep(&uri,"/");

	  /* Ports are digits only */
	  ch=opt.keyserver_port;
	  while(*ch!='\0')
	    {
	      if(!digitp(ch))
		return G10ERR_BAD_URI;

	      ch++;
	    }

	  /* It would seem to be reasonable to limit the range of the
	     ports to values between 1-65535, but RFC 1738 and 1808
	     imply there is no limit.  Of course, the real world has
	     limits. */
	}

      /* (any path part of the URI is discarded for now as no keyserver
	 uses it yet) */
    }
  else if(uri[0]!='/')
    {
      /* No slash means opaque.  Just record the opaque blob and get
	 out. */
      opt.keyserver_opaque=uri;
      return 0;
    }
  else
    {
      /* One slash means absolute path.  We don't need to support that
	 yet. */
      return G10ERR_BAD_URI;
    }

  if(opt.keyserver_scheme[0]=='\0')
    return G10ERR_BAD_URI;

  return 0;
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
    case KEYDB_SEARCH_MODE_SHORT_KID:
      printf("key %08lX",(ulong)keyrec->desc.u.kid[1]);
      break;

    case KEYDB_SEARCH_MODE_LONG_KID:
      printf("key %08lX%08lX",(ulong)keyrec->desc.u.kid[0],
	     (ulong)keyrec->desc.u.kid[1]);
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      printf("key ");
      for(i=0;i<16;i++)
	printf("%02X",(unsigned char)keyrec->desc.u.fpr[i]);
      break;

    case KEYDB_SEARCH_MODE_FPR20:
      printf("key ");
      for(i=0;i<20;i++)
	printf("%02X",(unsigned char)keyrec->desc.u.fpr[i]);
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

      work->createtime=atoi(tok);

      if((tok=strsep(&keystring,":"))==NULL)
	return ret;

      work->expiretime=atoi(tok);

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

      if(work->expiretime && work->expiretime<=make_timestamp())
	work->flags|=4;
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
	  keyserver_work(GET,NULL,&desc[atoi(num)-1],1);

      m_free(answer);
      return 1;
    }

  return 0;
}

/* Count and searchstr are just for cosmetics.  If the count is too
   small, it will grow safely.  If negative it disables the "Key x-y
   of z" messages. */
static void
keyserver_search_prompt(IOBUF buffer,const char *searchstr)
{
  int i=0,validcount=0,started=0,header=0,count=1;
  unsigned int maxlen,buflen;
  KEYDB_SEARCH_DESC *desc;
  byte *line=NULL;
  /* TODO: Something other than 23?  That's 24-1 (the prompt). */
  int maxlines=23,numlines=0;

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
		  if(show_prompt(desc,i,validcount?count:0,searchstr))
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
	      if(numlines+keyrec->lines>maxlines)
		{
		  if(show_prompt(desc,i,validcount?count:0,searchstr))
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

#define KEYSERVER_ARGS_KEEP " -o \"%O\" \"%I\""
#define KEYSERVER_ARGS_NOKEEP " -o \"%o\" \"%i\""

static int 
keyserver_spawn(int action,STRLIST list,
		KEYDB_SEARCH_DESC *desc,int count,int *prog)
{
  int ret=0,i,gotversion=0,outofband=0;
  STRLIST temp;
  unsigned int maxlen,buflen;
  char *command=NULL,*searchstr=NULL;
  byte *line=NULL;
  struct kopts *kopts;
  struct exec_info *spawn;

#ifdef EXEC_TEMPFILE_ONLY
  opt.keyserver_options.use_temp_files=1;
#endif

  /* Push the libexecdir into path.  If DISABLE_KEYSERVER_PATH is set,
     use the 0 arg to replace the path. */
#ifdef DISABLE_KEYSERVER_PATH
  set_exec_path(GNUPG_LIBEXECDIR,0);
#else
  set_exec_path(GNUPG_LIBEXECDIR,opt.exec_path_set);
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

      ret=exec_write(&spawn,NULL,command,NULL,0,0);
    }
  else
    ret=exec_write(&spawn,command,NULL,NULL,0,0);

  if(ret)
    return ret;

  fprintf(spawn->tochild,"# This is a gpg keyserver communications file\n");
  fprintf(spawn->tochild,"VERSION %d\n",KEYSERVER_PROTO_VERSION);
  fprintf(spawn->tochild,"PROGRAM %s\n",VERSION);

  if(opt.keyserver_opaque)
    fprintf(spawn->tochild,"OPAQUE %s\n",opt.keyserver_opaque);
  else
    {
      if(opt.keyserver_host)
	fprintf(spawn->tochild,"HOST %s\n",opt.keyserver_host);

      if(opt.keyserver_port)
	fprintf(spawn->tochild,"PORT %s\n",opt.keyserver_port);
    }

  /* Write options */

  for(i=0,kopts=keyserver_opts;kopts[i].name;i++)
    if(*(kopts[i].flag) && kopts[i].tell)
      fprintf(spawn->tochild,"OPTION %s\n",kopts[i].name);

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
	    KBNODE block;

	    temp=NULL;
	    add_to_strlist(&temp,key->d);

	    memset(&afx,0,sizeof(afx));
	    afx.what=1;
	    iobuf_push_filter(buffer,armor_filter,&afx);

	    /* TODO: Don't use the keyblock hack here - instead,
	       output each key as a different ascii armored blob with
	       its own INFO section. */

	    if(export_pubkeys_stream(buffer,temp,&block,
				     opt.keyserver_options.export_options)==-1)
	      iobuf_close(buffer);
	    else
	      {
		KBNODE node;

		iobuf_flush_temp(buffer);

		merge_keys_and_selfsig(block);

		fprintf(spawn->tochild,"INFO %s BEGIN\n",key->d);

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

			  break;
			}

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
				fprintf(spawn->tochild,"%%%02X",uid->name[r]);
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
		      }
		  }

		fprintf(spawn->tochild,"INFO %s END\n",key->d);

		fprintf(spawn->tochild,"KEY %s BEGIN\n",key->d);
		fwrite(iobuf_get_temp_buffer(buffer),
		       iobuf_get_temp_length(buffer),1,spawn->tochild);
		fprintf(spawn->tochild,"KEY %s END\n",key->d);

		iobuf_close(buffer);
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
	    log_info(_("WARNING: keyserver handler from a different "
		       "version of GnuPG (%s)\n"),&ptr[8]);
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
	{
	  keyserver_search_prompt(spawn->fromchild,searchstr);

	  break;
	}

      default:
	log_fatal(_("no keyserver action!\n"));
	break;
      }

 fail:
  m_free(line);

  *prog=exec_finish(spawn);

  return ret;
}

static int 
keyserver_work(int action,STRLIST list,KEYDB_SEARCH_DESC *desc,int count)
{
  int rc=0,ret=0;

  if(opt.keyserver_scheme==NULL)
    {
      log_error(_("no keyserver known (use option --keyserver)\n"));
      return G10ERR_BAD_URI;
    }

#ifdef DISABLE_KEYSERVER_HELPERS

  log_error(_("external keyserver calls are not supported in this build\n"));
  return G10ERR_KEYSERVER;

#else
  /* Spawn a handler */

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
	  break;

	case KEYSERVER_VERSION_ERROR:
	  log_error(_("gpgkeys_%s does not support handler version %d\n"),
		    opt.keyserver_scheme,KEYSERVER_PROTO_VERSION);
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
  /* We better ask for confirmation when the user entered --send-keys
     without arguments.  Sending all keys might not be the thing he
     intended to do */
  if (users || opt.batch || opt.answer_yes)
    ;
  else if ( !cpr_get_answer_is_yes
            ("keyserver_export.send_all",
             _("Do you really want to send all your "
               "public keys to the keyserver? (y/N) ")))
    return -1;

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

  /* We switch merge_only on during a refresh, as 'refresh' should
     never import new keys, even if their keyids match.  Is it worth
     preserving the old merge_only value here? */
  opt.merge_only=1;

  /* If refresh_add_fake_v3_keyids is on and it's a HKP or MAILTO
     scheme, then enable fake v3 keyid generation. */
  if(opt.keyserver_options.fake_v3_keyids && opt.keyserver_scheme &&
     (ascii_strcasecmp(opt.keyserver_scheme,"hkp")==0 ||
      ascii_strcasecmp(opt.keyserver_scheme,"mailto")==0))
    fakev3=1;

  rc=keyidlist(users,&desc,&count,fakev3);
  if(rc)
    return rc;

  if(count>0)
    {
      if(opt.keyserver_uri)
	{
	  if(count==1)
	    log_info(_("refreshing 1 key from %s\n"),opt.keyserver_uri);
	  else
	    log_info(_("refreshing %d keys from %s\n"),
		     count,opt.keyserver_uri);
	}

      rc=keyserver_work(GET,NULL,desc,count);
    }

  m_free(desc);

  return rc;
}

int
keyserver_search(STRLIST tokens)
{
  if(tokens)
    return keyserver_work(SEARCH,tokens,NULL,0);
  else
    return 0;
}
