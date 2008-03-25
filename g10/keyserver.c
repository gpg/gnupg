/* keyserver.c - generic keyserver code
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006,
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
#include "trustdb.h"
#include "keyserver-internal.h"
#include "util.h"

#ifdef HAVE_W32_SYSTEM
/* It seems Vista doesn't grok X_OK and so fails access() tests.
   Previous versions interpreted X_OK as F_OK anyway, so we'll just
   use F_OK directly. */
#undef X_OK
#define X_OK F_OK
#endif /* HAVE_W32_SYSTEM */

struct keyrec
{
  KEYDB_SEARCH_DESC desc;
  u32 createtime,expiretime;
  int size,flags;
  byte type;
  IOBUF uidbuf;
  unsigned int lines;
};

enum ks_action {KS_UNKNOWN=0,KS_GET,KS_GETNAME,KS_SEND,KS_SEARCH};

static struct parse_options keyserver_opts[]=
  {
    /* some of these options are not real - just for the help
       message */
    {"max-cert-size",0,NULL,NULL},
    {"include-revoked",0,NULL,N_("include revoked keys in search results")},
    {"include-subkeys",0,NULL,N_("include subkeys when searching by key ID")},
    {"use-temp-files",0,NULL,
     N_("use temporary files to pass data to keyserver helpers")},
    {"keep-temp-files",KEYSERVER_KEEP_TEMP_FILES,NULL,
     N_("do not delete temporary files after using them")},
    {"refresh-add-fake-v3-keyids",KEYSERVER_ADD_FAKE_V3,NULL,
     NULL},
    {"auto-key-retrieve",KEYSERVER_AUTO_KEY_RETRIEVE,NULL,
     N_("automatically retrieve keys when verifying signatures")},
    {"honor-keyserver-url",KEYSERVER_HONOR_KEYSERVER_URL,NULL,
     N_("honor the preferred keyserver URL set on the key")},
    {"honor-pka-record",KEYSERVER_HONOR_PKA_RECORD,NULL,
     N_("honor the PKA record set on a key when retrieving keys")},
    {NULL,0,NULL,NULL}
  };

static int keyserver_work(enum ks_action action,STRLIST list,
			  KEYDB_SEARCH_DESC *desc,int count,
			  unsigned char **fpr,size_t *fpr_len,
			  struct keyserver_spec *keyserver);

/* Reasonable guess */
#define DEFAULT_MAX_CERT_SIZE 16384

static size_t max_cert_size=DEFAULT_MAX_CERT_SIZE;

static void
add_canonical_option(char *option,STRLIST *list)
{
  char *arg=argsplit(option);

  if(arg)
    {
      char *joined;

      joined=xmalloc(strlen(option)+1+strlen(arg)+1);
      /* Make a canonical name=value form with no spaces */
      strcpy(joined,option);
      strcat(joined,"=");
      strcat(joined,arg);
      append_to_strlist(list,joined);
      xfree(joined);
    }
  else
    append_to_strlist(list,option);
}

int
parse_keyserver_options(char *options)
{
  int ret=1;
  char *tok;
  char *max_cert=NULL;

  keyserver_opts[0].value=&max_cert;

  while((tok=optsep(&options)))
    {
      if(tok[0]=='\0')
	continue;

      /* For backwards compatibility.  1.2.x used honor-http-proxy and
	 there are a good number of documents published that recommend
	 it. */
      if(ascii_strcasecmp(tok,"honor-http-proxy")==0)
	tok="http-proxy";
      else if(ascii_strcasecmp(tok,"no-honor-http-proxy")==0)
	tok="no-http-proxy";

      /* We accept quite a few possible options here - some options to
	 handle specially, the keyserver_options list, and import and
	 export options that pertain to keyserver operations.  Note
	 that you must use strncasecmp here as there might be an
	 =argument attached which will foil the use of strcasecmp. */

#ifdef EXEC_TEMPFILE_ONLY
      if(ascii_strncasecmp(tok,"use-temp-files",14)==0 ||
	      ascii_strncasecmp(tok,"no-use-temp-files",17)==0)
	log_info(_("WARNING: keyserver option `%s' is not used"
		   " on this platform\n"),tok);
#else
      if(ascii_strncasecmp(tok,"use-temp-files",14)==0)
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
	  add_canonical_option(tok,&opt.keyserver_options.other);
	}
    }

  if(max_cert)
    {
      max_cert_size=strtoul(max_cert,(char **)NULL,10);

      if(max_cert_size==0)
	max_cert_size=DEFAULT_MAX_CERT_SIZE;
    }

  return ret;
}

void
free_keyserver_spec(struct keyserver_spec *keyserver)
{
  xfree(keyserver->uri);
  xfree(keyserver->scheme);
  xfree(keyserver->auth);
  xfree(keyserver->host);
  xfree(keyserver->port);
  xfree(keyserver->path);
  xfree(keyserver->opaque);
  free_strlist(keyserver->options);
  xfree(keyserver);
}

/* Return 0 for match */
static int
cmp_keyserver_spec(struct keyserver_spec *one,struct keyserver_spec *two)
{
  if(ascii_strcasecmp(one->scheme,two->scheme)==0)
    {
      if(one->host && two->host && ascii_strcasecmp(one->host,two->host)==0)
	{
	  if((one->port && two->port
	      && ascii_strcasecmp(one->port,two->port)==0)
	     || (!one->port && !two->port))
	    return 0;
	}
      else if(one->opaque && two->opaque
	      && ascii_strcasecmp(one->opaque,two->opaque)==0)
	return 0;
    }

  return 1;
}

/* Try and match one of our keyservers.  If we can, return that.  If
   we can't, return our input. */
struct keyserver_spec *
keyserver_match(struct keyserver_spec *spec)
{
  struct keyserver_spec *ks;

  for(ks=opt.keyserver;ks;ks=ks->next)
    if(cmp_keyserver_spec(spec,ks)==0)
      return ks;

  return spec;
}

/* TODO: once we cut over to an all-curl world, we don't need this
   parser any longer so it can be removed, or at least moved to
   keyserver/ksutil.c for limited use in gpgkeys_ldap or the like. */

struct keyserver_spec *
parse_keyserver_uri(const char *string,int require_scheme,
		    const char *configname,unsigned int configlineno)
{
  int assume_hkp=0;
  struct keyserver_spec *keyserver;
  const char *idx;
  int count;
  char *uri,*options;

  assert(string!=NULL);

  keyserver=xmalloc_clear(sizeof(struct keyserver_spec));

  uri=xstrdup(string);

  options=strchr(uri,' ');
  if(options)
    {
      char *tok;

      *options='\0';
      options++;

      while((tok=optsep(&options)))
	add_canonical_option(tok,&keyserver->options);
    }

  /* Get the scheme */

  for(idx=uri,count=0;*idx && *idx!=':';idx++)
    {
      count++;

      /* Do we see the start of an RFC-2732 ipv6 address here?  If so,
	 there clearly isn't a scheme so get out early. */
      if(*idx=='[')
	{
	  /* Was the '[' the first thing in the string?  If not, we
	     have a mangled scheme with a [ in it so fail. */
	  if(count==1)
	    break;
	  else
	    goto fail;
	}
    }

  if(count==0)
    goto fail;

  if(*idx=='\0' || *idx=='[')
    {
      if(require_scheme)
	return NULL;

      /* Assume HKP if there is no scheme */
      assume_hkp=1;
      keyserver->scheme=xstrdup("hkp");

      keyserver->uri=xmalloc(strlen(keyserver->scheme)+3+strlen(uri)+1);
      strcpy(keyserver->uri,keyserver->scheme);
      strcat(keyserver->uri,"://");
      strcat(keyserver->uri,uri);
    }
  else
    {
      int i;

      keyserver->uri=xstrdup(uri);

      keyserver->scheme=xmalloc(count+1);

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
      xfree(keyserver->scheme);
      keyserver->scheme=xstrdup("hkp");
      append_to_strlist(&opt.keyserver_options.other,"broken-http-proxy");
    }
  else if(ascii_strcasecmp(keyserver->scheme,"x-hkp")==0)
    {
      /* Canonicalize this to "hkp" so it works with both the internal
	 and external keyserver interface. */
      xfree(keyserver->scheme);
      keyserver->scheme=xstrdup("hkp");
    }

  if(assume_hkp || (uri[0]=='/' && uri[1]=='/'))
    {
      /* Two slashes means network path. */

      /* Skip over the "//", if any */
      if(!assume_hkp)
	uri+=2;

      /* Do we have userinfo auth data present? */
      for(idx=uri,count=0;*idx && *idx!='@' && *idx!='/';idx++)
	count++;

      /* We found a @ before the slash, so that means everything
	 before the @ is auth data. */
      if(*idx=='@')
	{
	  if(count==0)
	    goto fail;

	  keyserver->auth=xmalloc(count+1);
	  strncpy(keyserver->auth,uri,count);
	  keyserver->auth[count]='\0';
	  uri+=count+1;
	}

      /* Is it an RFC-2732 ipv6 [literal address] ? */
      if(*uri=='[')
	{
	  for(idx=uri+1,count=1;*idx
		&& ((isascii (*idx) && isxdigit(*idx))
                    || *idx==':' || *idx=='.');idx++)
	    count++;

	  /* Is the ipv6 literal address terminated? */
	  if(*idx==']')
	    count++;
	  else
	    goto fail;
	}
      else
	for(idx=uri,count=0;*idx && *idx!=':' && *idx!='/';idx++)
	  count++;

      if(count==0)
	goto fail;

      keyserver->host=xmalloc(count+1);
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

	  keyserver->port=xmalloc(count+1);
	  strncpy(keyserver->port,uri+1,count);
	  keyserver->port[count]='\0';

	  /* Skip past the colon and port number */
	  uri+=1+count;
	}

      /* Everything else is the path */
      if(*uri)
	keyserver->path=xstrdup(uri);
      else
	keyserver->path=xstrdup("/");

      if(keyserver->path[1])
	keyserver->flags.direct_uri=1;
    }
  else if(uri[0]!='/')
    {
      /* No slash means opaque.  Just record the opaque blob and get
	 out. */
      keyserver->opaque=xstrdup(uri);
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
      byte *dupe=xmalloc(plen+1);

      memcpy(dupe,p,plen);
      dupe[plen]='\0';
      spec=parse_keyserver_uri(dupe,1,NULL,0);
      xfree(dupe);
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
    {
      printf(", ");
      printf(_("created: %s"),strtimestamp(keyrec->createtime));
    }

  if(keyrec->expiretime>0)
    {
      printf(", ");
      printf(_("expires: %s"),strtimestamp(keyrec->expiretime));
    }

  if(keyrec->flags&1)
    printf(" (%s)",_("revoked"));
  if(keyrec->flags&2)
    printf(" (%s)",_("disabled"));
  if(keyrec->flags&4)
    printf(" (%s)",_("expired"));

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
	  xfree(work);
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
      work=xmalloc_clear(sizeof(struct keyrec));
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
	  work=xmalloc_clear(sizeof(struct keyrec));
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
            int c;

	    userid[i] = (c=hextobyte(&tok[1])) == -1 ? '?' : c;
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
      xfree(decoded);
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
      xfree(answer);
      return 1;
    }
  else if(atoi(answer)>=1 && atoi(answer)<=numdesc)
    {
      char *split=answer,*num;

      while((num=strsep(&split," ,"))!=NULL)
	if(atoi(num)>=1 && atoi(num)<=numdesc)
	  keyserver_work(KS_GET,NULL,&desc[atoi(num)-1],1,
			 NULL,NULL,opt.keyserver);

      xfree(answer);
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

  desc=xmalloc(count*sizeof(KEYDB_SEARCH_DESC));

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

	      desc=xrealloc(desc,count*sizeof(KEYDB_SEARCH_DESC));
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
	  desc=xrealloc(desc,count*sizeof(KEYDB_SEARCH_DESC));
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
	  xfree(keyrec);

	  started=1;
	  i++;
	}
    }

 notfound:
  /* Leave this commented out or now, and perhaps for a very long
     time.  All HKPish servers return HTML error messages for
     no-key-found. */
  /* 
     if(!started)
     log_info(_("keyserver does not support searching\n"));
     else
  */
  if(count==0)
    {
      if(localstr)
	log_info(_("key \"%s\" not found on keyserver\n"),localstr);
      else
	log_info(_("key not found on keyserver\n"));
    }

  xfree(localstr);
  xfree(desc);
  xfree(line);
}

/* We sometimes want to use a different gpgkeys_xxx for a given
   protocol (for example, ldaps is handled by gpgkeys_ldap).  Map
   these here. */
static const char *
keyserver_typemap(const char *type)
{
  if(strcmp(type,"ldaps")==0)
    return "ldap";
  else
    return type;
}

/* The PGP LDAP and the curl fetch-a-LDAP-object methodologies are
   sufficiently different that we can't use curl to do LDAP. */
static int
direct_uri_map(const char *scheme,unsigned int is_direct)
{
  if(is_direct && strcmp(scheme,"ldap")==0)
    return 1;

  return 0;
}

#define GPGKEYS_PREFIX "gpgkeys_"
#define GPGKEYS_CURL GPGKEYS_PREFIX "curl" EXEEXT
#define GPGKEYS_PREFIX_LEN (strlen(GPGKEYS_CURL))
#define KEYSERVER_ARGS_KEEP " -o \"%O\" \"%I\""
#define KEYSERVER_ARGS_NOKEEP " -o \"%o\" \"%i\""

static int 
keyserver_spawn(enum ks_action action,STRLIST list,KEYDB_SEARCH_DESC *desc,
		int count,int *prog,unsigned char **fpr,size_t *fpr_len,
		struct keyserver_spec *keyserver)
{
  int ret=0,i,gotversion=0,outofband=0;
  STRLIST temp;
  unsigned int maxlen,buflen;
  char *command,*end,*searchstr=NULL;
  byte *line=NULL;
  struct exec_info *spawn;
  const char *scheme;
  const char *libexecdir = get_libexecdir ();

  assert(keyserver);

#ifdef EXEC_TEMPFILE_ONLY
  opt.keyserver_options.options|=KEYSERVER_USE_TEMP_FILES;
#endif

  /* Build the filename for the helper to execute */
  scheme=keyserver_typemap(keyserver->scheme);

#ifdef DISABLE_KEYSERVER_PATH
  /* Destroy any path we might have.  This is a little tricky,
     portability-wise.  It's not correct to delete the PATH
     environment variable, as that may fall back to a system built-in
     PATH.  Similarly, it is not correct to set PATH to the null
     string (PATH="") since this actually deletes the PATH environment
     variable under MinGW.  The safest thing to do here is to force
     PATH to be GNUPG_LIBEXECDIR.  All this is not that meaningful on
     Unix-like systems (since we're going to give a full path to
     gpgkeys_foo), but on W32 it prevents loading any DLLs from
     directories in %PATH%.

     After some more thinking about this we came to the conclusion
     that it is better to load the helpers from the directory where
     the program of this process lives.  Fortunately Windows provides
     a way to retrieve this and our get_libexecdir function has been
     modified to return just this.  Setting the exec-path is not
     anymore required.  
       set_exec_path(libexecdir);
 */
#else
  if(opt.exec_path_set)
    {
      /* If exec-path was set, and DISABLE_KEYSERVER_PATH is
	 undefined, then don't specify a full path to gpgkeys_foo, so
	 that the PATH can work. */
      command=xmalloc(GPGKEYS_PREFIX_LEN+strlen(scheme)+3+strlen(EXEEXT)+1);
      command[0]='\0';
    }
  else
#endif
    {
      /* Specify a full path to gpgkeys_foo. */
      command=xmalloc(strlen(libexecdir)+strlen(DIRSEP_S)+
		      GPGKEYS_PREFIX_LEN+strlen(scheme)+3+strlen(EXEEXT)+1);
      strcpy(command,libexecdir);
      strcat(command,DIRSEP_S);
    }

  end=command+strlen(command);

  /* Build a path for the keyserver helper.  If it is direct_uri
     (i.e. an object fetch and not a keyserver), then add "_uri" to
     the end to distinguish the keyserver helper from an object
     fetcher that can speak that protocol (this is a problem for
     LDAP). */

  strcat(command,GPGKEYS_PREFIX); 
  strcat(command,scheme);

  /* This "_uri" thing is in case we need to call a direct handler
     instead of the keyserver handler.  This lets us use gpgkeys_curl
     or gpgkeys_ldap_uri (we don't provide it, but a user might)
     instead of gpgkeys_ldap to fetch things like
     ldap://keyserver.pgp.com/o=PGP%20keys?pgpkey?sub?pgpkeyid=99242560 */

  if(direct_uri_map(scheme,keyserver->flags.direct_uri))
    strcat(command,"_uri");

  strcat(command,EXEEXT);

  /* Can we execute it?  If not, try curl as our catchall. */
  if(path_access(command,X_OK)!=0)
    strcpy(end,GPGKEYS_CURL);

  if(opt.keyserver_options.options&KEYSERVER_USE_TEMP_FILES)
    {
      if(opt.keyserver_options.options&KEYSERVER_KEEP_TEMP_FILES)
	{
	  command=xrealloc(command,strlen(command)+
			    strlen(KEYSERVER_ARGS_KEEP)+1);
	  strcat(command,KEYSERVER_ARGS_KEEP);
	}
      else
	{
	  command=xrealloc(command,strlen(command)+
			    strlen(KEYSERVER_ARGS_NOKEEP)+1);
	  strcat(command,KEYSERVER_ARGS_NOKEEP);  
	}

      ret=exec_write(&spawn,NULL,command,NULL,0,0);
    }
  else
    ret=exec_write(&spawn,command,NULL,NULL,0,0);

  xfree(command);

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
      if(keyserver->auth)
	fprintf(spawn->tochild,"AUTH %s\n",keyserver->auth);

      if(keyserver->host)
	fprintf(spawn->tochild,"HOST %s\n",keyserver->host);

      if(keyserver->port)
	fprintf(spawn->tochild,"PORT %s\n",keyserver->port);

      if(keyserver->path)
	fprintf(spawn->tochild,"PATH %s\n",keyserver->path);
    }

  /* Write global options */

  for(temp=opt.keyserver_options.other;temp;temp=temp->next)
    fprintf(spawn->tochild,"OPTION %s\n",temp->d);

  /* Write per-keyserver options */

  for(temp=keyserver->options;temp;temp=temp->next)
    fprintf(spawn->tochild,"OPTION %s\n",temp->d);

  switch(action)
    {
    case KS_GET:
      {
	fprintf(spawn->tochild,"COMMAND GET\n\n");

	/* Which keys do we want? */

	for(i=0;i<count;i++)
	  {
	    int quiet=0;

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
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_EXACT)
	      {
		fprintf(spawn->tochild,"0x0000000000000000\n");
		quiet=1;
	      }
	    else if(desc[i].mode==KEYDB_SEARCH_MODE_NONE)
	      continue;
	    else
	      BUG();

	    if(!quiet)
	      {
		if(keyserver->host)
		  log_info(_("requesting key %s from %s server %s\n"),
			   keystr_from_desc(&desc[i]),
			   keyserver->scheme,keyserver->host);
		else
		  log_info(_("requesting key %s from %s\n"),
			   keystr_from_desc(&desc[i]),keyserver->uri);
	      }
	  }

	fprintf(spawn->tochild,"\n");

	break;
      }

    case KS_GETNAME:
      {
	STRLIST key;

	fprintf(spawn->tochild,"COMMAND GETNAME\n\n");

	/* Which names do we want? */

	for(key=list;key!=NULL;key=key->next)
	  fprintf(spawn->tochild,"%s\n",key->d);

	fprintf(spawn->tochild,"\n");

	if(keyserver->host)
	  log_info(_("searching for names from %s server %s\n"),
		   keyserver->scheme,keyserver->host);
	else
	  log_info(_("searching for names from %s\n"),keyserver->uri);

	break;
      }

    case KS_SEND:
      {
	STRLIST key;

	/* Note the extra \n here to send an empty keylist block */
	fprintf(spawn->tochild,"COMMAND SEND\n\n\n");

	for(key=list;key!=NULL;key=key->next)
	  {
	    armor_filter_context_t *afx;
	    IOBUF buffer=iobuf_temp();
	    KBNODE block;

	    temp=NULL;
	    add_to_strlist(&temp,key->d);

	    afx = new_armor_context ();
	    afx->what = 1;
	    /* Tell the armor filter to use Unix-style \n line
	       endings, since we're going to fprintf this to a file
	       that (on Win32) is open in text mode.  The win32 stdio
	       will transform the \n to \r\n and we'll end up with the
	       proper line endings on win32.  This is a no-op on
	       Unix. */
	    afx->eol[0]='\n';
	    push_armor_filter (afx, buffer);
            release_armor_context (afx);

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

		fprintf(spawn->tochild,"KEY %08lX%08lX BEGIN\n",
			(ulong)block->pkt->pkt.public_key->keyid[0],
			(ulong)block->pkt->pkt.public_key->keyid[1]);
		fwrite(iobuf_get_temp_buffer(buffer),
		       iobuf_get_temp_length(buffer),1,spawn->tochild);
		fprintf(spawn->tochild,"KEY %08lX%08lX END\n",
			(ulong)block->pkt->pkt.public_key->keyid[0],
			(ulong)block->pkt->pkt.public_key->keyid[1]);

		iobuf_close(buffer);

		if(keyserver->host)
		  log_info(_("sending key %s to %s server %s\n"),
			   keystr(block->pkt->pkt.public_key->keyid),
			   keyserver->scheme,keyserver->host);
		else
		  log_info(_("sending key %s to %s\n"),
			   keystr(block->pkt->pkt.public_key->keyid),
			   keyserver->uri);

		release_kbnode(block);
	      }

	    free_strlist(temp);
	  }

	break;
      }

    case KS_SEARCH:
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
		searchstr=xrealloc(searchstr,
				    strlen(searchstr)+strlen(key->d)+2);
		strcat(searchstr," ");
	      }
	    else
	      {
		searchstr=xmalloc(strlen(key->d)+1);
		searchstr[0]='\0';
	      }

	    strcat(searchstr,key->d);
	  }

	fprintf(spawn->tochild,"\n");

	if(keyserver->host)
	  log_info(_("searching for \"%s\" from %s server %s\n"),
		   searchstr,keyserver->scheme,keyserver->host);
	else
	  log_info(_("searching for \"%s\" from %s\n"),
		   searchstr,keyserver->uri);

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
      ptr[plen]='\0';

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
      case KS_GET:
      case KS_GETNAME:
	{
	  void *stats_handle;

	  stats_handle=import_new_stats_handle();

	  /* Slurp up all the key data.  In the future, it might be
	     nice to look for KEY foo OUTOFBAND and FAILED indicators.
	     It's harmless to ignore them, but ignoring them does make
	     gpg complain about "no valid OpenPGP data found".  One
	     way to do this could be to continue parsing this
	     line-by-line and make a temp iobuf for each key. */

	  import_keys_stream(spawn->fromchild,stats_handle,fpr,fpr_len,
			     opt.keyserver_options.import_options);

	  import_print_stats(stats_handle);
	  import_release_stats_handle(stats_handle);

	  break;
	}

	/* Nothing to do here */
      case KS_SEND:
	break;

      case KS_SEARCH:
	keyserver_search_prompt(spawn->fromchild,searchstr);
	break;

      default:
	log_fatal(_("no keyserver action!\n"));
	break;
      }

 fail:
  xfree(line);
  xfree(searchstr);


  *prog=exec_finish(spawn);

  return ret;
}

static int 
keyserver_work(enum ks_action action,STRLIST list,KEYDB_SEARCH_DESC *desc,
	       int count,unsigned char **fpr,size_t *fpr_len,
	       struct keyserver_spec *keyserver)
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

  rc=keyserver_spawn(action,list,desc,count,&ret,fpr,fpr_len,keyserver);
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
		    action==KS_GET?"get":action==KS_SEND?"send":
		    action==KS_SEARCH?"search":"unknown",
		    keyserver->scheme);
	  break;

	case KEYSERVER_VERSION_ERROR:
	  log_error(_(GPGKEYS_PREFIX "%s does not support"
		      " handler version %d\n"),
		    keyserver_typemap(keyserver->scheme),
		    KEYSERVER_PROTO_VERSION);
	  break;

	case KEYSERVER_TIMEOUT:
	  log_error(_("keyserver timed out\n"));
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
      rc=keyserver_work(KS_SEND,sl,NULL,0,NULL,NULL,opt.keyserver);
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
  desc=xmalloc(sizeof(KEYDB_SEARCH_DESC)*num);

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
	  desc=xrealloc(desc,sizeof(KEYDB_SEARCH_DESC)*num);
	}
    }

  if(count>0)
    rc=keyserver_work(KS_GET,NULL,desc,count,NULL,NULL,opt.keyserver);

  xfree(desc);

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

  /* TODO: Warn here if the fingerprint we got doesn't match the one
     we asked for? */
  return keyserver_work(KS_GET,NULL,&desc,1,NULL,NULL,keyserver);
}

int 
keyserver_import_keyid(u32 *keyid,struct keyserver_spec *keyserver)
{
  KEYDB_SEARCH_DESC desc;

  memset(&desc,0,sizeof(desc));

  desc.mode=KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0]=keyid[0];
  desc.u.kid[1]=keyid[1];

  return keyserver_work(KS_GET,NULL,&desc,1,NULL,NULL,keyserver);
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

  *klist=xmalloc(sizeof(KEYDB_SEARCH_DESC)*num);

  kdbhd=keydb_new(0);

  if(!users)
    {
      ndesc = 1;
      desc = xmalloc_clear ( ndesc * sizeof *desc);
      desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
    }
  else
    {
      for (ndesc=0, sl=users; sl; sl = sl->next, ndesc++) 
	;
      desc = xmalloc ( ndesc * sizeof *desc);
        
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
		  *klist=xrealloc(*klist,sizeof(KEYDB_SEARCH_DESC)*num);
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
	      if(sig)
		(*klist)[*count].skipfncvalue=parse_preferred_keyserver(sig);
	    }

	  (*count)++;

	  if(*count==num)
	    {
	      num+=100;
	      *klist=xrealloc(*klist,sizeof(KEYDB_SEARCH_DESC)*num);
	    }
	}
    }

  if(rc==-1)
    rc=0;
  
 leave:
  if(rc)
    xfree(*klist);
  xfree(desc);
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
  unsigned int options=opt.keyserver_options.import_options;

  /* We switch merge-only on during a refresh, as 'refresh' should
     never import new keys, even if their keyids match. */
  opt.keyserver_options.import_options|=IMPORT_MERGE_ONLY;

  /* Similarly, we switch on fast-import, since refresh may make
     multiple import sets (due to preferred keyserver URLs).  We don't
     want each set to rebuild the trustdb.  Instead we do it once at
     the end here. */
  opt.keyserver_options.import_options|=IMPORT_FAST;

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
      for(i=0;i<numdesc;i++)
	{
	  if(desc[i].skipfncvalue)
	    {
	      struct keyserver_spec *keyserver=desc[i].skipfncvalue;

	      /* We use the keyserver structure we parsed out before.
		 Note that a preferred keyserver without a scheme://
		 will be interpreted as hkp:// */

	      rc=keyserver_work(KS_GET,NULL,&desc[i],1,NULL,NULL,keyserver);
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

      rc=keyserver_work(KS_GET,NULL,desc,numdesc,NULL,NULL,opt.keyserver);
    }

  xfree(desc);

  opt.keyserver_options.import_options=options;

  /* If the original options didn't have fast import, and the trustdb
     is dirty, rebuild. */
  if(!(opt.keyserver_options.import_options&IMPORT_FAST))
    trustdb_check_or_update();

  return rc;
}

int
keyserver_search(STRLIST tokens)
{
  if(tokens)
    return keyserver_work(KS_SEARCH,tokens,NULL,0,NULL,NULL,opt.keyserver);
  else
    return 0;
}

int
keyserver_fetch(STRLIST urilist)
{
  KEYDB_SEARCH_DESC desc;
  STRLIST sl;
  unsigned int options=opt.keyserver_options.import_options;

  /* Switch on fast-import, since fetch can handle more than one
     import and we don't want each set to rebuild the trustdb.
     Instead we do it once at the end. */
  opt.keyserver_options.import_options|=IMPORT_FAST;

  /* A dummy desc since we're not actually fetching a particular key
     ID */
  memset(&desc,0,sizeof(desc));
  desc.mode=KEYDB_SEARCH_MODE_EXACT;

  for(sl=urilist;sl;sl=sl->next)
    {
      struct keyserver_spec *spec;

      spec=parse_keyserver_uri(sl->d,1,NULL,0);
      if(spec)
	{
	  int rc;

	  rc=keyserver_work(KS_GET,NULL,&desc,1,NULL,NULL,spec);
	  if(rc)
	    log_info (_("WARNING: unable to fetch URI %s: %s\n"),
		     sl->d,g10_errstr(rc));

	  free_keyserver_spec(spec);
	}
      else
	log_info (_("WARNING: unable to parse URI %s\n"),sl->d);
    }

  opt.keyserver_options.import_options=options;

  /* If the original options didn't have fast import, and the trustdb
     is dirty, rebuild. */
  if(!(opt.keyserver_options.import_options&IMPORT_FAST))
    trustdb_check_or_update();

  return 0;
}

/* Import key in a CERT or pointed to by a CERT */
int
keyserver_import_cert(const char *name,unsigned char **fpr,size_t *fpr_len)
{
  char *domain,*look,*url;
  IOBUF key;
  int type,rc=G10ERR_GENERAL;

  look=xstrdup(name);

  domain=strrchr(look,'@');
  if(domain)
    *domain='.';

  type=get_cert(look,max_cert_size,&key,fpr,fpr_len,&url);
  if(type==1)
    {
      int armor_status=opt.no_armor;

      /* CERTs are always in binary format */
      opt.no_armor=1;

      rc=import_keys_stream(key,NULL,fpr,fpr_len,
			    opt.keyserver_options.import_options);

      opt.no_armor=armor_status;

      iobuf_close(key);
    }
  else if(type==2 && *fpr)
    {
      /* We only consider the IPGP type if a fingerprint was provided.
	 This lets us select the right key regardless of what a URL
	 points to, or get the key from a keyserver. */
      if(url)
	{
	  struct keyserver_spec *spec;

	  spec=parse_keyserver_uri(url,1,NULL,0);
	  if(spec)
	    {
	      STRLIST list=NULL;

	      add_to_strlist(&list,url);

	      rc=keyserver_fetch(list);

	      free_strlist(list);
	      free_keyserver_spec(spec);
	    }
	}
      else if(opt.keyserver)
	{
	  /* If only a fingerprint is provided, try and fetch it from
	     our --keyserver */

	  rc=keyserver_import_fprint(*fpr,*fpr_len,opt.keyserver);
	}
      else
	log_info(_("no keyserver known (use option --keyserver)\n"));

      /* Give a better string here? "CERT fingerprint for \"%s\"
	 found, but no keyserver" " known (use option
	 --keyserver)\n" ? */

      xfree(url);
    }

  xfree(look);

  return rc;
}

/* Import key pointed to by a PKA record. Return the requested
   fingerprint in fpr. */
int
keyserver_import_pka(const char *name,unsigned char **fpr,size_t *fpr_len)
{
  char *uri;
  int rc=-1;

  *fpr=xmalloc(20);
  *fpr_len=20;

  uri = get_pka_info (name, *fpr);
  if (uri)
    {
      struct keyserver_spec *spec;
      spec = parse_keyserver_uri (uri, 1, NULL, 0);
      if (spec)
	{
	  rc=keyserver_import_fprint (*fpr, 20, spec);
	  free_keyserver_spec (spec);
	}
      xfree (uri);
    }

  if(rc!=0)
    xfree(*fpr);

  return rc;
}

/* Import all keys that match name */
int
keyserver_import_name(const char *name,unsigned char **fpr,size_t *fpr_len,
		      struct keyserver_spec *keyserver)
{
  STRLIST list=NULL;
  int rc;

  append_to_strlist(&list,name);

  rc=keyserver_work(KS_GETNAME,list,NULL,0,fpr,fpr_len,keyserver);

  free_strlist(list);

  return rc;
}

/* Use the PGP Universal trick of asking ldap://keys.(maildomain) for
   the key. */
int
keyserver_import_ldap(const char *name,unsigned char **fpr,size_t *fpr_len)
{
  char *domain;
  struct keyserver_spec *keyserver;
  STRLIST list=NULL;
  int rc;

  append_to_strlist(&list,name);

  /* Parse out the domain */
  domain=strrchr(name,'@');
  if(!domain)
    return G10ERR_GENERAL;

  domain++;

  keyserver=xmalloc_clear(sizeof(struct keyserver_spec));

  keyserver->scheme=xstrdup("ldap");
  keyserver->host=xmalloc(5+strlen(domain)+1);
  strcpy(keyserver->host,"keys.");
  strcat(keyserver->host,domain);
  keyserver->uri=xmalloc(strlen(keyserver->scheme)+
			 3+strlen(keyserver->host)+1);
  strcpy(keyserver->uri,keyserver->scheme);
  strcat(keyserver->uri,"://");
  strcat(keyserver->uri,keyserver->host);
    
  rc=keyserver_work(KS_GETNAME,list,NULL,0,fpr,fpr_len,keyserver);

  free_strlist(list);

  free_keyserver_spec(keyserver);

  return rc;
}
