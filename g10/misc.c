/* misc.c -  miscellaneous functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#include <asm/sysinfo.h>
#include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#ifdef ENABLE_SELINUX_HACKS
#include <sys/stat.h>
#endif
#ifdef _WIN32
#include <time.h>
#include <process.h>
#include <windows.h> 
#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_FLAG_CREATE
#define CSIDL_FLAG_CREATE 0x8000
#endif
#include "errors.h"
#include "dynload.h"
#endif /*_WIN32*/

#include "util.h"
#include "main.h"
#include "photoid.h"
#include "options.h"
#include "i18n.h"
#include "cardglue.h"




#ifdef ENABLE_SELINUX_HACKS
/* A object and a global variable to keep track of files marked as
   secured. */
struct secured_file_item 
{
  struct secured_file_item *next;
  ino_t ino;
  dev_t dev;
};
static struct secured_file_item *secured_files;
#endif /*ENABLE_SELINUX_HACKS*/



#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
static int
setsysinfo(unsigned long op, void *buffer, unsigned long size,
		     int *start, void *arg, unsigned long flag)
{
    return syscall(__NR_osf_setsysinfo, op, buffer, size, start, arg, flag);
}

void
trap_unaligned(void)
{
    unsigned int buf[2];

    buf[0] = SSIN_UACPROC;
    buf[1] = UAC_SIGBUS | UAC_NOPRINT;
    setsysinfo(SSI_NVPAIRS, buf, 1, 0, 0, 0);
}
#else
void
trap_unaligned(void)
{  /* dummy */
}
#endif


int
disable_core_dumps()
{
#ifdef HAVE_DOSISH_SYSTEM
    return 0;
#else
#ifdef HAVE_SETRLIMIT
    struct rlimit limit;

    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if( !setrlimit( RLIMIT_CORE, &limit ) )
	return 0;
    if( errno != EINVAL && errno != ENOSYS )
	log_fatal(_("can't disable core dumps: %s\n"), strerror(errno) );
#endif
    return 1;
#endif
}


/* For the sake of SELinux we want to restrict access through gpg to
   certain files we keep under our own control.  This function
   registers such a file and is_secured_file may then be used to
   check whether a file has ben registered as secured. */
void
register_secured_file (const char *fname)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf;

  /* Note that we stop immediatley if something goes wrong here. */
  if (stat (fname, &buf))
    log_fatal (_("fstat of `%s' failed in %s: %s\n"), fname, 
               "register_secured_file", strerror (errno));
/*   log_debug ("registering `%s' i=%lu.%lu\n", fname, */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sf=secured_files; sf; sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        return; /* Already registered.  */
    }

  sf = xmalloc (sizeof *sf);
  sf->ino = buf.st_ino;
  sf->dev = buf.st_dev;
  sf->next = secured_files;
  secured_files = sf;
#endif /*ENABLE_SELINUX_HACKS*/
}

/* Remove a file registerd as secure. */
void
unregister_secured_file (const char *fname)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf, *sfprev;

  if (stat (fname, &buf))
    {
      log_error (_("fstat of `%s' failed in %s: %s\n"), fname,
                 "unregister_secured_file", strerror (errno));
      return;
    }
/*   log_debug ("unregistering `%s' i=%lu.%lu\n", fname,  */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sfprev=NULL,sf=secured_files; sf; sfprev=sf, sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        {
          if (sfprev)
            sfprev->next = sf->next;
          else
            secured_files = sf->next;
          xfree (sf);
          return;
        }
    }
#endif /*ENABLE_SELINUX_HACKS*/
}

/* Return true if FD is corresponds to a secured file.  Using -1 for
   FS is allowed and will return false. */ 
int 
is_secured_file (int fd)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf;

  if (fd == -1)
    return 0; /* No file descriptor so it can't be secured either.  */

  /* Note that we print out a error here and claim that a file is
     secure if something went wrong. */
  if (fstat (fd, &buf))
    {
      log_error (_("fstat(%d) failed in %s: %s\n"), fd, 
                 "is_secured_file", strerror (errno));
      return 1;
    }
/*   log_debug ("is_secured_file (%d) i=%lu.%lu\n", fd, */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sf=secured_files; sf; sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        return 1; /* Yes.  */
    }
#endif /*ENABLE_SELINUX_HACKS*/
  return 0; /* No. */
}

/* Return true if FNAME is corresponds to a secured file.  Using NULL,
   "" or "-" for FS is allowed and will return false. This function is
   used before creating a file, thus it won't fail if the file does
   not exist. */ 
int 
is_secured_filename (const char *fname)
{
#ifdef ENABLE_SELINUX_HACKS
  struct stat buf;
  struct secured_file_item *sf;

  if (iobuf_is_pipe_filename (fname) || !*fname)
    return 0; 

  /* Note that we print out a error here and claim that a file is
     secure if something went wrong. */
  if (stat (fname, &buf))
    {
      if (errno == ENOENT || errno == EPERM || errno == EACCES)
        return 0;
      log_error (_("fstat of `%s' failed in %s: %s\n"), fname,
                 "is_secured_filename", strerror (errno));
      return 1;
    }
/*   log_debug ("is_secured_filename (%s) i=%lu.%lu\n", fname, */
/*              (unsigned long)buf.st_dev, (unsigned long)buf.st_ino); */
  for (sf=secured_files; sf; sf = sf->next)
    {
      if (sf->ino == buf.st_ino && sf->dev == buf.st_dev)
        return 1; /* Yes.  */
    }
#endif /*ENABLE_SELINUX_HACKS*/
  return 0; /* No. */
}



u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    a += n & 0xff;
    return a;
}


u16
checksum( byte *p, unsigned n )
{
    u16 a;

    for(a=0; n; n-- )
	a += *p++;
    return a;
}

u16
checksum_mpi( MPI a )
{
    u16 csum;
    byte *buffer;
    unsigned nbytes;
    unsigned nbits;

    buffer = mpi_get_buffer( a, &nbytes, NULL );
    nbits = mpi_get_nbits(a);
    csum = checksum_u16( nbits );
    csum += checksum( buffer, nbytes );
    xfree( buffer );
    return csum;
}

u32
buffer_to_u32( const byte *buffer )
{
    unsigned long a;
    a =  *buffer << 24;
    a |= buffer[1] << 16;
    a |= buffer[2] << 8;
    a |= buffer[3];
    return a;
}

void
print_pubkey_algo_note( int algo )
{
  if(algo >= 100 && algo <= 110)
    {
      static int warn=0;
      if(!warn)
	{
	  warn=1;
	  log_info(_("WARNING: using experimental public key algorithm %s\n"),
		   pubkey_algo_to_string(algo));
	}
    }
  else if (algo == 20)
    {
      log_info (_("WARNING: Elgamal sign+encrypt keys are deprecated\n"));
    }
}

void
print_cipher_algo_note( int algo )
{
  if(algo >= 100 && algo <= 110)
    {
      static int warn=0;
      if(!warn)
	{
	  warn=1;
	  log_info(_("WARNING: using experimental cipher algorithm %s\n"),
		   cipher_algo_to_string(algo));
	}
    }
}

void
print_digest_algo_note( int algo )
{
  if(algo >= 100 && algo <= 110)
    {
      static int warn=0;
      if(!warn)
	{
	  warn=1;
	  log_info(_("WARNING: using experimental digest algorithm %s\n"),
		   digest_algo_to_string(algo));
	}
    }
  else if(algo==DIGEST_ALGO_MD5)
    log_info(_("WARNING: digest algorithm %s is deprecated\n"),
	     digest_algo_to_string(algo));
}

/* Return a string which is used as a kind of process ID */
const byte *
get_session_marker( size_t *rlen )
{
    static byte marker[SIZEOF_UNSIGNED_LONG*2];
    static int initialized;

    if ( !initialized ) {
        volatile ulong aa, bb; /* we really want the uninitialized value */
        ulong a, b;

        initialized = 1;
        /* also this marker is guessable it is not easy to use this 
         * for a faked control packet because an attacker does not
         * have enough control about the time the verification does 
         * take place.  Of course, we can add just more random but 
         * than we need the random generator even for verification
         * tasks - which does not make sense. */
        a = aa ^ (ulong)getpid();
        b = bb ^ (ulong)time(NULL);
        memcpy( marker, &a, SIZEOF_UNSIGNED_LONG );
        memcpy( marker+SIZEOF_UNSIGNED_LONG, &b, SIZEOF_UNSIGNED_LONG );
    }
    *rlen = sizeof(marker);
    return marker;
}

/****************
 * Wrapper around the libgcrypt function with addional checks on
 * openPGP contraints for the algo ID.
 */
int
openpgp_cipher_test_algo( int algo )
{
    if( algo < 0 || algo > 110 )
        return G10ERR_CIPHER_ALGO;
    return check_cipher_algo(algo);
}

int
openpgp_pk_test_algo( int algo, unsigned int usage_flags )
{
    /* Dont't allow type 20 keys unless in rfc2440 mode.  */
    if (!RFC2440 && algo == 20)
        return G10ERR_PUBKEY_ALGO;
    if( algo < 0 || algo > 110 )
	return G10ERR_PUBKEY_ALGO;
    return check_pubkey_algo2( algo, usage_flags );
}

int 
openpgp_pk_algo_usage ( int algo )
{
    int use = 0; 
    
    /* they are hardwired in gpg 1.0 */
    switch ( algo ) {    
      case PUBKEY_ALGO_RSA:
          use = PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC | PUBKEY_USAGE_AUTH;
          break;
      case PUBKEY_ALGO_RSA_E:
          use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_RSA_S:
          use = PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG;
          break;
      case PUBKEY_ALGO_ELGAMAL:
          /* Allow encryption with type 20 keys if RFC-2440 compliance
             has been selected.  Signing is broken thus we won't allow
             this.  */  
          if (RFC2440)
            use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_ELGAMAL_E:
          use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_DSA:  
          use = PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG | PUBKEY_USAGE_AUTH;
          break;
      default:
          break;
    }
    return use;
}

int
openpgp_md_test_algo( int algo )
{
    if( algo < 0 || algo > 110 )
        return G10ERR_DIGEST_ALGO;
    return check_digest_algo(algo);
}

#ifdef USE_IDEA
/* Special warning for the IDEA cipher */
void
idea_cipher_warn(int show)
{
  static int warned=0;

  if(!warned || show)
    {
      log_info(_("the IDEA cipher plugin is not present\n"));
      log_info(_("please see %s for more information\n"),
               "http://www.gnupg.org/faq/why-not-idea.html");
      warned=1;
    }
}
#endif

static unsigned long get_signature_count(PKT_secret_key *sk)
{
#ifdef ENABLE_CARD_SUPPORT
  if(sk && sk->is_protected && sk->protect.s2k.mode==1002)
    {
      struct agent_card_info_s info;
      if(agent_scd_getattr("SIG-COUNTER",&info)==0)
	return info.sig_counter;
    }  
#endif

  /* How to do this without a card? */

  return 0;
}

/* Expand %-strings.  Returns a string which must be xfreed.  Returns
   NULL if the string cannot be expanded (too large). */
char *
pct_expando(const char *string,struct expando_args *args)
{
  const char *ch=string;
  int idx=0,maxlen=0,done=0;
  u32 pk_keyid[2]={0,0},sk_keyid[2]={0,0};
  char *ret=NULL;

  if(args->pk)
    keyid_from_pk(args->pk,pk_keyid);

  if(args->sk)
    keyid_from_sk(args->sk,sk_keyid);

  /* This is used so that %k works in photoid command strings in
     --list-secret-keys (which of course has a sk, but no pk). */
  if(!args->pk && args->sk)
    keyid_from_sk(args->sk,pk_keyid);

  while(*ch!='\0')
    {
      char *str=NULL;

      if(!done)
	{
	  /* 8192 is way bigger than we'll need here */
	  if(maxlen>=8192)
	    goto fail;

	  maxlen+=1024;
	  ret=xrealloc(ret,maxlen);
	}

      done=0;

      if(*ch=='%')
	{
	  switch(*(ch+1))
	    {
	    case 's': /* short key id */
	      if(idx+8<maxlen)
		{
		  sprintf(&ret[idx],"%08lX",(ulong)sk_keyid[1]);
		  idx+=8;
		  done=1;
		}
	      break;

	    case 'S': /* long key id */
	      if(idx+16<maxlen)
		{
		  sprintf(&ret[idx],"%08lX%08lX",
			  (ulong)sk_keyid[0],(ulong)sk_keyid[1]);
		  idx+=16;
		  done=1;
		}
	      break;

	    case 'k': /* short key id */
	      if(idx+8<maxlen)
		{
		  sprintf(&ret[idx],"%08lX",(ulong)pk_keyid[1]);
		  idx+=8;
		  done=1;
		}
	      break;

	    case 'K': /* long key id */
	      if(idx+16<maxlen)
		{
		  sprintf(&ret[idx],"%08lX%08lX",
			  (ulong)pk_keyid[0],(ulong)pk_keyid[1]);
		  idx+=16;
		  done=1;
		}
	      break;

	    case 'c': /* signature count from card, if any. */
	      if(idx+10<maxlen)
		{
		  sprintf(&ret[idx],"%lu",get_signature_count(args->sk));
		  idx+=strlen(&ret[idx]);
		  done=1;
		}	      
	      break;

	    case 'p': /* primary pk fingerprint of a sk */
	    case 'f': /* pk fingerprint */
	    case 'g': /* sk fingerprint */
	      {
		byte array[MAX_FINGERPRINT_LEN];
		size_t len;
		int i;

		if((*(ch+1))=='p' && args->sk)
		  {
		    if(args->sk->is_primary)
		      fingerprint_from_sk(args->sk,array,&len);
		    else if(args->sk->main_keyid[0] || args->sk->main_keyid[1])
		      {
			PKT_public_key *pk=
			  xmalloc_clear(sizeof(PKT_public_key));

			if(get_pubkey_fast(pk,args->sk->main_keyid)==0)
			  fingerprint_from_pk(pk,array,&len);
			else
			  memset(array,0,(len=MAX_FINGERPRINT_LEN));
			free_public_key(pk);
		      }
		    else
		      memset(array,0,(len=MAX_FINGERPRINT_LEN));
		  }
		else if((*(ch+1))=='f' && args->pk)
		  fingerprint_from_pk(args->pk,array,&len);
		else if((*(ch+1))=='g' && args->sk)
		  fingerprint_from_sk(args->sk,array,&len);
		else
		  memset(array,0,(len=MAX_FINGERPRINT_LEN));

		if(idx+(len*2)<maxlen)
		  {
		    for(i=0;i<len;i++)
		      {
			sprintf(&ret[idx],"%02X",array[i]);
			idx+=2;
		      }
		    done=1;
		  }
	      }
	      break;

	    case 't': /* e.g. "jpg" */
	      str=image_type_to_string(args->imagetype,0);
	      /* fall through */

	    case 'T': /* e.g. "image/jpeg" */
	      if(str==NULL)
		str=image_type_to_string(args->imagetype,2);

	      if(idx+strlen(str)<maxlen)
		{
		  strcpy(&ret[idx],str);
		  idx+=strlen(str);
		  done=1;
		}
	      break;

	    case '%':
	      if(idx+1<maxlen)
		{
		  ret[idx++]='%';
		  ret[idx]='\0';
		  done=1;
		}
	      break;

	      /* Any unknown %-keys (like %i, %o, %I, and %O) are
		 passed through for later expansion.  Note this also
		 handles the case where the last character in the
		 string is a '%' - the terminating \0 will end up here
		 and properly terminate the string. */
	    default:
	      if(idx+2<maxlen)
		{
		  ret[idx++]='%';
		  ret[idx++]=*(ch+1);
		  ret[idx]='\0';
		  done=1;
		}
	      break;
	      }

	  if(done)
	    ch++;
	}
      else
	{
	  if(idx+1<maxlen)
	    {
	      ret[idx++]=*ch;
	      ret[idx]='\0';
	      done=1;
	    }
	}

      if(done)
	ch++;
    }

  return ret;

 fail:
  xfree(ret);
  return NULL;
}

void
deprecated_warning(const char *configname,unsigned int configlineno,
		   const char *option,const char *repl1,const char *repl2)
{
  if(configname)
    {
      if(strncmp("--",option,2)==0)
	option+=2;

      if(strncmp("--",repl1,2)==0)
	repl1+=2;

      log_info(_("%s:%d: deprecated option \"%s\"\n"),
	       configname,configlineno,option);
    }
  else
    log_info(_("WARNING: \"%s\" is a deprecated option\n"),option);

  log_info(_("please use \"%s%s\" instead\n"),repl1,repl2);
}


void
deprecated_command (const char *name)
{
  log_info(_("WARNING: \"%s\" is a deprecated command - do not use it\n"),
           name);
}


const char *
compress_algo_to_string(int algo)
{
  const char *s=NULL;

  switch(algo)
    {
    case COMPRESS_ALGO_NONE:
      s=_("Uncompressed");
      break;

    case COMPRESS_ALGO_ZIP:
      s="ZIP";
      break;

    case COMPRESS_ALGO_ZLIB:
      s="ZLIB";
      break;

#ifdef HAVE_BZIP2
    case COMPRESS_ALGO_BZIP2:
      s="BZIP2";
      break;
#endif
    }

  return s;
}

int
string_to_compress_algo(const char *string)
{
  /* NOTE TO TRANSLATOR: See doc/TRANSLATE about this string. */
  if(match_multistr(_("uncompressed|none"),string))
    return 0;
  else if(ascii_strcasecmp(string,"uncompressed")==0)
    return 0;
  else if(ascii_strcasecmp(string,"none")==0)
    return 0;
  else if(ascii_strcasecmp(string,"zip")==0)
    return 1;
  else if(ascii_strcasecmp(string,"zlib")==0)
    return 2;
#ifdef HAVE_BZIP2
  else if(ascii_strcasecmp(string,"bzip2")==0)
    return 3;
#endif
  else if(ascii_strcasecmp(string,"z0")==0)
    return 0;
  else if(ascii_strcasecmp(string,"z1")==0)
    return 1;
  else if(ascii_strcasecmp(string,"z2")==0)
    return 2;
#ifdef HAVE_BZIP2
  else if(ascii_strcasecmp(string,"z3")==0)
    return 3;
#endif
  else
    return -1;
}

int
check_compress_algo(int algo)
{
#ifdef HAVE_BZIP2
  if(algo>=0 && algo<=3)
    return 0;
#else
  if(algo>=0 && algo<=2)
    return 0;
#endif

  return G10ERR_COMPR_ALGO;
}

int
default_cipher_algo(void)
{
  if(opt.def_cipher_algo)
    return opt.def_cipher_algo;
  else if(opt.personal_cipher_prefs)
    return opt.personal_cipher_prefs[0].value;
  else
    return opt.s2k_cipher_algo;
}

/* There is no default_digest_algo function, but see
   sign.c:hash_for() */

int
default_compress_algo(void)
{
  if(opt.compress_algo!=-1)
    return opt.compress_algo;
  else if(opt.personal_compress_prefs)
    return opt.personal_compress_prefs[0].value;
  else
    return DEFAULT_COMPRESS_ALGO;
}

const char *
compliance_option_string(void)
{
  char *ver="???";

  switch(opt.compliance)
    {
    case CO_GNUPG:   return "--gnupg";
    case CO_RFC4880: return "--openpgp";
    case CO_RFC2440: return "--rfc2440";
    case CO_RFC1991: return "--rfc1991";
    case CO_PGP2:    return "--pgp2";
    case CO_PGP6:    return "--pgp6";
    case CO_PGP7:    return "--pgp7";
    case CO_PGP8:    return "--pgp8";
    }

  return ver;
}

void
compliance_failure(void)
{
  char *ver="???";

  switch(opt.compliance)
    {
    case CO_GNUPG:
      ver="GnuPG";
      break;

    case CO_RFC4880:
      ver="OpenPGP";
      break;

    case CO_RFC2440:
      ver="OpenPGP (older)";
      break;

    case CO_RFC1991:
      ver="old PGP";
      break;

    case CO_PGP2:
      ver="PGP 2.x";
      break;

    case CO_PGP6:
      ver="PGP 6.x";
      break;

    case CO_PGP7:
      ver="PGP 7.x";
      break;

    case CO_PGP8:
      ver="PGP 8.x";
      break;
    }

  log_info(_("this message may not be usable by %s\n"),ver);
  opt.compliance=CO_GNUPG;
}

/* Break a string into successive option pieces.  Accepts single word
   options and key=value argument options. */
char *
optsep(char **stringp)
{
  char *tok,*end;

  tok=*stringp;
  if(tok)
    {
      end=strpbrk(tok," ,=");
      if(end)
	{
	  int sawequals=0;
	  char *ptr=end;

	  /* what we need to do now is scan along starting with *end,
	     If the next character we see (ignoring spaces) is an =
	     sign, then there is an argument. */

	  while(*ptr)
	    {
	      if(*ptr=='=')
		sawequals=1;
	      else if(*ptr!=' ')
		break;
	      ptr++;
	    }

	  /* There is an argument, so grab that too.  At this point,
	     ptr points to the first character of the argument. */
	  if(sawequals)
	    {
	      /* Is it a quoted argument? */
	      if(*ptr=='"')
		{
		  ptr++;
		  end=strchr(ptr,'"');
		  if(end)
		    end++;
		}
	      else
		end=strpbrk(ptr," ,");
	    }

	  if(end && *end)
	    {
	      *end='\0';
	      *stringp=end+1;
	    }
	  else
	    *stringp=NULL;
	}
      else
	*stringp=NULL;
    }

  return tok;
}

/* Breaks an option value into key and value.  Returns NULL if there
   is no value.  Note that "string" is modified to remove the =value
   part. */
char *
argsplit(char *string)
{
  char *equals,*arg=NULL;

  equals=strchr(string,'=');
  if(equals)
    {
      char *quote,*space;

      *equals='\0';
      arg=equals+1;

      /* Quoted arg? */
      quote=strchr(arg,'"');
      if(quote)
	{
	  arg=quote+1;

	  quote=strchr(arg,'"');
	  if(quote)
	    *quote='\0';
	}
      else
	{
	  size_t spaces;

	  /* Trim leading spaces off of the arg */
	  spaces=strspn(arg," ");
	  arg+=spaces;
	}

      /* Trim tailing spaces off of the tag */
      space=strchr(string,' ');
      if(space)
	*space='\0';
    }

  return arg;
}

/* Return the length of the initial token, leaving off any
   argument. */
static size_t
optlen(const char *s)
{
  char *end=strpbrk(s," =");

  if(end)
    return end-s;
  else
    return strlen(s);
}

int
parse_options(char *str,unsigned int *options,
	      struct parse_options *opts,int noisy)
{
  char *tok;

  if (str && !strcmp (str, "help"))
    {
      int i,maxlen=0;

      /* Figure out the longest option name so we can line these up
	 neatly. */
      for(i=0;opts[i].name;i++)
	if(opts[i].help && maxlen<strlen(opts[i].name))
	  maxlen=strlen(opts[i].name);

      for(i=0;opts[i].name;i++)
        if(opts[i].help)
	  printf("%s%*s%s\n",opts[i].name,
		 maxlen+2-(int)strlen(opts[i].name),"",_(opts[i].help));

      g10_exit(0);
    }

  while((tok=optsep(&str)))
    {
      int i,rev=0;
      char *otok=tok;

      if(tok[0]=='\0')
	continue;

      if(ascii_strncasecmp("no-",tok,3)==0)
	{
	  rev=1;
	  tok+=3;
	}

      for(i=0;opts[i].name;i++)
	{
	  size_t toklen=optlen(tok);

	  if(ascii_strncasecmp(opts[i].name,tok,toklen)==0)
	    {
	      /* We have a match, but it might be incomplete */
	      if(toklen!=strlen(opts[i].name))
		{
		  int j;

		  for(j=i+1;opts[j].name;j++)
		    {
		      if(ascii_strncasecmp(opts[j].name,tok,toklen)==0)
			{
			  if(noisy)
			    log_info(_("ambiguous option `%s'\n"),otok);
			  return 0;
			}
		    }
		}

	      if(rev)
		{
		  *options&=~opts[i].bit;
		  if(opts[i].value)
		    *opts[i].value=NULL;
		}
	      else
		{
		  *options|=opts[i].bit;
		  if(opts[i].value)
		    *opts[i].value=argsplit(tok);
		}
	      break;
	    }
	}

      if(!opts[i].name)
	{
	  if(noisy)
	    log_info(_("unknown option `%s'\n"),otok);
	  return 0;
	}
    }

  return 1;
}


/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF. */
char *
unescape_percent_string (const unsigned char *s)
{
  char *buffer, *d;

  buffer = d = xmalloc (strlen (s)+1);
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
  return buffer;
}


int
has_invalid_email_chars (const char *s)
{
  int at_seen=0;
  const char *valid_chars=
    "01234567890_-.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for ( ; *s; s++ ) 
    {
      if ( *s & 0x80 )
        return 1;
      if ( *s == '@' )
        at_seen=1;
      else if ( !at_seen && !( !!strchr( valid_chars, *s ) || *s == '+' ) )
        return 1;
      else if ( at_seen && !strchr( valid_chars, *s ) )
        return 1;
    }
  return 0;
}


/* Check whether NAME represents a valid mailbox according to
   RFC822. Returns true if so. */
int
is_valid_mailbox (const char *name)
{
  return !( !name
            || !*name
            || has_invalid_email_chars (name)
            || string_count_chr (name,'@') != 1
            || *name == '@'
            || name[strlen(name)-1] == '@'
            || name[strlen(name)-1] == '.'
            || strstr (name, "..") );
}


/* This is a helper function to load a Windows function from either of
   one DLLs. */
#ifdef HAVE_W32_SYSTEM
static HRESULT
w32_shgetfolderpath (HWND a, int b, HANDLE c, DWORD d, LPSTR e)
{
  static int initialized;
  static HRESULT (WINAPI * func)(HWND,int,HANDLE,DWORD,LPSTR);

  if (!initialized)
    {
      static char *dllnames[] = { "shell32.dll", "shfolder.dll", NULL };
      void *handle;
      int i;

      initialized = 1;

      for (i=0, handle = NULL; !handle && dllnames[i]; i++)
        {
          handle = dlopen (dllnames[i], RTLD_LAZY);
          if (handle)
            {
              func = dlsym (handle, "SHGetFolderPathA");
              if (!func)
                {
                  dlclose (handle);
                  handle = NULL;
                }
            }
        }
    }

  if (func)
    return func (a,b,c,d,e);
  else
    return -1;
}
#endif /*HAVE_W32_SYSTEM*/


/* Set up the default home directory.  The usual --homedir option
   should be parsed later. */
char *
default_homedir (void)
{
  char *dir;

  dir = getenv("GNUPGHOME");
#ifdef HAVE_W32_SYSTEM
  if (!dir || !*dir)
    dir = read_w32_registry_string (NULL, "Software\\GNU\\GnuPG", "HomeDir");
  if (!dir || !*dir)
    {
      char path[MAX_PATH];
      
      /* It might be better to use LOCAL_APPDATA because this is
         defined as "non roaming" and thus more likely to be kept
         locally.  For private keys this is desired.  However, given
         that many users copy private keys anyway forth and back,
         using a system roaming serives might be better than to let
         them do it manually.  A security conscious user will anyway
         use the registry entry to have better control.  */
      if (w32_shgetfolderpath (NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE, 
                               NULL, 0, path) >= 0) 
        {
          char *tmp = xmalloc (strlen (path) + 6 +1);
          strcpy (stpcpy (tmp, path), "\\gnupg");
          dir = tmp;
          
          /* Try to create the directory if it does not yet
             exists.  */
          if (access (dir, F_OK))
            CreateDirectory (dir, NULL);
        }
    }
#endif /*HAVE_W32_SYSTEM*/
  if (!dir || !*dir)
    dir = GNUPG_HOMEDIR;

  return dir;
}


/* Return the name of the libexec directory.  The name is allocated in
   a static area on the first use.  This function won't fail. */
const char *
get_libexecdir (void)
{
#ifdef HAVE_W32_SYSTEM
  static int got_dir;
  static char dir[MAX_PATH+5];

  if (!got_dir)
    {
      char *p;

      if ( !GetModuleFileName ( NULL, dir, MAX_PATH) )
        {
          log_debug ("GetModuleFileName failed: %s\n", w32_strerror (0));
          *dir = 0;
        }
      got_dir = 1;
      p = strrchr (dir, DIRSEP_C);
      if (p)
        *p = 0;
      else
        {
          log_debug ("bad filename `%s' returned for this process\n", dir);
          *dir = 0; 
        }
    }

  if (*dir)
    return dir;
  /* Fallback to the hardwired value. */
#endif /*HAVE_W32_SYSTEM*/

  return GNUPG_LIBEXECDIR;
}

/* Similar to access(2), but uses PATH to find the file. */
int
path_access(const char *file,int mode)
{
  char *envpath;
  int ret=-1;

  envpath=getenv("PATH");

  if(!envpath
#ifdef HAVE_DRIVE_LETTERS
     || (((file[0]>='A' && file[0]<='Z')
	  || (file[0]>='a' && file[0]<='z'))
	 && file[1]==':')
#else
     || file[0]=='/'
#endif
     )
    return access(file,mode);
  else
    {
      /* At least as large as, but most often larger than we need. */
      char *buffer=xmalloc(strlen(envpath)+1+strlen(file)+1);
      char *split,*item,*path=xstrdup(envpath);

      split=path;

      while((item=strsep(&split,PATHSEP_S)))
	{
	  strcpy(buffer,item);
	  strcat(buffer,"/");
	  strcat(buffer,file);
	  ret=access(buffer,mode);
	  if(ret==0)
	    break;
	}

      xfree(path);
      xfree(buffer);
    }

  return ret;
}
