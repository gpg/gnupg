/* misc.c -  miscellaneous functions
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_STAT
#include <sys/stat.h>
#endif
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
  #include <asm/sysinfo.h>
  #include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
  #include <time.h>
  #include <sys/time.h>
  #include <sys/resource.h>
#endif
#include "util.h"
#include "main.h"
#include "options.h"
#include "i18n.h"


const char *g10m_revision_string(int);
const char *g10c_revision_string(int);
const char *g10u_revision_string(int);

#ifdef __GNUC__
volatile
#endif
	 void
pull_in_libs(void)
{
    g10m_revision_string(0);
    g10c_revision_string(0);
    g10u_revision_string(0);
}


#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#warning using trap_unaligned
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



u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    if( opt.emulate_bugs & EMUBUG_GPGCHKSUM ) {
       a |= n & 0xff;
       log_debug("csum_u16 emulated for n=%u\n", n);
    }
    else
       a += n & 0xff;
    return a;
}

static u16
checksum_u16_nobug( unsigned n )
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
    /* some versions of gpg encode wrong values for the length of an mpi
     * so that mpi_get_nbits() which counts the mpi yields another (shorter)
     * value than the one store with the mpi.  mpi_get_nbit_info() returns
     * this stored value if it is still available.
     */

    if( opt.emulate_bugs & EMUBUG_GPGCHKSUM )
	nbits = 0;
    else
	nbits = mpi_get_nbit_info(a);
    if( !nbits )
       nbits = mpi_get_nbits(a);
    csum = checksum_u16( nbits );
    csum += checksum( buffer, nbytes );
    m_free( buffer );
    return csum;
}

/****************
 * This is the correct function
 */
u16
checksum_mpi_counted_nbits( MPI a )
{
    u16 csum;
    byte *buffer;
    unsigned nbytes;
    unsigned nbits;

    buffer = mpi_get_buffer( a, &nbytes, NULL );
    nbits = mpi_get_nbits(a);
    mpi_set_nbit_info(a,nbits);
    csum = checksum_u16_nobug( nbits );
    csum += checksum( buffer, nbytes );
    m_free( buffer );
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


static void
no_exp_algo(void)
{
    static int did_note = 0;

    if( !did_note ) {
	did_note = 1;
	log_info(_("Experimental algorithms should not be used!\n"));
    }
}

void
print_pubkey_algo_note( int algo )
{
    if( algo >= 100 && algo <= 110 )
	no_exp_algo();
}

void
print_cipher_algo_note( int algo )
{
    if( algo >= 100 && algo <= 110 )
	no_exp_algo();
    else if(	algo == CIPHER_ALGO_3DES
	     || algo == CIPHER_ALGO_CAST5
	     || algo == CIPHER_ALGO_BLOWFISH
	     || algo == CIPHER_ALGO_TWOFISH
	     || algo == CIPHER_ALGO_RIJNDAEL
	     || algo == CIPHER_ALGO_RIJNDAEL192
	     || algo == CIPHER_ALGO_RIJNDAEL256
	   )
	;
    else {
	static int did_note = 0;

	if( !did_note ) {
	    did_note = 1;
	    log_info(_("this cipher algorithm is deprecated; "
		       "please use a more standard one!\n"));
	}
    }
}

void
print_digest_algo_note( int algo )
{
    if( algo >= 100 && algo <= 110 )
	no_exp_algo();
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
          use = PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_RSA_E:
          use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_RSA_S:
          use = PUBKEY_USAGE_SIG;
          break;
      case PUBKEY_ALGO_ELGAMAL_E:
          use = PUBKEY_USAGE_ENC;
          break;
      case PUBKEY_ALGO_DSA:  
          use = PUBKEY_USAGE_SIG;
          break;
      case PUBKEY_ALGO_ELGAMAL:
          use = PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC;
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

int
check_permissions(const char *path,int extension,int checkonly)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  char *tmppath;
  struct stat statbuf;
  int ret=1;
  int isdir=0;

  if(opt.no_perm_warn)
    return 0;

  if(extension && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(GNUPG_LIBDIR,path,NULL);
    }
  else
    tmppath=m_strdup(path);

  /* It's okay if the file doesn't exist */
  if(stat(tmppath,&statbuf)!=0)
    {
      ret=0;
      goto end;
    }

  isdir=S_ISDIR(statbuf.st_mode);

  /* Per-user files must be owned by the user.  Extensions must be
     owned by the user or root. */
  if((!extension && statbuf.st_uid != getuid()) ||
     (extension && statbuf.st_uid!=0 && statbuf.st_uid!=getuid()))
    {
      if(!checkonly)
	log_info(_("Warning: unsafe ownership on %s \"%s\"\n"),
		 isdir?"directory":extension?"extension":"file",path);
      goto end;
    }

  /* This works for both directories and files - basically, we don't
     care what the owner permissions are, so long as the group and
     other permissions are 0 for per-user files, and non-writable for
     extensions. */
  if((extension && (statbuf.st_mode & (S_IWGRP|S_IWOTH)) !=0) ||
     (!extension && (statbuf.st_mode & (S_IRWXG|S_IRWXO)) != 0))
    {
      char *dir;

      /* However, if the directory the directory/file is in is owned
         by the user and is 700, then this is not a problem.
         Theoretically, we could walk this test up to the root
         directory /, but for the sake of sanity, I'm stopping at one
         level down. */

      dir=make_dirname(tmppath);
      if(stat(dir,&statbuf)==0 && statbuf.st_uid==getuid() &&
	 S_ISDIR(statbuf.st_mode) && (statbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
	{
	  m_free(dir);
	  ret=0;
	  goto end;
	}

      m_free(dir);

      if(!checkonly)
	log_info(_("Warning: unsafe permissions on %s \"%s\"\n"),
		 isdir?"directory":extension?"extension":"file",path);
      goto end;
    }

  ret=0;

 end:
  m_free(tmppath);

  return ret;

#endif /* HAVE_STAT && !HAVE_DOSISH_SYSTEM */

  return 0;
}

/* Special warning for the IDEA cipher */
void
idea_cipher_warn(int show)
{
  static int warned=0;

  if(!warned || show)
    {
      log_info(_("the IDEA cipher plugin is not present\n"));
      log_info(_("please see http://www.gnupg.org/why-not-idea.html "
		 "for more information\n"));
      warned=1;
    }
}

/* The largest string we have an expando for, times two. */
#define LARGEST_EXPANDO ((MAX_FINGERPRINT_LEN*2)*2)

/* Expand %-strings.  Returns a string which must be m_freed.  Returns
   NULL if the string cannot be expanded (too large). */
char *
pct_expando(const char *string,PKT_public_key *pk)
{
  const char *ch=string;
  int idx=0,maxlen;
  u32 keyid[2]={0,0};
  char *ret;

  keyid_from_pk(pk,keyid);

  maxlen=LARGEST_EXPANDO;
  ret=m_alloc(maxlen+1);  /* one more to leave room for the trailing \0 */

  ret[0]='\0';

  while(*ch!='\0')
    {
      /* 8192 is way bigger than we'll need here */
      if(maxlen-idx<LARGEST_EXPANDO && maxlen<8192)
	{
	  maxlen+=LARGEST_EXPANDO;
	  ret=m_realloc(ret,maxlen+1);
	}

      if(*ch=='%')
	{
	  ch++;

	  switch(*ch)
	    {
	    case 'k': /* short key id */
	      if(idx+8>maxlen)
		goto fail;

	      sprintf(&ret[idx],"%08lX",(ulong)keyid[1]);
	      idx+=8;
	      break;

	    case 'K': /* long key id */
	      if(idx+16>maxlen)
		goto fail;

	      sprintf(&ret[idx],"%08lX%08lX",(ulong)keyid[0],(ulong)keyid[1]);
	      idx+=16;
	      break;

	    case 'f': /* fingerprint */
	      {
		byte array[MAX_FINGERPRINT_LEN];
		size_t len;
		int i;

		fingerprint_from_pk(pk,array,&len);

		if(idx+(len*2)>maxlen)
		  goto fail;

		for(i=0;i<len;i++)
		  {
		    sprintf(&ret[idx],"%02X",array[i]);
		    idx+=2;
		  }
	      }
	      break;
		
	    case '%':
	      if(idx+1>maxlen)
		goto fail;

	      ret[idx++]='%';
	      ret[idx]='\0';
	      break;

	      /* Any unknown %-keys (like %i, %o, %I, and %O) are
		 passed through for later expansion.  Note this also
		 handles the case where the last character in the
		 string is a '%' - the terminating \0 will end up here
		 and properly terminate the string. */
	    default:
	      if(idx+2>maxlen)
		goto fail;

	      ret[idx++]='%';
	      ret[idx++]=*ch;
	      ret[idx]='\0';
	      break;
	    }
	}
      else
	{
	  if(idx+1>maxlen)
	    goto fail;

	  ret[idx++]=*ch;
	  ret[idx]='\0';
	}

      ch++;
    }

  return ret;

 fail:
  m_free(ret);
  return NULL;
}
