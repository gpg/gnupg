/* misc.c -  miscellaneous functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2003 Free Software Foundation, Inc.
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
#include <assert.h>
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#include <asm/sysinfo.h>
#include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include "gpg.h"
#include "util.h"
#include "main.h"
#include "photoid.h"
#include "options.h"
#include "i18n.h"

#define MAX_EXTERN_MPI_BITS 16384


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
checksum_mpi( gcry_mpi_t a )
{
  int rc;
  u16 csum;
  byte *buffer;
  size_t nbytes;

  rc = gcry_mpi_print( GCRYMPI_FMT_PGP, NULL, 0, &nbytes, a );
  if (rc)
    BUG ();
  /* fixme: for numbers not in secure memory we should use a stack
   * based buffer and only allocate a larger one if mpi_print return
   * an error */
  buffer = gcry_is_secure(a)? gcry_xmalloc_secure(nbytes):gcry_xmalloc(nbytes);
  rc = gcry_mpi_print (GCRYMPI_FMT_PGP, buffer, nbytes, NULL, a );
  if (rc)
    BUG ();
  csum = checksum (buffer, nbytes );
  xfree (buffer );
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
        return GPG_ERR_CIPHER_ALGO;
    return gcry_cipher_test_algo (algo);
}

int
openpgp_pk_test_algo( int algo, unsigned int usage_flags )
{
  size_t value = usage_flags;

  if (algo == GCRY_PK_ELG_E)
    algo = GCRY_PK_ELG;
#ifdef __GNUC__
#warning need to handle the usage here?
#endif
  if (algo < 0 || algo > 110)
    return GPG_ERR_PUBKEY_ALGO;
  return gcry_pk_algo_info (algo, GCRYCTL_TEST_ALGO, NULL, &value);
}

int 
openpgp_pk_algo_usage ( int algo )
{
    int use = 0; 
    
    /* they are hardwired in gpg 1.0 */
    switch ( algo ) {    
      case PUBKEY_ALGO_RSA:
          use = PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC | PUBKEY_USAGE_AUTH;
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
          use = PUBKEY_USAGE_SIG | PUBKEY_USAGE_AUTH;
          break;
      case PUBKEY_ALGO_ELGAMAL:
          use = PUBKEY_USAGE_SIG | PUBKEY_USAGE_ENC | PUBKEY_USAGE_AUTH;
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
        return GPG_ERR_DIGEST_ALGO;
    return gcry_md_test_algo (algo);
}

int
openpgp_md_map_name (const char *string)
{
  int i = gcry_md_map_name (string);

  if (!i && (string[0]=='H' || string[0]=='h'))
    { /* Didn't find it, so try the Hx format */
      long val;
      char *endptr;

      string++;
      
      val=strtol(string,&endptr,10);
      if (*string!='\0' && *endptr=='\0' && !openpgp_md_test_algo(val))
        i = val;
    }
  return i < 0 || i > 110? 0 : i;
}

int
openpgp_cipher_map_name (const char *string)
{
  int i = gcry_cipher_map_name (string);

  if (!i && (string[0]=='S' || string[0]=='s'))
    { /* Didn't find it, so try the Sx format */
      long val;
      char *endptr;

      string++;
      
      val=strtol(string,&endptr,10);
      if (*string!='\0' && *endptr=='\0' && !openpgp_cipher_test_algo(val))
        i = val;
    }
  return i < 0 || i > 110? 0 : i;
}

int
openpgp_pk_map_name (const char *string)
{
  int i = gcry_pk_map_name (string);
  return i < 0 || i > 110? 0 : i;
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
      log_info(_("please see http://www.gnupg.org/why-not-idea.html "
		 "for more information\n"));
      warned=1;
    }
}
#endif

/* Expand %-strings.  Returns a string which must be m_freed.  Returns
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
	  ret= xrealloc(ret,maxlen);
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

	    case 'p': /* primary pk fingerprint of a sk */
	    case 'f': /* pk fingerprint */
	    case 'g': /* sk fingerprint */
	      {
		byte array[MAX_FINGERPRINT_LEN];
		size_t len;
		int i;

		if( ch[1]=='p' && args->sk)
		  {
		    if(args->sk->is_primary)
		      fingerprint_from_sk(args->sk,array,&len);
		    else if(args->sk->main_keyid[0] || args->sk->main_keyid[1])
		      {
			PKT_public_key *pk= xcalloc(1, sizeof(PKT_public_key));

			if(get_pubkey_fast(pk,args->sk->main_keyid)==0)
			  fingerprint_from_pk(pk,array,&len);
			else
			  memset(array,0,(len=MAX_FINGERPRINT_LEN));
			free_public_key(pk);
		      }
		    else
		      memset(array,0,(len=MAX_FINGERPRINT_LEN));
		  }
		else if( ch[1]=='f' && args->pk)
		  fingerprint_from_pk(args->pk,array,&len);
		else if( ch[1]=='g' && args->sk)
		  fingerprint_from_sk(args->sk,array,&len);
		else
		  memset(array, 0, (len=MAX_FINGERPRINT_LEN));

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
  xfree (ret);
  return NULL;
}

int
hextobyte( const char *s )
{
    int c;

    if( *s >= '0' && *s <= '9' )
	c = 16 * (*s - '0');
    else if( *s >= 'A' && *s <= 'F' )
	c = 16 * (10 + *s - 'A');
    else if( *s >= 'a' && *s <= 'f' )
	c = 16 * (10 + *s - 'a');
    else
	return -1;
    s++;
    if( *s >= '0' && *s <= '9' )
	c += *s - '0';
    else if( *s >= 'A' && *s <= 'F' )
	c += 10 + *s - 'A';
    else if( *s >= 'a' && *s <= 'f' )
	c += 10 + *s - 'a';
    else
	return -1;
    return c;
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

const char *
compress_algo_to_string(int algo)
{
  const char *s="?";

  switch(algo)
    {
    case 0:
      s="Uncompressed";
      break;

    case 1:
      s="ZIP";
      break;

    case 2:
      s="ZLIB";
      break;
    }

  return s;
}

int
string_to_compress_algo(const char *string)
{
  if(ascii_strcasecmp(string,"uncompressed")==0)
    return 0;
  else if(ascii_strcasecmp(string,"zip")==0)
    return 1;
  else if(ascii_strcasecmp(string,"zlib")==0)
    return 2;
  else if(ascii_strcasecmp(string,"z0")==0)
    return 0;
  else if(ascii_strcasecmp(string,"z1")==0)
    return 1;
  else if(ascii_strcasecmp(string,"z2")==0)
    return 2;
  else
    return -1;
}

int
check_compress_algo(int algo)
{
  if(algo>=0 && algo<=2)
    return 0;

  return GPG_ERR_COMPR_ALGO;
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
   sign.c:hash_for */

int
default_compress_algo(void)
{
  if(opt.def_compress_algo!=-1)
    return opt.def_compress_algo;
  else if(opt.personal_compress_prefs)
    return opt.personal_compress_prefs[0].value;
  else
    return DEFAULT_COMPRESS_ALGO;
}

const char *
compliance_option_string(void)
{
  switch(opt.compliance)
    {
    case CO_RFC2440:
      return "--openpgp";
    case CO_PGP2:
      return "--pgp2";
    case CO_PGP6:
      return "--pgp6";
    case CO_PGP7:
      return "--pgp7";
    case CO_PGP8:
      return "--pgp8";
    default:
      return "???";
    }
}

static const char *
compliance_string(void)
{
  switch(opt.compliance)
    {
    case CO_RFC2440:
      return "OpenPGP";
    case CO_PGP2:
      return "PGP 2.x";
    case CO_PGP6:
      return "PGP 6.x";
    case CO_PGP7:
      return "PGP 7.x";
    case CO_PGP8:
      return "PGP 8.x";
    default:
      return "???";
    }
}

void
compliance_failure(void)
{
  log_info(_("this message may not be usable by %s\n"),compliance_string());
  opt.compliance=CO_GNUPG;
}

int
parse_options(char *str,unsigned int *options,struct parse_options *opts)
{
  char *tok;

  while((tok=strsep(&str," ,")))
    {
      int i,rev=0;

      if(tok[0]=='\0')
	continue;

      if(ascii_strncasecmp("no-",tok,3)==0)
	{
	  rev=1;
	  tok+=3;
	}

      for(i=0;opts[i].name;i++)
	{
	  if(ascii_strcasecmp(opts[i].name,tok)==0)
	    {
	      if(rev)
		*options&=~opts[i].bit;
	      else
		*options|=opts[i].bit;
	      break;
	    }
	}

      if(!opts[i].name)
	return 0;
    }

  return 1;
}



/* Temporary helper. */
int
pubkey_get_npkey( int algo )
{
  size_t n;

  if (algo == GCRY_PK_ELG_E)
    algo = GCRY_PK_ELG;
  if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NPKEY, NULL, &n))
    n = 0;
  return n;
}

/* Temporary helper. */
int
pubkey_get_nskey( int algo )
{
  size_t n;

  if (algo == GCRY_PK_ELG_E)
    algo = GCRY_PK_ELG;
  if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NSKEY, NULL, &n ))
    n = 0;
  return n;
}

/* Temporary helper. */
int
pubkey_get_nsig( int algo )
{
  size_t n;

  if (algo == GCRY_PK_ELG_E)
    algo = GCRY_PK_ELG;
  if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NSIGN, NULL, &n))
    n = 0;
  return n;
}

/* Temporary helper. */
int
pubkey_get_nenc( int algo )
{
  size_t n;
  
  if (algo == GCRY_PK_ELG_E)
    algo = GCRY_PK_ELG;
  if (gcry_pk_algo_info( algo, GCRYCTL_GET_ALGO_NENCR, NULL, &n ))
    n = 0;
  return n;
}


/* Temporary helper. */
unsigned int
pubkey_nbits( int algo, gcry_mpi_t *key )
{
    int rc, nbits;
    gcry_sexp_t sexp;

    if( algo == GCRY_PK_DSA ) {
	rc = gcry_sexp_build ( &sexp, NULL,
			      "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
				  key[0], key[1], key[2], key[3] );
    }
    else if( algo == GCRY_PK_ELG || algo == GCRY_PK_ELG_E ) {
	rc = gcry_sexp_build ( &sexp, NULL,
			      "(public-key(elg(p%m)(g%m)(y%m)))",
				  key[0], key[1], key[2] );
    }
    else if( algo == GCRY_PK_RSA ) {
	rc = gcry_sexp_build ( &sexp, NULL,
			      "(public-key(rsa(n%m)(e%m)))",
				  key[0], key[1] );
    }
    else
	return 0;

    if ( rc )
	BUG ();

    nbits = gcry_pk_get_nbits( sexp );
    gcry_sexp_release( sexp );
    return nbits;
}


/* MPI helper functions. */


/****************
 * write an mpi to out.
 */
int
mpi_write( iobuf_t out, gcry_mpi_t a )
{
    char buffer[(MAX_EXTERN_MPI_BITS+7)/8];
    size_t nbytes;
    int rc;

    nbytes = (MAX_EXTERN_MPI_BITS+7)/8;
    rc = gcry_mpi_print (GCRYMPI_FMT_PGP, buffer, nbytes, &nbytes, a );
    if( !rc )
	rc = iobuf_write( out, buffer, nbytes );

    return rc;
}

/****************
 * Writyeg a MPI to out, but in this case it is an opaque one,
 * s used vor v3 protected keys.
 */
int
mpi_write_opaque( iobuf_t out, gcry_mpi_t a )
{
    size_t nbytes, nbits;
    int rc;
    char *p;

    assert( gcry_mpi_get_flag( a, GCRYMPI_FLAG_OPAQUE ) );
    p = gcry_mpi_get_opaque( a, &nbits );
    nbytes = (nbits+7) / 8;
    iobuf_put( out, nbits >> 8 );
    iobuf_put( out, nbits );
    rc = iobuf_write( out, p, nbytes );
    return rc;
}


/****************
 * Read an external representation of an mpi and return the MPI
 * The external format is a 16 bit unsigned value stored in network byte order,
 * giving the number of bits for the following integer. The integer is stored
 * with MSB first (left padded with zeroes to align on a byte boundary).
 */
gcry_mpi_t
mpi_read(iobuf_t inp, unsigned int *ret_nread, int secure)
{
    int c, c1, c2, i;
    unsigned int nbits, nbytes, nread=0;
    gcry_mpi_t a = NULL;
    byte *buf = NULL;
    byte *p;

    if( (c = c1 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits = c << 8;
    if( (c = c2 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits |= c;
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	goto leave;
    }
    nread = 2;
    nbytes = (nbits+7) / 8;
    buf = secure? gcry_xmalloc_secure( nbytes+2 ) : gcry_xmalloc( nbytes+2 );
    p = buf;
    p[0] = c1;
    p[1] = c2;
    for( i=0 ; i < nbytes; i++ ) {
	p[i+2] = iobuf_get(inp) & 0xff;
	nread++;
    }
    nread += nbytes;
    if( gcry_mpi_scan( &a, GCRYMPI_FMT_PGP, buf, nread, &nread ) )
	a = NULL;

  leave:
    gcry_free(buf);
    if( nread > *ret_nread )
	log_bug("mpi larger than packet");
    else
	*ret_nread = nread;
    return a;
}

/****************
 * Same as mpi_read but the value is stored as an opaque MPI.
 * This function is used to read encrypted MPI of v3 packets.
 */
gcry_mpi_t
mpi_read_opaque(iobuf_t inp, unsigned *ret_nread )
{
    int c, c1, c2, i;
    unsigned nbits, nbytes, nread=0;
    gcry_mpi_t a = NULL;
    byte *buf = NULL;
    byte *p;

    if( (c = c1 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits = c << 8;
    if( (c = c2 = iobuf_get(inp)) == -1 )
	goto leave;
    nbits |= c;
    if( nbits > MAX_EXTERN_MPI_BITS ) {
	log_error("mpi too large (%u bits)\n", nbits);
	goto leave;
    }
    nread = 2;
    nbytes = (nbits+7) / 8;
    buf = gcry_xmalloc( nbytes );
    p = buf;
    for( i=0 ; i < nbytes; i++ ) {
	p[i] = iobuf_get(inp) & 0xff;
    }
    nread += nbytes;
    a = gcry_mpi_set_opaque(NULL, buf, nbits );
    buf = NULL;

  leave:
    gcry_free(buf);
    if( nread > *ret_nread )
	log_bug("mpi larger than packet");
    else
	*ret_nread = nread;
    return a;
}


int
mpi_print( FILE *fp, gcry_mpi_t a, int mode )
{
    int n=0;

    if( !a )
	return fprintf(fp, "[MPI_NULL]");
    if( !mode ) {
	unsigned int n1;
	n1 = gcry_mpi_get_nbits(a);
	n += fprintf(fp, "[%u bits]", n1);
    }
    else {
	int rc;
	unsigned char *buffer;

	rc = gcry_mpi_aprint( GCRYMPI_FMT_HEX, &buffer, NULL, a );
	assert( !rc );
	fputs( buffer, fp );
	n += strlen(buffer);
	gcry_free( buffer );
    }
    return n;
}


