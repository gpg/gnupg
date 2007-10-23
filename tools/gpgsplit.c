/* gpgsplit.c - An OpenPGP packet splitting tool
 * Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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

/* 
 * TODO: Add an option to uncompress packets.  This should come quite handy.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#ifdef HAVE_DOSISH_SYSTEM
# include <fcntl.h> /* for setmode() */
#endif
#include <zlib.h>
#ifdef HAVE_BZIP2
#include <bzlib.h>
#endif /* HAVE_BZIP2 */
#if defined(__riscos__) && defined(USE_ZLIBRISCOS)
# include "zlib-riscos.h"
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "../g10/packet.h"
#include "util.h"

static int opt_verbose;
static const char *opt_prefix = "";
static int opt_uncompress;
static int opt_secret_to_public;
static int opt_no_split;

static void g10_exit( int rc );
static void split_packets (const char *fname);


enum cmd_and_opt_values {
  aNull = 0,
  oVerbose	  = 'v',
  oPrefix       = 'p',                          
  oUncompress   = 500,                      
  oSecretToPublic,                      
  oNoSplit,

  aTest
};


static ARGPARSE_OPTS opts[] = {

    { 301, NULL, 0, "@Options:\n " },

    { oVerbose, "verbose",   0, "verbose" },
    { oPrefix,  "prefix",    2, "|STRING|Prepend filenames with STRING" },
    { oUncompress, "uncompress", 0, "uncompress a packet"},
    { oSecretToPublic, "secret-to-public", 0, "convert secret keys to public keys"},
    { oNoSplit, "no-split", 0, "write to stdout and don't actually split"},
{0} };


const char *
strusage( int level )
{
  const char *p;
  switch (level)
    {
    case 11: p = "gpgsplit (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p =
               "Please report bugs to <bug-gnupg@gnu.org>.\n";
    break;
    case 1:
    case 40:	p =
                  "Usage: gpgsplit [options] [files] (-h for help)";
    break;
    case 41:	p =
                  "Syntax: gpgsplit [options] [files]\n"
                  "Split an OpenPGP message into packets\n";
    break;
    
    default:	p = default_strusage(level);
    }
  return p;
}



int
main( int argc, char **argv )
{
  ARGPARSE_ARGS pargs;

#ifdef HAVE_DOSISH_SYSTEM
  setmode( fileno(stdin), O_BINARY );
  setmode( fileno(stdout), O_BINARY );
#endif
  log_set_name("gpgsplit");
  
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
  while (optfile_parse( NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose: opt_verbose = 1; break;
        case oPrefix: opt_prefix = pargs.r.ret_str; break;
        case oUncompress: opt_uncompress = 1; break;
        case oSecretToPublic: opt_secret_to_public = 1; break;
        case oNoSplit: opt_no_split = 1; break;
        default : pargs.err = 2; break;
	}
    }
  
  if (log_get_errorcount(0))
    g10_exit (2);

  if (!argc)
    split_packets (NULL);
  else
    {
      for ( ;argc; argc--, argv++) 
        split_packets (*argv);
    }
  
  g10_exit (0);
  return 0; 
}


static void
g10_exit (int rc)
{
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit(rc );
}

static const char *
pkttype_to_string (int pkttype)
{
  const char *s;

  switch (pkttype)
    {
    case PKT_PUBKEY_ENC    : s = "pk_enc"; break;
    case PKT_SIGNATURE     : s = "sig"; break;
    case PKT_SYMKEY_ENC    : s = "sym_enc"; break;
    case PKT_ONEPASS_SIG   : s = "onepass_sig"; break;
    case PKT_SECRET_KEY    : s = "secret_key"; break;
    case PKT_PUBLIC_KEY    : s = "public_key"; break;
    case PKT_SECRET_SUBKEY : s = "secret_subkey"; break;
    case PKT_COMPRESSED    : 
      s = opt_uncompress? "uncompressed":"compressed";
      break;
    case PKT_ENCRYPTED     : s = "encrypted"; break;
    case PKT_MARKER	       : s = "marker"; break;
    case PKT_PLAINTEXT     : s = "plaintext"; break;
    case PKT_RING_TRUST    : s = "ring_trust"; break;
    case PKT_USER_ID       : s = "user_id"; break;
    case PKT_PUBLIC_SUBKEY : s = "public_subkey"; break;
    case PKT_OLD_COMMENT   : s = "old_comment"; break;
    case PKT_ATTRIBUTE     : s = "attribute"; break;
    case PKT_ENCRYPTED_MDC : s = "encrypted_mdc"; break;
    case PKT_MDC 	       : s = "mdc"; break;
    case PKT_COMMENT       : s = "comment"; break;
    case PKT_GPG_CONTROL   : s = "gpg_control"; break;
    default: s = "unknown"; break;
    }
  return s;
}


/*
 * Create a new filename and a return a pointer to a statically
 * allocated buffer 
 */
static char *
create_filename (int pkttype)
{
  static unsigned int partno = 0;
  static char *name;
  
  if (!name) 
    name = xmalloc (strlen (opt_prefix) + 100 );
  
  assert (pkttype < 1000 && pkttype >= 0 );
  partno++;
  sprintf (name, "%s%06u-%03d" EXTSEP_S "%.40s",
           opt_prefix, partno, pkttype, pkttype_to_string (pkttype));
  return name;
}

static int
read_u16 (FILE *fp, size_t *rn)
{
  int c;

  if ( (c = getc (fp)) == EOF )
    return -1;
  *rn = c << 8;
  if ( (c = getc (fp)) == EOF )
    return -1;
  *rn |= c;
  return 0;
}

static int
read_u32 (FILE *fp, unsigned long *rn)
{
  size_t tmp;
  
  if (read_u16 (fp, &tmp))
    return -1;
  *rn = tmp << 16;
  if (read_u16 (fp, &tmp))
    return -1;
  *rn |= tmp;
  return 0;
}

static int
write_old_header (FILE *fp, int pkttype, unsigned int len)
{     
  int ctb = (0x80 | ((pkttype & 15)<<2));
  
  if (len < 256)
    ;
  else if (len < 65536)
    ctb |= 1;
  else
    ctb |= 2;

  if ( putc ( ctb, fp) == EOF )
    return -1;

  if ( (ctb & 2) )
    {
      if (putc ((len>>24), fp) == EOF)
        return -1;
      if (putc ((len>>16), fp) == EOF)
        return -1;
    }
  if ( (ctb & 3) )
    {
      if (putc ((len>>8), fp) == EOF)
        return -1;
    }
  if (putc ((len&0xff), fp) == EOF)
    return -1;
  return 0;
}

static int
write_new_header (FILE *fp, int pkttype, unsigned int len)
{     
  if ( putc ((0xc0 | (pkttype & 0x3f)), fp) == EOF )
    return -1;

  if (len < 192)
    {
      if (putc (len, fp) == EOF)
        return -1;
    }
  else if (len < 8384)
    {
      len -= 192;
      if (putc ((len/256)+192, fp) == EOF)
        return -1;
      if (putc ((len%256), fp) == EOF)
        return -1;
    }
  else
    {
      if (putc ( 0xff, fp) == EOF)
        return -1;
      if (putc ( (len >> 24), fp) == EOF)
        return -1;
      if (putc ( (len >> 16), fp) == EOF)
        return -1;
      if (putc ( (len >> 8), fp) == EOF)
        return -1;
      if (putc ( (len & 0xff), fp) == EOF)
        return -1;
    }
  return 0;
}

/* Return the length of the public key given BUF of BUFLEN with a
   secret key. */
static int
public_key_length (const unsigned char *buf, size_t buflen)
{
  const unsigned char *s;
  int nmpis;

  /*   byte version number (3 or 4)
       u32  creation time 
       [u16  valid days (version 3 only)]
       byte algorithm 
       n    MPIs (n and e) */
  if (!buflen)
    return 0;
  if (buf[0] < 2 || buf[0] > 4)
    return 0; /* wrong version number */
  if (buflen < (buf[0] == 4? 6:8))
    return 0;
  s = buf + (buf[0] == 4? 6:8);
  buflen -= (buf[0] == 4? 6:8);
  switch (s[-1])
    {
    case 1:
    case 2:
    case 3:
      nmpis = 2;
      break;
    case 16:
    case 20:
      nmpis = 3;
      break;
    case 17:
      nmpis = 4;
      break;
    default:
      return 0;
    }

  for (; nmpis; nmpis--)
    {
      unsigned int nbits, nbytes;

      if (buflen < 2)
        return 0;
      nbits = (s[0] << 8) | s[1];
      s += 2; buflen -= 2;
      nbytes = (nbits+7) / 8;
      if (buflen < nbytes)
        return 0;
      s += nbytes; buflen -= nbytes;
    }

  return s - buf;
}

static int
handle_zlib(int algo,FILE *fpin,FILE *fpout)
{
  z_stream zs;
  byte *inbuf, *outbuf;
  unsigned int inbufsize, outbufsize;
  int c,zinit_done, zrc, nread, count;
  size_t n;
              
  memset (&zs, 0, sizeof zs);
  inbufsize = 2048;
  inbuf = xmalloc (inbufsize);
  outbufsize = 8192;
  outbuf = xmalloc (outbufsize);
  zs.avail_in = 0;
  zinit_done = 0;
              
  do
    {
      if (zs.avail_in < inbufsize)
	{
	  n = zs.avail_in;
	  if (!n)
	    zs.next_in = (Bytef *) inbuf;
	  count = inbufsize - n;
	  for (nread=0;
	       nread < count && (c=getc (fpin)) != EOF;
	       nread++) 
	    inbuf[n+nread] = c;
                      
	  n += nread;
	  if (nread < count && algo == 1) 
	    {
	      inbuf[n] = 0xFF; /* chew dummy byte */
	      n++;
	    }
	  zs.avail_in = n;
	}
      zs.next_out = (Bytef *) outbuf;
      zs.avail_out = outbufsize;
                    
      if (!zinit_done) 
	{
	  zrc = (algo == 1? inflateInit2 ( &zs, -13)
		 : inflateInit ( &zs ));
	  if (zrc != Z_OK) 
	    {
	      log_fatal ("zlib problem: %s\n", zs.msg? zs.msg :
			 zrc == Z_MEM_ERROR ? "out of core" :
			 zrc == Z_VERSION_ERROR ?
			 "invalid lib version" :
			 "unknown error" );
	    }
	  zinit_done = 1;
	}
      else
	{
#ifdef Z_SYNC_FLUSH
	  zrc = inflate (&zs, Z_SYNC_FLUSH);
#else
	  zrc = inflate (&zs, Z_PARTIAL_FLUSH);
#endif
	  if (zrc == Z_STREAM_END)
	    ; /* eof */
	  else if (zrc != Z_OK && zrc != Z_BUF_ERROR)
	    {
	      if (zs.msg)
		log_fatal ("zlib inflate problem: %s\n", zs.msg );
	      else
		log_fatal ("zlib inflate problem: rc=%d\n", zrc );
	    }
	  for (n=0; n < outbufsize - zs.avail_out; n++) 
	    {
	      if (putc (outbuf[n], fpout) == EOF )
		return 1;
	    }
	}
    } 
  while (zrc != Z_STREAM_END && zrc != Z_BUF_ERROR);
  inflateEnd (&zs);

  return 0;
}

#ifdef HAVE_BZIP2
static int
handle_bzip2(int algo,FILE *fpin,FILE *fpout)
{
  bz_stream bzs;
  byte *inbuf, *outbuf;
  unsigned int inbufsize, outbufsize;
  int c,zinit_done, zrc, nread, count;
  size_t n;
              
  memset (&bzs, 0, sizeof bzs);
  inbufsize = 2048;
  inbuf = xmalloc (inbufsize);
  outbufsize = 8192;
  outbuf = xmalloc (outbufsize);
  bzs.avail_in = 0;
  zinit_done = 0;
              
  do
    {
      if (bzs.avail_in < inbufsize)
	{
	  n = bzs.avail_in;
	  if (!n)
	    bzs.next_in = inbuf;
	  count = inbufsize - n;
	  for (nread=0;
	       nread < count && (c=getc (fpin)) != EOF;
	       nread++) 
	    inbuf[n+nread] = c;
                      
	  n += nread;
	  if (nread < count && algo == 1) 
	    {
	      inbuf[n] = 0xFF; /* chew dummy byte */
	      n++;
	    }
	  bzs.avail_in = n;
	}
      bzs.next_out = outbuf;
      bzs.avail_out = outbufsize;
                    
      if (!zinit_done) 
	{
	  zrc = BZ2_bzDecompressInit(&bzs,0,0);
	  if (zrc != BZ_OK) 
	    log_fatal ("bz2lib problem: %d\n",zrc);
	  zinit_done = 1;
	}
      else
	{
	  zrc = BZ2_bzDecompress(&bzs);
	  if (zrc == BZ_STREAM_END)
	    ; /* eof */
	  else if (zrc != BZ_OK && zrc != BZ_PARAM_ERROR)
	    log_fatal ("bz2lib inflate problem: %d\n", zrc );
	  for (n=0; n < outbufsize - bzs.avail_out; n++) 
	    {
	      if (putc (outbuf[n], fpout) == EOF )
		return 1;
	    }
	}
    } 
  while (zrc != BZ_STREAM_END && zrc != BZ_PARAM_ERROR);
  BZ2_bzDecompressEnd(&bzs);

  return 0;
}
#endif /* HAVE_BZIP2 */

/* hdr must point to a buffer large enough to hold all header bytes */
static int
write_part ( const char *fname, FILE *fpin, unsigned long pktlen,
             int pkttype, int partial, unsigned char *hdr, size_t hdrlen)
{
  FILE *fpout;
  int c, first;
  unsigned char *p;
  const char *outname = create_filename (pkttype);
  
#if defined(__riscos__) && defined(USE_ZLIBRISCOS)
  static int initialized = 0;

  if (!initialized)
      initialized = riscos_load_module("ZLib", zlib_path, 1);
#endif
  if (opt_no_split)
    fpout = stdout;
  else
    {
      if (opt_verbose)
        log_info ("writing `%s'\n", outname);
      fpout = fopen (outname, "wb");
      if (!fpout) 
        {
          log_error ("error creating `%s': %s\n", outname, strerror(errno));
          /* stop right now, otherwise we would mess up the sequence
             of the part numbers */
          g10_exit (1);
        }
    }

  if (opt_secret_to_public
      && (pkttype == PKT_SECRET_KEY || pkttype == PKT_SECRET_SUBKEY))
    {
      unsigned char *blob = xmalloc (pktlen);
      int i, len;

      pkttype = pkttype == PKT_SECRET_KEY? PKT_PUBLIC_KEY:PKT_PUBLIC_SUBKEY;

      for (i=0; i < pktlen; i++) 
        {
          c = getc (fpin);
          if (c == EOF) 
            goto read_error;
          blob[i] = c;
        }
      len = public_key_length (blob, pktlen);
      if (!len)
        {
          log_error ("error calcualting public key length\n");
          g10_exit (1);
        }
      if ( (hdr[0] & 0x40) )
        { 
          if (write_new_header (fpout, pkttype, len))
            goto write_error;
        }
      else
        { 
          if (write_old_header (fpout, pkttype, len))
            goto write_error;
        }

      for (i=0; i < len; i++) 
        {
          if ( putc (blob[i], fpout) == EOF )
            goto write_error;
        }

      goto ready;
    }


  if (!opt_uncompress)
    {
      for (p=hdr; hdrlen; p++, hdrlen--)
        {
          if ( putc (*p, fpout) == EOF )
            goto write_error;
        }
    }
  
  first = 1;
  while (partial)
    {
      size_t partlen;
      
      if (partial == 1)
        { /* openpgp */
          if (first )
            {
              c = pktlen;
              assert( c >= 224 && c < 255 );
              first = 0;
            }
          else if ((c = getc (fpin)) == EOF ) 
            goto read_error;
          else
            hdr[hdrlen++] = c;
            
          if (c < 192)
            {
              pktlen = c;
              partial = 0; /* (last segment may follow) */
            }
          else if (c < 224 )
            {
              pktlen = (c - 192) * 256;
              if ((c = getc (fpin)) == EOF) 
                goto read_error;
              hdr[hdrlen++] = c;
              pktlen += c + 192;
              partial = 0;
            }
          else if (c == 255)
            {
              if (read_u32 (fpin, &pktlen))
                goto read_error;
              hdr[hdrlen++] = pktlen >> 24;
              hdr[hdrlen++] = pktlen >> 16;
              hdr[hdrlen++] = pktlen >> 8;
              hdr[hdrlen++] = pktlen;
              partial = 0;
            }
          else
            { /* next partial body length */
              for (p=hdr; hdrlen; p++, hdrlen--)
                {
                  if ( putc (*p, fpout) == EOF )
                    goto write_error;
                }
              partlen = 1 << (c & 0x1f);
              for (; partlen; partlen--) 
                {
                  if ((c = getc (fpin)) == EOF) 
                    goto read_error;
                  if ( putc (c, fpout) == EOF )
                    goto write_error;
                }
            }
        }
      else if (partial == 2)
        { /* old gnupg */
          assert (!pktlen);
          if ( read_u16 (fpin, &partlen) )
            goto read_error;
          hdr[hdrlen++] = partlen >> 8;
          hdr[hdrlen++] = partlen;
          for (p=hdr; hdrlen; p++, hdrlen--) 
            {
              if ( putc (*p, fpout) == EOF )
                goto write_error;
            }
          if (!partlen)
            partial = 0; /* end of packet */
          for (; partlen; partlen--) 
            {
              c = getc (fpin);
              if (c == EOF) 
                goto read_error;
              if ( putc (c, fpout) == EOF )
                goto write_error;
            }
        }
      else
        { /* compressed: read to end */
          pktlen = 0;
          partial = 0;
          hdrlen = 0;
          if (opt_uncompress) 
            {
              if ((c = getc (fpin)) == EOF)
                goto read_error;

	      if(c==1 || c==2)
		{
		  if(handle_zlib(c,fpin,fpout))
		    goto write_error;
		}
#ifdef HAVE_BZIP2
	      else if(c==3)
		{
		  if(handle_bzip2(c,fpin,fpout))
		    goto write_error;
		}
#endif /* HAVE_BZIP2 */
	      else
		{
		  log_error("invalid compression algorithm (%d)\n",c);
		  goto read_error;
		}
            }
          else
            {
              while ( (c=getc (fpin)) != EOF ) 
                {
                  if ( putc (c, fpout) == EOF )
                    goto write_error;
                }
            }
          if (!feof (fpin))
            goto read_error;
	}
    }

  for (p=hdr; hdrlen; p++, hdrlen--) 
    {
      if ( putc (*p, fpout) == EOF )
        goto write_error;
    }
  
  /* standard packet or last segment of partial length encoded packet */
  for (; pktlen; pktlen--) 
    {
      c = getc (fpin);
      if (c == EOF) 
        goto read_error;
      if ( putc (c, fpout) == EOF )
        goto write_error;
    }
  
 ready:
  if ( !opt_no_split && fclose (fpout) )
    log_error ("error closing `%s': %s\n", outname, strerror (errno));
  return 0;
  
 write_error:    
  log_error ("error writing `%s': %s\n", outname, strerror (errno));
  if (!opt_no_split)
    fclose (fpout);
  return 2;
  
 read_error:
  if (!opt_no_split)
    {
      int save = errno;
      fclose (fpout);
      errno = save;
    }
  return -1;
}



static int
do_split (const char *fname, FILE *fp)
{
  int c, ctb, pkttype;
  unsigned long pktlen = 0;
  int partial = 0;
  unsigned char header[20];
  int header_idx = 0;
  
  ctb = getc (fp);
  if (ctb == EOF)
    return 3; /* ready */
  header[header_idx++] = ctb;
  
  if (!(ctb & 0x80))
    {
      log_error("invalid CTB %02x\n", ctb );
      return 1;
    }
  if ( (ctb & 0x40) )
    { /* new CTB */
      pkttype =  (ctb & 0x3f);
      if( (c = getc (fp)) == EOF )
        return -1;
      header[header_idx++] = c;

      if ( c < 192 )
        pktlen = c;
      else if ( c < 224 )
        {
          pktlen = (c - 192) * 256;
          if( (c = getc (fp)) == EOF ) 
            return -1;
          header[header_idx++] = c;
          pktlen += c + 192;
	}
      else if ( c == 255 ) 
        {
          if (read_u32 (fp, &pktlen))
            return -1;
          header[header_idx++] = pktlen >> 24;
          header[header_idx++] = pktlen >> 16;
          header[header_idx++] = pktlen >> 8;
          header[header_idx++] = pktlen; 
	}
      else
        { /* partial body length */
          pktlen = c;
          partial = 1;
	}
    }
  else
    {
      int lenbytes;
      
      pkttype = (ctb>>2)&0xf;
      lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
      if (!lenbytes )
        {
          pktlen = 0; /* don't know the value */
          if( pkttype == PKT_COMPRESSED )
            partial = 3;
          else
            partial = 2; /* the old GnuPG partial length encoding */
	}
      else
        {
          for ( ; lenbytes; lenbytes-- ) 
            {
              pktlen <<= 8;
              if( (c = getc (fp)) == EOF ) 
                return -1;
              header[header_idx++] = c;
              
              pktlen |= c;
	    }
	}
    }

  return write_part (fname, fp, pktlen, pkttype, partial,
                     header, header_idx);
}


static void
split_packets (const char *fname)
{
  FILE *fp;
  int rc;
  
  if (!fname || !strcmp (fname, "-"))
    {
      fp = stdin;
      fname = "-";
    }
  else if ( !(fp = fopen (fname,"rb")) ) 
    {
      log_error ("can't open `%s': %s\n", fname, strerror (errno));
      return;
    }
  
  while ( !(rc = do_split (fname, fp)) )
    ;
  if ( rc > 0 )
    ; /* error already handled */
  else if ( ferror (fp) )
    log_error ("error reading `%s': %s\n", fname, strerror (errno));
  else
    log_error ("premature EOF while reading `%s'\n", fname );
  
  if ( fp != stdin )
    fclose (fp);
}
