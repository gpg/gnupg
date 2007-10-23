/* compress.c - bzip2 compress filter
 * Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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
#include <string.h>
#include <stdio.h> /* Early versions of bzlib (1.0) require stdio.h */
#include <bzlib.h>

#include "util.h"
#include "memory.h"
#include "packet.h"
#include "filter.h"
#include "main.h"
#include "options.h"

/* Note that the code in compress.c is nearly identical to the code
   here, so if you fix a bug here, look there to see if a matching bug
   needs to be fixed.  I tried to have one set of functions that could
   do ZIP, ZLIB, and BZIP2, but it became dangerously unreadable with
   #ifdefs and if(algo) -dshaw */

static void
init_compress( compress_filter_context_t *zfx, bz_stream *bzs )
{
  int rc;
  int level;

  if( opt.bz2_compress_level >= 1 && opt.bz2_compress_level <= 9 )
    level = opt.bz2_compress_level;
  else if( opt.bz2_compress_level == -1 )
    level = 6; /* no particular reason, but it seems reasonable */
  else
    {
      log_error("invalid compression level; using default level\n");
      level = 6;
    }

  if((rc=BZ2_bzCompressInit(bzs,level,0,0))!=BZ_OK)
    log_fatal("bz2lib problem: %d\n",rc);

  zfx->outbufsize = 8192;
  zfx->outbuf = xmalloc( zfx->outbufsize );
}

static int
do_compress(compress_filter_context_t *zfx, bz_stream *bzs, int flush, IOBUF a)
{
  int zrc;
  unsigned n;

  do
    {
      bzs->next_out = zfx->outbuf;
      bzs->avail_out = zfx->outbufsize;
      if( DBG_FILTER )
	log_debug("enter bzCompress: avail_in=%u, avail_out=%u, flush=%d\n",
		  (unsigned)bzs->avail_in, (unsigned)bzs->avail_out, flush );
      zrc = BZ2_bzCompress( bzs, flush );
      if( zrc == BZ_STREAM_END && flush == BZ_FINISH )
	;
      else if( zrc != BZ_RUN_OK && zrc != BZ_FINISH_OK )
	log_fatal("bz2lib deflate problem: rc=%d\n", zrc );

      n = zfx->outbufsize - bzs->avail_out;
      if( DBG_FILTER )
	log_debug("leave bzCompress:"
		  " avail_in=%u, avail_out=%u, n=%u, zrc=%d\n",
		  (unsigned)bzs->avail_in, (unsigned)bzs->avail_out,
		  (unsigned)n, zrc );

      if( iobuf_write( a, zfx->outbuf, n ) )
	{
	  log_debug("bzCompress: iobuf_write failed\n");
	  return G10ERR_WRITE_FILE;
	}
    }
  while( bzs->avail_in || (flush == BZ_FINISH && zrc != BZ_STREAM_END) );

  return 0;
}

static void
init_uncompress( compress_filter_context_t *zfx, bz_stream *bzs )
{
  int rc;

  if((rc=BZ2_bzDecompressInit(bzs,0,opt.bz2_decompress_lowmem))!=BZ_OK)
    log_fatal("bz2lib problem: %d\n",rc);

  zfx->inbufsize = 2048;
  zfx->inbuf = xmalloc( zfx->inbufsize );
  bzs->avail_in = 0;
}

static int
do_uncompress( compress_filter_context_t *zfx, bz_stream *bzs,
	       IOBUF a, size_t *ret_len )
{
  int zrc;
  int rc=0;
  size_t n;
  int nread, count;
  int refill = !bzs->avail_in;

  if( DBG_FILTER )
    log_debug("begin bzDecompress: avail_in=%u, avail_out=%u, inbuf=%u\n",
	      (unsigned)bzs->avail_in, (unsigned)bzs->avail_out,
	      (unsigned)zfx->inbufsize );
  do
    {
      if( bzs->avail_in < zfx->inbufsize && refill )
	{
	  n = bzs->avail_in;
	  if( !n )
	    bzs->next_in = zfx->inbuf;
	  count = zfx->inbufsize - n;
	  nread = iobuf_read( a, zfx->inbuf + n, count );
	  if( nread == -1 ) nread = 0;
	  n += nread;
	  bzs->avail_in = n;
	}

      refill = 1;

      if( DBG_FILTER )
	log_debug("enter bzDecompress: avail_in=%u, avail_out=%u\n",
		  (unsigned)bzs->avail_in, (unsigned)bzs->avail_out);

      zrc=BZ2_bzDecompress(bzs);
      if( DBG_FILTER )
	log_debug("leave bzDecompress: avail_in=%u, avail_out=%u, zrc=%d\n",
		  (unsigned)bzs->avail_in, (unsigned)bzs->avail_out, zrc);
      if( zrc == BZ_STREAM_END )
	rc = -1; /* eof */
      else if( zrc != BZ_OK && zrc != BZ_PARAM_ERROR )
	log_fatal("bz2lib inflate problem: rc=%d\n", zrc );
    }
  while( bzs->avail_out && zrc != BZ_STREAM_END && zrc != BZ_PARAM_ERROR );

  /* I'm not completely happy with the two uses of BZ_PARAM_ERROR
     here.  The corresponding zlib function is Z_BUF_ERROR, which
     covers a narrower scope than BZ_PARAM_ERROR. -dshaw */

  *ret_len = zfx->outbufsize - bzs->avail_out;
  if( DBG_FILTER )
    log_debug("do_uncompress: returning %u bytes\n", (unsigned)*ret_len );
  return rc;
}

int
compress_filter_bz2( void *opaque, int control,
		     IOBUF a, byte *buf, size_t *ret_len)
{
  size_t size = *ret_len;
  compress_filter_context_t *zfx = opaque;
  bz_stream *bzs = zfx->opaque;
  int rc=0;

  if( control == IOBUFCTRL_UNDERFLOW )
    {
      if( !zfx->status )
	{
	  bzs = zfx->opaque = xmalloc_clear( sizeof *bzs );
	  init_uncompress( zfx, bzs );
	  zfx->status = 1;
	}

      bzs->next_out = buf;
      bzs->avail_out = size;
      zfx->outbufsize = size; /* needed only for calculation */
      rc = do_uncompress( zfx, bzs, a, ret_len );
    }
  else if( control == IOBUFCTRL_FLUSH )
    {
      if( !zfx->status )
	{
	  PACKET pkt;
	  PKT_compressed cd;

	  if( zfx->algo != COMPRESS_ALGO_BZIP2 )
	    BUG();
	  memset( &cd, 0, sizeof cd );
	  cd.len = 0;
	  cd.algorithm = zfx->algo;
	  init_packet( &pkt );
	  pkt.pkttype = PKT_COMPRESSED;
	  pkt.pkt.compressed = &cd;
	  if( build_packet( a, &pkt ))
	    log_bug("build_packet(PKT_COMPRESSED) failed\n");
	  bzs = zfx->opaque = xmalloc_clear( sizeof *bzs );
	  init_compress( zfx, bzs );
	  zfx->status = 2;
	}

      bzs->next_in = buf;
      bzs->avail_in = size;
      rc = do_compress( zfx, bzs, BZ_RUN, a );
    }
  else if( control == IOBUFCTRL_FREE )
    {
      if( zfx->status == 1 )
	{
	  BZ2_bzDecompressEnd(bzs);
	  xfree(bzs);
	  zfx->opaque = NULL;
	  xfree(zfx->outbuf); zfx->outbuf = NULL;
	}
      else if( zfx->status == 2 )
	{
	  bzs->next_in = buf;
	  bzs->avail_in = 0;
	  do_compress( zfx, bzs, BZ_FINISH, a );
	  BZ2_bzCompressEnd(bzs);
	  xfree(bzs);
	  zfx->opaque = NULL;
	  xfree(zfx->outbuf); zfx->outbuf = NULL;
	}
      if (zfx->release)
	zfx->release (zfx);
    }
  else if( control == IOBUFCTRL_DESC )
    *(char**)buf = "compress_filter";
  return rc;
}
