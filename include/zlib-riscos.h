/* zlib-riscos.h
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef G10_ZLIB_RISCOS_H
#define G10_ZLIB_RISCOS_H

#include <kernel.h>
#include <swis.h>

static const char * const zlib_path[] = {
    "System:310.Modules.ZLib",
    NULL
};

#define ZLib_Compress             0x53AC0
#define ZLib_Decompress           0x53AC1
#define ZLib_CRC32                0x53AC2
#define ZLib_Adler32              0x53AC3
#define ZLib_Version              0x53AC4
#define ZLib_ZCompress            0x53AC5
#define ZLib_ZCompress2           0x53AC6
#define ZLib_ZUncompress          0x53AC7
#define ZLib_DeflateInit          0x53AC8
#define ZLib_InflateInit          0x53AC9
#define ZLib_DeflateInit2         0x53ACA
#define ZLib_InflateInit2         0x53ACB
#define ZLib_Deflate              0x53ACC
#define ZLib_DeflateEnd           0x53ACD
#define ZLib_Inflate              0x53ACE
#define ZLib_InflateEnd           0x53ACF
#define ZLib_DeflateSetDictionary 0x53AD0
#define ZLib_DeflateCopy          0x53AD1
#define ZLib_DeflateReset         0x53AD2
#define ZLib_DeflateParams        0x53AD3
#define ZLib_InflateSetDictionary 0x53AD4
#define ZLib_InflateSync          0x53AD5
#define ZLib_InflateReset         0x53AD6
#define ZLib_GZOpen               0x53AD7
#define ZLib_GZRead               0x53AD8
#define ZLib_GRWrite              0x53AD9
#define ZLib_GZFlush              0x53ADA
#define ZLib_GZClose              0x53ADB
#define ZLib_GZError              0x53ADC
#define ZLib_GZSeek               0x53ADD
#define ZLib_GZTell               0x53ADE
#define ZLib_GZEOF                0x53ADF
#define ZLib_TaskAssociate        0x53AE0

#define crc32(r0,r1,r2) \
    _swi(ZLib_CRC32, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define adler32(r0,r1,r2) \
    _swi(ZLib_Adler32, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define zlibVersion() \
    _swi(ZLib_Version, _RETURN(0))
#define compress(r0,r1,r2,r3) \
    _swi(ZLib_ZCompress, _INR(0,3) | _RETURN(0)|_OUT(1), r0,r1,r2,r3, &r1)
#define compress2(r0,r1,r2,r3,r4) \
    _swi(ZLib_ZCompress2, _INR(0,4) | _RETURN(0)|_OUT(1), r0,r1,r2,r3,r4, &r1)
#define uncompress(r0,r1,r2,r3) \
    _swi(ZLib_ZUncompress, _INR(0,3) | _RETURN(0)|_OUT(1), r0,r1,r2,r3, &r1)
#define deflateInit_(r0,r1,r2,r3) \
    _swi(ZLib_DeflateInit, _INR(0,3) | _RETURN(0), r0,r1,r2,r3)
#define inflateInit_(r0,r1,r2) \
    _swi(ZLib_InflateInit, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define deflateInit2_(r0,r1,r2,r3,r4,r5,r6,r7) \
    _swi(ZLib_DeflateInit2, _INR(0,7) | _RETURN(0), r0,r1,r2,r3,r4,r5,r6,r7)
#define inflateInit2_(r0,r1,r2,r3) \
    _swi(ZLib_InflateInit2, _INR(0,3) | _RETURN(0), r0,r1,r2,r3)
#define deflate(r0,r1) \
    _swi(ZLib_Deflate, _INR(0,1) | _RETURN(0), r0,r1)
#define deflateEnd(r0) \
    _swi(ZLib_DeflateEnd, _IN(0) | _RETURN(0), r0)
#define inflate(r0,r1) \
    _swi(ZLib_Inflate, _INR(0,1) | _RETURN(0), r0,r1)
#define inflateEnd(r0) \
    _swi(ZLib_InflateEnd, _IN(0) | _RETURN(0), r0)
#define deflateSetDictionary(r0,r1,r2) \
    _swi(ZLib_DeflateSetDictionary, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define deflateCopy(r0,r1) \
    _swi(ZLib_DeflateCopy, _INR(0,1) | _RETURN(0), r0,r1)
#define deflateReset(r0) \
    _swi(ZLib_DeflateReset, _IN(0) | _RETURN(0), r0)
#define deflateParams(r0,r1,r2) \
    _swi(ZLib_DeflateParams, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define inflateSetDictionary(r0,r1,r2) \
    _swi(ZLib_InflateSetDictionary, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define inflateSync(r0) \
    _swi(ZLib_InflateSync, _IN(0) | _RETURN(0), r0)
#define inflateReset(r0) \
    _swi(ZLib_InflateReset, _IN(0) | _RETURN(0), r0)
#define gzopen(r0,r1) \
    _swi(ZLib_GZOpen, _INR(0,1) | _RETURN(0), r0)
#define gzdopen(r0,r1) BUG()
#define gzsetparams(r0,r1,r2) BUG()
#define gzread(r0,r1,r2) \
    _swi(ZLib_GZRead, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define gzwrite(r0,r1,r2) \
    _swi(ZLib_GZWrite, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define gzprintf(r0,r1,...) BUG()
#define gzputs(r0,r1) BUG()
#define gzgets(r0,r1,r2) BUG()
#define gzputc(r0,r1) BUG()
#define gzgetc(r0) BUG()
#define gzflush(r0,r1) \
    _swi(ZLib_GZFlush, _INR(0,1) | _RETURN(0), r0,r1)
#define gzclose(r0) \
    _swi(ZLib_GZClose, _IN(0) | _RETURN(0), r0)
#define gzerror(r0,r1) \
    _swi(ZLib_GZError, _IN(0) | _RETURN(0)|_OUT(1), r0, &r1)
#define gzseek(r0,r1,r2) \
    _swi(ZLib_GZSeek, _INR(0,2) | _RETURN(0), r0,r1,r2)
#define gzrewind(r0) BUG()
#define gztell(r0) \
    _swi(ZLib_GZTell, _IN(0) | _RETURN(0), r0)
#define gzeof(r0) \
    _swi(ZLib_GZEOF, _IN(0) | _RETURN(0), r0)

#endif /* G10_ZLIB_RISCOS_H */
