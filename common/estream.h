/* estream.h - Extended stream I/O Library
 * Copyright (C) 2004, 2005, 2006, 2007, 2010 g10 Code GmbH
 *
 * This file is part of Libestream.
 *
 * Libestream is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Libestream is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Libestream; if not, see <http://www.gnu.org/licenses/>.
 *
 * ALTERNATIVELY, Libestream may be distributed under the terms of the
 * following license, in which case the provisions of this license are
 * required INSTEAD OF the GNU General Public License. If you wish to
 * allow use of your version of this file only under the terms of the
 * GNU General Public License, and not to allow others to use your
 * version of this file under the terms of the following license,
 * indicate your decision by deleting this paragraph and the license
 * below.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ESTREAM_H
#define ESTREAM_H

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

/* To use this file with libraries the following macro is useful:

     #define _ESTREAM_EXT_SYM_PREFIX _foo_

       This prefixes all external symbols with "_foo_".

 */


#ifdef _ESTREAM_EXT_SYM_PREFIX
#ifndef _ESTREAM_PREFIX
#define _ESTREAM_PREFIX1(x,y)  x ## y
#define _ESTREAM_PREFIX2(x,y) _ESTREAM_PREFIX1(x,y)
#define _ESTREAM_PREFIX(x)    _ESTREAM_PREFIX2(_ESTREAM_EXT_SYM_PREFIX,x)
#endif /*_ESTREAM_PREFIX*/
#define es_fopen              _ESTREAM_PREFIX(es_fopen)
#define es_mopen              _ESTREAM_PREFIX(es_mopen)
#define es_fopenmem           _ESTREAM_PREFIX(es_fopenmem)
#define es_fdopen             _ESTREAM_PREFIX(es_fdopen)
#define es_fdopen_nc          _ESTREAM_PREFIX(es_fdopen_nc)
#define es_fpopen             _ESTREAM_PREFIX(es_fpopen)
#define es_fpopen_nc          _ESTREAM_PREFIX(es_fpopen_nc)
#define _es_set_std_fd        _ESTREAM_PREFIX(_es_set_std_fd)
#define _es_get_std_stream    _ESTREAM_PREFIX(_es_get_std_stream)
#define es_freopen            _ESTREAM_PREFIX(es_freopen)
#define es_fopencookie        _ESTREAM_PREFIX(es_fopencookie)
#define es_fclose             _ESTREAM_PREFIX(es_fclose)
#define es_fileno             _ESTREAM_PREFIX(es_fileno)
#define es_fileno_unlocked    _ESTREAM_PREFIX(es_fileno_unlocked)
#define es_flockfile          _ESTREAM_PREFIX(es_flockfile)
#define es_ftrylockfile       _ESTREAM_PREFIX(es_ftrylockfile)
#define es_funlockfile        _ESTREAM_PREFIX(es_funlockfile)
#define es_feof               _ESTREAM_PREFIX(es_feof)
#define es_feof_unlocked      _ESTREAM_PREFIX(es_feof_unlocked)
#define es_ferror             _ESTREAM_PREFIX(es_ferror)
#define es_ferror_unlocked    _ESTREAM_PREFIX(es_ferror_unlocked)
#define es_clearerr           _ESTREAM_PREFIX(es_clearerr)
#define es_clearerr_unlocked  _ESTREAM_PREFIX(es_clearerr_unlocked)
#define es_fflush             _ESTREAM_PREFIX(es_fflush)
#define es_fseek              _ESTREAM_PREFIX(es_fseek)
#define es_fseeko             _ESTREAM_PREFIX(es_fseeko)
#define es_ftell              _ESTREAM_PREFIX(es_ftell)
#define es_ftello             _ESTREAM_PREFIX(es_ftello)
#define es_rewind             _ESTREAM_PREFIX(es_rewind)
#define es_fgetc              _ESTREAM_PREFIX(es_fgetc)
#define es_fputc              _ESTREAM_PREFIX(es_fputc)
#define _es_getc_underflow    _ESTREAM_PREFIX(_es_getc_underflow)
#define _es_putc_overflow     _ESTREAM_PREFIX(_es_putc_overflow)
#define es_ungetc             _ESTREAM_PREFIX(es_ungetc)
#define es_read               _ESTREAM_PREFIX(es_read)
#define es_write              _ESTREAM_PREFIX(es_write)
#define es_write_sanitized    _ESTREAM_PREFIX(es_write_sanitized)
#define es_write_hexstring    _ESTREAM_PREFIX(es_write_hexstring)
#define es_fread              _ESTREAM_PREFIX(es_fread)
#define es_fwrite             _ESTREAM_PREFIX(es_fwrite)
#define es_fgets              _ESTREAM_PREFIX(es_fgets)
#define es_fputs              _ESTREAM_PREFIX(es_fputs)
#define es_fputs_unlocked     _ESTREAM_PREFIX(es_fputs_unlocked)
#define es_getline            _ESTREAM_PREFIX(es_getline)
#define es_read_line          _ESTREAM_PREFIX(es_read_line)
#define es_free               _ESTREAM_PREFIX(es_free)
#define es_fprintf            _ESTREAM_PREFIX(es_fprintf)
#define es_fprintf_unlocked   _ESTREAM_PREFIX(es_fprintf_unlocked)
#define es_vfprintf           _ESTREAM_PREFIX(es_vfprint)
#define es_vfprintf_unlocked  _ESTREAM_PREFIX(es_vfprint_unlocked)
#define es_setvbuf            _ESTREAM_PREFIX(es_setvbuf)
#define es_setbuf             _ESTREAM_PREFIX(es_setbuf)
#define es_tmpfile            _ESTREAM_PREFIX(es_tmpfile)
#define es_opaque_set         _ESTREAM_PREFIX(es_opaque_set)
#define es_opaque_get         _ESTREAM_PREFIX(es_opaque_get)
#define es_fname_set          _ESTREAM_PREFIX(es_fname_set)
#define es_fname_get          _ESTREAM_PREFIX(es_fname_get)
#define es_write_sanitized_utf8_buffer  \
              _ESTREAM_PREFIX(es_write_sanitized_utf8_buffer)
#endif /*_ESTREAM_EXT_SYM_PREFIX*/


#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif


/* Forward declaration for the (opaque) internal type.  */
struct estream_internal;

/* The definition of this struct is entirely private.  You must not
   use it for anything.  It is only here so some functions can be
   implemented as macros.  */
struct es__stream
{
  /* The layout of this struct must never change.  It may be grown,
     but only if all functions which access the new members are
     versioned.  */

  /* A pointer to the stream buffer.  */
  unsigned char *buffer;

  /* The size of the buffer in bytes.  */
  size_t buffer_size;

  /* The length of the usable data in the buffer, only valid when in
     read mode (see flags).  */
  size_t data_len;

  /* The current position of the offset pointer, valid in read and
     write mode.  */
  size_t data_offset;

  size_t data_flushed;
  unsigned char *unread_buffer;
  size_t unread_buffer_size;

  /* The number of unread bytes.  */
  size_t unread_data_len;

  /* Various flags.  */
  struct {
    unsigned int writing: 1;
    unsigned int reserved: 7;
  } flags;

  /* A pointer to our internal data for this stream.  */
  struct estream_internal *intern;
};

/* The opaque type for an estream.  */
typedef struct es__stream *estream_t;


typedef ssize_t (*es_cookie_read_function_t) (void *cookie,
					      void *buffer, size_t size);
typedef ssize_t (*es_cookie_write_function_t) (void *cookie,
					       const void *buffer,
					       size_t size);
typedef int (*es_cookie_seek_function_t) (void *cookie,
					  off_t *pos, int whence);
typedef int (*es_cookie_close_function_t) (void *cookie);

typedef struct es_cookie_io_functions
{
  es_cookie_read_function_t func_read;
  es_cookie_write_function_t func_write;
  es_cookie_seek_function_t func_seek;
  es_cookie_close_function_t func_close;
} es_cookie_io_functions_t;


#ifndef _ESTREAM_GCC_A_PRINTF
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define _ESTREAM_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
#else
# define _ESTREAM_GCC_A_PRINTF( f, a )
#endif
#endif /*_ESTREAM_GCC_A_PRINTF*/


#ifndef ES__RESTRICT
#  if defined __GNUC__ && defined __GNUC_MINOR__
#    if  (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 92))
#      define ES__RESTRICT __restrict__
#    endif
#  endif
#endif
#ifndef ES__RESTRICT
#  define ES__RESTRICT
#endif

int es_init (void);

int es_pth_kill (void);

estream_t es_fopen (const char *ES__RESTRICT path,
		    const char *ES__RESTRICT mode);
estream_t es_mopen (unsigned char *ES__RESTRICT data,
		    size_t data_n, size_t data_len,
		    unsigned int grow,
		    void *(*func_realloc) (void *mem, size_t size),
		    void (*func_free) (void *mem),
		    const char *ES__RESTRICT mode);
estream_t es_fopenmem (size_t memlimit, const char *ES__RESTRICT mode);
estream_t es_fdopen (int filedes, const char *mode);
estream_t es_fdopen_nc (int filedes, const char *mode);
estream_t es_fpopen (FILE *fp, const char *mode);
estream_t es_fpopen_nc (FILE *fp, const char *mode);
estream_t es_freopen (const char *ES__RESTRICT path,
		      const char *ES__RESTRICT mode,
		      estream_t ES__RESTRICT stream);
estream_t es_fopencookie (void *ES__RESTRICT cookie,
			  const char *ES__RESTRICT mode,
			  es_cookie_io_functions_t functions);
int es_fclose (estream_t stream);
int es_fileno (estream_t stream);
int es_fileno_unlocked (estream_t stream);

void _es_set_std_fd (int no, int fd);
estream_t _es_get_std_stream (int fd);

#define es_stdin  _es_get_std_stream (0)
#define es_stdout _es_get_std_stream (1)
#define es_stderr _es_get_std_stream (2)


void es_flockfile (estream_t stream);
int es_ftrylockfile (estream_t stream);
void es_funlockfile (estream_t stream);

int es_feof (estream_t stream);
int es_feof_unlocked (estream_t stream);
int es_ferror (estream_t stream);
int es_ferror_unlocked (estream_t stream);
void es_clearerr (estream_t stream);
void es_clearerr_unlocked (estream_t stream);

int es_fflush (estream_t stream);
int es_fseek (estream_t stream, long int offset, int whence);
int es_fseeko (estream_t stream, off_t offset, int whence);
long int es_ftell (estream_t stream);
off_t es_ftello (estream_t stream);
void es_rewind (estream_t stream);

int es_fgetc (estream_t stream);
int es_fputc (int c, estream_t stream);

int _es_getc_underflow (estream_t stream);
int _es_putc_overflow (int c, estream_t stream);

#define es_getc_unlocked(stream)				\
  (((!(stream)->flags.writing)					\
    && ((stream)->data_offset < (stream)->data_len)		\
    && (! (stream)->unread_data_len))				\
  ? ((int) (stream)->buffer[((stream)->data_offset)++])		\
  : _es_getc_underflow ((stream)))

#define es_putc_unlocked(c, stream)				\
  (((stream)->flags.writing					\
    && ((stream)->data_offset < (stream)->buffer_size)		\
    && (c != '\n'))						\
  ? ((int) ((stream)->buffer[((stream)->data_offset)++] = (c)))	\
  : _es_putc_overflow ((c), (stream)))

#define es_getc(stream)    es_fgetc (stream)
#define es_putc(c, stream) es_fputc (c, stream)

int es_ungetc (int c, estream_t stream);

int es_read (estream_t ES__RESTRICT stream,
	     void *ES__RESTRICT buffer, size_t bytes_to_read,
	     size_t *ES__RESTRICT bytes_read);
int es_write (estream_t ES__RESTRICT stream,
	      const void *ES__RESTRICT buffer, size_t bytes_to_write,
	      size_t *ES__RESTRICT bytes_written);
int es_write_sanitized (estream_t ES__RESTRICT stream,
                        const void *ES__RESTRICT buffer, size_t length,
                        const char *delimiters,
                        size_t *ES__RESTRICT bytes_written);
int es_write_hexstring (estream_t ES__RESTRICT stream,
                        const void *ES__RESTRICT buffer, size_t length,
                        int reserved, size_t *ES__RESTRICT bytes_written);

size_t es_fread (void *ES__RESTRICT ptr, size_t size, size_t nitems,
		 estream_t ES__RESTRICT stream);
size_t es_fwrite (const void *ES__RESTRICT ptr, size_t size, size_t memb,
		  estream_t ES__RESTRICT stream);

char *es_fgets (char *ES__RESTRICT s, int n, estream_t ES__RESTRICT stream);
int es_fputs (const char *ES__RESTRICT s, estream_t ES__RESTRICT stream);
int es_fputs_unlocked (const char *ES__RESTRICT s,
                       estream_t ES__RESTRICT stream);

ssize_t es_getline (char *ES__RESTRICT *ES__RESTRICT lineptr,
		    size_t *ES__RESTRICT n,
		    estream_t stream);
ssize_t es_read_line (estream_t stream,
                      char **addr_of_buffer, size_t *length_of_buffer,
                      size_t *max_length);
void es_free (void *a);

int es_fprintf (estream_t ES__RESTRICT stream,
		const char *ES__RESTRICT format, ...)
     _ESTREAM_GCC_A_PRINTF(2,3);
int es_fprintf_unlocked (estream_t ES__RESTRICT stream,
                         const char *ES__RESTRICT format, ...)
     _ESTREAM_GCC_A_PRINTF(2,3);

int es_vfprintf (estream_t ES__RESTRICT stream,
		 const char *ES__RESTRICT format, va_list ap)
     _ESTREAM_GCC_A_PRINTF(2,0);
int es_vfprintf_unlocked (estream_t ES__RESTRICT stream,
                          const char *ES__RESTRICT format, va_list ap)
     _ESTREAM_GCC_A_PRINTF(2,0);

int es_setvbuf (estream_t ES__RESTRICT stream,
		char *ES__RESTRICT buf, int mode, size_t size);
void es_setbuf (estream_t ES__RESTRICT stream, char *ES__RESTRICT buf);

estream_t es_tmpfile (void);

void es_opaque_set (estream_t ES__RESTRICT stream, void *ES__RESTRICT opaque);
void *es_opaque_get (estream_t stream);

void es_fname_set (estream_t stream, const char *fname);
const char *es_fname_get (estream_t stream);


#ifdef GNUPG_MAJOR_VERSION
int es_write_sanitized_utf8_buffer (estream_t stream,
                                    const void *buffer, size_t length,
                                    const char *delimiters,
                                    size_t *bytes_written);
#endif /*GNUPG_MAJOR_VERSION*/

#ifdef __cplusplus
}
#endif
#endif /*ESTREAM_H*/
