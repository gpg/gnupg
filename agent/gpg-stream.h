/* stream.h - Stream I/O layer
   Copyright (C) 2004 g10 Code GmbH

   This file is part of libgpg-stream.
 
   libgpg-stream is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
 
   libgpg-stream is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with libgpg-stream; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef GPG_STREAM_H
#define GPG_STREAM_H

#include <sys/types.h>
#include <stdarg.h>

#include <gpg-error.h>



#define STREAM_BLOCK_SIZE 1024



typedef struct gpg_stream *gpg_stream_t;

typedef gpg_error_t (*gpg_stream_func_create_t) (void **handle,
						 void *spec,
						 unsigned int flags);
typedef gpg_error_t (*gpg_stream_func_read_t) (void *handle,
					       char *buffer,
					       size_t bytes_to_read,
					       size_t *bytes_read);
typedef gpg_error_t (*gpg_stream_func_write_t) (void *handle,
						const char *buffer,
						size_t bytes_to_write,
						size_t *bytes_written);
typedef gpg_error_t (*gpg_stream_func_seek_t) (void *handle,
					       off_t pos,
					       int whence);
typedef gpg_error_t (*gpg_stream_func_stat_t) (void *handle,
					       size_t *size);
typedef gpg_error_t (*gpg_stream_func_destroy_t) (void *handle);

typedef struct gpg_stream_functions
{
  gpg_stream_func_create_t func_create;
  gpg_stream_func_read_t func_read;
  gpg_stream_func_write_t func_write;
  gpg_stream_func_seek_t func_seek;
  gpg_stream_func_stat_t func_stat;
  gpg_stream_func_destroy_t func_destroy;
} gpg_stream_functions_t;

#define GPG_STREAM_FLAG_READ      (1 << 0)
#define GPG_STREAM_FLAG_WRITE     (1 << 1)
#define GPG_STREAM_FLAG_EXCLUSIVE (1 << 2)
#define GPG_STREAM_FLAG_APPEND    (1 << 3)
#define GPG_STREAM_FLAG_CREATE    (1 << 4)
#define GPG_STREAM_FLAG_NONBLOCK  (1 << 5)
#define GPG_STREAM_FLAG_TRUNCATE  (1 << 6)
#define GPG_STREAM_FLAG_BINARY    (1 << 7)

gpg_error_t gpg_stream_create (gpg_stream_t *stream,
			       void *spec,
			       unsigned int flags,
			       gpg_stream_functions_t functions);

gpg_error_t gpg_stream_create_file (gpg_stream_t *stream,
				    const char *filename,
				    unsigned int flags);

gpg_error_t gpg_stream_create_fd (gpg_stream_t *stream,
				  int fd,
				  unsigned int flags);

gpg_error_t gpg_stream_destroy (gpg_stream_t stream);

gpg_error_t gpg_stream_read (gpg_stream_t stream,
			     char *buffer,
			     size_t bytes_to_read,
			     size_t *bytes_read);

gpg_error_t gpg_stream_write (gpg_stream_t stream,
			      const char *buffer,
			      size_t bytes_to_write,
			      size_t *bytes_written);

gpg_error_t gpg_stream_read_line (gpg_stream_t stream,
				  char **line,
				  size_t *line_length);

gpg_error_t gpg_stream_print_va (gpg_stream_t stream,
				 const char *format,
				 va_list ap);

gpg_error_t gpg_stream_print (gpg_stream_t stream,
			      const char *format,
			      ...);

gpg_error_t gpg_stream_flush (gpg_stream_t stream);

gpg_error_t gpg_stream_peek (gpg_stream_t stream,
			     char **buffer,
			     size_t *size);

gpg_error_t gpg_stream_seek (gpg_stream_t stream,
			     off_t offset,
			     int whence);

gpg_error_t gpg_stream_stat (gpg_stream_t stream,
			     size_t *size);

gpg_error_t gpg_stream_copy (gpg_stream_t dst,
			     gpg_stream_t src);

typedef struct gpg_stream_spec_mem
{
  char *memory;
  size_t memory_size;
  unsigned int grow: 1;
} gpg_stream_spec_mem_t;

extern gpg_stream_functions_t gpg_stream_functions_mem;

typedef struct gpg_stream_spec_file
{
  const char *filename;
  mode_t mode;
} gpg_stream_spec_file_t;

extern gpg_stream_functions_t gpg_stream_functions_file;

typedef struct gpg_stream_spec_fd
{
  int fd;
} gpg_stream_spec_fd_t;

extern gpg_stream_functions_t gpg_stream_functions_fd;

#endif
