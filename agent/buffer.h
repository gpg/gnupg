/* buffer.h - Buffer management layer
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

#ifndef BUFFER_H
#define BUFFER_H

#include <sys/types.h>
#include <stdarg.h>

#include <gpg-error.h>



#define BUFFER_BLOCK_SIZE 1024



typedef struct buffer *buffer_t;

/* Callbacks, necessary for filling/flushing/seeking.  */
typedef gpg_error_t (*buffer_func_read_t) (void *handle,
					   char *buffer,
					   size_t bytes_to_read,
					   size_t *bytes_read);
typedef gpg_error_t (*buffer_func_write_t) (void *handle,
					    const char *buffer,
					    size_t bytes_to_write,
					    size_t *bytes_written);
typedef gpg_error_t (*buffer_func_seek_t) (void *handle,
					   off_t offset,
					   int whence);

typedef gpg_error_t (*buffer_func_stat_t) (void *handle,
					   size_t *size);

typedef struct buffer_functions
{
  buffer_func_read_t  func_read;  /* Read callback.   */
  buffer_func_write_t func_write; /* Write callback.  */
  buffer_func_seek_t  func_seek;  /* Seek callback.   */
  buffer_func_stat_t  func_stat;  /* Stat callback.   */
} buffer_functions_t;

/* Create a new buffer.  */
gpg_error_t buffer_create (buffer_t *buffer,
			   void *handle,
			   buffer_functions_t functions);

/* Destroy a buffer.  */
gpg_error_t buffer_destroy (buffer_t buffer);

/* Read from a buffer.  */
gpg_error_t buffer_read (buffer_t buffer,
			 char *data,
			 size_t bytes_to_read,
			 size_t *bytes_read);

/* Write to a buffer.  */
gpg_error_t buffer_write (buffer_t buffer,
			  const char *data,
			  size_t bytes_to_write,
			  size_t *bytes_written);

/* Seek in a buffer.  */
gpg_error_t buffer_seek (buffer_t buffer,
			 off_t offset,
			 int whence);

/* Return the unread data contained in a buffer.  */
gpg_error_t buffer_peek (buffer_t buffer,
			 char **data,
			 size_t *data_size);

/* Skip SIZE bytes of input data contained in buffer.  */
gpg_error_t buffer_skip (buffer_t buffer,
			 size_t size);

/* Write out unwritten data contained in buffer.  */
gpg_error_t buffer_flush (buffer_t buffer);

/* Stat buffer.  */
gpg_error_t buffer_stat (buffer_t buffer,
			 size_t *size);

#endif
