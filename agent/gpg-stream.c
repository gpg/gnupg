/* stream.c - Stream I/O/ layer
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

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#include <gpg-error.h>

#include "gpg-stream.h"
#include "gpg-stream-config.h"
#include "buffer.h"



/* A Stream Context.  */
struct gpg_stream
{
  void *handle;			    /* Handle.               */
  unsigned int flags;		    /* Flags.                */
  buffer_t buffer;		    /* Buffer used for I/O.  */
  gpg_stream_functions_t functions; /* Callbacks.            */
};



/* Macros.  */

/* Standard permissions used for creating new files.  */
#define GPG_STREAM_FILE_PERMISSIONS 0600

/* Evaluate EXPRESSION, setting VARIABLE to the return code, if
   VARIABLE is zero.  */
#define SET_UNLESS_NONZERO(variable, tmp_variable, expression) \
  do                                                           \
    {                                                          \
      tmp_variable = expression;                               \
      if ((! variable) && tmp_variable)                        \
        variable = tmp_variable;                               \
    }                                                          \
  while (0)

/* Implementation of Memory I/O.  */

typedef struct gpg_stream_handle_mem
{
  char *memory;			/* Data.                       */
  size_t memory_size;		/* Size of MEMORY.             */
  size_t data_size;		/* Size of data in MEMORY.     */
  unsigned int grow: 1;		/* MEMORY is allowed to grow.  */
  size_t offset;		/* Current offset in MEMORY.   */
} *gpg_stream_handle_mem_t;

static gpg_error_t
gpg_stream_func_mem_create (void **handle,
			    void *spec,
			    unsigned int flags)
{
  gpg_stream_handle_mem_t mem_handle = NULL;
  gpg_stream_spec_mem_t *mem_spec = spec;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  mem_handle = malloc (sizeof (*mem_handle));
  if (! mem_handle)
    err = gpg_error_from_errno (errno);
  else
    {
      mem_handle->memory = mem_spec ? mem_spec->memory : 0;
      mem_handle->memory_size = mem_spec ? mem_spec->memory_size : 0;
      mem_handle->data_size = 0;
      mem_handle->grow = mem_spec ? mem_spec->grow : 1;
      mem_handle->offset = 0;
      *handle = mem_handle;
    }

  return err;
}

static gpg_error_t
gpg_stream_func_mem_read (void *handle,
			  char *buffer,
			  size_t bytes_to_read,
			  size_t *bytes_read)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (bytes_to_read > mem_handle->data_size - mem_handle->offset)
    bytes_to_read = mem_handle->data_size - mem_handle->offset;

  memcpy (buffer, mem_handle->memory + mem_handle->offset,
	  bytes_to_read);
  mem_handle->offset += bytes_to_read;
  *bytes_read = bytes_to_read;

  return err;
}

static gpg_error_t
gpg_stream_func_mem_write (void *handle,
			   const char *buffer,
			   size_t bytes_to_write,
			   size_t *bytes_written)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  char *memory_new = NULL;

  if (! mem_handle->grow)
    if (bytes_to_write > mem_handle->memory_size - mem_handle->offset)
      bytes_to_write = mem_handle->memory_size - mem_handle->offset;

  while (bytes_to_write > mem_handle->memory_size - mem_handle->offset)
    {
      memory_new = realloc (mem_handle->memory,
			    mem_handle->memory_size + BUFFER_BLOCK_SIZE);
      if (! memory_new)
	err = gpg_error_from_errno (errno);
      else
	{
	  if (mem_handle->memory != memory_new)
	    mem_handle->memory = memory_new;
	  mem_handle->memory_size += BUFFER_BLOCK_SIZE;
	}
    }

  if (! err)
    {
      memcpy (mem_handle->memory + mem_handle->offset, buffer,
	      bytes_to_write);
      if (mem_handle->offset + bytes_to_write > mem_handle->data_size)
	mem_handle->data_size = mem_handle->offset + bytes_to_write;
      mem_handle->offset += bytes_to_write;
    }
  *bytes_written = bytes_to_write;

  return err;
}

gpg_error_t
gpg_stream_func_mem_seek (void *handle,
			  off_t offset,
			  int whence)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  switch (whence)
    {
    case SEEK_SET:
      if ((offset < 0) || (offset > mem_handle->data_size))
	err = gpg_error (GPG_ERR_INV_ARG);
      else
	mem_handle->offset = offset;
      break;

    case SEEK_CUR:
      if ((mem_handle->offset + offset < 0)
	  || (mem_handle->offset + offset > mem_handle->data_size))
	err = gpg_error (GPG_ERR_INV_ARG);
      else
	mem_handle->offset += offset;
      break;

    case SEEK_END:
      if ((mem_handle->data_size + offset < 0)
	  || (mem_handle->data_size + offset > mem_handle->data_size))
	err = gpg_error (GPG_ERR_INV_ARG);
      else
	mem_handle->offset += offset;
    }

  return err;
}

static gpg_error_t
gpg_stream_func_mem_stat (void *handle,
			  size_t *size)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  *size = mem_handle->data_size;

  return err;
}

static gpg_error_t
gpg_stream_func_mem_destroy (void *handle)
{
  gpg_stream_handle_mem_t mem_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (mem_handle->memory)
    free (mem_handle->memory);
  free (mem_handle);

  return err;
}

gpg_stream_functions_t gpg_stream_functions_mem =
  {
    gpg_stream_func_mem_create,
    gpg_stream_func_mem_read,
    gpg_stream_func_mem_write,
    gpg_stream_func_mem_seek,
    gpg_stream_func_mem_stat,
    gpg_stream_func_mem_destroy
  };

/* Implementation of FD I/O.  */

typedef struct gpg_stream_handle_fd
{
  int fd;
} *gpg_stream_handle_fd_t;

static gpg_error_t
gpg_stream_func_fd_create (void **handle,
			   void *spec,
			   unsigned int flags)
{
  gpg_stream_handle_fd_t fd_handle = NULL;
  gpg_stream_spec_fd_t *fd_spec = spec;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  fd_handle = malloc (sizeof (*fd_handle));
  if (! fd_handle)
    err = gpg_error_from_errno (errno);
  else
    {
      fd_handle->fd = fd_spec->fd;
      *handle = fd_handle;
    }
  
  return err;
}

static gpg_error_t
gpg_stream_func_fd_read (void *handle,
			 char *buffer,
			 size_t bytes_to_read,
			 size_t *bytes_read)

{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  ssize_t ret = -1;

  ret = READ (file_handle->fd, buffer, bytes_to_read);
  if (ret == -1)
    err = gpg_error_from_errno (errno);
  else
    *bytes_read = ret;

  return err;
}

static gpg_error_t
gpg_stream_func_fd_write (void *handle,
			  const char *buffer,
			  size_t bytes_to_write,
			  size_t *bytes_written)
			   
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  ssize_t ret = -1;

  ret = WRITE (file_handle->fd, buffer, bytes_to_write);
  if (ret == -1)
    err = gpg_error_from_errno (errno);
  else
    *bytes_written = ret;

  return err;
}

static gpg_error_t
gpg_stream_func_fd_seek (void *handle,
			 off_t pos,
			 int whence)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  off_t ret = -1;

  ret = lseek (file_handle->fd, pos, whence);
  if (ret == -1)
    err = gpg_error_from_errno (errno);

  return err;
}

static gpg_error_t
gpg_stream_func_fd_stat (void *handle,
			 size_t *size)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  struct stat statbuf;
  int ret = 0;

  ret = fstat (file_handle->fd, &statbuf);
  if (ret == -1)
    err = gpg_error_from_errno (errno);
  else
    *size = statbuf.st_size;

  return err;
}

static gpg_error_t
gpg_stream_func_fd_destroy (void *handle)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;

  free (file_handle);

  return err;
}

gpg_stream_functions_t gpg_stream_functions_fd =
  {
    gpg_stream_func_fd_create,
    gpg_stream_func_fd_read,
    gpg_stream_func_fd_write,
    gpg_stream_func_fd_seek,
    gpg_stream_func_fd_stat,
    gpg_stream_func_fd_destroy
  };


/* Implementation of File I/O.  */

static gpg_error_t
gpg_stream_func_file_create (void **handle,
			     void *spec,
			     unsigned int flags)
{
  gpg_stream_handle_fd_t file_handle = NULL;
  gpg_stream_spec_file_t *file_spec = spec;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int open_flags = 0;
  int fd = -1;

  file_handle = malloc (sizeof (*file_handle));
  if (! file_handle)
    err = gpg_error_from_errno (errno);

  if (! err)
    {
      struct flag_mapping
      {
	unsigned int gpg_stream;
	unsigned int sys;
      } flag_mappings[] = { { GPG_STREAM_FLAG_READ,
			      O_RDONLY },
			    { GPG_STREAM_FLAG_WRITE,
			      O_WRONLY },
			    { GPG_STREAM_FLAG_EXCLUSIVE,
			      O_EXCL },
			    { GPG_STREAM_FLAG_APPEND,
			      O_APPEND },
			    { GPG_STREAM_FLAG_CREATE,
			      O_CREAT },
			    { GPG_STREAM_FLAG_NONBLOCK,
			      O_NONBLOCK },
			    { GPG_STREAM_FLAG_TRUNCATE,
			      O_TRUNC } };
      unsigned int i = 0;

      for (i = 0; i < (sizeof (flag_mappings) / sizeof (*flag_mappings)); i++)
	if (flags & flag_mappings[i].gpg_stream)
	  open_flags |= flag_mappings[i].sys;

      fd = open (file_spec->filename, open_flags, file_spec->mode);
      if (fd == -1)
	err = gpg_error_from_errno (errno);
    }

  if (! err)
    {
      file_handle->fd = fd;
      *handle = file_handle;
    }
  else
    {
      if (file_handle)
	free (file_handle);
      if (fd != -1)
	close (fd);
    }

  return err;
}

static gpg_error_t
gpg_stream_func_file_destroy (void *handle)
{
  gpg_stream_handle_fd_t file_handle = handle;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int ret = 0;

  if (file_handle)
    {
      ret = close (file_handle->fd);
      if (ret == -1)
	err = gpg_error_from_errno (errno);
      free (file_handle);
    }

  return err;
}

gpg_stream_functions_t gpg_stream_functions_file =
  {
    gpg_stream_func_file_create,
    gpg_stream_func_fd_read,
    gpg_stream_func_fd_write,
    gpg_stream_func_fd_seek,
    gpg_stream_func_fd_stat,
    gpg_stream_func_file_destroy
  };



static gpg_error_t
gpg_stream_create_do (gpg_stream_t *stream,
		      void *spec,
		      unsigned int flags,
		      gpg_stream_functions_t functions)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (1
	 && (0
	     || ((flags & GPG_STREAM_FLAG_READ) && functions.func_read)
	     || ((flags & GPG_STREAM_FLAG_WRITE) && functions.func_write))))
    err = gpg_error (GPG_ERR_INV_ARG);
  else
    {
      buffer_functions_t buffer_fncs = { functions.func_read,
					 functions.func_write,
					 functions.func_seek,
					 functions.func_stat };
      gpg_stream_t stream_new = NULL;
      buffer_t buffer = NULL;
      void *handle = NULL;
  
      stream_new = malloc (sizeof (*stream_new));
      if (! stream_new)
	err = gpg_error_from_errno (errno);

      if (! err)
	if (functions.func_create)
	  err = (*functions.func_create) (&handle, spec, flags);
      
      if (! err)
	err = buffer_create (&buffer, handle, buffer_fncs);

      if (! err)
	{
	  stream_new->handle = handle;
	  stream_new->flags = flags;
	  stream_new->buffer = buffer;
	  stream_new->functions = functions;
	  *stream = stream_new;
	}
      else
	{
	  if (functions.func_destroy)
	    (*functions.func_destroy) (handle);
	  if (buffer)
	    buffer_destroy (buffer);
	}
    }

  return err;
}

gpg_error_t
gpg_stream_create (gpg_stream_t *stream,
		   void *spec,
		   unsigned int flags,
		   gpg_stream_functions_t functions)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_create_do (stream, spec, flags, functions);

  return err;
}

gpg_error_t
gpg_stream_create_file (gpg_stream_t *stream,
			const char *filename,
			unsigned int flags)
{
  gpg_stream_spec_file_t spec = { filename, GPG_STREAM_FILE_PERMISSIONS };
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_create_do (stream, &spec, flags, gpg_stream_functions_file);

  return err;
}

gpg_error_t
gpg_stream_create_fd (gpg_stream_t *stream,
		      int fd,
		      unsigned int flags)
{
  gpg_stream_spec_fd_t spec = { fd };
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_create_do (stream, &spec, flags, gpg_stream_functions_fd);

  return err;
}


gpg_error_t
gpg_stream_destroy (gpg_stream_t stream)
{
  gpg_error_t err = GPG_ERR_NO_ERROR, tmp_err = GPG_ERR_NO_ERROR;

  if (stream)
    {
      SET_UNLESS_NONZERO (err, tmp_err, buffer_destroy (stream->buffer));
      if (stream->functions.func_destroy)
	SET_UNLESS_NONZERO (err, tmp_err, \
			    (*stream->functions.func_destroy) (stream->handle));
      free (stream);
    }

  return err;
}

static gpg_error_t
gpg_stream_read_do (gpg_stream_t stream,
		    char *buffer,
		    size_t bytes_to_read,
		    size_t *bytes_read)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (stream->flags & GPG_STREAM_FLAG_READ))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    err = buffer_read (stream->buffer,
		       buffer, bytes_to_read, bytes_read);

  return err;
}

gpg_error_t
gpg_stream_read (gpg_stream_t stream,
		 char *buffer,
		 size_t bytes_to_read,
		 size_t *bytes_read)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_read_do (stream, buffer, bytes_to_read, bytes_read);

  return err;
}

static gpg_error_t
gpg_stream_write_do (gpg_stream_t stream,
		     const char *buffer,
		     size_t bytes_to_write,
		     size_t *bytes_written)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (stream->flags & GPG_STREAM_FLAG_WRITE))
    err = GPG_ERR_NOT_SUPPORTED;
  else
    err = buffer_write (stream->buffer,
			buffer, bytes_to_write, bytes_written);

  return err;
}

gpg_error_t
gpg_stream_write (gpg_stream_t stream,
		  const char *buffer,
		  size_t bytes_to_write,
		  size_t *bytes_written)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_write_do (stream, buffer, bytes_to_write, bytes_written);

  return err;
}

static gpg_error_t
gpg_stream_read_line_do (gpg_stream_t stream,
			 char **line,
			 size_t *line_length)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  if (! (stream->flags & GPG_STREAM_FLAG_READ))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    {
      buffer_functions_t buffer_fncs_mem = { gpg_stream_func_mem_read,
					     gpg_stream_func_mem_write,
					     gpg_stream_func_mem_seek };
      void *handle = NULL;
      char *line_new = NULL;
      buffer_t line_buffer = NULL;
      char *newline = NULL;
      size_t data_size = 0;
      char *data = NULL;
      size_t line_size = 0;

      err = gpg_stream_func_mem_create (&handle, NULL, 0);
      if (! err)
	err = buffer_create (&line_buffer, handle, buffer_fncs_mem);
      if (! err)
	do
	  {
	    err = buffer_peek (stream->buffer, &data, &data_size);
	    if (! err)
	      {
		size_t bytes_written = 0;

		newline = memchr (data, '\n', data_size);
		if (newline)
		  {
		    /* Write until newline.  */
		    line_size += newline - data + 1;
		    err = buffer_write (line_buffer, data, newline - data + 1,
					&bytes_written);
		    if (! err)
		      err = buffer_skip (stream->buffer, bytes_written);
		    break;
		  }
		else
		  {
		    /* Write whole block.  */
		    line_size += data_size;
		    err = buffer_write (line_buffer, data, data_size,
					&bytes_written);
		    if (! err)
		      err = buffer_skip (stream->buffer, bytes_written);
		  }
	      }
	  }
	while ((! err) && data_size);

      if (! err)
	{
	  /* Complete line has been written to line_buffer.  */
	  if (line_size)
	    {
	      err = buffer_seek (line_buffer, 0, SEEK_SET);
	      if (! err)
		{
		  line_new = malloc (line_size + 1);
		  if (! line_new)
		    err = gpg_error_from_errno (errno);
		}
	      if (! err)
		{
		  size_t bytes_written = 0, written = 0;
		  
		  while ((bytes_written < line_size) && (! err))
		    {
		      err = buffer_read (line_buffer, line_new + bytes_written,
					 line_size - bytes_written, &written);
		      bytes_written += written;
		    }
		  if (! err)
		    line_new[line_size] = 0;
		}
	    }
	}
	  
      if (line_buffer)
	buffer_destroy (line_buffer);
      if (handle)
	gpg_stream_func_mem_destroy (handle);

      if (! err)
	{
	  *line = line_new;
	  if (line_length)
	    *line_length = line_size;
	}
      else
	{
	  if (line_new)
	    free (line_new);
	}
    }

  return err;
}

gpg_error_t
gpg_stream_read_line (gpg_stream_t stream,
		      char **line,
		      size_t *line_length)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_read_line_do (stream, line, line_length);

  return err;
}

static gpg_error_t
gpg_stream_print_va_do (gpg_stream_t stream,
			const char *format,
			va_list ap)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  FILE *tmp_stream = NULL;
  int ret = 0;

  if (! (stream->flags & GPG_STREAM_FLAG_WRITE))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    {
      tmp_stream = tmpfile ();
      if (! tmp_stream)
	err = gpg_error_from_errno (errno);

      if (! err)
	{
	  ret = vfprintf (tmp_stream, format, ap);
	  if (ret == -1)
	    err = gpg_error_from_errno (errno);
	}

      if (! err)
	{
	  ret = fseek (tmp_stream, 0, SEEK_SET);
	  if (ret == -1)
	    err = gpg_error_from_errno (errno);
	}

      if (! err)
	{
	  size_t bytes_read = 0, bytes_written = 0;
	  char data[BUFFER_BLOCK_SIZE];

	  while (! err)
	    {
	      bytes_read = fread (data, 1, sizeof (data), tmp_stream);
	      if (ferror (tmp_stream))
		err = gpg_error_from_errno (errno);
	      if (! err)
		err = gpg_stream_write_do (stream, data,
					   bytes_read, &bytes_written);
	      if (! err)
		if (feof (tmp_stream))
		  break;
	    }
	}

      if (tmp_stream)
	fclose (tmp_stream);
    }

  return err;
}

gpg_error_t
gpg_stream_print_va (gpg_stream_t stream,
		     const char *format,
		     va_list ap)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  
  err = gpg_stream_print_va_do (stream, format, ap);

  return err;
}

gpg_error_t
gpg_stream_print (gpg_stream_t stream,
		  const char *format,
		  ...)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  va_list ap;

  va_start (ap, format);
  err = gpg_stream_print_va (stream, format, ap);
  va_end (ap);

  return err;
}

static gpg_error_t
gpg_stream_flush_do (gpg_stream_t stream)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_flush (stream->buffer);

  return err;
}

gpg_error_t
gpg_stream_flush (gpg_stream_t stream)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_flush_do (stream);

  return err;
}

static gpg_error_t
gpg_stream_peek_do (gpg_stream_t stream,
		    char **buffer,
		    size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_peek (stream->buffer, buffer, size);

  return err;
}

gpg_error_t
gpg_stream_peek (gpg_stream_t stream,
		 char **buffer,
		 size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_peek_do (stream, buffer, size);

  return err;
}

static gpg_error_t
gpg_stream_seek_do (gpg_stream_t stream,
		    off_t offset,
		    int whence)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_seek (stream->buffer, offset, whence);

  return err;
}

gpg_error_t
gpg_stream_seek (gpg_stream_t stream,
		 off_t offset,
		 int whence)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_seek_do (stream, offset, whence);

  return err;
}

static gpg_error_t
gpg_stream_stat_do (gpg_stream_t stream,
		    size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = buffer_stat (stream->buffer, size);

  return err;
}

gpg_error_t
gpg_stream_stat (gpg_stream_t stream,
		 size_t *size)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = gpg_stream_stat_do (stream, size);

  return err;
}
