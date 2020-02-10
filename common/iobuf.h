/* iobuf.h - I/O buffer
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_IOBUF_H
#define GNUPG_COMMON_IOBUF_H

/* An iobuf is basically a filter in a pipeline.

   Consider the following command, which consists of three filters
   that are chained together:

     $ cat file | base64 --decode | gunzip

   The first filter reads the file from the file system and sends that
   data to the second filter.  The second filter decodes
   base64-encoded data and sends the data to the third and last
   filter.  The last filter decompresses the data and the result is
   displayed on the terminal.  The iobuf system works in the same way
   where each iobuf is a filter and the individual iobufs can be
   chained together.

   There are number of predefined filters.  iobuf_open(), for
   instance, creates a filter that reads from a specified file.  And,
   iobuf_temp_with_content() creates a filter that returns some
   specified contents.  There are also filters for writing content.
   iobuf_openrw opens a file for writing.  iobuf_temp creates a filter
   that writes data to a fixed-sized buffer.

   To chain filters together, you use the iobuf_push_filter()
   function.  The filters are chained together using the chain field
   in the iobuf_t.

   A pipeline can only be used for reading (IOBUF_INPUT) or for
   writing (IOBUF_OUTPUT / IOBUF_OUTPUT_TEMP).  When reading, data
   flows from the last filter towards the first.  That is, the user
   calls iobuf_read(), the module reads from the first filter, which
   gets its input from the second filter, etc.  When writing, data
   flows from the first filter towards the last.  In this case, when
   the user calls iobuf_write(), the data is written to the first
   filter, which writes the transformed data to the second filter,
   etc.

   An iobuf_t contains some state about the filter.  For instance, it
   indicates if the filter has already returned EOF (filter_eof) and
   the next filter in the pipeline, if any (chain).  It also contains
   a function pointer, filter.  This is a generic function.  It is
   called when input is needed or output is available.  In this case
   it is passed a pointer to some filter-specific persistent state
   (filter_ov), the actual operation, the next filter in the chain, if
   any, and a buffer that either contains the contents to write, if
   the pipeline is setup to write data, or is the place to store data,
   if the pipeline is setup to read data.


   Unlike a Unix pipeline, an IOBUF pipeline can return EOF multiple
   times.  This is similar to the following:

     { cat file1; cat file2; } | grep foo

   However, instead of grep seeing a single stream, grep would see
   each byte stream followed by an EOF marker.  (When a filter returns
   EOF, the EOF is returned to the user exactly once and then the
   filter is removed from the pipeline.)  */

/* For estream_t.  */
#include <gpg-error.h>

#include "../common/types.h"
#include "../common/sysutils.h"

#define DBG_IOBUF   iobuf_debug_mode

/* Filter control modes.  */
enum
  {
    IOBUFCTRL_INIT	= 1,
    IOBUFCTRL_FREE	= 2,
    IOBUFCTRL_UNDERFLOW = 3,
    IOBUFCTRL_FLUSH     = 4,
    IOBUFCTRL_DESC	= 5,
    IOBUFCTRL_CANCEL    = 6,
    IOBUFCTRL_USER	= 16
  };


/* Command codes for iobuf_ioctl.  */
typedef enum
  {
    IOBUF_IOCTL_KEEP_OPEN        = 1, /* Uses intval.  */
    IOBUF_IOCTL_INVALIDATE_CACHE = 2, /* Uses ptrval.  */
    IOBUF_IOCTL_NO_CACHE         = 3, /* Uses intval.  */
    IOBUF_IOCTL_FSYNC            = 4  /* Uses ptrval.  */
  } iobuf_ioctl_t;

enum iobuf_use
  {
    /* Pipeline is in input mode.  The data flows from the end to the
       beginning.  That is, when reading from the pipeline, the first
       filter gets its input from the second filter, etc.  */
    IOBUF_INPUT,
    /* Pipeline is in input mode.  The last filter in the pipeline is
       a temporary buffer from which the data is "read".  */
    IOBUF_INPUT_TEMP,
    /* Pipeline is in output mode.  The data flows from the beginning
       to the end.  That is, when writing to the pipeline, the user
       writes to the first filter, which transforms the data and sends
       it to the second filter, etc.  */
    IOBUF_OUTPUT,
    /* Pipeline is in output mode.  The last filter in the pipeline is
       a temporary buffer that grows as necessary.  */
    IOBUF_OUTPUT_TEMP
  };


typedef struct iobuf_struct *iobuf_t;
typedef struct iobuf_struct *IOBUF;  /* Compatibility with gpg 1.4. */

/* fixme: we should hide most of this stuff */
struct iobuf_struct
{
  /* The type of filter.  Either IOBUF_INPUT, IOBUF_OUTPUT or
     IOBUF_OUTPUT_TEMP.  */
  enum iobuf_use use;

  /* nlimit can be changed using iobuf_set_limit.  If non-zero, it is
     the number of additional bytes that can be read from the filter
     before EOF is forcefully returned.  */
  off_t nlimit;
  /* nbytes if the number of bytes that have been read (using
     iobuf_get / iobuf_readbyte / iobuf_read) since the last call to
     iobuf_set_limit.  */
  off_t nbytes;

  /* The number of bytes read prior to the last call to
     iobuf_set_limit.  Thus, the total bytes read (i.e., the position
     of stream) is ntotal + nbytes. */
  off_t ntotal;

  /* Whether we need to read from the filter one byte at a time or
     whether we can do bulk reads.  We need to read one byte at a time
     if a limit (set via iobuf_set_limit) is active.  */
  int nofast;

  /* A buffer for unread/unwritten data.

     For an output pipeline (IOBUF_OUTPUT), this is the data that has
     not yet been written to the filter.  Consider a simple pipeline
     consisting of a single stage, which writes to a file.  When you
     write to the pipeline (iobuf_writebyte or iobuf_write), the data
     is first stored in this buffer.  Only when the buffer is full or
     you call iobuf_flush() is FILTER actually called and the data
     written to the file.

     For an input pipeline (IOBUF_INPUT), this is the data that has
     been read from this filter, but not yet been read from the
     preceding filter (or the user, if this filter is the head of the
     pipeline).  Again, consider a simple pipeline consisting of a
     single stage.  This stage reads from a file.  If you read a
     single byte (iobuf_get) and the buffer is empty, then FILTER is
     called to fill the buffer.  In this case, a single byte is not
     requested, but the whole buffer is filled (if possible).  */
  struct
  {
    /* Size of the buffer.  */
    size_t size;
    /* Number of bytes at the beginning of the buffer that have
       already been consumed.  (In other words: the index of the first
       byte that hasn't been consumed.)  This is only non-zero for
       input filters.  */
    size_t start;
    /* The number of bytes in the buffer including any bytes that have
       been consumed.  */
    size_t len;
    /* The buffer itself.  */
    byte *buf;
  } d;

  /* When FILTER is called to read some data, it may read some data
     and then return EOF.  We can't return the EOF immediately.
     Instead, we note that we observed the EOF and when the buffer is
     finally empty, we return the EOF.  */
  int filter_eof;
  /* Like filter_eof, when FILTER is called to read some data, it may
     read some data and then return an error.  We can't return the
     error (in the form of an EOF) immediately.  Instead, we note that
     we observed the error and when the buffer is finally empty, we
     return the EOF.  */
  int error;

  /* The callback function to read data from the filter, etc.  See
     iobuf_filter_push for details.  */
  int (*filter) (void *opaque, int control,
		 iobuf_t chain, byte * buf, size_t * len);
  /* An opaque pointer that can be used for local filter state.  This
     is passed as the first parameter to FILTER.  */
  void *filter_ov;
  /* Whether the iobuf code should free(filter_ov) when destroying the
     filter.  */
  int filter_ov_owner;

  /* When using iobuf_open, iobuf_create, iobuf_openrw to open a file,
     the file's name is saved here.  This is used to delete the file
     when an output pipeline (IOBUF_OUPUT) is canceled
     (iobuf_cancel).  */
  char *real_fname;

  /* The next filter in the pipeline.  */
  iobuf_t chain;

  /* This field is for debugging.  Each time a filter is allocated
     (via iobuf_alloc()), a monotonically increasing counter is
     incremented and this field is set to the new value.  This field
     should only be accessed via the iobuf_io macro.  */
  int no;

  /* The number of filters in the pipeline following (not including)
     this one.  When you call iobuf_push_filter or iobuf_push_filter2,
     this value is used to check the length of the pipeline if the
     pipeline already contains 65 stages then these functions fail.
     This amount of nesting typically indicates corrupted data or an
     active denial of service attack.  */
  int subno;
};

extern int iobuf_debug_mode;


/* Returns whether the specified filename corresponds to a pipe.  In
   particular, this function checks if FNAME is "-" and, if special
   filenames are enabled (see check_special_filename), whether
   FNAME is a special filename.  */
int  iobuf_is_pipe_filename (const char *fname);

/* Allocate a new filter.  This filter doesn't have a function
   assigned to it.  Thus you need to manually set IOBUF->FILTER and
   IOBUF->FILTER_OV, if required.  This function is intended to help
   create a new primary source or primary sink, i.e., the last filter
   in the pipeline.

   USE is IOBUF_INPUT, IOBUF_INPUT_TEMP, IOBUF_OUTPUT or
   IOBUF_OUTPUT_TEMP.

   BUFSIZE is the desired internal buffer size (that is, the size of
   the typical read / write request).  */
iobuf_t iobuf_alloc (int use, size_t bufsize);

/* Create an output filter that simply buffers data written to it.
   This is useful for collecting data for later processing.  The
   buffer can be written to in the usual way (iobuf_write, etc.).  The
   data can later be extracted using iobuf_write_temp() or
   iobuf_temp_to_buffer().  */
iobuf_t iobuf_temp (void);

/* Create an input filter that contains some data for reading.  */
iobuf_t iobuf_temp_with_content (const char *buffer, size_t length);

/* Create an input file filter that reads from a file.  If FNAME is
   '-', reads from stdin.  If special filenames are enabled
   (iobuf_enable_special_filenames), then interprets special
   filenames.  */
iobuf_t iobuf_open (const char *fname);

/* Create an output file filter that writes to a file.  If FNAME is
   NULL or '-', writes to stdout.  If special filenames are enabled
   (iobuf_enable_special_filenames), then interprets special
   filenames.  If FNAME is not NULL, '-' or a special filename, the
   file is opened for writing.  If the file exists, it is truncated.
   If MODE700 is TRUE, the file is created with mode 600.  Otherwise,
   mode 666 is used.  */
iobuf_t iobuf_create (const char *fname, int mode700);

/* Create an output file filter that writes to a specified file.
   Neither '-' nor special file names are recognized.  */
iobuf_t iobuf_openrw (const char *fname);

/* Create a file filter using an existing file descriptor.  If MODE
   contains the letter 'w', creates an output filter.  Otherwise,
   creates an input filter.  Note: MODE must reflect the file
   descriptors actual mode!  When the filter is destroyed, the file
   descriptor is closed.  */
iobuf_t iobuf_fdopen (int fd, const char *mode);

/* Like iobuf_fdopen, but doesn't close the file descriptor when the
   filter is destroyed.  */
iobuf_t iobuf_fdopen_nc (int fd, const char *mode);

/* Create a filter using an existing estream.  If MODE contains the
   letter 'w', creates an output filter.  Otherwise, creates an input
   filter.  If KEEP_OPEN is TRUE, then the stream is not closed when
   the filter is destroyed.  Otherwise, the stream is closed when the
   filter is destroyed.  */
iobuf_t iobuf_esopen (estream_t estream, const char *mode, int keep_open);

/* Create a filter using an existing socket.  On Windows creates a
   special socket filter.  On non-Windows systems simply, this simply
   calls iobuf_fdopen.  */
iobuf_t iobuf_sockopen (int fd, const char *mode);

/* Set various options / perform different actions on a PIPELINE.  See
   the IOBUF_IOCTL_* macros above.  */
int iobuf_ioctl (iobuf_t a, iobuf_ioctl_t cmd, int intval, void *ptrval);

/* Close a pipeline.  The filters in the pipeline are first flushed
   using iobuf_flush, if they are output filters, and then
   IOBUFCTRL_FREE is called on each filter.

   If any filter returns a non-zero value in response to the
   IOBUFCTRL_FREE, that first such non-zero value is returned.  Note:
   processing is not aborted in this case.  If all filters are freed
   successfully, 0 is returned.  */
int iobuf_close (iobuf_t iobuf);

/* Calls IOBUFCTRL_CANCEL on each filter in the pipeline.  Then calls
   io_close() on the pipeline.  Finally, if the pipeline is an output
   pipeline, deletes the file.  Returns the result of calling
   iobuf_close on the pipeline.  */
int iobuf_cancel (iobuf_t iobuf);

/* Add a new filter to the front of a pipeline.  A is the head of the
   pipeline.  F is the filter implementation.  OV is an opaque pointer
   that is passed to F and is normally used to hold any internal
   state, such as a file pointer.

   Note: you may only maintain a reference to an iobuf_t as a
   reference to the head of the pipeline.  That is, don't think about
   setting a pointer in OV to point to the filter's iobuf_t.  This is
   because when we add a new filter to a pipeline, we memcpy the state
   in A into new buffer.  This has the advantage that there is no need
   to update any references to the pipeline when a filter is added or
   removed, but it also means that a filter's state moves around in
   memory.

   The behavior of the filter function is determined by the value of
   the control parameter:

     IOBUFCTRL_INIT: Called this value just before the filter is
       linked into the pipeline. This can be used to initialize
       internal data structures.

     IOBUFCTRL_FREE: Called with this value just before the filter is
       removed from the pipeline.  Normally used to release internal
       data structures, close a file handle, etc.

     IOBUFCTRL_UNDERFLOW: Called with this value to fill the passed
       buffer with more data. *LEN is the size of the buffer.  Before
       returning, it should be set to the number of bytes which were
       written into the buffer.  The function must return 0 to
       indicate success, -1 on EOF and a GPG_ERR_xxxxx code for any
       error.

       Note: this function may both return data and indicate an error
       or EOF.  In this case, it simply writes the data to BUF, sets
       *LEN and returns the appropriate return code.  The implication
       is that if an error occurs and no data has yet been written, it
       is essential that *LEN be set to 0!

     IOBUFCTRL_FLUSH: Called with this value to write out any
       collected data.  *LEN is the number of bytes in BUF that need
       to be written out.  Returns 0 on success and a GPG_ERR_* code
       otherwise.  *LEN must be set to the number of bytes that were
       written out.

     IOBUFCTRL_CANCEL: Called with this value when iobuf_cancel() is
       called on the pipeline.

     IOBUFCTRL_DESC: Called with this value to get a human-readable
       description of the filter.  *LEN is the size of the buffer.
       The description is filled into BUF, NUL-terminated.  Always
       returns 0.
  */
int iobuf_push_filter (iobuf_t a, int (*f) (void *opaque, int control,
					    iobuf_t chain, byte * buf,
					    size_t * len), void *ov);
/* This variant of iobuf_push_filter allows the called to indicate
   that OV should be freed when this filter is freed.  That is, if
   REL_OV is TRUE, then when the filter is popped or freed OV will be
   freed after the filter function is called with control set to
   IOBUFCTRL_FREE.  */
int iobuf_push_filter2 (iobuf_t a,
			int (*f) (void *opaque, int control, iobuf_t chain,
				  byte * buf, size_t * len), void *ov,
			int rel_ov);

/* Pop the top filter.  The top filter must have the filter function F
   and the cookie OV.  The cookie check is ignored if OV is NULL.  */
int iobuf_pop_filter (iobuf_t a,
                      int (*f) (void *opaque, int control,
                                iobuf_t chain, byte * buf, size_t * len),
                      void *ov);

/* Used for debugging.  Prints out the chain using log_debug if
   IOBUF_DEBUG_MODE is not 0.  */
int iobuf_print_chain (iobuf_t a);

/* Indicate that some error occurred on the specified filter.  */
#define iobuf_set_error(a)    do { (a)->error = 1; } while(0)

/* Return any pending error on filter A.  */
#define iobuf_error(a)	      ((a)->error)

/* Limit the amount of additional data that may be read from the
   filter.  That is, if you've already read 100 bytes from A and you
   set the limit to 50, then you can read up to an additional 50 bytes
   (i.e., a total of 150 bytes) before EOF is forcefully returned.
   Setting NLIMIT to 0 removes any active limit.

   Note: using iobuf_seek removes any currently enforced limit!  */
void iobuf_set_limit (iobuf_t a, off_t nlimit);

/* Returns the number of bytes that have been read from the pipeline.
   Note: the result is undefined for IOBUF_OUTPUT and IOBUF_OUTPUT_TEMP
   pipelines!  */
off_t iobuf_tell (iobuf_t a);

/* There are two cases:

   - If A is an INPUT or OUTPUT pipeline, then the last filter in the
     pipeline is found.  If that is not a file filter, -1 is returned.
     Otherwise, an fseek(..., SEEK_SET) is performed on the file
     descriptor.

   - If A is a TEMP pipeline and the *first* (and thus only filter) is
     a TEMP filter, then the "file position" is effectively unchanged.
     That is, data is appended to the buffer and the seek does not
     cause the size of the buffer to grow.

   If no error occurred, then any limit previous set by
   iobuf_set_limit() is cleared.  Further, any error on the filter
   (the file filter or the temp filter) is cleared.

   Returns 0 on success and -1 if an error occurs.  */
int iobuf_seek (iobuf_t a, off_t newpos);

/* Read a single byte.  If a filter has no more data, returns -1 to
   indicate the EOF.  Generally, you don't want to use this function,
   but instead prefer the iobuf_get macro, which is faster if there is
   data in the internal buffer.  */
int iobuf_readbyte (iobuf_t a);

/* Get a byte from the iobuf; must check for eof prior to this
   function.  This function returns values in the range 0 .. 255 or -1
   to indicate EOF.  iobuf_get_noeof() does not return -1 to indicate
   EOF, but masks the returned value to be in the range 0 .. 255.  */
#define iobuf_get(a)  \
     (	((a)->nofast || (a)->d.start >= (a)->d.len )?  \
	iobuf_readbyte((a)) : ( (a)->nbytes++, (a)->d.buf[(a)->d.start++] ) )
#define iobuf_get_noeof(a)    (iobuf_get((a))&0xff)

/* Fill BUF with up to BUFLEN bytes.  If a filter has no more data,
   returns -1 to indicate the EOF.  Otherwise returns the number of
   bytes read.  */
int iobuf_read (iobuf_t a, void *buf, unsigned buflen);

/* Read a line of input (including the '\n') from the pipeline.

   The semantics are the same as for fgets(), but if the buffer is too
   short a larger one will be allocated up to *MAX_LENGTH and the end
   of the line except the trailing '\n' discarded.  (Thus,
   *ADDR_OF_BUFFER must be allocated using malloc().)  If the buffer
   is enlarged, then *LENGTH_OF_BUFFER will be updated to reflect the
   new size.  If the line is truncated, then *MAX_LENGTH will be set
   to 0.  If *ADDR_OF_BUFFER is NULL, a buffer is allocated using
   malloc().

   A line is considered a byte stream ending in a '\n'.  Returns the
   number of characters written to the buffer (i.e., excluding any
   discarded characters due to truncation).  Thus, use this instead of
   strlen(buffer) to determine the length of the string as this is
   unreliable if the input contains NUL characters.

   EOF is indicated by a line of length zero.

   The last LF may be missing due to an EOF.  */
unsigned iobuf_read_line (iobuf_t a, byte ** addr_of_buffer,
			  unsigned *length_of_buffer, unsigned *max_length);

/* Read up to BUFLEN bytes from pipeline A.  Note: this function can't
   return more than the pipeline's internal buffer size.  The return
   value is the number of bytes actually written to BUF.  If the
   filter returns EOF, then this function returns -1.

   This function does not clear any pending EOF.  That is, if the
   pipeline consists of two filters and the first one returns EOF
   during the peek, then the subsequent iobuf_read* will still return
   EOF before returning the data from the second filter.  */
int iobuf_peek (iobuf_t a, byte * buf, unsigned buflen);

/* Write a byte to the pipeline.  Returns 0 on success and an error
   code otherwise.  */
int iobuf_writebyte (iobuf_t a, unsigned c);

/* Alias for iobuf_writebyte.  */
#define iobuf_put(a,c)	iobuf_writebyte(a,c)

/* Write a sequence of bytes to the pipeline.  Returns 0 on success
   and an error code otherwise.  */
int iobuf_write (iobuf_t a, const void *buf, unsigned buflen);

/* Write a string (not including the NUL terminator) to the pipeline.
   Returns 0 on success and an error code otherwise.  */
int iobuf_writestr (iobuf_t a, const char *buf);

/* Flushes the pipeline removing all filters but the sink (the last
   filter) in the process.  */
void iobuf_flush_temp (iobuf_t temp);

/* Flushes the pipeline SOURCE removing all filters but the sink (the
   last filter) in the process (i.e., it calls
   iobuf_flush_temp(source)) and then writes the data to the pipeline
   DEST.  Note: this doesn't free (iobuf_close()) SOURCE.  Both SOURCE
   and DEST must be output pipelines.  */
int iobuf_write_temp (iobuf_t dest, iobuf_t source);

/* Flushes each filter in the pipeline (i.e., sends any buffered data
   to the filter by calling IOBUFCTRL_FLUSH).  Then, copies up to the
   first BUFLEN bytes from the last filter's internal buffer (which
   will only be non-empty if it is a temp filter) to the buffer
   BUFFER.  Returns the number of bytes actually copied.  */
size_t iobuf_temp_to_buffer (iobuf_t a, byte * buffer, size_t buflen);

/* Copies the data from the input iobuf SOURCE to the output iobuf
   DEST until either an error is encountered or EOF is reached.
   Returns the number of bytes successfully written.  If an error
   occurred, then any buffered bytes are not returned to SOURCE and are
   effectively lost.  To check if an error occurred, use
   iobuf_error.  */
size_t iobuf_copy (iobuf_t dest, iobuf_t source);

/* Return the size of any underlying file.  This only works with
   file_filter based pipelines.

   On Win32, it is sometimes not possible to determine the size of
   files larger than 4GB.  In this case, *OVERFLOW (if not NULL) is
   set to 1.  Otherwise, *OVERFLOW is set to 0.  */
off_t iobuf_get_filelength (iobuf_t a, int *overflow);
#define IOBUF_FILELENGTH_LIMIT 0xffffffff

/* Return the file descriptor designating the underlying file.  This
   only works with file_filter based pipelines.  */
int  iobuf_get_fd (iobuf_t a);

/* Return the real filename, if available.  This only supports
   pipelines that end in file filters.  Returns NULL if not
   available.  */
const char *iobuf_get_real_fname (iobuf_t a);

/* Return the filename or a description thereof.  For instance, for
   iobuf_open("-"), this will return "[stdin]".  This only supports
   pipelines that end in file filters.  Returns NULL if not
   available.  */
const char *iobuf_get_fname (iobuf_t a);

/* Like iobuf_getfname, but instead of returning NULL if no
   description is available, return "[?]".  */
const char *iobuf_get_fname_nonnull (iobuf_t a);

/* Pushes a filter on the pipeline that interprets the datastream as
   an OpenPGP data block whose length is encoded using partial body
   length headers (see Section 4.2.2.4 of RFC 4880).  Concretely, it
   just returns / writes the data and finishes the packet with an
   EOF.  */
void iobuf_set_partial_body_length_mode (iobuf_t a, size_t len);

/* If PARTIAL is set, then read from the pipeline until the first EOF
   is returned.

   If PARTIAL is 0, then read up to N bytes or until the first EOF is
   returned.

   Recall: a filter can return EOF.  In this case, it and all
   preceding filters are popped from the pipeline and the next read is
   from the following filter (which may or may not return EOF).  */
void iobuf_skip_rest (iobuf_t a, unsigned long n, int partial);

#define iobuf_where(a)	"[don't know]"

/* Each time a filter is allocated (via iobuf_alloc()), a
   monotonically increasing counter is incremented and this field is
   set to the new value.  This macro returns that number.  */
#define iobuf_id(a)	((a)->no)

#define iobuf_get_temp_buffer(a) ( (a)->d.buf )
#define iobuf_get_temp_length(a) ( (a)->d.len )

/* Whether the filter uses an in-memory buffer.  */
#define iobuf_is_temp(a)	 ( (a)->use == IOBUF_OUTPUT_TEMP )

#endif /*GNUPG_COMMON_IOBUF_H*/
