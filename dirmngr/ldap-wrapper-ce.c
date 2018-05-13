/* ldap-wrapper-ce.c - LDAP access via W32 threads
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
   Alternative wrapper for use with WindowsCE.  Under WindowsCE the
   number of processes is strongly limited (32 processes including the
   kernel processes) and thus we don't use the process approach but
   implement a wrapper based on native threads.

   See ldap-wrapper.c for  the standard wrapper interface.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <npth.h>
#include <assert.h>

#include "dirmngr.h"
#include "misc.h"
#include "ldap-wrapper.h"

#ifdef USE_LDAPWRAPPER
# error This module is not expected to be build.
#endif
#error This module might not anymore work.



/* Read a fixed amount of data from READER into BUFFER.  */
static gpg_error_t
read_buffer (ksba_reader_t reader, unsigned char *buffer, size_t count)
{
  gpg_error_t err;
  size_t nread;

  while (count)
    {
      err = ksba_reader_read (reader, buffer, count, &nread);
      if (err)
        return err;
      buffer += nread;
      count -= nread;
    }
  return 0;
}




/* Start the reaper thread for this wrapper.  */
void
ldap_wrapper_launch_thread (void)
{
  /* Not required.  */
}





/* Wait until all ldap wrappers have terminated.  We assume that the
   kill has already been sent to all of them.  */
void
ldap_wrapper_wait_connections ()
{
  /* Not required.  */
}


/* Cleanup all resources held by the connection associated with
   CTRL.  This is used after a cancel to kill running wrappers.  */
void
ldap_wrapper_connection_cleanup (ctrl_t ctrl)
{
  (void)ctrl;

  /* Not required.  */
}



/* The cookie we use to implement the outstream of the wrapper thread.  */
struct outstream_cookie_s
{
  int refcount; /* Reference counter - possible values are 1 and 2.  */

  /* We don't need a mutex for the conditions, as npth provides a
     simpler condition interface that relies on the global lock.  This
     can be used if we never yield between testing the condition and
     waiting on it.  */
  npth_cond_t wait_data; /* Condition that data is available.  */
  npth_cond_t wait_space; /* Condition that space is available.  */

  int eof_seen;       /* EOF indicator.  */
  char buffer[4000];  /* Data ring buffer.  */
  size_t buffer_len;  /* The amount of data in the BUFFER.  */
  size_t buffer_pos;  /* The next read position of the BUFFER.  */
  size_t buffer_read_pos;  /* The next read position of the BUFFER.  */
};

#define BUFFER_EMPTY(c) ((c)->buffer_len == 0)
#define BUFFER_FULL(c) ((c)->buffer_len == DIM((c)->buffer))
#define BUFFER_DATA_AVAILABLE(c) ((c)->buffer_len)
#define BUFFER_SPACE_AVAILABLE(c) (DIM((c)->buffer) - (c)->buffer_len)
#define BUFFER_INC_POS(c,n) (c)->buffer_pos = ((c)->buffer_pos + (n)) % DIM((c)->buffer)
#define BUFFER_CUR_POS(c) (&(c)->buffer[(c)->buffer_pos])
#define BUFFER_INC_READ_POS(c,n) (c)->buffer_read_pos = ((c)->buffer_read_pos + (n)) % DIM((c)->buffer)
#define BUFFER_CUR_READ_POS(c) (&(c)->buffer[(c)->buffer_read_pos])

static int
buffer_get_data (struct outstream_cookie_s *cookie, char *dst, int cnt)
{
  int amount;
  int left;
  int chunk;

  amount = cnt;
  if (BUFFER_DATA_AVAILABLE (cookie) < amount)
    amount = BUFFER_DATA_AVAILABLE (cookie);
  left = amount;

  /* How large is the part up to the end of the buffer array?  */
  chunk = DIM(cookie->buffer) - cookie->buffer_pos;
  if (chunk > left)
    chunk = left;

  memcpy (dst, BUFFER_CUR_READ_POS (cookie), chunk);
  BUFFER_INC_READ_POS (cookie, chunk);
  left -= chunk;
  dst += chunk;

  if (left)
    {
      memcpy (dst, BUFFER_CUR_READ_POS (cookie), left);
      BUFFER_INC_READ_POS (cookie, left);
    }

  return amount;
}


static int
buffer_put_data (struct outstream_cookie_s *cookie, const char *src, int cnt)
{
  int amount;
  int remain;
  int left;
  int chunk;

  remain = DIM(cookie->buffer) - cookie->buffer_len;

  amount = cnt;
  if (remain < amount)
    amount = remain;
  left = amount;

  /* How large is the part up to the end of the buffer array?  */
  chunk = DIM(cookie->buffer) - cookie->buffer_pos;
  if (chunk > left)
    chunk = left;

  memcpy (BUFFER_CUR_POS (cookie), src, chunk);
  BUFFER_INC_POS (cookie, chunk);
  left -= chunk;
  src += chunk;

  if (left)
    {
      memcpy (BUFFER_CUR_POS (cookie), src, left);
      BUFFER_INC_POS (cookie, left);
    }

  cookie->buffer_len -= amount;
  return amount;
}


/* The writer function for the outstream.  This is used to transfer
   the output of the ldap wrapper thread to the ksba reader object.  */
static gpgrt_ssize_t
outstream_cookie_writer (void *cookie_arg, const void *buffer, size_t size)
{
  struct outstream_cookie_s *cookie = cookie_arg;
  const char *src;
  ssize_t nwritten = 0;
  int res;
  ssize_t amount = 0;

  src = buffer;
  do
    {
      int was_empty = 0;

      /* Wait for free space.  */
      while (BUFFER_FULL(cookie))
        {
          /* Buffer is full:  Wait for space.  */
          res = npth_cond_wait (&cookie->wait_space, NULL);
	  if (res)
	    {
	      gpg_err_set_errno (res);
	      return -1;
	    }
        }

      if (BUFFER_EMPTY(cookie))
	was_empty = 1;

      /* Copy data.  */
      nwritten = buffer_put_data (cookie, buffer, size);
      size -= nwritten;
      src += nwritten;
      amount += nwritten;

      if (was_empty)
	npth_cond_signal (&cookie->wait_data);
    }
  while (size);  /* Until done.  */

  return amount;
}


static void
outstream_release_cookie (struct outstream_cookie_s *cookie)
{
  cookie->refcount--;
  if (!cookie->refcount)
    {
      npth_cond_destroy (&cookie->wait_data);
      npth_cond_destroy (&cookie->wait_space);
      xfree (cookie);
    }
}


/* Closer function for the outstream.  This deallocates the cookie if
   it won't be used anymore.  */
static int
outstream_cookie_closer (void *cookie_arg)
{
  struct outstream_cookie_s *cookie = cookie_arg;

  if (!cookie)
    return 0;  /* Nothing to do.  */

  cookie->eof_seen = 1; /* (only useful if refcount > 1)  */

  assert (cookie->refcount > 0);
  outstream_release_cookie (cookie);
  return 0;
}


/* The KSBA reader callback which takes the output of the ldap thread
   form the outstream_cookie_writer and make it available to the ksba
   reader.  */
static int
outstream_reader_cb (void *cb_value, char *buffer, size_t count,
                     size_t *r_nread)
{
  struct outstream_cookie_s *cookie = cb_value;
  size_t nread = 0;
  int was_full = 0;

  if (!buffer && !count && !r_nread)
    return gpg_error (GPG_ERR_NOT_SUPPORTED); /* Rewind is not supported.  */

  *r_nread = 0;

  while (BUFFER_EMPTY(cookie))
    {
      if (cookie->eof_seen)
        return gpg_error (GPG_ERR_EOF);

      /* Wait for data to become available.  */
      npth_cond_wait (&cookie->wait_data, NULL);
    }

  if (BUFFER_FULL(cookie))
    was_full = 1;

  nread = buffer_get_data (cookie, buffer, count);

  if (was_full)
    {
      npth_cond_signal (&cookie->wait_space);
    }

  *r_nread = nread;
  return 0; /* Success.  */
}


/* This function is called by ksba_reader_release.  */
static void
outstream_reader_released (void *cb_value, ksba_reader_t r)
{
  struct outstream_cookie_s *cookie = cb_value;

  (void)r;

  assert (cookie->refcount > 0);
  outstream_release_cookie (cookie);
}



/* This function is to be used to release a context associated with the
   given reader object.  This does not release the reader object, though. */
void
ldap_wrapper_release_context (ksba_reader_t reader)
{
  (void)reader;
  /* Nothing to do.  */
}



/* Free a NULL terminated array of malloced strings and the array
   itself.  */
static void
free_arg_list (char **arg_list)
{
  int i;

  if (arg_list)
    {
      for (i=0; arg_list[i]; i++)
        xfree (arg_list[i]);
      xfree (arg_list);
    }
}


/* Copy ARGV into a new array and prepend one element as name of the
   program (which is more or less a stub).  We need to allocate all
   the strings to get ownership of them.  */
static gpg_error_t
create_arg_list (const char *argv[], char ***r_arg_list)
{
  gpg_error_t err;
  char **arg_list;
  int i, j;

  for (i = 0; argv[i]; i++)
    ;
  arg_list = xtrycalloc (i + 2, sizeof *arg_list);
  if (!arg_list)
    goto outofcore;

  i = 0;
  arg_list[i] = xtrystrdup ("<ldap-wrapper-thread>");
  if (!arg_list[i])
    goto outofcore;
  i++;
  for (j=0; argv[j]; j++)
    {
      arg_list[i] = xtrystrdup (argv[j]);
      if (!arg_list[i])
        goto outofcore;
      i++;
    }
  arg_list[i] = NULL;
  *r_arg_list = arg_list;
  return 0;

 outofcore:
  err = gpg_error_from_syserror ();
  log_error (_("error allocating memory: %s\n"), strerror (errno));
  free_arg_list (arg_list);
  *r_arg_list = NULL;
  return err;

}


/* Parameters passed to the wrapper thread. */
struct ldap_wrapper_thread_parms
{
  char **arg_list;
  estream_t outstream;
};

/* The thread which runs the LDAP wrapper.  */
static void *
ldap_wrapper_thread (void *opaque)
{
  struct ldap_wrapper_thread_parms *parms = opaque;

  /*err =*/ ldap_wrapper_main (parms->arg_list, parms->outstream);

  /* FIXME: Do we need to return ERR?  */

  free_arg_list (parms->arg_list);
  es_fclose (parms->outstream);
  xfree (parms);
  return NULL;
}



/* Start a new LDAP thread and returns a new libksba reader
   object at READER.  ARGV is a NULL terminated list of arguments for
   the wrapper.  The function returns 0 on success or an error code.  */
gpg_error_t
ldap_wrapper (ctrl_t ctrl, ksba_reader_t *r_reader, const char *argv[])
{
  gpg_error_t err;
  struct ldap_wrapper_thread_parms *parms;
  npth_attr_t tattr;
  es_cookie_io_functions_t outstream_func = { NULL };
  struct outstream_cookie_s *outstream_cookie;
  ksba_reader_t reader;
  int res;
  npth_t thread;

  (void)ctrl;

  *r_reader = NULL;

  parms = xtrycalloc (1, sizeof *parms);
  if (!parms)
    return gpg_error_from_syserror ();

  err = create_arg_list (argv, &parms->arg_list);
  if (err)
    {
      xfree (parms);
      return err;
    }

  outstream_cookie = xtrycalloc (1, sizeof *outstream_cookie);
  if (!outstream_cookie)
    {
      err = gpg_error_from_syserror ();
      free_arg_list (parms->arg_list);
      xfree (parms);
      return err;
    }
  outstream_cookie->refcount++;

  res = npth_cond_init (&outstream_cookie->wait_data, NULL);
  if (res)
    {
      free_arg_list (parms->arg_list);
      xfree (parms);
      return gpg_error_from_errno (res);
    }
  res = npth_cond_init (&outstream_cookie->wait_space, NULL);
  if (res)
    {
      npth_cond_destroy (&outstream_cookie->wait_data);
      free_arg_list (parms->arg_list);
      xfree (parms);
      return gpg_error_from_errno (res);
    }

  err = ksba_reader_new (&reader);
  if (!err)
    err = ksba_reader_set_release_notify (reader,
                                          outstream_reader_released,
                                          outstream_cookie);
  if (!err)
    err = ksba_reader_set_cb (reader,
                              outstream_reader_cb, outstream_cookie);
  if (err)
    {
      log_error (_("error initializing reader object: %s\n"),
                 gpg_strerror (err));
      ksba_reader_release (reader);
      outstream_release_cookie (outstream_cookie);
      free_arg_list (parms->arg_list);
      xfree (parms);
      return err;
    }


  outstream_func.func_write = outstream_cookie_writer;
  outstream_func.func_close = outstream_cookie_closer;
  parms->outstream = es_fopencookie (outstream_cookie, "wb", outstream_func);
  if (!parms->outstream)
    {
      err = gpg_error_from_syserror ();
      ksba_reader_release (reader);
      outstream_release_cookie (outstream_cookie);
      free_arg_list (parms->arg_list);
      xfree (parms);
      return err;
    }
  outstream_cookie->refcount++;

  res = npth_attr_init(&tattr);
  if (res)
    {
      err = gpg_error_from_errno (res);
      ksba_reader_release (reader);
      free_arg_list (parms->arg_list);
      es_fclose (parms->outstream);
      xfree (parms);
      return err;
    }
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

  res = npth_create (&thread, &tattr, ldap_wrapper_thread, parms);
  npth_attr_destroy (&tattr);
  if (res)
    {
      err = gpg_error_from_errno (res);
      log_error ("error spawning ldap wrapper thread: %s\n",
                 strerror (res) );
    }
  else
    parms = NULL; /* Now owned by the thread.  */

  if (parms)
    {
      free_arg_list (parms->arg_list);
      es_fclose (parms->outstream);
      xfree (parms);
    }
  if (err)
    {
      ksba_reader_release (reader);
      return err;
    }

  /* Need to wait for the first byte so we are able to detect an empty
     output and not let the consumer see an EOF without further error
     indications.  The CRL loading logic assumes that after return
     from this function, a failed search (e.g. host not found ) is
     indicated right away. */
  {
    unsigned char c;

    err = read_buffer (reader, &c, 1);
    if (err)
      {
        ksba_reader_release (reader);
        reader = NULL;
        if (gpg_err_code (err) == GPG_ERR_EOF)
          return gpg_error (GPG_ERR_NO_DATA);
        else
          return err;
      }
    ksba_reader_unread (reader, &c, 1);
  }

  *r_reader = reader;

  return 0;
}
