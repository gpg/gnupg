/* call-agent.c - divert operations to the agent
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <gcrypt.h>

#include "gpgsm.h"
#include "../assuan/assuan.h"
#include "i18n.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

#define LINELENGTH 1002 /* 1000 + [CR,]LF */

#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


static pid_t agent_pid = -1;
/* fixme: replace this code by calling assuna functions */
static int inbound_fd = -1;
static int outbound_fd = -1;
static struct {
  int eof;
  char line[LINELENGTH];
  int linelen;  /* w/o CR, LF - might not be the same as
                   strlen(line) due to embedded nuls. However a nul
                   is always written at this pos */
  struct {
    char line[LINELENGTH];
    int linelen ;
  } attic;
} inbound;


struct membuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};



/* A simple implemnation of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  */

static void
init_membuf (struct membuf *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = xtrymalloc (initiallen);
  if (!mb->buf)
      mb->out_of_core = 1;
}

static void
put_membuf (struct membuf *mb, const void *buf, size_t len)
{
  if (mb->out_of_core)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;
      
      mb->size += len + 1024;
      p = xtryrealloc (mb->buf, mb->size);
      if (!p)
        {
          mb->out_of_core = 1;
          return;
        }
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}

static void *
get_membuf (struct membuf *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      xfree (mb->buf);
      mb->buf = NULL;
      return NULL;
    }

  p = mb->buf;
  *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = 1; /* don't allow a reuse */
  return p;
}



static int
writen (int fd, const void *buf, size_t nbytes)
{
  size_t nleft = nbytes;
  int nwritten;

  while (nleft > 0)
    {
      nwritten = write (fd, buf, nleft);
      if (nwritten < 0)
        {
          if (errno == EINTR)
            nwritten = 0;
          else 
            {
              log_error ("write() failed: %s\n", strerror (errno));
              return seterr (Write_Error);
            }
        }
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }
  
  return 0;
}



/* read an entire line */
static int
readline (int fd, char *buf, size_t buflen, int *r_nread, int *eof)
{
  size_t nleft = buflen;
  int n;
  char *p;

  *eof = 0;
  *r_nread = 0;
  while (nleft > 0)
    {
      do 
        n = read (fd, buf, nleft);
      while (n < 0 && errno == EINTR);
      if (n < 0)
        {
          log_error ("read() error: %s\n", strerror (errno) );
          return seterr (Read_Error);
        }
        
      if (!n)
        {
          *eof = 1;
          break; /* allow incomplete lines */
        }
      p = buf;
      nleft -= n;
      buf += n;
      *r_nread += n;
      
      for (; n && *p != '\n'; n--, p++)
        ;
      if (n)
        break; /* at least one full line available - that's enough for now */
    }
  
  return 0;
}


static int
read_from_agent (int *okay)
{
  char *line = inbound.line;
  int n, nread;
  int rc;

  *okay = 0;
 restart:  
  if (inbound.eof)
    return -1;

  if (inbound.attic.linelen)
    {
      memcpy (line, inbound.attic.line, inbound.attic.linelen);
      nread = inbound.attic.linelen;
      inbound.attic.linelen = 0;
      for (n=0; n < nread && line[n] != '\n'; n++)
        ;
      if (n < nread)
        rc = 0; /* found another line in the attic */
      else
        { /* read the rest */
          n = nread;
          assert (n < LINELENGTH);
          rc = readline (inbound_fd, line + n, LINELENGTH - n,
                         &nread, &inbound.eof);
        }
    }
  else
    rc = readline (inbound_fd, line, LINELENGTH,
                   &nread, &inbound.eof);
  if (rc)
    return seterr(Read_Error);
  if (!nread)
    {
      assert (inbound.eof);
      return -1; /* eof */ 
    }

  for (n=0; n < nread; n++)
    {
      if (line[n] == '\n')
        {
          if (n+1 < nread)
            {
              n++;
              /* we have to copy the rest because the handlers are
                 allowed to modify the passed buffer */
              memcpy (inbound.attic.line, line+n, nread-n);
              inbound.attic.linelen = nread-n;
              n--;
            }
          if (n && line[n-1] == '\r')
            n--;
          line[n] = 0;
          inbound.linelen = n;
          if (n && *line == '#')
            goto restart;

          rc = 0;
          if (n >= 1
              && line[0] == 'D' && line[1] == ' ')
            *okay = 2; /* data line */
          else if (n >= 2
              && line[0] == 'O' && line[1] == 'K'
              && (line[2] == '\0' || line[2] == ' '))
            *okay = 1;
          else if (n >= 3
                   && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
                   && (line[3] == '\0' || line[3] == ' '))
            *okay = 0;
          else
            rc = seterr (Invalid_Response);
          return rc;
        }
    }

  *line = 0;
  inbound.linelen = 0;
  return inbound.eof? seterr (Incomplete_Line):seterr (Invalid_Response);
}





/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
static int
start_agent (void)
{
  int rc;
  char *infostr, *p;
  int okay;

  if (agent_pid != -1)
    return 0;

  infostr = getenv ("GPG_AGENT_INFO");
  if (!infostr)
    {
      pid_t pid;
      int inpipe[2], outpipe[2];

      log_info (_("no running gpg-agent - starting one\n"));
      
      if (fflush (NULL))
        {
          log_error ("error flushing pending output: %s\n", strerror (errno));
          return seterr (Write_Error);
        }

      if (pipe (inpipe))
        {
          log_error ("error creating pipe: %s\n", strerror (errno));
          return seterr (General_Error);
        }
      if (pipe (outpipe))
        {
          log_error ("error creating pipe: %s\n", strerror (errno));
          close (inpipe[0]);
          close (inpipe[1]);
          return seterr (General_Error);
        }

      pid = fork ();
      if (pid == -1) 
        return seterr (General_Error);

      if (!pid)
        { /* child */
          int i, n;
          char errbuf[100];
          int log_fd = log_get_fd ();

          /* close all files which will not be duped but keep stderr
             and log_stream for now */
          n = sysconf (_SC_OPEN_MAX);
          if (n < 0)
              n = MAX_OPEN_FDS;
          for (i=0; i < n; i++)
            {
              if (i != fileno (stderr) && i != log_fd
                  && i != inpipe[1] && i != outpipe[0])
                close(i);
            }
          errno = 0;

          if (inpipe[1] != 1)
            {
              if (dup2 (inpipe[1], 1) == -1)
                {
                  log_error ("dup2 failed in child: %s\n", strerror (errno));
                  _exit (4);
                }
              close (inpipe[1]);
            }
          if (outpipe[0] != 0)
            {
              if (dup2 (outpipe[0], 0) == -1)
                {
                  log_error ("dup2 failed in child: %s\n", strerror (errno));
                  _exit (4);
                }
              close (outpipe[0]);
            }

          /* and start it */
          execl ("../agent/gpg-agent", "gpg-agent", "--server", NULL); 
          /* oops - tell the parent about it */
          snprintf (errbuf, DIM(errbuf)-1, "ERR %d execl failed: %.50s\n",
                    ASSUAN_Problem_Starting_Server, strerror (errno));
          errbuf[DIM(errbuf)-1] = 0;
          writen (1, errbuf, strlen (errbuf));
          _exit (4);
        } /* end child */

      agent_pid = pid;
    
      inbound_fd = inpipe[0];
      close (inpipe[1]);

      close (outpipe[0]);
      outbound_fd = outpipe[1];
    }
  else
    {
      infostr = xstrdup (infostr);
      if ( !(p = strchr (infostr, ':')) || p == infostr
           /* || (p-infostr)+1 >= sizeof client_addr.sun_path */)
        {
          log_error (_("malformed GPG_AGENT_INFO environment variable\n"));
          xfree (infostr);
          return seterr (General_Error);
        }
      *p = 0;
      log_error (_("socket based agent communication not yet implemented\n"));
      return seterr (Not_Implemented);
    }

  inbound.eof = 0;
  inbound.linelen = 0;
  inbound.attic.linelen = 0;

  /* The server is available - read the greeting */
  rc = read_from_agent (&okay);
  if (rc)
    {
      log_error ("can't connect to the agent: %s\n", gnupg_strerror (rc));
    }
  else if (!okay)
    {
      log_error ("can't connect to the agent: %s\n", inbound.line);
      rc = seterr (No_Agent);
    }
 else
   log_debug ("connection to agent established\n");

  return 0;
}


static int
request_reply (const char *line, struct membuf *membuf)
{
  int rc, okay;

  if (DBG_AGENT)
    log_debug ("agent-request=`%.*s'", (int)(*line? strlen(line)-1:0), line);
  rc = writen (outbound_fd, line, strlen (line));
  if (rc)
    return rc;
 again:
  rc = read_from_agent (&okay);
  if (rc)
      log_error ("error reading from agent: %s\n", gnupg_strerror (rc));
  else if (!okay)
    {
      log_error ("got error from agent: %s\n", inbound.line);
      rc = seterr (Agent_Error);
    }
  else if (okay == 2 && !membuf)
    {
      log_error ("got unexpected data line\n");
      rc = seterr (Agent_Error);
    }
  else
    {
      if (DBG_AGENT)
        log_debug ("agent-reply=`%s'", inbound.line);
    }

  if (!rc && okay == 2 && inbound.linelen >= 2)
    { /* handle data line */
      unsigned char *buf = inbound.line;
      size_t len = inbound.linelen;
      unsigned char *p;

      buf += 2;
      len -= 2;

      p = buf;
      while (len)
        {
          for (;len && *p != '%'; len--, p++)
            ;
          put_membuf (membuf, buf, p-buf);
          if (len>2)
            { /* handle escaping */
              unsigned char tmp[1];
              p++;
              *tmp = xtoi_2 (p);
              p += 2;
              len -= 3;
              put_membuf (membuf, tmp, 1);
            }
          buf = p;
        }
      goto again;
    }
  return rc;
}




/* Call the agent to do a sign operation using the key identified by
   the hex string KEYGRIP. */
int
gpgsm_agent_pksign (const char *keygrip,
                    unsigned char *digest, size_t digestlen, int digestalgo,
                    char **r_buf, size_t *r_buflen )
{
  int rc, i;
  char *p, line[LINELENGTH];
  struct membuf data;
  size_t len;

  *r_buf = NULL;
  rc = start_agent ();
  if (rc)
    return rc;

  if (digestlen*2 + 50 > DIM(line))
    return seterr (General_Error);

  rc = request_reply ("RESET\n", NULL);
  if (rc)
    return rc;

  snprintf (line, DIM(line)-1, "SIGKEY %s\n", keygrip);
  line[DIM(line)-1] = 0;
  rc = request_reply (line, NULL);
  if (rc)
    return rc;

  sprintf (line, "SETHASH %d ", digestalgo);
  p = line + strlen (line);
  for (i=0; i < digestlen ; i++, p += 2 )
    sprintf (p, "%02X", digest[i]);
  strcpy (p, "\n");
  rc = request_reply (line, NULL);
  if (rc)
    return rc;

  init_membuf (&data, 1024);
  rc = request_reply ("PKSIGN\n", &data);
  if (rc)
    {
      xfree (get_membuf (&data, &len));
      return rc;
    }
  *r_buf = get_membuf (&data, r_buflen);
/*    if (DBG_AGENT && *r_buf) */
/*      {  */
/*        FILE *fp; */
/*        char fname[100]; */
      
/*        memcpy (fname, keygrip, 40); */
/*        strcpy (fname+40, "_pksign-dump.tmp"); */
/*        fp = fopen (fname, "wb"); */
/*        fwrite (*r_buf, *r_buflen, 1, fp); */
/*        fclose (fp); */
/*    } */

  return *r_buf? 0 : GNUPG_Out_Of_Core;
}




