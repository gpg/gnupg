/* simple-pwquery.c - A simple password query cleint for gpg-agent
 *	Copyright (C) 2002 Free Software Foundation, Inc.
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

/* This module is intended as a standalone client implementation to
   gpg-agent's GET_PASSPHRASE command.  In particular it does not use
   the Assuan library and can only cope with an already running
   gpg-agent.  Some stuff is configurable in the header file. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#define SIMPLE_PWQUERY_IMPLEMENTATION 1
#include "simple-pwquery.h"

#if defined(SPWQ_USE_LOGGING) && !defined(HAVE_JNLIB_LOGGING)
# undef SPWQ_USE_LOGGING
#endif

#ifndef _
#define _(a) (a)
#endif

#if !defined (hexdigitp) && !defined (xtoi_2)
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#endif


/* Write NBYTES of BUF to file descriptor FD. */
static int
writen (int fd, const void *buf, size_t nbytes)
{
  size_t nleft = nbytes;
  int nwritten;
  
  while (nleft > 0)
    {
      nwritten = write( fd, buf, nleft );
      if (nwritten < 0)
        {
          if (errno == EINTR)
            nwritten = 0;
          else {
#ifdef SPWQ_USE_LOGGING
            log_error ("write failed: %s\n", strerror (errno));
#endif
            return SPWQ_IO_ERROR;
          }
        }
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }
    
  return 0;
}


/* Read an entire line and return number of bytes read. */
static int
readline (int fd, char *buf, size_t buflen)
{
  size_t nleft = buflen;
  char *p;
  int nread = 0;

  while (nleft > 0)
    {
      int n = read (fd, buf, nleft);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -(SPWQ_IO_ERROR);
        }
      else if (!n)
        {
          return -(SPWQ_PROTOCOL_ERROR); /* incomplete line */
        }
      p = buf;
      nleft -= n;
      buf += n;
      nread += n;
      
      for (; n && *p != '\n'; n--, p++)
        ;
      if (n)
        {
          break; /* at least one full line available - that's enough.
                    This function is just a simple implementation, so
                    it is okay to forget about pending bytes */
        }
    }

  return nread; 
}


/* Send an option to the agent */
static int
agent_send_option (int fd, const char *name, const char *value)
{
  char buf[200];
  int nread;
  char *line;
  int i; 
  
  line = spwq_malloc (7 + strlen (name) + 1 + strlen (value) + 2);
  if (!line)
    return SPWQ_OUT_OF_CORE;
  strcpy (stpcpy (stpcpy (stpcpy (
                     stpcpy (line, "OPTION "), name), "="), value), "\n");
  i = writen (fd, line, strlen (line));
  spwq_free (line);
  if (i)
    return i;
  
  /* get response */
  nread = readline (fd, buf, DIM(buf)-1);
  if (nread < 0)
    return -nread;
  if (nread < 3)
    return SPWQ_PROTOCOL_ERROR;
  
  if (buf[0] == 'O' && buf[1] == 'K' && (buf[2] == ' ' || buf[2] == '\n')) 
    return 0; /* okay */

  return SPWQ_ERR_RESPONSE;
}


/* Send all available options to the agent. */
static int 
agent_send_all_options (int fd)
{
  char *dft_display = NULL;
  char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
  int rc = 0;

  dft_display = getenv ("DISPLAY");
  if (dft_display)
    {
      if ((rc = agent_send_option (fd, "display", dft_display)))
        return rc;
    }

  dft_ttyname = getenv ("GPG_TTY");
  if ((!dft_ttyname || !*dft_ttyname) && ttyname (0))
    dft_ttyname = ttyname (0);
  if (dft_ttyname && *dft_ttyname)
    {
      if ((rc=agent_send_option (fd, "ttyname", dft_ttyname)))
        return rc;
    }

  dft_ttytype = getenv ("TERM");
  if (dft_ttyname && dft_ttytype)
    {
      if ((rc = agent_send_option (fd, "ttytype", dft_ttytype)))
        return rc;
    }

#if defined(HAVE_SETLOCALE) 
  {
    char *old_lc = NULL;
    char *dft_lc = NULL;

#if defined(LC_CTYPE)
    old_lc = setlocale (LC_CTYPE, NULL);
    if (old_lc)
      {
        char *p = spwq_malloc (strlen (old_lc)+1);
        if (!p)
          return SPWQ_OUT_OF_CORE;
        strcpy (p, old_lc);
        old_lc = p;
      }
    dft_lc = setlocale (LC_CTYPE, "");
    if (dft_ttyname && dft_lc)
      rc = agent_send_option (fd, "lc-ctype", dft_lc);
    if (old_lc)
      {
        setlocale (LC_CTYPE, old_lc);
        spwq_free (old_lc);
      }
    if (rc)
      return rc;
#endif

#if defined(LC_MESSAGES)
    old_lc = setlocale (LC_MESSAGES, NULL);
    if (old_lc)
      {
        char *p = spwq_malloc (strlen (old_lc)+1);
        if (!p)
          return SPWQ_OUT_OF_CORE;
        strcpy (p, old_lc);
        old_lc = p;
      }
    dft_lc = setlocale (LC_MESSAGES, "");
    if (dft_ttyname && dft_lc)
      rc = agent_send_option (fd, "lc-messages", dft_lc);
    if (old_lc)
      {
        setlocale (LC_MESSAGES, old_lc);
        spwq_free (old_lc);
      }
    if (rc)
      return rc;
#endif
  }
#endif /*HAVE_SETLOCALE*/

  return 0;
}



/* Try to open a connection to the agent, send all options and return
   the file descriptor for the connection.  Return -1 in case of
   error. */
static int
agent_open (int *rfd)
{
  int rc;
  int fd;
  char *infostr, *p;
  struct sockaddr_un client_addr;
  size_t len;
  int prot;
  char line[200];
  int nread;

  *rfd = -1;
  infostr = getenv ( "GPG_AGENT_INFO" );
  if ( !infostr || !*infostr ) 
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("gpg-agent is not available in this session\n"));
#endif
      return SPWQ_NO_AGENT;
    }

  if ( !(p = strchr ( infostr, ':')) || p == infostr
       || (p-infostr)+1 >= sizeof client_addr.sun_path ) 
    {
#ifdef SPWQ_USE_LOGGING
      log_error ( _("malformed GPG_AGENT_INFO environment variable\n"));
#endif
      return SPWQ_NO_AGENT;
    }
  *p++ = 0;

  while (*p && *p != ':')
    p++;
  prot = *p? atoi (p+1) : 0;
  if ( prot != 1)
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("gpg-agent protocol version %d is not supported\n"),prot);
#endif
      return SPWQ_PROTOCOL_ERROR;
    }
       
  if( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ) 
    {
#ifdef SPWQ_USE_LOGGING
      log_error ("can't create socket: %s\n", strerror(errno) );
#endif
      return SPWQ_SYS_ERROR;
    }
    
  memset (&client_addr, 0, sizeof client_addr);
  client_addr.sun_family = AF_UNIX;
  strcpy (client_addr.sun_path, infostr);
  len = (offsetof (struct sockaddr_un, sun_path)
         + strlen(client_addr.sun_path) + 1);
    
  if (connect (fd, (struct sockaddr*)&client_addr, len ) == -1)
    {
#ifdef SPWQ_USE_LOGGING
      log_error ( _("can't connect to `%s': %s\n"), infostr, strerror (errno));
#endif
      close (fd );
      return SPWQ_IO_ERROR;
    }

  nread = readline (fd, line, DIM(line));
  if (nread < 3 || !(line[0] == 'O' && line[1] == 'K'
                     && (line[2] == '\n' || line[2] == ' ')) ) 
    {
#ifdef SPWQ_USE_LOGGING
      log_error ( _("communication problem with gpg-agent\n"));
#endif
      close (fd );
      return SPWQ_PROTOCOL_ERROR;
    }

  rc = agent_send_all_options (fd);
  if (rc)
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("problem setting the gpg-agent options\n"));
#endif
      close (fd);
      return rc;
    }

  *rfd = fd;
  return 0;
}


/* Copy text to BUFFER and escape as required.  Return a poiinter to
   the end of the new buffer.  NOte that BUFFER must be large enough
   to keep the entire text; allocataing it 3 times the size of TEXT
   is sufficient. */
static char *
copy_and_escape (char *buffer, const char *text)
{
  int i;
  char *p = buffer;

  for (i=0; text[i]; i++)
    {
      if (text[i] < ' ' || text[i] == '+')
        {
          sprintf (p, "%%%02X", text[i]);
          p += 3;
        }
      else if (text[i] == ' ')
        *p++ = '+';
      else
        *p++ = text[i];
    }
  return p;
}


/* Ask the gpg-agent for a passphrase and present the user with a
   DESCRIPTION, a PROMPT and optiaonlly with a TRYAGAIN extra text.
   If a CACHEID is not NULL it is used to locate the passphrase in in
   the cache and store it under this ID.  If ERRORCODE is not NULL it
   should point a variable receiving an errorcode; thsi errocode might
   be 0 if the user canceled the operation.  The function returns NULL
   to indicate an error. */
char *
simple_pwquery (const char *cacheid, 
                const char *tryagain,
                const char *prompt,
                const char *description,
                int *errorcode)
{
  int fd = -1;
  int nread;
  char *result = NULL;
  char *pw = NULL;
  char *p;
  int rc, i; 

  rc = agent_open (&fd);
  if (rc)
    goto leave;

  if (!cacheid)
    cacheid = "X";
  if (!tryagain)
    tryagain = "X";
  if (!prompt)
    prompt = "X";
  if (!description)
    description = "X";

  {
    char *line;
    /* We allocate 3 times the needed space so that there is enough
       space for escaping. */
    line = spwq_malloc (15
                        + 3*strlen (cacheid) + 1
                        + 3*strlen (tryagain) + 1
                        + 3*strlen (prompt) + 1
                        + 3*strlen (description) + 1
                        + 2);
    if (!line)
      {
        rc = SPWQ_OUT_OF_CORE;
        goto leave;
      }
    strcpy (line, "GET_PASSPHRASE ");
    p = line+15;
    p = copy_and_escape (p, cacheid);
    *p++ = ' ';
    p = copy_and_escape (p, tryagain);
    *p++ = ' ';
    p = copy_and_escape (p, prompt);
    *p++ = ' ';
    p = copy_and_escape (p, description);
    *p++ = '\n';
    rc = writen (fd, line, p - line);
    spwq_free (line);
    if (rc)
      goto leave;
  }

  /* get response */
  pw = spwq_secure_malloc (500);
  nread = readline (fd, pw, 499);
  if (nread < 0)
    {
      rc = -nread;
      goto leave;
    }
  if (nread < 3)
    {
      rc = SPWQ_PROTOCOL_ERROR;
      goto leave;
    }
      
  if (pw[0] == 'O' && pw[1] == 'K' && pw[2] == ' ') 
    { /* we got a passphrase - convert it back from hex */
      size_t pwlen = 0;
      
      for (i=3; i < nread && hexdigitp (pw+i); i+=2)
        pw[pwlen++] = xtoi_2 (pw+i);
      pw[pwlen] = 0; /* make a C String */
      result = pw;
      pw = NULL;
    }
  else if (nread > 7 && !memcmp (pw, "ERR 111", 7)
      && (pw[7] == ' ' || pw[7] == '\n') )
    {
#ifdef SPWQ_USE_LOGGING
      log_info (_("canceled by user\n") );
#endif
      *errorcode = 0; /* canceled */
    }
  else 
    {
#ifdef SPWQ_USE_LOGGING
      log_error (_("problem with the agent\n"));
#endif
      rc = SPWQ_ERR_RESPONSE;
    }
        
 leave:
  if (errorcode)
    *errorcode = rc;
  if (fd != -1)
    close (fd);
  if (pw)
    spwq_free (pw);
  return result;
}
