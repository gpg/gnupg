/* passphrase.c -  Get a passphrase
 * Copyright (C) 1998,1999,2000,2001,2002,2003 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#if !defined(HAVE_DOSISH_SYSTEM) && !defined(__riscos__)
#include <sys/socket.h>
#include <sys/un.h>
#endif
#if defined (_WIN32) || defined (__CYGWIN32__)
# include <windows.h>
#endif
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#include "util.h"
#include "memory.h"
#include "options.h"
#include "ttyio.h"
#include "cipher.h"
#include "keydb.h"
#include "main.h"
#include "i18n.h"
#include "status.h"


enum gpga_protocol_codes {
    /* Request codes */
    GPGA_PROT_GET_VERSION     = 1,
    GPGA_PROT_GET_PASSPHRASE  = 2,
    GPGA_PROT_CLEAR_PASSPHRASE= 3,
    GPGA_PROT_SHUTDOWN        = 4,
    GPGA_PROT_FLUSH           = 5,

    /* Reply codes */
    GPGA_PROT_REPLY_BASE     = 0x10000,
    GPGA_PROT_OKAY           = 0x10001,
    GPGA_PROT_GOT_PASSPHRASE = 0x10002,

    /* Error codes */
    GPGA_PROT_ERROR_BASE     = 0x20000,
    GPGA_PROT_PROTOCOL_ERROR = 0x20001,
    GPGA_PROT_INVALID_REQUEST= 0x20002,
    GPGA_PROT_CANCELED       = 0x20003,    
    GPGA_PROT_NO_PASSPHRASE  = 0x20004,    
    GPGA_PROT_BAD_PASSPHRASE = 0x20005,
    GPGA_PROT_INVALID_DATA   = 0x20006,
    GPGA_PROT_NOT_IMPLEMENTED= 0x20007,
    GPGA_PROT_UI_PROBLEM     = 0x20008
};


#define buftou32( p )  ((*(byte*)(p) << 24) | (*((byte*)(p)+1)<< 16) | \
		       (*((byte*)(p)+2) << 8) | (*((byte*)(p)+3)))
#define u32tobuf( p, a ) do { 			                \
			    ((byte*)p)[0] = (byte)((a) >> 24);	\
			    ((byte*)p)[1] = (byte)((a) >> 16);	\
			    ((byte*)p)[2] = (byte)((a) >>  8);	\
			    ((byte*)p)[3] = (byte)((a) 	    );	\
			} while(0)

#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))



static char *fd_passwd = NULL;
static char *next_pw = NULL;
static char *last_pw = NULL;

#if defined (_WIN32)
static int read_fd = 0;
static int write_fd = 0;
#endif

static void hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k, int create );

int
have_static_passphrase()
{
    if ( opt.use_agent )
        return 0;
    return !!fd_passwd;
}

/****************
 * Set the passphrase to be used for the next query and only for the next
 * one.
 */
void
set_next_passphrase( const char *s )
{
    m_free(next_pw);
    next_pw = NULL;
    if( s ) {
	next_pw = m_alloc_secure( strlen(s)+1 );
	strcpy(next_pw, s );
    }
}

/****************
 * Get the last passphrase used in passphrase_to_dek.
 * Note: This removes the passphrase from this modules and
 * the caller must free the result.  May return NULL:
 */
char *
get_last_passphrase()
{
    char *p = last_pw;
    last_pw = NULL;
    return p;
}


void
read_passphrase_from_fd( int fd )
{
  int i, len;
  char *pw;
  
  if ( opt.use_agent ) 
    { /* Not used but we have to do a dummy read, so that it won't end
         up at the begin of the message if the quite usual trick to
         prepend the passphtrase to the message is used. */
      char buf[1];

      while (!(read (fd, buf, 1) != 1 || *buf == '\n' ))
        ;
      *buf = 0;
      return; 
    }

  if (!opt.batch )
	tty_printf("Reading passphrase from file descriptor %d ...", fd );
  for (pw = NULL, i = len = 100; ; i++ ) 
    {
      if (i >= len-1 ) 
        {
          char *pw2 = pw;
          len += 100;
          pw = m_alloc_secure( len );
          if( pw2 )
            memcpy(pw, pw2, i );
          else
            i=0;
	}
      if (read( fd, pw+i, 1) != 1 || pw[i] == '\n' )
        break;
    }
  pw[i] = 0;
  if (!opt.batch)
    tty_printf("\b\b\b   \n" );

  m_free( fd_passwd );
  fd_passwd = pw;
}

static int
writen ( int fd, const void *buf, size_t nbytes )
{
#if defined (_WIN32)
    DWORD nwritten, nleft = nbytes;
    
    while (nleft > 0) {
    	if ( !WriteFile( (HANDLE)write_fd, buf, nleft, &nwritten, NULL) ) {
    		log_error("write failed: ec=%d\n", (int)GetLastError());
    		return -1;
    	}
    	/*log_info("** WriteFile fd=%d nytes=%d nwritten=%d\n",
    		 write_fd, nbytes, (int)nwritten);*/
    	Sleep(100);
    	
    	nleft -= nwritten;
    	buf = (const BYTE *)buf + nwritten;
    }
#elif defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
    /* not implemented */
#else
    size_t nleft = nbytes;
    int nwritten;

    while( nleft > 0 ) {
        nwritten = write( fd, buf, nleft );
        if( nwritten < 0 ) {
            if ( errno == EINTR )
                nwritten = 0;
            else {
                log_error ( "write() failed: %s\n", strerror (errno) );
                return -1;
            }
        }
        nleft -= nwritten;
        buf = (const char*)buf + nwritten;
    }
#endif
    
    return 0;
}


static int
readn ( int fd, void *buf, size_t buflen, size_t *ret_nread )
{
#if defined (_WIN32)
    DWORD nread, nleft = buflen;
    
    while (nleft > 0) {
    	if ( !ReadFile( (HANDLE)read_fd, buf, nleft, &nread, NULL) ) {
            log_error("read() error: ec=%d\n", (int)GetLastError());
            return -1;
    	}
    	if (!nread || GetLastError() == ERROR_BROKEN_PIPE)
            break;
    	/*log_info("** ReadFile fd=%d buflen=%d nread=%d\n",
          read_fd, buflen, (int)nread);*/
    	Sleep(100);
    	
    	nleft -= nread;
    	buf = (BYTE *)buf + nread;
    }    	
    if (ret_nread)
    	*ret_nread = buflen - nleft;

#elif defined(HAVE_DOSISH_SYSTEM) || defined(__riscos__)
    /* not implemented */
#else
    size_t nleft = buflen;
    int nread;
    char *p;

    p = buf;
    while( nleft > 0 ) {
        nread = read ( fd, buf, nleft );
        if( nread < 0 ) {
            if (nread == EINTR)
                nread = 0;
            else {
                log_error ( "read() error: %s\n", strerror (errno) );
                return -1;
            }
        }
        else if( !nread )
            break; /* EOF */
        nleft -= nread;
        buf = (char*)buf + nread;
    }
    if( ret_nread )
        *ret_nread = buflen - nleft;
#endif
    
    return 0;
}

/* read an entire line */
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
          return -1; /* read error */
        }
      else if (!n)
        {
          return -1; /* incomplete line */
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
                    This function is just a temporary hack until we use
                    the assuna lib in gpg.  So it is okay to forget
                    about pending bytes */
        }
    }

  return nread; 
}



#if !defined (__riscos__)

#if !defined (_WIN32)
/* For the new Assuan protocol we may have to send options */
static int
agent_send_option (int fd, const char *name, const char *value)
{
  char buf[200];
  int nread;
  char *line;
  int i; 
  
  line = m_alloc (7 + strlen (name) + 1 + strlen (value) + 2);
  strcpy (stpcpy (stpcpy (stpcpy (
                     stpcpy (line, "OPTION "), name), "="), value), "\n");
  i = writen (fd, line, strlen (line));
  m_free (line);
  if (i)
    return -1;
  
  /* get response */
  nread = readline (fd, buf, DIM(buf)-1);
  if (nread < 3)
    return -1;
  
  if (buf[0] == 'O' && buf[1] == 'K' && (buf[2] == ' ' || buf[2] == '\n')) 
    return 0; /* okay */

  return -1;
}

static int 
agent_send_all_options (int fd)
{
  char *dft_display = NULL;
  const char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
  char *old_lc = NULL;
  char *dft_lc = NULL;
  int rc = 0;

  dft_display = getenv ("DISPLAY");
  if (opt.display || dft_display)
    {
      if (agent_send_option (fd, "display",
                             opt.display ? opt.display : dft_display))
        return -1;
    }

  if (!opt.ttyname)
    {
      dft_ttyname = getenv ("GPG_TTY");
      if ((!dft_ttyname || !*dft_ttyname) && tty_get_ttyname ())
        dft_ttyname = tty_get_ttyname ();
    }
  if (opt.ttyname || dft_ttyname)
    {
      if (agent_send_option (fd, "ttyname",
                             opt.ttyname ? opt.ttyname : dft_ttyname))
        return -1;
    }

  dft_ttytype = getenv ("TERM");
  if (opt.ttytype || (dft_ttyname && dft_ttytype))
    {
      if (agent_send_option (fd, "ttytype",
                             opt.ttyname ? opt.ttytype : dft_ttytype))
        return -1;
    }

#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale (LC_CTYPE, NULL);
  if (old_lc)
    old_lc = m_strdup (old_lc);
  dft_lc = setlocale (LC_CTYPE, "");
#endif
  if (opt.lc_ctype || (dft_ttyname && dft_lc))
    {
      rc = agent_send_option (fd, "lc-ctype",
                              opt.lc_ctype ? opt.lc_ctype : dft_lc);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      m_free (old_lc);
    }
#endif
  if (rc)
    return rc;

#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale (LC_MESSAGES, NULL);
  if (old_lc)
    old_lc = m_strdup (old_lc);
  dft_lc = setlocale (LC_MESSAGES, "");
#endif
  if (opt.lc_messages || (dft_ttyname && dft_lc))
    {
      rc = agent_send_option (fd, "lc-messages",
                              opt.lc_messages ? opt.lc_messages : dft_lc);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      m_free (old_lc);
    }
#endif
  return rc;
}
#endif /*!_WIN32*/


/*
 * Open a connection to the agent and send the magic string
 * Returns: -1 on error or an filedescriptor for urther processing
 */

static int
agent_open (int *ret_prot)
{
#if defined (_WIN32)
    int fd;
    char *infostr, *p;
    HANDLE h;
    char pidstr[128];

    *ret_prot = 0;
    if ( !(infostr = read_w32_registry_string(NULL, "Software\\GNU\\GnuPG",
                                              "agentPID")) 
         || *infostr == '0') {
    	log_error( _("gpg-agent is not available in this session\n"));
    	return -1;
    }
    free(infostr);
    
    sprintf(pidstr, "%u", (unsigned int)GetCurrentProcessId());
    if (write_w32_registry_string(NULL, "Software\\GNU\\GnuPG",
                                  "agentCID", pidstr)) {
        log_error( _("can't set client pid for the agent\n") );
        return -1;
    }
    h = OpenEvent(EVENT_ALL_ACCESS, FALSE, "gpg_agent");
    SetEvent(h);
    Sleep(50); /* some time for the server */ 
    if ( !(p = read_w32_registry_string(NULL, "Software\\GNU\\GnuPG",
                                        "agentReadFD")) ) {
    	log_error( _("can't get server read FD for the agent\n") );
    	return -1;
    }
    read_fd = atol(p);
    free(p);    
    if ( !(p = read_w32_registry_string(NULL, "Software\\GNU\\GnuPG",
                                        "agentWriteFD")) ) {
    	log_error ( _("can't get server write FD for the agent\n") );
    	return -1;
    }
    write_fd = atol(p);
    free(p);
    fd = 0;

    if ( writen ( fd, "GPGA\0\0\0\x01", 8 ) ) {
        fd = -1;
    }
#else /* Posix */

    int fd;
    char *infostr, *p;
    struct sockaddr_un client_addr;
    size_t len;
    int prot;

    if (opt.gpg_agent_info)
      infostr = m_strdup (opt.gpg_agent_info);
    else
      {
        infostr = getenv ( "GPG_AGENT_INFO" );
        if ( !infostr ) {
          log_error (_("gpg-agent is not available in this session\n"));
          opt.use_agent = 0;
          return -1;
        }
        infostr = m_strdup ( infostr );
      }

    if ( !(p = strchr ( infostr, ':')) || p == infostr
         || (p-infostr)+1 >= sizeof client_addr.sun_path ) {
        log_error( _("malformed GPG_AGENT_INFO environment variable\n"));
        m_free (infostr );
        opt.use_agent = 0;
        return -1;
    }
    *p++ = 0;
    /* See whether this is the new gpg-agent using the Assuna protocl.
       This agent identifies itself by have an info string with a
       version number in the 3rd field. */
    while (*p && *p != ':')
      p++;
    prot = *p? atoi (p+1) : 0;
    if ( prot < 0 || prot > 1) {
        log_error (_("gpg-agent protocol version %d is not supported\n"),prot);
        m_free (infostr );
        opt.use_agent = 0;
        return -1;
    }
    *ret_prot = prot;
       
    if( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ) {
        log_error ("can't create socket: %s\n", strerror(errno) );
        m_free (infostr );
        opt.use_agent = 0;
        return -1;
    }
    
    memset( &client_addr, 0, sizeof client_addr );
    client_addr.sun_family = AF_UNIX;
    strcpy( client_addr.sun_path, infostr );
    len = offsetof (struct sockaddr_un, sun_path)
        + strlen(client_addr.sun_path) + 1;
    
    if( connect( fd, (struct sockaddr*)&client_addr, len ) == -1 ) {
        log_error ( _("can't connect to `%s': %s\n"), 
                    infostr, strerror (errno) );
        m_free (infostr );
        close (fd );
        opt.use_agent = 0;
        return -1;
    }
    m_free (infostr);

    if (!prot) {
        if ( writen ( fd, "GPGA\0\0\0\x01", 8 ) ) {
          close (fd);
          fd = -1;
        }
    }
    else { /* assuan based gpg-agent */
      char line[200];
      int nread;

      nread = readline (fd, line, DIM(line));
      if (nread < 3 || !(line[0] == 'O' && line[1] == 'K'
                         && (line[2] == '\n' || line[2] == ' ')) ) {
        log_error ( _("communication problem with gpg-agent\n"));
        close (fd );
        opt.use_agent = 0;
        return -1;
      }

      if (agent_send_all_options (fd)) {
        log_error (_("problem with the agent - disabling agent use\n"));
        close (fd);
        opt.use_agent = 0;
        return -1;
      }
        
    }
#endif

    return fd;
}


static void
agent_close ( int fd )
{
#if defined (_WIN32)
    HANDLE h = OpenEvent(EVENT_ALL_ACCESS, FALSE, "gpg_agent");
    ResetEvent(h);
#else
    close (fd);
#endif
}
#endif /* !__riscos__ */



/*
 * Ask the GPG Agent for the passphrase.
 * Mode 0:  Allow cached passphrase
 *      1:  No cached passphrase FIXME: Not really implemented
 *      2:  Ditto, but change the text to "repeat entry"
 *
 * Note that TRYAGAIN_TEXT must not be translated.  If canceled is not
 * NULL, the function does set it to 1 if the user canceled the
 * operation.
 */
static char *
agent_get_passphrase ( u32 *keyid, int mode, const char *tryagain_text,
                       int *canceled)
{
#if defined(__riscos__)
  return NULL;
#else
  size_t n;
  char *atext = NULL;
  char buf[50];
  int fd = -1;
  int nread;
  u32 reply;
  char *pw = NULL;
  PKT_public_key *pk = m_alloc_clear( sizeof *pk );
  byte fpr[MAX_FINGERPRINT_LEN];
  int have_fpr = 0;
  int prot;
  char *orig_codeset = NULL;

  if (canceled)
    *canceled = 0;

#if MAX_FINGERPRINT_LEN < 20
#error agent needs a 20 byte fingerprint
#endif

  memset (fpr, 0, MAX_FINGERPRINT_LEN );
  if( keyid && get_pubkey( pk, keyid ) )
    {
      free_public_key( pk );      
      pk = NULL; /* oops: no key for some reason */
    }
  
#ifdef ENABLE_NLS
  /* The Assuan agent protol requires us to trasnmit utf-8 strings */
  orig_codeset = bind_textdomain_codeset (PACKAGE, NULL);
#ifdef HAVE_LANGINFO_CODESET
  if (!orig_codeset)
    orig_codeset = nl_langinfo (CODESET);
#endif
  if (orig_codeset)
    { /* We only switch when we are able to restore the codeset later. */
      orig_codeset = m_strdup (orig_codeset);
      if (!bind_textdomain_codeset (PACKAGE, "utf-8"))
        orig_codeset = NULL; 
    }
#endif

  if ( (fd = agent_open (&prot)) == -1 ) 
    goto failure;

  if ( !mode && pk && keyid )
    { 
      char *uid;
      size_t uidlen;
      const char *algo_name = pubkey_algo_to_string ( pk->pubkey_algo );
      const char *timestr;
      char *maink;
      const char *fmtstr;
      
      if ( !algo_name )
        algo_name = "?";
      
      fmtstr = _(" (main key ID %08lX)");
      maink = m_alloc ( strlen (fmtstr) + 20 );
      if( keyid[2] && keyid[3] && keyid[0] != keyid[2] 
          && keyid[1] != keyid[3] )
        sprintf( maink, fmtstr, (ulong)keyid[3] );
      else
        *maink = 0;
      
      uid = get_user_id ( keyid, &uidlen ); 
      timestr = strtimestamp (pk->timestamp);
      fmtstr = _("You need a passphrase to unlock the"
                 " secret key for user:\n"
                 "\"%.*s\"\n"
                 "%u-bit %s key, ID %08lX, created %s%s\n" );
      atext = m_alloc ( 100 + strlen (fmtstr)  
                        + uidlen + 15 + strlen(algo_name) + 8
                        + strlen (timestr) + strlen (maink) );
      sprintf (atext, fmtstr,
               uidlen, uid,
               nbits_from_pk (pk), algo_name, (ulong)keyid[1], timestr,
               maink  );
      m_free (uid);
      m_free (maink);
      
      { 
        size_t dummy;
        fingerprint_from_pk( pk, fpr, &dummy );
        have_fpr = 1;
      }
      
    }
  else if (mode == 2 ) 
    atext = m_strdup ( _("Repeat passphrase\n") );
  else
    atext = m_strdup ( _("Enter passphrase\n") );
                
  if (!prot)
    { /* old style protocol */
      n = 4 + 20 + strlen (atext);
      u32tobuf (buf, n );
      u32tobuf (buf+4, GPGA_PROT_GET_PASSPHRASE );
      memcpy (buf+8, fpr, 20 );
      if ( writen ( fd, buf, 28 ) || writen ( fd, atext, strlen (atext) ) ) 
        goto failure;
      m_free (atext); atext = NULL;
      
      /* get response */
      if ( readn ( fd, buf, 12, &nread ) ) 
        goto failure;
      
      if ( nread < 8 ) 
        {
          log_error ( "response from agent too short\n" );
          goto failure;
        }
      n = buftou32 ( buf );
      reply = buftou32 ( buf + 4 );
      if ( reply == GPGA_PROT_GOT_PASSPHRASE ) 
        {
          size_t pwlen;
          size_t nn;
          
          if ( nread < 12 || n < 8 ) 
            {
              log_error ( "response from agent too short\n" );
              goto failure;
            }
          pwlen = buftou32 ( buf + 8 );
          nread -= 12;
          n -= 8;
          if ( pwlen > n || n > 1000 ) 
            {
              log_error (_("passphrase too long\n"));
              /* or protocol error */
              goto failure;
            }
          /* we read the whole block in one chunk to give no hints
           * on how long the passhrase actually is - this wastes some bytes
           * but because we already have this padding we should not loosen
           * this by issuing 2 read calls */
          pw = m_alloc_secure ( n+1 );
          if ( readn ( fd, pw, n, &nn ) )
            goto failure;
          if ( n != nn ) 
            {
              log_error (_("invalid response from agent\n"));
              goto failure;           
            }
          pw[pwlen] = 0; /* make a C String */
          agent_close (fd);
          free_public_key( pk );
#ifdef ENABLE_NLS
          if (orig_codeset)
            bind_textdomain_codeset (PACKAGE, orig_codeset);
#endif
          m_free (orig_codeset);
          return pw;
        }
      else if ( reply == GPGA_PROT_CANCELED ) 
        {
          log_info ( _("cancelled by user\n") );
          if (canceled)
            *canceled = 1;
        }
      else 
        log_error ( _("problem with the agent: agent returns 0x%lx\n"),
                    (ulong)reply );
    }
  else
    { /* The new Assuan protocol */
      char *line, *p;
      const unsigned char *s;
      int i; 

      if (!tryagain_text)
        tryagain_text = "X";
      else
        tryagain_text = _(tryagain_text);

      /* We allocate 2 time the needed space for atext so that there
         is nenough space for escaping */
      line = m_alloc (15 + 46 
                      +  3*strlen (tryagain_text) + 3*strlen (atext) + 2);
      strcpy (line, "GET_PASSPHRASE ");
      p = line+15;
      if (!mode && have_fpr)
        {
          for (i=0; i < 20; i++, p +=2 )
            sprintf (p, "%02X", fpr[i]);
        }
      else
        *p++ = 'X'; /* no caching */
      *p++ = ' ';
      for (i=0, s=tryagain_text; *s; s++)
        {
          if (*s < ' ' || *s == '+')
            {
              sprintf (p, "%%%02X", *s);
              p += 3;
            }
          else if (*s == ' ')
            *p++ = '+';
          else
            *p++ = *s;
        }
      *p++ = ' ';
      *p++ = 'X'; /* Use the standard prompt */
      *p++ = ' ';
      /* copy description */
      for (i=0, s= atext; *s; s++)
        {
          if (*s < ' ' || *s == '+')
            {
              sprintf (p, "%%%02X", *s);
              p += 3;
            }
          else if (*s == ' ')
            *p++ = '+';
          else
            *p++ = *s;
        }
      *p++ = '\n';
      i = writen (fd, line, p - line);
      m_free (line);
      if (i)
        goto failure;
      m_free (atext); atext = NULL;
      
      /* get response */
      pw = m_alloc_secure (500);
      nread = readline (fd, pw, 499);
      if (nread < 3)
        goto failure;
      
      if (pw[0] == 'O' && pw[1] == 'K' && pw[2] == ' ') 
        { /* we got a passphrase - convert it back from hex */
          size_t pwlen = 0;

          for (i=3; i < nread && hexdigitp (pw+i); i+=2)
            pw[pwlen++] = xtoi_2 (pw+i);
          pw[pwlen] = 0; /* make a C String */
          agent_close (fd);
          free_public_key( pk );
#ifdef ENABLE_NLS
          if (orig_codeset)
            bind_textdomain_codeset (PACKAGE, orig_codeset);
#endif
          m_free (orig_codeset);
          return pw;
        }
      else if (nread > 7 && !memcmp (pw, "ERR 111", 7)
               && (pw[7] == ' ' || pw[7] == '\n') ) 
        {
          log_info (_("cancelled by user\n") );
          if (canceled)
            *canceled = 1;
        }
      else 
        {
          log_error (_("problem with the agent - disabling agent use\n"));
          opt.use_agent = 0;
        }
    }
      
        
 failure:
#ifdef ENABLE_NLS
  if (orig_codeset)
    bind_textdomain_codeset (PACKAGE, orig_codeset);
#endif
  m_free (atext);
  if ( fd != -1 )
    agent_close (fd);
  m_free (pw );
  free_public_key( pk );
  
  return NULL;
#endif /* Posix or W32 */
}

/*
 * Clear the cached passphrase
 */
void
passphrase_clear_cache ( u32 *keyid, int algo )
{
#if defined(__riscos__)
  return ;
#else
  size_t n;
  char buf[200];
  int fd = -1;
  size_t nread;
  u32 reply;
  PKT_public_key *pk;
  byte fpr[MAX_FINGERPRINT_LEN];
  int prot;
  
#if MAX_FINGERPRINT_LEN < 20
#error agent needs a 20 byte fingerprint
#endif
    
  if (!opt.use_agent)
    return;
  
  pk = m_alloc_clear ( sizeof *pk );
  memset (fpr, 0, MAX_FINGERPRINT_LEN );
  if( !keyid || get_pubkey( pk, keyid ) )
    {
      log_debug ("oops, no key in passphrase_clear_cache\n");
      goto failure; /* oops: no key for some reason */
    }
  
  {
    size_t dummy;
    fingerprint_from_pk( pk, fpr, &dummy );
  }
    
  if ( (fd = agent_open (&prot)) == -1 ) 
    goto failure;

  if (!prot)
    {
      n = 4 + 20;
      u32tobuf (buf, n );
      u32tobuf (buf+4, GPGA_PROT_CLEAR_PASSPHRASE );
      memcpy (buf+8, fpr, 20 );
      if ( writen ( fd, buf, 28 ) )  
        goto failure;
      
      /* get response */
      if ( readn ( fd, buf, 8, &nread ) ) 
        goto failure;
      
      if ( nread < 8 ) {
        log_error ( "response from agent too short\n" );
        goto failure;
      }
      
      reply = buftou32 ( buf + 4 );
      if ( reply != GPGA_PROT_OKAY && reply != GPGA_PROT_NO_PASSPHRASE )
        {
          log_error ( _("problem with the agent: agent returns 0x%lx\n"),
                      (ulong)reply );
        }
    }
  else 
    { /* The assuan protocol */
      char *line, *p;
      int i; 

      line = m_alloc (17 + 40 + 2);
      strcpy (line, "CLEAR_PASSPHRASE ");
      p = line+17;
      for (i=0; i < 20; i++, p +=2 )
        sprintf (p, "%02X", fpr[i]);
      *p++ = '\n';
      i = writen (fd, line, p - line);
      m_free (line);
      if (i)
        goto failure;
      
      /* get response */
      nread = readline (fd, buf, DIM(buf)-1);
      if (nread < 3)
        goto failure;
      
      if (buf[0] == 'O' && buf[1] == 'K' && (buf[2] == ' ' || buf[2] == '\n')) 
        ;
      else 
        {
          log_error (_("problem with the agent - disabling agent use\n"));
          opt.use_agent = 0;
        }
    }
        
 failure:
  if (fd != -1)
    agent_close (fd);
  free_public_key( pk );
#endif /* Posix or W32 */
}




/****************
 * Ask for a passphrase and return that string.
 */
char *
ask_passphrase (const char *description,
                const char *promptid,
                const char *prompt, int *canceled)
{
  char *pw = NULL;
  
  if (canceled)
    *canceled = 0;

  if (is_status_enabled())
    write_status_text( STATUS_NEED_PASSPHRASE_SYM, "0 0 0");

  if (!opt.batch && description)
    tty_printf ("\n%s\n",description);
               
 agent_died:
  if ( opt.use_agent ) 
    {
      pw = agent_get_passphrase (NULL, 0,  description, canceled );
      if (!pw)
        {
          if (!opt.use_agent)
            goto agent_died;
          pw = NULL;
        }
    }
  else if (fd_passwd) 
    {
      pw = m_alloc_secure (strlen(fd_passwd)+1);
      strcpy (pw, fd_passwd);
    }
  else if (opt.batch)
    {
      log_error(_("can't query password in batchmode\n"));
      pw = NULL;
    }
  else {
    pw = cpr_get_hidden(promptid? promptid : "passphrase.ask",
                        prompt?prompt : _("Enter passphrase: ") );
    tty_kill_prompt();
  }

  if (!pw || !*pw)
    write_status( STATUS_MISSING_PASSPHRASE );

  return pw;
}



DEK *
passphrase_to_dek( u32 *keyid, int pubkey_algo,
		   int cipher_algo, STRING2KEY *s2k, int mode,
                   const char *tryagain_text, int *canceled)
{
    char *pw = NULL;
    DEK *dek;
    STRING2KEY help_s2k;

    if (canceled)
      *canceled = 0;

    if( !s2k ) {
        /* This is used for the old rfc1991 mode 
         * Note: This must match the code in encode.c with opt.rfc1991 set */
	s2k = &help_s2k;
	s2k->mode = 0;
	s2k->hash_algo = opt.s2k_digest_algo;
    }

    if( !next_pw && is_status_enabled() ) {
	char buf[50];

	if( keyid ) {
            u32 used_kid[2];
            char *us;

	    if( keyid[2] && keyid[3] ) {
                used_kid[0] = keyid[2];
                used_kid[1] = keyid[3];
            }
            else {
                used_kid[0] = keyid[0];
                used_kid[1] = keyid[1];
            }

            us = get_long_user_id_string( keyid );
            write_status_text( STATUS_USERID_HINT, us );
            m_free(us);

	    sprintf( buf, "%08lX%08lX %08lX%08lX %d 0",
                     (ulong)keyid[0], (ulong)keyid[1],
                     (ulong)used_kid[0], (ulong)used_kid[1],
                     pubkey_algo );
                     
	    write_status_text( STATUS_NEED_PASSPHRASE, buf );
	}
	else {
	    sprintf( buf, "%d %d %d", cipher_algo, s2k->mode, s2k->hash_algo );
	    write_status_text( STATUS_NEED_PASSPHRASE_SYM, buf );
	}
    }

    if( keyid && !opt.batch && !next_pw && mode!=1 ) {
	PKT_public_key *pk = m_alloc_clear( sizeof *pk );
	size_t n;
	char *p;

	tty_printf(_("\nYou need a passphrase to unlock the secret key for\n"
		     "user: \"") );
	p = get_user_id( keyid, &n );
	tty_print_utf8_string( p, n );
	m_free(p);
	tty_printf("\"\n");

	if( !get_pubkey( pk, keyid ) ) {
	    const char *s = pubkey_algo_to_string( pk->pubkey_algo );
	    tty_printf( _("%u-bit %s key, ID %08lX, created %s"),
		       nbits_from_pk( pk ), s?s:"?", (ulong)keyid[1],
		       strtimestamp(pk->timestamp) );
	    if( keyid[2] && keyid[3] && keyid[0] != keyid[2]
				     && keyid[1] != keyid[3] )
		tty_printf( _(" (main key ID %08lX)"), (ulong)keyid[3] );
	    tty_printf("\n");
	}

	tty_printf("\n");
	free_public_key( pk );
    }

 agent_died:
    if( next_pw ) {
	pw = next_pw;
	next_pw = NULL;
    }
    else if ( opt.use_agent ) {
	pw = agent_get_passphrase ( keyid, mode == 2? 1: 0,
                                    tryagain_text, canceled );
        if (!pw)
          {
            if (!opt.use_agent)
              goto agent_died;
            pw = m_strdup ("");
          }
        if( *pw && mode == 2 ) {
	    char *pw2 = agent_get_passphrase ( keyid, 2, NULL, canceled );
            if (!pw2)
              {
                if (!opt.use_agent)
                  {
                    m_free (pw);
                    pw = NULL;
                    goto agent_died;
                  }
                pw2 = m_strdup ("");
              }
	    if( strcmp(pw, pw2) ) {
		m_free(pw2);
		m_free(pw);
		return NULL;
	    }
	    m_free(pw2);
	}
    }
    else if( fd_passwd ) {
	pw = m_alloc_secure( strlen(fd_passwd)+1 );
	strcpy( pw, fd_passwd );
    }
    else if( opt.batch ) {
	log_error(_("can't query password in batchmode\n"));
	pw = m_strdup( "" ); /* return an empty passphrase */
    }
    else {
	pw = cpr_get_hidden("passphrase.enter", _("Enter passphrase: ") );
	tty_kill_prompt();
	if( mode == 2 && !cpr_enabled() ) {
	    char *pw2 = cpr_get_hidden("passphrase.repeat",
				       _("Repeat passphrase: ") );
	    tty_kill_prompt();
	    if( strcmp(pw, pw2) ) {
		m_free(pw2);
		m_free(pw);
		return NULL;
	    }
	    m_free(pw2);
	}
    }

    if( !pw || !*pw )
	write_status( STATUS_MISSING_PASSPHRASE );

    dek = m_alloc_secure_clear ( sizeof *dek );
    dek->algo = cipher_algo;
    if( !*pw && mode == 2 )
	dek->keylen = 0;
    else
	hash_passphrase( dek, pw, s2k, mode==2 );
    m_free(last_pw);
    last_pw = pw;
    return dek;
}


/****************
 * Hash a passphrase using the supplied s2k. If create is true, create
 * a new salt or what else must be filled into the s2k for a new key.
 * always needs: dek->algo, s2k->mode, s2k->hash_algo.
 */
static void
hash_passphrase( DEK *dek, char *pw, STRING2KEY *s2k, int create )
{
    MD_HANDLE md;
    int pass, i;
    int used = 0;
    int pwlen = strlen(pw);

    assert( s2k->hash_algo );
    dek->keylen = cipher_get_keylen( dek->algo ) / 8;
    if( !(dek->keylen > 0 && dek->keylen <= DIM(dek->key)) )
	BUG();

    md = md_open( s2k->hash_algo, 1);
    for(pass=0; used < dek->keylen ; pass++ ) {
	if( pass ) {
            md_reset(md);
	    for(i=0; i < pass; i++ ) /* preset the hash context */
		md_putc(md, 0 );
	}

	if( s2k->mode == 1 || s2k->mode == 3 ) {
	    int len2 = pwlen + 8;
	    ulong count = len2;

	    if( create && !pass ) {
		randomize_buffer(s2k->salt, 8, 1);
		if( s2k->mode == 3 )
		    s2k->count = 96; /* 65536 iterations */
	    }

	    if( s2k->mode == 3 ) {
		count = (16ul + (s2k->count & 15)) << ((s2k->count >> 4) + 6);
		if( count < len2 )
		    count = len2;
	    }
	    /* a little bit complicated because we need a ulong for count */
	    while( count > len2 ) { /* maybe iterated+salted */
		md_write( md, s2k->salt, 8 );
		md_write( md, pw, pwlen );
		count -= len2;
	    }
	    if( count < 8 )
		md_write( md, s2k->salt, count );
	    else {
		md_write( md, s2k->salt, 8 );
		count -= 8;
                md_write( md, pw, count );
	    }
	}
	else
	    md_write( md, pw, pwlen );
	md_final( md );
	i = md_digest_length( s2k->hash_algo );
	if( i > dek->keylen - used )
	    i = dek->keylen - used;
	memcpy( dek->key+used, md_read(md, s2k->hash_algo), i );
	used += i;
    }
    md_close(md);
}

