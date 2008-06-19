/* sysutils.c -  system helpers
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004,
 *               2007, 2008  Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#ifdef WITHOUT_GNU_PTH /* Give the Makefile a chance to build without Pth.  */
# undef HAVE_PTH
# undef USE_GNU_PTH
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_STAT
# include <sys/stat.h>
#endif
#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
# include <asm/sysinfo.h>
# include <asm/unistd.h>
#endif
#ifdef HAVE_SETRLIMIT
# include <time.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif
#ifdef HAVE_W32_SYSTEM
# define WINVER 0x0500  /* Required for AllowSetForegroundWindow.  */
# include <windows.h>
#endif
#ifdef HAVE_PTH      
# include <pth.h>
#endif
#include <fcntl.h>

#include "util.h"
#include "i18n.h"

#include "sysutils.h"

#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))


#if defined(__linux__) && defined(__alpha__) && __GLIBC__ < 2
#warning using trap_unaligned
static int
setsysinfo(unsigned long op, void *buffer, unsigned long size,
		     int *start, void *arg, unsigned long flag)
{
    return syscall(__NR_osf_setsysinfo, op, buffer, size, start, arg, flag);
}

void
trap_unaligned(void)
{
    unsigned int buf[2];

    buf[0] = SSIN_UACPROC;
    buf[1] = UAC_SIGBUS | UAC_NOPRINT;
    setsysinfo(SSI_NVPAIRS, buf, 1, 0, 0, 0);
}
#else
void
trap_unaligned(void)
{  /* dummy */
}
#endif


int
disable_core_dumps (void)
{
#ifdef HAVE_DOSISH_SYSTEM
    return 0;
#else
# ifdef HAVE_SETRLIMIT
    struct rlimit limit;

    /* We only set the current limit unless we were not able to
       retrieve the old value. */
    if (getrlimit (RLIMIT_CORE, &limit))
      limit.rlim_max = 0;
    limit.rlim_cur = 0;
    if( !setrlimit (RLIMIT_CORE, &limit) )
	return 0;
    if( errno != EINVAL && errno != ENOSYS )
	log_fatal (_("can't disable core dumps: %s\n"), strerror(errno) );
#endif
    return 1;
#endif
}

int
enable_core_dumps (void)
{
#ifdef HAVE_DOSISH_SYSTEM
    return 0;
#else
# ifdef HAVE_SETRLIMIT
    struct rlimit limit;

    if (getrlimit (RLIMIT_CORE, &limit))
      return 1;
    limit.rlim_cur = limit.rlim_max;
    setrlimit (RLIMIT_CORE, &limit);
    return 1; /* We always return true because this function is
                 merely a debugging aid. */
# endif
    return 1;
#endif
}



/* Return a string which is used as a kind of process ID */
const byte *
get_session_marker( size_t *rlen )
{
    static byte marker[SIZEOF_UNSIGNED_LONG*2];
    static int initialized;

    if ( !initialized ) {
        volatile ulong aa, bb; /* we really want the uninitialized value */
        ulong a, b;

        initialized = 1;
        /* Although this marker is guessable it is not easy to use
         * for a faked control packet because an attacker does not
         * have enough control about the time the verification does 
         * take place.  Of course, we can add just more random but 
         * than we need the random generator even for verification
         * tasks - which does not make sense. */
        a = aa ^ (ulong)getpid();
        b = bb ^ (ulong)time(NULL);
        memcpy( marker, &a, SIZEOF_UNSIGNED_LONG );
        memcpy( marker+SIZEOF_UNSIGNED_LONG, &b, SIZEOF_UNSIGNED_LONG );
    }
    *rlen = sizeof(marker);
    return marker;
}


#if 0 /* not yet needed - Note that this will require inclusion of
         cmacros.am in Makefile.am */
int
check_permissions(const char *path,int extension,int checkonly)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  char *tmppath;
  struct stat statbuf;
  int ret=1;
  int isdir=0;

  if(opt.no_perm_warn)
    return 0;

  if(extension && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(GNUPG_LIBDIR,path,NULL);
    }
  else
    tmppath=m_strdup(path);

  /* It's okay if the file doesn't exist */
  if(stat(tmppath,&statbuf)!=0)
    {
      ret=0;
      goto end;
    }

  isdir=S_ISDIR(statbuf.st_mode);

  /* Per-user files must be owned by the user.  Extensions must be
     owned by the user or root. */
  if((!extension && statbuf.st_uid != getuid()) ||
     (extension && statbuf.st_uid!=0 && statbuf.st_uid!=getuid()))
    {
      if(!checkonly)
	log_info(_("Warning: unsafe ownership on %s \"%s\"\n"),
		 isdir?"directory":extension?"extension":"file",path);
      goto end;
    }

  /* This works for both directories and files - basically, we don't
     care what the owner permissions are, so long as the group and
     other permissions are 0 for per-user files, and non-writable for
     extensions. */
  if((extension && (statbuf.st_mode & (S_IWGRP|S_IWOTH)) !=0) ||
     (!extension && (statbuf.st_mode & (S_IRWXG|S_IRWXO)) != 0))
    {
      char *dir;

      /* However, if the directory the directory/file is in is owned
         by the user and is 700, then this is not a problem.
         Theoretically, we could walk this test up to the root
         directory /, but for the sake of sanity, I'm stopping at one
         level down. */

      dir= make_dirname (tmppath);
      if(stat(dir,&statbuf)==0 && statbuf.st_uid==getuid() &&
	 S_ISDIR(statbuf.st_mode) && (statbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
	{
	  xfree (dir);
	  ret=0;
	  goto end;
	}

      m_free(dir);

      if(!checkonly)
	log_info(_("Warning: unsafe permissions on %s \"%s\"\n"),
		 isdir?"directory":extension?"extension":"file",path);
      goto end;
    }

  ret=0;

 end:
  m_free(tmppath);

  return ret;

#endif /* HAVE_STAT && !HAVE_DOSISH_SYSTEM */

  return 0;
}
#endif


/* Wrapper around the usual sleep fucntion.  This one won't wake up
   before the sleep time has really elapsed.  When build with Pth it
   merely calls pth_sleep and thus suspends only the current
   thread. */
void
gnupg_sleep (unsigned int seconds)
{
#ifdef HAVE_PTH
  /* With Pth we force a regular sleep for seconds == 0 so that also
     the process will give up its timeslot.  */
  if (!seconds)
    {
# ifdef HAVE_W32_SYSTEM    
      Sleep (0);
# else
      sleep (0);
# endif
    }
  pth_sleep (seconds);
#else
  /* Fixme:  make sure that a sleep won't wake up to early.  */
# ifdef HAVE_W32_SYSTEM    
  Sleep (seconds*1000);
# else
  sleep (seconds);
# endif
#endif
}



/* Handle translation.  On W32, we provide handle values on the
   command line directly and using special file names such as
   "-&HANDLE".  However, in GPGME we can not directly inherit the
   handles as this may interfere with other components in a
   multithreaded application.  Thus, we inject the handles after
   creating the GPG process.  The problem is that the handle numbers
   change at injection, but it is too late to change the command line.
   Hence this hack, which allows us to translate the handle values
   in the command line to their new values after injection.

   Handles that must be translated are those occuring in special file
   names (see iobuf.c::check_special_filename) as well as those given
   directly to options (see translate_sys2libc_fd_int).  */

/* For W32, we may have to translate handle values given on the
   command line.  */
#define FD_TRANSLATE_MAX 8
static struct
{
  int from;
  int to;
} fd_translate[FD_TRANSLATE_MAX];

/* Number of entries used in fd_translate.  */
static int fd_translate_len;


/* Initialize the fd translation table.  This reads one line from
   stdin which is expected to be in the format "FROM TO [...]" where
   each "FROM TO" pair are two handle numbers.  Handle number FROM on
   the command line is translated to handle number TO.  

   Note that this function may be called while still being setuid.  */
void
translate_table_init (void)
{
  /* Hold roughly 8 pairs of 64 bit numbers in hex notation:
     "0xFEDCBA9876543210 0xFEDCBA9876543210".  8*19*2 - 1 = 303.  This
     plans ahead for a time where a HANDLE is 64 bit.  */
#define TRANS_MAX 350
  char line[TRANS_MAX + 1];
  char *linep;
  int idx;
  int res;
  int newl = 0;

  /* We always read one line from stdin.  */
  for (idx = 0; idx < TRANS_MAX; idx++)
    {
      do
        res = read (0, &line[idx], 1);
      while (res == -1 && errno == EINTR);
      if (res != 1)
	break;
      if (line[idx] == '\n')
	{
	  newl = 1;
	  break;
	}
    }
  if (!newl)
    {
      char buf[1];
      do
        {
          do
            res = read (0, buf, 1);
          while (res == -1 && errno == EINTR);
        }
      while (res == 1 && *buf != '\n');
    }

  line[idx] = '\0';
  linep = line;

  /* Now start to read mapping pairs.  */
  for (idx = 0; idx < FD_TRANSLATE_MAX; idx++)
    {
      unsigned long from;
      unsigned long to;
      char *tail;

      while (spacep (linep))
	linep++;
      if (*linep == '\0')
	break;
      from = strtoul (linep, &tail, 0);
      if (tail == NULL || ! (*tail == '\0' || spacep (tail)))
	break;
      linep = tail;

      while (spacep (linep))
	linep++;
      if (*linep == '\0')
	break;
      to = strtoul (linep, &tail, 0);
      if (tail == NULL || ! (*tail == '\0' || spacep (tail)))
	break;
      linep = tail;

      fd_translate[idx].from = from;
      fd_translate[idx].to = to;
      fd_translate_len++;
    }
}


/* Translate a handle number.  */
int
translate_table_lookup (int fd)
{
  int idx;

  for (idx = 0; idx < fd_translate_len; idx++)
    if (fd_translate[idx].from == fd)
      return fd_translate[idx].to;
  return fd;
}


/* This function is a NOP for POSIX systems but required under Windows
   as the file handles as returned by OS calls (like CreateFile) are
   different from the libc file descriptors (like open). This function
   translates system file handles to libc file handles.  FOR_WRITE
   gives the direction of the handle.  */
int
translate_sys2libc_fd (gnupg_fd_t fd, int for_write)
{
#ifdef HAVE_W32_SYSTEM
  int x;

  if (fd == GNUPG_INVALID_FD)
    return -1;
  
  /* Note that _open_osfhandle is currently defined to take and return
     a long.  */
  x = _open_osfhandle ((long)fd, for_write ? 1 : 0);
  if (x == -1)
    log_error ("failed to translate osfhandle %p\n", (void *) fd);
  return x;
#else /*!HAVE_W32_SYSTEM */
  return fd;
#endif
}


/* This is the same as translate_sys2libc_fd but takes an integer
   which is assumed to be such an system handle.  */
int
translate_sys2libc_fd_int (int fd, int for_write)
{
#ifdef HAVE_W32_SYSTEM
  if (fd <= 2)
    return fd;	/* Do not do this for error, stdin, stdout, stderr. */

  /* Note: If this function is ever used in a different context than
     option parsing in the main function, a variant that does not do
     translation probable needs to be used.  */
  fd = translate_table_lookup (fd);

  return translate_sys2libc_fd ((void*)fd, for_write);
#else
  fd = translate_table_lookup (fd);
  return fd;
#endif
}



/* Replacement for tmpfile().  This is required because the tmpfile
   function of Windows' runtime library is broken, insecure, ignores
   TMPDIR and so on.  In addition we create a file with an inheritable
   handle.  */
FILE *
gnupg_tmpfile (void)
{
#ifdef HAVE_W32_SYSTEM
  int attempts, n;
  char buffer[MAX_PATH+7+12+1];
  char *name, *p;
  HANDLE file;
  int pid = GetCurrentProcessId ();
  unsigned int value;
  int i;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = TRUE;

  n = GetTempPath (MAX_PATH+1, buffer);
  if (!n || n > MAX_PATH || strlen (buffer) > MAX_PATH)
    {
      errno = ENOENT;
      return NULL;
    }
  p = buffer + strlen (buffer);
  p = stpcpy (p, "_gnupg");
  /* We try to create the directory but don't care about an error as
     it may already exist and the CreateFile would throw an error
     anyway.  */
  CreateDirectory (buffer, NULL);
  *p++ = '\\';
  name = p;
  for (attempts=0; attempts < 10; attempts++)
    {
      p = name;
      value = (GetTickCount () ^ ((pid<<16) & 0xffff0000));
      for (i=0; i < 8; i++)
        {
          *p++ = tohex (((value >> 28) & 0x0f));
          value <<= 4;
        }
      strcpy (p, ".tmp");
      file = CreateFile (buffer,
                         GENERIC_READ | GENERIC_WRITE,
                         0,
                         &sec_attr,
                         CREATE_NEW,
                         FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                         NULL);
      if (file != INVALID_HANDLE_VALUE)
        {
          FILE *fp;
          int fd = _open_osfhandle ((long)file, 0);
          if (fd == -1)
            {
              CloseHandle (file);
              return NULL;
            }
          fp = fdopen (fd, "w+b");
          if (!fp)
            {
              int save = errno;
              close (fd);
              errno = save;
              return NULL;
            }
          return fp;
        }
      Sleep (1); /* One ms as this is the granularity of GetTickCount.  */
    }
  errno = ENOENT;
  return NULL;
#else /*!HAVE_W32_SYSTEM*/
  return tmpfile ();
#endif /*!HAVE_W32_SYSTEM*/
}


/* Make sure that the standard file descriptors are opened. Obviously
   some folks close them before an exec and the next file we open will
   get one of them assigned and thus any output (i.e. diagnostics) end
   up in that file (e.g. the trustdb).  Not actually a gpg problem as
   this will hapen with almost all utilities when called in a wrong
   way.  However we try to minimize the damage here and raise
   awareness of the problem.

   Must be called before we open any files! */
void
gnupg_reopen_std (const char *pgmname)
{  
#if defined(HAVE_STAT) && !defined(HAVE_W32_SYSTEM)
  struct stat statbuf;
  int did_stdin = 0;
  int did_stdout = 0;
  int did_stderr = 0;
  FILE *complain;

  if (fstat (STDIN_FILENO, &statbuf) == -1 && errno ==EBADF)
    {
      if (open ("/dev/null",O_RDONLY) == STDIN_FILENO)
	did_stdin = 1;
      else
	did_stdin = 2;
    }
  
  if (fstat (STDOUT_FILENO, &statbuf) == -1 && errno == EBADF)
    {
      if (open ("/dev/null",O_WRONLY) == STDOUT_FILENO)
	did_stdout = 1;
      else
	did_stdout = 2;
    }

  if (fstat (STDERR_FILENO, &statbuf)==-1 && errno==EBADF)
    {
      if (open ("/dev/null", O_WRONLY) == STDERR_FILENO)
	did_stderr = 1;
      else
	did_stderr = 2;
    }

  /* It's hard to log this sort of thing since the filehandle we would
     complain to may be closed... */
  if (!did_stderr)
    complain = stderr;
  else if (!did_stdout)
    complain = stdout;
  else
    complain = NULL;

  if (complain)
    {
      if (did_stdin == 1)
	fprintf (complain, "%s: WARNING: standard input reopened\n", pgmname);
      if (did_stdout == 1)
	fprintf (complain, "%s: WARNING: standard output reopened\n", pgmname);
      if (did_stderr == 1)
	fprintf (complain, "%s: WARNING: standard error reopened\n", pgmname);

      if (did_stdin == 2 || did_stdout == 2 || did_stderr == 2)
	fprintf(complain,"%s: fatal: unable to reopen standard input,"
		" output, or error\n", pgmname);
    }

  if (did_stdin == 2 || did_stdout == 2 || did_stderr == 2)
    exit (3);
#endif /* HAVE_STAT && !HAVE_W32_SYSTEM */
}


/* Hack required for Windows.  */
void 
gnupg_allow_set_foregound_window (pid_t pid)
{
  if (!pid || pid == (pid_t)(-1))
    log_info ("%s called with invalid pid %lu\n",
              "gnupg_allow_set_foregound_window", (unsigned long)pid);
#ifdef HAVE_W32_SYSTEM  
  else if (!AllowSetForegroundWindow (pid))
    log_info ("AllowSetForegroundWindow(%lu) failed: %s\n",
               (unsigned long)pid, w32_strerror (-1));
#endif
}
