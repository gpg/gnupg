/* sysutils.c -  system helpers
 * Copyright (C) 1991-2001, 2003-2004,
 *               2006-2008  Free Software Foundation, Inc.
 * Copyright (C) 2013-2016 Werner Koch
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

#include <config.h>

#ifdef WITHOUT_NPTH /* Give the Makefile a chance to build without Pth.  */
# undef HAVE_NPTH
# undef USE_NPTH
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
#include <time.h>
#ifdef HAVE_SETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif
#ifdef HAVE_W32_SYSTEM
# if WINVER < 0x0500
#   define WINVER 0x0500  /* Required for AllowSetForegroundWindow.  */
# endif
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/socket.h>
# include <sys/un.h>
#endif
#ifdef HAVE_INOTIFY_INIT
# include <sys/inotify.h>
#endif /*HAVE_INOTIFY_INIT*/
#ifdef HAVE_NPTH
# include <npth.h>
#endif
#include <fcntl.h>

#include <assuan.h>

#include "util.h"
#include "i18n.h"

#include "sysutils.h"

#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))

/* Flag to tell whether special file names are enabled.  See gpg.c for
 * an explanation of these file names.  */
static int allow_special_filenames;


static GPGRT_INLINE gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}

static GPGRT_INLINE gpg_error_t
my_error (int e)
{
  return gpg_err_make (default_errsource, (e));
}



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


/* Allow the use of special "-&nnn" style file names.  */
void
enable_special_filenames (void)
{
  allow_special_filenames = 1;
}


/* Return a string which is used as a kind of process ID.  */
const byte *
get_session_marker (size_t *rlen)
{
  static byte marker[SIZEOF_UNSIGNED_LONG*2];
  static int initialized;

  if (!initialized)
    {
      gcry_create_nonce (marker, sizeof marker);
      initialized = 1;
    }
  *rlen = sizeof (marker);
  return marker;
}

/* Return a random number in an unsigned int. */
unsigned int
get_uint_nonce (void)
{
  unsigned int value;

  gcry_create_nonce (&value, sizeof value);
  return value;
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


/* Wrapper around the usual sleep function.  This one won't wake up
   before the sleep time has really elapsed.  When build with Pth it
   merely calls pth_sleep and thus suspends only the current
   thread. */
void
gnupg_sleep (unsigned int seconds)
{
#ifdef USE_NPTH
  npth_sleep (seconds);
#else
  /* Fixme:  make sure that a sleep won't wake up to early.  */
# ifdef HAVE_W32_SYSTEM
  Sleep (seconds*1000);
# else
  sleep (seconds);
# endif
#endif
}


/* Wrapper around the platforms usleep function.  This one won't wake
 * up before the sleep time has really elapsed.  When build with nPth
 * it merely calls npth_usleep and thus suspends only the current
 * thread. */
void
gnupg_usleep (unsigned int usecs)
{
#if defined(USE_NPTH)

  npth_usleep (usecs);

#elif defined(HAVE_W32_SYSTEM)

  Sleep ((usecs + 999) / 1000);

#elif defined(HAVE_NANOSLEEP)

  if (usecs)
    {
      struct timespec req;
      struct timespec rem;

      req.tv_sec = 0;
      req.tv_nsec = usecs * 1000;

      while (nanosleep (&req, &rem) < 0 && errno == EINTR)
        req = rem;
    }

#else /*Standard Unix*/

  if (usecs)
    {
      struct timeval tv;

      tv.tv_sec  = usecs / 1000000;
      tv.tv_usec = usecs % 1000000;
      select (0, NULL, NULL, NULL, &tv);
    }

#endif
}


/* This function is a NOP for POSIX systems but required under Windows
   as the file handles as returned by OS calls (like CreateFile) are
   different from the libc file descriptors (like open). This function
   translates system file handles to libc file handles.  FOR_WRITE
   gives the direction of the handle.  */
int
translate_sys2libc_fd (gnupg_fd_t fd, int for_write)
{
#if defined(HAVE_W32CE_SYSTEM)
  (void)for_write;
  return (int) fd;
#elif defined(HAVE_W32_SYSTEM)
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
  (void)for_write;
  return fd;
#endif
}

/* This is the same as translate_sys2libc_fd but takes an integer
   which is assumed to be such an system handle.  On WindowsCE the
   passed FD is a rendezvous ID and the function finishes the pipe
   creation. */
int
translate_sys2libc_fd_int (int fd, int for_write)
{
#if HAVE_W32CE_SYSTEM
  fd = (int) _assuan_w32ce_finish_pipe (fd, for_write);
  return translate_sys2libc_fd ((void*)fd, for_write);
#elif HAVE_W32_SYSTEM
  if (fd <= 2)
    return fd;	/* Do not do this for error, stdin, stdout, stderr. */

  return translate_sys2libc_fd ((void*)fd, for_write);
#else
  (void)for_write;
  return fd;
#endif
}


/* Check whether FNAME has the form "-&nnnn", where N is a non-zero
 * number.  Returns this number or -1 if it is not the case.  If the
 * caller wants to use the file descriptor for writing FOR_WRITE shall
 * be set to 1.  If NOTRANSLATE is set the Windows specific mapping is
 * not done. */
int
check_special_filename (const char *fname, int for_write, int notranslate)
{
  if (allow_special_filenames
      && fname && *fname == '-' && fname[1] == '&')
    {
      int i;

      fname += 2;
      for (i=0; digitp (fname+i); i++ )
        ;
      if (!fname[i])
        return notranslate? atoi (fname)
          /**/            : translate_sys2libc_fd_int (atoi (fname), for_write);
    }
  return -1;
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
#ifdef HAVE_W32CE_SYSTEM
  wchar_t buffer[MAX_PATH+7+12+1];
# define mystrlen(a) wcslen (a)
  wchar_t *name, *p;
#else
  char buffer[MAX_PATH+7+12+1];
# define mystrlen(a) strlen (a)
  char *name, *p;
#endif
  HANDLE file;
  int pid = GetCurrentProcessId ();
  unsigned int value;
  int i;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = TRUE;

  n = GetTempPath (MAX_PATH+1, buffer);
  if (!n || n > MAX_PATH || mystrlen (buffer) > MAX_PATH)
    {
      gpg_err_set_errno (ENOENT);
      return NULL;
    }
  p = buffer + mystrlen (buffer);
#ifdef HAVE_W32CE_SYSTEM
  wcscpy (p, L"_gnupg");
  p += 7;
#else
  p = stpcpy (p, "_gnupg");
#endif
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
#ifdef HAVE_W32CE_SYSTEM
      wcscpy (p, L".tmp");
#else
      strcpy (p, ".tmp");
#endif
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
#ifdef HAVE_W32CE_SYSTEM
          int fd = (int)file;
          fp = _wfdopen (fd, L"w+b");
#else
          int fd = _open_osfhandle ((long)file, 0);
          if (fd == -1)
            {
              CloseHandle (file);
              return NULL;
            }
          fp = fdopen (fd, "w+b");
#endif
          if (!fp)
            {
              int save = errno;
              close (fd);
              gpg_err_set_errno (save);
              return NULL;
            }
          return fp;
        }
      Sleep (1); /* One ms as this is the granularity of GetTickCount.  */
    }
  gpg_err_set_errno (ENOENT);
  return NULL;
#undef mystrlen
#else /*!HAVE_W32_SYSTEM*/
  return tmpfile ();
#endif /*!HAVE_W32_SYSTEM*/
}


/* Make sure that the standard file descriptors are opened. Obviously
   some folks close them before an exec and the next file we open will
   get one of them assigned and thus any output (i.e. diagnostics) end
   up in that file (e.g. the trustdb).  Not actually a gpg problem as
   this will happen with almost all utilities when called in a wrong
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
#else /* !(HAVE_STAT && !HAVE_W32_SYSTEM) */
  (void)pgmname;
#endif
}


/* Hack required for Windows.  */
void
gnupg_allow_set_foregound_window (pid_t pid)
{
  if (!pid)
    log_info ("%s called with invalid pid %lu\n",
              "gnupg_allow_set_foregound_window", (unsigned long)pid);
#if defined(HAVE_W32_SYSTEM) && !defined(HAVE_W32CE_SYSTEM)
  else if (!AllowSetForegroundWindow ((pid_t)pid == (pid_t)(-1)?ASFW_ANY:pid))
    log_info ("AllowSetForegroundWindow(%lu) failed: %s\n",
               (unsigned long)pid, w32_strerror (-1));
#endif
}

int
gnupg_remove (const char *fname)
{
#ifdef HAVE_W32CE_SYSTEM
  int rc;
  wchar_t *wfname;

  wfname = utf8_to_wchar (fname);
  if (!wfname)
    rc = 0;
  else
    {
      rc = DeleteFile (wfname);
      xfree (wfname);
    }
  if (!rc)
    return -1; /* ERRNO is automagically provided by gpg-error.h.  */
  return 0;
#else
  return remove (fname);
#endif
}


/* Wrapper for rename(2) to handle Windows peculiarities.  If
 * BLOCK_SIGNALS is not NULL and points to a variable set to true, all
 * signals will be blocked by calling gnupg_block_all_signals; the
 * caller needs to call gnupg_unblock_all_signals if that variable is
 * still set to true on return. */
gpg_error_t
gnupg_rename_file (const char *oldname, const char *newname, int *block_signals)
{
  gpg_error_t err = 0;

  if (block_signals && *block_signals)
    gnupg_block_all_signals ();

#ifdef HAVE_DOSISH_SYSTEM
  {
    int wtime = 0;

    gnupg_remove (newname);
  again:
    if (rename (oldname, newname))
      {
        if (GetLastError () == ERROR_SHARING_VIOLATION)
          {
            /* Another process has the file open.  We do not use a
             * lock for read but instead we wait until the other
             * process has closed the file.  This may take long but
             * that would also be the case with a dotlock approach for
             * read and write.  Note that we don't need this on Unix
             * due to the inode concept.
             *
             * So let's wait until the rename has worked.  The retry
             * intervals are 50, 100, 200, 400, 800, 50ms, ...  */
            if (!wtime || wtime >= 800)
              wtime = 50;
            else
              wtime *= 2;

            if (wtime >= 800)
              log_info (_("waiting for file '%s' to become accessible ...\n"),
                        oldname);

            Sleep (wtime);
            goto again;
          }
        err = my_error_from_syserror ();
      }
  }
#else /* Unix */
  {
#ifdef __riscos__
    gnupg_remove (newname);
#endif
    if (rename (oldname, newname) )
      err = my_error_from_syserror ();
  }
#endif /* Unix */

  if (block_signals && *block_signals && err)
    {
      gnupg_unblock_all_signals ();
      *block_signals = 0;
    }

  if (err)
    log_error (_("renaming '%s' to '%s' failed: %s\n"),
               oldname, newname, gpg_strerror (err));
  return err;
}


#ifndef HAVE_W32_SYSTEM
static mode_t
modestr_to_mode (const char *modestr)
{
  mode_t mode = 0;

  if (modestr && *modestr)
    {
      modestr++;
      if (*modestr && *modestr++ == 'r')
        mode |= S_IRUSR;
      if (*modestr && *modestr++ == 'w')
        mode |= S_IWUSR;
      if (*modestr && *modestr++ == 'x')
        mode |= S_IXUSR;
      if (*modestr && *modestr++ == 'r')
        mode |= S_IRGRP;
      if (*modestr && *modestr++ == 'w')
        mode |= S_IWGRP;
      if (*modestr && *modestr++ == 'x')
        mode |= S_IXGRP;
      if (*modestr && *modestr++ == 'r')
        mode |= S_IROTH;
      if (*modestr && *modestr++ == 'w')
        mode |= S_IWOTH;
      if (*modestr && *modestr++ == 'x')
        mode |= S_IXOTH;
    }

  return mode;
}
#endif


/* A wrapper around mkdir which takes a string for the mode argument.
   This makes it easier to handle the mode argument which is not
   defined on all systems.  The format of the modestring is

      "-rwxrwxrwx"

   '-' is a don't care or not set.  'r', 'w', 'x' are read allowed,
   write allowed, execution allowed with the first group for the user,
   the second for the group and the third for all others.  If the
   string is shorter than above the missing mode characters are meant
   to be not set.  */
int
gnupg_mkdir (const char *name, const char *modestr)
{
#ifdef HAVE_W32CE_SYSTEM
  wchar_t *wname;
  (void)modestr;

  wname = utf8_to_wchar (name);
  if (!wname)
    return -1;
  if (!CreateDirectoryW (wname, NULL))
    {
      xfree (wname);
      return -1;  /* ERRNO is automagically provided by gpg-error.h.  */
    }
  xfree (wname);
  return 0;
#elif MKDIR_TAKES_ONE_ARG
  (void)modestr;
  /* Note: In the case of W32 we better use CreateDirectory and try to
     set appropriate permissions.  However using mkdir is easier
     because this sets ERRNO.  */
  return mkdir (name);
#else
  return mkdir (name, modestr_to_mode (modestr));
#endif
}


/* A wrapper around chmod which takes a string for the mode argument.
   This makes it easier to handle the mode argument which is not
   defined on all systems.  The format of the modestring is the same
   as for gnupg_mkdir.  */
int
gnupg_chmod (const char *name, const char *modestr)
{
#ifdef HAVE_W32_SYSTEM
  (void)name;
  (void)modestr;
  return 0;
#else
  return chmod (name, modestr_to_mode (modestr));
#endif
}


/* Our version of mkdtemp.  The API is identical to POSIX.1-2008
   version.  We do not use a system provided mkdtemp because we have a
   good RNG instantly available and this way we don't have diverging
   versions.  */
char *
gnupg_mkdtemp (char *tmpl)
{
  /* A lower bound on the number of temporary files to attempt to
     generate.  The maximum total number of temporary file names that
     can exist for a given template is 62**6 (5*36**3 for Windows).
     It should never be necessary to try all these combinations.
     Instead if a reasonable number of names is tried (we define
     reasonable as 62**3 or 5*36**3) fail to give the system
     administrator the chance to remove the problems.  */
#ifdef HAVE_W32_SYSTEM
  static const char letters[] =
    "abcdefghijklmnopqrstuvwxyz0123456789";
# define NUMBER_OF_LETTERS 36
# define ATTEMPTS_MIN (5 * 36 * 36 * 36)
#else
  static const char letters[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
# define NUMBER_OF_LETTERS 62
# define ATTEMPTS_MIN (62 * 62 * 62)
#endif
  int len;
  char *XXXXXX;
  uint64_t value;
  unsigned int count;
  int save_errno = errno;
  /* The number of times to attempt to generate a temporary file.  To
     conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
  unsigned int attempts = TMP_MAX;
#else
  unsigned int attempts = ATTEMPTS_MIN;
#endif

  len = strlen (tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get a random start value.  */
  gcry_create_nonce (&value, sizeof value);

  /* Loop until a directory was created.  */
  for (count = 0; count < attempts; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % NUMBER_OF_LETTERS];
      v /= NUMBER_OF_LETTERS;
      XXXXXX[1] = letters[v % NUMBER_OF_LETTERS];
      v /= NUMBER_OF_LETTERS;
      XXXXXX[2] = letters[v % NUMBER_OF_LETTERS];
      v /= NUMBER_OF_LETTERS;
      XXXXXX[3] = letters[v % NUMBER_OF_LETTERS];
      v /= NUMBER_OF_LETTERS;
      XXXXXX[4] = letters[v % NUMBER_OF_LETTERS];
      v /= NUMBER_OF_LETTERS;
      XXXXXX[5] = letters[v % NUMBER_OF_LETTERS];

      if (!gnupg_mkdir (tmpl, "-rwx"))
        {
          gpg_err_set_errno (save_errno);
          return tmpl;
        }
      if (errno != EEXIST)
	return NULL;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  gpg_err_set_errno (EEXIST);
  return NULL;
}


int
gnupg_setenv (const char *name, const char *value, int overwrite)
{
#ifdef HAVE_W32CE_SYSTEM
  (void)name;
  (void)value;
  (void)overwrite;
  return 0;
#else /*!W32CE*/
# ifdef HAVE_W32_SYSTEM
  /*  Windows maintains (at least) two sets of environment variables.
      One set can be accessed by GetEnvironmentVariable and
      SetEnvironmentVariable.  This set is inherited by the children.
      The other set is maintained in the C runtime, and is accessed
      using getenv and putenv.  We try to keep them in sync by
      modifying both sets.  */
  {
    int exists;
    char tmpbuf[10];
    exists = GetEnvironmentVariable (name, tmpbuf, sizeof tmpbuf);

    if ((! exists || overwrite) && !SetEnvironmentVariable (name, value))
      {
        gpg_err_set_errno (EINVAL); /* (Might also be ENOMEM.) */
        return -1;
      }
  }
# endif /*W32*/

# ifdef HAVE_SETENV
  return setenv (name, value, overwrite);
# else /*!HAVE_SETENV*/
  if (! getenv (name) || overwrite)
    {
      char *buf;

      (void)overwrite;
      if (!name || !value)
        {
          gpg_err_set_errno (EINVAL);
          return -1;
        }
      buf = strconcat (name, "=", value, NULL);
      if (!buf)
        return -1;
# if __GNUC__
#  warning no setenv - using putenv but leaking memory.
# endif
      return putenv (buf);
    }
  return 0;
# endif /*!HAVE_SETENV*/
#endif /*!W32CE*/
}


int
gnupg_unsetenv (const char *name)
{
#ifdef HAVE_W32CE_SYSTEM
  (void)name;
  return 0;
#else /*!W32CE*/
# ifdef HAVE_W32_SYSTEM
  /*  Windows maintains (at least) two sets of environment variables.
      One set can be accessed by GetEnvironmentVariable and
      SetEnvironmentVariable.  This set is inherited by the children.
      The other set is maintained in the C runtime, and is accessed
      using getenv and putenv.  We try to keep them in sync by
      modifying both sets.  */
  if (!SetEnvironmentVariable (name, NULL))
    {
      gpg_err_set_errno (EINVAL); /* (Might also be ENOMEM.) */
      return -1;
    }
# endif /*W32*/

# ifdef HAVE_UNSETENV
  return unsetenv (name);
# else /*!HAVE_UNSETENV*/
  {
    char *buf;

    if (!name)
      {
        gpg_err_set_errno (EINVAL);
        return -1;
      }
    buf = xtrystrdup (name);
    if (!buf)
      return -1;
#  if __GNUC__
#   warning no unsetenv - trying putenv but leaking memory.
#  endif
    return putenv (buf);
  }
# endif /*!HAVE_UNSETENV*/
#endif /*!W32CE*/
}


/* Return the current working directory as a malloced string.  Return
   NULL and sets ERRNo on error.  */
char *
gnupg_getcwd (void)
{
  char *buffer;
  size_t size = 100;

  for (;;)
    {
      buffer = xtrymalloc (size+1);
      if (!buffer)
        return NULL;
#ifdef HAVE_W32CE_SYSTEM
      strcpy (buffer, "/");  /* Always "/".  */
      return buffer;
#else
      if (getcwd (buffer, size) == buffer)
        return buffer;
      xfree (buffer);
      if (errno != ERANGE)
        return NULL;
      size *= 2;
#endif
    }
}



#ifdef HAVE_W32CE_SYSTEM
/* There is a isatty function declaration in cegcc but it does not
   make sense, thus we redefine it.  */
int
_gnupg_isatty (int fd)
{
  (void)fd;
  return 0;
}
#endif


#ifdef HAVE_W32CE_SYSTEM
/* Replacement for getenv which takes care of the our use of getenv.
   The code is not thread safe but we expect it to work in all cases
   because it is called for the first time early enough.  */
char *
_gnupg_getenv (const char *name)
{
  static int initialized;
  static char *assuan_debug;

  if (!initialized)
    {
      assuan_debug = read_w32_registry_string (NULL,
                                               "\\Software\\GNU\\libassuan",
                                               "debug");
      initialized = 1;
    }

  if (!strcmp (name, "ASSUAN_DEBUG"))
    return assuan_debug;
  else
    return NULL;
}

#endif /*HAVE_W32CE_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
/* Return the user's security identifier from the current process.  */
PSID
w32_get_user_sid (void)
{
  int okay = 0;
  HANDLE proc = NULL;
  HANDLE token = NULL;
  TOKEN_USER *user = NULL;
  PSID sid = NULL;
  DWORD tokenlen, sidlen;

  proc = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
  if (!proc)
    goto leave;

  if (!OpenProcessToken (proc, TOKEN_QUERY, &token))
    goto leave;

  if (!GetTokenInformation (token, TokenUser, NULL, 0, &tokenlen)
      && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    goto leave;

  user = xtrymalloc (tokenlen);
  if (!user)
    goto leave;

  if (!GetTokenInformation (token, TokenUser, user, tokenlen, &tokenlen))
    goto leave;
  if (!IsValidSid (user->User.Sid))
    goto leave;
  sidlen = GetLengthSid (user->User.Sid);
  sid = xtrymalloc (sidlen);
  if (!sid)
    goto leave;
  if (!CopySid (sidlen, sid, user->User.Sid))
    goto leave;
  okay = 1;

 leave:
  xfree (user);
  if (token)
    CloseHandle (token);
  if (proc)
    CloseHandle (proc);

  if (!okay)
    {
      xfree (sid);
      sid = NULL;
    }
  return sid;
}
#endif /*HAVE_W32_SYSTEM*/



/* Support for inotify under Linux.  */

/* Store a new inotify file handle for SOCKET_NAME at R_FD or return
 * an error code. */
gpg_error_t
gnupg_inotify_watch_socket (int *r_fd, const char *socket_name)
{
#if HAVE_INOTIFY_INIT
  gpg_error_t err;
  char *fname;
  int fd;
  char *p;

  *r_fd = -1;

  if (!socket_name)
    return my_error (GPG_ERR_INV_VALUE);

  fname = xtrystrdup (socket_name);
  if (!fname)
    return my_error_from_syserror ();

  fd = inotify_init ();
  if (fd == -1)
    {
      err = my_error_from_syserror ();
      xfree (fname);
      return err;
    }

  /* We need to watch the directory for the file because there won't
   * be an IN_DELETE_SELF for a socket file.  To handle a removal of
   * the directory we also watch the directory itself. */
  p = strrchr (fname, '/');
  if (p)
    *p = 0;
  if (inotify_add_watch (fd, fname,
                         (IN_DELETE|IN_DELETE_SELF|IN_EXCL_UNLINK)) == -1)
    {
      err = my_error_from_syserror ();
      close (fd);
      xfree (fname);
      return err;
    }

  xfree (fname);

  *r_fd = fd;
  return 0;
#else /*!HAVE_INOTIFY_INIT*/

  (void)socket_name;
  *r_fd = -1;
  return my_error (GPG_ERR_NOT_SUPPORTED);

#endif /*!HAVE_INOTIFY_INIT*/
}


/* Read an inotify event and return true if it matches NAME or if it
 * sees an IN_DELETE_SELF event for the directory of NAME.  */
int
gnupg_inotify_has_name (int fd, const char *name)
{
#if USE_NPTH && HAVE_INOTIFY_INIT
#define BUFSIZE_FOR_INOTIFY (sizeof (struct inotify_event) + 255 + 1)
  union {
    struct inotify_event ev;
    char _buf[sizeof (struct inotify_event) + 255 + 1];
  } buf;
  struct inotify_event *evp;
  int n;

  n = npth_read (fd, &buf, sizeof buf);
  /* log_debug ("notify read: n=%d\n", n); */
  evp = &buf.ev;
  while (n >= sizeof (struct inotify_event))
    {
      /* log_debug ("             mask=%x len=%u name=(%s)\n", */
      /*        evp->mask, (unsigned int)evp->len, evp->len? evp->name:""); */
      if ((evp->mask & IN_UNMOUNT))
        {
          /* log_debug ("             found (dir unmounted)\n"); */
          return 3; /* Directory was unmounted.  */
        }
      if ((evp->mask & IN_DELETE_SELF))
        {
          /* log_debug ("             found (dir removed)\n"); */
          return 2; /* Directory was removed.  */
        }
      if ((evp->mask & IN_DELETE))
        {
          if (evp->len >= strlen (name) && !strcmp (evp->name, name))
            {
              /* log_debug ("             found (file removed)\n"); */
              return 1; /* File was removed.  */
            }
        }
      n -= sizeof (*evp) + evp->len;
      evp = (struct inotify_event *)(void *)
        ((char *)evp + sizeof (*evp) + evp->len);
    }

#else /*!(USE_NPTH && HAVE_INOTIFY_INIT)*/

  (void)fd;
  (void)name;

#endif  /*!(USE_NPTH && HAVE_INOTIFY_INIT)*/

  return 0; /* Not found.  */
}


/* Return a malloc'ed string that is the path to the passed
 * unix-domain socket (or return NULL if this is not a valid
 * unix-domain socket).  We use a plain int here because it is only
 * used on Linux.
 *
 * FIXME: This function needs to be moved to libassuan.  */
#ifndef HAVE_W32_SYSTEM
char *
gnupg_get_socket_name (int fd)
{
  struct sockaddr_un un;
  socklen_t len = sizeof(un);
  char *name = NULL;

  if (getsockname (fd, (struct sockaddr*)&un, &len) != 0)
    log_error ("could not getsockname(%d): %s\n", fd,
               gpg_strerror (my_error_from_syserror ()));
  else if (un.sun_family != AF_UNIX)
    log_error ("file descriptor %d is not a unix-domain socket\n", fd);
  else if (len <= offsetof (struct sockaddr_un, sun_path))
    log_error ("socket name not present for file descriptor %d\n", fd);
  else if (len > sizeof(un))
    log_error ("socket name for file descriptor %d was truncated "
               "(passed %zu bytes, wanted %u)\n", fd, sizeof(un), len);
  else
    {
      size_t namelen = len - offsetof (struct sockaddr_un, sun_path);

      /* log_debug ("file descriptor %d has path %s (%zu octets)\n", fd, */
      /*            un.sun_path, namelen); */
      name = xtrymalloc (namelen + 1);
      if (!name)
        log_error ("failed to allocate memory for name of fd %d: %s\n",
                   fd, gpg_strerror (my_error_from_syserror ()));
      else
        {
          memcpy (name, un.sun_path, namelen);
          name[namelen] = 0;
        }
    }

  return name;
}
#endif /*!HAVE_W32_SYSTEM*/

/* Check whether FD is valid.  */
int
gnupg_fd_valid (int fd)
{
  int d = dup (fd);
  if (d < 0)
    return 0;
  close (d);
  return 1;
}
