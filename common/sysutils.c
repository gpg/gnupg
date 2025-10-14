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
#include <limits.h>
#include <sys/types.h>
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
#ifdef HAVE_PWD_H
# include <pwd.h>
# include <grp.h>
#endif /*HAVE_PWD_H*/
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
#include <dirent.h>

#include <assuan.h>

#include "util.h"
#include "i18n.h"

#include "sysutils.h"

#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))


/* The object used with our opendir functions.  We need to define our
 * own so that we can properly handle Unicode on Windows.  */
struct gnupg_dir_s
{
#ifdef HAVE_W32_SYSTEM
  _WDIR *dir;                    /* The system's DIR pointer.  */
#else
  DIR *dir;                      /* The system's DIR pointer.  */
#endif
  struct gnupg_dirent_s dirent;  /* The current dirent.  */
  size_t namesize;  /* If not 0 the allocated size of dirent.d_name.  */
  char name[256];   /* Only used if NAMESIZE is 0.  */
};


/* Flag to tell whether special file names are enabled.  See gpg.c for
 * an explanation of these file names.  */
static int allow_special_filenames;

#ifdef HAVE_W32_SYSTEM
/* State of gnupg_inhibit_set_foregound_window.  */
static int inhibit_set_foregound_window;
/* Disable the use of _open_osfhandle.  */
static int no_translate_sys2libc_fd;
#endif


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

#ifdef HAVE_W32_SYSTEM
static int
any8bitchar (const char *string)
{
  if (string)
    for ( ; *string; string++)
      if ((*string & 0x80))
        return 1;
  return 0;
}
#endif /*HAVE_W32_SYSTEM*/


/* Helper for gnupg_w32_set_errno.  */
#ifdef HAVE_W32_SYSTEM
static int
map_w32_to_errno (DWORD w32_err)
{
  switch (w32_err)
    {
    case 0:
      return 0;

    case ERROR_FILE_NOT_FOUND:
      return ENOENT;

    case ERROR_PATH_NOT_FOUND:
      return ENOENT;

    case ERROR_ACCESS_DENIED:
      return EPERM;  /* ReactOS uses EACCES ("Permission denied") and
                      * is likely right because they used an
                      * undocumented function to associate the error
                      * codes.  However we have always used EPERM
                      * ("Operation not permitted", e.g. function is
                      * required to be called by root) and we better
                      * stick to that to avoid surprising bugs. */

    case ERROR_INVALID_HANDLE:
      return EBADF;

    case ERROR_INVALID_BLOCK:
      return ENOMEM;

    case ERROR_NOT_ENOUGH_MEMORY:
      return ENOMEM;

    case ERROR_NO_DATA:
      return EPIPE;

    case ERROR_ALREADY_EXISTS:
      return EEXIST;

    case ERROR_FILE_INVALID:
      return EIO;

      /* This mapping has been taken from reactOS.  */
    case ERROR_TOO_MANY_OPEN_FILES: return EMFILE;
    case ERROR_ARENA_TRASHED: return ENOMEM;
    case ERROR_BAD_ENVIRONMENT: return E2BIG;
    case ERROR_BAD_FORMAT: return ENOEXEC;
    case ERROR_INVALID_DRIVE: return ENOENT;
    case ERROR_CURRENT_DIRECTORY: return EACCES;
    case ERROR_NOT_SAME_DEVICE: return EXDEV;
    case ERROR_NO_MORE_FILES: return ENOENT;
    case ERROR_WRITE_PROTECT: return EACCES;
    case ERROR_BAD_UNIT: return EACCES;
    case ERROR_NOT_READY: return EACCES;
    case ERROR_BAD_COMMAND: return EACCES;
    case ERROR_CRC: return EACCES;
    case ERROR_BAD_LENGTH: return EACCES;
    case ERROR_SEEK: return EACCES;
    case ERROR_NOT_DOS_DISK: return EACCES;
    case ERROR_SECTOR_NOT_FOUND: return EACCES;
    case ERROR_OUT_OF_PAPER: return EACCES;
    case ERROR_WRITE_FAULT: return EACCES;
    case ERROR_READ_FAULT: return EACCES;
    case ERROR_GEN_FAILURE: return EACCES;
    case ERROR_SHARING_VIOLATION: return EACCES;
    case ERROR_LOCK_VIOLATION: return EACCES;
    case ERROR_WRONG_DISK: return EACCES;
    case ERROR_SHARING_BUFFER_EXCEEDED: return EACCES;
    case ERROR_BAD_NETPATH: return ENOENT;
    case ERROR_NETWORK_ACCESS_DENIED: return EACCES;
    case ERROR_BAD_NET_NAME: return ENOENT;
    case ERROR_FILE_EXISTS: return EEXIST;
    case ERROR_CANNOT_MAKE: return EACCES;
    case ERROR_FAIL_I24: return EACCES;
    case ERROR_NO_PROC_SLOTS: return EAGAIN;
    case ERROR_DRIVE_LOCKED: return EACCES;
    case ERROR_BROKEN_PIPE: return EPIPE;
    case ERROR_DISK_FULL: return ENOSPC;
    case ERROR_INVALID_TARGET_HANDLE: return EBADF;
    case ERROR_WAIT_NO_CHILDREN: return ECHILD;
    case ERROR_CHILD_NOT_COMPLETE: return ECHILD;
    case ERROR_DIRECT_ACCESS_HANDLE: return EBADF;
    case ERROR_SEEK_ON_DEVICE: return EACCES;
    case ERROR_DIR_NOT_EMPTY: return ENOTEMPTY;
    case ERROR_NOT_LOCKED: return EACCES;
    case ERROR_BAD_PATHNAME: return ENOENT;
    case ERROR_MAX_THRDS_REACHED: return EAGAIN;
    case ERROR_LOCK_FAILED: return EACCES;
    case ERROR_INVALID_STARTING_CODESEG: return ENOEXEC;
    case ERROR_INVALID_STACKSEG: return ENOEXEC;
    case ERROR_INVALID_MODULETYPE: return ENOEXEC;
    case ERROR_INVALID_EXE_SIGNATURE: return ENOEXEC;
    case ERROR_EXE_MARKED_INVALID: return ENOEXEC;
    case ERROR_BAD_EXE_FORMAT: return ENOEXEC;
    case ERROR_ITERATED_DATA_EXCEEDS_64k: return ENOEXEC;
    case ERROR_INVALID_MINALLOCSIZE: return ENOEXEC;
    case ERROR_DYNLINK_FROM_INVALID_RING: return ENOEXEC;
    case ERROR_IOPL_NOT_ENABLED: return ENOEXEC;
    case ERROR_INVALID_SEGDPL: return ENOEXEC;
    case ERROR_AUTODATASEG_EXCEEDS_64k: return ENOEXEC;
    case ERROR_RING2SEG_MUST_BE_MOVABLE: return ENOEXEC;
    case ERROR_RELOC_CHAIN_XEEDS_SEGLIM: return ENOEXEC;
    case ERROR_INFLOOP_IN_RELOC_CHAIN: return ENOEXEC;
    case ERROR_FILENAME_EXCED_RANGE: return ENOENT;
    case ERROR_NESTING_NOT_ALLOWED: return EAGAIN;
    case ERROR_NOT_ENOUGH_QUOTA: return ENOMEM;

    default:
      return EIO;
    }
}
#endif /*HAVE_W32_SYSTEM*/


/* Set ERRNO from the Windows error.  EC may be -1 to use the last
 * error.  Returns the Windows error code.  */
#ifdef HAVE_W32_SYSTEM
int
gnupg_w32_set_errno (int ec)
{
  /* FIXME: Replace by gpgrt_w32_set_errno.  */
  if (ec == -1)
    ec = GetLastError ();
  _set_errno (map_w32_to_errno (ec));
  return ec;
}
#endif /*HAVE_W32_SYSTEM*/



/* Allow the use of special "-&nnn" style file names.  */
void
enable_special_filenames (void)
{
  allow_special_filenames = 1;
}


/* Disable the use use of _open_osfhandle on Windows.  */
void
disable_translate_sys2libc_fd (void)
{
#ifdef HAVE_W32_SYSTEM
  no_translate_sys2libc_fd = 1;
#endif
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

      req.tv_sec  = usecs / 1000000;
      req.tv_nsec = (usecs % 1000000) * 1000;
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
#if defined(HAVE_W32_SYSTEM)
static int
translate_sys2libc_fd (gnupg_fd_t fd, int for_write)
{
  int x;

  if (fd == GNUPG_INVALID_FD)
    return -1;

  /* Note that _open_osfhandle is currently defined to take and return
     a long.  */
  x = _open_osfhandle ((intptr_t)fd, for_write ? 1 : 0);
  if (x == -1)
    log_error ("failed to translate osfhandle %p\n", (void *) fd);
  return x;
}
#endif /*!HAVE_W32_SYSTEM */


/* This is the same as translate_sys2libc_fd but takes an integer
   which is assumed to be such an system handle.   */
int
translate_sys2libc_fd_int (int fd, int for_write)
{
#ifdef HAVE_W32_SYSTEM
  if (fd <= 2 || no_translate_sys2libc_fd)
    return fd;	/* Do not do this for stdin, stdout, and stderr.  */

  return translate_sys2libc_fd ((void*)(intptr_t)fd, for_write);
#else
  (void)for_write;
  return fd;
#endif
}


/*
 * Parse the string representation of a file reference (file handle on
 * Windows or file descriptor on POSIX) in FDSTR.  The string
 * representation may be either of following:

 *  (1) 0, 1, or 2 which means stdin, stdout, and stderr, respectively.
 *  (2) Integer representation (by %d of printf).
 *  (3) Hex representation which starts as "0x".
 *
 * Then, fill R_SYSHD, according to the value of a file reference.
 *
 */
gpg_error_t
gnupg_parse_fdstr (const char *fdstr, es_syshd_t *r_syshd)
{
  int fd = -1;
#ifdef HAVE_W32_SYSTEM
  gnupg_fd_t hd;
  char *endptr;
  int base;

  if (!strcmp (fdstr, "0"))
    fd = 0;
  else if (!strcmp (fdstr, "1"))
    fd = 1;
  else if (!strcmp (fdstr, "2"))
    fd = 2;

  if (fd >= 0)
    {
      r_syshd->type = ES_SYSHD_FD;
      r_syshd->u.fd = fd;
      return 0;
    }

  if (!strncmp (fdstr, "0x", 2))
    {
      base = 16;
      fdstr += 2;
    }
  else
    base = 10;

  gpg_err_set_errno (0);
#ifdef _WIN64
  hd = (gnupg_fd_t)strtoll (fdstr, &endptr, base);
#else
  hd = (gnupg_fd_t)strtol (fdstr, &endptr, base);
#endif
  if (errno != 0 || endptr == fdstr || *endptr != '\0')
    return gpg_error (GPG_ERR_INV_ARG);

  r_syshd->type = ES_SYSHD_HANDLE;
  r_syshd->u.handle = hd;
  return 0;
#else
  fd = atoi (fdstr);
  r_syshd->type = ES_SYSHD_FD;
  r_syshd->u.fd = fd;
  return 0;
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
        {
          if (notranslate)
            return atoi (fname);
          else
            {
              es_syshd_t syshd;

              if (gnupg_parse_fdstr (fname,  &syshd))
                return -1;

#ifdef HAVE_W32_SYSTEM
              if (syshd.type == ES_SYSHD_FD)
                return syshd.u.fd;
              else
                return translate_sys2libc_fd ((gnupg_fd_t)syshd.u.handle, for_write);
#else
              (void)for_write;
              return syshd.u.fd;
#endif
            }
        }
    }
  return -1;
}


/* Check whether FNAME has the form "-&nnnn", where N is a number
 * representing a file.  Returns GNUPG_INVALID_FD if it is not the
 * case.  Returns a file descriptor on POSIX, a system handle on
 * Windows.  */
gnupg_fd_t
gnupg_check_special_filename (const char *fname)
{
  if (allow_special_filenames
      && fname && *fname == '-' && fname[1] == '&')
    {
      int i;

      fname += 2;
      for (i=0; digitp (fname+i); i++ )
        ;
      if (!fname[i])
        {
          es_syshd_t syshd;

          if (gnupg_parse_fdstr (fname,  &syshd))
            return GNUPG_INVALID_FD;

#ifdef HAVE_W32_SYSTEM
          if (syshd.type == ES_SYSHD_FD)
            {
              if (syshd.u.fd == 0)
                return GetStdHandle (STD_INPUT_HANDLE);
              else if (syshd.u.fd == 1)
                return GetStdHandle (STD_OUTPUT_HANDLE);
              else if (syshd.u.fd == 2)
                return GetStdHandle (STD_ERROR_HANDLE);
            }
          else
            return syshd.u.handle;
#else
          return syshd.u.fd;
#endif
        }
    }
  return GNUPG_INVALID_FD;
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
  unsigned int value = 0;
  int i;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = TRUE;

  n = GetTempPath (MAX_PATH+1, buffer);
  if (!n || n > MAX_PATH || strlen (buffer) > MAX_PATH)
    {
      gpg_err_set_errno (ENOENT);
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
      value += (GetTickCount () ^ ((pid<<16) & 0xffff0000));
      for (i=0; i < 8; i++)
	*p++ = tohex (((value >> (7 - i)*4) & 0x0f));
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
          int fd = _open_osfhandle ((intptr_t)file, 0);
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
              gpg_err_set_errno (save);
              return NULL;
            }
          return fp;
        }
      Sleep (1); /* One ms as this is the granularity of GetTickCount.  */
    }
  gpg_err_set_errno (ENOENT);
  return NULL;

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
#ifdef F_GETFD
  int did_stdin = 0;
  int did_stdout = 0;
  int did_stderr = 0;
  FILE *complain;

  if (fcntl (STDIN_FILENO, F_GETFD) == -1 && errno ==EBADF)
    {
      if (open ("/dev/null",O_RDONLY) == STDIN_FILENO)
	did_stdin = 1;
      else
	did_stdin = 2;
    }

  if (fcntl (STDOUT_FILENO, F_GETFD) == -1 && errno == EBADF)
    {
      if (open ("/dev/null",O_WRONLY) == STDOUT_FILENO)
	did_stdout = 1;
      else
	did_stdout = 2;
    }

  if (fcntl (STDERR_FILENO, F_GETFD)==-1 && errno==EBADF)
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
#else /* !F_GETFD */
  (void)pgmname;
#endif
}


/* Inhibit calls to AllowSetForegroundWindow on Windows.  Calling this
 * with YES set to true calls to gnupg_allow_set_foregound_window are
 * shunted.  */
void
gnupg_inhibit_set_foregound_window (int yes)
{
#ifdef HAVE_W32_SYSTEM
  inhibit_set_foregound_window = yes;
#else
  (void)yes;
#endif
}


/* Hack required for Windows.  */
void
gnupg_allow_set_foregound_window (pid_t pid)
{
  if (!pid)
    log_info ("%s called with invalid pid %lu\n",
              "gnupg_allow_set_foregound_window", (unsigned long)pid);
#if defined(HAVE_W32_SYSTEM)
  else if (inhibit_set_foregound_window)
    ;
  else if (!AllowSetForegroundWindow ((pid_t)pid == (pid_t)(-1)?ASFW_ANY:pid))
    {
      char *flags = getenv ("GNUPG_EXEC_DEBUG_FLAGS");
      if (flags && (atoi (flags) & 2))
        log_info ("AllowSetForegroundWindow(%lu) failed: %s\n",
                  (unsigned long)pid, w32_strerror (-1));
    }
#endif
}


/* Helper for gnupg_rename and gnupg_remove.  */
#ifdef HAVE_W32_SYSTEM
static int
w32_wait_when_sharing_violation (int wtime, const char *fname)
{
  int ec = GetLastError ();

  if (ec != ERROR_SHARING_VIOLATION)
    {
      gnupg_w32_set_errno (ec);
      return 0;
    }

  /* Another process has the file open.  We do not use a
   * lock for read but instead we wait until the other
   * process has closed the file.  This may take long but
   * that would also be the case with a dotlock approach for
   * read and write.  Note that we don't need this on Unix
   * due to the inode concept.
   *
   * So let's wait until the file_op has worked.  The retry
   * intervals are 50, 100, 200, 400, 800, 50ms, ...  */
  if (!wtime || wtime >= 800)
    wtime = 50;
  else
    wtime *= 2;

  if (wtime >= 800)
    log_info (_("waiting for file '%s' to become accessible ...\n"),
              fname);

  gnupg_usleep (wtime);
  return wtime;  /* Note: WTIME is always > 0 */
}
#endif /*HAVE_W32_SYSTEM*/


/* The Windows version to remove a file.  If WAIT_FOR_ACCESS is
 * non-zero the functions waits until a sharing violation has been
 * solved.  A value of -1 waits indefinitely, a positive value gives
 * the number of milliseconds to wait at max.  */
#ifdef HAVE_W32_SYSTEM
static int
w32_remove (const char *fname, int wait_for_access)
{
  wchar_t *wfname;
  int wtime = 0;
  int totalwtime = 0;

  wfname = utf8_to_wchar (fname);
  if (!wfname)
    return -1; /* Error - ERRNO has already been set.  */

 again:
  if (DeleteFileW (wfname))
    {
      xfree (wfname);
      return 0; /* Success.  */
    }
  if (!wait_for_access
      || (wait_for_access > 0 && totalwtime > wait_for_access))
    gnupg_w32_set_errno (-1);
  else if ((wtime = w32_wait_when_sharing_violation (wtime, fname)))
    {
      totalwtime += wtime;
      goto again;
    }

  xfree (wfname);
  return -1;
}
#endif /* HAVE_W32_SYSTEM */

/* This is a remove function which allows - on Windows - to wait until
 * a sharing violation has been solved.  WAIT_FOR_ACCESS may eitehr be
 * -1 to wait indefinitely or the number of milliseconds to wait
 * before giving up.  */
int
gnupg_remove_ext (const char *fname, int wait_for_access)
{
#ifdef HAVE_W32_SYSTEM
  return w32_remove (fname, wait_for_access);
#else /* Unix */
  (void)wait_for_access;
  /* It is common to use /dev/null for testing.  We better don't
   * remove that file.  */
  if (fname && !strcmp (fname, "/dev/null"))
    return 0;
  else
    return remove (fname);
#endif
}

int
gnupg_remove (const char *fname)
{
  return gnupg_remove_ext (fname, 0);
}


/* Helper for gnupg_rename_file.  */
#ifdef HAVE_W32_SYSTEM
static int
w32_rename (const char *oldname, const char *newname)
{
  if (any8bitchar (oldname) || any8bitchar (newname))
    {
      wchar_t *woldname, *wnewname;
      int ret;

      woldname = utf8_to_wchar (oldname);
      if (!woldname)
        return -1;
      wnewname = utf8_to_wchar (newname);
      if (!wnewname)
        {
          xfree (wnewname);
          return -1;
        }
      ret = _wrename (woldname, wnewname);
      xfree (wnewname);
      xfree (woldname);
      return ret;
    }
  else
    return rename (oldname, newname);
}
#endif /*HAVE_W32_SYSTEM*/


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

    w32_remove (newname, -1);
  again:
    if (w32_rename (oldname, newname))
      {
        if ((wtime = w32_wait_when_sharing_violation (wtime, oldname)))
          goto again;
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
modestr_to_mode (const char *modestr, mode_t oldmode)
{
  static struct {
    char letter;
    mode_t value;
  } table[] = { { '-', 0 },
                { 'r', S_IRUSR }, { 'w', S_IWUSR }, { 'x', S_IXUSR },
                { 'r', S_IRGRP }, { 'w', S_IWGRP }, { 'x', S_IXGRP },
                { 'r', S_IROTH }, { 'w', S_IWOTH }, { 'x', S_IXOTH } };
  int idx;
  mode_t mode = 0;

  /* For now we only support a string as used by ls(1) and no octal
   * numbers.  The first character must be a dash.  */
  for (idx=0; idx < 10 && *modestr; idx++, modestr++)
    {
      if (*modestr == table[idx].letter)
        mode |= table[idx].value;
      else if (*modestr == '.')
        {
          if (!idx)
            ;  /* Skip the dummy.  */
          else if ((oldmode & table[idx].value))
            mode |= (oldmode & table[idx].value);
          else
            mode &= ~(oldmode & table[idx].value);
        }
      else if (*modestr != '-')
        break;
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
  /* Note that gpgrt_mkdir also sets ERRNO in addition to returning an
   * gpg-error style error code.  */
  return gpgrt_mkdir (name, modestr);
}


/* A simple wrapper around chdir.  NAME is expected to be utf8
 * encoded.  */
int
gnupg_chdir (const char *name)
{
  /* Note that gpgrt_chdir also sets ERRNO in addition to returning an
   * gpg-error style error code.  */
  return gpgrt_chdir (name);
}


/* A wrapper around rmdir.  NAME is expected to be utf8 encoded.  */
int
gnupg_rmdir (const char *name)
{
#ifdef HAVE_W32_SYSTEM
  int rc;
  wchar_t *wfname;

  wfname = utf8_to_wchar (name);
  if (!wfname)
    rc = 0;
  else
    {
      rc = RemoveDirectoryW (wfname);
      if (!rc)
        gnupg_w32_set_errno (-1);
      xfree (wfname);
    }
  if (!rc)
    return -1;
  return 0;
#else
  return rmdir (name);
#endif
}


/* A wrapper around chmod which takes a string for the mode argument.
   This makes it easier to handle the mode argument which is not
   defined on all systems.  The format of the modestring is the same
   as for gnupg_mkdir with extra feature that a '.' keeps the original
   mode bit.  */
int
gnupg_chmod (const char *name, const char *modestr)
{
#ifdef HAVE_W32_SYSTEM
  (void)name;
  (void)modestr;
  return 0;
#else
  mode_t oldmode;
  if (strchr (modestr, '.'))
    {
      /* Get the old mode so that a '.' can copy that bit.  */
      struct stat st;

      if (stat (name, &st))
        return -1;
      oldmode = st.st_mode;
    }
  else
    oldmode = 0;
  return chmod (name, modestr_to_mode (modestr, oldmode));
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
#ifdef HAVE_W32_SYSTEM
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
#endif /*W32*/

#ifdef HAVE_SETENV
  return setenv (name, value, overwrite);
#else /*!HAVE_SETENV*/
  if (! getenv (name) || overwrite)
#if defined(HAVE_W32_SYSTEM) && defined(_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES)
    {
      int e = _putenv_s (name, value);

      if (e)
        {
          gpg_err_set_errno (e);
          return -1;
        }
      else
        return 0;
    }
#else
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
#endif /*!HAVE_W32_SYSTEM*/
  return 0;
#endif /*!HAVE_SETENV*/
}


int
gnupg_unsetenv (const char *name)
{
#ifdef HAVE_W32_SYSTEM
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
#endif /*W32*/

#ifdef HAVE_UNSETENV
  return unsetenv (name);
#elif defined(HAVE_W32_SYSTEM) && defined(_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES)
  {
    int e = _putenv_s (name, "");

    if (e)
      {
	gpg_err_set_errno (e);
	return -1;
      }
    else
      return 0;
  }
#else /*!HAVE_UNSETENV*/
  {
    char *buf;
    int r;

    if (!name)
      {
        gpg_err_set_errno (EINVAL);
        return -1;
      }
    buf = strconcat (name, "=", NULL);
    if (!buf)
      return -1;

    r = putenv (buf);
# ifdef HAVE_W32_SYSTEM
    /* For Microsoft implementation, we can free the memory in this
       use case.  */
    xfree (buf);
# else
#  if __GNUC__
#   warning no unsetenv - trying putenv but leaking memory.
#  endif
# endif
    return r;
  }
#endif /*!HAVE_UNSETENV*/
}


/* Return the current working directory as a malloced string.  Return
   NULL and sets ERRNO on error.  */
char *
gnupg_getcwd (void)
{
  return gpgrt_getcwd ();
}


/* A simple wrapper around access.  NAME is expected to be utf8
 * encoded.  This function returns an error code and sets ERRNO. */
gpg_err_code_t
gnupg_access (const char *name, int mode)
{
  return gpgrt_access (name, mode);
}


/* A wrapper around stat to handle Unicode file names under Windows.  */
#ifdef HAVE_STAT
int
gnupg_stat (const char *name, struct stat *statbuf)
{
# ifdef HAVE_W32_SYSTEM
#  if __MINGW32_MAJOR_VERSION > 3
    /* mingw.org's MinGW */
#   define STRUCT_STAT _stat
#  elif defined(_USE_32BIT_TIME_T)
    /* MinGW64 for i686 */
#   define STRUCT_STAT _stat32
#  else
    /* MinGW64 for x86_64 */
#   define STRUCT_STAT _stat64i32
#  endif
  if (any8bitchar (name))
    {
      wchar_t *wname;
      struct STRUCT_STAT st32;
      int ret;

      wname = utf8_to_wchar (name);
      if (!wname)
        return -1;
      ret = _wstat (wname, &st32);
      xfree (wname);
      if (!ret)
        {
          statbuf->st_dev   = st32.st_dev;
          statbuf->st_ino   = st32.st_ino;
          statbuf->st_mode  = st32.st_mode;
          statbuf->st_nlink = st32.st_nlink;
          statbuf->st_uid   = st32.st_uid;
          statbuf->st_gid   = st32.st_gid;
          statbuf->st_rdev  = st32.st_rdev;
          statbuf->st_size  = st32.st_size;
          statbuf->st_atime = st32.st_atime;
          statbuf->st_mtime = st32.st_mtime;
          statbuf->st_ctime = st32.st_ctime;
        }
      return ret;
    }
  else
    return stat (name, statbuf);
# else
  return stat (name, statbuf);
# endif
}
#endif /*HAVE_STAT*/


/* A wrapper around open to handle Unicode file names under Windows.  */
int
gnupg_open (const char *name, int flags, unsigned int mode)
{
#ifdef HAVE_W32_SYSTEM
  if (any8bitchar (name))
    {
      wchar_t *wname;
      int ret;

      wname = utf8_to_wchar (name);
      if (!wname)
        return -1;
      ret = _wopen (wname, flags, mode);
      xfree (wname);
      return ret;
    }
  else
    return open (name, flags, mode);
#else
  return open (name, flags, mode);
#endif
}


/* A wrapper around opendir to handle Unicode file names under
 * Windows.  This assumes the mingw toolchain.  */
gnupg_dir_t
gnupg_opendir (const char *name)
{
#ifdef HAVE_W32_SYSTEM
  _WDIR *dir;
  wchar_t *wname;
#else
  DIR *dir;
#endif
  gnupg_dir_t gdir;

#ifdef HAVE_W32_SYSTEM
  /* Note: See gpgtar-create for an alternative implementation which
   * could be used here to avoid a mingw dependency.  */
  wname = utf8_to_wchar (name);
  if (!wname)
    return NULL;
  dir = _wopendir (wname);
  xfree (wname);
#else
  dir = opendir (name);
#endif

  if (!dir)
    return NULL;

  gdir = xtrymalloc (sizeof *gdir);
  if (!gdir)
    {
      int save_errno = errno;
#ifdef HAVE_W32_SYSTEM
      _wclosedir (dir);
#else
      closedir (dir);
#endif
      gpg_err_set_errno (save_errno);
      return NULL;
    }
  gdir->dir = dir;
  gdir->namesize = 0;
  gdir->dirent.d_name = gdir->name;

  return gdir;
}


gnupg_dirent_t
gnupg_readdir (gnupg_dir_t gdir)
{
#ifdef HAVE_W32_SYSTEM
  char *namebuffer = NULL;
  struct _wdirent *de;
#else
  struct dirent *de;
#endif
  size_t n;
  gnupg_dirent_t gde;
  const char *name;

  if (!gdir)
    {
      gpg_err_set_errno (EINVAL);
      return 0;
    }

#ifdef HAVE_W32_SYSTEM
  de = _wreaddir (gdir->dir);
  if (!de)
    return NULL;
  namebuffer = wchar_to_utf8 (de->d_name);
  if (!namebuffer)
    return NULL;
  name = namebuffer;
#else
  de = readdir (gdir->dir);
  if (!de)
    return NULL;
  name = de->d_name;
#endif

  gde = &gdir->dirent;
  n = strlen (name);
  if (gdir->namesize)
    {
      /* Use allocated buffer.  */
      if (n+1 >= gdir->namesize || !gde->d_name)
        {
          gdir->namesize = n + 256;
          xfree (gde->d_name);
          gde->d_name = xtrymalloc (gdir->namesize);
          if (!gde->d_name)
            return NULL;  /* ERRNO is already set.  */
        }
      strcpy (gde->d_name, name);
    }
  else if (n+1 >= sizeof (gdir->name))
    {
      /* Switch to allocated buffer.  */
      gdir->namesize = n + 256;
      gde->d_name = xtrymalloc (gdir->namesize);
      if (!gde->d_name)
        return NULL;  /* ERRNO is already set.  */
      strcpy (gde->d_name, name);
    }
  else
    {
      /* Use static buffer.  */
      gde->d_name = gdir->name;
      strcpy (gde->d_name, name);
    }

#ifdef HAVE_W32_SYSTEM
  xfree (namebuffer);
#endif

  return gde;
}


int
gnupg_closedir (gnupg_dir_t gdir)
{
#ifdef HAVE_W32_SYSTEM
  _WDIR *dir;
#else
  DIR *dir;
#endif

  if (!gdir)
    return 0;
  dir = gdir->dir;
  if (gdir->namesize)
    xfree (gdir->dirent.d_name);
  xfree (gdir);

#ifdef HAVE_W32_SYSTEM
  return _wclosedir (dir);
#else
  return closedir (dir);
#endif
}


/* Try to set an envvar.  Print only a notice on error.  */
#ifndef HAVE_W32_SYSTEM
static void
try_set_envvar (const char *name, const char *value, int silent)
{
  if (gnupg_setenv (name, value, 1))
    if (!silent)
      log_info ("error setting envvar %s to '%s': %s\n", name, value,
                gpg_strerror (my_error_from_syserror ()));
}
#endif /*!HAVE_W32_SYSTEM*/


/* Switch to USER which is either a name or an UID.  This is a nop
 * under Windows.  Note that in general it is only possible to switch
 * to another user id if the process is running under root.  if silent
 * is set no diagnostics are printed.  */
gpg_error_t
gnupg_chuid (const char *user, int silent)
{
#ifdef HAVE_W32_SYSTEM
  (void)user;  /* Not implemented for Windows - ignore.  */
  (void)silent;
  return 0;

#elif HAVE_PWD_H /* A proper Unix  */
  unsigned long ul;
  struct passwd *pw;
  struct stat st;
  char *endp;
  gpg_error_t err;

  gpg_err_set_errno (0);
  ul = strtoul (user, &endp, 10);
  if (errno || endp == user || *endp)
    pw = getpwnam (user);  /* Not a number; assume USER is a name.  */
  else
    pw = getpwuid ((uid_t)ul);

  if (!pw)
    {
      if (!silent)
        log_error ("user '%s' not found\n", user);
      return my_error (GPG_ERR_NOT_FOUND);
    }

  /* Try to set some envvars even if we are already that user.  */
  if (!stat (pw->pw_dir, &st))
    try_set_envvar ("HOME", pw->pw_dir, silent);

  try_set_envvar ("USER", pw->pw_name, silent);
  try_set_envvar ("LOGNAME", pw->pw_name, silent);
#ifdef _AIX
  try_set_envvar ("LOGIN", pw->pw_name, silent);
#endif

  if (getuid () == pw->pw_uid)
    return 0;  /* We are already this user.  */

  /* If we need to switch set PATH to a standard value and make sure
   * GNUPGHOME is not set. */
  try_set_envvar ("PATH", "/usr/local/bin:/usr/bin:/bin", silent);
  if (gnupg_unsetenv ("GNUPGHOME"))
    if (!silent)
      log_info ("error unsetting envvar %s: %s\n", "GNUPGHOME",
                gpg_strerror (gpg_error_from_syserror ()));

  if (initgroups (pw->pw_name, pw->pw_gid))
    {
      err = my_error_from_syserror ();
      if (!silent)
        log_error ("error setting supplementary groups for '%s': %s\n",
                   pw->pw_name, gpg_strerror (err));
      return err;
    }

  if (setuid (pw->pw_uid))
    {
      err = my_error_from_syserror ();
      log_error ("error switching to user '%s': %s\n",
                 pw->pw_name, gpg_strerror (err));
      return err;
    }

  return 0;

#else /*!HAVE_PWD_H */
  if (!silent)
    log_info ("system is missing passwd querying functions\n");
  return my_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}





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

/* Store a new inotify file handle for FNAME at R_FD or return an
 * error code.  This file descriptor watch the removal of FNAME. */
gpg_error_t
gnupg_inotify_watch_delete_self (int *r_fd, const char *fname)
{
#if HAVE_INOTIFY_INIT
  gpg_error_t err;
  int fd;

  *r_fd = -1;

  if (!fname)
    return my_error (GPG_ERR_INV_VALUE);

  fd = inotify_init ();
  if (fd == -1)
    return my_error_from_syserror ();

  if (inotify_add_watch (fd, fname, IN_DELETE_SELF) == -1)
    {
      err = my_error_from_syserror ();
      close (fd);
      return err;
    }

  *r_fd = fd;
  return 0;
#else /*!HAVE_INOTIFY_INIT*/

  (void)fname;
  *r_fd = -1;
  return my_error (GPG_ERR_NOT_SUPPORTED);

#endif /*!HAVE_INOTIFY_INIT*/
}


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


/* Open a stream from FD (a file descriptor on POSIX, a system
   handle on Windows), non-closed.  */
estream_t
open_stream_nc (gnupg_fd_t fd, const char *mode)
{
  es_syshd_t syshd;

#ifdef HAVE_W32_SYSTEM
  syshd.type = ES_SYSHD_HANDLE;
  syshd.u.handle = fd;
#else
  syshd.type = ES_SYSHD_FD;
  syshd.u.fd = fd;
#endif

  return es_sysopen_nc (&syshd, mode);
}


/* Debug helper to track down problems with logging under Windows.  */
void
output_debug_string (const char *format, ...)
{
#ifdef HAVE_W32_SYSTEM
  char *buf;
  va_list arg_ptr;

  va_start (arg_ptr, format);
  buf = gpgrt_vbsprintf (format, arg_ptr);
  va_end (arg_ptr);
  if (buf)
    OutputDebugStringA (buf);
  else
    OutputDebugStringA ("vbsprintf failed");
  gpgrt_free (buf);
#else
  (void)format;
#endif
}
