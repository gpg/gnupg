/* exec.c - generic call-a-program code
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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
   FIXME: We should replace most code in this module by our
   spawn implementation from common/exechelp.c.
 */


#include <config.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef EXEC_TEMPFILE_ONLY
#include <sys/wait.h>
#endif
#ifdef HAVE_DOSISH_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "gpg.h"
#include "options.h"
#include "../common/i18n.h"
#include "../common/iobuf.h"
#include "../common/util.h"
#include "../common/membuf.h"
#include "../common/sysutils.h"
#include "exec.h"

#ifdef NO_EXEC
int
exec_write(struct exec_info **info,const char *program,
	       const char *args_in,const char *name,int writeonly,int binary)
{
  log_error(_("no remote program execution supported\n"));
  return GPG_ERR_GENERAL;
}

int
exec_read(struct exec_info *info) { return GPG_ERR_GENERAL; }
int
exec_finish(struct exec_info *info) { return GPG_ERR_GENERAL; }
int
set_exec_path(const char *path) { return GPG_ERR_GENERAL; }

#else /* ! NO_EXEC */

#if defined (_WIN32)
/* This is a nicer system() for windows that waits for programs to
   return before returning control to the caller.  I hate helpful
   computers. */
static int
w32_system(const char *command)
{
  if (!strncmp (command, "!ShellExecute ", 14))
    {
      SHELLEXECUTEINFOW see;
      wchar_t *wname;
      int waitms;

      command = command + 14;
      while (spacep (command))
        command++;
      waitms = atoi (command);
      if (waitms < 0)
        waitms = 0;
      else if (waitms > 60*1000)
        waitms = 60000;
      while (*command && !spacep (command))
        command++;
      while (spacep (command))
        command++;

      wname = utf8_to_wchar (command);
      if (!wname)
        return -1;

      memset (&see, 0, sizeof see);
      see.cbSize = sizeof see;
      see.fMask = (SEE_MASK_NOCLOSEPROCESS
                   | SEE_MASK_NOASYNC
                   | SEE_MASK_FLAG_NO_UI
                   | SEE_MASK_NO_CONSOLE);
      see.lpVerb = L"open";
      see.lpFile = (LPCWSTR)wname;
      see.nShow = SW_SHOW;

      if (DBG_EXTPROG)
        log_debug ("running ShellExecuteEx(open,'%s')\n", command);
      if (!ShellExecuteExW (&see))
        {
          if (DBG_EXTPROG)
            log_debug ("ShellExecuteEx failed: rc=%d\n", (int)GetLastError ());
          xfree (wname);
          return -1;
        }
      if (DBG_EXTPROG)
        log_debug ("ShellExecuteEx succeeded (hProcess=%p,hInstApp=%d)\n",
                   see.hProcess, (int)see.hInstApp);

      if (!see.hProcess)
        {
          gnupg_usleep (waitms*1000);
          if (DBG_EXTPROG)
            log_debug ("ShellExecuteEx ready (wait=%dms)\n", waitms);
        }
      else
        {
          WaitForSingleObject (see.hProcess, INFINITE);
          if (DBG_EXTPROG)
            log_debug ("ShellExecuteEx ready\n");
        }
      CloseHandle (see.hProcess);

      xfree (wname);
    }
  else
    {
      char *string;
      PROCESS_INFORMATION pi;
      STARTUPINFO si;

      /* We must use a copy of the command as CreateProcess modifies
       * this argument. */
      string = xstrdup (command);

      memset (&pi, 0, sizeof(pi));
      memset (&si, 0, sizeof(si));
      si.cb = sizeof (si);

      if (!CreateProcess (NULL, string, NULL, NULL, FALSE,
                          DETACHED_PROCESS,
                          NULL, NULL, &si, &pi))
        return -1;

      /* Wait for the child to exit */
      WaitForSingleObject (pi.hProcess, INFINITE);

      CloseHandle (pi.hProcess);
      CloseHandle (pi.hThread);
      xfree (string);
    }

  return 0;
}
#endif /*_W32*/


/* Replaces current $PATH */
int
set_exec_path(const char *path)
{
#ifdef HAVE_W32CE_SYSTEM
#warning Change this code to use common/exechelp.c
#else
  char *p;

  p=xmalloc(5+strlen(path)+1);
  strcpy(p,"PATH=");
  strcat(p,path);

  if(DBG_EXTPROG)
    log_debug("set_exec_path: %s\n",p);

  /* Notice that path is never freed.  That is intentional due to the
     way putenv() works.  This leaks a few bytes if we call
     set_exec_path multiple times. */

  if(putenv(p)!=0)
    return GPG_ERR_GENERAL;
  else
    return 0;
#endif
}

/* Makes a temp directory and filenames */
static int
make_tempdir(struct exec_info *info)
{
  char *tmp=opt.temp_dir,*namein=info->name,*nameout;

  if(!namein)
    namein=info->flags.binary?"tempin" EXTSEP_S "bin":"tempin" EXTSEP_S "txt";

  nameout=info->flags.binary?"tempout" EXTSEP_S "bin":"tempout" EXTSEP_S "txt";

  /* Make up the temp dir and files in case we need them */

  if(tmp==NULL)
    {
#if defined (_WIN32)
      int err;

      tmp=xmalloc(MAX_PATH+2);
      err=GetTempPath(MAX_PATH+1,tmp);
      if(err==0 || err>MAX_PATH+1)
	strcpy(tmp,"c:\\windows\\temp");
      else
	{
	  int len=strlen(tmp);

	  /* GetTempPath may return with \ on the end */
	  while(len>0 && tmp[len-1]=='\\')
	    {
	      tmp[len-1]='\0';
	      len--;
	    }
	}
#else /* More unixish systems */
      tmp=getenv("TMPDIR");
      if(tmp==NULL)
	{
	  tmp=getenv("TMP");
	  if(tmp==NULL)
	    {
#ifdef __riscos__
	      tmp="<Wimp$ScrapDir>.GnuPG";
	      mkdir(tmp,0700); /* Error checks occur later on */
#else
	      tmp="/tmp";
#endif
	    }
	}
#endif
    }

  info->tempdir=xmalloc(strlen(tmp)+strlen(DIRSEP_S)+10+1);

  sprintf(info->tempdir,"%s" DIRSEP_S "gpg-XXXXXX",tmp);

#if defined (_WIN32)
  xfree(tmp);
#endif

  if (!gnupg_mkdtemp(info->tempdir))
    log_error(_("can't create directory '%s': %s\n"),
	      info->tempdir,strerror(errno));
  else
    {
      info->flags.madedir=1;

      info->tempfile_in=xmalloc(strlen(info->tempdir)+
				strlen(DIRSEP_S)+strlen(namein)+1);
      sprintf(info->tempfile_in,"%s" DIRSEP_S "%s",info->tempdir,namein);

      if(!info->flags.writeonly)
	{
	  info->tempfile_out=xmalloc(strlen(info->tempdir)+
				     strlen(DIRSEP_S)+strlen(nameout)+1);
	  sprintf(info->tempfile_out,"%s" DIRSEP_S "%s",info->tempdir,nameout);
	}
    }

  return info->flags.madedir? 0 : GPG_ERR_GENERAL;
}

/* Expands %i and %o in the args to the full temp files within the
   temp directory. */
static int
expand_args(struct exec_info *info,const char *args_in)
{
  const char *ch = args_in;
  membuf_t command;

  info->flags.use_temp_files=0;
  info->flags.keep_temp_files=0;

  if(DBG_EXTPROG)
    log_debug("expanding string \"%s\"\n",args_in);

  init_membuf (&command, 100);

  while(*ch!='\0')
    {
      if(*ch=='%')
	{
	  char *append=NULL;

	  ch++;

	  switch(*ch)
	    {
	    case 'O':
	      info->flags.keep_temp_files=1;
	      /* fall through */

	    case 'o': /* out */
	      if(!info->flags.madedir)
		{
		  if(make_tempdir(info))
		    goto fail;
		}
	      append=info->tempfile_out;
	      info->flags.use_temp_files=1;
	      break;

	    case 'I':
	      info->flags.keep_temp_files=1;
	      /* fall through */

	    case 'i': /* in */
	      if(!info->flags.madedir)
		{
		  if(make_tempdir(info))
		    goto fail;
		}
	      append=info->tempfile_in;
	      info->flags.use_temp_files=1;
	      break;

	    case '%':
	      append="%";
	      break;
	    }

	  if(append)
            put_membuf_str (&command, append);
	}
      else
        put_membuf (&command, ch, 1);

      ch++;
    }

  put_membuf (&command, "", 1);  /* Terminate string.  */

  info->command = get_membuf (&command, NULL);
  if (!info->command)
    return gpg_error_from_syserror ();

  if(DBG_EXTPROG)
    log_debug("args expanded to \"%s\", use %u, keep %u\n",info->command,
	      info->flags.use_temp_files,info->flags.keep_temp_files);

  return 0;

 fail:
  xfree (get_membuf (&command, NULL));
  return GPG_ERR_GENERAL;
}

/* Either handles the tempfile creation, or the fork/exec.  If it
   returns ok, then info->tochild is a FILE * that can be written to.
   The rules are: if there are no args, then it's a fork/exec/pipe.
   If there are args, but no tempfiles, then it's a fork/exec/pipe via
   shell -c.  If there are tempfiles, then it's a system. */

int
exec_write(struct exec_info **info,const char *program,
           const char *args_in,const char *name,int writeonly,int binary)
{
  int ret = GPG_ERR_GENERAL;

  if(opt.exec_disable && !opt.no_perm_warn)
    {
      log_info(_("external program calls are disabled due to unsafe "
		 "options file permissions\n"));

      return ret;
    }

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
  /* There should be no way to get to this spot while still carrying
     setuid privs.  Just in case, bomb out if we are. */
  if ( getuid () != geteuid ())
    BUG ();
#endif

  if(program==NULL && args_in==NULL)
    BUG();

  *info=xmalloc_clear(sizeof(struct exec_info));

  if(name)
    (*info)->name=xstrdup(name);
  (*info)->flags.binary=binary;
  (*info)->flags.writeonly=writeonly;

  /* Expand the args, if any */
  if(args_in && expand_args(*info,args_in))
    goto fail;

#ifdef EXEC_TEMPFILE_ONLY
  if(!(*info)->flags.use_temp_files)
    {
      log_error(_("this platform requires temporary files when calling"
		  " external programs\n"));
      goto fail;
    }

#else /* !EXEC_TEMPFILE_ONLY */

  /* If there are no args, or there are args, but no temp files, we
     can use fork/exec/pipe */
  if(args_in==NULL || (*info)->flags.use_temp_files==0)
    {
      int to[2],from[2];

      if(pipe(to)==-1)
	goto fail;

      if(pipe(from)==-1)
	{
	  close(to[0]);
	  close(to[1]);
	  goto fail;
	}

      if(((*info)->child=fork())==-1)
	{
	  close(to[0]);
	  close(to[1]);
	  close(from[0]);
	  close(from[1]);
	  goto fail;
	}

      if((*info)->child==0)
	{
	  char *shell=getenv("SHELL");

	  if(shell==NULL)
	    shell="/bin/sh";

	  /* I'm the child */

	  /* If the program isn't going to respond back, they get to
             keep their stdout/stderr */
	  if(!(*info)->flags.writeonly)
	    {
	      /* implied close of STDERR */
	      if(dup2(STDOUT_FILENO,STDERR_FILENO)==-1)
		_exit(1);

	      /* implied close of STDOUT */
	      close(from[0]);
	      if(dup2(from[1],STDOUT_FILENO)==-1)
		_exit(1);
	    }

	  /* implied close of STDIN */
	  close(to[1]);
	  if(dup2(to[0],STDIN_FILENO)==-1)
	    _exit(1);

	  if(args_in==NULL)
	    {
	      if(DBG_EXTPROG)
		log_debug("execlp: %s\n",program);

	      execlp(program,program,(void *)NULL);
	    }
	  else
	    {
	      if(DBG_EXTPROG)
		log_debug("execlp: %s -c %s\n",shell,(*info)->command);

	      execlp(shell,shell,"-c",(*info)->command,(void *)NULL);
	    }

	  /* If we get this far the exec failed.  Clean up and return. */

	  if(args_in==NULL)
	    log_error(_("unable to execute program '%s': %s\n"),
		      program,strerror(errno));
	  else
	    log_error(_("unable to execute shell '%s': %s\n"),
		      shell,strerror(errno));

	  /* This mimics the POSIX sh behavior - 127 means "not found"
             from the shell. */
	  if(errno==ENOENT)
	    _exit(127);

	  _exit(1);
	}

      /* I'm the parent */

      close(to[0]);

      (*info)->tochild=fdopen(to[1],binary?"wb":"w");
      if((*info)->tochild==NULL)
	{
          ret = gpg_error_from_syserror ();
	  close(to[1]);
	  goto fail;
	}

      close(from[1]);

      (*info)->fromchild=iobuf_fdopen(from[0],"r");
      if((*info)->fromchild==NULL)
	{
          ret = gpg_error_from_syserror ();
	  close(from[0]);
	  goto fail;
	}

      /* fd iobufs are cached! */
      iobuf_ioctl((*info)->fromchild, IOBUF_IOCTL_NO_CACHE, 1, NULL);

      return 0;
    }
#endif /* !EXEC_TEMPFILE_ONLY */

  if(DBG_EXTPROG)
    log_debug("using temp file '%s'\n",(*info)->tempfile_in);

  /* It's not fork/exec/pipe, so create a temp file */
  if( is_secured_filename ((*info)->tempfile_in) )
    {
      (*info)->tochild = NULL;
      gpg_err_set_errno (EPERM);
    }
  else
    (*info)->tochild = gnupg_fopen ((*info)->tempfile_in,binary?"wb":"w");
  if((*info)->tochild==NULL)
    {
      ret = gpg_error_from_syserror ();
      log_error(_("can't create '%s': %s\n"),
		(*info)->tempfile_in,strerror(errno));
      goto fail;
    }

  ret=0;

 fail:
  if (ret)
    {
      xfree (*info);
      *info = NULL;
    }
  return ret;
}

int
exec_read(struct exec_info *info)
{
  int ret = GPG_ERR_GENERAL;

  fclose(info->tochild);
  info->tochild=NULL;

  if(info->flags.use_temp_files)
    {
      if(DBG_EXTPROG)
	log_debug ("running command: %s\n",info->command);

#if defined (_WIN32)
      info->progreturn=w32_system(info->command);
#else
      info->progreturn=system(info->command);
#endif

      if(info->progreturn==-1)
	{
	  log_error(_("system error while calling external program: %s\n"),
		    strerror(errno));
	  info->progreturn=127;
	  goto fail;
	}

#if defined(WIFEXITED) && defined(WEXITSTATUS)
      if(WIFEXITED(info->progreturn))
	info->progreturn=WEXITSTATUS(info->progreturn);
      else
	{
	  log_error(_("unnatural exit of external program\n"));
	  info->progreturn=127;
	  goto fail;
	}
#else
      /* If we don't have the macros, do the best we can. */
      info->progreturn = (info->progreturn & 0xff00) >> 8;
#endif

      /* 127 is the magic value returned from system() to indicate
         that the shell could not be executed, or from /bin/sh to
         indicate that the program could not be executed. */

      if(info->progreturn==127)
	{
	  log_error(_("unable to execute external program\n"));
	  goto fail;
	}

      if(!info->flags.writeonly)
	{
	  info->fromchild=iobuf_open(info->tempfile_out);
          if (info->fromchild
              && is_secured_file (iobuf_get_fd (info->fromchild)))
            {
              iobuf_close (info->fromchild);
              info->fromchild = NULL;
              gpg_err_set_errno (EPERM);
            }
	  if(info->fromchild==NULL)
	    {
              ret = gpg_error_from_syserror ();
	      log_error(_("unable to read external program response: %s\n"),
			strerror(errno));
	      goto fail;
	    }

	  /* Do not cache this iobuf on close */
	  iobuf_ioctl(info->fromchild, IOBUF_IOCTL_NO_CACHE, 1, NULL);
	}
    }

  ret=0;

 fail:
  return ret;
}

int
exec_finish(struct exec_info *info)
{
  int ret=info->progreturn;

  if(info->fromchild)
    iobuf_close(info->fromchild);

  if(info->tochild)
    fclose(info->tochild);

#ifndef EXEC_TEMPFILE_ONLY
  if(info->child>0)
    {
      if(waitpid(info->child,&info->progreturn,0)!=0 &&
	 WIFEXITED(info->progreturn))
	ret=WEXITSTATUS(info->progreturn);
      else
	{
	  log_error(_("unnatural exit of external program\n"));
	  ret=127;
	}
    }
#endif

  if(info->flags.madedir && !info->flags.keep_temp_files)
    {
      if(info->tempfile_in)
	{
	  if(unlink(info->tempfile_in)==-1)
	    log_info(_("WARNING: unable to remove tempfile (%s) '%s': %s\n"),
		     "in",info->tempfile_in,strerror(errno));
	}

      if(info->tempfile_out)
	{
	  if(unlink(info->tempfile_out)==-1)
	    log_info(_("WARNING: unable to remove tempfile (%s) '%s': %s\n"),
		     "out",info->tempfile_out,strerror(errno));
	}

      if(rmdir(info->tempdir)==-1)
	log_info(_("WARNING: unable to remove temp directory '%s': %s\n"),
		 info->tempdir,strerror(errno));
    }

  xfree(info->command);
  xfree(info->name);
  xfree(info->tempdir);
  xfree(info->tempfile_in);
  xfree(info->tempfile_out);
  xfree(info);

  return ret;
}
#endif /* ! NO_EXEC */
