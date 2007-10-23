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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
#include <windows.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "options.h"
#include "memory.h"
#include "i18n.h"
#include "iobuf.h"
#include "util.h"
#include "exec.h"

#ifdef NO_EXEC
int exec_write(struct exec_info **info,const char *program,
	       const char *args_in,const char *name,int writeonly,int binary)
{
  log_error(_("no remote program execution supported\n"));
  return G10ERR_GENERAL;
}

int exec_read(struct exec_info *info) { return G10ERR_GENERAL; }
int exec_finish(struct exec_info *info) { return G10ERR_GENERAL; }
int set_exec_path(const char *path) { return G10ERR_GENERAL; }

#else /* ! NO_EXEC */

#ifndef HAVE_MKDTEMP
char *mkdtemp(char *template);
#endif

#if defined (_WIN32)
/* This is a nicer system() for windows that waits for programs to
   return before returning control to the caller.  I hate helpful
   computers. */
static int win_system(const char *command)
{
  PROCESS_INFORMATION pi;
  STARTUPINFO si;
  char *string;

  /* We must use a copy of the command as CreateProcess modifies this
     argument. */
  string=xstrdup(command);

  memset(&pi,0,sizeof(pi));
  memset(&si,0,sizeof(si));
  si.cb=sizeof(si);

  if(!CreateProcess(NULL,string,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
    return -1;

  /* Wait for the child to exit */
  WaitForSingleObject(pi.hProcess,INFINITE);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  xfree(string);

  return 0;
}
#endif

/* Replaces current $PATH */
int set_exec_path(const char *path)
{
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
    return G10ERR_GENERAL;
  else
    return 0;
}

/* Makes a temp directory and filenames */
static int make_tempdir(struct exec_info *info)
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

      tmp=xmalloc(MAX_PATH);
      err=GetTempPath(MAX_PATH,tmp);
      if(err==0 || err>MAX_PATH)
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

  if(mkdtemp(info->tempdir)==NULL)
    log_error(_("can't create directory `%s': %s\n"),
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

  return info->flags.madedir?0:G10ERR_GENERAL;
}

/* Expands %i and %o in the args to the full temp files within the
   temp directory. */
static int expand_args(struct exec_info *info,const char *args_in)
{
  const char *ch=args_in;
  unsigned int size,len;

  info->flags.use_temp_files=0;
  info->flags.keep_temp_files=0;

  if(DBG_EXTPROG)
    log_debug("expanding string \"%s\"\n",args_in);

  size=100;
  info->command=xmalloc(size);
  len=0;
  info->command[0]='\0';

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
	    {
	      size_t applen=strlen(append);

	      if(applen+len>size-1)
		{
		  if(applen<100)
		    applen=100;

		  size+=applen;
		  info->command=xrealloc(info->command,size);
		}

	      strcat(info->command,append);
	      len+=strlen(append);
	    }
	}
      else
	{
	  if(len==size-1) /* leave room for the \0 */
	    {
	      size+=100;
	      info->command=xrealloc(info->command,size);
	    }

	  info->command[len++]=*ch;
	  info->command[len]='\0';
	}

      ch++;
    }

  if(DBG_EXTPROG)
    log_debug("args expanded to \"%s\", use %u, keep %u\n",info->command,
	      info->flags.use_temp_files,info->flags.keep_temp_files);

  return 0;

 fail:

  xfree(info->command);
  info->command=NULL;

  return G10ERR_GENERAL;
}

/* Either handles the tempfile creation, or the fork/exec.  If it
   returns ok, then info->tochild is a FILE * that can be written to.
   The rules are: if there are no args, then it's a fork/exec/pipe.
   If there are args, but no tempfiles, then it's a fork/exec/pipe via
   shell -c.  If there are tempfiles, then it's a system. */

int exec_write(struct exec_info **info,const char *program,
	       const char *args_in,const char *name,int writeonly,int binary)
{
  int ret=G10ERR_GENERAL;

  if(opt.exec_disable && !opt.no_perm_warn)
    {
      log_info(_("external program calls are disabled due to unsafe "
		 "options file permissions\n"));

      return ret;
    }

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
  /* There should be no way to get to this spot while still carrying
     setuid privs.  Just in case, bomb out if we are. */
  if(getuid()!=geteuid())
    BUG();
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
	    log_error(_("unable to execute program `%s': %s\n"),
		      program,strerror(errno));
	  else
	    log_error(_("unable to execute shell `%s': %s\n"),
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
	  close(to[1]);
	  ret=G10ERR_WRITE_FILE;
	  goto fail;
	}

      close(from[1]);

      (*info)->fromchild=iobuf_fdopen(from[0],"r");
      if((*info)->fromchild==NULL)
	{
	  close(from[0]);
	  ret=G10ERR_READ_FILE;
	  goto fail;
	}

      /* fd iobufs are cached?! */
      iobuf_ioctl((*info)->fromchild,3,1,NULL);

      return 0;
    }
#endif /* !EXEC_TEMPFILE_ONLY */

  if(DBG_EXTPROG)
    log_debug("using temp file `%s'\n",(*info)->tempfile_in);

  /* It's not fork/exec/pipe, so create a temp file */
  if( is_secured_filename ((*info)->tempfile_in) )
    {
      (*info)->tochild = NULL;
      errno = EPERM;
    }
  else
    (*info)->tochild=fopen((*info)->tempfile_in,binary?"wb":"w");
  if((*info)->tochild==NULL)
    {
      log_error(_("can't create `%s': %s\n"),
		(*info)->tempfile_in,strerror(errno));
      ret=G10ERR_WRITE_FILE;
      goto fail;
    }

  ret=0;

 fail:
  return ret;
}

int exec_read(struct exec_info *info)
{
  int ret=G10ERR_GENERAL;

  fclose(info->tochild);
  info->tochild=NULL;

  if(info->flags.use_temp_files)
    {
      if(DBG_EXTPROG)
	log_debug("system() command is %s\n",info->command);

#if defined (_WIN32)
      info->progreturn=win_system(info->command);
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
              errno = EPERM;
            }
	  if(info->fromchild==NULL)
	    {
	      log_error(_("unable to read external program response: %s\n"),
			strerror(errno));
	      ret=G10ERR_READ_FILE;
	      goto fail;
	    }

	  /* Do not cache this iobuf on close */
	  iobuf_ioctl(info->fromchild,3,1,NULL);
	}
    }

  ret=0;

 fail:
  return ret;
}

int exec_finish(struct exec_info *info)
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
	    log_info(_("WARNING: unable to remove tempfile (%s) `%s': %s\n"),
		     "in",info->tempfile_in,strerror(errno));
	}
  
      if(info->tempfile_out)
	{
	  if(unlink(info->tempfile_out)==-1)
	    log_info(_("WARNING: unable to remove tempfile (%s) `%s': %s\n"),
		     "out",info->tempfile_out,strerror(errno));
	}

      if(rmdir(info->tempdir)==-1)
	log_info(_("WARNING: unable to remove temp directory `%s': %s\n"),
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
