/* photoid.c - photo ID handling code
 * Copyright (C) 2001, 2002, 2005, 2006, 2008, 2011 Free Software Foundation, Inc.
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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
# ifndef VER_PLATFORM_WIN32_WINDOWS
#  define VER_PLATFORM_WIN32_WINDOWS 1
# endif
#endif

#include "gpg.h"
#include "../common/util.h"
#include "packet.h"
#include "../common/status.h"
#include "keydb.h"
#include "../common/i18n.h"
#include "../common/iobuf.h"
#include "options.h"
#include "main.h"
#include "photoid.h"
#include "../common/ttyio.h"
#include "trustdb.h"

#if defined (_WIN32)
/* This is a nicer system() for windows that waits for programs to
   return before returning control to the caller.  I hate helpful
   computers. */
static int
w32_system (const char *command)
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
      wchar_t *wstring;
      PROCESS_INFORMATION pi;
      STARTUPINFOW si;

      /* We must use a copy of the command as CreateProcess modifies
       * this argument. */
      string = xstrdup (command);
      wstring = utf8_to_wchar (string);
      xfree (string);
      if (!wstring)
        return -1;

      memset (&pi, 0, sizeof(pi));
      memset (&si, 0, sizeof(si));
      si.cb = sizeof (si);

      if (!CreateProcessW (NULL, wstring, NULL, NULL, FALSE,
                           DETACHED_PROCESS,
                           NULL, NULL, &si, &pi))
        {
          xfree (wstring);
          return -1;
        }

      /* Wait for the child to exit */
      WaitForSingleObject (pi.hProcess, INFINITE);

      CloseHandle (pi.hProcess);
      CloseHandle (pi.hThread);
      xfree (wstring);
    }

  return 0;
}
#endif /*_W32*/

/* Generate a new photo id packet, or return NULL if canceled.
   FIXME:  Should we add a duplicates check similar to generate_user_id? */
PKT_user_id *
generate_photo_id (ctrl_t ctrl, PKT_public_key *pk,const char *photo_name)
{
  PKT_user_id *uid;
  int error=1,i;
  uint64_t len;
  char *filename;
  byte *photo=NULL;
  byte header[16];
  IOBUF file;

  header[0]=0x10; /* little side of photo header length */
  header[1]=0;    /* big side of photo header length */
  header[2]=1;    /* 1 == version of photo header */
  header[3]=1;    /* 1 == JPEG */

  for(i=4;i<16;i++) /* The reserved bytes */
    header[i]=0;

#define EXTRA_UID_NAME_SPACE 71
  uid=xmalloc_clear(sizeof(*uid)+71);

  if(photo_name && *photo_name)
    filename=make_filename(photo_name,(void *)NULL);
  else
    {
      tty_printf(_("\nPick an image to use for your photo ID."
		   "  The image must be a JPEG file.\n"
		   "Remember that the image is stored within your public key."
		   "  If you use a\n"
		   "very large picture, your key will become very large"
		   " as well!\n"
		   "Keeping the image close to 240x288 is a good size"
		   " to use.\n"));
      filename=NULL;
    }

  while(photo==NULL)
    {
      if(filename==NULL)
	{
	  char *tempname;

	  tty_printf("\n");

	  tty_enable_completion(NULL);

	  tempname=cpr_get("photoid.jpeg.add",
			   _("Enter JPEG filename for photo ID: "));

	  tty_disable_completion();

	  filename=make_filename(tempname,(void *)NULL);

	  xfree(tempname);

	  if(strlen(filename)==0)
	    goto scram;
	}

      file=iobuf_open(filename);
      if (file && is_secured_file (iobuf_get_fd (file)))
        {
          iobuf_close (file);
          file = NULL;
          gpg_err_set_errno (EPERM);
        }
      if(!file)
	{
	  log_error(_("unable to open JPEG file '%s': %s\n"),
		    filename,strerror(errno));
	  xfree(filename);
	  filename=NULL;
	  continue;
	}


      len = iobuf_get_filelength(file);
      if(len>6144)
	{
          /* We silently skip JPEGs larger than 1MiB because we have a
           * 2MiB limit on the user ID packets and we need some limit
           * anyway because the returned u64 is larger than the u32 or
           * OpenPGP.  Note that the diagnostic may print a wrong
           * value if the value is really large; we don't fix this to
           * avoid a string change.  */
	  tty_printf( _("This JPEG is really large (%d bytes) !\n"), (int)len);
	  if(len > 1024*1024
             || !cpr_get_answer_is_yes("photoid.jpeg.size",
			    _("Are you sure you want to use it? (y/N) ")))
	  {
	    iobuf_close(file);
	    xfree(filename);
	    filename=NULL;
	    continue;
	  }
	}

      photo=xmalloc(len);
      iobuf_read(file,photo,len);
      iobuf_close(file);

      /* Is it a JPEG? */
      if(photo[0]!=0xFF || photo[1]!=0xD8)
	{
	  log_error(_("'%s' is not a JPEG file\n"),filename);
	  xfree(photo);
	  photo=NULL;
	  xfree(filename);
	  filename=NULL;
	  continue;
	}

      /* Build the packet */
      build_attribute_subpkt(uid,1,photo,len,header,16);
      parse_attribute_subpkts(uid);
      make_attribute_uidname(uid, EXTRA_UID_NAME_SPACE);

      /* Showing the photo is not safe when noninteractive since the
         "user" may not be able to dismiss a viewer window! */
      if(opt.command_fd==-1)
	{
	  show_photos (ctrl, uid->attribs, uid->numattribs, pk, uid);
	  switch(cpr_get_answer_yes_no_quit("photoid.jpeg.okay",
					 _("Is this photo correct (y/N/q)? ")))
	    {
	    case -1:
	      goto scram;
	    case 0:
	      free_attributes(uid);
	      xfree(photo);
	      photo=NULL;
	      xfree(filename);
	      filename=NULL;
	      continue;
	    }
	}
    }

  error=0;
  uid->ref=1;

 scram:
  xfree(filename);
  xfree(photo);

  if(error)
    {
      free_attributes(uid);
      xfree(uid);
      return NULL;
    }

  return uid;
}

/* Returns 0 for error, 1 for valid */
int parse_image_header(const struct user_attribute *attr,byte *type,u32 *len)
{
  u16 headerlen;

  if(attr->len<3)
    return 0;

  /* For historical reasons (i.e. "oops!"), the header length is
     little endian. */
  headerlen=(attr->data[1]<<8) | attr->data[0];

  if(headerlen>attr->len)
    return 0;

  if(type && attr->len>=4)
    {
      if(attr->data[2]==1) /* header version 1 */
	*type=attr->data[3];
      else
	*type=0;
    }

  *len=attr->len-headerlen;

  if(*len==0)
    return 0;

  return 1;
}

/* style==0 for extension, 1 for name, 2 for MIME type.  Remember that
   the "name" style string could be used in a user ID name field, so
   make sure it is not too big (see parse-packet.c:parse_attribute).
   Extensions should be 3 characters long for the best cross-platform
   compatibility. */
const char *
image_type_to_string(byte type,int style)
{
  const char *string;

  switch(type)
    {
    case 1: /* jpeg */
      if(style==0)
	string="jpg";
      else if(style==1)
	string="jpeg";
      else
	string="image/jpeg";
      break;

    default:
      if(style==0)
	string="bin";
      else if(style==1)
	string="unknown";
      else
	string="image/x-unknown";
      break;
    }

  return string;
}

#if !defined(FIXED_PHOTO_VIEWER) && !defined(DISABLE_PHOTO_VIEWER)
static const char *
get_default_photo_command(void)
{
#if defined(_WIN32)
  OSVERSIONINFO osvi;

  memset(&osvi,0,sizeof(osvi));
  osvi.dwOSVersionInfoSize=sizeof(osvi);
  GetVersionEx(&osvi);

  if(osvi.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
    return "start /w %i";
  else
    return "!ShellExecute 400 %i";
#elif defined(__APPLE__)
  /* OS X.  This really needs more than just __APPLE__. */
  return "open %I";
#else
  if (!path_access ("xloadimage", X_OK))
    return "xloadimage -fork -quiet -title 'KeyID 0x%k' stdin";
  else if (!path_access ("display",X_OK))
    return "display -title 'KeyID 0x%k' %i";
  else if (getuid () && !path_access ("xdg-open", X_OK))
    {
      /* xdg-open spawns the actual program and exits so we need to
       * keep the temp file */
      return "xdg-open %I";
    }
  else
    return "/bin/true";
#endif
}
#endif

#ifndef DISABLE_PHOTO_VIEWER
struct spawn_info
{
  unsigned int keep_temp_file;
  char *command;
  char *tempdir;
  char *tempfile;
};

#ifdef NO_EXEC
static void
show_photo (const char *command, const char *name, const void *image, u32 len)
{
  log_error(_("no remote program execution supported\n"));
  return GPG_ERR_GENERAL;
}
#else /* ! NO_EXEC */
#include "../common/membuf.h"
#include "../common/exechelp.h"

/* Makes a temp directory and filenames */
static int
setup_input_file (struct spawn_info *info, const char *name)
{
  char *tmp = opt.temp_dir;
  int len;
#define TEMPLATE "gpg-XXXXXX"

  /* Initialize by the length of last part in the path + 1 */
  len = strlen (DIRSEP_S) + strlen (TEMPLATE) + 1;

  /* Make up the temp dir and file in case we need them */
  if (tmp)
    {
      len += strlen (tmp);
      info->tempdir = xmalloc (len);
    }
  else
    {
#if defined (_WIN32)
      int ret;

      tmp = xmalloc (MAX_PATH+1);
      if (!tmp)
        return -1;

      ret = GetTempPath (MAX_PATH-len, tmp);
      if (ret == 0 || ret >= MAX_PATH-len)
	strcpy (tmp, "c:\\windows\\temp");
      else
	{
	  /* GetTempPath may return with \ on the end */
	  while (ret > 0 && tmp[ret-1] == '\\')
	    {
	      tmp[ret-1]='\0';
	      ret--;
	    }
	}

      len += ret;
      info->tempdir = tmp;
#else /* More unixish systems */
      if (!(tmp = getenv ("TMPDIR"))
          && !(tmp = getenv ("TMP")))
        tmp = "/tmp";

      len += strlen (tmp);
      info->tempdir = xmalloc (len);
#endif
    }

  if (info->tempdir == NULL)
    return -1;

  sprintf (info->tempdir, "%s" DIRSEP_S TEMPLATE, tmp);

  if (gnupg_mkdtemp (info->tempdir) == NULL)
    {
      log_error (_("can't create directory '%s': %s\n"),
                 info->tempdir, strerror (errno));
      return -1;
    }

  info->tempfile = xmalloc (strlen (info->tempdir) + strlen (DIRSEP_S)
                               + strlen (name) + 1);
  if (info->tempfile == NULL)
    {
      xfree (info->tempdir);
      info->tempdir = NULL;
      return -1;
    }
  sprintf (info->tempfile, "%s" DIRSEP_S "%s", info->tempdir, name);
  return 0;
}

/* Expands %i or %I in the args to the full temp file within the temp
   directory. */
static int
expand_args (struct spawn_info *info, const char *args_in, const char *name)
{
  const char *ch = args_in;
  membuf_t command;

  info->keep_temp_file = 0;

  if (DBG_EXTPROG)
    log_debug ("expanding string \"%s\"\n", args_in);

  init_membuf (&command, 100);

  while (*ch != '\0')
    {
      if (*ch == '%')
	{
	  const char *append = NULL;

	  ch++;

	  switch (*ch)
	    {
	    case 'I':
	      info->keep_temp_file = 1;
	      /* fall through */

	    case 'i': /* in */
	      if (info->tempfile == NULL)
		{
		  if (setup_input_file (info, name) < 0)
		    goto fail;
		}
	      append = info->tempfile;
	      break;

	    case '%':
	      append = "%";
	      break;
	    }

	  if (append)
            put_membuf_str (&command, append);
	}
      else
        put_membuf (&command, ch, 1);

      ch++;
    }

  put_membuf (&command, "", 1);  /* Terminate string.  */

  info->command = get_membuf (&command, NULL);
  if (!info->command)
    return -1;

  if(DBG_EXTPROG)
    log_debug("args expanded to \"%s\", use %s, keep %u\n", info->command,
	      info->tempfile, info->keep_temp_file);

  return 0;

 fail:
  xfree (get_membuf (&command, NULL));
  return -1;
}

#ifndef EXEC_TEMPFILE_ONLY
static void
fill_command_argv (const char *argv[4], const char *command)
{
  argv[0] = getenv ("SHELL");
  if (argv[0] == NULL)
    argv[0] = "/bin/sh";

  argv[1] = "-c";
  argv[2] = command;
  argv[3] = NULL;
}
#endif

static void
run_with_pipe (struct spawn_info *info, const void *image, u32 len)
{
#ifdef EXEC_TEMPFILE_ONLY
  (void)info;
  (void)image;
  (void)len;
  log_error (_("this platform requires temporary files when calling"
               " external programs\n"));
  return;
#else /* !EXEC_TEMPFILE_ONLY */
  int to[2];
  pid_t pid;
  gpg_error_t err;
  const char *argv[4];

  err = gnupg_create_pipe (to);
  if (err)
    return;

  fill_command_argv (argv, info->command);
  err = gnupg_spawn_process_fd (argv[0], argv+1, to[0], -1, -1, &pid);

  close (to[0]);

  if (err)
    {
      log_error (_("unable to execute shell '%s': %s\n"),
                 argv[0], gpg_strerror (err));
      close (to[1]);
    }
  else
    {
      write (to[1], image, len);
      close (to[1]);

      err = gnupg_wait_process (argv[0], pid, 1, NULL);
      if (err)
        log_error (_("unnatural exit of external program\n"));
    }
#endif /* !EXEC_TEMPFILE_ONLY */
}

static int
create_temp_file (struct spawn_info *info, const void *ptr, u32 len)
{
  if (DBG_EXTPROG)
    log_debug ("using temp file '%s'\n", info->tempfile);

  /* It's not fork/exec/pipe, so create a temp file */
  if ( is_secured_filename (info->tempfile) )
    {
      log_error (_("can't create '%s': %s\n"),
                 info->tempfile, strerror (EPERM));
      gpg_err_set_errno (EPERM);
      return -1;
    }
  else
    {
      estream_t fp = es_fopen (info->tempfile, "wb");

      if (fp)
        {
          es_fwrite (ptr, len, 1, fp);
          es_fclose (fp);
          return 0;
        }
      else
        {
          int save = errno;
          log_error (_("can't create '%s': %s\n"),
                     info->tempfile, strerror(errno));
          gpg_err_set_errno (save);
          return -1;
        }
    }
}

static void
show_photo (const char *command, const char *name, const void *image, u32 len)
{
  struct spawn_info *spawn;

  spawn = xmalloc_clear (sizeof (struct spawn_info));
  if (!spawn)
    return;

  /* Expand the args */
  if (expand_args (spawn, command, name) < 0)
    {
      xfree (spawn);
      return;
    }

  if (DBG_EXTPROG)
    log_debug ("running command: %s\n", spawn->command);

  if (spawn->tempfile == NULL)
    run_with_pipe (spawn, image, len);
  else if (create_temp_file (spawn, image, len) == 0)
    {
#if defined (_WIN32)
      if (w32_system (spawn->command) < 0)
        log_error (_("system error while calling external program: %s\n"),
                   strerror (errno));
#else
      pid_t pid;
      gpg_error_t err;
      const char *argv[4];

      fill_command_argv (argv, spawn->command);
      err = gnupg_spawn_process_fd (argv[0], argv+1, -1, -1, -1, &pid);
      if (!err)
        err = gnupg_wait_process (argv[0], pid, 1, NULL);
      if (err)
        log_error (_("unnatural exit of external program\n"));
#endif

      if (!spawn->keep_temp_file)
        {
          if (unlink (spawn->tempfile) < 0)
            log_info (_("WARNING: unable to remove tempfile (%s) '%s': %s\n"),
                      "in", spawn->tempfile, strerror(errno));

          if (rmdir (spawn->tempdir) < 0)
            log_info (_("WARNING: unable to remove temp directory '%s': %s\n"),
                      spawn->tempdir, strerror(errno));
        }
    }

  xfree(spawn->command);
  xfree(spawn->tempdir);
  xfree(spawn->tempfile);
  xfree(spawn);
}
#endif
#endif


void
show_photos (ctrl_t ctrl, const struct user_attribute *attrs, int count,
             PKT_public_key *pk, PKT_user_id *uid)
{
#ifdef DISABLE_PHOTO_VIEWER
  (void)attrs;
  (void)count;
  (void)pk;
  (void)uid;
#else /*!DISABLE_PHOTO_VIEWER*/
  int i;
  struct expando_args args;
  u32 len;
  u32 kid[2]={0,0};

  if (opt.exec_disable && !opt.no_perm_warn)
    {
      log_info (_("external program calls are disabled due to unsafe "
                  "options file permissions\n"));
      return;
    }

#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
  /* There should be no way to get to this spot while still carrying
     setuid privs.  Just in case, bomb out if we are. */
  if ( getuid () != geteuid ())
    BUG ();
#endif

  memset (&args, 0, sizeof(args));
  args.pk = pk;
  args.validity_info = get_validity_info (ctrl, NULL, pk, uid);
  args.validity_string = get_validity_string (ctrl, pk, uid);
  namehash_from_uid (uid);
  args.namehash = uid->namehash;

  if (pk)
    keyid_from_pk (pk, kid);

  es_fflush (es_stdout);

#ifdef FIXED_PHOTO_VIEWER
  opt.photo_viewer = FIXED_PHOTO_VIEWER;
#else
  if (!opt.photo_viewer)
    opt.photo_viewer = get_default_photo_command ();
#endif

  for (i=0; i<count; i++)
    if (attrs[i].type == ATTRIB_IMAGE
        && parse_image_header (&attrs[i], &args.imagetype, &len))
      {
        char *command, *name;
        int offset = attrs[i].len-len;

	/* make command grow */
	command = pct_expando (ctrl, opt.photo_viewer,&args);
	if(!command)
	  goto fail;
        if (!*command)
          {
            xfree (command);
            goto fail;
          }

	name = xmalloc (1 + 16 + strlen(EXTSEP_S)
                        + strlen (image_type_to_string (args.imagetype, 0)));

	if (!name)
          {
            xfree (command);
            goto fail;
          }

	/* Make the filename.  Notice we are not using the image
           encoding type for more than cosmetics.  Most external image
           viewers can handle a multitude of types, and even if one
           cannot understand a particular type, we have no way to know
           which.  The spec permits this, by the way. -dms */

#ifdef USE_ONLY_8DOT3
	sprintf (name,"%08lX" EXTSEP_S "%s", (ulong)kid[1],
                 image_type_to_string (args.imagetype, 0));
#else
	sprintf (name, "%08lX%08lX" EXTSEP_S "%s",
                 (ulong)kid[0], (ulong)kid[1],
                 image_type_to_string (args.imagetype, 0));
#endif

        show_photo (command, name, &attrs[i].data[offset], len);
        xfree (name);
        xfree (command);
      }

  return;

 fail:
  log_error(_("unable to display photo ID!\n"));
#endif /*!DISABLE_PHOTO_VIEWER*/
}
