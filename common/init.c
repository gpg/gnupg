/* init.c - Various initializations
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif
#ifdef HAVE_W32CE_SYSTEM
# include <assuan.h> /* For _assuan_w32ce_finish_pipe. */
#endif

#include <gcrypt.h>
#include "util.h"
#include "i18n.h"

/* This object is used to register memory cleanup functions.
   Technically they are not needed but they can avoid frequent
   questions about un-released memory.  Note that we use the system
   malloc and not any wrappers.  */
struct mem_cleanup_item_s;
typedef struct mem_cleanup_item_s *mem_cleanup_item_t;

struct mem_cleanup_item_s
{
  mem_cleanup_item_t next;
  void (*func) (void);
};

static mem_cleanup_item_t mem_cleanup_list;


/* The default error source of the application.  This is different
   from GPG_ERR_SOURCE_DEFAULT in that it does not depend on the
   source file and thus is usable in code shared by applications.
   Note that we need to initialize it because otherwise some linkers
   (OS X at least) won't find the symbol when linking the t-*.c
   files.  */
gpg_err_source_t default_errsource = 0;


#ifdef HAVE_W32CE_SYSTEM
static void parse_std_file_handles (int *argcp, char ***argvp);
static void
sleep_on_exit (void)
{
  /* The sshd on CE swallows some of the command output.  Sleeping a
     while usually helps.  */
  Sleep (400);
}
#endif /*HAVE_W32CE_SYSTEM*/


static void
run_mem_cleanup (void)
{
  mem_cleanup_item_t next;

  while (mem_cleanup_list)
    {
      next = mem_cleanup_list->next;
      mem_cleanup_list->func ();
      free (mem_cleanup_list);
      mem_cleanup_list = next;
    }
}


void
register_mem_cleanup_func (void (*func)(void))
{
  mem_cleanup_item_t item;

  for (item = mem_cleanup_list; item; item = item->next)
    if (item->func == func)
      return; /* Function has already been registered.  */

  item = malloc (sizeof *item);
  if (item)
    {
      item->func = func;
      item->next = mem_cleanup_list;
      mem_cleanup_list = item;
    }
}


/* If STRING is not NULL write string to es_stdout or es_stderr.  MODE
   must be 1 or 2.  If STRING is NULL flush the respective stream.  */
static int
writestring_via_estream (int mode, const char *string)
{
  if (mode == 1 || mode == 2)
    {
      if (string)
        return es_fputs (string, mode == 1? es_stdout : es_stderr);
      else
        return es_fflush (mode == 1? es_stdout : es_stderr);
    }
  else
    return -1;
}


/* This function should be the first called after main.  */
void
early_system_init (void)
{
}


/* This function is to be used early at program startup to make sure
   that some subsystems are initialized.  This is in particular
   important for W32 to initialize the sockets so that our socket
   emulation code used directly as well as in libassuan may be used.
   It should best be called before any I/O is done so that setup
   required for logging is ready.  ARGCP and ARGVP are the addresses
   of the parameters given to main.  This function may modify them.

   This function should be called only via the macro
   init_common_subsystems.

   CAUTION: This might be called while running suid(root).  */
void
_init_common_subsystems (gpg_err_source_t errsource, int *argcp, char ***argvp)
{
  /* Store the error source in a global variable. */
  default_errsource = errsource;

  atexit (run_mem_cleanup);

  /* Try to auto set the character set.  */
  set_native_charset (NULL);

#ifdef HAVE_W32_SYSTEM
  /* For W32 we need to initialize the socket layer.  This is because
     we use recv and send in libassuan as well as at some other
     places.  */
  {
    WSADATA wsadat;

    WSAStartup (0x202, &wsadat);
  }
#endif

#ifdef HAVE_W32CE_SYSTEM
  /* Register the sleep exit function before the estream init so that
     the sleep will be called after the estream registered atexit
     function which flushes the left open estream streams and in
     particular es_stdout.  */
  atexit (sleep_on_exit);
#endif

  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION))
    {
      log_fatal (_("%s is too old (need %s, have %s)\n"), "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
    }

  /* Initialize the Estream library. */
  gpgrt_init ();
  gpgrt_set_alloc_func (gcry_realloc);

  /* Special hack for Windows CE: We extract some options from arg
     to setup the standard handles.  */
#ifdef HAVE_W32CE_SYSTEM
  parse_std_file_handles (argcp, argvp);
#else
  (void)argcp;
  (void)argvp;
#endif

  /* Access the standard estreams as early as possible.  If we don't
     do this the original stdio streams may have been closed when
     _es_get_std_stream is first use and in turn it would connect to
     the bit bucket.  */
  {
    int i;
    for (i=0; i < 3; i++)
      (void)_gpgrt_get_std_stream (i);
  }

  /* --version et al shall use estream as well.  */
  gnupg_set_usage_outfnc (writestring_via_estream);

  /* Register our string mapper with gpgrt.  */
  gnupg_set_fixed_string_mapper (map_static_macro_string);

  /* Logging shall use the standard socket directory as fallback.  */
  log_set_socket_dir_cb (gnupg_socketdir);
}



/* WindowsCE uses a very strange way of handling the standard streams.
   There is a function SetStdioPath to associate a standard stream
   with a file or a device but what we really want is to use pipes as
   standard streams.  Despite that we implement pipes using a device,
   we would have some limitations on the number of open pipes due to
   the 3 character limit of device file name.  Thus we don't take this
   path.  Another option would be to install a file system driver with
   support for pipes; this would allow us to get rid of the device
   name length limitation.  However, with GnuPG we can get away be
   redefining the standard streams and passing the handles to be used
   on the command line.  This has also the advantage that it makes
   creating a process much easier and does not require the
   SetStdioPath set and restore game.  The caller needs to pass the
   rendezvous ids using up to three options:

     -&S0=<rvid> -&S1=<rvid> -&S2=<rvid>

   They are all optional but they must be the first arguments on the
   command line.  Parsing stops as soon as an invalid option is found.
   These rendezvous ids are then used to finish the pipe creation.*/
#ifdef HAVE_W32CE_SYSTEM
static void
parse_std_file_handles (int *argcp, char ***argvp)
{
  int argc = *argcp;
  char **argv = *argvp;
  const char *s;
  assuan_fd_t fd;
  int i;
  int fixup = 0;

  if (!argc)
    return;

  for (argc--, argv++; argc; argc--, argv++)
    {
      s = *argv;
      if (*s == '-' && s[1] == '&' && s[2] == 'S'
          && (s[3] == '0' || s[3] == '1' || s[3] == '2')
          && s[4] == '='
          && (strchr ("-01234567890", s[5]) || !strcmp (s+5, "null")))
        {
          if (s[5] == 'n')
            fd = ASSUAN_INVALID_FD;
          else
            fd = _assuan_w32ce_finish_pipe (atoi (s+5), s[3] != '0');
          _es_set_std_fd (s[3] - '0', (int)fd);
          fixup++;
        }
      else
        break;
    }

  if (fixup)
    {
      argc = *argcp;
      argc -= fixup;
      *argcp = argc;

      argv = *argvp;
      for (i=1; i < argc; i++)
        argv[i] = argv[i + fixup];
      for (; i < argc + fixup; i++)
        argv[i] = NULL;
    }


}
#endif /*HAVE_W32CE_SYSTEM*/
