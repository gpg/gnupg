/* exechelp.h - Definitions for the fork and exec helpers
 * Copyright (C) 2004, 2009, 2010 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_EXECHELP_H
#define GNUPG_COMMON_EXECHELP_H


/* Return the maximum number of currently allowed file descriptors.
   Only useful on POSIX systems.  */
int get_max_fds (void);


/* Close all file descriptors starting with descriptor FIRST.  If
   EXCEPT is not NULL, it is expected to be a list of file descriptors
   which are not to close.  This list shall be sorted in ascending
   order with its end marked by -1.  */
void close_all_fds (int first, int *except);


/* Returns an array with all currently open file descriptors.  The end
   of the array is marked by -1.  The caller needs to release this
   array using the *standard free* and not with xfree.  This allow the
   use of this function right at startup even before libgcrypt has
   been initialized.  Returns NULL on error and sets ERRNO accordingly.  */
int *get_all_open_fds (void);


/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  If R_FP is not NULL, an estream is created for the
   write end and stored at R_FP.  */
gpg_error_t gnupg_create_inbound_pipe (int filedes[2],
                                       estream_t *r_fp, int nonblock);

/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  If R_FP is not NULL, an estream is created for the
   write end and stored at R_FP.  */
gpg_error_t gnupg_create_outbound_pipe (int filedes[2],
                                        estream_t *r_fp, int nonblock);

/* Portable function to create a pipe.  Under Windows both ends are
   inheritable.  */
gpg_error_t gnupg_create_pipe (int filedes[2]);


#define GNUPG_SPAWN_NONBLOCK   16
#define GNUPG_SPAWN_RUN_ASFW   64
#define GNUPG_SPAWN_DETACHED  128
#define GNUPG_SPAWN_KEEP_STDIN   256
#define GNUPG_SPAWN_KEEP_STDOUT  512
#define GNUPG_SPAWN_KEEP_STDERR 1024

/* Fork and exec the program PGMNAME.

   If R_INFP is NULL connect stdin of the new process to /dev/null; if
   it is not NULL store the address of a pointer to a new estream
   there. If R_OUTFP is NULL connect stdout of the new process to
   /dev/null; if it is not NULL store the address of a pointer to a
   new estream there.  If R_ERRFP is NULL connect stderr of the new
   process to /dev/null; if it is not NULL store the address of a
   pointer to a new estream there.  On success the pid of the new
   process is stored at PID.  On error -1 is stored at PID and if
   R_OUTFP or R_ERRFP are not NULL, NULL is stored there.

   The arguments for the process are expected in the NULL terminated
   array ARGV.  The program name itself should not be included there.
   If PREEXEC is not NULL, the given function will be called right
   before the exec.

   IF EXCEPT is not NULL, it is expected to be an ordered list of file
   descriptors, terminated by an entry with the value (-1).  These
   file descriptors won't be closed before spawning a new program.

   Returns 0 on success or an error code.  Calling gnupg_wait_process
   and gnupg_release_process is required if the function succeeded.

   FLAGS is a bit vector:

   GNUPG_SPAWN_NONBLOCK
          If set the two output streams are created in non-blocking
          mode and the input stream is switched to non-blocking mode.
          This is merely a convenience feature because the caller
          could do the same with gpgrt_set_nonblock.  Does not yet
          work for Windows.

   GNUPG_SPAWN_DETACHED
          If set the process will be started as a background process.
          This flag is only useful under W32 (but not W32CE) systems,
          so that no new console is created and pops up a console
          window when starting the server.  Does not work on W32CE.

   GNUPG_SPAWN_RUN_ASFW
          On W32 (but not on W32CE) run AllowSetForegroundWindow for
          the child.  Note that due to unknown problems this actually
          allows SetForegroundWindow for all children of this process.

   GNUPG_SPAWN_KEEP_STDIN
   GNUPG_SPAWN_KEEP_STDOUT
   GNUPG_SPAWN_KEEP_STDERR
          Do not assign /dev/null to a non-required standard file
          descriptor.

 */
gpg_error_t
gnupg_spawn_process (const char *pgmname, const char *argv[],
                     int *execpt, void (*preexec)(void), unsigned int flags,
                     estream_t *r_infp,
                     estream_t *r_outfp,
                     estream_t *r_errfp,
                     pid_t *pid);


/* Simplified version of gnupg_spawn_process.  This function forks and
   then execs PGMNAME, while connecting INFD to stdin, OUTFD to stdout
   and ERRFD to stderr (any of them may be -1 to connect them to
   /dev/null).  The arguments for the process are expected in the NULL
   terminated array ARGV.  The program name itself should not be
   included there.  Calling gnupg_wait_process and
   gnupg_release_process is required.  Returns 0 on success or an
   error code. */
gpg_error_t gnupg_spawn_process_fd (const char *pgmname,
                                    const char *argv[],
                                    int infd, int outfd, int errfd,
                                    pid_t *pid);


/* If HANG is true, waits for the process identified by PID to exit;
   if HANG is false, checks whether the process has terminated.
   PGMNAME should be the same as supplied to the spawn function and is
   only used for diagnostics.  Return values:

   0
       The process exited successful.  0 is stored at R_EXITCODE.

   GPG_ERR_GENERAL
       The process exited without success.  The exit code of process
       is then stored at R_EXITCODE.  An exit code of -1 indicates
       that the process terminated abnormally (e.g. due to a signal).

   GPG_ERR_TIMEOUT
       The process is still running (returned only if HANG is false).

   GPG_ERR_INV_VALUE
       An invalid PID has been specified.

   Other error codes may be returned as well.  Unless otherwise noted,
   -1 will be stored at R_EXITCODE.  R_EXITCODE may be passed as NULL
   if the exit code is not required (in that case an error message will
   be printed).  Note that under Windows PID is not the process id but
   the handle of the process.  */
gpg_error_t gnupg_wait_process (const char *pgmname, pid_t pid, int hang,
                                int *r_exitcode);

/* Like gnupg_wait_process, but for COUNT processes.  */
gpg_error_t gnupg_wait_processes (const char **pgmnames, pid_t *pids,
				  size_t count, int hang, int *r_exitcodes);


/* Kill a process; that is send an appropriate signal to the process.
   gnupg_wait_process must be called to actually remove the process
   from the system.  An invalid PID is ignored.  */
void gnupg_kill_process (pid_t pid);

/* Release the process identified by PID.  This function is actually
   only required for Windows but it does not harm to always call it.
   It is a nop if PID is invalid.  */
void gnupg_release_process (pid_t pid);


/* Spawn a new process and immediately detach from it.  The name of
   the program to exec is PGMNAME and its arguments are in ARGV (the
   programname is automatically passed as first argument).
   Environment strings in ENVP are set.  An error is returned if
   pgmname is not executable; to make this work it is necessary to
   provide an absolute file name.  */
gpg_error_t gnupg_spawn_process_detached (const char *pgmname,
                                          const char *argv[],
                                          const char *envp[] );



#endif /*GNUPG_COMMON_EXECHELP_H*/
