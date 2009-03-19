/* exechelp.h - Definitions for the fork and exec helpers
 *	Copyright (C) 2004, 2009 Free Software Foundation, Inc.
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
   use of this fucntion right at startup even before libgcrypt has
   been initialized.  Returns NULL on error and sets ERRNO accordingly.  */
int *get_all_open_fds (void);


/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  */
gpg_error_t gnupg_create_inbound_pipe (int filedes[2]);


/* Fork and exec the PGMNAME, connect the file descriptor of INFILE to
   stdin, write the output to OUTFILE, return a new stream in
   STATUSFILE for stderr and the pid of the process in PID. The
   arguments for the process are expected in the NULL terminated array
   ARGV.  The program name itself should not be included there.  If
   PREEXEC is not NULL, that function will be called right before the
   exec.  FLAGS is currently only useful for W32, see the source for
   details.  Calling gnupg_wait_process is required.  Returns 0 on
   success or an error code. */
gpg_error_t gnupg_spawn_process (const char *pgmname, const char *argv[],
                                 FILE *infile, FILE *outfile,
                                 void (*preexec)(void), unsigned int flags,
                                 FILE **statusfile, pid_t *pid);


/* Simplified version of gnupg_spawn_process.  This function forks and
   then execs PGMNAME, while connecting INFD to stdin, OUTFD to stdout
   and ERRFD to stderr (any of them may be -1 to connect them to
   /dev/null).  The arguments for the process are expected in the NULL
   terminated array ARGV.  The program name itself should not be
   included there.  Calling gnupg_wait_process is required.  Returns 0
   on success or an error code. */
gpg_error_t gnupg_spawn_process_fd (const char *pgmname, 
                                    const char *argv[],
                                    int infd, int outfd, int errfd,
                                    pid_t *pid);


/* Wait for the process identified by PID to terminate. PGMNAME should
   be the same as supplied to the spawn fucntion and is only used for
   diagnostics.  Returns 0 if the process succeded, GPG_ERR_GENERAL
   for any failures of the spawned program or other error codes.  If
   EXITCODE is not NULL the exit code of the process is stored at this
   address or -1 if it could not be retrieved.  */
gpg_error_t gnupg_wait_process (const char *pgmname, pid_t pid, int *exitcode);


/* Spawn a new process and immediatley detach from it.  The name of
   the program to exec is PGMNAME and its arguments are in ARGV (the
   programname is automatically passed as first argument).
   Environment strings in ENVP are set.  An error is returned if
   pgmname is not executable; to make this work it is necessary to
   provide an absolute file name.  */
gpg_error_t gnupg_spawn_process_detached (const char *pgmname,
                                          const char *argv[],
                                          const char *envp[] );



#endif /*GNUPG_COMMON_EXECHELP_H*/
