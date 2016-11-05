/* runner.h - Run and watch the backend engines
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#ifndef G13_RUNNER_H
#define G13_RUNNER_H

/* The runner object.  */
struct runner_s;
typedef struct runner_s *runner_t;

/* Prototypes for the handler functions provided by the engine.  */
typedef gpg_error_t (*engine_handler_fnc_t) (void *opaque,
                                             runner_t runner,
                                             const char *statusline);
typedef void (*engine_handler_cleanup_fnc_t) (void *opaque);


/* Return the number of active threads.  */
unsigned int runner_get_threads (void);

/* Create a new runner object.  */
gpg_error_t runner_new (runner_t *r_runner, const char *name);

/* Free a runner object.  */
void runner_release (runner_t runner);

/* Return the identifier of RUNNER.  */
unsigned int runner_get_rid (runner_t runner);

/* Find a runner by its rid.  */
runner_t runner_find_by_rid (unsigned int rid);

/* Functions to set properties of the runner.  */
void runner_set_fds (runner_t runner, int in_fd, int out_fd);

void runner_set_pid (runner_t runner, pid_t pid);

/* Register the handler functions with a runner.  */
void runner_set_handler (runner_t runner,
                         engine_handler_fnc_t handler,
                         engine_handler_cleanup_fnc_t handler_cleanup,
                         void *handler_data);

/* Start the runner.  */
gpg_error_t runner_spawn (runner_t runner);

/* Cancel a runner.  */
void runner_cancel (runner_t runner);

/* Cancel all runner.  */
void runner_cancel_all (void);

/* Send data back to the engine.  This function is used by the
   engine's handler.  */
gpg_error_t runner_send_line (runner_t runner,
                              const void *data, size_t datalen);



#endif /*G13_RUNNER_H*/
