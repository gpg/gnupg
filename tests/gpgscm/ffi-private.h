/* FFI interface for TinySCHEME.
 *
 * Copyright (C) 2016 g10 code GmbH
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

#ifndef GPGSCM_FFI_PRIVATE_H
#define GPGSCM_FFI_PRIVATE_H

#include <gpg-error.h>
#include "scheme.h"
#include "scheme-private.h"

#define FFI_PROLOG()						\
  unsigned int ffi_arg_index GPGRT_ATTR_UNUSED = 1;		\
  int err GPGRT_ATTR_UNUSED = 0					\

int ffi_bool_value (scheme *sc, pointer p);

#define CONVERSION_number(SC, X) (SC)->vptr->ivalue (X)
#define CONVERSION_string(SC, X) (SC)->vptr->string_value (X)
#define CONVERSION_character(SC, X) (SC)->vptr->charvalue (X)
#define CONVERSION_list(SC, X)	(X)
#define CONVERSION_bool(SC, X)	ffi_bool_value ((SC), (X))
#define CONVERSION_path(SC, X)	(((SC)->vptr->is_string (X)	  \
				  ? (SC)->vptr->string_value	  \
				  : (SC)->vptr->symname) (X))

#define IS_A_number(SC, X)	(SC)->vptr->is_number (X)
#define IS_A_string(SC, X)	(SC)->vptr->is_string (X)
#define IS_A_character(SC, X)	(SC)->vptr->is_character (X)
#define IS_A_list(SC, X)	(SC)->vptr->is_list ((SC), X)
#define IS_A_bool(SC, X)	((X) == (SC)->F || (X) == (SC)->T)
#define IS_A_path(SC, X)	((SC)->vptr->is_string (X)	\
				 || (SC)->vptr->is_symbol (X))

#define FFI_ARG_OR_RETURN(SC, CTYPE, TARGET, WANT, ARGS)		\
  do {									\
  if ((ARGS) == (SC)->NIL)						\
    return (SC)->vptr->mk_string ((SC),					\
				  "too few arguments: want "		\
				  #TARGET "("#WANT"/"#CTYPE")\n");	\
  if (! IS_A_##WANT ((SC), pair_car (ARGS))) {				\
    char ffi_error_message[256];					\
    snprintf (ffi_error_message, sizeof ffi_error_message,		\
	      "argument %d must be: " #WANT "\n", ffi_arg_index);	\
    return  (SC)->vptr->mk_string ((SC), ffi_error_message);		\
  }									\
  TARGET = CONVERSION_##WANT (SC, pair_car (ARGS));			\
  ARGS = pair_cdr (ARGS);						\
  ffi_arg_index += 1;							\
  } while (0)

#define FFI_ARGS_DONE_OR_RETURN(SC, ARGS)                               \
  do {									\
  if ((ARGS) != (SC)->NIL)						\
    return (SC)->vptr->mk_string ((SC), "too many arguments");		\
  } while (0)

#define FFI_RETURN_ERR(SC, ERR)					\
  return _cons ((SC), mk_integer ((SC), (ERR)), (SC)->NIL, 1)

#define FFI_RETURN(SC)	FFI_RETURN_ERR (SC, err)

#define FFI_RETURN_POINTER(SC, X)					\
  return _cons ((SC), mk_integer ((SC), err),				\
		_cons ((SC), (X), (SC)->NIL, 1), 1)
#define FFI_RETURN_INT(SC, X)						\
  FFI_RETURN_POINTER ((SC), mk_integer ((SC), (X)))
#define FFI_RETURN_STRING(SC, X)			\
  FFI_RETURN_POINTER ((SC), mk_string ((SC), (X)))

char *ffi_schemify_name (const char *s, int macro);

void ffi_scheme_eval (scheme *sc, const char *format, ...)
  GPGRT_ATTR_PRINTF (2, 3);
pointer ffi_sprintf (scheme *sc, const char *format, ...)
  GPGRT_ATTR_PRINTF (2, 3);

#define ffi_define_function_name(SC, NAME, F)				\
  do {									\
    char *_fname = ffi_schemify_name ("__" #F, 0);                      \
    scheme_define ((SC),						\
		   (SC)->global_env,					\
		   mk_symbol ((SC), _fname),                            \
		   mk_foreign_func ((SC), (do_##F)));			\
    ffi_scheme_eval ((SC),						\
		     "(define (%s . a) (ffi-apply \"%s\" %s a))",	\
		     (NAME), (NAME), _fname);                           \
    free (_fname);                                                      \
  } while (0)

#define ffi_define_function(SC, F)                                      \
  do {									\
    char *_name = ffi_schemify_name (#F, 0);                            \
    ffi_define_function_name ((SC), _name, F);                          \
    free (_name);                                                       \
  } while (0)

#define ffi_define_constant(SC, C)					\
  do {									\
    char *_name = ffi_schemify_name (#C, 1);                            \
    scheme_define ((SC),                                                \
                   (SC)->global_env,					\
                   mk_symbol ((SC), _name),                             \
                   mk_integer ((SC), (C)));                             \
    free (_name);                                                       \
  } while (0)

#define ffi_define(SC, SYM, EXP)					\
  scheme_define ((SC), (SC)->global_env, mk_symbol ((SC), (SYM)), EXP)

#define ffi_define_variable_pointer(SC, C, P)				\
  do {									\
    char *_name = ffi_schemify_name (#C, 0);                            \
    scheme_define ((SC),                                                \
                   (SC)->global_env,					\
                   mk_symbol ((SC), _name),                             \
                   (P));                                                \
    free (_name);                                                       \
  } while (0)

#define ffi_define_variable_integer(SC, C)				\
  ffi_define_variable_pointer ((SC), C, (SC)->vptr->mk_integer ((SC), C))

#define ffi_define_variable_string(SC, C)				\
  ffi_define_variable_pointer ((SC), C, (SC)->vptr->mk_string ((SC), C ?: ""))

gpg_error_t ffi_list2argv (scheme *sc, pointer list,
			   char ***argv, size_t *len);
gpg_error_t ffi_list2intv (scheme *sc, pointer list,
			   int **intv, size_t *len);

#endif /* GPGSCM_FFI_PRIVATE_H */
