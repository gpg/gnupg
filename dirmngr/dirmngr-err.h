/* Definition of the gpg-error source.  */

#ifndef DIRMNGR_ERR_H
#define DIRMNGR_ERR_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_DIRMNGR
#include <gpg-error.h>

#endif /*DIRMNGR_ERR_H*/
