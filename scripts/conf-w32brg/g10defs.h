
#define inline __inline
#define __inline__	__inline

#define	BYTES_PER_MPI_LIMB	4

#define PRINTABLE_OS_NAME	"Win32"

#define GNUPG_HOMEDIR	 "c:\\Program Files\\gnupg"
#define GNUPG_LIBDIR	 "c:\\Program Files\\gnupg"
#define GNUPG_DATADIR	 "c:\\Program Files\\gnupg"
#define GNUPG_LIBEXECDIR "c:\\Program Files\\gnupg"

#define	EXTSEP_S	"."
#define	DIRSEP_S	"\\"
#define	DIRSEP_C	'\\'

#include <io.h>
#include <direct.h>
#define getpid	_getpid
#define pid_t	int
#define	mode_t	int
#define access	_access
#define chmod	_chmod
#define	mkdir	_mkdir
#define	open	_open
#define	close	_close
#define	read	_read
#define write	_write
#define	umask	_umask
#define	strncasecmp	_strnicmp
#define	F_OK	0
#define	W_OK	2
#define	R_OK	4
#define	RW_OK	6
#define S_IRUSR	_S_IREAD
#define S_IWUSR	_S_IWRITE 
#define S_RWUSR	(_S_IREAD|_S_IWRITE) 
#define	S_ISREG(x)	(x & _S_IFREG)
#define	sockaddr_un	sockaddr_in
#define	sun_path	sin_zero
#define	sun_family	sin_family
