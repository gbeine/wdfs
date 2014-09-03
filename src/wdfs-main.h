#ifndef WDFSMAIN_H_
#define WDFSMAIN_H_


#define FUSE_USE_VERSION 25


#include <fuse.h>
#include <ne_basic.h>


/* build the neon version, which is not directly exported by the neon library */
#if defined(NE_FEATURE_TS_SSL)	/* true for neon 0.26+  */
  #define NEON_VERSION 26
#elif defined(NE_FEATURE_SSL)	/* true for neon 0.25+  */
  #define NEON_VERSION 25
#else							/* neon 0.24 is the minimal requirement */
  #define NEON_VERSION 24
#endif
/* 	it's also possible to replace the above with the following: 
	(file configure.ac, after the PKG_CHECK_MODULES call)

	case `pkg-config --modversion neon` in
		0.24*) AC_DEFINE(NEON_VERSION, 24,
				[The minor version number of the neon library]) ;;
		0.25*) AC_DEFINE(NEON_VERSION, 25) ;;
		*)     AC_DEFINE(NEON_VERSION, 26) ;;
	esac
*/


typedef enum {
	true 	= 1,
	false 	= 0
} bool_t;


/* look at wdfs-main.c for comments on these extern variables */
extern bool_t debug_mode;
extern bool_t accept_certificate;
extern const char *project_name;
extern char *remotepath_basedir;


/* used by wdfs_readdir() and by svn.h/svn.c to add files to requested 
 * directories by using the fuse filler() method. */
struct dir_item {
	void *buf;
	fuse_fill_dir_t filler;
	char *remotepath;
};


char* remove_ending_slash(const char *in);
void free_chars(char **arg, ...);


/* Macro to free things: takes an lvalue and sets it to NULL after freeing. */
#define FREE(x) do { if ((x) != NULL) free((x)); (x) = NULL; } while (0)


#endif /*WDFSMAIN_H_*/
