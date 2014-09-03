#ifndef WDFSMAIN_H_
#define WDFSMAIN_H_

#include <fuse.h>
#include <ne_basic.h>


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


#endif /*WDFSMAIN_H_*/
