/*
 *  this file is part of wdfs --> http://noedler.de/projekte/wdfs/
 *
 *  wdfs is a webdav filesystem with special features for accessing subversion
 *  repositories. it is based on fuse v2.3+ and neon v0.24.7+.
 *
 *  copyright (c) 2005 - 2006 jens m. noedler, noedler@web.de
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <glib.h>
#include <ne_props.h>
#include <ne_dates.h>
#include <ne_redirect.h>

#include "wdfs-main.h"
#include "webdav.h"
#include "cache.h"
#include "svn.h"


/* use package name and version from config.h, if it is available. */
#ifdef HAVE_CONFIG_H
  #include <config.h>
  #define PROJECT_NAME PACKAGE_NAME"/"VERSION
#else
  #define PROJECT_NAME "wdfs/unknown-version"
#endif

/* build the fuse version; only needed by fuse 2.3 and earlier */
#ifndef FUSE_VERSION
  #define FUSE_MAKE_VERSION(maj, min)  ((maj) * 10 + (min))
  #define FUSE_VERSION FUSE_MAKE_VERSION(FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION)
#endif

#if FUSE_VERSION < 25
  /* include is needed for the definition of uintptr_t,
   * fuse 2.5 and later export it thru fuse_common.h */
  #include <stdint.h>
#endif


/* if set to "true" wdfs specific debug output is generated. default is "false".
 * do not edit here! it can be changed via parameter "-D" passed to wdfs.    */
bool_t debug_mode = false;

/* if set to "true" via parameter "-ac" verify_ssl_certificate() [in webdav.c]
 * will not ask the user wether to accept the certificate or not. */
bool_t accept_certificate = false;

/* if set to "true" via parameter "-r" wdfs provides http redirect support   */
bool_t redirect_support = false;

/* webdav server base directory. if you are connected to "http://server/dir/"
 * remotepath_basedir is set to "/dir" (starting slash, no ending slash).
 * if connected to the root directory (http://server/) it will be set to "". */
char *remotepath_basedir;

/* product string according RFC2616, that is included in every request.      */
const char *project_name = PROJECT_NAME;

/* homepage of this filesystem                                               */
const char *project_url = "http://noedler.de/projekte/wdfs/";

/* enables or disables file locking for the webdav resource. 
 * do not edit here! it can be changed via parameter "-l" passed to wdfs.    */
bool_t locking_enabled = false;

/* lock timeout in seconds. "-1" means infinite. default are 300 sec. / 5 min.
 * do not edit here! it can be changed via parameter "-t sec" passed to wdfs */
int lock_timeout = 300;

/* there are two locking modes available. the simple locking mode locks a file 
 * on open()ing it and unlocks it on close()ing the file. the advanced mode 
 * prevents data curruption by locking the file on open() and holds the lock 
 * until the file was writen and closed or the lock timed out. the eternity 
 * mode holds the lock until wdfs is unmounted or the lock times out.        */
#define SIMPLE_LOCK 1
#define ADVANCED_LOCK 2
#define ETERNITY_LOCK 3

/* default locking mode is SIMPLE_LOCK
 * do not edit here! it can be changed via parameter "-m mode" passed to wdfs*/
int locking_mode = SIMPLE_LOCK;


/* infos about an open file. used by open(), read(), write() and release()   */
struct open_file {
	unsigned long fh;	/* this file's filehandle                            */
	bool_t modified;	/* set true if the filehandle's content is modified  */
};


/* webdav properties used to get file attributes */
static const ne_propname properties_fileattr[] = {
	{ "DAV:", "resourcetype" },
	{ "DAV:", "getcontentlength" },
	{ "DAV:", "getlastmodified" },
	{ "DAV:", "creationdate" },
	{ NULL }  /* MUST be NULL terminated! */
};


/* +++ exported method +++ */


/* free()s each char passed that is not NULL and sets it to NULL after freeing */
void free_chars(char **arg, ...) {
	va_list ap;
	va_start(ap, arg);
	while (arg) {
		if (*arg != NULL)
			free(*arg);
		*arg = NULL;
		/* get the next parameter */
		arg = va_arg(ap, char **);
	}
	va_end(ap);
}


/* removes '/' if it's the last character. returns the new malloc()d string. */
char* remove_ending_slash(const char *in)
{
	int length = strlen(in);
	if (length-1 >= 0  &&  in[length-1] == '/')
		return (char *)strndup(in, length-1);
	else
		return (char *)strdup(in);
}


/* +++ helper methods +++ */


/* this method prints some debug output and sets the http user agent string to
 * a more informative value. */
static void print_debug_infos(const char *method, const char *parameter)
{
	assert(method);
	printf(">> %s(%s)\n", method, parameter);
	char *useragent = ne_concat(project_name, " ", method, NULL);
	ne_set_useragent(session, useragent);
	FREE(useragent);
}


/* returns the malloc()ed escaped remotepath on success or NULL on error */
static char* get_remotepath(const char *localpath)
{
	assert(localpath);
	char *remotepath = ne_concat(remotepath_basedir, localpath, NULL);
	if (remotepath == NULL)
		return NULL;
	char *remotepath2 = ne_path_escape(remotepath);
	FREE(remotepath);
	if (remotepath2 == NULL)
		return NULL;
	return remotepath2;
}


/* returns a filehandle for read and write on success or -1 on error */
static int get_filehandle()
{
	char dummyfile[] = "/tmp/wdfs-tmp-XXXXXX";
	/* mkstemp() replaces XXXXXX by unique random chars and
	 * returns a filehandle for reading and writing */
	int fh = mkstemp(dummyfile);
	if (fh == -1)
		printf("## mkstemp(%s) error\n", dummyfile);
	if (unlink(dummyfile))
		printf("## unlink() error\n");
	return fh;
}


/* evaluates the propfind result set and sets the file's attributes (stat) */
static void set_stat(struct stat* stat, const ne_prop_result_set *results)
{
	if (debug_mode == true)
		print_debug_infos(__func__, "");

	const char *resourcetype, *contentlength, *lastmodified, *creationdate;
	assert(stat && results);
	memset(stat, 0, sizeof(struct stat));

	/* get the values from the propfind result set */
	resourcetype	= ne_propset_value(results, &properties_fileattr[0]);
	contentlength	= ne_propset_value(results, &properties_fileattr[1]);
	lastmodified	= ne_propset_value(results, &properties_fileattr[2]);
	creationdate	= ne_propset_value(results, &properties_fileattr[3]);

	/* webdav collection == directory entry */
	if (resourcetype != NULL && !strstr("<collection", resourcetype)) {
		stat->st_mode = S_IFDIR | 0777;
		stat->st_size = 4096;
	} else {
		stat->st_mode = S_IFREG | 0666;
		if (contentlength != NULL)
			stat->st_size = atoll(contentlength);
		else
			stat->st_size = 0;
	}

	stat->st_nlink	= 1;
	stat->st_atime	= time(NULL);

	if (lastmodified != NULL)
		stat->st_mtime = ne_rfc1123_parse(lastmodified);
	else
		stat->st_mtime = 0;

	if (creationdate != NULL)
		stat->st_ctime = ne_iso8601_parse(creationdate);
	else
		stat->st_ctime = 0;

	/* calculate number of 512 byte blocks */
	stat->st_blocks	= (stat->st_size + 511) / 512;

	/* no need to set a restrict mode, because fuse filesystems can
	 * only be accessed by the user that mounted the filesystem.  */
	stat->st_mode &= ~umask(0);
	stat->st_uid = getuid();
	stat->st_gid = getgid();
}


/* this method is invoked, if a redirect needs to be done. actually it simple 
 * frees the current remotepath and sets the remotepath to the redirect target.
 * return and prints an error if the current host and new host differ. returns
 * 0 on success and -1 on error. side effect: remotepath is freed on error. */
static int handle_redirect(char **remotepath) {
	if (debug_mode == true)
		print_debug_infos(__func__, *remotepath);

	/* free the old value of remotepath, because it's no longer needed */
	FREE(*remotepath);

	/* get the current_uri and new_uri structs */
	ne_uri current_uri;
	ne_fill_server_uri(session, &current_uri);
	const ne_uri *new_uri = ne_redirect_location(session);

	if (strcasecmp(current_uri.host, new_uri->host)) {
		printf("## error: wdfs does not support redirect to other hosts!\n");
		free_chars(&current_uri.host, &current_uri.scheme, NULL);
		return -1;
	}

	/* can't use ne_uri_free() here, because only host and scheme are mallocd */
	free_chars(&current_uri.host, &current_uri.scheme, NULL);

	/* set the new remotepath to the redirect target path */
	*remotepath = ne_strdup(new_uri->path);

	return 0;
}


/* +++ fuse callback methods +++ */


/* this method is called by ne_simple_propfind() from wdfs_getattr() for a
 * specific file. it sets the file's attributes and and them to the cache. */
static void wdfs_getattr_propfind_callback(
#if NEON_VERSION >= 26
	void *userdata, const ne_uri* href_uri, const ne_prop_result_set *results)
#else
	void *userdata, const char *remotepath, const ne_prop_result_set *results)
#endif

{
#if NEON_VERSION >= 26
	char *remotepath = ne_uri_unparse(href_uri);
#endif

	if (debug_mode == true)
		print_debug_infos(__func__, remotepath);

	struct stat *stat = (struct stat*)userdata;
	memset(stat, 0, sizeof(struct stat));

	assert(stat && remotepath);

	set_stat(stat, results);
	cache_add_item(stat, remotepath);

#if NEON_VERSION >= 26
	FREE(remotepath);
#endif
}


/* this method returns the file attributes (stat) for a requested file either
 * from the cache or directly from the webdav server by performing a propfind
 * request. */
static int wdfs_getattr(const char *localpath, struct stat *stat)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && stat);

	char *remotepath;

	/* for details about the svn_mode, please have a look at svn.c */
	/* get the stat for the svn_basedir, if localpath equals svn_basedir. */
	if (svn_mode == true && !strcmp(localpath, svn_basedir)) {
		*stat = svn_get_static_dir_stat();
		return 0;
	}

	/* if svn_mode is enabled and string localpath starts with svn_basedir... */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir)) {
		/* ...get stat for the level 1 directories... */
		if (svn_get_level1_stat(stat, localpath) == 0) {
			return 0;
		/* ...or get remotepath and go on. */
		} else {
			remotepath = svn_get_remotepath(localpath);
		}
	/* normal mode; no svn mode */
	} else {
		remotepath = get_remotepath(localpath);
	}

	if (remotepath == NULL)
		return -ENOMEM;


	/* stat not found in the cache? perform a propfind to get stat! */
	if (cache_get_item(stat, remotepath)) {
		int ret = ne_simple_propfind(
			session, remotepath, NE_DEPTH_ZERO, properties_fileattr,
			wdfs_getattr_propfind_callback, stat);
		/* handle the redirect and retry the propfind with the new target */
		if (redirect_support == true && ret == NE_REDIRECT) {
			if (handle_redirect(&remotepath))
				return -ENOENT;
			ret = ne_simple_propfind(
				session, remotepath, NE_DEPTH_ZERO, properties_fileattr,
				wdfs_getattr_propfind_callback, stat);
		}
		if (ret != NE_OK) {
			printf("## PROPFIND error in %s(): %s\n",
				__func__, ne_get_error(session));
			FREE(remotepath);
			return -ENOENT;
		}
	}

	FREE(remotepath);
	return 0;
}


/* this method is called by ne_simple_propfind() from wdfs_readdir() for each 
 * member (file) of the requested collection. this method extracts the file's
 * attributes from the webdav response, adds it to the cache and calls the fuse
 * filler method to add the file to the requested directory. */
static void wdfs_readdir_propfind_callback(
#if NEON_VERSION >= 26
	void *userdata, const ne_uri* href_uri, const ne_prop_result_set *results)
#else
	void *userdata, const char *remotepath0, const ne_prop_result_set *results)
#endif

{
#if NEON_VERSION >= 26
	char *remotepath = ne_uri_unparse(href_uri);
#else
	char *remotepath = strdup(remotepath0);
#endif

	if (debug_mode == true)
		print_debug_infos(__func__, remotepath);

	struct dir_item *item_data = (struct dir_item*)userdata;
	assert(item_data);

	/* remove ending slash to be able to compare the strings */
	char *remotepath_tmp1 = remove_ending_slash(remotepath);
	char *remotepath_tmp2 = remove_ending_slash(item_data->remotepath);

	/* unescape the paths to be able to compare the strings */
	char *remotepath1 = ne_path_unescape(remotepath_tmp1);
	char *remotepath2 = ne_path_unescape(remotepath_tmp2);
	free_chars(&remotepath_tmp1, &remotepath_tmp2, NULL);
	if (remotepath1 == NULL || remotepath2 == NULL) {
		free_chars(&remotepath, &remotepath1, &remotepath2, NULL);
		printf("## ne_path_unescape() error in %s()!\n", __func__);
		return;
	}

	/* some servers send the complete URI in 'char *remotepath' not only the 
	 * path. so we remove the server part and use only the path.
	 * example1:  before: "https://server.com/path/to/hell/"
	 *            after:  "/path/to/hell/"
	 * example2:  before: "http://server.com"
	 *            after:  ""                                                 */
	if (g_str_has_prefix(remotepath1, "http")) {
		char *tmp0 = strdup(remotepath1);
		FREE(remotepath1);
		/* jump to the 1st '/' of http[s]:// */
		char *tmp1 = strchr(tmp0, '/');
		/* jump behind the two '//' and get the next '/'. voila: the path! */
		char *tmp2 = strchr(tmp1 + 2, '/');

		if (tmp2 == NULL)
			remotepath1 = strdup("");
		else
			remotepath1 = strdup(tmp2);

		FREE(tmp0);
	}

	/* don't add this directory to itself */
	if (!strcmp(remotepath2, remotepath1)) {
		free_chars(&remotepath, &remotepath1, &remotepath2, NULL);
		return;
	}

	/* extract filename from the path. it's the string behind the last '/'. */
	char *filename = strrchr(remotepath1, '/');
	filename++;

	/* set this file's attributes. the "ne_prop_result_set *results" contains
	 * the file attributes of all files of this collection (directory). this 
	 * performs better then single requests for each file in getattr().  */
	struct stat stat;
	set_stat(&stat, results);

	/* add this file's attributes to the cache */
	cache_add_item(&stat, remotepath1);

	/* add directory entry */
	if (item_data->filler(item_data->buf, filename, &stat, 0))
		printf("## filler() error in %s()!\n", __func__);

	free_chars(&remotepath, &remotepath1, &remotepath2, NULL);
}


/* this method adds the files to the requested directory using the webdav method
 * propfind. the server responds with status code 207 that contains metadata of 
 * all files of the requested collection. for each file the method wdfs_readdir_
 * propfind_callback() is called. */
static int wdfs_readdir(
	const char *localpath, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && filler);

	struct dir_item item_data;
	item_data.buf = buf;
	item_data.filler = filler;

	/* for details about the svn_mode, please have a look at svn.c */
	/* if svn_mode is enabled, add svn_basedir to root */
	if (svn_mode == true && !strcmp(localpath, "/")) {
		filler(buf, svn_basedir + 1, NULL, 0);
	}

	/* if svn_mode is enabled, add level 1 directories to svn_basedir */
	if (svn_mode == true && !strcmp(localpath, svn_basedir)) {
		svn_add_level1_directories(&item_data);
		return 0;
	}

	/* if svn_mode is enabled and string localpath starts with svn_basedir... */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir)) {
		/* ... add level 2 directories and return... */
		if (svn_add_level2_directories(&item_data, localpath) == 0) {
			return 0;
		/* ...or get remote path and go on */
		} else {
			item_data.remotepath = svn_get_remotepath(localpath);
		}
	/* normal mode; no svn mode */
	} else {
		item_data.remotepath = get_remotepath(localpath);
	}

	if (item_data.remotepath == NULL)
		return -ENOMEM;


	int ret = ne_simple_propfind(
		session, item_data.remotepath, NE_DEPTH_ONE,
		properties_fileattr, wdfs_readdir_propfind_callback, &item_data);
	/* handle the redirect and retry the propfind with the redirect target */
	if (redirect_support == true && ret == NE_REDIRECT) {
		if (handle_redirect(&item_data.remotepath))
			return -ENOENT;
		ret = ne_simple_propfind(
			session, item_data.remotepath, NE_DEPTH_ONE,
			properties_fileattr, wdfs_readdir_propfind_callback, &item_data);
	}
	if (ret != NE_OK) {
			printf("## PROPFIND error in %s(): %s\n",
				__func__, ne_get_error(session));
		FREE(item_data.remotepath);
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	FREE(item_data.remotepath);
	return 0;
}


/* author jens, 13.08.2005 11:22:20, location: unknown, refactored in goettingen
 * get the file from the server already at open() and write the data to a new
 * filehandle. also create a "struct open_file" to store the filehandle. */
static int wdfs_open(const char *localpath, struct fuse_file_info *fi)
{
	if (debug_mode == true) {
		print_debug_infos(__func__, localpath);
		printf(">> %s() by PID %d\n", __func__, fuse_get_context()->pid);
	}

	assert(localpath && fi);

	struct open_file *file = g_new0(struct open_file, 1);
	file->modified = false;

	file->fh = get_filehandle();
	if (file->fh == -1)
		return -EIO;


	char *remotepath;

	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		remotepath = svn_get_remotepath(localpath);
	else
		remotepath = get_remotepath(localpath);

	if (remotepath == NULL) {
		FREE(file);
		return -ENOMEM;
	}


	/* try to lock, if locking is enabled and file is not below svn_basedir. */
	if (locking_enabled == true && !g_str_has_prefix(localpath, svn_basedir)) {
		if (lockfile(remotepath, lock_timeout)) {
			/* locking the file is not possible, because the file is locked by 
			 * somebody else. read-only access is allowed. */
			if ((fi->flags & O_ACCMODE) == O_RDONLY) {
				printf("## error: file %s is already locked. ", remotepath);
				printf("nevertheless allowing read-only (O_RDONLY) access!\n");
			} else {
				FREE(file);
				FREE(remotepath);
				return -EACCES;
			}
		}
	}

	/* GET the data to the filehandle even if the file is opened O_WRONLY,
	 * because the opening application could use pwrite() or use O_APPEND
	 * and than the data needs to be present. */
	if (ne_get(session, remotepath, file->fh)) {
		printf("## GET error: %s\n", ne_get_error(session));
		FREE(remotepath);
		return -ENOENT;
	}

	FREE(remotepath);

	/* save our "struct open_file" to the fuse filehandle
	 * this looks like a dirty hack too me, but it's the fuse way... */
	fi->fh = (unsigned long)file;

	return 0;
}


/* reads data from the filehandle with pread() to fulfill read requests */
static int wdfs_read(
	const char *localpath, char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && buf && size &&  &fi);

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	int ret = pread(file->fh, buf, size, offset);
	if (ret < 0) {
		printf("## pread() error: %d\n", ret);
		return -EIO;
	}

	return ret;
}


/* writes data to the filehandle with pwrite() to fulfill write requests */
static int wdfs_write(
	const char *localpath, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && buf && size &&  &fi);

	/* data below svn_basedir is read-only */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	int ret = pwrite(file->fh, buf, size, offset);
	if (ret < 0) {
		printf("## pwrite() error: %d\n", ret);
		return -EIO;
	}

	/* set this flag, to indicate that data has been modified and needs to be
	 * put to the webdav server. */
	file->modified = true;

	return ret;
}


/* author jens, 13.08.2005 11:28:40, location: unknown, refactored in goettingen
 * wdfs_release is called by fuse, when the last reference to the filehandle is
 * removed. this happens if the file is closed. after closing the file it's
 * time to put it to the server, but only if it was modified. */
static int wdfs_release(const char *localpath, struct fuse_file_info *fi)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	/* put the file only to the server, if it was modified. */
	if (file->modified == true) 	{
		if (ne_put(session, remotepath, file->fh)) {
			printf("## PUT error: %s\n", ne_get_error(session));
			FREE(remotepath);
			return -EIO;
		}

		if (debug_mode == true)
			printf(">> wdfs_release(): PUT the file to the server.\n");

		/* attributes for this file are no longer up to date.
		 * so remove it from cache. */
		cache_delete_item(remotepath);

		/* unlock if locking is enabled and mode is ADVANCED_LOCK, because data
		 * has been read and writen and so now it's time to remove the lock. */
		if (locking_enabled == true && locking_mode == ADVANCED_LOCK) {
			if (unlockfile(remotepath)) {
				FREE(remotepath);
				return -EACCES;
			}
		}
	}

	/* if locking is enabled and mode is SIMPLE_LOCK, simple unlock on close() */
	if (locking_enabled == true && locking_mode == SIMPLE_LOCK) {
		if (unlockfile(remotepath)) {
			FREE(remotepath);
			return -EACCES;
		}
	}

	/* close filehandle and free memory */
	close(file->fh);
	FREE(file);
	FREE(remotepath);

	return 0;
}


/* author jens, 13.08.2005 11:32:20, location: unknown, refactored in goettingen
 * wdfs_truncate is called by fuse, when a file is opened with the O_TRUNC flag
 * or truncate() is called. according to 'man truncate' if the file previously 
 * was larger than this size, the extra data is lost. if the file previously 
 * was shorter, it is extended, and the extended part is filled with zero bytes.
 */
static int wdfs_truncate(const char *localpath, off_t size)
{
	if (debug_mode == true) {
		print_debug_infos(__func__, localpath);
		printf(">> truncate() at offset %li\n", (long int)size);
	}

	assert(localpath &&  &size);

	/* data below svn_basedir is read-only */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	/* the truncate procedure:
	 *  1. get the complete file and write into fh_in
	 *  2. read size bytes from fh_in to buffer
	 *  3. write size bytes from buffer to fh_out
	 *  4. read from fh_out and put file to the server
	 */

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	int ret;
	int fh_in  = get_filehandle();
	int fh_out = get_filehandle();
	if (fh_in == -1 || fh_out == -1)
		return -EIO;

	char buffer[size];
	memset(buffer, 0, size);

	/* if truncate(0) is called, there is no need to get the data, because it 
	 * would not be used. */
	if (size != 0) {
		if (ne_get(session, remotepath, fh_in)) {
			printf("## GET error: %s\n", ne_get_error(session));
			close(fh_in);
			close(fh_out);
			FREE(remotepath);
			return -ENOENT;
		}

		ret = pread(fh_in, buffer, size, 0);
		if (ret < 0) {
			printf("## pread() error: %d\n", ret);
			close(fh_in);
			close(fh_out);
			FREE(remotepath);
			return -EIO;
		}
	}

	ret = pwrite(fh_out, buffer, size, 0);
	if (ret < 0) {
		printf("## pwrite() error: %d\n", ret);
		close(fh_in);
		close(fh_out);
		FREE(remotepath);
		return -EIO;
	}

	if (ne_put(session, remotepath, fh_out)) {
		printf("## PUT error: %s\n", ne_get_error(session));
		close(fh_in);
		close(fh_out);
		FREE(remotepath);
		return -EIO;
	}

	/* stat for this file is no longer up to date. remove it from the cache. */
	cache_delete_item(remotepath);

	close(fh_in);
	close(fh_out);
	FREE(remotepath);
	return 0;
}


/* author jens, 12.03.2006 19:44:23, location: goettingen in the winter
 * ftruncate is called on already opened files, truncate on not yet opened
 * files. ftruncate is supported since wdfs 1.2.0 and needs at least 
 * fuse 2.5.0 and linux kernel 2.6.15. */
#if FUSE_VERSION >= 25
static int wdfs_ftruncate(
	const char *localpath, off_t size, struct fuse_file_info *fi)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && size && &fi);

	/* data below svn_basedir is read-only */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	int ret = ftruncate(file->fh, size);
	if (ret < 0) {
		printf("## ftruncate() error: %d\n", ret);
		FREE(remotepath);
		return -EIO;
	}

	/* set this flag, to indicate that data has been modified and needs to be
	 * put to the webdav server. */
	file->modified = true;

	/* update the cache item of the ftruncate()d file */
	struct stat stat;
	if (cache_get_item(&stat, remotepath) < 0) {
		printf("## cache_get_item() error: item '%s' not found!\n", remotepath);
		FREE(remotepath);
		return -EIO;
	}

	/* set the new size after the ftruncate() call */
	stat.st_size = size;

	/* calculate number of 512 byte blocks */
	stat.st_blocks	= (stat.st_size + 511) / 512;

	/* update the cache */
	cache_add_item(&stat, remotepath);

	FREE(remotepath);

	return 0;
}
#endif

/* author jens, 28.07.2005 18:15:12, location: noedlers garden in trubenhausen
 * this method creates a empty file using the webdav method put. */
static int wdfs_mknod(const char *localpath, mode_t mode, dev_t rdev)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	int fh = get_filehandle();
	if (fh == -1) {
		FREE(remotepath);
		return -EIO;
	}

	if (ne_put(session, remotepath, fh)) {
		printf("## PUT error: %s\n", ne_get_error(session));
		close(fh);
		FREE(remotepath);
		return -EIO;
	}

	close(fh);
	FREE(remotepath);
	return 0;
}


/* author jens, 03.08.2005 12:03:40, location: goettingen
 * this method creates a directory / collection using the webdav method mkcol. */
static int wdfs_mkdir(const char *localpath, mode_t mode)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	if (ne_mkcol(session, remotepath)) {
		printf("MKCOL error: %s\n", ne_get_error(session));
		FREE(remotepath);
		return -ENOENT;
	}

	FREE(remotepath);
	return 0;
}


/* author jens, 30.07.2005 13:08:11, location: heli at heinemanns
 * this methods removes a file or directory using the webdav method delete. */
static int wdfs_unlink(const char *localpath)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	/* unlock the file, to be able to unlink it */
	if (locking_enabled == true) {
		if (unlockfile(remotepath)) {
			FREE(remotepath);
			return -EACCES;
		}
	}

	if (ne_delete(session, remotepath)) {
		printf("## DELETE error: %s\n", ne_get_error(session));
		FREE(remotepath);
		return -ENOENT;
	}

	/* this file no longer exists, so remove it also from the cache */
	cache_delete_item(remotepath);

	FREE(remotepath);
	return 0;
}


/* author jens, 31.07.2005 19:13:39, location: heli at heinemanns
 * this methods renames a file. it uses the webdav method move to do that. */
static int wdfs_rename(const char *localpath_src, const char *localpath_dest)
{
	if (debug_mode == true) {
		print_debug_infos(__func__, localpath_src);
		print_debug_infos(__func__, localpath_dest);
	}

	assert(localpath_src && localpath_dest);

	/* data below svn_basedir is read-only */
	if	(svn_mode == true &&
		(g_str_has_prefix(localpath_src, svn_basedir) ||
		 g_str_has_prefix(localpath_dest, svn_basedir)))
		return -EROFS;

	char *remotepath_src  = get_remotepath(localpath_src);
	char *remotepath_dest = get_remotepath(localpath_dest);
	if (remotepath_src == NULL || remotepath_dest == NULL )
		return -ENOMEM;

	/* unlock the source file, before renaming */
	if (locking_enabled == true) {
		if (unlockfile(remotepath_src)) {
			FREE(remotepath_src);
			return -EACCES;
		}
	}

	if (ne_move(session, 1, remotepath_src, remotepath_dest)) {
		printf("## MOVE error: %s\n", ne_get_error(session));
		free_chars(&remotepath_src, &remotepath_dest, NULL);
		return -ENOENT;
	}

	cache_delete_item(remotepath_src);

	free_chars(&remotepath_src, &remotepath_dest, NULL);
	return 0;
}


/* this is just a dummy implementation to avoid errors, when running chmod. */
int wdfs_chmod(const char *localpath, mode_t mode)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	printf("## error: chmod() is not (yet) implemented.\n");

	return 0;
}


/* this is just a dummy implementation to avoid errors, when setting attributes.
 * a usefull implementation is not possible, because the webdav standard only 
 * defines a "getlastmodified" property that is read-only and just updated when
 * the file's content or properties change. */
static int wdfs_setattr(const char *localpath, struct utimbuf *buf)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	return 0;
}


/* author jens, 04.08.2005 17:41:12, location: goettingen
 * this method is called, when the filesystems is unmounted. time to clean up! */
static void wdfs_destroy() {
	if (debug_mode == true)
		printf(">> free()ing globaly used memory\n");

	/* free globaly used memory */
	cache_destroy();
	unlock_all_files();
	ne_session_destroy(session);
	FREE(remotepath_basedir);
	svn_free_repository_root();
}


static struct fuse_operations wdfs_operations = {
	.getattr	= wdfs_getattr,
	.readdir	= wdfs_readdir,
	.open		= wdfs_open,
	.read		= wdfs_read,
	.write		= wdfs_write,
	.release	= wdfs_release,
	.truncate	= wdfs_truncate,
#if FUSE_VERSION >= 25
	.ftruncate	= wdfs_ftruncate,
#endif
	.mknod		= wdfs_mknod,
	.mkdir		= wdfs_mkdir,
	/* webdav treats file and directory deletions equal, both use wdfs_unlink */
	.unlink		= wdfs_unlink,
	.rmdir		= wdfs_unlink,
	.rename		= wdfs_rename,
	.chmod		= wdfs_chmod,
	/* utime should be better named setattr
	 * see: http://sourceforge.net/mailarchive/message.php?msg_id=11344401 */
	.utime		= wdfs_setattr,
	.destroy	= wdfs_destroy,
};


/* author jens, 26.08.2005 12:26:59, location: lystrup near aarhus 
 * this method prints help and usage information, call fuse to print its
 * help information and then exits. */
static void print_help_and_exit(const char *program_name)
{
	printf(
"usage: %s mountpoint -a http[s]://webdav-server/[directory/] [options]\n\n"
"wdfs options:\n"
"    -v                     show short informations about wdfs\n"
"    -vv                    show versions of wdfs, fuse and neon\n"
"    -h                     show this help page\n"
"    -D                     enable wdfs debug output\n"
"    -a URI                 address of the webdav resource to mount\n"
"    -ac                    accept ssl certificate. don't prompt the user.\n"
"    -u username            username of the webdav resource\n"
"    -p password            password of the webdav resource\n"
"    -r                     enable redirect support (not for the mountpoint)\n"
"    -S                     enable subversion mode to access old revisions\n"
"    -l                     enable locking of files, while they are open\n"
"    -t locking_timeout     timeout for a lock in seconds, -1 means infinite\n"
"                           default is 5 minutes / 300 seconds\n"
"    -m locking_mode        select a locking mode:\n"
"                           1: simple lock:   from open until close (default)\n"
"                           2: advanced lock: from open until write + close\n"
"                           3: eternity lock: from open until umount or timeout\n"
"\n", program_name);

	/* just call fuse to display it's help */
	const char *fusehelp[] = { program_name, "-ho", NULL };
	fuse_main(2, (char **)fusehelp, NULL);

	exit(1);
}


/* author jens, 25.08.2005 09:22:39, location: hamburg hagenbeck 
 * the main method parses the parameters passed to wdfs and separates them from
 * parameter for fuse. the it connects to the webdav resource (server) and 
 * starts the cache. finally it calls main_fuse() with the fuse parameters. */
int main(int argc, char *argv[])
{
	char *webdav_resource = NULL, *username = NULL, *password = NULL;
	int status_program_exec = 1;

	/* at least 2 parameters are needed for 'wdfs -v' and 'wdfs -h' */
	if (argc < 2) {
		printf("## error: too few parameters.\n");
		print_help_and_exit("wdfs");
	}
	/* print help or wdfs version if requested */
	if (!strcmp(argv[1], "-h"))
		print_help_and_exit(argv[0]);
	if (!strcmp(argv[1], "-v")) {
		printf(	"%s | wdfs is a webdav filesystem with special "
				"features for accessing subversion | %s\n",
				project_name, project_url);
		exit(0);
	}
	if (!strcmp(argv[1], "-vv")) {
		printf(	"%s using fuse/%d.%d.x and neon/0.%d.x\n",
			project_name, FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION, NEON_VERSION);
		exit(0);
	}
	/* at least 4 parameters are needed to mount a webdav resource successfully:
	 * wdfs ~/mountpoint -a http://server/                                 */
	if (argc < 4) {
		printf("## error: too few parameters.\n");
		print_help_and_exit("wdfs");
	}

	int fuse_argc = 0;
	/* initialize array for the parameters, that are passed to fuse_main() */
	char **fuse_argv = (char **) malloc(sizeof(char **) * (argc + 10));
	if (fuse_argv == NULL)
		return -ENOMEM;

	/* safe this program's name */
	fuse_argv[fuse_argc++] = strdup(argv[0]);
	/* safe the mointpoint. it's checked by fuse so no need to do it here. */
	fuse_argv[fuse_argc++] = strdup(argv[1]);

	int arg_number;
	bool_t error_parameter_parsing = false;
	/* check the parameters passed to wdfs. some are used by wdfs and some are
	 * for fuse. these are put into a new argv-array and later passed to 
	 * fuse_main(). */
	for (arg_number = 2; arg_number < argc; arg_number++) {
		char *this_arg = argv[arg_number];
		/* each parameter must start with an "-"  */
		if (this_arg[0] != '-') {
			printf("## error: passed invalid parameter '%s'.\n", this_arg);
			error_parameter_parsing = true;
			goto cleanup;
		}
		switch (this_arg[1]) {
			case 'a':
				/* parameter "-ac" (accept certificate) */
				if (this_arg[2] == 'c' && this_arg[3] == '\0')
					accept_certificate = true;
				/* parameter "-a" (address of the webdav resource) */
				else {
					if (++arg_number >= argc) {
						error_parameter_parsing = true;
						goto cleanup;
					}
					webdav_resource = strdup(argv[arg_number]);
				}
				break;
			case 'u':
				if (++arg_number >= argc) {
					error_parameter_parsing = true;
					goto cleanup;
				}
				username = strdup(argv[arg_number]);
				break;
			case 'p':
				if (++arg_number >= argc) {
					error_parameter_parsing = true;
					goto cleanup;
				}
				password = strdup(argv[arg_number]);
				break;
			case 'r':
				redirect_support = true;
				break;
			case 'S':
				svn_mode = true;
				break;
			case 'l':
				locking_enabled = true;
				break;
			case 't':
				if (++arg_number >= argc) {
					error_parameter_parsing = true;
					goto cleanup;
				}
				lock_timeout = atoi(argv[arg_number]);
				if (lock_timeout == 0) {
					printf("## error: 0 is an invalid timeout value.\n");
					error_parameter_parsing = true;
					goto cleanup;
				}
				break;
			case 'm':
				if (++arg_number >= argc) {
					error_parameter_parsing = true;
					goto cleanup;
				}
				int locking_mode_tmp = atoi(argv[arg_number]);
				if (locking_mode_tmp == 1)
					locking_mode = SIMPLE_LOCK;
				else if (locking_mode_tmp == 2)
					locking_mode = ADVANCED_LOCK;
				else if (locking_mode_tmp == 3)
					locking_mode = ETERNITY_LOCK;
				else {
					printf("## error: passed invalid locking mode.\n");
					error_parameter_parsing = true;
					goto cleanup;
				}
				break;
			case 'D':
				debug_mode = true;
				/* to see wdfs debug output, fuse must run in foreground */
				fuse_argv[fuse_argc++] = strdup("-f");
				break;

			/* collect parameters for fuse_main() */
			case 'f':
			case 'd':
			case 's':
				fuse_argv[fuse_argc++] = strdup(argv[arg_number]);
				break;
			case 'o':
				/* parameter was passed like this: "-o name" */
				if (this_arg[2] == '\0') {
					fuse_argv[fuse_argc++] = strdup(argv[arg_number]);
					if (++arg_number >= argc) {
						error_parameter_parsing = true;
						goto cleanup;
					}
					fuse_argv[fuse_argc++] = strdup(argv[arg_number]);
				/* parameter was passed like this: "-oname" */
				} else
					fuse_argv[fuse_argc++] = strdup(argv[arg_number]);
				break;
			default:
				printf("## error: passed unknown parameter.\n");
				error_parameter_parsing = true;
				goto cleanup;
		}
	}

	/* reset parameters to avoid storing sensitive data in the process table */
	for (arg_number = 2; arg_number < argc; arg_number++)
		memset(argv[arg_number], 0, strlen(argv[arg_number]));
	/* set a nice name for /proc/mounts */
	fuse_argv[fuse_argc++] =
		ne_concat("-ofsname=wdfs (", webdav_resource, ")", NULL);
	/* ensure that wdfs is called in single thread mode */
	fuse_argv[fuse_argc++] = strdup("-s");
#if FUSE_VERSION >= 24
	/* wdfs must not use the fuse caching of names (entries) and attributes! */
	fuse_argv[fuse_argc++] = strdup("-oentry_timeout=0");
	fuse_argv[fuse_argc++] = strdup("-oattr_timeout=0");
#endif
	/* array must be NULL-terminated */
	fuse_argv[fuse_argc] = NULL;

	/* set up webdav connection, exit on error */
	if (setup_webdav_session(webdav_resource, username, password)) {
		status_program_exec = 1;
		goto cleanup;
	}

	if (svn_mode == true) {
		if(svn_set_repository_root()) {
			printf("## error: could not set subversion repository root.\n");
			ne_session_destroy(session);
			status_program_exec = 1;
			goto cleanup;
		}
	}

	cache_initialize();

	/* finally call fuse */
	status_program_exec = fuse_main(fuse_argc, fuse_argv, &wdfs_operations);

	/* clean up and quit wdfs */
cleanup:
	for (arg_number = 0; arg_number < fuse_argc; arg_number++)
		FREE(fuse_argv[arg_number]);
	FREE(fuse_argv);
	free_chars(&webdav_resource, &username, &password, NULL);

	if (error_parameter_parsing == true)
		print_help_and_exit(argv[0]);

	return status_program_exec;
}

