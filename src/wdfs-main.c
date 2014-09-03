/* 
 *  this file is part of wdfs --> http://noedler.de/projekte/wdfs/
 *
 *  wdfs is a webdav filesystem with special features for accessing subversion
 *  repositories. it is based on fuse v2.3+ and neon v0.24.7+.
 * 
 *  copyright (c) 2005 jens m. noedler, noedler@web.de
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

/* use package name and version from config.h, if the file is available. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#define PROJECT_NAME PACKAGE_NAME"/"VERSION
#else
#define PROJECT_NAME "wdfs/unknown-version"
#endif

#define FUSE_USE_VERSION 22

#include <fuse.h>
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

#include "wdfs-main.h"
#include "webdav.h"
#include "cache.h"
#include "svn.h"


/* if set to "true" wdfs specific debug output is generated. default is "false".
 * do not edit here! it can be changed via parameter "-D" passed to wdfs.    */
bool_t debug_mode = false;

/* if set to "true" via parameter "-ac" verify_ssl_certificate() [in webdav.c]
 * will not ask the user wether to accept the certificate or not. */
bool_t accept_certificate = false;

/* webdav server base directory. if you are connected to "http://server/dir/"
 * remotepath_basedir is set to "/dir" (starting slash, no ending slash).
 * if connected to the root directory (http://server/) it will be set to "". */
char *remotepath_basedir;

/* product string according RFC2616, that is included in every request.      */
const char *project_name = PROJECT_NAME;

/* homepage of this filesystem.                                              */
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
 * mode holds the lock until wdfs is unmounted or the lock timed out. */
#define SIMPLE_LOCK 1
#define ADVANCED_LOCK 2
#define ETERNITY_LOCK 3

/* default locking mode is SIMPLE_LOCK
 * do not edit here! it can be changed via parameter "-m mode" passed to wdfs*/
int locking_mode = SIMPLE_LOCK;


/* infos about an open file. used by open(), read(), write() and release()   */
struct open_file {
	unsigned long fh;	/* this file's filehandle                            */
	bool_t modified;		/* set true if the filehandle's content is modified  */
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


/* removes '/' if it's the last character. returns the new malloc()d string. */
char* remove_ending_slash(const char *in)
{
	int length = strlen(in);
	if (in[length - 1] == '/')
		return (char*)strndup(in, length - 1);
	else
		return (char*)strdup(in);
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
	NE_FREE(useragent);
}


/* returns the malloc()ed escaped remotepath on success or NULL on error */
static char* get_remotepath(const char *localpath)
{
	assert(localpath);
	char *remotepath = ne_concat(remotepath_basedir, localpath, NULL);
	if (remotepath == NULL)
		return NULL;
	char *remotepath2 = ne_path_escape(remotepath);
	NE_FREE(remotepath);
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

	const char 	*resourcetype, *contentlength, *lastmodified, *creationdate;
	assert(stat && results);
	memset(stat, 0, sizeof(struct stat));

	/* get the values from the propfind result set */
	resourcetype	= ne_propset_value(results, &properties_fileattr[0]);
	contentlength	= ne_propset_value(results, &properties_fileattr[1]);
	lastmodified		= ne_propset_value(results, &properties_fileattr[2]);
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
	stat->st_mode	&= ~umask(0);
	stat->st_uid	= getuid();
	stat->st_gid	= getgid();
}


/* +++ fuse callback methods +++ */


/* this method is called by ne_simple_propfind() from wdfs_getattr() for a
 * specific file. it sets the file's attributes and and them to the cache. */
static void wdfs_getattr_propfind_callback(
	void *userdata, const char *remotepath, const ne_prop_result_set *results)
{
	if (debug_mode == true)
		print_debug_infos(__func__, remotepath);

	struct stat *stat = (struct stat*)userdata;
	memset(stat, 0, sizeof(struct stat));

	assert(stat && remotepath);

	set_stat(stat, results);
	cache_add_item(stat, remotepath);
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
		if (ret != NE_OK) {
			printf("## PROPFIND error in %s(): %s\n",
				__func__, ne_get_error(session));
			NE_FREE(remotepath);
			return -ENOENT;
		}
	}

	NE_FREE(remotepath);
	return 0;
}


/* this method is called by ne_simple_propfind() from wdfs_readdir() for each 
 * member (file) of the requested collection. this method extracts the file's
 * attributes from the webdav response, adds it to the cache and calls the fuse
 * filler() method to add the file to the requested directory. */
static void wdfs_readdir_propfind_callback(
	void *userdata, const char *remotepath, const ne_prop_result_set *results)
{
	if (debug_mode == true)
		print_debug_infos(__func__, remotepath);

	struct dir_item *item_data = (struct dir_item*)userdata;
	assert(item_data);

	/* remove ending slash to be able to compare the strings */
	char *tmp_remotepath  = remove_ending_slash(remotepath);
	char *tmp_remotepath2 = remove_ending_slash(item_data->remotepath);

	/* don't add this directory to itself */
	if (!strcmp(tmp_remotepath2, tmp_remotepath)) {
		NE_FREE(tmp_remotepath);
		NE_FREE(tmp_remotepath2);
		return;
	}

	/* extract filename from the path. it's the string behind the last '/'. */
	char *filename = strrchr(tmp_remotepath, '/');
	filename++;

	/* unescape the filename to add the file to the filesystem */
	filename = ne_path_unescape(filename);
	if (filename == NULL) {
		NE_FREE(tmp_remotepath);
		NE_FREE(tmp_remotepath2);
		printf("## ne_path_unescape() error in %s()!\n", __func__);
		return;
	}

	/* set this file's attributes. the "ne_prop_result_set *results" contains
	 * the file attributes of all files of this collection (directory). this 
	 * performs better then single requests for each file in getattr().  */
	struct stat stat;
	set_stat(&stat, results);

	/* add this file's attributes to the cache */
	cache_add_item(&stat, tmp_remotepath);

	/* add directory entry */
	if (item_data->filler(item_data->buf, filename, &stat, 0))
		printf("## filler() error in %s()!\n", __func__);

	NE_FREE(filename);
	NE_FREE(tmp_remotepath);
	NE_FREE(tmp_remotepath2);
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
	if (ret != NE_OK) {
			printf("## PROPFIND error in %s(): %s\n",
				__func__, ne_get_error(session));
		NE_FREE(item_data.remotepath);
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	NE_FREE(item_data.remotepath);
	return 0;
}


/* author jens, 13.08.2005 11:22:20, location: unknown, refactored in goettingen
 * get the file from the server already at open() and write the data to a new
 * filehandle. also create a "struct open_file" to store information about
 * flags passed to open() (O_RDONLY, O_WRONLY, ...) */
static int wdfs_open(const char *localpath, struct fuse_file_info *fi)
{
	if (debug_mode == true) {
		print_debug_infos(__func__, localpath);
		printf(">> %s() called by PID %d\n", __func__, fuse_get_context()->pid);
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
		NE_FREE(file);
		return -ENOMEM;
	}


	/* try to lock, if locking is enabled and file is not below svn_basedir. */
	if (locking_enabled == true && !g_str_has_prefix(localpath, svn_basedir)) {
		if (lockfile(remotepath, lock_timeout)) {
			/* locking the file is not possible, because the file is locked by 
			 * somebody else. read-only access is allowed. */
			if ((fi->flags & O_ACCMODE) == O_RDONLY) {
				printf("## file '%s' is locked. ", remotepath);
				printf("nevertheless allowing read-only (O_RDONLY) access!\n");
			} else {
				NE_FREE(file);
				NE_FREE(remotepath);
				return -EACCES;
			}
		}
	}

	/* GET the data to the filehandle even if the file is opened O_WRONLY,
	 * because the opening application could use pwrite() or use O_APPEND
	 * and than the data needs to be present. */
	if (ne_get(session, remotepath, file->fh)) {
		printf("## GET error: %s\n", ne_get_error(session));
		NE_FREE(remotepath);
		return -ENOENT;
	}

	NE_FREE(remotepath);

	fi->fh = (unsigned long)file;

	return 0;
}


/* reads data from the filehandle with pread() to fullfill read requests */
static int wdfs_read(
	const char *localpath, char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	if (debug_mode == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && buf && size &&  &fi);

	struct open_file *file = (struct open_file*)fi->fh;

	int ret = pread(file->fh, buf, size, offset);
	if (ret < 0) {
		printf("## pread() error: %d\n", ret);
		return -EIO;
	}

	return ret;
}


/* writes data to the filehandle with pwrite() to fullfill write requests */
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

	struct open_file *file = (struct open_file*)fi->fh;

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

	struct open_file *file = (struct open_file*)fi->fh;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	/* put the file only to the server, if it was modified. */
	if (file->modified == true) 	{
		if (ne_put(session, remotepath, file->fh)) {
			printf("## PUT error: %s\n", ne_get_error(session));
			NE_FREE(remotepath);
			return -EIO;
		}

		if (debug_mode == true)
			printf(">> wdfs_release(): PUT the file to the server\n");

		/* attributes for this file are no longer up to date.
		 * so remove it from cache. */
		cache_delete_item(remotepath);

		/* unlock if locking is enabled and mode is ADVANCED_LOCK, because data
		 * has been read and writen and so now it's time to remove the lock. */
		if (locking_enabled == true && locking_mode == ADVANCED_LOCK) {
			if (unlockfile(remotepath)) {
				NE_FREE(remotepath);
				return -EACCES;
			}
		}
	}

	/* if locking is enabled and mode is SIMPLE_LOCK, simple unlock on close() */
	if (locking_enabled == true && locking_mode == SIMPLE_LOCK) {
		if (unlockfile(remotepath)) {
			NE_FREE(remotepath);
			return -EACCES;
		}
	}

	/* close filehandle and free memory */
	close(file->fh);
	NE_FREE(file);
	NE_FREE(remotepath);

	return 0;
}


/* author jens, 13.08.2005 11:32:20, location: unknown, refactored in goettingen
 * wdfs_truncate is called by fuse, when a file is opened with the O_TRUNC flag, 
 * ftruncate() or truncate() is called. it is used to resize a file. according
 * to 'man truncate' if the file previously was larger than this size, the 
 * extra data is lost. if the file previously was shorter, it is extended, and
 * the extended part is filled with zero bytes. 
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
	if (fh_in == -1 || fh_out == -1 )
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
			NE_FREE(remotepath);
			return -ENOENT;
		}

		ret = pread(fh_in, buffer, size, 0);
		if (ret < 0) {
			printf("## pread() error: %d\n", ret);
			close(fh_in);
			close(fh_out);
			NE_FREE(remotepath);
			return -EIO;
		}
	}

	ret = pwrite(fh_out, buffer, size, 0);
	if (ret < 0) {
		printf("## pwrite() error: %d\n", ret);
		close(fh_in);
		close(fh_out);
		NE_FREE(remotepath);
		return -EIO;
	}

	if (ne_put(session, remotepath, fh_out)) {
		printf("## PUT error: %s\n", ne_get_error(session));
		close(fh_in);
		close(fh_out);
		NE_FREE(remotepath);
		return -EIO;
	}

	/* stat for this file is no longer up to date. remove it from the cache. */
	cache_delete_item(remotepath);

	close(fh_in);
	close(fh_out);
	NE_FREE(remotepath);
	return 0;
}



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
		NE_FREE(remotepath);
		return -EIO;
	}

	if (ne_put(session, remotepath, fh)) {
		printf("## PUT error: %s\n", ne_get_error(session));
		close(fh);
		NE_FREE(remotepath);
		return -EIO;
	}

	close(fh);
	NE_FREE(remotepath);
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
		NE_FREE(remotepath);
		return -ENOENT;
	}

	NE_FREE(remotepath);
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
			NE_FREE(remotepath);
			return -EACCES;
		}
	}

	if (ne_delete(session, remotepath)) {
		printf("## DELETE error: %s\n", ne_get_error(session));
		NE_FREE(remotepath);
		return -ENOENT;
	}

	/* this file no longer exists, so remove it also from the cache */
	cache_delete_item(remotepath);

	NE_FREE(remotepath);
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
			NE_FREE(remotepath_src);
			return -EACCES;
		}
	}

	if (ne_move(session, 1, remotepath_src, remotepath_dest)) {
		printf("## MOVE error: %s\n", ne_get_error(session));
		NE_FREE(remotepath_src)	;
		NE_FREE(remotepath_dest);
		return -ENOENT;
	}

	cache_delete_item(remotepath_src);

	NE_FREE(remotepath_src)	;
	NE_FREE(remotepath_dest);
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
	NE_FREE(remotepath_basedir);
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
	.mknod		= wdfs_mknod,
	.mkdir		= wdfs_mkdir,
	/* webdav treats file and directory deletions equal, both use wdfs_unlink */
	.unlink		= wdfs_unlink,
	.rmdir		= wdfs_unlink,
	.rename		= wdfs_rename,
	/* utime should better be named setattr
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
"usage: %s mountpoint -a http://webdav-server/[directory/] [options]\n"
"\n"
"wdfs options:\n"
"    -v                     show version information\n"
"    -h                     show this help page\n"
"    -D                     enable wdfs debug output\n"
"    -a URI                 address of the webdav resource to mount\n"
"    -ac                    accept ssl certificate. don't prompt the user.\n"
"    -u username            username of the webdav resource\n"
"    -p password            password of the webdav resource\n"
"    -S                     enable subversion mode to access old revisions\n"
"    -l                     enable locking of files, while they are open\n"
"    -t locking_timeout     timeout for a lock in seconds, -1 means infinite\n"
"                           default is 5 minutes / 300 seconds\n"
"    -m locking_mode        select a locking mode:\n"
"                           1: simple lock:   from open until close (default)\n"
"                           2: advanced lock: from open until write + close\n"
"                           3: eternity lock: from open until unmount of timeout\n"
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

	int fuse_argc = 0;
	/* initialize array for the parameters, that are passed to fuse_main() */
	char **fuse_argv = (char **) malloc(sizeof(char **) * argc + 15);
	if (fuse_argv == NULL)
		return -ENOMEM;

	/* safe this program's name */
	fuse_argv[fuse_argc++] = argv[0];
	/* safe the mointpoint. it's checked by fuse so no need to do it here. */
	fuse_argv[fuse_argc++] = argv[1];

	int arg_number, tmp_lock_mode;
	/* check the parameters passed to wdfs. some are used by wdfs and some are
	 * for fuse. these are put into a new argv-array and later passed to 
	 * fuse_main(). */
	for (arg_number = 1; arg_number < argc; arg_number++) {
		char *this_arg = argv[arg_number];
		if (this_arg[0] == '-') {
			switch (this_arg[1]) {
				case 'a':
					/* parameter "-ac" (accept certificate) */
					if (this_arg[2] == 'c' && this_arg[3] == '\0')
						accept_certificate = true;
					/* parameter "-a" (address of the webdav resource) */
					else
						webdav_resource = argv[++arg_number];
					break;
				case 'u':
					username = argv[++arg_number];
					break;
				case 'p':
					password = argv[++arg_number];
					break;
				case 'S':
					svn_mode = true;
					break;
				case 'l':
					locking_enabled = true;
					break;
				case 't':
					lock_timeout = atoi(argv[++arg_number]);
					break;
				case 'm':
					tmp_lock_mode = atoi(argv[++arg_number]);
					if (tmp_lock_mode == 1)
						locking_mode = SIMPLE_LOCK;
					else if (tmp_lock_mode == 2)
						locking_mode = ADVANCED_LOCK;
					else if (tmp_lock_mode == 3)
						locking_mode = ETERNITY_LOCK;
					else {
						NE_FREE(fuse_argv);
						printf("## error: passed invalid locking mode.\n");
						print_help_and_exit(argv[0]);
					}
					break;
				case 'D':
					debug_mode = true;
					/* to see wdfs debug output, fuse must run in foreground */
					fuse_argv[fuse_argc++] = "-f";
					break;
				case 'h':
					NE_FREE(fuse_argv);
					print_help_and_exit(argv[0]);
					break;
				case 'v':
					NE_FREE(fuse_argv);
					printf(	"%s | wdfs is a webdav filesystem with special "
							"features for accessing subversion | %s\n",
							project_name, project_url);
					exit(0);
					break;

				/* collect parameters for fuse_main() */
				case 'f':
				case 'd':
				case 's':
				case 'r':
					fuse_argv[fuse_argc++] = argv[arg_number];
					break;
				case 'o':
					/* parameter was passed like this: "-o name" */
					if (this_arg[2] == '\0') {
						fuse_argv[fuse_argc++] = argv[arg_number];
						fuse_argv[fuse_argc++] = argv[++arg_number];
					/* parameter was passed like this: "-oname" */
					} else {
						fuse_argv[fuse_argc++] = argv[arg_number];
					}
					break;

				default:
					printf("## error: passed unknown parameter.\n");
					NE_FREE(fuse_argv);
					print_help_and_exit(argv[0]);
			}
		}
	}

	/* set a nice name for /proc/mounts */
	fuse_argv[fuse_argc++] = "-ofsname=wdfs";
	/* ensure that wdfs is called in single thread mode */
	fuse_argv[fuse_argc++] = "-s";
	/* array must be NULL-terminated */
	fuse_argv[fuse_argc] = NULL;

	/* exit, if there is no webdav resource to connect to */
	if (webdav_resource == NULL) {
		printf("## error: use parameter -a with webdav resource to mount.\n");
		NE_FREE(fuse_argv);
		print_help_and_exit(argv[0]);
	}

	/* set up webdav connection, exit on error */
	if (setup_webdav_session(webdav_resource, username, password)) {
		NE_FREE(fuse_argv);
		return 1;
	}
	
	if (svn_mode == true) {
		if(svn_set_repository_root()) {
			printf("## error: could not set repository root!\n");
			ne_session_destroy(session);
			NE_FREE(fuse_argv);
			return 1;
		}
	}

	cache_initialize();

	/* finally call fuse */
	int ret = fuse_main(fuse_argc, fuse_argv, &wdfs_operations);

	/* clean up and quit wdfs */
	NE_FREE(fuse_argv);
	return ret;
}

