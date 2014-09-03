#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ne_basic.h>
#include <ne_auth.h>
#include <ne_locks.h>

#include "wdfs-main.h"
#include "webdav.h"

/* used to authorize at the webdav server */
struct ne_auth_data {
	const char *username;
	const char *password;
};

ne_session *session;
ne_lock_store *store = NULL;
struct ne_auth_data auth_data;


static int ne_set_server_auth_callback(
	void *userdata, const char *realm, int attempt, char *user, char *password)
{
	assert(auth_data.username && auth_data.password);

	strncpy(user, 		auth_data.username, NE_ABUFSIZ);
	strncpy(password, 	auth_data.password, NE_ABUFSIZ);

	return attempt;
}


/* sets up a webdav connection. if you want to use authentication, 
 * pass username and password. if not pass twise NULL. */
int setup_webdav_session(
	const char *uri_string, const char *username, const char *password)
{
	assert(uri_string);

	bool_t use_authentication = false;

	/* if only username xor password are given, return an error */
	if ((username != NULL) ^ (password != NULL)) {
		printf("## error: please pass username _and_ password to %s()!\n",
			__func__);
		return -1;
	}

	if (username != NULL && password != NULL)
		use_authentication = true;

	if (use_authentication == true) {
		auth_data.username = username;
		auth_data.password = password;
	}

	/* parse the uri_string and return a uri struct */
	ne_uri uri;
	if (ne_uri_parse(uri_string, &uri)) {
		printf("## ne_uri_parse() error: invalid URI <%s>\n", uri_string);
		ne_uri_free(&uri);
		return -1;
	}

	assert(uri.scheme && uri.host && uri.path);

	/* if no port was defined use the default port */
	uri.port = uri.port ? uri.port : ne_uri_defaultport(uri.scheme);

	/* create a session object, that allows to access the server */
	session = ne_session_create(uri.scheme, uri.host, uri.port);

	/* authentication */
	if (use_authentication == true)
		ne_set_server_auth(session, ne_set_server_auth_callback, NULL);

	/* try to access the server */
	ne_server_capabilities dummy;
	int ret = ne_options(session, uri.path, &dummy);
	if (ret != NE_OK) {
		printf("## error: could not connect to '%s'. ", uri_string);
		printf("reason: %s\n", ne_get_error(session));
		ne_session_destroy(session);
		ne_uri_free(&uri);
		return -1;
	}

	/* set a useragent string, to identify wdfs in the server log files */
	ne_set_useragent(session, project_name);

	/* save the remotepath, because each fuse callback method need it to 
	 * access the files at the webdav server */
	remotepath_basedir = remove_ending_slash(uri.path);

	ne_uri_free(&uri);
	return 0;
}


/* +++++++ locking methods +++++++ */

/* returns the lock for this file from the lockstore on success 
 * or NULL if the lock is not found in the lockstore. */
static struct ne_lock* get_lock_by_path(const char *remotepath)
{
	assert(remotepath);

	/* unless the lockstore is initialized, no lock can be found */
	if (store == NULL)
		return NULL;

	/* generate a ne_uri object to find the lock by its uri */
	ne_uri uri;
	uri.path = (char *)remotepath;
	ne_fill_server_uri(session, &uri);

	/* find the lock for this uri in the lockstore */
	struct ne_lock *lock = NULL;
	lock = ne_lockstore_findbyuri(store, &uri);

	/* ne_fill_server_uri() malloc()d these fields, time to free them */
	NE_FREE(uri.scheme);
	NE_FREE(uri.host);

	return lock;
}


/* tries to lock the file and returns 0 on success and 1 on error */
int lockfile(const char *remotepath, const int timeout)
{
	assert(remotepath && timeout);

	/* initialize the lockstore, if needed (e.g. first locking a file). */
	if (store == NULL) {
		store = ne_lockstore_create();
		if (store == NULL)
			return 1;
		ne_lockstore_register(store, session);
	}


	/* check, if we already hold a lock for this file */
	struct ne_lock *lock = get_lock_by_path(remotepath);

	/* we already hold a lock for this file, simply return 0 */
	if (lock != NULL) {
		if (debug_mode == true)
			printf("++ file '%s' is already locked.\n", remotepath);
		return 0;
	}

	/* otherwise lock the file exclusivly */
	lock = ne_lock_create();
	enum ne_lock_scope scope = ne_lockscope_exclusive;
	lock->scope	= scope;
	lock->owner = ne_concat("wdfs, user: ", getenv("USER"), NULL);
	lock->timeout = timeout;
	lock->depth = NE_DEPTH_ZERO;
	ne_fill_server_uri(session, &lock->uri);
	lock->uri.path = ne_strdup(remotepath);

	if (ne_lock(session, lock)) {
		printf("## ne_lock() error\n");
		printf("## could _not_ lock file '%s'\n", lock->uri.path);
		ne_lock_destroy(lock);
		return 1;
	} else {
		ne_lockstore_add(store, lock);
		if (debug_mode == true)
			printf("++ locked file '%s'\n", remotepath);
	}

	return 0;
}


/* tries to unlock the file and returns 0 on success and 1 on error */
int unlockfile(const char *remotepath)
{
	assert(remotepath);

	struct ne_lock *lock = get_lock_by_path(remotepath);

	/* if the lock was not found, the file is already unlocked */
	if (lock == NULL)
		return 0;


	/* if the lock was found, unlock the file */
	if (ne_unlock(session, lock)) {
		printf("## ne_unlock() error\n");
		printf("## could _not_ unlock file '%s'\n", lock->uri.path);
		ne_lock_destroy(lock);
		return 1;
	} else {
		/* on success remove the lock from the store and destroy the lock */
		ne_lockstore_remove(store, lock);
		ne_lock_destroy(lock);
		if (debug_mode == true)
			printf("++ unlocked file '%s'\n", remotepath);
	}

	return 0;
}


/* this method unlocks all files of the lockstore and destroys the lockstore */
void unlock_all_files()
{
	/* only unlock all files, if the lockstore is initialized */
	if (store != NULL) {
		/* get each lock from the lockstore and try to unlock the file */
		struct ne_lock *this_lock = NULL;
		this_lock = ne_lockstore_first(store);
		while (this_lock != NULL) {
			if (ne_unlock(session, this_lock)) {
				printf("## ne_unlock() error\n");
				printf("## could _not_ unlock file '%s'\n", this_lock->uri.path);
			} else {
				if (debug_mode == true)
					printf("++ unlocked file '%s'\n", this_lock->uri.path);
			}
			/* get the next lock from the lockstore */
			this_lock = ne_lockstore_next(store);
		}

		/* finally destroy the lockstore */
		if (debug_mode == true)
			printf("++ destroying lockstore\n");
		ne_lockstore_destroy(store);
	}
}

