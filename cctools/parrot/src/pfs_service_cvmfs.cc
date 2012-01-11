/*
This software is distributed under the GNU General Public License.
See the file COPYING for details.
*/

#ifdef HAS_CVMFS

#include "pfs_service.h"
#include "libcvmfs.h"

extern "C" {
#include "debug.h"
#include "full_io.h"
#include "xmalloc.h"
#include "macros.h"
#include "sha1.h"
}
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <assert.h>
extern int pfs_master_timeout;
extern int pfs_checksum_files;
extern char pfs_temp_dir[];
extern struct file_cache *pfs_file_cache;


static struct cvmfs_filesystem *cvmfs_filesystem_list = 0;
static struct cvmfs_filesystem *cvmfs_active_filesystem = 0;
static bool allow_switching_cvmfs_repos = false;

/*
A cvmfs_filesystem structure represents an entire
filesystem rooted at a given host and path.
All known filesystem are kept in a linked list
rooted at cvmfs_filesystem_list 
*/

struct cvmfs_filesystem {
	char host[PFS_PATH_MAX];
	char path[PFS_PATH_MAX];
	struct cvmfs_dirent *root;
	struct cvmfs_filesystem *next;
	char *cvmfs_options;
};

/*
A grow_dirent is a node in a tree representing the
entire directory structure of a grow_filesystem.
Each node describes its name, metadata, checksum,
and children (if a directory)
*/

class cvmfs_dirent {
      public:
	cvmfs_dirent();
	~cvmfs_dirent();

	bool lookup(pfs_name * name, bool follow_symlinks);

	char *name;
	char *linkname;
	unsigned mode;
	UINT64_T size;
	UINT64_T inode;
	time_t mtime;
};

cvmfs_dirent::cvmfs_dirent():
name(0), linkname(0), mode(0), size(0), inode(0), mtime(0)
{
}

cvmfs_dirent::~cvmfs_dirent()
{
	if(name) {
		free(name);
	}
	if(linkname) {
		free(linkname);
	}
}

/*
Compare two entire path strings to see if a is a prefix of b.
Return the remainder of b not matched by a.
For example, compare_path_prefix("foo/baz","foo/baz/bar") returns "/bar".
Return null if a is not a prefix of b.
*/

static const char *compare_path_prefix(const char *a, const char *b)
{
	while(1) {
		if(*a == '/' && *b == '/') {
			while(*a == '/')
				a++;
			while(*b == '/')
				b++;
		}

		if(!*a)
			return b;
		if(!*b)
			return 0;

		if(*a == *b) {
			a++;
			b++;
			continue;
		} else {
			return 0;
		}
	}
}

static void cvmfs_dirent_to_stat(struct cvmfs_dirent *d, struct pfs_stat *s)
{
	s->st_dev = 1;
	s->st_ino = d->inode;
	s->st_mode = d->mode;
	s->st_nlink = 1;
	s->st_uid = 0;
	s->st_gid = 0;
	s->st_rdev = 1;
	s->st_size = d->size;
	s->st_blksize = 65536;
	s->st_blocks = 1 + d->size / 512;
	s->st_atime = d->mtime;
	s->st_mtime = d->mtime;
	s->st_ctime = d->mtime;
}

static void cvmfs_parrot_logger(const char *msg)
{
	debug(D_CVMFS, "%s", msg);
}

static bool cvmfs_activate_filesystem(struct cvmfs_filesystem *f)
{
	if(cvmfs_active_filesystem != f) {
		if(cvmfs_active_filesystem != NULL) {

			if(!allow_switching_cvmfs_repos) {
				debug(D_CVMFS|D_NOTICE,
					  "ERROR: using multiple CVMFS repositories in a single parrot session "
					  "is not allowed.  Define PARROT_ALLOW_SWITCHING_CVMFS_REPOSITORIES "
					  "to enable experimental support, which could result in parrot crashing "
					  "or performing poorly.");
				return false;
			} else {
				debug(D_CVMFS|D_NOTICE,
					  "ERROR: using multiple CVMFS repositories in a single parrot session "
					  "is not fully supported.  PARROT_ALLOW_SWITCHING_CVMFS_REPOSITORIES "
					  "has been defined, so switching now from %s to %s.  "
					  "Parrot may crash or perform poorly!",
					  cvmfs_active_filesystem->host,
					  f->host);
			}

			cvmfs_fini();
			cvmfs_active_filesystem = NULL;
		}

		debug(D_CVMFS, "Initializing libcvmfs with the following options: %s", f->cvmfs_options);

		cvmfs_set_log_fn(cvmfs_parrot_logger);

		int rc = cvmfs_init(f->cvmfs_options);
		if(rc != 0) {
			return false;
		}
		cvmfs_active_filesystem = f;
	}
	return true;
}

static struct cvmfs_filesystem *cvmfs_filesystem_create(const char *repo_name, const char *path, const char *user_options)
{
	struct cvmfs_filesystem *f = (struct cvmfs_filesystem *) xxmalloc(sizeof(*f));
	strcpy(f->host, repo_name);
	strcpy(f->path, path);

	char *proxy = getenv("HTTP_PROXY");
	if( !proxy ) {
		proxy = "DIRECT";
	}

	if( !user_options ) {
		user_options = "";
	}

	f->cvmfs_options = (char *)malloc(strlen(user_options)+2*strlen(repo_name)+strlen(pfs_temp_dir)+strlen(proxy)+100);
	sprintf(f->cvmfs_options,
			"repo_name=%s,cachedir=%s/cvmfs/%s,timeout=%d,timeout_direct=%d,proxies=%s,%s",
			repo_name,
			pfs_temp_dir, repo_name,
			pfs_master_timeout,
			pfs_master_timeout,
			proxy,
			user_options);

	debug(D_CVMFS, "filesystem configured %s with repo path %s and options %s", repo_name, f->path, f->cvmfs_options);

	return f;
}

/* Read configuration for CVMFS repositories accessible to parrot.
 * Expected format of the configuration string:
 *   repo_name/subpath:cvmfs_options repo_name2/subpath:cvmfs_options ...
 *
 * The subpath is optional.  Literal spaces in the configuration must
 * be escaped with a backslash.
 *
 * Example:
 * cms.cern.ch:force_signing,pubkey=/path/to/cern.ch.pub,url=http://cvmfs-stratum-one.cern.ch/opt/cms
 */
static void cvmfs_read_config()
{
	char *allow_switching = getenv("PARROT_ALLOW_SWITCHING_CVMFS_REPOSITORIES");
	if( allow_switching && strcmp(allow_switching,"0")!=0) {
		allow_switching_cvmfs_repos = true;
	}

	char *cvmfs_options = getenv("PARROT_CVMFS_REPO");
	if( !cvmfs_options ) {
		return;
	}

	while( isspace(*cvmfs_options) ) {
		cvmfs_options++;
	}

	while( *cvmfs_options ) {
		char *start = cvmfs_options;
		for(; *cvmfs_options && !isspace(*cvmfs_options); cvmfs_options++ ) {
			if( *cvmfs_options == '\\' ) {
				cvmfs_options++;
				if( *cvmfs_options == '\0' ) break;
			}
		}

		char *repo = strdup(start);
		size_t pos = strcspn(repo,"/:");
		repo[pos] = '\0';

		char *path = NULL;
		start += pos;
		if( *start == '/' ) {
			path = strdup(start);
			pos = strcspn(path,":");
			path[pos] = '\0';
			start += pos;
		}
		else {
			path = strdup("/");
		}

		char *options = NULL;
		if( *start == ':' ) {
			start++;
			options = strdup(start);
			options[cvmfs_options-start] = '\0';
		}

		cvmfs_filesystem *f = cvmfs_filesystem_create(repo,path,options);
		if(f) {
			f->next = cvmfs_filesystem_list;
			cvmfs_filesystem_list = f;
		}

		free(repo);
		free(path);
		free(options);

		while( isspace(*cvmfs_options) ) {
			cvmfs_options++;
		}
	}
}

/*
Recursively destroy a cvmfs filesystem object.
*/

static void cvmfs_filesystem_delete(struct cvmfs_filesystem *f)
{
	if(!f)
		return;
	cvmfs_filesystem_delete(f->next);

	free(f->cvmfs_options);

	if(cvmfs_active_filesystem == f) {
		cvmfs_fini();
		cvmfs_active_filesystem = NULL;
	}

	free(f);
}

static cvmfs_filesystem *lookup_filesystem(pfs_name * name, char const **subpath_result)
{
	struct cvmfs_filesystem *f;
	const char *subpath;

	debug(D_CVMFS, "lookup_filesystem(%s,%s)", name->host, name->rest);

	if(!name->host[0]) {
		debug(D_CVMFS, "lookup_filesystem(%s,%s) --> ENOENT", name->host, name->rest);
		errno = ENOENT;
		return 0;
	}

	if( !cvmfs_filesystem_list ) {
		cvmfs_read_config();
	}
	if( !cvmfs_filesystem_list ) {
		debug(D_CVMFS|D_NOTICE, "No CVMFS filesystems have been configured.  To access CVMFS, you must configure PARROT_CVMFS_REPO.");
		errno = ENOENT;
		return 0;
	}

	for(f = cvmfs_filesystem_list; f; f = f->next) {
		if(!strcmp(f->host, name->host)) {
			subpath = compare_path_prefix(f->path, name->rest);
			if(!subpath) {
				subpath = compare_path_prefix(name->rest, f->path);
				if(subpath) {
					debug(D_CVMFS, "lookup_filesystem(%s,%s) --> ENOENT", name->host, name->rest);
					errno = ENOENT;
					return 0;
				} else {
					continue;
				}
			}
			debug(D_CVMFS, "lookup_filesystem(%s,%s) --> %s,%s,%s", name->host, name->rest, f->host, f->path, subpath);
			*subpath_result = subpath;
			return f;
		}
	}

	debug(D_CVMFS, "lookup_filesystem(%s,%s) --> ENOENT", name->host, name->rest);
	debug(D_CVMFS|D_NOTICE, "PARROT_CVMFS_REPO does not contain an entry for the CVMFS repository '%s'",name->host);
	errno = ENOENT;
	return 0;
}

/*
Given a full PFS path name, search for an already-loaded
filesystem record.  If it exists, then search it for the
appropriate dirent.  If no filesystem record is found,
then search for and load the needed filesystem.
*/

bool cvmfs_dirent::lookup(pfs_name * path, bool follow_symlinks)
{
	char const *subpath = NULL;
	cvmfs_filesystem *f = lookup_filesystem(path, &subpath);

	if(!f) {
		return false;
	}

	if(!cvmfs_activate_filesystem(f)) {
		errno = EIO;
		return false;
	}

	struct stat st;
	int rc = cvmfs_stat(path->rest, &st);
	if(rc != 0) {
		return false;
	}

	name = strdup(subpath);
	mode = st.st_mode;
	size = st.st_size;
	inode = st.st_ino;
	mtime = st.st_mtime;
	return true;
}


class pfs_file_cvmfs:public pfs_file {
      private:
	int fd;
	pfs_stat info;
	pfs_off_t last_offset;

      public:
	pfs_file_cvmfs(pfs_name * n, int fd_arg, cvmfs_dirent & d):pfs_file(n) {
		fd = fd_arg;
		last_offset = 0;
		cvmfs_dirent_to_stat(&d, &info);
	} virtual int close() {
		return cvmfs_close(fd);
	}

	virtual pfs_ssize_t read(void *d, pfs_size_t length, pfs_off_t offset) {
		pfs_ssize_t result;

		debug(D_LOCAL, "read %d 0x%x %lld %lld", fd, d, length, offset);

		if(offset != last_offset)
			::lseek64(fd, offset, SEEK_SET);
		result =::read(fd, d, length);
		if(result > 0)
			last_offset = offset + result;

		return result;
	}

	virtual int fstat(struct pfs_stat *i) {
		*i = info;
		return 0;
	}

	/*
	   This is a compatibility hack.
	   This filesystem is read only, so locks make no sense.
	   This simply satisfies some programs that insist upon it.
	 */
	virtual int flock(int op) {
		return 0;
	}

	virtual pfs_ssize_t get_size() {
		return info.st_size;
	}

};

class pfs_service_cvmfs:public pfs_service {
      public:
	virtual int get_default_port() {
		return 0;
	} virtual int is_seekable() {
		// CVMFS has its own cache, and the file descriptors returned
		// by cvmfs_open are just handles to whole files in the CVMFS
		// cache.  Telling parrot that the handle is seekable also
		// causes parrot not to copy the files from the CVMFS cache
		// into the parrot cache.

		return 1;
	}

	virtual pfs_file *open(pfs_name * name, int flags, mode_t mode) {
		struct cvmfs_dirent d;

		debug(D_CVMFS, "open(%s,%d,%d)", name->rest, flags, mode);

		if(!d.lookup(name, 1)) {
			return 0;
		}

		int fd = cvmfs_open(name->rest);
		if(fd == -1) {
			return 0;
		}
		return new pfs_file_cvmfs(name, fd, d);
	}

	pfs_dir *getdir(pfs_name * name) {
		struct cvmfs_dirent d;

		debug(D_CVMFS, "getdir(%s)", name->rest);

		if(!d.lookup(name, 1)) {
			return 0;
		}

		if(!S_ISDIR(d.mode)) {
			errno = ENOTDIR;
			return 0;
		}

		pfs_dir *dir = new pfs_dir(name);

		char **buf = NULL;
		size_t buflen = 0;

		int rc = cvmfs_listdir(name->rest, &buf, &buflen);
		if(rc != 0) {
			errno = -rc;
			return 0;
		}

		int i;
		for(i = 0; buf[i]; i++) {
			dir->append(buf[i]);
			free(buf[i]);
		}
		free(buf);

		return dir;
	}

	virtual int lstat(pfs_name * name, struct pfs_stat *info) {
		struct cvmfs_dirent d;

		debug(D_CVMFS, "lstat(%s)", name->rest);

		if(!d.lookup(name, 0)) {
			return -1;
		}

		cvmfs_dirent_to_stat(&d, info);

		return 0;
	}

	virtual int stat(pfs_name * name, struct pfs_stat *info) {
		struct cvmfs_dirent d;

		if(!d.lookup(name, 1)) {
			debug(D_CVMFS, "stat(%s) --> -1 (lookup failed)", name->rest);

			return -1;
		}

		cvmfs_dirent_to_stat(&d, info);

		debug(D_CVMFS, "stat(%s) --> (%d,%d,%d,%d) ISDIR=%d", name->rest, info->st_mode, info->st_size, info->st_mtime, info->st_ino, S_ISDIR(info->st_mode));

		return 0;
	}

	virtual int unlink(pfs_name * name) {
		errno = EROFS;
		return -1;
	}

	virtual int access(pfs_name * name, mode_t mode) {
		struct pfs_stat info;
		debug(D_CVMFS, "access(%s,%d)", name->rest, mode);
		if(this->stat(name, &info) == 0) {
			if(mode & W_OK) {
				errno = EROFS;
				return -1;
			} else {
				return 0;
			}
		} else {
			return -1;
		}
	}

	virtual int chmod(pfs_name * name, mode_t mode) {
		errno = EROFS;
		return -1;
	}

	virtual int chown(pfs_name * name, uid_t uid, gid_t gid) {
		errno = EROFS;
		return -1;
	}

	virtual int lchown(pfs_name * name, uid_t uid, gid_t gid) {
		errno = EROFS;
		return -1;
	}

	virtual int truncate(pfs_name * name, pfs_off_t length) {
		errno = EROFS;
		return -1;
	}

	virtual int utime(pfs_name * name, struct utimbuf *buf) {
		errno = EROFS;
		return -1;
	}

	virtual int rename(pfs_name * oldname, pfs_name * newname) {
		errno = EROFS;
		return -1;
	}

	virtual int chdir(pfs_name * name, char *newpath) {
		struct pfs_stat info;

		debug(D_CVMFS, "chdir(%s)", name->rest);

		if(this->stat(name, &info) == 0) {
			if(S_ISDIR(info.st_mode)) {
				return 0;
			} else {
				errno = ENOTDIR;
				return -1;
			}
		} else {
			return -1;
		}
	}

	virtual int link(pfs_name * oldname, pfs_name * newname) {
		errno = EROFS;
		return -1;
	}

	virtual int symlink(const char *linkname, pfs_name * newname) {
		errno = EROFS;
		return -1;
	}

	virtual int readlink(pfs_name * name, char *buf, pfs_size_t bufsiz) {
		struct cvmfs_dirent d;

		if(!d.lookup(name, 0)) {
			return -1;
		}

		if(S_ISLNK(d.mode)) {
			int rc = cvmfs_readlink(name->rest, buf, bufsiz);
			debug(D_CVMFS, "readlink(%s) --> %d", name->rest, rc);
			if(rc < 0) {
				errno = -rc;
				return -1;
			}
			return strlen(buf);
		} else {
			debug(D_CVMFS, "readlink(%s) --> -1 (not a link)", name->rest);
			errno = EINVAL;
			return -1;
		}
	}

	virtual int mkdir(pfs_name * name, mode_t mode) {
		errno = EROFS;
		return -1;
	}

	virtual int rmdir(pfs_name * name) {
		errno = EROFS;
		return -1;
	}
};

static pfs_service_cvmfs pfs_service_cvmfs_instance;
pfs_service *pfs_service_cvmfs = &pfs_service_cvmfs_instance;

#endif
