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
#define CVMFS_PORT 80
#define CVMFS_ARGS_MAX 10
extern int pfs_master_timeout;
extern int pfs_checksum_files;
extern char pfs_temp_dir[];
extern struct file_cache *pfs_file_cache;

extern void pfs_abort();
extern int pfs_cache_invalidate(pfs_name * name);

static struct cvmfs_filesystem *cvmfs_filesystem_list = 0;
static struct cvmfs_filesystem *cvmfs_active_filesystem = 0;

/*
A cvmfs_filesystem structure represents an entire
filesystem rooted at a given host and path.
All known filesystem are kept in a linked list
rooted at cvmfs_filesystem_list 
*/

struct cvmfs_filesystem {
	char hostport[PFS_PATH_MAX];
	char path[PFS_PATH_MAX];
	struct cvmfs_dirent *root;
	struct cvmfs_filesystem *next;
	char *argv[CVMFS_ARGS_MAX];
	int argc;
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

void cvmfs_dirent_to_stat(struct cvmfs_dirent *d, struct pfs_stat *s)
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

bool cvmfs_activate_filesystem(struct cvmfs_filesystem *f)
{
	if(cvmfs_active_filesystem != f) {
		if(cvmfs_active_filesystem != NULL) {
			cvmfs_fini();
			cvmfs_active_filesystem = NULL;
		}
		int rc = cvmfs_init(f->argc, f->argv);
		if(rc != 0) {
			return false;
		}
		cvmfs_active_filesystem = f;
	}
	return true;
}

/*
Search for a cvmfs filesystem rooted at the given host and path.
On failure, return zero.
*/

struct cvmfs_filesystem *cvmfs_filesystem_create(const char *hostport, const char *path)
{
	struct cvmfs_filesystem *f = (struct cvmfs_filesystem *) xxmalloc(sizeof(*f));
	strcpy(f->hostport, hostport);
	strcpy(f->path, path);

	f->argv[f->argc++] = strdup("unused");
	f->argv[f->argc++] = strdup("-o");
	f->argv[f->argc++] =
		strdup
		("fsname=cvmfs2,ro,nodev,kernel_cache,auto_cache,uid=275,gid=275,cachedir=/scratch/dan/cache,entry_timeout=60,attr_timeout=60,negative_timeout=60,use_ino,proxies=DIRECT,repo_name=cms.hep.wisc.edu,timeout=5,timeout_direct=10,ro,syslog_level=1,force_signing,pubkey=/etc/cvmfs/keys/cms.hep.wisc.edu.pub");
	f->argv[f->argc++] = strdup("http://cvmfs01.hep.wisc.edu/cvmfs/cms.hep.wisc.edu");
	f->argv[f->argc] = NULL;

	assert(f->argc < CVMFS_ARGS_MAX);

	return f;
}

/*
Recursively destroy a cvmfs filesystem object.
*/

void cvmfs_filesystem_delete(struct cvmfs_filesystem *f)
{
	if(!f)
		return;
	cvmfs_filesystem_delete(f->next);

	int i;
	for(i = 0; i < f->argc; i++) {
		free(f->argv[i]);
	}

	if(cvmfs_active_filesystem == f) {
		cvmfs_fini();
		cvmfs_active_filesystem = NULL;
	}

	free(f);
}

/*
Destroy all internal state for all filesystems.
This is called whenever a file checksum is found
to be inconsistent, and the state must be reloaded.
*/

void cvmfs_filesystem_flush_all()
{
	cvmfs_filesystem_delete(cvmfs_filesystem_list);
	cvmfs_filesystem_list = 0;
}

cvmfs_filesystem *lookup_filesystem(pfs_name * name, char const **subpath_result)
{
	struct cvmfs_filesystem *f;
	char path[PFS_PATH_MAX];
	const char *subpath;
	char *s;

	debug(D_GROW, "cvmfs lookup_filesystem(%s,%s)", name->hostport, name->rest);

	if(!name->hostport[0]) {
		debug(D_GROW, "cvmfs lookup_filesystem(%s,%s) --> ENOENT", name->hostport, name->rest);
		errno = ENOENT;
		return 0;
	}

	for(f = cvmfs_filesystem_list; f; f = f->next) {
		if(!strcmp(f->hostport, name->hostport)) {
			subpath = compare_path_prefix(f->path, name->rest);
			if(!subpath) {
				subpath = compare_path_prefix(name->rest, f->path);
				if(subpath) {
					debug(D_GROW, "cvmfs lookup_filesystem(%s,%s) --> ENOENT", name->hostport, name->rest);
					errno = ENOENT;
					return 0;
				} else {
					continue;
				}
			}
			debug(D_GROW, "cvmfs lookup_filesystem(%s,%s) --> %s,%s,%s", name->hostport, name->rest, f->hostport, f->path, subpath);
			*subpath_result = subpath;
			return f;
		}
	}

	strcpy(path, name->rest);
	while(1) {
		f = cvmfs_filesystem_create(name->hostport, path);
		if(f) {
			f->next = cvmfs_filesystem_list;
			cvmfs_filesystem_list = f;
			subpath = compare_path_prefix(f->path, name->rest);
			*subpath_result = subpath;
			debug(D_GROW, "cvmfs lookup_filesystem(%s,%s) --> new fs %s,%s,%s", name->hostport, name->rest, f->hostport, f->path, subpath);
			return f;
		}
		s = strrchr(path, '/');
		if(s) {
			*s = 0;
		} else {
			break;
		}
	}

	debug(D_GROW, "cvmfs lookup_filesystem(%s,%s) --> ENOENT", name->hostport, name->rest);
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
		errno = EIO;
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
		return CVMFS_PORT;
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

		debug(D_GROW, "cvmfs open(%s,%d,%d)", name->rest, flags, mode);

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

		debug(D_GROW, "cvmfs getdir(%s)", name->rest);

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

		debug(D_GROW, "cvmfs lstat(%s)", name->rest);

		if(!d.lookup(name, 0)) {
			return -1;
		}

		cvmfs_dirent_to_stat(&d, info);

		return 0;
	}

	virtual int stat(pfs_name * name, struct pfs_stat *info) {
		struct cvmfs_dirent d;

		if(!d.lookup(name, 1)) {
			debug(D_GROW, "cvmfs stat(%s) --> -1 (lookup failed)", name->rest);

			return -1;
		}

		cvmfs_dirent_to_stat(&d, info);

		debug(D_GROW, "cvmfs stat(%s) --> (%d,%d,%d,%d) ISDIR=%d", name->rest, info->st_mode, info->st_size, info->st_mtime, info->st_ino, S_ISDIR(info->st_mode));

		return 0;
	}

	virtual int unlink(pfs_name * name) {
		errno = EROFS;
		return -1;
	}

	virtual int access(pfs_name * name, mode_t mode) {
		struct pfs_stat info;
		debug(D_GROW, "cvmfs access(%s,%d)", name->rest, mode);
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

		debug(D_GROW, "cvmfs chdir(%s)", name->rest);

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
			debug(D_GROW, "cvmfs readlink(%s) --> %d", name->rest, rc);
			if(rc < 0) {
				errno = -rc;
				return -1;
			}
			return strlen(buf);
		} else {
			debug(D_GROW, "cvmfs readlink(%s) --> -1 (not a link)", name->rest);
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