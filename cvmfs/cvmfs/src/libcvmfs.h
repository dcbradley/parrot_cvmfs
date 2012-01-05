#ifndef LIBCVMFS_H
#define LIBCVMFS_H 1

extern "C" {

/* Initialize the CVMFS library and attach the specified remote
 * repository.
 *
 * See libcvmfs usage() for possible options.
 *
 * @param[in] options, option1,option2,...
 * \return 0 on success
 */
int cvmfs_init(char const *options);

/* Shut down the CVMFS library and release all resources.
 */
void cvmfs_fini();

/* Open a file in the CVMFS cache.
 *
 * @param[in] path, path to open (e.g. /dir/file, not /cvmfs/repo/dir/file)
 * \return read-only file descriptor, -1 on failure (sets errno)
 */
int cvmfs_open(const char *path);

/* Closes a file previously opened with cvmfs_open().
 *
 * @param[in] fd, file descriptor to close
 * \return 0 on success, -1 on failure (sets errno)
 */
int cvmfs_close(int fd);

/*
 * Reads a symlink from the catalog.  Environment variables in the
 * symlink that are of the form $(varname) are expanded.  If the
 * provided buffer is not long enough for the null-terminated value of
 * the symlink, -1 is returned and errno is set to ERANGE.
 *
 * @param[in] path, path of symlink (e.g. /dir/file, not /cvmfs/repo/dir/file)
 * @param[out] buf, buffer in which to write the null-terminated value of the symlink
 * @param[in] size, size of buffer
 * \return 0 on success, -1 on failure (sets errno)
 */
int cvmfs_readlink(const char *path, char *buf, size_t size);

/* Get information about a file.
 *
 * @param[in] path, path of file (e.g. /dir/file, not /cvmfs/repo/dir/file)
 * @param[out] st, stat buffer in which to write the result
 * \return 0 on success, -1 on failure (sets errno)
 */
int cvmfs_stat(const char *path,struct stat *st);

/* Get list of directory contents.  The directory contents
 * includes "." and "..".
 *
 * On return, the array will contain a NULL-terminated list of
 * strings.  The caller must free the strings and the array containing
 * them.  The array (*buf) may be NULL when this function is called.
 *
 * @param[in] path, path of directory (e.g. /dir, not /cvmfs/repo/dir)
 * @param[out] buf, pointer to dynamically allocated NULL-terminated array of strings
 * @param[in] buflen, pointer to variable containing size of array
 * \return 0 on success, -1 on failure (sets errno)
 */
int cvmfs_listdir(const char *path,char ***buf,size_t *buflen);

}

#endif