#ifndef CVMFS_H
#define CVMFS_H 1

#include <string>
#include <vector>
#include "tracer.h"
#include <unistd.h>
#include <time.h>

namespace cvmfs {

   extern pid_t pid;
   extern std::string root_url;
   extern std::string mountpoint;
   extern int max_cache_timeout;
   int catalog_cache_memusage_bytes();
   void catalog_cache_memusage_slots(int &positive, int &negative, int &all,
                                     int &inserts, int &replaces, int &cleans, int &hits, int &misses,
                                     int &cert_hits, int &cert_misses);
   void info_loaded_catalogs(std::vector<std::string> &prefix, std::vector<time_t> &last_modified, 
                             std::vector<time_t> &expires);
   int clear_file(const std::string &path);
   int remount();
   unsigned get_max_ttl(); /* in minutes */
   void set_max_ttl(const unsigned value); /* in minutes */

   int cvmfs_common_init(
      const std::string &cvmfs_opts_hostname, /* url of repository */
      const std::string &cvmfs_opts_proxies,
      const std::string &cvmfs_opts_repo_name,
      const std::string &cvmfs_opts_pubkey,
      const std::string &cvmfs_opts_cachedir,
      bool cvmfs_opts_cd_to_cachedir,
      int64_t cvmfs_opts_quota_limit,
      int64_t cvmfs_opts_quota_threshold,
      bool cvmfs_opts_rebuild_cachedb,
      int cvmfs_opts_uid,
      int cvmfs_opts_gid,
      unsigned cvmfs_opts_max_ttl,
      bool cvmfs_opts_force_signing,
      unsigned cvmfs_opts_timeout,
      unsigned cvmfs_opts_timeout_direct,
      int cvmfs_opts_syslog_level,
      const std::string &cvmfs_opts_logfile,
      const std::string &cvmfs_opts_tracefile,
      const std::string &cvmfs_opts_deep_mount,
      const std::string &cvmfs_opts_blacklist,
      const std::string &cvmfs_opts_whitelist,
      int cvmfs_opts_nofiles,
      bool cvmfs_opts_grab_mountpoint,
      bool cvmfs_opts_enable_talk,
      void (*cvmfs_opts_set_cache_drainout_fn)(),
      void (*cvmfs_opts_unset_cache_drainout_fn)()
   );
   void cvmfs_common_fini();
   void cvmfs_common_spawn();

   int cvmfs_readlink(const char *path, char *buf, size_t size);
   int cvmfs_open(const char *c_path);
   int cvmfs_close(int fd);
   int cvmfs_statfs(const char *path __attribute__((unused)), struct statvfs *info);
   int cvmfs_getattr(const char *c_path, struct stat *info);
   int cvmfs_getxattr(const char *path, const char *name, char *value, size_t vlen);
   int cvmfs_listdir(const char *path,char ***buf,size_t *buflen);
}


#endif
