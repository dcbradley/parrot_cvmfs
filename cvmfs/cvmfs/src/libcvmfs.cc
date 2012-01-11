/**
 * \file libcvmfs.cc
 *
 * libcvmfs provides an API for the CernVM-FS client.  This is an
 * alternative to FUSE for reading a remote CernVM-FS repository.
 *
 *
 * Developed by Dan Bradley <dan@hep.wisc.edu> 2012 at University of
 * Wisconsin, largely based on the FUSE client cvmfs.cc.
 */

#define _FILE_OFFSET_BITS 64

#include "config.h"

#include <string>
#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>

#include "cvmfs_common.h"
#include "libcvmfs.h"

extern "C" {
   #include "debug.h"
   #include "log.h"
}

using namespace std;

using namespace cvmfs;

/**
 * Structure to parse the file system options.
 */
struct cvmfs_opts {
   unsigned timeout;
   unsigned timeout_direct;
   unsigned max_ttl;
   string   url;
   string   cachedir;
   string   proxies;
   string   tracefile;
   string   whitelist;
   string   pubkey;
   string   logfile;
   string   deep_mount;
   string   blacklist;
   string   repo_name;
   bool     force_signing;
   bool     rebuild_cachedb;
   int      nofiles;
   int      syslog_level;
   unsigned long  quota_limit;
   unsigned long  quota_threshold;

   cvmfs_opts():
      timeout(2),
      timeout_direct(2),
      max_ttl(0),
      cachedir("/var/cache/cvmfs2/default"),
      whitelist("/.cvmfswhitelist"),
      pubkey("/etc/cvmfs/keys/cern.ch.pub"),
      blacklist("/etc/cvmfs/blacklist"),
      force_signing(false),
      rebuild_cachedb(false),
      nofiles(0),
      syslog_level(3),
      quota_limit(0),
      quota_threshold(0) {}

   int set_option(char const *name, char const *value, bool *var) {
      if( *value != '\0' ) {
         fprintf(stderr,"Option %s=%s contains a value when none was expected.\n",name,value);
         return -1;
      }
      *var = true;
      return 0;
   }

   int set_option(char const *name, char const *value, unsigned *var) {
      unsigned v = 0;
      int end = 0;
      int rc = sscanf(value,"%u%n",&v,&end);
      if( rc != 1 || value[end] != '\0' ) {
         fprintf(stderr,"Invalid unsigned integer value for %s=%s\n",name,value);
         return -1;
      }
      *var = v;
      return 0;
   }

   int set_option(char const *name, char const *value, unsigned long *var) {
      unsigned v = 0;
      int end = 0;
      int rc = sscanf(value,"%ul%n",&v,&end);
      if( rc != 1 || value[end] != '\0' ) {
         fprintf(stderr,"Invalid unsigned long integer value for %s=%s\n",name,value);
         return -1;
      }
      *var = v;
      return 0;
   }

   int set_option(char const *name, char const *value, int *var) {
      unsigned v = 0;
      int end = 0;
      int rc = sscanf(value,"%d%n",&v,&end);
      if( rc != 1 || value[end] != '\0' ) {
         fprintf(stderr,"Invalid integer value for %s=%s\n",name,value);
         return -1;
      }
      *var = v;
      return 0;
   }

   int set_option(char const *name, char const *value, string *var) {
      *var = value;
      return 0;
   }

   int set_option(char const *name, char const *value)
   {
      #define CVMFS_OPT(var) if( strcmp(name,#var)==0 ) return set_option(name,value,&var)
      CVMFS_OPT(url);
      CVMFS_OPT(timeout);
      CVMFS_OPT(timeout_direct);
      CVMFS_OPT(max_ttl);
      CVMFS_OPT(cachedir);
      CVMFS_OPT(proxies);
      CVMFS_OPT(tracefile);
      CVMFS_OPT(force_signing);
      CVMFS_OPT(whitelist);
      CVMFS_OPT(pubkey);
      CVMFS_OPT(logfile);
      CVMFS_OPT(rebuild_cachedb);
      CVMFS_OPT(quota_limit);
      CVMFS_OPT(quota_threshold);
      CVMFS_OPT(nofiles);
      CVMFS_OPT(deep_mount);
      CVMFS_OPT(repo_name);
      CVMFS_OPT(blacklist);
      CVMFS_OPT(syslog_level);

      if( strcmp(name,"help")==0 ) {
         usage();
         return 1;
      }
      fprintf(stderr,"Unknown libcvmfs option: %s\n",name);
      return -1;
   }

   int parse_options(char const *options)
   {
      while( *options ) {
         char const *next = options;
         string name;
         string value;

         // get the option name
         for( next=options; *next && *next != ',' && *next != '='; next++ ) {
            if( *next == '\\' ) {
               next++;
               if( *next == '\0' ) break;
            }
            name += *next;
         }

         if( *next == '=' ) {
            next++;
         }

         // get the option value
         for(; *next && *next != ','; next++ ) {
            if( *next == '\\' ) {
               next++;
               if( *next == '\0' ) break;
            }
            value += *next;
         }

         if( !name.empty() || !value.empty() ) {
            int result = set_option(name.c_str(),value.c_str());
            if (result != 0) {
               return result;
            }
         }

         if( *next == ',' ) next++;
         options = next;
      }
      return 0;
   }

   /** 
    * Display the usage message.
    */
   static void usage() {
      struct cvmfs_opts defaults;
      fprintf(stderr,
            "CernVM-FS version %s\n"
            "Copyright (c) 2009- CERN\n"
            "All rights reserved\n\n"
            "Please visit http://cernvm.cern.ch/project/info for license details and author list.\n\n"

            "libcvmfs options are expected in the form: option1,option2,option3,...\n"
            "Within an option, the characters , and \\ must be preceded by \\.\n\n"

            "options are:\n"
            " url=REPOSITORY_URL      The URL of the CernVM-FS server(s): 'url1;url2;...'\n"
            " timeout=SECONDS         Timeout for network operations (default is %d)\n"
            " timeout_direct=SECONDS  Timeout for network operations without proxy (default is %d)\n"
            " max_ttl=MINUTES         Maximum TTL for file catalogs (default: take from catalog)\n"
            " cachedir=DIR            Where to store disk cache\n"
            " proxies=HTTP_PROXIES    Set the HTTP proxy list, such as 'proxy1|proxy2;DIRECT'\n"
            " tracefile=FILE          Trace FUSE opaerations into FILE\n"
            " whitelist=URL           HTTP location of trusted catalog certificates (defaults is /.cvmfswhitelist)\n"
            " pubkey=PEMFILE          Public RSA key that is used to verify the whitelist signature.\n"
            " force_signing           Except only signed catalogs\n"
            " rebuild_cachedb         Force rebuilding the quota cache db from cache directory\n"
            " quota_limit=MB          Limit size of data chunks in cache. -1 Means unlimited.\n"
            " quota_threshold=MB      Cleanup until size is <= threshold\n"
            " nofiles=NUMBER          Set the maximum number of open files for CernVM-FS process (soft limit)\n"
            " logfile=FILE            Logs all messages to FILE instead of stderr and daemonizes.\n"
            "                         Makes only sense for the debug version\n"
            " deep_mount=prefix       Path prefix if a repository is mounted on a nested catalog,\n"
            "                         i.e. deep_mount=/software/15.0.1\n"
            " repo_name=<repository>  Unique name of the mounted repository, e.g. atlas.cern.ch\n"
            " blacklist=FILE          Local blacklist for invalid certificates.  Has precedence over the whitelist.\n"
            "                         (Default is /etc/cvmfs/blacklist)\n"
            " syslog_level=NUMBER     Sets the level used for syslog to DEBUG (1), INFO (2), or NOTICE (3).\n"
            "                         Default is NOTICE.\n"
            " Note: you cannot load files greater than quota_limit-quota_threshold\n",
            PACKAGE_VERSION, defaults.timeout, defaults.timeout_direct
            );
   }
};



int cvmfs_open(const char *path)
{
   int rc = cvmfs::cvmfs_open(path);
   if (rc < 0) {
       errno = -rc;
       return -1;
   }
   return rc;
}

int cvmfs_close(int fd)
{
   int rc = cvmfs::cvmfs_close(fd);
   if (rc < 0) {
       errno = -rc;
       return -1;
   }
   return 0;
}

int cvmfs_readlink(const char *path, char *buf, size_t size) {
   int rc = cvmfs::cvmfs_readlink(path,buf,size);
   if (rc < 0) {
       errno = -rc;
       return -1;
   }
   return 0;
}

int cvmfs_stat(const char *c_path,struct stat *st)
{ 
   int rc = cvmfs_getattr(c_path,st);
   if( rc < 0 ) {
       errno = -rc;
       return -1;
   }
   return 0;
}

int cvmfs_listdir(const char *path,char ***buf,size_t *buflen)
{
    int rc = cvmfs::cvmfs_listdir(path,buf,buflen);
    if( rc < 0 ) {
        errno = -rc;
        return -1;
    }
    return 0;
}

int cvmfs_init(char const *options)
{
   /* Parse options */
   struct cvmfs_opts cvmfs_opts;
   int parse_result = cvmfs_opts.parse_options(options);
   if (parse_result != 0)
   {
      if (parse_result < 0) {
         fprintf(stderr,"Invalid CVMFS options: %s.\n",options);
         cvmfs_opts.usage();
      }
      return -1;
   }
   if (cvmfs_opts.url.empty()) {
      fprintf(stderr,"No url specified in CVMFS options: %s.\n",options);
      return -1;
   }

   int rc = cvmfs_common_init(
      cvmfs_opts.url,
      cvmfs_opts.proxies,
      cvmfs_opts.repo_name,
      cvmfs_opts.pubkey,
      cvmfs_opts.cachedir,
      false, /* cd_to_cachedir */
      cvmfs_opts.quota_limit,
      cvmfs_opts.quota_threshold,
      cvmfs_opts.rebuild_cachedb,
      getuid(),
      getgid(),
      cvmfs_opts.max_ttl,
      cvmfs_opts.force_signing,
      cvmfs_opts.timeout,
      cvmfs_opts.timeout_direct,
      cvmfs_opts.syslog_level,
      cvmfs_opts.logfile,
      cvmfs_opts.tracefile,
      cvmfs_opts.deep_mount,
      cvmfs_opts.blacklist,
      cvmfs_opts.whitelist,
      cvmfs_opts.nofiles,
      false, /* grab_mountpoint */
      false, /* enable_talk */
      NULL,  /* cvmfs_set_cache_drainout_fn */
      NULL   /* cvmfs_unset_cache_drainout_fn */
   );
   if( rc != 0 ) {
       return -1;
   }

   cvmfs_common_spawn();

   return 0;
}

void cvmfs_fini() {
   cvmfs_common_fini();
}

void cvmfs_set_log_fn( void (*log_fn)(const char *msg) )
{
   syslog_set_alt_logger( log_fn );
}
