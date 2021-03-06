/**
 * \file cvmfs.cc
 * \namespace cvmfs
 *
 * CernVM-FS is a FUSE module which implements an HTTP read-only filesystem.
 * The original idea is based on GROW-FS.
 *
 * CernVM-FS shows a remote HTTP directory as local file system.  The client
 * sees all available files.  On first access, a file is downloaded and
 * cached locally.  All downloaded pieces are verified with SHA1.
 *
 * To do so, a directory hive has to be transformed into a CVMFS2
 * "repository".  This can be done by the CernVM-FS server tools.
 *
 * This preparation of directories is transparent to web servers and
 * web proxies.  They just serve static content, i.e. arbitrary files.
 * Any HTTP server should do the job.  We use Apache + Squid.  Serving
 * files from the memory of a web proxy brings significant performance
 * improvement.
 *
 *
 * Developed by Jakob Blomer 2009 at CERN
 * jakob.blomer@cern.ch
 */

#define FUSE_USE_VERSION 25
#define _FILE_OFFSET_BITS 64
#define ENOATTR ENODATA /* instead including attr/xattr.h */

#include "config.h"

#include "fuse-duplex.h"

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <ctime>
#include <cassert>
#include <cstdio>

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <sys/xattr.h>

#include "tracer.h"
#include "catalog.h"
#include "catalog_tree.h"
#include "cache.h"
#include "hash.h"
#include "talk.h"
#include "monitor.h"
#include "signature.h"
#include "lru.h"
#include "util.h"
#include "atomic.h"

extern "C" {
   #include "debug.h"
   #include "sha1.h"
   #include "http_curl.h"
   #include "compression.h"
   #include "smalloc.h"
   #include "log.h"
   #include "sqlite3-duplex.h"
}

using namespace std;


namespace cvmfs {
   string mountpoint = "";
   string root_url = "";
   string root_catalog = "";
   string cachedir = "/var/cache/cvmfs2/default";
   string proxies = "";
   string whitelist = "";
   string blacklist = "/etc/cvmfs/blacklist"; /* blacklist for compromised certificates */
   string deep_mount = "";
   string repo_name = ""; ///< Expected reposiotry name, e.g. atlas.cern.ch
   const double whitelist_lifetime = 3600.0*24.0*30.0; ///< 30 days in seconds
   const int short_term_ttl = 240; /* in offline mode, check every 4 minutes */
   string tracefile = "";
   uid_t uid = 0;                ///< will be set to uid of launching user.
   gid_t gid = 0;                ///< will be set to gid of launching user.
   pid_t pid = 0;                ///< will be set after deamon()
   bool force_signing = false;   ///< Do not load not-signed catalogs.
   unsigned max_ttl = 0;
   pthread_mutex_t mutex_max_ttl = PTHREAD_MUTEX_INITIALIZER;
   int max_cache_timeout = 0;
   time_t drainout_deadline = 0;
   hash::t_sha1 next_root;
   time_t boot_time;

   /* Prevent DoS attacks on the Squid server */
   static struct {
      time_t timestamp;
      int delay;
   } prev_io_error;
   const int MAX_INIT_IO_DELAY = 32; // Maximum start value for exponential backoff
   const int MAX_IO_DELAY = 2000; // Maximum 2 seconds
   const int FORGET_DOS = 10000; // Clear DoS memory after 10 seconds

   pthread_mutex_t mutex_download = PTHREAD_MUTEX_INITIALIZER; ///< avoids downloading the same file twice

   /* Caches */
   const int CATALOG_CACHE_SIZE = 32768*2;
   static inline int catalog_cache_idx(const hash::t_md5 &md5) {
      //return md5.digest[0] + (md5.digest[1] % 256) * 256;
      return (int)md5.digest[0] + ((int)md5.digest[1] << 8);
   }
   struct catalog_cacheline {
      hash::t_md5 md5;
      catalog::t_dirent d;
   };
   struct catalog_cacheline catalog_cache[CATALOG_CACHE_SIZE];
   atomic_int cache_inserts;
   atomic_int cache_replaces;
   atomic_int cache_cleans;
   atomic_int cache_hits;
   atomic_int cache_misses;

   atomic_int certificate_hits;
   atomic_int certificate_misses;

   atomic_int64 nopen;
   atomic_int64 ndownload;

   atomic_int open_files; ///< number of currently open files by Fuse calls
   unsigned nofiles; ///< maximum allowed number of open files
   const int NUM_RESERVED_FD = 512; ///< number of reserved file descriptors for internal use
   atomic_int nioerr;

   static uint64_t effective_ttl(const uint64_t ttl) {
      pthread_mutex_lock(&mutex_max_ttl);
      const uint64_t current_max = max_ttl;
      pthread_mutex_unlock(&mutex_max_ttl);

      if (current_max == 0)
         return ttl;

      pmesg(D_CVMFS, "building effective TTL from max (%u) and given (%u)", current_max, ttl);
      return (current_max < ttl) ? current_max : ttl;
   }

   void reset_error_counters() {
      atomic_init(&nioerr);
   }

   unsigned get_max_ttl() {
      pthread_mutex_lock(&mutex_max_ttl);
      const unsigned current_max = max_ttl/60;
      pthread_mutex_unlock(&mutex_max_ttl);

      return current_max;
   }

   void set_max_ttl(const unsigned value) {
      pthread_mutex_lock(&mutex_max_ttl);
      max_ttl = value*60;
      pthread_mutex_unlock(&mutex_max_ttl);
   }

   void info_loaded_catalogs(vector<string> &prefix, vector<time_t> &last_modified,
                             vector<time_t> &expires)
   {
      catalog::lock();
      for (int i = 0; i < catalog::get_num_catalogs(); ++i) {
         catalog_tree::catalog_meta_t *info = catalog_tree::get_catalog(i);
         string path = info->path;
         if (info->dirty)
            path = "(!) " + path;
         prefix.push_back(path);
         last_modified.push_back(catalog::get_lastmodified(i));
         expires.push_back(info->expires);
      }
      catalog::unlock();
   }

   /**
    * Replaces ":" and "/" with "-" to name the url of a catalog as file in the cache.
    * \return mangled url, usable as file name.
    */
   static string make_fs_key(string url) {
      string::size_type pos;
      while ((pos = url.find(':', 0)) != string::npos)
         url[pos] = '-';
      while ((pos = url.find('/', 0)) != string::npos)
         url[pos] = '-';
      return url;
   }


   /**
    * Checks, if the SHA1 checksum of a PEM certificate is listed on the
    * whitelist at URL cvmfs::cert_whitelist.
    * With nocache, whitelist is downloaded with pragma:no-cache
    */
   static bool valid_certificate(bool nocache) {
      const string fingerprint = signature::fingerprint();
      if (fingerprint == "") {
         pmesg(D_CVMFS, "invalid catalog signature");
         return false;
      }
      pmesg(D_CVMFS, "checking certificate with fingerprint %s against whitelist", fingerprint.c_str());

      time_t local_timestamp = time(NULL);
      struct mem_url mem_url_wl;
      mem_url_wl.data = NULL;
      string buffer;
      istringstream stream;
      string line;
      unsigned skip = 0;

      /* download whitelist */
      int curl_result;
      if (nocache) curl_result = curl_download_mem_nocache(whitelist.c_str(), &mem_url_wl, 1, 0);
      else curl_result = curl_download_mem(whitelist.c_str(), &mem_url_wl, 1, 0);
      if ((curl_result != CURLE_OK) || !mem_url_wl.data) {
         pmesg(D_CVMFS, "whitelist could not be loaded from %s", whitelist.c_str());
         return false;
      }
      buffer = string(mem_url_wl.data, mem_url_wl.size);

      /* parse whitelist */
      stream.str(buffer);

      /* check timestamp (UTC) */
      if (!getline(stream, line) || (line.length() != 14)) {
         pmesg(D_CVMFS, "invalid timestamp format");
         free(mem_url_wl.data);
         return false;
      }
      skip += 15;
      /* Ignore issue date (legacy) */

      /* Now expiry date */
      if (!getline(stream, line) || (line.length() != 15)) {
         pmesg(D_CVMFS, "invalid timestamp format");
         free(mem_url_wl.data);
         return false;
      }
      skip += 16;
      struct tm tm_wl;
      memset(&tm_wl, 0, sizeof(struct tm));
      tm_wl.tm_year = atoi(line.substr(1, 4).c_str())-1900;
      tm_wl.tm_mon = atoi(line.substr(5, 2).c_str()) - 1;
      tm_wl.tm_mday = atoi(line.substr(7, 2).c_str());
      tm_wl.tm_hour = atoi(line.substr(9, 2).c_str());
      tm_wl.tm_min = 0; /* exact on hours level */
      tm_wl.tm_sec = 0;
      time_t timestamp = timegm(&tm_wl);
      pmesg(D_CVMFS, "whitelist UTC expiry timestamp in localtime: %s", localtime_ascii(timestamp, false).c_str());
      if (timestamp < 0) {
         pmesg(D_CVMFS, "invalid timestamp");
         free(mem_url_wl.data);
         return false;
      }
      pmesg(D_CVMFS, "local time: %s", localtime_ascii(local_timestamp, true).c_str());
      if (local_timestamp > timestamp) {
         pmesg(D_CVMFS, "whitelist lifetime verification failed, expired");
         free(mem_url_wl.data);
         return false;
      }

      /* Check repository name */
      if (!getline(stream, line)) {
         pmesg(D_CVMFS, "failed to get repository name");
         free(mem_url_wl.data);
         return false;
      }
      skip += line.length() + 1;
      if ((repo_name != "") && ("N" + repo_name != line)) {
         pmesg(D_CVMFS, "repository name does not match (found %s, expected %s)",
                        line.c_str(), repo_name.c_str());
         free(mem_url_wl.data);
         return false;
      }

      /* search the fingerprint */
      bool found = false;
      while (getline(stream, line)) {
         skip += line.length() + 1;
         if (line == "--") break;
         if (line.substr(0, 59) == fingerprint)
            found = true;
      }
      if (!found) {
         pmesg(D_CVMFS, "the certificate's fingerprint is not on the whitelist");
         if (mem_url_wl.data)
            free(mem_url_wl.data);
         return false;
      }

      /* check whitelist signature */
      if (!getline(stream, line) || (line.length() < 40)) {
         pmesg(D_CVMFS, "no checksum at the end of whitelist found");
         free(mem_url_wl.data);
         return false;
      }
      hash::t_sha1 sha1;
      sha1.from_hash_str(line.substr(0, 40));
      if (sha1 != hash::t_sha1(buffer.substr(0, skip-3))) {
         pmesg(D_CVMFS, "whitelist checksum does not match");
         free(mem_url_wl.data);
         return false;
      }

      /* check local blacklist */
      ifstream fblacklist;
      fblacklist.open(blacklist.c_str());
      if (fblacklist) {
         string blackline;
         while (getline(fblacklist, blackline)) {
            if (blackline.substr(0, 59) == fingerprint) {
               pmesg(D_CVMFS, "this fingerprint is blacklisted");
               logmsg("Blacklisted fingerprint (%s)", fingerprint.c_str());
               fblacklist.close();
               free(mem_url_wl.data);
               return false;
            }
         }
         fblacklist.close();
      }

      void *sig_buf;
      unsigned sig_buf_size;
      if (!read_sig_tail(&buffer[0], buffer.length(), skip,
                         &sig_buf, &sig_buf_size))
      {
         pmesg(D_CVMFS, "no signature at the end of whitelist found");
         free(mem_url_wl.data);
         return false;
      }
      const string sha1str = sha1.to_string();
      bool result = signature::verify_rsa(&sha1str[0], 40, sig_buf, sig_buf_size);
      free(sig_buf);
      if (!result) pmesg(D_CVMFS, "whitelist signature verification failed, %s", signature::get_crypto_err().c_str());
      else pmesg(D_CVMFS, "whitelist signature verification passed");

      if (result) {
         return true;
      } else {
         free(mem_url_wl.data);
         return false;
      }
   }


   /**
    * Loads a catalog from an url into local cache if there is a newer version.
    * Catalogs are stored like data chunks.
    * This funktions returns a temporary file that is not tampered with by LRU.
    *
    * We first download the checksum of the catalog to quickly see if anyting changed.
    *
    * The checksum can be signed by an X.509 certificate.  If so, we only load succeed
    * only with a valid signature and a valid certificate.
    *
    * @param[in] url, relative directory path starting from root_url
    * @param[in] no_proxy, if true, fetch checksum and signature/whitelist with pragma: no-cache
    * @param[in] mount_point, expected mount path (required for sanity check)
    * @param[out] cat_file, file name of the catalog cache copy or the new catalog on success.
    * @param[out] cat_sha1, sha1 value of the catalog returned by cat_file.
    * @param[out] old_file, file name of the old catalog cache copy if new catalog is loaded.
    * @param[out] old_sha1, sha1 value of the old catalog cache copy if new catalog is loaded.
    * @param[out] cached_copy, indicates if a new catalog version was loaded.
    * \return 0 on success, a standard error code else
    */
   static int fetch_catalog(const string &url_path, const bool no_proxy, const hash::t_md5 &mount_point,
                            string &cat_file, hash::t_sha1 &cat_sha1, string &old_file, hash::t_sha1 &old_sha1,
                            bool &cached_copy, const hash::t_sha1 &sha1_expected, const bool dry_run = false)
   {
      const string fskey = (repo_name == "") ? cvmfs::root_url : repo_name;
      const string lpath_chksum = "./cvmfs.checksum." + make_fs_key(fskey + url_path);
      const string rpath_chksum = url_path + "/.cvmfspublished";
      bool have_cached = false;
      bool signature_ok = false;
      hash::t_sha1 sha1_download;
      hash::t_sha1 sha1_local;
      hash::t_sha1 sha1_chksum; /* required for signature verification */
      struct mem_url mem_url_chksum;
      struct mem_url mem_url_cert;
      map<char, string> chksum_keyval;
      int curl_result;
      int64_t local_modified;
      char *checksum = NULL;

      pmesg(D_CVMFS, "searching for filesystem at %s", (cvmfs::root_url+url_path).c_str());

      cached_copy = false;
      cat_file = old_file = "";
      old_sha1 = cat_sha1 = hash::t_sha1();
      local_modified = 0;

      /* load local checksum */
      pmesg(D_CVMFS, "local checksum file is %s", lpath_chksum.c_str());
      FILE *fchksum = fopen(lpath_chksum.c_str(), "r");
      char tmp[40];
      if (fchksum && (fread(tmp, 1, 40, fchksum) == 40))
      {
         sha1_local.from_hash_str(string(tmp, 40));
         cat_file = "./" + string(tmp, 2) + "/" + string(tmp+2, 38);

         /* try to get local last modified time */
         char buf_modified;
         string str_modified;
         if ((fread(&buf_modified, 1, 1, fchksum) == 1) && (buf_modified == 'T')) {
            while (fread(&buf_modified, 1, 1, fchksum) == 1)
               str_modified += string(&buf_modified, 1);
            local_modified = atoll(str_modified.c_str());
            pmesg(D_CVMFS, "cached copy publish date %s", localtime_ascii(local_modified, true).c_str());
         }

         /* Sanity check, do we have the catalog? If yes, save it to temporary file. */
         if (!dry_run) {
            if (rename(cat_file.c_str(), (cat_file + "T").c_str()) != 0) {
               cat_file = "";
               unlink(lpath_chksum.c_str());
               pmesg(D_CVMFS, "checksum existed but no catalog with it");
            } else {
               cat_file += "T";
               old_file = cat_file;
               cat_sha1 = old_sha1 = sha1_local;
               have_cached = cached_copy = true;
               pmesg(D_CVMFS, "local checksum is %s", sha1_local.to_string().c_str());
            }
         } else {
            old_file = cat_file;
            cat_sha1 = old_sha1 = sha1_local;
            have_cached = cached_copy = true;
         }
      } else {
         pmesg(D_CVMFS, "unable to read local checksum");
      }
      if (fchksum) fclose(fchksum);

      /* load remote checksum */
      int sig_start = 0;
      if (sha1_expected == hash::t_sha1()) {
         if (no_proxy) curl_result = curl_download_mem_nocache(rpath_chksum.c_str(), &mem_url_chksum, 1, 0);
         else curl_result = curl_download_mem(rpath_chksum.c_str(), &mem_url_chksum, 1, 0);
         if (curl_result != CURLE_OK) {
            if (mem_url_chksum.size > 0) free(mem_url_chksum.data);
            pmesg(D_CVMFS, "unable to load checksum from %s (%d), going to offline mode", rpath_chksum.c_str(), curl_result);
            logmsg("unable to load checksum from %s (%d), going to offline mode", rpath_chksum.c_str(), curl_result);
            return -EIO;
         }
         checksum = (char *)alloca(mem_url_chksum.size);
         memcpy(checksum, mem_url_chksum.data, mem_url_chksum.size);
         free(mem_url_chksum.data);

         /* parse remote checksum */
         parse_keyval(checksum, mem_url_chksum.size, sig_start, sha1_chksum, chksum_keyval);

         map<char, string>::const_iterator clg_key = chksum_keyval.find('C');
         if (clg_key == chksum_keyval.end()) {
            pmesg(D_CVMFS, "failed to find catalog key in checksum");
            return -EINVAL;
         }
         sha1_download.from_hash_str(clg_key->second);
         pmesg(D_CVMFS, "remote checksum is %s", sha1_download.to_string().c_str());
      } else {
         sha1_download = sha1_expected;
      }

      /* short way out, use cached copy */
      if (have_cached) {
         if (sha1_download == sha1_local)
            return 0;

         /* Sanity check, last modified (if available, i.e. if signed) */
         map<char, string>::const_iterator published = chksum_keyval.find('T');
         if (published != chksum_keyval.end()) {
            if (local_modified > atoll(published->second.c_str())) {
               pmesg(D_CVMFS, "cached checksum newer than loaded checksum");
               logmsg("Cached copy of %s newer than remote copy", rpath_chksum.c_str());
               return 0;
            }
         }
      }

      if (sha1_expected == hash::t_sha1()) {
         /* Sanity check: repository name */
         if (repo_name != "") {
            map<char, string>::const_iterator name = chksum_keyval.find('N');
            if (name == chksum_keyval.end()) {
               pmesg(D_CVMFS, "failed to find repository name in checksum");
               return -EINVAL;
            }
            if (name->second != repo_name) {
               pmesg(D_CVMFS, "expected repository name does not match");
               logmsg("Expected repository name does not match in %s", rpath_chksum.c_str());
               return -EINVAL;
            }
         }


         /* Sanity check: root prefix */
         map<char, string>::const_iterator root_prefix = chksum_keyval.find('R');
         if (root_prefix == chksum_keyval.end()) {
            pmesg(D_CVMFS, "failed to find root prefix in checksum");
            return -EINVAL;
         }
         if (root_prefix->second != mount_point.to_string()) {
            pmesg(D_CVMFS, "expected mount point does not match");
            logmsg("Expected mount point does not match in %s", rpath_chksum.c_str());
            return -EINVAL;
         }

         /* verify remote checksum signature, failure is handled like checksum could not be downloaded,
            except for error code -2 instead of -1. */
         void *sig_buf_heap;
         unsigned sig_buf_size;
         if ((sig_start > 0) &&
             read_sig_tail(checksum, mem_url_chksum.size, sig_start,
                           &sig_buf_heap, &sig_buf_size))
         {
            void *sig_buf = alloca(sig_buf_size);
            memcpy(sig_buf, sig_buf_heap, sig_buf_size);
            free(sig_buf_heap);

            /* retrieve certificate */
            map<char, string>::const_iterator key_cert = chksum_keyval.find('X');
            if ((key_cert == chksum_keyval.end()) || (key_cert->second.length() < 40)) {
               pmesg(D_CVMFS, "invalid certificate in checksum");
               return -EINVAL;
            }

            bool cached_cert = false;
            hash::t_sha1 cert_sha1;
            cert_sha1.from_hash_str(key_cert->second.substr(0, 40));

            if (cache::disk_to_mem(cert_sha1, &mem_url_cert.data, &mem_url_cert.size)) {
               atomic_inc(&certificate_hits);
               cached_cert = true;
            } else {
               atomic_inc(&certificate_misses);
               cached_cert = false;

               const string url_cert = "/data/" + key_cert->second.substr(0, 2) + "/" +
                                       key_cert->second.substr(2) + "X";
               if (no_proxy) curl_result = curl_download_mem_nocache(url_cert.c_str(), &mem_url_cert, 1, 1);
               else curl_result = curl_download_mem(url_cert.c_str(), &mem_url_cert, 1, 1);
               if (curl_result != CURLE_OK) {
                  pmesg(D_CVMFS, "unable to load certificate from %s (%d)", url_cert.c_str(), curl_result);
                  if (mem_url_cert.size > 0) free(mem_url_cert.data);
                  return -EAGAIN;
               }

               /* verify downloaded chunk */
               void *outbuf;
               size_t outsize;
               hash::t_sha1 verify_sha1;
               bool verify_result;
               if (compress_mem(mem_url_cert.data, mem_url_cert.size, &outbuf, &outsize) != 0) {
                  verify_result = false;
               } else {
                  sha1_mem(outbuf, outsize, verify_sha1.digest);
                  free(outbuf);
                  verify_result = (verify_sha1 == cert_sha1);
               }
               if (!verify_result) {
                  pmesg(D_CVMFS, "data corruption for %s", url_cert.c_str());
                  free(mem_url_cert.data);
                  return -EAGAIN;
               }
            }

            /* read certificate */
            if (!signature::load_certificate(mem_url_cert.data, mem_url_cert.size, false)) {
               pmesg(D_CVMFS, "could not read certificate");
               free(mem_url_cert.data);
               return -EINVAL;
            }

            /* verify certificate and signature */
            if (!valid_certificate(no_proxy) ||
                !signature::verify(&((sha1_chksum.to_string())[0]), 40, sig_buf, sig_buf_size))
            {
               pmesg(D_CVMFS, "signature verification failed against %s", sha1_chksum.to_string().c_str());
               free(mem_url_cert.data);
               return -EPERM;
            }
            pmesg(D_CVMFS, "catalog signed by: %s", signature::whois().c_str());
            signature_ok = true;

            if (!cached_cert) {
               cache::mem_to_disk(cert_sha1, mem_url_cert.data, mem_url_cert.size,
                                  "certificate of " + signature::whois());
            }
            free(mem_url_cert.data);
         } else {
            pmesg(D_CVMFS, "remote checksum is not signed");
            if (force_signing) {
               logmsg("Remote checksum %s is not signed", rpath_chksum.c_str());
               return -EPERM;
            }
         }
      }

      if (dry_run) {
         cat_sha1 = sha1_download;
         return 1;
      }

      /* load new catalog */
      const string tmp_file_template = "./cvmfs.catalog.XXXXXX";
      char *tmp_file = strdupa(tmp_file_template.c_str());
      int tmp_fd = mkstemp(tmp_file);
      if (tmp_fd < 0) return -EIO;
      FILE *tmp_fp = fdopen(tmp_fd, "w");
      if (!tmp_fp) {
         close(tmp_fd);
         unlink(tmp_file);
         return -EIO;
      }
      int retval;
      char strmbuf[4096];
      retval = setvbuf(tmp_fp, strmbuf, _IOFBF, 4096);
      assert(retval == 0);

      const string sha1_clg_str = sha1_download.to_string();
      const string url_clg = "/data/" + sha1_clg_str.substr(0, 2) + "/" +
                             sha1_clg_str.substr(2) + "C";
      if (no_proxy) curl_result = curl_download_stream_nocache(url_clg.c_str(), tmp_fp, sha1_local.digest, 1, 1);
      else curl_result = curl_download_stream(url_clg.c_str(), tmp_fp, sha1_local.digest, 1, 1);
      fclose(tmp_fp);
      if ((curl_result != CURLE_OK) || (sha1_local != sha1_download)) {
         pmesg(D_CVMFS, "unable to load catalog from %s, going to offline mode (%d)", url_clg.c_str(), curl_result);
         logmsg("unable to load catalog from %s, going to offline mode", url_clg.c_str());
         unlink(tmp_file);
         return -EAGAIN;
      }

      /* we have all bits and pieces, write checksum and catalog into cache directory */
      const string sha1_download_str = sha1_download.to_string();
      cat_file = tmp_file;
      cat_sha1 = sha1_download;
      cached_copy = false;

      int fdchksum = open(lpath_chksum.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
      if (fdchksum >= 0) {
         string local_chksum = sha1_local.to_string();
         map<char, string>::const_iterator published = chksum_keyval.find('T');
         if (published != chksum_keyval.end())
            local_chksum += "T" + published->second;

         fchksum = fdopen(fdchksum, "w");
         if (fchksum) {
            if (fwrite(&(local_chksum[0]), 1, local_chksum.length(), fchksum) != local_chksum.length())
               unlink(lpath_chksum.c_str());
            fclose(fchksum);
         } else {
            unlink(lpath_chksum.c_str());
         }
      } else {
         unlink(lpath_chksum.c_str());
      }
      if ((sha1_expected == hash::t_sha1()) && signature_ok) {
         logmsg("Signed catalog loaded from %s, signed by %s",
                (cvmfs::root_url + url_path).c_str(), signature::whois().c_str());
      }
      return 0;
   }


   static void update_ttl(catalog_tree::catalog_meta_t *info) {
      info->expires = time(NULL) + effective_ttl(catalog::get_ttl(info->catalog_id));
   }

   static void update_ttl_shortterm(catalog_tree::catalog_meta_t *info) {
      info->expires = time(NULL) + effective_ttl(short_term_ttl);
   }

   /**
    * Carefully invalidate memory cache
    */
   static void invalidate_cache(const int catalog_id) {
      hash::t_md5 md5_null;
      for (int i = 0; i < CATALOG_CACHE_SIZE; ++i) {
         if (!(catalog_cache[i].md5 == md5_null) &&
             (((catalog_id >= 0) && (catalog_cache[i].d.catalog_id == catalog_id)) ||
              catalog_cache[i].d.flags & catalog::DIR_NESTED))
         {
            catalog_cache[i].md5 = hash::t_md5();
            atomic_inc(&cache_cleans);
         }
      }
   }

   static void set_dirty(catalog_tree::catalog_meta_t *info) {
      const int catalog_id = info->catalog_id;
      const int parent_id = catalog_tree::get_parent(catalog_id)->catalog_id;

      if (catalog_tree::get_catalog(parent_id)->dirty) {
         info->dirty = true;
      } else {
         hash::t_sha1 expected_clg;
         if (!catalog::lookup_nested_unprotected(parent_id,
                                                 catalog::mangled_path(info->path),
                                                 expected_clg))
         {
            logmsg("Nested catalog at %s not found (forward scan)", (info->path).c_str());
            info->dirty = true;
            invalidate_cache(catalog_id);
         } else {
            if (expected_clg != info->snapshot) {
               info->dirty = true;
               invalidate_cache(catalog_id);
            } else {
               info->dirty = false;
            }
         }
      }
   }


   /* returns: 0 -- cached, 1 -- new, negative -- error */
   static int check_catalog(const string &url_path, const hash::t_md5 &mount_point,
                            const string &mount_path, hash::t_sha1 &new_catalog)
   {
      string cat_file;
      string old_file;
      hash::t_sha1 sha1_old;
      bool cached_copy;

      int result = fetch_catalog(url_path, false, mount_point,
                                 cat_file, new_catalog, old_file, sha1_old, cached_copy, hash::t_sha1(), true);
      if ((result == -EPERM) || (result == -EAGAIN) || (result == -EINVAL)) {
         /* retry with no-cache pragma */
         pmesg(D_CVMFS, "could not load catalog, trying again with pragma: no-cache");
         logmsg("possible data corruption while trying to retrieve catalog from %s, trying with no-cache",
                (cvmfs::root_url + url_path).c_str());
         result = fetch_catalog(url_path, true, mount_point,
                                cat_file, new_catalog, old_file, sha1_old, cached_copy, hash::t_sha1(), true);
      }

      /* log certain failures */
      if (result == -EPERM) {
         logmsg("signature verification failure while trying to retrieve catalog from %s",
                (cvmfs::root_url + url_path).c_str());
      }
      if ((result == -EINVAL) || (result == -EAGAIN)) {
         logmsg("data corruption while trying to retrieve catalog from %s",
                (cvmfs::root_url + url_path).c_str());
      }
      else if (result < 0) {
         logmsg("catalog load failure while try to retrieve catalog from %s",
                (cvmfs::root_url + url_path).c_str());
      }

      return result;
   }

   /**
    * Uses fetch catalog to get a possibly new catalog version.
    * Old catalog has to be detached afterwards.
    * Updates LRU database and TTL list.
    * \return 0 on success (also cached copy is success), standard error code else
    */
   static int load_and_attach_catalog(const string &url_path, const hash::t_md5 &mount_point,
                                      const string &mount_path, const int existing_cat_id, const bool no_cache,
                                      const hash::t_sha1 expected_clg = hash::t_sha1())
   {
      string cat_file;
      string old_file;
      hash::t_sha1 sha1_old;
      hash::t_sha1 sha1_cat;
      bool cached_copy;
      int cat_id = existing_cat_id;

      int result = fetch_catalog(url_path, no_cache, mount_point,
                                 cat_file, sha1_cat, old_file, sha1_old, cached_copy, expected_clg);
      if (((result == -EPERM) || (result == -EAGAIN) || (result == -EINVAL)) && !no_cache) {
         /* retry with no-cache pragma */
         pmesg(D_CVMFS, "could not load catalog, trying again with pragma: no-cache");
         logmsg("possible data corruption while trying to retrieve catalog from %s, trying with no-cache",
                (cvmfs::root_url + url_path).c_str());
         result = fetch_catalog(url_path, true, mount_point,
                                cat_file, sha1_cat, old_file, sha1_old, cached_copy, expected_clg);
      }
      /* log certain failures */
      if (result == -EPERM) {
         logmsg("signature verification failure while trying to retrieve catalog from %s",
                (cvmfs::root_url + url_path).c_str());
      }
      if ((result == -EINVAL) || (result == -EAGAIN)) {
         logmsg("data corruption while trying to retrieve catalog from %s",
                (cvmfs::root_url + url_path).c_str());
      }
      else if (result < 0) {
         logmsg("catalog load failure while try to retrieve catalog from %s",
                (cvmfs::root_url + url_path).c_str());
      }

      /* LRU handling, could still fail due to cache size restrictions */
      if (((result == 0) && !cached_copy) ||
          ((existing_cat_id < 0) && ((result == 0) || cached_copy)))
      {
         struct stat64 info;
         if (stat64(cat_file.c_str(), &info) != 0) {
            /* should never happen */
            lru::remove(sha1_cat);
            cached_copy = false;
            result = -EIO;
            pmesg(D_CVMFS, "failed to access new catalog");
            logmsg("catalog access failure for %s", cat_file.c_str());
         } else {
            if (((uint64_t)info.st_size > lru::max_file_size()) ||
                (!lru::pin(sha1_cat, info.st_size, root_url + url_path)))
            {
               pmesg(D_CVMFS, "failed to store %s in LRU cache (no space)", cat_file.c_str());
               logmsg("catalog load failure for %s (no space)", cat_file.c_str());
               lru::remove(sha1_cat);
               unlink(cat_file.c_str());
               cached_copy = false;
               result = -ENOSPC;
            } else {
               /* From now on we have to go with the new catalog */
               if (!sha1_old.is_null() && (sha1_old != sha1_cat)) {
                  lru::remove(sha1_old);
                  unlink(old_file.c_str());
               }
            }
         }
      }

      time_t now = time(NULL);

      /* Now we have the right catalog in cat_file, which might be
            already loaded (cache_copy and existing_cat_id > 0) */
      if (((result == 0) && !cached_copy) ||
          ((existing_cat_id < 0) && ((result == 0) || cached_copy)))
      {
         bool attach_result;
         if (existing_cat_id >= 0) {
            catalog::detach_intermediate(existing_cat_id);
            attach_result = catalog::reattach(existing_cat_id, cat_file, url_path);
            catalog_tree::get_catalog(existing_cat_id)->last_changed = now;
            catalog_tree::get_catalog(existing_cat_id)->snapshot = sha1_cat;
         } else {
            attach_result = catalog::attach(cat_file, url_path, true, false);
            /* Insert new catalog into the tree */
            catalog_tree::catalog_meta_t *info =
               new catalog_tree::catalog_meta_t(canonical_path(mount_path),
                                                catalog::get_num_catalogs()-1, sha1_cat);
            if (cached_copy)
               info->last_changed = 0;
            else
               info->last_changed = now;

            catalog_tree::insert(info);
         }

         /* Also for existing_cat_id < 0 to remove the "nested" flags from cache */
         invalidate_cache(existing_cat_id);

         if (!attach_result) {
            /* should never happen, no reasonable continuation */
            pmesg(D_CVMFS, "failed to attach new catalog");
            logmsg("catalog attach failure for %s", cat_file.c_str());
            abort();
         } else {
            if (existing_cat_id < 0) {
               cat_id = catalog::get_num_catalogs()-1;
            }
         }
      }

      /* Back-rename if we have a catalog at all.  No race condition with LRU
         because file is pinned. */
      if ((result == 0) || cached_copy) {
         const string sha1_cat_str = sha1_cat.to_string();
         const string final_file = "./" + sha1_cat_str.substr(0, 2) + "/" +
                                   sha1_cat_str.substr(2);
         (void)rename(cat_file.c_str(), final_file.c_str());
      }

      if (cat_id >= 0) {
         catalog_tree::catalog_meta_t *info = catalog_tree::get_catalog(cat_id);

         info->last_checked = now;
         /* Forward TTL adjustment, only on success */
         if (result == 0) {
            info->expires = now + effective_ttl(catalog::get_ttl(cat_id));
            if (info->last_checked > info->last_changed) {
               catalog_tree::visit_children(cat_id, update_ttl);
            }
         } else {
            info->expires = now + effective_ttl(short_term_ttl);
            if (info->last_checked > info->last_changed) {
               catalog_tree::visit_children(cat_id, update_ttl_shortterm);
            }
         }
         info->dirty = false;
         catalog_tree::visit_children(cat_id, set_dirty);

         return 0;
      } else {
         return result;
      }
   }



   /**
    * Tries to find a directory entry in local direct mapped cache.
    * Same interface as catalog::lookup_unprotected
    * Lock this function.
    * \return true, if md5 is in cache, false otherwise
    */
   static int resolve_cache_idx_find(const hash::t_md5 &md5, bool &found) {
      const int idx = catalog_cache_idx(md5);
      const int bucket_start = idx - idx%2;

      found = true;
      if (catalog_cache[bucket_start].md5 == md5)
         return bucket_start;

      if (!(catalog_cache[bucket_start+1].md5 == md5)) {
         found = false;
      } else {
         struct catalog_cacheline tmp = catalog_cache[bucket_start];
         catalog_cache[bucket_start] = catalog_cache[bucket_start+1];
         catalog_cache[bucket_start+1] = tmp;
      }

      return bucket_start;
   }

   static int resolve_cache_idx_insert(const hash::t_md5 &md5) {
      const int idx = catalog_cache_idx(md5);
      const int bucket_start = idx - idx%2;
      const hash::t_md5 null_md5;

      if (!(catalog_cache[bucket_start].md5 == md5) &&
          !(catalog_cache[bucket_start].md5 == null_md5))
      {
         /*if (!(catalog_cache[bucket_start+1].md5 == md5) &&
             !(catalog_cache[bucket_start].md5 == null_md5))
         {
            atomic_inc(&cache_replaces);
         } */
         catalog_cache[bucket_start+1] = catalog_cache[bucket_start];
      }

      return bucket_start;
   }

   static bool lookup_cache(const hash::t_md5 &md5, catalog::t_dirent &d) {
      bool found;
      const int idx = resolve_cache_idx_find(md5, found);
      if (found) {
      //if (catalog_cache[idx].md5 == md5) {
         d = catalog_cache[idx].d;
         atomic_inc(&cache_hits);
         return true;
      }

      atomic_inc(&cache_misses);
      return false;
   }


   /**
    * Inserts or replaces md5 in local d-cache.
    */
   static void insert_cache(const hash::t_md5 &md5, const catalog::t_dirent &d) {
      const int idx = resolve_cache_idx_insert(md5);
      //if (!(catalog_cache[idx].md5 == hash::t_md5())) atomic_inc(&cache_replaces);

      catalog_cache[idx].md5 = md5;
      catalog_cache[idx].d = d;
      atomic_inc(&cache_inserts);
   }


   /**
    * Inserts a negative entry for md5 in local d-cache.
    */
   static void insert_cache_negative(const hash::t_md5 &md5) {
      const int idx = resolve_cache_idx_insert(md5);
      //if (!(catalog_cache[idx].md5 == hash::t_md5())) atomic_inc(&cache_replaces);

      catalog_cache[idx].md5 = md5;
      catalog_cache[idx].d.catalog_id = -1;
      atomic_inc(&cache_inserts);
   }


   /**
    * Don't call without catalog::lock()
    */
   int catalog_cache_memusage_bytes() {
      int result = 0;
      for (int i = 0; i < CATALOG_CACHE_SIZE; ++i) {
         result += sizeof(catalog_cacheline);
         result += catalog_cache[i].d.name.capacity();
         result += catalog_cache[i].d.symlink.capacity();
      }
      return result;
   }

   void catalog_cache_memusage_slots(int &positive, int &negative, int &all,
                                     int &inserts, int &replaces, int &cleans, int &hits, int &misses,
                                     int &cert_hits, int &cert_misses)
   {
      positive = negative = 0;
      all = CATALOG_CACHE_SIZE;
      hash::t_md5 null;
      for (int i = 0; i < CATALOG_CACHE_SIZE; ++i) {
         if (!(catalog_cache[i].md5 == null)) {
            if (catalog_cache[i].d.catalog_id == -1)
               negative++;
            else
               positive++;
         }
      }
      inserts = atomic_read(&cache_inserts);
      replaces = atomic_read(&cache_replaces);
      cleans = atomic_read(&cache_cleans);
      hits = atomic_read(&cache_hits);
      misses = atomic_read(&cache_misses);

      cert_hits = atomic_read(&certificate_hits);
      cert_misses = atomic_read(&certificate_misses);
   }

   static int find_catalog_id(const string &path) {
      return catalog_tree::get_hosting((path == "") ? "/" : path)->catalog_id;
   }


   static int refresh_catalog(const int catalog_id) {
      catalog_tree::catalog_meta_t *catalog = catalog_tree::get_catalog(catalog_id);

      if (catalog->dirty) {
         pmesg(D_CVMFS, "refreshing catalog id %d", catalog_id);
         int parent_id = catalog_tree::get_parent(catalog_id)->catalog_id;

         /* Refresh parent catalog */
         int result = refresh_catalog(parent_id);
         if (result != 0) {
            logmsg("Nested catalog at %s not refreshed because of parent", (catalog->path).c_str());
            return result;
         }

         /* Get the new checksum from parent catalog */
         hash::t_sha1 expected_clg;
         if (!catalog::lookup_nested_unprotected(parent_id,
                                                 catalog::mangled_path(catalog->path),
                                                 expected_clg))
         {
            logmsg("Nested catalog at %s not found (refresh)", (catalog->path).c_str());
            return -ENOENT;
         }

         result = load_and_attach_catalog(catalog::get_catalog_url(catalog_id),
                                          hash::t_md5(catalog::get_root_prefix_specific(catalog_id)),
                                          catalog->path, catalog_id, false, expected_clg);
         return result;
      }

      return 0;
   }


   /* negative -- error, 0 -- cached, 1 -- switched to drainout, 2 -- already in drainout */
   int remount() {
      catalog::lock();
      pmesg(D_CVMFS, "Forced catalog reload...");

      if (drainout_deadline) {
         catalog::unlock();
         return 2;
      }

      /* Reload root catalog */
      hash::t_sha1 new_catalog;
      int result = check_catalog(catalog::get_catalog_url(0),
                                 hash::t_md5(catalog::get_root_prefix_specific(0)),
                                 catalog_tree::get_catalog(0)->path, new_catalog);
      pmesg(D_CVMFS, "Check for new catalog returned %d", result);
      if (result == 1) {
         fuse_set_cache_drainout();
         drainout_deadline = time(NULL) + max_cache_timeout;
         next_root = new_catalog;
      }

      catalog::unlock();
      return result;
   }



   /**
    * Gets called as kind of prerequisit to every operation.
    * We do two kinds of magic here: check catalog TTL (and reload, if necessary)
    * and load nested catalogs. Nested catalogs may also be loaded on readdir.
    *
    * Also, we insert things in our d-cache here.  It is not sufficient to do
    * all the inserts here, even though stat will be called before anything else;
    * they might be cached by the kernel.
    */
   static int cvmfs_getattr(const char *c_path, struct stat *info) {
      /* use the cache only, don't contact the server */
      pmesg(D_CVMFS, "stat %s", c_path);
      const string path = string(c_path);
      Tracer::trace(Tracer::FUSE_STAT, path, "stat() call");
      const hash::t_md5 md5(catalog::mangled_path(path));
      struct catalog::t_dirent d;

      catalog::lock();
      int catalog_id = find_catalog_id(path);
      time_t now = time(NULL);

      /* Check for drainout timestamp, reload and reset if larger then max_cache_timeout */
      if (drainout_deadline && (now > drainout_deadline)) {
         /* Reload root catalog */
         pmesg(D_CVMFS, "Catalog %d: TTL expired, kernel cache drainout complete, reloading...", catalog_id);

         /* Don't load very old stuff */
         if (now > drainout_deadline + max_cache_timeout)
            next_root = hash::t_sha1();

         int result = load_and_attach_catalog(catalog::get_catalog_url(0),
                                              hash::t_md5(catalog::get_root_prefix_specific(0)),
                                              catalog_tree::get_catalog(0)->path, 0, false, next_root);
         fuse_unset_cache_drainout();
         drainout_deadline = 0;

         if (result != 0) {
            catalog::unlock();
            atomic_inc(&nioerr);
            return result;
         }

         logmsg("switched to catalog revision %d", catalog::get_revision());
      }

      /* Check catalog TTL, goto drainout mode if necessary */
      pmesg(D_CVMFS, "current time %lu, deadline %lu", time(NULL), catalog_tree::get_catalog(catalog_id)->expires);
      if ((!drainout_deadline) && (now > catalog_tree::get_catalog(catalog_id)->expires)) {
         /* Reload root catalog */
         pmesg(D_CVMFS, "Catalog %d: TTL expired, draining out caches...", catalog_id);

         hash::t_sha1 new_catalog;
         catalog_tree::catalog_meta_t *clginfo = catalog_tree::get_catalog(0);
         int result = check_catalog(catalog::get_catalog_url(0),
                                    hash::t_md5(catalog::get_root_prefix_specific(0)),
                                    clginfo->path, new_catalog);

         if (result < 0) {
            clginfo->expires = time(NULL) + effective_ttl(short_term_ttl);
            catalog_tree::visit_children(0, update_ttl_shortterm);
         }

         if (result == 0) {
            clginfo->expires = now + effective_ttl(catalog::get_ttl(0));
            catalog_tree::visit_children(0, update_ttl);
         }

         if (result == 1) {
            fuse_set_cache_drainout();
            drainout_deadline = time(NULL) + max_cache_timeout;
            next_root = new_catalog;
         }
      }

      /* Hopefully in mem-cache */
      if (lookup_cache(md5, d)) {
         pmesg(D_CVMFS, "catalog cache HIT (getattr)");
         if (d.catalog_id < 0) {
            catalog::unlock();
            Tracer::trace(Tracer::FUSE_STAT, path, "memcache n-hit");
            return -ENOENT;
         } else {
            Tracer::trace(Tracer::FUSE_STAT, path, "memcache hit");
         }
      } else {
         /* Otherwise, look in the catalog */
         pmesg(D_CVMFS, "catalog cache MISS (getattr)");
         int catalog_id = find_catalog_id(path);

         /* Check if this catalog is dirty, reload if necessary
            Can only happen for nested catalogs. */
         int result = refresh_catalog(catalog_id);
         if (result != 0) {
            catalog::unlock();
            atomic_inc(&nioerr);
            return result;
         }

         /* Now lookup */
         if (!catalog::lookup_informed_unprotected(md5, catalog_id, d)) {
            pmesg(D_CVMFS, "getattr: file %s not existant, maybe we are in a nested catalog?", c_path);

            /* Look for nested catalog in a parent path */
            const string p_path = get_parent_path(path);
            const hash::t_md5 p_md5(catalog::mangled_path(p_path));
            catalog::t_dirent p;
            if ((lookup_cache(p_md5, p) || catalog::lookup_informed_unprotected(p_md5, find_catalog_id(p_path), p)) &&
                (p.flags & catalog::DIR_NESTED) && (p_path != ""))
            {
               /* Load nested catalog */
               pmesg(D_CVMFS, "first time access to nested path %s, loading catalog at %s", c_path, p_path.c_str());
               hash::t_sha1 expected_clg;
               if (!catalog::lookup_nested_unprotected(
                   p.catalog_id, catalog::mangled_path(p_path), expected_clg))
               {
                  catalog::unlock();
                  logmsg("Nested catalog at %s not found (getattr)", c_path);
                  return -ENOENT;
               }

               int result = load_and_attach_catalog(p_path,
                  hash::t_md5(catalog::mangled_path(p_path)), p_path, -1, false, expected_clg);
               if (result != 0) {
                  catalog::unlock();
                  atomic_inc(&nioerr);
                  return result;
               }

               /* and again, maybe we find it in the nested catalog */
               if (!catalog::lookup_informed_unprotected(md5, find_catalog_id(path), d)) {
                  insert_cache_negative(md5);
                  catalog::unlock();
                  return -ENOENT;
               }
            } else {
               insert_cache_negative(md5);
               catalog::unlock();
               Tracer::trace(Tracer::FUSE_STAT, path, "ENOENT");
               return -ENOENT;
            }
         }
         /* OK, we have d from the catalog */
      }

      insert_cache(md5, d);
      catalog::unlock();

      /* The actual getattr-work */
      d.to_stat(info);
      //if (path == "/") {
      //   info->st_mode &= ~7;
      //}
      if (d.flags & catalog::FILE_LINK) {
         info->st_size = expand_env(d.symlink).length();
         pmesg(D_CVMFS, "stat %s expanded to %s", c_path, expand_env(d.symlink).c_str());
      }

      return 0;
   }


   /**
    * Reads a symlink from the catalog.  Environment variables are expanded.
    */
   static int cvmfs_readlink(const char *path, char *buf, size_t size) {
      const hash::t_md5 md5(catalog::mangled_path(path));
      Tracer::trace(Tracer::FUSE_READLINK, path, "readlink() call");

      struct catalog::t_dirent d;
      catalog::lock();
      if (lookup_cache(md5, d)) {
         pmesg(D_CVMFS, "catalog cache HIT");
         if (d.catalog_id < 0) {
            catalog::unlock();
            return -ENOENT;
         }
      } else {
         if (!catalog::lookup_informed_unprotected(md5, find_catalog_id(path), d)) {
            catalog::unlock();
            return -ENOENT;
         }
      }
      catalog::unlock();


      if(!S_ISLNK(d.mode))
         return -ENOLINK;

      const string lnk_exp = expand_env(d.symlink);
      unsigned len = (lnk_exp.length() >= size) ? size : lnk_exp.length()+1;

      strncpy(buf, &lnk_exp[0], len-1);
      buf[len-1] = '\0';

      return 0;
   }


   /**
    * The ls-callback. If we hit a nested catalog, we load it.
    */
   static int cvmfs_readdir(const char *path,
                            void *buf,
                            fuse_fill_dir_t filler,
                            off_t offset __attribute__((unused)),
                            struct fuse_file_info *fi __attribute__((unused)))
   {
      /* Read a directory structure, this is enough to be able to navigate through
         a filesystem */
      struct stat info;
      const hash::t_md5 md5 = hash::t_md5(catalog::mangled_path(path));

      pmesg(D_CVMFS, "readdir %s", path);

      Tracer::trace(Tracer::FUSE_LS, path, "ls() call");

      struct catalog::t_dirent d;
      catalog::lock();
      if (lookup_cache(md5, d)) {
         pmesg(D_CVMFS, "catalog cache HIT");
         if (d.catalog_id < 0) {
            catalog::unlock();
            return -ENOENT;
         }
      } else {
         if (!catalog::lookup_informed_unprotected(md5, find_catalog_id(path), d)) {
            catalog::unlock();
            return -ENOENT;
         }
      }
      /* Maybe we have to load the nested catalog */
      if (d.flags & catalog::DIR_NESTED) {
         pmesg(D_CVMFS, "listing nested catalog at %s (first time access)", path);
         hash::t_sha1 expected_clg;
         if (!catalog::lookup_nested_unprotected(
             d.catalog_id, catalog::mangled_path(path), expected_clg))
         {
            catalog::unlock();
            logmsg("Nested catalog at %s not found (ls)", path);
            return -ENOENT;
         }

         int result = load_and_attach_catalog(path,
            hash::t_md5(catalog::mangled_path(path)), path, -1, false, expected_clg);
         if (result != 0) {
            catalog::unlock();
            atomic_inc(&nioerr);
            return result;
         }
      }

      pmesg(D_CVMFS, "Found entry %s in catalog %d, check if directory", d.name.c_str(), d.catalog_id);
      if(!S_ISDIR(d.mode)) {
         catalog::unlock();
         return -ENOTDIR;
      }

      d.to_stat(&info);
      filler(buf, ".", &info, 0);

      struct catalog::t_dirent p;
      if (catalog::parent_unprotected(md5, p)) {
         p.to_stat(&info);
         filler(buf, "..", &info, 0);
      }

      vector<catalog::t_dirent> dir = catalog::ls_unprotected(md5);
      catalog::unlock();
      for (vector<catalog::t_dirent>::const_iterator i = dir.begin(), iEnd = dir.end();
           i != iEnd; ++i)
      {
         i->to_stat(&info);
         filler(buf, i->name.c_str(), &info, 0);
      }

      return 0;
   }


   /**
    * Open a file from cache.  If necessary, file is downloaded first.
    * Also catalog reload magic can happen, if file download fails.
    *
    * \return Read-only file descriptor in fi->fh
    */
   static int cvmfs_open(const char *c_path, struct fuse_file_info *fi)
   {
      const string path = c_path;
      Tracer::trace(Tracer::FUSE_OPEN, path, "open() call");

      int fd = -1;
      const hash::t_md5 md5(catalog::mangled_path(path));

      /* Look for it in the catalog. If it's not there, it doesn't exist. */
      struct catalog::t_dirent d;
      catalog::lock();
      if (lookup_cache(md5, d)) {
         pmesg(D_CVMFS, "catalog cache HIT");
         if (d.catalog_id < 0) {
            catalog::unlock();
            Tracer::trace(Tracer::FUSE_OPEN, path, "memcache n-hit");
            return -ENOENT;
         } else {
            Tracer::trace(Tracer::FUSE_OPEN, path, "memcache hit");
         }
      } else {
         if (!catalog::lookup_informed_unprotected(md5, find_catalog_id(path), d)) {
            insert_cache_negative(md5);
            catalog::unlock();
            Tracer::trace(Tracer::FUSE_OPEN, path, "ENOENT");
            return -ENOENT;
         } else {
            insert_cache(md5, d);
         }
      }
      catalog::unlock();

      fd = cache::open_or_lock(d);
      atomic_inc64(&nopen);
      if (fd < 0) {
         Tracer::trace(Tracer::FUSE_OPEN, path, "disk cache miss");
         fd = cache::fetch(d, path);
         pthread_mutex_unlock(&mutex_download);
         atomic_inc64(&ndownload);
      }

      if (fd >= 0) {
         if (atomic_xadd(&open_files, 1) < ((int)nofiles)-NUM_RESERVED_FD) {
            fi->fh = fd;
            return 0;
         } else {
            if (close(fd) == 0) atomic_dec(&open_files);
            logmsg("open file descriptor limit exceeded");
            return -EMFILE;
         }
      } else {
         logmsg("failed to open %s, CAS key %s, error code %d",
                c_path, d.checksum.to_string().c_str(), errno);
         if (errno == EMFILE) return -EMFILE;
      }

      /* Prevent Squid DoS */
      time_t now = time(NULL);
      if (now-prev_io_error.timestamp < FORGET_DOS) {
         usleep(prev_io_error.delay*1000);
         if (prev_io_error.delay < MAX_IO_DELAY)
            prev_io_error.delay *= 2;
      } else {
         /* Init delay */
         prev_io_error.delay = (random() % (MAX_INIT_IO_DELAY-1)) + 2;
      }
      prev_io_error.timestamp = now;

      atomic_inc(&nioerr);
      return -EIO;
   }


   /**
    * Redirected to pread into cache.
    */
   static int cvmfs_read(const char *path,
                         char *buf,
                         size_t size,
                         off_t offset,
                         struct fuse_file_info *fi)
   {
      Tracer::trace(Tracer::FUSE_READ, path, "read() call");

      const int64_t fd = fi->fh;
      return pread(fd, buf, size, offset);
   }


   /**
    * File close operation. Redirected into cache.
    */
   static int cvmfs_release(const char *path __attribute__((unused)), struct fuse_file_info *fi)
   {
      pmesg(D_CVMFS, "closeing file number %d", fi->fh);

      const int64_t fd = fi->fh;
      if (close(fd) == 0) atomic_dec(&open_files);

      return 0;
   }



   /**
    * Emulates the getattr walk done by Fuse
    */
   static int walk_path(const string &path) {
      struct stat info;
      if ((path == "") || (path == "/"))
         return cvmfs_getattr("/", &info);

      int attr_result = walk_path(get_parent_path(path));
      if (attr_result == 0)
         return cvmfs_getattr(path.c_str(), &info);

      return attr_result;
   }


   /**
    * Removes a file from local cache
    */
   int clear_file(const string &path) {
      int attr_result = walk_path(path);
      if (attr_result != 0)
         return attr_result;

      const hash::t_md5 md5(catalog::mangled_path(path));
      int result;

      catalog::lock();

      catalog::t_dirent d;
      if (catalog::lookup_informed_unprotected(md5, find_catalog_id(path), d)) {
         if ((!(d.flags & catalog::FILE)) || (d.flags & catalog::FILE_LINK)) {
            result = -EINVAL;
         } else {
            lru::remove(d.checksum);
            result = 0;
         }
      } else {
         result = -ENOENT;
      }

      catalog::unlock();

      return result;
   }


   static int cvmfs_statfs(const char *path __attribute__((unused)), struct statvfs *info)
   {
      /* If we return 0 it will cause the fs
         to be ignored in "df" */
      memset(info, 0, sizeof(*info));

      /* Unmanaged cache */
      if (lru::capacity() == 0)
         return 0;

      uint64_t available = 0;
      uint64_t size = lru::size();

      info->f_bsize = 1;

      if (lru::capacity() == (uint64_t)(-1)) {
         /* Unrestricted cache, look at free space on cache dir fs */
         struct statfs cache_buf;
         if (statfs(".", &cache_buf) == 0) {
            available = cache_buf.f_bavail * cache_buf.f_bsize;
            info->f_blocks = size + available;
         } else {
            info->f_blocks = size;
         }
      } else {
         /* Take values from LRU module */
         info->f_blocks = lru::capacity();
         available = lru::capacity() - size;
      }

      //info->f_blocks = 50000000000L;
      //available = 20000000000L;

      info->f_bfree = info->f_bavail = available;

      return 0;
   }


   static int fill_xattr(const string src, char *dst, const size_t ldst) {
      size_t lsrc = src.length();

      if (!dst)
         return lsrc;

      if (src.length() > ldst)
         return -ERANGE;

      memcpy(dst, &src[0], lsrc);
      return lsrc;
   }

   static int cvmfs_getxattr(const char *path, const char *name, char *value, size_t vlen) {
      const string attr = name;
      catalog::t_dirent d;
      hash::t_md5 md5(catalog::mangled_path(path));

      pmesg(D_CVMFS, "getxattr %s on %s", name, path);

      catalog::lock();
      if (!catalog::lookup_informed_unprotected(md5, find_catalog_id(path), d)) {
         catalog::unlock();
         return -ENOENT;
      }
      catalog::unlock();

      if (attr == "user.pid") {
         ostringstream result;
         result << cvmfs::pid;
         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.version") {
         const string result = string(VERSION) + "." + string(CVMFS_PATCH_LEVEL);
         return fill_xattr(result, value, vlen);
      } else if (attr == "user.hash") {
         if (d.checksum != hash::t_sha1()) {
            const string result = d.checksum.to_string() + " (SHA-1)";
            return fill_xattr(result, value, vlen);
         }
         return -ENOATTR;
      } else if (attr == "user.lhash") {
         if (d.checksum != hash::t_sha1()) {
            string result;
            int fd = cache::open(d.checksum);
            if (fd < 0)
               return fill_xattr("Not in cache", value, vlen);

            hash::t_sha1 hash;
            FILE *f = fdopen(fd, "r");
            if (!f)
               return -EIO;

            if (compress_file_sha1_only(f, hash.digest) != 0) {
               fclose(f);
               return -EIO;
            }
            fclose(f);
            return fill_xattr(hash.to_string() + " (SHA-1)", value, vlen);
         }
         return -ENOATTR;
      } else if (attr == "user.revision") {
         catalog::lock();
         const uint64_t revision = catalog::get_revision();
         catalog::unlock();

         ostringstream result;
         result << revision;
         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.expires") {
         catalog::lock();
         int catalog_id = find_catalog_id(path);
         time_t expires = catalog_tree::get_catalog(catalog_id)->expires;
         catalog::unlock();

         time_t now = time(NULL);
         ostringstream result;
         result << (expires-now)/60;
         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.maxfd") {
         ostringstream result;
         result << nofiles-NUM_RESERVED_FD;
         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.usedfd") {
         ostringstream result;
         result << atomic_read(&open_files);
         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.nioerr") {
         ostringstream result;
         result << atomic_read(&nioerr);
         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.proxy") {
         int num;
         int num_lb;
         char *current;
         int current_lb;
         char **proxies;
         int *lb_starts;
         curl_get_proxy_info(&num, &current, &current_lb, &proxies, &num_lb, &lb_starts);
         string proxy;
         if (num) {
            proxy = string(current);
            for (int i = 0; i < num; ++i) {
               free(proxies[i]);
            }
            free(lb_starts);
            free(proxies);
            free(current);
         } else {
            proxy = "DIRECT";
         }

         return fill_xattr(proxy, value, vlen);
      } else if (attr == "user.host") {
         int num;
         int current;
         char **all_hosts;
         int *rtt;
         curl_get_host_info(&num, &current, &all_hosts, &rtt);
         const string host = string(all_hosts[current]);
         free(rtt);
         free(all_hosts);

         return fill_xattr(host, value, vlen);
      } else if (attr == "user.uptime") {
         time_t now = time(NULL);
         uint64_t uptime = now - boot_time;
         ostringstream result;
         /*if (uptime / 60) {
            if (uptime / 3600) {
               if (uptime / 84600) {
                  result << uptime/84600 << " days, ";
               }
               result << (uptime / 3600)%24 << " hours, ";
            }
            result << (uptime / 60)%60 << " minutes, ";
         }*/
         result << uptime / 60;

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.nclg") {
         catalog::lock();
         int num = catalog::get_num_catalogs();
         catalog::unlock();
         ostringstream result;
         result << num;

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.nopen") {
         ostringstream result;
         result << atomic_read64(&nopen);

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.ndownload") {
         ostringstream result;
         result << atomic_read64(&ndownload);

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.timeout") {
         unsigned seconds, seconds_direct;
         curl_get_timeout(&seconds, &seconds_direct);
         ostringstream result;
         result << seconds;

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.timeout_direct") {
         unsigned seconds, seconds_direct;
         curl_get_timeout(&seconds, &seconds_direct);
         ostringstream result;
         result << seconds_direct;

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.rx") {
         int64_t rx = curl_get_allbytes();
         ostringstream result;
         result << rx/1024;

         return fill_xattr(result.str(), value, vlen);
      } else if (attr == "user.speed") {
         int64_t rx = curl_get_allbytes();
         int64_t time = curl_get_alltime();
         ostringstream result;
         if (time == 0)
            result << "n/a";
         else
            result << (rx/1024)/time;

         return fill_xattr(result.str(), value, vlen);
      }

      return -ENOATTR;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_chmod(const char *path __attribute__((unused)),
                          mode_t mode __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_mkdir(const char *path __attribute__((unused)),
                          mode_t mode __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_unlink(const char *path __attribute__((unused))) {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_rmdir(const char *path __attribute__((unused))) {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_symlink(const char *from __attribute__((unused)),
                            const char *to __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_rename(const char *from __attribute__((unused)),
                           const char *to __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_link(const char *from __attribute__((unused)),
                         const char *to __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_chown(const char *path __attribute__((unused)),
                          uid_t uid __attribute__((unused)),
                          gid_t gid __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_truncate(const char *path __attribute__((unused)),
                             off_t size __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_utime(const char *path __attribute__((unused)),
                          struct utimbuf *buf __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_write(const char *path __attribute__((unused)),
                          const char *buf __attribute__((unused)),
                          size_t size __attribute__((unused)),
                          off_t offset __attribute__((unused)),
                          struct fuse_file_info *fi __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * \return -EROFS
    */
   static int cvmfs_mknod(const char *path __attribute__((unused)),
                          mode_t mode __attribute__((unused)),
                          dev_t rdev __attribute__((unused)))
   {
      return -EROFS;
   }


   /**
    * Do after-daemon() initialization
    */
   static void *cvmfs_init() {
      int retval;

      pid = getpid();

      /* Switch back to cache dir after daemon() */
      retval = chdir(cachedir.c_str());
      assert(retval == 0);

      monitor::spawn();

      /* Setup Tracer */
      if (tracefile != "") Tracer::init(8192, 7000, tracefile);
      else Tracer::init_null();

      lru::spawn();
      talk::spawn();

      max_cache_timeout = fuse_get_max_cache_timeout();

      return NULL;
   }

   static void cvmfs_destroy(void *unused __attribute__((unused))) {
      Tracer::fini();
   }

   /**
    * Puts the callback functions in one single structure
    */
   static void set_cvmfs_ops(struct fuse_operations *cvmfs_operations) {
      /* Implemented */
      cvmfs_operations->getattr	= cvmfs_getattr;
      cvmfs_operations->readlink	= cvmfs_readlink;
      cvmfs_operations->readdir	= cvmfs_readdir;
      cvmfs_operations->open	   = cvmfs_open;
      cvmfs_operations->read	   = cvmfs_read;
      cvmfs_operations->release 	= cvmfs_release;
      cvmfs_operations->chmod    = cvmfs_chmod;
      cvmfs_operations->statfs   = cvmfs_statfs;
      cvmfs_operations->getxattr = cvmfs_getxattr;

      /* Return EROFS (read-only filesystem) */
      cvmfs_operations->mkdir    = cvmfs_mkdir;
      cvmfs_operations->unlink   = cvmfs_unlink;
      cvmfs_operations->rmdir    = cvmfs_rmdir;
      cvmfs_operations->symlink	= cvmfs_symlink;
      cvmfs_operations->rename   = cvmfs_rename;
      cvmfs_operations->chown    = cvmfs_chown;
      cvmfs_operations->link	   = cvmfs_link;
      cvmfs_operations->truncate	= cvmfs_truncate;
      cvmfs_operations->utime    = cvmfs_utime;
      cvmfs_operations->write    = cvmfs_write;
      cvmfs_operations->mknod    = cvmfs_mknod;
      cvmfs_operations->chmod    = cvmfs_chmod;

      /* Init/Fini */
      cvmfs_operations->init     = cvmfs_init;
      cvmfs_operations->destroy  = cvmfs_destroy;
   }

} /* namespace cvmfs */



using namespace cvmfs;

/**
 * One single structure to contain the file system options.
 * Strings(char *) must be deallocated by the user
 */
struct cvmfs_opts {
   unsigned timeout;
   unsigned timeout_direct;
   unsigned max_ttl;
   char     *hostname;
   char     *cachedir;
   char     *proxies;
   char     *tracefile;
   char     *whitelist;
   char     *pubkey;
   char     *logfile;
   char     *deep_mount;
   char     *blacklist;
   char     *repo_name;
   int      force_signing;
   int      rebuild_cachedb;
   int      nofiles;
   int      grab_mountpoint;
   int      syslog_level;
   int64_t  quota_limit;
   int64_t  quota_threshold;
};

/* Follow the fuse convention for option parsing */
enum {
   KEY_HELP,
   KEY_VERSION,
   KEY_FOREGROUND,
   KEY_SINGLETHREAD,
   KEY_DEBUG,
};
#define CVMFS_OPT(t, p, v) { t, offsetof(struct cvmfs_opts, p), v }
#define CVMFS_SWITCH(t, p) { t, offsetof(struct cvmfs_opts, p), 1 }
static struct fuse_opt cvmfs_array_opts[] = {
   CVMFS_OPT("timeout=%u",          timeout, 2),
   CVMFS_OPT("timeout_direct=%u",   timeout_direct, 2),
   CVMFS_OPT("max_ttl=%u",          max_ttl, 0),
   CVMFS_OPT("cachedir=%s",         cachedir, 0),
   CVMFS_OPT("proxies=%s",          proxies, 0),
   CVMFS_OPT("tracefile=%s",        tracefile, 0),
   CVMFS_SWITCH("force_signing",    force_signing),
   CVMFS_OPT("whitelist=%s",        whitelist, 0),
   CVMFS_OPT("pubkey=%s",           pubkey, 0),
   CVMFS_OPT("logfile=%s",          logfile, 0),
   CVMFS_SWITCH("rebuild_cachedb",  rebuild_cachedb),
   CVMFS_OPT("quota_limit=%ld",     quota_limit, 0),
   CVMFS_OPT("quota_threshold=%ld", quota_threshold, 0),
   CVMFS_OPT("nofiles=%d",          nofiles, 0),
   CVMFS_SWITCH("grab_mountpoint",  grab_mountpoint),
   CVMFS_OPT("deep_mount=%s",       deep_mount, 0),
   CVMFS_OPT("repo_name=%s",        repo_name, 0),
   CVMFS_OPT("blacklist=%s",        blacklist, 0),
   CVMFS_OPT("syslog_level=%d",     syslog_level, 3),

   FUSE_OPT_KEY("-V",            KEY_VERSION),
   FUSE_OPT_KEY("--version",     KEY_VERSION),
   FUSE_OPT_KEY("-h",            KEY_HELP),
   FUSE_OPT_KEY("--help",        KEY_HELP),
   FUSE_OPT_KEY("-f",            KEY_FOREGROUND),
   FUSE_OPT_KEY("-d",            KEY_DEBUG),
   FUSE_OPT_KEY("debug",         KEY_DEBUG),
   FUSE_OPT_KEY("-s",            KEY_SINGLETHREAD),
   {0, 0, 0},
};


struct cvmfs_opts cvmfs_opts;
struct fuse_args fuse_args;
static struct fuse_operations cvmfs_operations;


/**
 * Display the usage message.
 * It will be done when we requested (the flag "-h" for example),
 * but also when an unidentified option is found.
 */
static void usage(const char *progname) {
   fprintf(stderr,
   "Copyright (c) 2009- CERN\n"
   "All rights reserved\n\n"
   "Please visit http://cernvm.cern.ch/project/info for license details and author list.\n\n");

   if (progname)
      fprintf(stderr,
      "usage: %s <mountpath> <url>[,<url>]* [options]\n\n", progname);

   fprintf(stderr,
      "where options are:\n"
      " -o opt,[opt...]  mount options\n\n"
      "CernVM-FS options: \n"
      " -o timeout=SECONDS         Timeout for network operations (default is %d)\n"
      " -o timeout_direct=SECONDS  Timeout for network operations without proxy (default is %d)\n"
      " -o max_ttl=MINUTES         Maximum TTL for file catalogs (default: take from catalog)\n"
      " -o cachedir=DIR            Where to store disk cache\n"
      " -o proxies=HTTP_PROXIES    Set the HTTP proxy list, such as 'proxy1|proxy2;DIRECT'\n"
      " -o tracefile=FILE          Trace FUSE opaerations into FILE\n"
      " -o whitelist=URL           HTTP location of trusted catalog certificates (defaults is /.cvmfswhitelist)\n"
      " -o pubkey=PEMFILE          Public RSA key that is used to verify the whitelist signature.\n"
      " -o force_signing           Except only signed catalogs\n"
      " -o rebuild_cachedb         Force rebuilding the quota cache db from cache directory\n"
      " -o quota_limit=MB          Limit size of data chunks in cache. -1 Means unlimited.\n"
      " -o quota_threshold=MB      Cleanup until size is <= threshold\n"
      " -o nofiles=NUMBER          Set the maximum number of open files for CernVM-FS process (soft limit)\n"
      " -o grab_mountpoint         Give ownership of the mountpoint to the user before mounting (automount hack)\n"
      " -o logfile=FILE            Logs all messages to FILE instead of stderr and daemonizes.\n"
      "                            Makes only sense for the debug version\n"
      " -o deep_mount=prefix       Path prefix if a repository is mounted on a nested catalog,\n"
      "                            i.e. deep_mount=/software/15.0.1\n"
      " -o repo_name=<repository>  Unique name of the mounted repository, e.g. atlas.cern.ch\n"
      " -o blacklist=FILE          Local blacklist for invalid certificates.  Has precedence over the whitelist.\n"
      "                            (Default is /etc/cvmfs/blacklist)\n"
      " -o syslog_level=NUMBER     Sets the level used for syslog to DEBUG (1), INFO (2), or NOTICE (3).\n"
      "                            Default is NOTICE.\n"
      " Note: you cannot load files greater than quota_limit-quota_threshold\n",
      2, 2
   );

   /* Print the help from FUSE */
   const char *args[] = {progname, "-h"};
   static struct fuse_operations op;
   fuse_main(2, (char**)args, &op);
}


/**
 * Since certain fileds in cvmfs_opts are filled automatically when parsing it, \
 * we needed a procedure to free the space.
 */
static void free_cvmfs_opts(struct cvmfs_opts *opts) {
   if (opts->hostname)       free(opts->hostname);
   if (opts->cachedir)       free(opts->cachedir);
   if (opts->proxies)        free(opts->proxies);
   if (opts->tracefile)      free(opts->tracefile);
   if (opts->whitelist)      free(opts->whitelist);
   if (opts->pubkey)         free(opts->pubkey);
   if (opts->logfile)        free(opts->logfile);
   if (opts->deep_mount)     free(opts->deep_mount);
   if (opts->blacklist)      free(opts->blacklist);
   if (opts->repo_name)      free(opts->repo_name);
}


/**
 * Checks whether the given option is one of our own options
 * (if it's not, it probably belongs to fuse).
 */
static int is_cvmfs_opt(const char *arg) {
   if (arg[0] != '-') {
      unsigned arglen = strlen(arg);
      const char **o;
      for (o = (const char**)cvmfs_array_opts; *o; o++) {
         unsigned olen = strlen(*o);
         if ((arglen > olen && arg[olen] == '=') && (strncasecmp(arg, *o, olen) == 0))
            return 1;
      }
   }
   return 0;
}


/**
 * The callback used when fuse is parsing all the options
 * We separate CVMFS options from FUSE options here.
 *
 * \return On success zero, else non-zero
 */
static int cvmfs_opt_proc(void *data __attribute__((unused)), const char *arg, int key,
                          struct fuse_args *outargs)
{
   switch (key) {
      case FUSE_OPT_KEY_OPT:
         if (is_cvmfs_opt(arg)) {
            /* If this is a "-o" option and is not one of ours, we assume that this must
               be used when mounting fuse not when instanciating the file system...
               It can't be one of our option if it doesnt match the template */
            return 0;
         }
         if (strstr(arg, "uid=")) {
            cvmfs::uid = atoi(arg+4);
         }
         if (strstr(arg, "gid=")) {
            cvmfs::gid = atoi(arg+4);
         }
         return 1;

      case FUSE_OPT_KEY_NONOPT:
         if (!cvmfs_opts.hostname &&
             ((strstr(arg, "http://") == arg) || (strstr(arg, "file://") == arg)))
         {
            /* If we receive a parameter that contains "http://"
               we know for sure that it's our remote server */
            cvmfs_opts.hostname = strdup(arg);
         } else {
            /* If we receive any other string, we take it as the mount point. */
            fuse_opt_add_arg(outargs, arg);
            cvmfs::mountpoint = arg;
         }
         return 0;

      case KEY_HELP:
         usage(outargs->argv[0]);
         fuse_opt_add_arg(outargs, "-ho");
         exit(0);

      case KEY_VERSION:
         fprintf(stderr, "CernVM-FS version %s\n", PACKAGE_VERSION);
#if FUSE_VERSION >= 25
         fuse_opt_add_arg(outargs, "--version");
#endif
         exit(0);

      case KEY_FOREGROUND:
         fuse_opt_add_arg(outargs, "-f");
         return 0;

      case KEY_SINGLETHREAD:
         fuse_opt_add_arg(outargs, "-s");
         return 0;

      case KEY_DEBUG:
         fuse_opt_add_arg(outargs, "-d");
         return 0;

      default:
         fprintf(stderr, "internal error\n");
         abort();
   }
}


/* Making OpenSSL (libcrypto) thread-safe */
pthread_mutex_t *libcrypto_locks;

static void libcrypto_lock_callback(int mode, int type, const char *file, int line) {
  (void)file;
  (void)line;

  int retval;

  if (mode & CRYPTO_LOCK) {
    retval = pthread_mutex_lock(&(libcrypto_locks[type]));
  } else {
    retval = pthread_mutex_unlock(&(libcrypto_locks[type]));
  }
  assert(retval == 0);
}

static unsigned long libcrypto_thread_id()
{
   return (unsigned long)pthread_self();
}

static void libcrypto_mt_setup() {
   libcrypto_locks = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
   for (int i = 0; i < CRYPTO_num_locks(); ++i) {
      int retval = pthread_mutex_init(&(libcrypto_locks[i]), NULL);
      assert(retval == 0);
   }

   CRYPTO_set_id_callback(libcrypto_thread_id);
   CRYPTO_set_locking_callback(libcrypto_lock_callback);
}

static void libcrypto_mt_cleanup(void) {
   CRYPTO_set_locking_callback(NULL);
   for (int i = 0; i < CRYPTO_num_locks(); ++i)
      pthread_mutex_destroy(&(libcrypto_locks[i]));

   OPENSSL_free(libcrypto_locks);
}


/**
 * Boot the beast up!
 */
int main(int argc, char *argv[])
{
   int result = 1;
   bool options_ready = false;
   bool curl_ready = false;
   bool cache_ready = false;
   bool monitor_ready = false;
   bool signature_ready = false;
   bool quota_ready = false;
   bool catalog_ready = false;
   bool talk_ready = false;
   bool running_created = false;
   int err_catalog;
   int num_hosts;
   int fd_lockfile = -1;
   int retval;

   /* Set a decent umask for new files (no write access to group/everyone).
      We want to allow group write access for the talk-socket. */
   umask(007);

   boot_time = time(NULL);
   prev_io_error.timestamp = 0;
   prev_io_error.delay = 0;

   libcrypto_mt_setup();

   /* Tune SQlite3 memory */
   void *sqlite_scratch = smalloc(8192*16); /* 8 KB for 8 threads (2 slots per thread) */
   void *sqlite_page_cache = smalloc(1280*3275); /* 4MB */
   assert(sqlite3_config(SQLITE_CONFIG_SCRATCH, sqlite_scratch, 8192, 16) == SQLITE_OK);
   assert(sqlite3_config(SQLITE_CONFIG_PAGECACHE, sqlite_page_cache, 1280, 3275) == SQLITE_OK);
   assert(sqlite3_config(SQLITE_CONFIG_LOOKASIDE, 32, 128) == SQLITE_OK); /* 4 KB */

   /* Catalog memory cache */
   for (int i = 0; i < CATALOG_CACHE_SIZE; ++i) {
      catalog_cache[i].md5 = hash::t_md5();
   }
   atomic_init(&cache_inserts);
   atomic_init(&cache_replaces);
   atomic_init(&cache_cleans);
   atomic_init(&cache_hits);
   atomic_init(&cache_misses);

   atomic_init(&certificate_hits);
   atomic_init(&certificate_misses);

   atomic_init64(&nopen);
   atomic_init64(&ndownload);

   /* Parse options */
   fuse_args.argc = argc;
   fuse_args.argv = argv;
   fuse_args.allocated = 0;
   if ((fuse_opt_parse(&fuse_args, &cvmfs_opts, cvmfs_array_opts, cvmfs_opt_proc) != 0) ||
       !cvmfs_opts.hostname)
   {
      usage(argv[0]);
      goto cvmfs_cleanup;
   }

   /* Fill cvmfs option variables from Fuse options */
   if (!cvmfs::uid) cvmfs::uid = getuid();
   if (!cvmfs::gid) cvmfs::gid = getgid();
   if (cvmfs_opts.max_ttl) cvmfs::max_ttl = cvmfs_opts.max_ttl*60;
   if (cvmfs_opts.cachedir) cvmfs::cachedir = cvmfs_opts.cachedir;
   if (cvmfs_opts.proxies) cvmfs::proxies = cvmfs_opts.proxies;
   if (cvmfs_opts.force_signing) cvmfs::force_signing = true;
   if (cvmfs_opts.timeout == 0) cvmfs_opts.timeout = 2;
   if (cvmfs_opts.timeout_direct == 0) cvmfs_opts.timeout_direct = 2;
   if (cvmfs_opts.syslog_level == 0) cvmfs_opts.syslog_level = 3;
   if (cvmfs_opts.tracefile) cvmfs::tracefile = cvmfs_opts.tracefile;
   if (cvmfs_opts.deep_mount) cvmfs::deep_mount = canonical_path(cvmfs_opts.deep_mount);
   if (cvmfs_opts.blacklist) cvmfs::blacklist = cvmfs_opts.blacklist;
   if (cvmfs_opts.repo_name) cvmfs::repo_name = cvmfs_opts.repo_name;
   /* seperate first host from hostlist */
   unsigned iter_hostname;
   for (iter_hostname = 0; iter_hostname < strlen(cvmfs_opts.hostname); ++iter_hostname) {
      if (cvmfs_opts.hostname[iter_hostname] == ',') break;
   }
   if (iter_hostname == 0) cvmfs::root_url = "";
   else cvmfs::root_url = string(cvmfs_opts.hostname, iter_hostname);

   if (cvmfs_opts.whitelist) cvmfs::whitelist = cvmfs_opts.whitelist;
   else cvmfs::whitelist = "/.cvmfswhitelist";
   options_ready = true;

   /* Syslog level */
   syslog_setlevel(cvmfs_opts.syslog_level);
   if (cvmfs::repo_name != "")
      syslog_setprefix(cvmfs::repo_name.c_str());

   /* Maximum number of open files */
   if (cvmfs_opts.nofiles) {
      if (cvmfs_opts.nofiles < 0) {
         cerr << "Failure: number of open files must be a positive number" << endl;
         goto cvmfs_cleanup;
      }
      struct rlimit rpl;
      memset(&rpl, 0, sizeof(rpl));
      getrlimit(RLIMIT_NOFILE, &rpl);
      if (rpl.rlim_max < (unsigned)cvmfs_opts.nofiles)
         rpl.rlim_max = cvmfs_opts.nofiles;
      rpl.rlim_cur = cvmfs_opts.nofiles;
      if (setrlimit(RLIMIT_NOFILE, &rpl) != 0) {
         cerr << "Failed to set maximum number of open files, insufficient permissions" << endl;
         goto cvmfs_cleanup;
      }
   }

   /* Grab mountpoint */
   if (cvmfs_opts.grab_mountpoint) {
      if ((chown(cvmfs::mountpoint.c_str(), uid, gid) != 0) ||
          (chmod(cvmfs::mountpoint.c_str(), 0755) != 0))
      {
         cerr << "Failed to grab mountpoint (" << errno << ")" << endl;
         goto cvmfs_cleanup;
      }
   }

   /* Set debug log file */
   if (cvmfs_opts.logfile) {
      debug_set_log(cvmfs_opts.logfile);
   }

   /* Drop rights */
   if ((cvmfs::uid != 0) || (cvmfs::gid != 0)) {
      cout << "CernVM-FS: running with credentials " << cvmfs::uid << ":" << cvmfs::gid << endl;
      if ((setgid(cvmfs::gid) != 0) || (setuid(cvmfs::uid) != 0)) {
         cerr << "Failed to drop credentials" << endl;
         goto cvmfs_cleanup;
      }
   }

   /* CVMFS has its own proxy environment, chain of proxies */
   num_hosts = curl_set_host_chain(cvmfs_opts.hostname);
   curl_set_proxy_chain(cvmfs::proxies.c_str());
   curl_set_timeout(cvmfs_opts.timeout, cvmfs_opts.timeout_direct);


   /* Try to jump to cache directory.  This tests, if it is accassible.  Also, it brings speed later on. */
   if (!mkdir_deep(cvmfs::cachedir, 0700) || (chdir(cvmfs::cachedir.c_str()) != 0)) {
      cerr << "Failure: cache directory " << cvmfs::cachedir << " is unavailable" << endl;
      goto cvmfs_cleanup;
   }

   curl_ready = true;

   // Create lock file
   fd_lockfile = open("lock", O_RDONLY | O_CREAT, 0600);
   if (fd_lockfile < 0) {
      cerr << "Failure: could not open lock file (" << errno << ")" << endl;
      goto cvmfs_cleanup;
   }
   if (flock(fd_lockfile, LOCK_EX) != 0) {
      cerr << "Failure: could not acquire lock (" << errno << ")" << endl;
      goto cvmfs_cleanup;
   }
   {
      struct stat info;
      if (stat("running", &info) == 0) {
         logmsg("Looks like cvmfs has been crashed previously, rebuilding cache database");
         cvmfs_opts.rebuild_cachedb = 1;
      }
   }
   retval = open("running", O_RDONLY | O_CREAT, 0600);
   if (retval < 0) {
      cerr << "Failure: could not acquire running sentinel (" << errno << ")" << endl;
      goto cvmfs_cleanup;
   }
   close(retval);
   running_created = true;

   /* Try to init the cache... this creates a set of directories in
      cvmfs::cachedir (256 directories named 00..ff) */
   if (!cache::init(".", cvmfs::root_url, &mutex_download)) {
      cerr << "Failed to setup cache in " << cvmfs::cachedir << ": " << strerror(errno) << endl;
      logmsg("failed to setup cache directory %s", cvmfs::cachedir.c_str());
      goto cvmfs_cleanup;
   }
   cache_ready = true;

   /* Monitor, check for maximum number of open files */
   if (!monitor::init(".", true)) {
      cerr << "Failed to initialize watchdog." << endl;
      goto cvmfs_cleanup;
   }
   nofiles = monitor::get_nofiles();
   atomic_init(&cvmfs::open_files);
   atomic_init(&cvmfs::nioerr);
   monitor_ready = true;

   signature::init();
   if (!signature::load_public_keys(cvmfs_opts.pubkey ? cvmfs_opts.pubkey : "")) {
      cout << "Failed to load public key(s)" << endl;
      goto cvmfs_cleanup;
   } else {
      if (!cvmfs_opts.pubkey)
         cout << "Warning: No public master key given. Cvmfs will fail on signed catalogs!" << endl;
      else
         cout << "CernVM-FS: using public key(s) "
              << join_strings(split_string(cvmfs_opts.pubkey, ':'), ", ") << endl;
   }
   signature_ready = true;

   /* Init quota / lru cache */
   if (cvmfs_opts.quota_limit < 0) {
      pmesg(D_CVMFS, "unlimited cache size");
      cvmfs_opts.quota_limit = -1;
      cvmfs_opts.quota_threshold = 0;
   } else {
      cvmfs_opts.quota_limit *= 1024*1024;
      cvmfs_opts.quota_threshold *= 1024*1024;
   }
   if (!lru::init(".", (uint64_t)cvmfs_opts.quota_limit,
                       (uint64_t)cvmfs_opts.quota_threshold,
                       cvmfs_opts.rebuild_cachedb))
   {
      cerr << "Failed to initialize lru cache" << endl;
      goto cvmfs_cleanup;
   }
   quota_ready = true;

   if (cvmfs_opts.rebuild_cachedb) {
      cout << "CernVM-FS: rebuilding lru cache database..." << endl;
      if (!lru::build()) {
         cerr << "Failed to rebuild lru cache database" << endl;
         goto cvmfs_cleanup;
      }
   }
   if (lru::size() > lru::capacity()) {
      cout << "Warning: your cache is already beyond quota size, cleaning up" << endl;
      if (!lru::cleanup(cvmfs_opts.quota_threshold)) {
         cerr << "Failed to clean up" << endl;
         goto cvmfs_cleanup;
      }
   }
   if (cvmfs_opts.quota_limit) {
      cout << "CernVM-FS: quota initialized, current size " << lru::size()/(1024*1024)
           << "MB" << endl;
   }

   /* Create the file catalog from the web server */
   if (!catalog::init(cvmfs::uid, cvmfs::gid)) {
      cerr << "Failed to initialize catalog" << endl;
      goto cvmfs_cleanup;
   }
   err_catalog = load_and_attach_catalog(cvmfs::root_catalog, hash::t_md5(cvmfs::deep_mount), "/", -1, false);
   pmesg(D_CVMFS, "initial catalog load results in %d", err_catalog);
   if (err_catalog == -EIO) {
      cerr << "Failed to load catalog (IO error)" << endl;
      goto cvmfs_cleanup;
   }
   if (err_catalog == -EPERM) {
      cerr << "Failed to verify catalog signature" << endl;
      goto cvmfs_cleanup;
   }
   if ((err_catalog == -EINVAL) || (err_catalog == -EAGAIN)) {
      cerr << "Failed to load catalog (corrupted data)" << endl;
      goto cvmfs_cleanup;
   }
   if (err_catalog == -ENOSPC) {
      cerr << "Failed to load catalog (no space in cache)" << endl;
      goto cvmfs_cleanup;
   }
   catalog_ready = true;

   if (!talk::init(".")) {
      cerr << "Failed to initialize talk socket (" << errno << ")" << endl;
      goto cvmfs_cleanup;
   }
   talk_ready = true;

   /* Set fuse callbacks, remove url from arguments */
   cout << "CernVM-FS: mounted cvmfs on " << cvmfs::mountpoint << endl;
   cout << "CernVM-FS: linking to remote directory " << cvmfs::root_url << endl;
   logmsg("CernVM-FS: linking %s to remote directory %s", cvmfs::mountpoint.c_str(), cvmfs::root_url.c_str());
   set_cvmfs_ops(&cvmfs_operations);
   result = fuse_main(fuse_args.argc, fuse_args.argv, &cvmfs_operations);

   pmesg(D_CVMFS, "Fuse loop terminated (%d)", result);
   logmsg("CernVM-FS: unmounted %s (%s)", cvmfs::mountpoint.c_str(), cvmfs::root_url.c_str());

cvmfs_cleanup:
   if (talk_ready) talk::fini();
   if (catalog_ready) catalog::fini();
   if (quota_ready) lru::fini();
   if (signature_ready) signature::fini();
   if (cache_ready) cache::fini();
   if (running_created) unlink("running");
   if (fd_lockfile >= 0) {
      int retval = flock(fd_lockfile, LOCK_UN);
      assert(retval == 0);
      close(fd_lockfile);
   }
   if (monitor_ready) monitor::fini();
   if (options_ready) {
      fuse_opt_free_args(&fuse_args);
      free_cvmfs_opts(&cvmfs_opts);
   }

   free(sqlite_page_cache);
   free(sqlite_scratch);

   libcrypto_mt_cleanup();

   return result;
}
