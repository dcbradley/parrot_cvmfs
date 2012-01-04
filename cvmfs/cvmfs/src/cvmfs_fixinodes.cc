
#include <iostream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <stdint.h>

#include "catalog.h"
#include "util.h"
#include "hash.h"

using namespace std;

static void usage() {
   cout << "This tool adjusts the catalog inodes to the inodes from the shadow tree." << endl;
   cout << "Usage: cvmfs_fixinodes <catalog> <shadow tree>" << endl;
}


string shadow_dir;
uint64_t ntotal = 0;
uint64_t nfixed = 0;

static void recursive_ls(const hash::t_md5 dir, const string path) {
   vector<catalog::t_dirent> entries;
   
   entries = catalog::ls_unprotected(dir);
      
   for (unsigned i = 0; i < entries.size(); ++i) {
      const string full_path = path + "/" + entries[i].name;
      
      struct stat64 info;
      if (lstat64((shadow_dir + full_path).c_str(), &info) != 0) {
         cerr << "Warning, " << full_path << " not in shadow tree" << endl;
         continue;
      }
      
      //cout << full_path << " catino: " << entries[i].inode << " fs ino " << info.st_ino << endl;
      if ((entries[i].inode != info.st_ino) || (entries[i].mtime != info.st_mtime)) {
         entries[i].inode = info.st_ino;
         entries[i].mtime = info.st_mtime;
         hash::t_md5 md5(full_path);
         if (!catalog::update_unprotected(md5, entries[i])) {
            cerr << "Warning, failed to fix " << full_path << endl;
         } else {
            nfixed++;
         }
      }
      
      
      
      ntotal++;
      if ((ntotal % 1000) == 0)
         cout << "." << flush;
      
      if (entries[i].flags & catalog::DIR)
      {
         recursive_ls(hash::t_md5(full_path), full_path);
      }
   }
}


int main(int argc, char **argv) {
   if (argc < 3) {
      usage();
      return 1;
   }
   
   if (!catalog::init(0, 0) || !catalog::attach(argv[1], "", false, true)) {
      cerr << "could not load catalog" << endl;
      return 1;
   }
   
   shadow_dir = canonical_path(argv[2]);
   
   catalog::t_dirent result;
   hash::t_md5 root(catalog::mangled_path(""));
   if (!catalog::lookup(root, result)) {
      cerr << "could not find root entry in catalog." << endl;
      return 1;
   }
   
   struct stat64 info;
   if (stat64((shadow_dir + catalog::get_root_prefix()).c_str(), &info) != 0) {
      cerr << "Warning, shadow tree not available" << endl;
      return 1;
   }
   if (result.inode != info.st_ino) {
      result.inode = info.st_ino;
      if (!catalog::update_unprotected(root, result)) {
         cerr << "Warning, failed to fix root hash" << endl;
      } else {
         nfixed++;
      }
   }
   
   ntotal++;
   
   cout << "Fixing " << shadow_dir << catalog::get_root_prefix() << ": " << flush;
   recursive_ls(root, catalog::mangled_path(""));
   cout << endl;
   
   catalog::commit(0);
   
   cout << "Processed " << ntotal << " entries" << endl;
   cout << "Fixed " << nfixed << " entries" << endl;
   
   catalog::fini();

   return 0;
}
