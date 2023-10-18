#include "pcapng_blocks.h"

#include <dirent.h>
#include <sys/prctl.h>        // prctl(), PR_SET_*
#include <sys/resource.h>     // setpriority(), PRIO_PROCESS
#include <sys/socket.h>       // socket()
#include <sys/stat.h>         // umask()
#include <sys/syscall.h>      // syscall(), SYS_gettid

bool OpenOrCreateFolder(const std::string& folderPath) {
  DIR* dir = opendir(folderPath.c_str());

  if (dir) {
    // Folder already exists
    closedir(dir);
    return true;
  }

  // Folder does not exist, create a new one
  int status = mkdir(folderPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  return status == 0;
}

bool isFilePcap(std::string s) {
  int n = s.length();
  if (n < 5) return false;
  if (s[n-5] != '.') return false;
  if (s[n-4] != 'p') return false;
  if (s[n-3] != 'c') return false;
  if (s[n-2] != 'a') return false;
  if (s[n-1] != 'p') return false;
  return true;
}

