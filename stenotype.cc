// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/***** stenotype *****
 *
 * stenotype is a mechanism for quickly dumping raw packets to disk.  It aims to
 * have a simple interface (no file rotation:  that's left as an exercise for
 * the reader) while being very powerful.
 *
 * stenotype uses a NIC->disk pipeline specifically designed to provide as fast
 * an output to disk as possible while just using the kernel's built-in
 *  mechanisms.
 *
 * 1) NIC -> RAM
 * stenotype uses MMAP'd AF_PACKET with 1MB blocks and a high timeout to offload
 * writing packets and deciding their layout to the kernel.  The kernel packs
 * all the packets it can into 1MB, then lets the userspace process know there's
 * a block available in the MMAP'd ring buffer.  Nicely, it guarantees no
 * overruns (packets crossing the 1MB boundary) and good alignment to memory
 * pages.
 *
 * 2) RAM -> Disk
 * Since the kernel already gave us a single 1MB block of packets that's nicely
 * aligned, we can O_DIRECT write it straight to disk.  This avoids any
 * additional copying or kernel buffering.  To keep sequential reads going
 * strong, we do all disk IO asynchronously via io_submit (which works
 * specifically for O_DIRECT files... joy!).  Since the data is being written to
 * disk asynchronously, we  use the time it's writing to disk to do our own
 * in-memory processing and indexing.
 *
 * There are N (flag-specified) async IO operations available... once we've used
 * up all N, we block on a used one finishing, then reuse it.
 * The whole pipeline consists of:
 *   - kernel gives userspace a 1MB block of packets
 *   - userspace iterates over packets in block, updates any indexes
 *   - userspace starts async IO operation to write block to disk
 *   - after N async IO operations are submitted, we synchronously wait for the
 *     least recent one to finish.
 *   - when an async IO operation finishes, we release the 1MB block back to the
 *     kernel to write more packets.
 */

#include <errno.h>            // errno
#include <fcntl.h>            // O_*
#include <grp.h>              // getgrnam()
#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <pcap.h>
#include <poll.h>             // POLLIN
#include <pthread.h>          // pthread_sigmask()
#include <pwd.h>              // getpwnam()
#include <sched.h>            // sched_setaffinity()
#include <seccomp.h>          // scmp_filter_ctx, seccomp_*(), SCMP_*
#include <signal.h>           // sigaction(), SIGINT, SIGTERM
#include <string.h>           // strerror()
#include <sys/prctl.h>        // prctl(), PR_SET_*
#include <sys/resource.h>     // setpriority(), PRIO_PROCESS
#include <sys/socket.h>       // socket()
#include <sys/stat.h>         // umask()
#include <sys/syscall.h>      // syscall(), SYS_gettid
#include <unistd.h>           // setuid(), setgid(), getpagesize()

#include <dirent.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <condition_variable>
#include <sys/inotify.h>
#include <unistd.h>
#include <vector>
#include <queue>

// Due to some weird interactions with <argp.h>, <string>, and --std=c++0x, this
// header MUST be included AFTER <string>.
#include <argp.h>  // argp_parse()

#include "aio.h"
#include "index.h"
#include "packets.h"
#include "util.h"
#include "pcapng_blocks.h"
#include "packet_shm.h"

namespace {

std::string flag_iface = "eth0";
std::string flag_filter = "";
std::string flag_dir = ""; // "/tmp/out"; //
std::string flag_pcap = "/tmp/in"; // ""; //
int64_t flag_count = -1;
int32_t flag_blocks = 2048;
int32_t flag_aiops = 128;
int64_t flag_filesize_mb = 4 << 10;
int32_t flag_threads = 1;
int64_t flag_fileage_sec = 60;
int64_t flag_blockage_sec = 10;
int64_t flag_stats_blocks = 100;
int64_t flag_stats_sec = 60;
uint64_t flag_blocksize_kb = 1024;
uint16_t flag_fanout_type =
// Use rollover as the default if it's available.
#ifdef PACKET_FANOUT_FLAG_ROLLOVER
    PACKET_FANOUT_LB | PACKET_FANOUT_FLAG_ROLLOVER;
#else
    PACKET_FANOUT_LB;
#endif

int64_t blocks_per_file = (flag_filesize_mb * 1024) / flag_blocksize_kb;
uint16_t flag_fanout_id = 0;
std::string flag_uid;
std::string flag_gid;
bool flag_index = true;
std::string flag_seccomp = "none";
int flag_index_nicelevel = 0;
int flag_preallocate_file_mb = 0;
bool flag_watchdogs = true;
bool flag_promisc = true;
std::string flag_testimony;

int ParseOptions(int key, char* arg, struct argp_state* state) {
  switch (key) {
    case 'v': st::logging_verbose_level++; break;
    case 'q': st::logging_verbose_level--; break;
    case 300: flag_iface = arg; break;
    case 301: flag_dir = arg; break;
    case 302: flag_count = atoi(arg); break;
    case 303: flag_blocks = atoi(arg); break;
    case 304: flag_aiops = atoi(arg); break;
    case 305: flag_filesize_mb = atoi(arg);
      blocks_per_file = (flag_filesize_mb * 1024) / flag_blocksize_kb; break;
    case 306: flag_threads = atoi(arg); break;
    case 307: flag_fileage_sec = atoi(arg); break;
    case 308: flag_fanout_type = atoi(arg); break;
    case 309: flag_fanout_id = atoi(arg); break;
    case 310: flag_uid = arg; break;
    case 311: flag_gid = arg; break;
    case 312: flag_index = false; break;
    case 313: flag_index_nicelevel = atoi(arg); break;
    case 314: flag_filter = arg; break;
    case 315: flag_seccomp = arg; break;
    case 316: flag_preallocate_file_mb = atoi(arg); break;
    case 317: flag_watchdogs = false; break;
    case 318: flag_testimony = arg; break;
    case 319: flag_blockage_sec = atoi(arg); break;
    case 320: flag_blocksize_kb = atoll(arg);
      blocks_per_file = (flag_filesize_mb * 1024) / flag_blocksize_kb; break;
    case 321: flag_promisc = false; break;
    case 322: flag_stats_blocks = atoi(arg); break;
    case 323: flag_stats_sec = atoi(arg); break;
    case 324: flag_pcap = arg; break;
  }
  return 0;
}

void ParseOptions(int argc, char** argv) {
  const char* s = "STRING";
  const char* n = "NUM";
  struct argp_option options[] = {
      {0, 'v', 0, 0, "Verbose logging, may be given multiple times"},
      {0, 'q', 0, 0, "Quiet logging.  Each -q counteracts one -v"},
      {"iface", 300, s, 0, "Interface to read packets from"},
      {"dir", 301, s, 0, "Directory to store packet files in"},
      {"dir_pcap", 324, s, 0, "Directory to read all pcap files"},
      {"count", 302, n, 0, "Total number of packets to read, -1 to read forever"},
      {"blocks", 303, n, 0, "Total number of blocks to use, each is 1MB"},
      {"aiops", 304, n, 0, "Max number of async IO operations"},
      {"filesize_mb", 305, n, 0, "Max file size in MB before file is rotated"},
      {"threads", 306, n, 0, "Number of parallel threads to read packets with"},
      {"fileage_sec", 307, n, 0, "Files older than this many secs are rotated"},
      {"fanout_type", 308, n, 0, "TPACKET_V3 fanout type to fanout packets"},
      {"fanout_id", 309, n, 0, "If fanning out across processes, set this"},
      {"uid", 310, n, 0, "Drop privileges to this user"},
      {"gid", 311, n, 0, "Drop privileges to this group"},
      {"no_index", 312, 0, 0, "Do not compute or write indexes"},
      {"index_nicelevel", 313, n, 0, "Nice level of indexing threads"},
      {"filter", 314, s, 0,
       "BPF compiled filter used to filter which packets "
       "will be captured. This has to be a compiled BPF in hexadecimal, which "
       "can be obtained from a human readable filter expression using the "
       "provided compile_bpf.sh script."},
      {"seccomp", 315, s, 0, "Seccomp style, one of 'none', 'trace', 'kill'."},
      {"preallocate_file_mb", 316, n, 0,
       "When creating new files, preallocate to this many MB"},
      {"no_watchdogs", 317, 0, 0, "Don't start any watchdogs"},
#ifdef TESTIMONY
      {"testimony", 318, n, 0, "Testimony socket to use"},
#else
      {"testimony", 318, n, 0, "TESTIMONY NOT COMPILED INTO THIS BINARY"},
#endif
      {"blockage_sec", 319, n, 0, "A block is written at least every N secs"},
      {"blocksize_kb", 320, n, 0, "Size of a block, in KB"},
      {"no_promisc", 321, 0, 0, "Don't set promiscuous mode"},
      {"stats_blocks", 322, n, 0, "Size block stats will be displayed, requires verbose, default 100, 0 disables"},
      {"stats_sec", 323, n, 0, "Seconds stats will be displayed, requires verbose, default 60, 0 disables"},
      {0},
  };
  struct argp argp = {options, &ParseOptions};
  argp_parse(&argp, argc, argv, 0, 0, 0);
}

}  // namespace

namespace st {

std::mutex file_iter_mutex;
std::mutex file_seeker_mutex;
std::mutex file_fetcher;
std::queue<std::string> fileQueue;
std::condition_variable conditionVar;

// These two synchronization mechanisms are used to coordinate when to
// chroot/chuid so it's after when the threads create their sockets but before
// they start writing files.
Notification main_complete;

void DropPrivileges() {
  LOG(INFO) << "Dropping privileges";
  if (getgid() == 0 || flag_gid != "") {
    if (flag_gid == "") {
      flag_gid = "nogroup";
    }
    LOG(INFO) << "Dropping privileges from " << getgid() << " to GID "
              << flag_gid;
    auto group = getgrnam(flag_gid.c_str());
    CHECK(group != NULL) << "Unable to get info for group " << flag_gid;
    CHECK_SUCCESS(Errno(setgid(group->gr_gid)));
  } else {
    VLOG(1) << "Staying with GID=" << getgid();
  }
  if (getuid() == 0 || flag_uid != "") {
    if (flag_uid == "") {
      flag_uid = "nobody";
    }
    LOG(INFO) << "Dropping privileges from " << getuid() << " to UID "
              << flag_uid;
    auto passwd = getpwnam(flag_uid.c_str());
    CHECK(passwd != NULL) << "Unable to get info for user " << flag_uid;
    flag_uid = std::to_string(passwd->pw_uid);
    CHECK_SUCCESS(Errno(initgroups(flag_uid.c_str(), getgid())));
    CHECK_SUCCESS(Errno(setuid(passwd->pw_uid)));
  } else {
    VLOG(1) << "Staying with UID=" << getuid();
  }
}

#define SECCOMP_RULE_ADD(...) \
  CHECK_SUCCESS(NegErrno(seccomp_rule_add(__VA_ARGS__)))

void CommonPrivileges(scmp_filter_ctx ctx) {
  // Very common operations, including sleeping, logging, and getting time.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  // Mutex and other synchronization.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0);
  // File operations.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fallocate), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
#ifdef __NR_fstat64
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 0);
#endif
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  // Signal handling and propagation to threads.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
  // Malloc/ringbuffer.
#ifdef __NR_mmap
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
#endif
#ifdef __NR_mmap2
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0);
#endif
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  // Malloc.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  // Exiting threads.
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
#ifdef __NR_sigreturn
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
#endif
}

scmp_filter_ctx kSkipSeccomp = scmp_filter_ctx(-1);

scmp_filter_ctx SeccompCtx() {
  if (flag_seccomp == "none") return kSkipSeccomp;
  if (flag_seccomp == "trace") return seccomp_init(SCMP_ACT_TRACE(1));
  if (flag_seccomp == "kill") return seccomp_init(SCMP_ACT_KILL);
  LOG(FATAL) << "invalid --seccomp flag: " << flag_seccomp;
  return NULL;  // unreachable
}

void DropCommonThreadPrivileges() {
  scmp_filter_ctx ctx = SeccompCtx();
  if (ctx == kSkipSeccomp) return;
  CHECK(ctx != NULL);
  CommonPrivileges(ctx);
  CHECK_SUCCESS(NegErrno(seccomp_load(ctx)));
  seccomp_release(ctx);
}

void DropIndexThreadPrivileges() {
  scmp_filter_ctx ctx = SeccompCtx();
  if (ctx == kSkipSeccomp) return;
  CHECK(ctx != NULL);
  CommonPrivileges(ctx);
#ifdef __NR_getrlimit
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
#endif
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                   SCMP_A1(SCMP_CMP_EQ, O_WRONLY | O_CREAT | O_TRUNC));
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                   SCMP_A1(SCMP_CMP_EQ, O_RDWR | O_CREAT | O_TRUNC));
  CHECK_SUCCESS(NegErrno(seccomp_load(ctx)));
  seccomp_release(ctx);
}

void DropPacketThreadPrivileges() {
  scmp_filter_ctx ctx = SeccompCtx();
  if (ctx == kSkipSeccomp) return;
  CHECK(ctx != NULL);
  CommonPrivileges(ctx);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_setup), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_submit), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_getevents), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 1,
                   SCMP_A1(SCMP_CMP_EQ, POLLIN));
  SECCOMP_RULE_ADD(
      ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 2,
      SCMP_A1(SCMP_CMP_EQ, O_WRONLY | O_CREAT | O_DSYNC | O_DIRECT),
      SCMP_A2(SCMP_CMP_EQ, 0600));
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
  SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
#ifdef TESTIMONY
  if (!flag_testimony.empty()) {
    SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    SECCOMP_RULE_ADD(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
  }
#endif
  CHECK_SUCCESS(NegErrno(seccomp_load(ctx)));
  seccomp_release(ctx);
}

#undef SECCOMP_RULE_ADD

Error SetAffinity(int cpu) {
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(cpu, &cpus);
  return Errno(sched_setaffinity(0, sizeof(cpus), &cpus));
}

void WriteIndexes(int thread, st::ProducerConsumerQueue* write_index) {
  VLOG(1) << "Starting WriteIndexes thread " << thread;
  Watchdog dog("WriteIndexes thread " + std::to_string(thread),
               (flag_watchdogs ? flag_fileage_sec * 3 : -1));
  pid_t tid = syscall(SYS_gettid);
  LOG_IF_ERROR(Errno(setpriority(PRIO_PROCESS, tid, flag_index_nicelevel)),
               "setpriority");
  DropIndexThreadPrivileges();
  while (true) {
    VLOG(1) << "Waiting for index";
    Index* i = reinterpret_cast<Index*>(write_index->Get());
    VLOG(1) << "Got index " << int64_t(i);
    if (i == NULL) {
      break;
    }
    LOG_IF_ERROR(i->Flush(), "index flush");
    VLOG(1) << "Wrote index " << int64_t(i);
    delete i;
    dog.Feed();
  }
  VLOG(1) << "Exiting write index thread";
}

bool run_threads = true;

void HandleSignals(int sig) {
  if (run_threads) {
    LOG(INFO) << "Got signal " << sig << ", stopping threads";
    run_threads = false;
  }
}

void HandleSignalsThread() {
  VLOG(1) << "Handling signals";
  struct sigaction handler;
  handler.sa_handler = &HandleSignals;
  sigemptyset(&handler.sa_mask);
  handler.sa_flags = 0;
  sigaction(SIGINT, &handler, NULL);
  sigaction(SIGTERM, &handler, NULL);
  DropCommonThreadPrivileges();
  main_complete.WaitForNotification();
  VLOG(1) << "Signal handling done";
}

#define IS_SEEKING_FILES 4
#define IS_PCAP_T_ACTIVE 2
#define IS_WRITER_ACTIVE 1


class RecvThreadCtx {
 public:
  RecvThreadCtx() {}
  RecvThreadCtx(uint32_t recv_id) {
    pcapng_dirname = flag_dir + "PKT" + std::to_string(recv_id) + "/";
    index_dirname = flag_dir + "IDX" + std::to_string(recv_id) + "/";
    CHECK(OpenOrCreateFolder(pcapng_dirname));
    CHECK(OpenOrCreateFolder(index_dirname));
    pcapng_writer = new std::ofstream;
    id = recv_id;
    file_status = 0;
  }

  // Create new pcapng file and its index
  void WriteNewPcapng() {
    int64_t micros = GetCurrentTimeMicros();
    if (!flag_index) {
      LOG(ERROR) << "Indexing turned off";
      return;
    }
    index = new Index(index_dirname, micros);

    if (file_status & IS_WRITER_ACTIVE) {
      pcapng_writer->close();
      file_status &= ~IS_WRITER_ACTIVE;
    }
    std::string pcapng_file_path = pcapng_dirname + std::to_string(micros);
    pcapng_writer->open(pcapng_file_path);
    file_status |= IS_WRITER_ACTIVE;

    if (!pcapng_writer->is_open()) {
      LOG(INFO) << "Error: Unable to open the pcapng file";
    } else {
      // Section Header Block & Interface Description Block
      SectionHdrBlock shb = SectionHdrBlock();
      pcapng_writer->write((const char*)&shb, MIN_SHB_LEN);
      IfaceDescBlock idb = IfaceDescBlock(pcap_handler);
      pcapng_writer->write((const char*)&idb, MIN_IDB_LEN);
    }
    curr_offset = MIN_SHB_IDB_LEN;
  }

  // Wait until we read a pcap file
  void FindNewPcap(DIR* directory) {
    // Read available files
    if ((file_status & IS_SEEKING_FILES) == 0) {
      std::unique_lock<std::mutex> lock_iter(file_iter_mutex);
      curr_pcap_path = "";
      dirent* entry;
      while(1){
        if ((entry = readdir(directory)) == NULL) { 
          file_status |= IS_SEEKING_FILES;
          break; // Read all available files, switch to seeking mode
        }
        if (entry == NULL || entry->d_type != DT_REG)
          continue;

        std::string file_name(entry->d_name);
        if (isFilePcap(file_name)) {
          curr_pcap_path = flag_pcap + file_name;
          break;
        }
      }
      lock_iter.unlock();
    }

    // If all files are browsed, find new files
    if (file_status & IS_SEEKING_FILES) { 
      std::unique_lock<std::mutex> lock_seeker(file_seeker_mutex);
      LOG(INFO) << "Thread #" << id << ": Waiting for new files...";
      while(fileQueue.empty()) {
        conditionVar.wait(lock_seeker); 
      }
      curr_pcap_path = flag_pcap + fileQueue.front();
      fileQueue.pop();
      lock_seeker.unlock();
    }
    
    // Error buffer
    char errbuff[PCAP_ERRBUF_SIZE];
    if (file_status & IS_PCAP_T_ACTIVE) {
      pcap_close(pcap_handler);
      file_status &= ~IS_PCAP_T_ACTIVE;
    }
    pcap_handler = pcap_open_offline(curr_pcap_path.c_str(), errbuff);
    file_status |= IS_PCAP_T_ACTIVE;
    if (pcap_handler == NULL) {
      LOG(INFO) << "Can not read " << curr_pcap_path << " -> Skipped";
      FindNewPcap(directory);
    }
    LOG(INFO) << "Thread #" << (int)id << ": Reading     \t" << curr_pcap_path;  

    WriteNewPcapng();
  }

  void ReachPcapEof() {
    LOG(INFO) << "Thread #" << (int)id << ": Done reading\t" << curr_pcap_path;  
    LOG_IF_ERROR(index->Flush2(), "index flush");
    delete index;
    pcapng_writer->close();
  }

  pcap_t*         pcap_handler;  // Need closing before change (-19 line)
  std::ofstream*  pcapng_writer; // Need closing before change
  st::Index*      index;
  uint32_t        curr_offset;
  uint16_t        file_status;
  uint16_t        id;   // padding
private:
  std::string     pcapng_dirname;
  std::string     index_dirname;
  std::string     curr_pcap_path;
};

RecvThreadCtx recv_thread_ctx[4];

static void init_file_seeker() {
  // Monitor directory
  int fd = inotify_init();
  CHECK(fd >= 0);

  int wd = inotify_add_watch(fd, flag_pcap.c_str(), IN_CREATE);
  CHECK(wd >= 0);

  // Suspected
  char buffer_seeker[512];
  while (true) {
    int length = read(fd, buffer_seeker, sizeof(buffer_seeker));
    CHECK(length >= 0);

    int i = 0;
    while (i < length) {
      struct inotify_event *event = (struct inotify_event *)&buffer_seeker[i];
      if (event->len > 0 && (event->mask & IN_CREATE) && !(event->mask & IN_ISDIR)) {
        std::lock_guard<std::mutex> lock(file_fetcher);
        fileQueue.push(event->name);
        conditionVar.notify_one();
      }
      i += sizeof(struct inotify_event) + event->len;
    }
  }
}

static void scde_process_packet(struct pcap_pkthdr *header_pcap, uint8_t *full_packet, int32_t recv_idx){
  EnhancedPktBlock epb = EnhancedPktBlock(header_pcap, full_packet);
  int64_t next_offset = recv_thread_ctx[recv_idx].curr_offset + epb.get_blocklen();

  if (next_offset >= (flag_filesize_mb << 20)) {
    LOG_IF_ERROR(recv_thread_ctx[recv_idx].index->Flush2(), "index flush");
    recv_thread_ctx[recv_idx].WriteNewPcapng();
    next_offset = MIN_SHB_IDB_LEN + epb.get_blocklen();
  }

  // Write the enhanced packet block to pcapng file
  recv_thread_ctx[recv_idx].pcapng_writer->write((const char*)&epb, EPB_HEADER_LEN);  
  recv_thread_ctx[recv_idx].pcapng_writer->write((const char*)full_packet, epb.get_cap_leng());
  if (epb.get_num_pads() > 0) {
    const unsigned char padding[] = {0x00, 0x00, 0x00};
    recv_thread_ctx[recv_idx].pcapng_writer->write((const char*)padding, epb.get_num_pads());  
  }
  recv_thread_ctx[recv_idx].pcapng_writer->write((const char*)epb.getptr_blocklen(), 4);  

  // Add packet's key to level-db
  recv_thread_ctx[recv_idx].index->ProcessRaw(
    (unsigned char*)full_packet, 
    recv_thread_ctx[recv_idx].curr_offset, 
    epb.get_cap_leng()
  );

  recv_thread_ctx[recv_idx].curr_offset = next_offset;  
}

void RunThread(int thread_id, DIR* directory) {
  if (flag_threads > 1) {
    LOG_IF_ERROR(SetAffinity(thread_id), "set affinity");
  }
  Watchdog dog("Thread " + std::to_string(thread_id),
               (flag_watchdogs ? flag_fileage_sec * 2 : -1));

  DropPacketThreadPrivileges();
  LOG(INFO) << "Thread " << thread_id << " starting to process";

  recv_thread_ctx[thread_id] = RecvThreadCtx(thread_id);
  
  while (1) {
    // WAIT until we found a pcap file and read it
    recv_thread_ctx[thread_id].FindNewPcap(directory);
    // The header that pcap gives us
    struct pcap_pkthdr *header_pcap;
    // The actual packet
    unsigned char const *full_packet;

    // Looping through each packet
    while (pcap_next_ex(recv_thread_ctx[thread_id].pcap_handler, &header_pcap, &full_packet) >= 0) {
      scde_process_packet(header_pcap, (uint8_t*)full_packet, thread_id);
    }

    // Read a file done
    recv_thread_ctx[thread_id].ReachPcapEof();

    // Reset time countdown
    dog.Feed();
  }

  LOG(INFO) << "Finished thread_id " << thread_id << " successfully";
}

int Main(int argc, char** argv) {
  LOG_IF_ERROR(Errno(prctl(PR_SET_PDEATHSIG, SIGTERM)), "prctl PDEATHSIG");
  ParseOptions(argc, argv);
  LOG(INFO) << "Stenotype running with these arguments:";
  for (int i = 0; i < argc; i++) {
    LOG(INFO) << i << " :[" << argv[i] << "]";
  }

  uint16_t num_threads = std::thread::hardware_concurrency();
  LOG(INFO) << "Max threads possible: " << num_threads;
  
  // Recommended at most 4 cores
  if (num_threads > 4) num_threads = 4;
  
  CHECK(flag_filesize_mb <= 4 << 10);
  CHECK(flag_threads >= 1);
  CHECK(flag_dir != "");
  CHECK(flag_pcap != "");

  if (flag_threads > num_threads) {
    flag_threads = num_threads;
  }
  if (flag_dir[flag_dir.size() - 1] != '/') {
    flag_dir += "/";
  }
  if (flag_pcap[flag_pcap.size() - 1] != '/') {
    flag_pcap += "/";
  }
  LOG(INFO) << "Max size in MB: " << flag_filesize_mb;
  LOG(INFO) << "Threads used: " << flag_threads;

  // To be safe, also set umask before any threads are created.
  umask(0077);

  // Now that we have sockets, drop privileges.
  DropPrivileges();

  std::thread signal_thread(&HandleSignalsThread);
  signal_thread.detach();
  // ... Then, we block those signals from being handled by this thread or any
  // of its children. All other threads MUST be created after this.
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);
  CHECK_SUCCESS(Errno(pthread_sigmask(SIG_BLOCK, &sigset, NULL)));

  DIR* directory = opendir(flag_pcap.c_str());
  CHECK(directory != NULL);

  LOG(INFO) << "---*--- START READING ---*---";
  std::vector<std::thread*> index_threads;
  for (int32_t i = 0; i < flag_threads; i++) {
    // Start a new thread and pass the files to it
    index_threads.emplace_back(new std::thread(&RunThread, i, directory));
    // int initer = packet_shm_init(flag_dir.c_str(), i, scde_process_packet);
    // LOG(INFO) << "Initer: " << initer;
  } 

  // Setup new_file seeker
  init_file_seeker();

  // Drop all privileges we need.
  DropCommonThreadPrivileges();

  if (flag_index) {
    for (int i = 0; i < flag_threads; i++) {
      CHECK(index_threads[i]->joinable());
      index_threads[i]->join();
      VLOG(1) << "Index thread finished";
      delete index_threads[i];
    }
  }
  LOG(INFO) << "---*--- END READING ---*---";

  // Stop
  main_complete.Notify();
  return 0;
}

} // namespace st

int main(int argc, char** argv) { return st::Main(argc, argv); }
