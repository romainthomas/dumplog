/*
 * MIT License
 *
 * Copyright (c) 2017 Romain THOMAS - http://www.romainthomas.fr
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <chrono>
#include <fstream>
#include <sstream>
#include <future>
#include <iostream>

#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>

#include "dumplog.hpp"
#include "args.hpp"

static std::initializer_list<std::string> DEFAULT_DEVICES = {"main", "system"};
static std::atomic_bool should_work = true;

static android_logger_open_t       android_logger_open;
static android_name_to_log_id_t    android_name_to_log_id;
static android_logger_list_read_t  android_logger_list_read;
static android_logger_list_alloc_t android_logger_list_alloc;
static android_logger_list_free_t  android_logger_list_free;
static android_logger_get_id_t     android_logger_get_id;


static const std::map<android_LogPriority, const char*> priorities_map {
  {ANDROID_LOG_UNKNOWN, "U"},
  {ANDROID_LOG_DEFAULT, "" },
  {ANDROID_LOG_VERBOSE, "V"},
  {ANDROID_LOG_DEBUG,   "D"},
  {ANDROID_LOG_INFO,    "I"},
  {ANDROID_LOG_WARN,    "W"},
  {ANDROID_LOG_ERROR,   "E"},
  {ANDROID_LOG_FATAL,   "F"},
  {ANDROID_LOG_SILENT,  "S"},
};


std::string priority2string(android_LogPriority p) {
  auto&& it = priorities_map.find(p);
  return it == std::end(priorities_map) ? std::to_string(static_cast<uint32_t>(p)) : it->second;
}

android_LogPriority string2priority(const std::string& priority) {
  auto&& it = std::find_if(
      std::begin(priorities_map),
      std::end(priorities_map),
      [&priority] (auto&& p) {
        return p.second == priority;
      });
  return it == std::end(priorities_map) ? ANDROID_LOG_UNKNOWN : it->first;
}


std::string cmdline(pid_t pid) {
  std::string output(512, '\0');
  std::ostringstream cmdline_path;
  cmdline_path << "/proc/" << std::dec << pid << "/cmdline";
  int fd = open(cmdline_path.str().c_str(), O_RDONLY);
  if (fd < 0) {
    return "";
  }

  if (int count = read(fd, &output[0], output.size())) {
    output.resize(count);
    output += '\0';
  }
  close(fd);
  return output.c_str();
}

std::string exe(pid_t pid) {
  std::ostringstream exe_path;
  exe_path << "/proc/" << std::dec << pid << "/exe";

  std::string exe_link(512, '\0');
  ssize_t count = readlink(exe_path.str().c_str(), &exe_link[0], exe_link.size());

  if (count > 0) {
    exe_link = exe_link.c_str();
  } else {
    exe_link = "";
  }
  return exe_link.c_str();
}

json process_message(const log_msg& buff, lid2str_t& lid_map, const filter_t& filters) {
  std::string message;
  android_LogPriority priority = android_LogPriority::ANDROID_LOG_UNKNOWN;
  std::string tag;
  time_t tv_sec = 0;
  long tv_nsec = 0;
  int32_t pid = -1;
  int32_t tid = -1;
  uint32_t euid = 0;


  if (buff.entry.hdr_size == sizeof(logger_entry_v3)) {
    priority = static_cast<android_LogPriority>(buff.entry_v3.msg[0]);
    tag      = std::string{&buff.entry_v3.msg[1]};
    tv_sec   = buff.entry_v3.sec;
    tv_nsec  = buff.entry_v3.nsec;
    pid      = buff.entry_v3.pid;
    tid      = buff.entry_v3.tid;
    euid     = buff.entry_v3.lid;

    message = std::string{buff.entry_v3.msg + 1 + tag.size() + 1, buff.entry_v3.len};
    message += '\0';
    message = message.c_str();
  }

  if (buff.entry.hdr_size == sizeof(logger_entry_v2)) {
    priority = static_cast<android_LogPriority>(buff.entry_v2.msg[0]);
    tag      = std::string{&buff.entry_v2.msg[1]};
    tv_sec   = buff.entry_v2.sec;
    tv_nsec  = buff.entry_v2.nsec;
    pid      = buff.entry_v2.pid;
    tid      = buff.entry_v2.tid;
    euid     = buff.entry_v2.euid;

    message = std::string{buff.entry_v2.msg + 1 + tag.size() + 1, buff.entry_v2.len};
    message += '\0';
    message = message.c_str();
  }

  if (buff.entry.hdr_size == sizeof(logger_entry)) {
    priority = static_cast<android_LogPriority>(buff.entry_v1.msg[0]);
    tag      = std::string{&buff.entry_v1.msg[1]};
    tv_sec   = buff.entry_v1.sec;
    tv_nsec  = buff.entry_v1.nsec;
    pid      = buff.entry_v1.pid;
    tid      = buff.entry_v1.tid;

    message = std::string{buff.entry_v1.msg + 1 + tag.size() + 1, buff.entry_v1.len};
    message += '\0';
    message = message.c_str();
  }

  std::chrono::time_point<std::chrono::system_clock> point{std::chrono::seconds(tv_sec)};
  std::time_t time = std::chrono::system_clock::to_time_t(point);
  std::tm*    localtm = std::localtime(&time);

  std::string device_name  = lid_map[euid];
  std::string exe_name     = exe(pid);
  std::string cmdline_str  = cmdline(pid);
  std::string priority_str = priority2string(priority);

  exe_name = exe_name.empty() ? std::to_string(pid) : exe_name;

  if (filters.size() == 0 or std::any_of(std::begin(filters), std::end(filters), [&] (auto&& p) {
    auto&& [id, value] = p;

    android_LogPriority filter_priority = string2priority(value);
    if (priority < filter_priority) {
      return false;
    }

    if (not id.empty() and std::all_of(std::begin(id), std::end(id), ::isdigit)) {
      int32_t target_pid = std::stoi(id.c_str());
      if (target_pid != pid) {
        return false;
      }
    }

    if (not (exe_name.find(id) == 0 or cmdline_str.find(id) == 0 or tag.find(id) == 0 or id == "*")) {
      return false;
    }

    return true;
  })) {

    std::cout << device_name << ": "
              << (localtm->tm_mon + 1) << "-" << localtm->tm_mday << " "
              << localtm->tm_hour << ":" << localtm->tm_min << ":" << localtm->tm_sec << " "
              << exe_name << " ";
    if (not cmdline_str.empty()) {
      std::cout << cmdline_str << " ";
    }
    std::cout << std::to_string(tid) << " "
              << priority_str << " "
              << tag << " " << message << std::endl;

    json result = {
      {"device", device_name},
      {"sec", tv_sec},
      {"nsec", tv_nsec},
      {"tag", tag},
      {"pid", pid},
      {"tid", tid},
      {"priority", priority_str},
      {"executable", exe_name},
      {"command", cmdline_str},
      {"message", message},
    };

    return result;
  }
  return {};
}

template<typename T>
int resolve(const char* library, const char* symbol, T* output) {
  std::string prefix = "";
  if constexpr (is_64) {
    prefix = "/system/lib64/";
  } else if constexpr (is_32) {
    prefix = "/system/lib/";
  }
  std::string fullpath = prefix + library;
  void* handler = dlopen(fullpath.c_str(), RTLD_LAZY);
  if (handler == nullptr) {
    return -1;
  }

  *output = reinterpret_cast<T>(dlsym(handler, symbol));
  if (*output == nullptr) {
    return -1;
  }
  return 0;
}

int imports(void) {
  int ret = 0;
  if (resolve("liblog.so", "android_logger_open", &android_logger_open)) {
    std::cerr << "Error while loading 'android_logger_open' in 'liblog.so'" << std::endl;
    ret = -1;
  }

  if (resolve("liblog.so", "android_name_to_log_id", &android_name_to_log_id)) {
    std::cerr << "Error while loading 'android_name_to_log_id' in 'liblog.so'" << std::endl;
    ret = -1;
  }

  if (resolve("liblog.so", "android_logger_list_read", &android_logger_list_read)) {
    std::cerr << "Error while loading 'android_logger_list_read' in 'liblog.so'" << std::endl;
    ret = -1;
  }

  if (resolve("liblog.so", "android_logger_list_alloc", &android_logger_list_alloc)) {
    std::cerr << "Error while loading 'android_logger_list_alloc' in 'liblog.so'" << std::endl;
    ret = -1;
  }

  if (resolve("liblog.so", "android_logger_list_free", &android_logger_list_free)) {
    std::cerr << "Error while loading 'android_logger_list_free' in 'liblog.so'" << std::endl;
    ret = -1;
  }

  if (resolve("liblog.so", "android_logger_get_id", &android_logger_get_id)) {
    std::cerr << "Error while loading 'android_logger_get_id' in 'liblog.so'" << std::endl;
    ret = -1;
  }
  return ret;
}


int log(const std::vector<std::string>& devices, bool block, bool dump_file, const filter_t& filters, const std::string& filename) {

  std::map<std::string, logger*> loggers;
  lid2str_t lid2str;
  unsigned int mode = ANDROID_LOG_RDONLY;
  if (not block) {
    mode |= O_NONBLOCK;
  }
  logger_list* llist = android_logger_list_alloc(mode, 0, 0);
  if (not llist) {
    std::cerr << "List allocation failed!" << std::endl;
    return EXIT_FAILURE;
  }

  for (const std::string& device : devices) {
    logger* logger_ptr = android_logger_open(llist, android_name_to_log_id(device.c_str()));
    if (not logger_ptr) {
      std::cerr << "Unable to open '" << device << "'" << std::endl;
      continue;
    }

    loggers.emplace(device, logger_ptr);
    lid2str.emplace(android_logger_get_id(logger_ptr), device);
  }

  auto&& read_message = [] (logger_list* lst, log_msg* msg) {
    return android_logger_list_read(lst, msg);
  };

  std::future_status status = std::future_status::ready;
  std::future<int>* message = new std::future<int>{}; // Bad Hack to avoid blocking 'delete' (Yes we leak data...)
  int ret = 0;
  json result;
  std::unique_ptr<std::ofstream> ofs;
  if (dump_file) {
    ofs = std::unique_ptr<std::ofstream>{new std::ofstream{filename, std::ios::trunc | std::ios::out}};
    *ofs << "[";
  }

  while (should_work) {
    log_msg buff;
    if (status == std::future_status::ready) {
      *message = std::async(std::launch::async, read_message, llist, &buff);
      status = message->wait_for(std::chrono::milliseconds(100));
    }

    if (status == std::future_status::timeout) {
      status = message->wait_for(std::chrono::milliseconds(100));
    }

    if (status == std::future_status::ready) {
      ret = message->get();

      if (ret <= 0) {
        if (not block) {
          delete message;
        }
        break;
      }
      result = process_message(buff, lid2str, filters);
      if (ofs and not result.is_null()) {
        *ofs << result << ", ";
      }
    }
  }
  if (ofs) {
    ofs->seekp(-2, std::ios::end); // Remove the last ','
    *ofs << "]";
  }
  android_logger_list_free(llist);
  return 0;
}

void on_sigint(int) {
  should_work = false;
}

int main(int argc, char *argv[]) {
  args::ArgumentParser parser(argv[0], "Android log utility");
  args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});

  args::ValueFlag<std::string> filename(parser, "filename", "Log to file (JSON format)", {'o', "output"}, "");

  args::Flag block(parser, "dont-block", "Dump the log and then exit (don't block)", {'d', "dont-block"});
  args::ValueFlagList<std::string> filters(parser, "filters", "List of tags to monitor ", {'f', "filter"});

  args::PositionalList<std::string> log_devices(parser, "log-devices", "Device sources (e.g. main, system, radio ...) ", {"main", "system"});

  // Filter examples:
  // -f 123:V
  // -f com.goo.bar:I
  //

  parser.ParseCLI(argc, argv);
  if (parser.GetError() == args::Error::Help) {
    std::cout << parser;
    return EXIT_SUCCESS;
  }

  if (parser.GetError() == args::Error::Parse) {
    std::cerr << parser;
    return EXIT_FAILURE;
  }

  if (imports() < 0) {
    std::cerr << "Abort!" << std::endl;
    return EXIT_FAILURE;
  }
  filter_t filters_formated;
  for (const std::string& filter : args::get(filters)) {
    size_t colon_pos = filter.find(":");
    if (colon_pos == std::string::npos) {
      std::cerr << "Filter '" << filter << "' bad format! Excepting a ':'" << std::endl;
      continue;
    }
    std::string id    = filter.substr(0, colon_pos);
    std::string value = filter.substr(colon_pos + 1, filter.size());
    filters_formated.emplace_back(id, value);
  }

  struct sigaction handler;
  handler.sa_handler = on_sigint;
  sigemptyset(&handler.sa_mask);
  handler.sa_flags = 0;
  sigaction(SIGINT, &handler, NULL);


  std::string outputfilename = args::get(filename);
  std::vector<std::string> devices = args::get(log_devices);
  if (devices.size() == 0) {
    devices = DEFAULT_DEVICES;
  }
  return log(devices, not block, not outputfilename.empty(), filters_formated, outputfilename);;
}



