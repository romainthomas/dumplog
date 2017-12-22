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

#ifndef DUMPLOG_H_
#define DUMPLOG_H_
#include <map>
#include <string>
#include <vector>

#include <fcntl.h>

#include "json.hpp"

using json = nlohmann::json;

using log_id_t  = unsigned char;
using uid_t     = uint32_t;
using thread_id = uint32_t;
using lid2str_t   = std::map<log_id_t, std::string>;
using filter_t    = std::vector<std::pair<std::string, std::string>>;

#if defined(__arm__) || defined(__i386__) || defined(_M_IX86)
#define IS_32 1
#else
#define IS_32 0
#endif


#if defined(__IA64__) || defined(__x86_64__) || defined(__aarch64__)
#define IS_64 1
#else
#define IS_64 0
#endif

static constexpr bool is_32 = IS_32;
static constexpr bool is_64 = IS_64;

// Android Structures
// ==================
#define ANDROID_LOG_RDONLY   O_RDONLY
#define ANDROID_LOG_WRONLY   O_WRONLY
#define ANDROID_LOG_RDWR     O_RDWR
#define ANDROID_LOG_ACCMODE  O_ACCMODE
#define ANDROID_LOG_NONBLOCK O_NONBLOCK
#define ANDROID_LOG_PSTORE   0x80000000

struct logger_list;
struct logger;
struct log_msg;

using android_logger_open_t       = logger* (*)(logger_list*, log_id_t);
using android_name_to_log_id_t    = log_id_t(*)(const char*);
using android_logger_list_read_t  = int(*)(logger_list*, log_msg*);
using android_logger_list_alloc_t = logger_list* (*)(int, unsigned int, pid_t);
using android_logger_list_free_t  = void (*)(logger_list*);
using android_logger_get_id_t     = log_id_t (*)(logger*);

extern "C" {
/*
 * The userspace structure for version 1 of the logger_entry ABI.
 * This structure is returned to userspace by the kernel logger
 * driver unless an upgrade to a newer ABI version is requested.
 */
struct logger_entry {
    uint16_t    len;    /* length of the payload */
    uint16_t    __pad;  /* no matter what, we get 2 bytes of padding */
    int32_t     pid;    /* generating process's pid */
    int32_t     tid;    /* generating process's tid */
    int32_t     sec;    /* seconds since Epoch */
    int32_t     nsec;   /* nanoseconds */
    char        msg[0]; /* the entry's payload */
} __attribute__((__packed__));

/*
 * The userspace structure for version 2 of the logger_entry ABI.
 * This structure is returned to userspace if ioctl(LOGGER_SET_VERSION)
 * is called with version==2; or used with the user space log daemon.
 */
struct logger_entry_v2 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v2) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    euid;      /* effective UID of logger */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

struct logger_entry_v3 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v3) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

#define LOGGER_ENTRY_MAX_LEN		(5*1024)

struct log_msg {
    union {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry_v3 entry;
        struct logger_entry_v3 entry_v3;
        struct logger_entry_v2 entry_v2;
        struct logger_entry    entry_v1;
    } __attribute__((aligned(4)));
};
}

enum android_LogPriority {
    ANDROID_LOG_UNKNOWN = 0,
    ANDROID_LOG_DEFAULT,    /* only for SetMinPriority() */
    ANDROID_LOG_VERBOSE,
    ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO,
    ANDROID_LOG_WARN,
    ANDROID_LOG_ERROR,
    ANDROID_LOG_FATAL,
    ANDROID_LOG_SILENT,     /* only for SetMinPriority(); must be last */
};

// Dumplog Functions
// =================
static constexpr char DEFAULT_OUTPUT_FILENAME[] = "/data/local/tmp/log.json";

std::string cmdline(pid_t);
std::string exe(pid_t);
json process_message(const log_msg&, lid2str_t&, const filter_t&);
int imports(void);
int log(const std::vector<std::string>& devices, bool block, bool dump_file, const filter_t& filters, const std::string& filename = DEFAULT_OUTPUT_FILENAME);
void on_sigint(int);
#endif
