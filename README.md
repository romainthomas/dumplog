Android Dumplog
===============

Android dumplog is a utility to:

  1. Filter android logs by package name (e.g. ``com.google.*``) - **Require root**
  2. Serialize output log in JSON

Pre-compiled binaries can be found in the ``bin`` directory

Examples
========

Filter by package name
----------------------

Only log ouput from ``com.google.android.youtube``:

```bash
$ adb shell dumplog -f com.google.android.youtube:V
```

Output:
```bash
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I qtaguid Tagging socket -1 with tag 0{0,0} uid -1, pid: 11582, getuid(): 10169
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I qtaguid Failed write_ctrl(t -1 0 -1) res=-1 errno=9
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I qtaguid Tagging socket -1 with tag 0(0) for uid -1 failed errno=-9
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I NetworkManagementSocketTagger tagSocketFd(-1, 0, -1) failed with errno-9
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I qtaguid Untagging socket -1
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I qtaguid Failed write_ctrl(u -1) res=-1 errno=9
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I qtaguid Untagging socket -1 failed errno=-9
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 W NetworkManagementSocketTagger untagSocket(-1) failed with errno -9
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11733 I System.out Thread-1158 calls detatch()
main: 12-22 17:14:2 /system/bin/app_process64 com.google.android.youtube 11582 I Timeline Timeline: Activity_idle id: android.os.BinderProxy@f4a0f1b time:8202654
```

Save to JSON
------------

Save log from packages starting with ``com.google`` into ``com_google.json``:

```bash
$ adb shell dumplog -o /data/local/tmp/com_google.json -f com.google:V
```

Output of ``com_google.json``:

```json
...
  {
    "command": "com.google.android.gms.persistent",
    "device": "main",
    "executable": "/system/bin/app_process64",
    "message": "Invalid task was provided to stopTracking.",
    "nsec": 251434303,
    "pid": 4459,
    "priority": "W",
    "sec": 1513959708,
    "tag": "ContentTaskController",
    "tid": 4459
  },
  {
    "command": "com.google.android.youtube",
    "device": "main",
    "executable": "/system/bin/app_process64",
    "message": "Failed write_ctrl(u -1) res=-1 errno=9",
    "nsec": 311434110,
    "pid": 11582,
    "priority": "I",
    "sec": 1513959302,
    "tag": "qtaguid",
    "tid": 11685
  },
...
```


Usage
=====

```bash
./dumplog [log-devices...] {OPTIONS}

  ./dumplog

OPTIONS:

    -h, --help                        Display this help menu
    -o[filename], --output=[filename] Log to file (JSON format)
    -d, --dont-block                  Dump the log and then exit (don't block)
    -f[filters...],
    --filter=[filters...]             List of tags to monitor
    log-devices...                    Device sources (e.g. main, system,
                                      radio ...)
    "--" can be used to terminate flag options and force all following
    arguments to be treated as positional options

```

Compilation
===========

```bash
$ ANDROID_NDK=<PATH TO NDK> ./generate.sh
```

See the ``generate.sh`` file for more information


Acknowledgements
================

Dumplog makes use of the following open source projects:

 * json - https://github.com/nlohmann/json - MIT
 * args - https://github.com/Taywee/args - MIT

Authors
=======

Romain Thomas ([@rh0main](https://twitter.com/rh0main))

