
#ifndef MEMLEAK_DAEMON_C
#define MEMLEAK_DAEMON_C

#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "daemon.h"

void run_daemon(rule_list rules, int poll_rate) {
    while (true) {
        printf("Retrieving process list...\n");
        DIR* proc = opendir("/proc");
        struct dirent *entry;
        char statpath[24];
        char procname[16];
        int chk;
        FILE * file;
        // iterate thru proc to get PIDS
        while ((entry = readdir(proc)) != NULL) {
            pid_t pid;
            if (str_isdigit(entry->d_name)) {
                // can't extract the pid
                if (sscanf(entry->d_name, "%i", &pid) != 1) continue;

                // create the path needed to get stats on the process
                sprintf(statpath, "/proc/%i/stat", pid);
                file = fopen(statpath, "r");
                chk = fscanf(file, "%*i (%[^)]s)", procname); // Get the process name
                //printf("%s\n", procname);
                fclose(file);
                if (chk != 1) continue; // Couldn't get the process name, move along

                for (int i=0; i<rules.size; ++i) {
                    if (match_rule(rules.data[i], procname)) {
                        // get memory info
                        sprintf(statpath, "/proc/%i/statm", pid);
                        file = fopen(statpath, "r");
                        uint64_t rss;
                        chk = fscanf(file, "%*i %lu", &rss);
                        rss *= 4 * KB; // RSS memory is given in 4 KB chunks
                        fclose(file);
                        if (chk == 1) {
                            if (rss > rules.data[i].mem_limit) {
                                printf("Process has exceeded its limit: %s %lu\n", procname, rss);
                                do_rule_action(rules.data[i], pid);
                            }
                        }
                    }
                }
            }
        }
        closedir(proc);
        printf("Done.\n");

        sleep(poll_rate);
    }
}

#endif
