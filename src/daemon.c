
#ifndef MEMLEAK_DAEMON_C
#define MEMLEAK_DAEMON_C

#include <unistd.h>

#include "daemon.h"

void run_daemon(rule_list rules, int poll_rate) {
    while (true) {
        printf("Retrieving process list...\n");
        printf("Testing against %i rules...\n", rules.size);
        for (int i=0; i<rules.size; ++i) {
            print_rule(rules.head[i]);
        }
        sleep(poll_rate);
    }
}

#endif
