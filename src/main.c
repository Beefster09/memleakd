// memleakd
// A daemon to watch process memory usage and perform actions on memory hogs,
// such as killing them or restarting them.

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include "const.h"
#include "util.c"

#include "rules.c"
#include "daemon.c"

int main() {
    rule_list rules = parse_rules("/etc/default/memleakd");
    printf("%i rules loaded...\n", rules.size);
    for (int i=0; i<rules.size; ++i) {
        print_rule(rules.data[i]);
    }
    run_daemon(rules, DEFAULT_POLL_RATE);
    return 0;
}


