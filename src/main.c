// memleakd
// A daemon to watch process memory usage and perform actions on memory hogs,
// such as killing them or restarting them.

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

#include "const.h"

#include "rules.c"
#include "daemon.c"

int main() {
    rule_list rules = parse_rules("rules.cfg");
    run_daemon(rules, DEFAULT_POLL_RATE);
    return 0;
}


