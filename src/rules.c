
#ifndef MEMLEAK_RULES_C
#define MEMLEAK_RULES_C

#include "rules.h"

rule_list parse_rules(char* filename) {
    rule* rules = malloc(sizeof(rule) * 2);

    rules[0].match_type = EXACT;
    rules[0].match_data = "polkitd";
    rules[0].action_type = KILL;
    rules[0].action_data = NULL;
    rules[0].mem_limit = 16 * MB;

    rules[1].match_type = EXACT;
    rules[1].match_data = "cinnamon";
    rules[1].action_type = SHELL;
    rules[1].action_data = "kill -9 $PID; sleep 3; cinnamon -d :0 --replace";
    rules[1].mem_limit = 512 * MB;

    rule_list result;
    result.head = rules;
    result.size = 2;
    return result;
}

void print_rule(rule r) {
    switch(r.match_type) {
        case EXACT:
            printf("\"%s\" %lu %s\n", (char *) r.match_data, r.mem_limit, rule_action_str(r));
            break;
        case SUBSTRING:
            printf("%s %lu %s\n", (char *) r.match_data, r.mem_limit, rule_action_str(r));
            break;
        case REGEX:
            printf("/%s/ %lu %s\n", (char *) r.match_data, r.mem_limit, rule_action_str(r));
            break;
    }
}

char* rule_action_str(rule r) {
    switch (r.action_type) {
        case KILL:
            return "KILL";
        case TERM:
            return "TERM";
        case SHELL:
            return "SHELL";
        default:
            return "?";
    }
}

#endif
