
#ifndef MEMLEAK_RULES_H
#define MEMLEAK_RULES_H

#include <inttypes.h>

typedef enum action {
    KILL,
    TERM,
    SHELL
} atype;

typedef enum match {
    SUBSTRING,
    EXACT,
    REGEX
} mtype;

typedef struct rule {
    uint64_t mem_limit;
    void* match_data;
    void* action_data;
    mtype match_type;
    atype action_type;
} rule;

typedef struct rule_list {
    rule* head;
    unsigned int size;
} rule_list;

rule_list parse_rules(char* filename);

void print_rule(rule r);
char* rule_action_str(rule r);

#endif
