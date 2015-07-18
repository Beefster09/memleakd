
#ifndef MEMLEAK_RULES_C
#define MEMLEAK_RULES_C

#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <regex.h>

#include "rules.h"

rule_list parse_rules(char* filename) {
    rule_list rules;
    int capacity = INITIAL_CAPACITY;
    // Init the base memory for parsing
    rules.data = malloc(sizeof(rule) * capacity);
    rules.size = 0;
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open %s.", filename);
        switch (errno) {
            case EACCES:
                fprintf(stderr, "(Access Denied)\n");
                break;
            case ENOENT:
                fprintf(stderr, "(File Not Found)\n");
                break;
            default:
                fprintf(stderr, "\n");
                break;
        }
    }

    char namestr[256];
    char memstr[32];
    char memtypestr[4];
    char atypestr[32];
    char* shellstr = NULL;
    size_t shellsize;
    int shellpos;
    int shelldepth = 0;

    char* line = NULL;
    size_t size;

    while (getline(&line, &size, file) != -1) {
        int pos = 0;

        if (!isspace(line[pos])) {
            if (rules.size == capacity) {
                capacity += GROWTH_STEP;
                rules.data = realloc(rules.data, sizeof(rule) * capacity );
            }
            // "Clear" the buffers
            namestr[0] = 0;
            memstr[0] = 0;
            // Read the name filter
            int i = 0;
            switch (line[pos]) {
                case '/': // Regex
                    rules.data[rules.size].match_type = REGEX;
                    ++pos;
                    while (line[pos] && line[pos] != '/') {
                        if (line[pos] == '\\' && line[pos+1] == '/') ++pos; // skip over \/ escapes
                        namestr[i++] = line[pos++];
                    }
                    namestr[i] = 0;
                    regex_t re;
                    regcomp(&re, namestr, 0);
                    rules.data[rules.size].match_data = &re;
                    break;
                case '"': // Exact
                    rules.data[rules.size].match_type = EXACT;
                    ++pos;
                    while (line[pos] && line[pos] != '"') {
                        if (line[pos] == '\\' && line[pos+1] == '"') ++pos; // skip over \" escapes
                        namestr[i++] = line[pos++];
                    }
                    namestr[i] = 0;
                    rules.data[rules.size].match_data = malloc(strlen(namestr) + 1);
                    strcpy(rules.data[rules.size].match_data, namestr);
                    break;
                default: // Substring
                    rules.data[rules.size].match_type = SUBSTRING;
                    while (line[pos] && !isspace(line[pos])) {
                        if (line[pos] == '\\' && isspace(line[pos+1])) ++pos; // skip over \{space} escapes
                        namestr[i++] = line[pos++];
                    }
                    namestr[i] = 0;
                    rules.data[rules.size].match_data = malloc(strlen(namestr) + 1);
                    strcpy(rules.data[rules.size].match_data, namestr);
                    break;
            }

            while (isspace(line[++pos])); // move until you hit a non-space character

            // Get the memory string
            i = 0;
            while (line[pos] && !isspace(line[pos])) {
                memstr[i++] = line[pos++];
            }
            memstr[i] = 0;
            if (sscanf(memstr, "%lu%s", &rules.data[rules.size].mem_limit, memtypestr) == 2) {
                for(int i = 0; memtypestr[i]; i++) memtypestr[i] = tolower(memtypestr[i]);
                if (strcmp(memtypestr, "kb") == 0) {
                    rules.data[rules.size].mem_limit *= KB;
                }
                else if (strcmp(memtypestr, "mb") == 0) {
                    rules.data[rules.size].mem_limit *= MB;
                }
                else if (strcmp(memtypestr, "gb") == 0) {
                    rules.data[rules.size].mem_limit *= GB;
                }
            }
            else {
                fprintf(stderr, "Cannot parse memory data: %s\n", memstr);
                continue; // Error! Move to next line
            }

            while (isspace(line[++pos])); // move until you hit a non-space character

            // Get the action type string
            i = 0;
            while (isalnum(line[pos])) {
                atypestr[i++] = line[pos++];
            }
            atypestr[i] = 0;
            for(int i = 0; atypestr[i]; i++) atypestr[i] = tolower(atypestr[i]);
            if (strcmp(atypestr, "kill") == 0) {
                rules.data[rules.size].action_type = KILL;
            }
            else if (strcmp(atypestr, "term") == 0) {
                rules.data[rules.size].action_type = TERM;
            }
            else if (strcmp(atypestr, "shell") == 0) {
                rules.data[rules.size].action_type = SHELL;
                // Advance to the { or end of line
                for( ; line[pos] && line[pos] != '{'; ++pos);
                if (line[pos] != '{') break; // invalid rule

                shellsize = 4*KB;
                shellstr = malloc(shellsize);
                shelldepth = 1;
                shellpos = 0;
                ++pos;

                do {
                    while (line[pos]) {
                        if (shellpos >= shellsize - 1) {
                            shellsize += 4*KB;
                            shellstr = realloc(shellstr, shellsize);
                        }
                        if (line[pos] == '\\' && (line[pos+1] == '{' || line[pos+1] == '}')) ++pos;
                        else { // handle unescaped braces as usual
                            if      (line[pos] == '{') ++shelldepth;
                            else if (line[pos] == '}') --shelldepth;
                        }

                        if (shelldepth == 0) { // end of shell block
                            shellstr[shellpos] = 0;
                            break;
                        }

                        shellstr[shellpos++] = line[pos++];
                    }
                    // we are done, so avoid getting the next line.
                    if (shelldepth == 0) break;
                    pos = 0;
                } while (getline(&line, &size, file) != -1);

                rules.data[rules.size].action_data = shellstr;
            }

            ++rules.size;
        }
    }

    free(line);

    fclose(file);
    return rules;
}

bool match_rule(rule r, char* procname) {
    switch(r.match_type) {
        case EXACT:
            return strcmp((char *) r.match_data, procname) == 0;
        case SUBSTRING:
            return strstr(procname, (char *) r.match_data) != NULL;
        case REGEX: ;
            //regmatch_t matches; // On stack; will auto-dispose
            return regexec((regex_t *) r.match_data, procname, 0, NULL, 0) == 0;
        default:
            return false;
    }
}



void do_rule_action(rule r, pid_t pid) {
    switch (r.action_type) {
        case KILL:
            send_signal(pid, SIGKILL);
            break;
        case TERM:
            send_signal(pid, SIGTERM);
            break;
        case SHELL: ;
            pid_t id = fork();
            switch (id) { // Error
                case -1:
                    fprintf(stderr, "Could not execute shell command: %s", (char *) r.action_data);
                    break;
                case 0: ;// Child
                    // Prepare args and environment for bash
                    char *args[4] = {"bash", "-c", (char *) r.action_data, NULL};
                    char *env[3];
                    env[0] = malloc(16);   // PID
                    env[1] = malloc(4096); // PATH
                    env[2] = NULL;
                    sprintf(env[0], "PID=%i", pid);
                    sprintf(env[1], "PATH=%s", getenv("PATH")); // inherit the PATH
                    execve("/bin/bash", args, env);
                    // Will only execute if there is an error
                    switch (errno) {
                        case EACCES:
                            perror("Could not run bash: Access Denied\n");
                            break;
                        case EIO:
                            perror("Could not run bash: I/O error.\n");
                            break;
                        default:
                            perror("Could not run bash.\n");
                            break;
                    }
                    exit(1);
                    break;
                default: // Parent
                    break; // nothing to do, really
            }
            break;
        default:
            break;
    }
}

void print_rule(rule r) {
    char *rule_str = rule_action_str(r);
    switch(r.match_type) {
        case EXACT:
            printf("\"%s\" %lu %s\n", (char *) r.match_data, r.mem_limit, rule_str);
            break;
        case SUBSTRING:
            printf("%s %lu %s\n", (char *) r.match_data, r.mem_limit, rule_str);
            break;
        case REGEX:
            printf("/%s/ %lu %s\n", (char *) r.match_data, r.mem_limit, rule_str);
            break;
        default:
            printf("?%s? %lu %s\n", (char *) r.match_data, r.mem_limit, rule_str);
            break;
    }
    // clean up to avoid memory leaks
    free(rule_str);
}

char* rule_action_str(rule r) {
    char* buffer;
    switch (r.action_type) {
        case KILL:
            buffer = malloc(5);
            strcpy(buffer, "kill");
            break;
        case TERM:
            buffer = malloc(5);
            strcpy(buffer, "term");
            break;
        case SHELL:
            buffer = malloc(strlen((char *) r.action_data) + 11); // 11 = length of "shell {\n\n}\0"
            sprintf(buffer, "shell {\n%s\n}", (char *) r.action_data);
            break;
        default:
            buffer = malloc(2);
            strcpy(buffer, "?");
    }
    return buffer;
}

#endif
