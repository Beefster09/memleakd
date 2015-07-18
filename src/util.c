
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

bool str_isdigit(char * const str) {
    for (int i=0; str[i]; ++i) {
        if (!isdigit(str[i])) return false;
    }
    return true;
}

// Wrapped kill signal sender
void send_signal(pid_t pid, int sig) {
    if (kill(pid, sig) == -1) {
        printf("Could not send signal (%i) process #%i ", sig, pid);
        switch (errno) {
            case EINVAL:
                printf("(Invalid Signal)\n");
                break;
            case EPERM:
                printf("(Access Denied)\n");
                break;
            case ESRCH:
                printf("(Process does not exist)\n");
                break;
            default:
                printf("(Unknown Reason)\n");
                break;
        }
    }
}
