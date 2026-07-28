/* netdiag: small on-host diagnostics helper for the ops team.
 *
 * It reports the privilege level it is running with and performs a couple of
 * routine checks. It was installed setuid-root long ago so that operators
 * without full root could run it; that decision was never revisited.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();
    printf("netdiag: ruid=%d euid=%d\n", (int)ruid, (int)euid);

    /* A "privileged" action a setuid helper might perform. When this binary is
     * setuid-root and launched by an unprivileged user, this runs as root. */
    if (euid == 0) {
        FILE *f = fopen("/var/run/netdiag.stamp", "w");
        if (f) {
            fprintf(f, "ran as root by uid %d\n", (int)ruid);
            fclose(f);
        }
    }
    return 0;
}
