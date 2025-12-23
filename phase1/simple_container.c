#define _GNU_SOURCE
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static void die(const char *msg)
{
	/* Print error message and exit */
	perror(msg);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	pid_t pid;

    /* usage check */
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <rootfs_path> <command> [args...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		/* Phase 1: basic namespace isolation (UTS, Mount, IPC, PID) */
		if (unshare(CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWPID) < 0)
			die("unshare failed");

        /* Phase 1: set hostname */
		if (sethostname("mycontainer", strlen("mycontainer")) < 0)
			die("sethostname failed");
        
        /* run the requested command */
		execv(argv[2], &argv[2]);
		die("execv failed");
	}

	/* Parent Process */

    /* parent process waits for child to finish */
	if (waitpid(pid, NULL, 0) < 0)
		die("waitpid failed");

	return 0;
}