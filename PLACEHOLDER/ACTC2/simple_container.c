#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	pid_t pid;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <rootfs_path> <command> [args...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		/* Phase 1: basic namespace isolation */
		if (unshare(CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWIPC) < 0)
			die("unshare");

		if (sethostname("mycontainer", strlen("mycontainer")) < 0)
			die("sethostname");

		execv(argv[2], &argv[2]);
		die("execv");
	}

	if (waitpid(pid, NULL, 0) < 0)
		die("waitpid");

	return 0;
}
