#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

static void setup_rootfs(const char *rootfs_path)
{
	char new_root[PATH_MAX];
	char put_old[PATH_MAX];

	if (!realpath(rootfs_path, new_root))
		die("realpath(rootfs)");

	/*
	 * Prevent mount propagation back to the host.
	 * MS_REC makes it recursive (applies to all submounts).
	 */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		die("mount(/) MS_PRIVATE");

	/*
	 * pivot_root requires new_root to be a mount point.
	 * Bind-mount rootfs onto itself to make it one.
	 */
	if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) < 0)
		die("mount(rootfs) MS_BIND");

	/* Create directory for old root inside new root */
	if (snprintf(put_old, sizeof(put_old), "%s/.old_root", new_root) >= (int)sizeof(put_old)) {
		errno = ENAMETOOLONG;
		die("snprintf(put_old)");
	}

	if (mkdir(put_old, 0755) < 0 && errno != EEXIST)
		die("mkdir(.old_root)");

	/*
	 * Switch root: new_root becomes "/", old root is mounted at /.old_root.
	 */
	if (pivot_root(new_root, put_old) < 0)
		die("pivot_root");

	/* Ensure we're operating relative to the new root */
	if (chdir("/") < 0)
		die("chdir(/)");

	/* Detach and remove the old root so it's inaccessible */
	if (umount2("/.old_root", MNT_DETACH) < 0)
		die("umount2(/.old_root)");

	if (rmdir("/.old_root") < 0)
		die("rmdir(/.old_root)");
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

		/* Phase 2: filesystem isolation using pivot_root */
		setup_rootfs(argv[1]);

		/* Execute command inside the new root */
		execv(argv[2], &argv[2]);
		die("execv");
	}

	if (waitpid(pid, NULL, 0) < 0)
		die("waitpid");

	return 0;
}

