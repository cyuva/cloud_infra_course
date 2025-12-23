#define _GNU_SOURCE
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <limits.h>


static void die(const char *msg)
{
	/* Print error message and exit */
	perror(msg);
	exit(EXIT_FAILURE);
}

/* Phase 2 functions */

/* Phase 2: wrraper for pivot_root syscall */
static int pivot_root_wrapper(const char *new_root, const char *put_old)
{
	/* Wrapper for pivot_root syscall */
	return syscall(SYS_pivot_root, new_root, put_old);
}

/* Phase 2: Setup rootfs using pivot_root */
static void setup_rootfs(const char *rootfs_path)
{
	char new_root[PATH_MAX];
	char put_old[PATH_MAX];

	/* Get the absolute path of the rootfs input path */
	if (!realpath(rootfs_path, new_root))
		die("realpath(rootfs) failed");

	/*
	 * Prevent mount propagation back to the host.
	 * MS_REC makes it recursive (applies to all submounts).
	 */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		die("mount(/) MS_PRIVATE failed");

	/*
	 * pivot_root requires new_root to be a mount point.
	 * Bind-mount rootfs onto itself to make it one.
	 */
	if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) < 0)
		die("mount(rootfs) MS_BIND failed");

	/*builds path for old root inside new root */
	if (snprintf(put_old, sizeof(put_old), "%s/.old_root", new_root) >= (int)sizeof(put_old)) {
		errno = ENAMETOOLONG;
		die("snprintf(put_old) failed");
	}

	/* Create the directory for the old root */
	if (mkdir(put_old, 0755) < 0 && errno != EEXIST)
		die("mkdir(.old_root) failed");

	/*
	 * Switch root: new_root becomes "/", old root is mounted at /.old_root.
	 */
	if (pivot_root_wrapper(new_root, put_old) < 0)
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

/* Phase 3 functions */

/* Phase 3: Mount a fresh /proc inside the container root */
static void mount_proc(void)
{
	/* Some rootfs may not have /proc; create it if missing. */
	if (mkdir("/proc", 0555) < 0 && errno != EEXIST)
		die("mkdir(/proc)");

	if (mount("proc", "/proc", "proc", 0, NULL) < 0)
		die("mount(/proc)");
}

int main(int argc, char **argv)
{
	pid_t pid;

    /* usage check */
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <rootfs_path> <command> [args...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	 /*
	 * Phase 3: PID namespaces only affect children.
	 * Unshare in the parent before fork so the child becomes PID 1.
	 */
	if (unshare(CLONE_NEWPID) < 0)
		die("unshare(CLONE_NEWPID)");

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		/* Phase 1: basic namespace isolation (UTS, Mount, IPC) */
		if (unshare(CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWIPC) < 0)
			die("unshare failed");

        /* Phase 1: set hostname */
		if (sethostname("mycontainer", strlen("mycontainer")) < 0)
			die("sethostname failed");
        
		/* Phase 2: filesystem isolation using pivot_root */
		setup_rootfs(argv[1]);

		/* Phase 3: mount a fresh /proc inside the container root */
		mount_proc();
        
		/* run the requested command */
		execv(argv[2], &argv[2]);
		die("execv failed");
	}

    /* parent process waits for child to finish */
	if (waitpid(pid, NULL, 0) < 0)
		die("waitpid failed");

	return 0;
}