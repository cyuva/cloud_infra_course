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

#include <fcntl.h>


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

/* phase 4 functions */

/* phase 4: Write data to a file specified by path */
static void write_file(const char *path, const char *data)
{
	
	int fd;
	ssize_t len, wr;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		die(path);

	len = (ssize_t)strlen(data);
	wr = write(fd, data, (size_t)len);
	if (wr != len) {
		if (wr < 0)
			die("write");
		errno = EIO;
		die("short write");
	}

	if (close(fd) < 0)
		die("close");
}

/*
 * Phase 4: We intentionally do not fail if enabling the memory controller is not possible
 * (some setups already enable it or disallow writing subtree_control here).
 */
static void try_enable_memory_controller(void)
{
	const char *path = "/sys/fs/cgroup/cgroup.subtree_control";

	if (access(path, F_OK) != 0)
		return;

	/* Use a small, warning-free write via write_file; ignore failure explicitly. */
	{
		int saved_errno;
		int fd = open(path, O_WRONLY | O_CLOEXEC);
		if (fd < 0)
			return;

		/* Must check return values under -Werror */
		if (write(fd, "+memory\n", 8) < 0) {
			/* ignore */
		}
		saved_errno = errno;
		if (close(fd) < 0) {
			/* ignore */
		}
		errno = saved_errno;
	}
}

/* 
 * phase 4: setup cgroup for the child process to limit memory usage
 * set memory.max to 100MB and add child_pid to cgroup.procs
 */
static void setup_cgroup(pid_t child_pid)
{
	const char *cg_dir_name = "/sys/fs/cgroup/simple_container";
	char path[PATH_MAX];
	char pidbuf[64];

	try_enable_memory_controller();

	/* Create the cgroup directory */
	if (mkdir(cg_dir_name, 0755) < 0 && errno != EEXIST)
		die("mkdir(cgroup)");

	/* resolve the path of memory.max*/
	if (snprintf(path, sizeof(path), "%s/memory.max", cg_dir_name) >= (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		die("snprintf(memory.max)");
	}
	/* Write memory.max value to 100MB */
	write_file(path, "100000000\n");

	/* resolve the path of cgroup.procs*/
	if (snprintf(path, sizeof(path), "%s/cgroup.procs", cg_dir_name) >= (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		die("snprintf(cgroup.procs)");
	}

	/* prepare child_pid string */
	if (snprintf(pidbuf, sizeof(pidbuf), "%d\n", child_pid) >= (int)sizeof(pidbuf)) {
		errno = ENAMETOOLONG;
		die("snprintf(pidbuf)");
	}
	
	/* Write child_pid to cgroup.procs */
	write_file(path, pidbuf);
}

/* phase 4: cleanup cgroup, erase the created cgroup directory */
static void cleanup_cgroup(void)
{
	if (rmdir("/sys/fs/cgroup/simple_container") < 0)
		die("rmdir(cgroup)");
}

/* Phase 5 functions */

/*
 * Phase 5: whitelist capabilities.
 * Allowed: CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT
 */
static void whitelist_capabilities(void)
{
	/* Clear all capabilities first */
	capng_clear(CAPNG_SELECT_BOTH);

	/* Add back only the whitelisted capabilities */
	capng_update(CAPNG_ADD,
		     CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET,
		     CAP_KILL);

	capng_update(CAPNG_ADD,
		     CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET,
		     CAP_SETGID);

	capng_update(CAPNG_ADD,
		     CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET,
		     CAP_SETUID);

	capng_update(CAPNG_ADD,
		     CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET,
		     CAP_NET_BIND_SERVICE);

	capng_update(CAPNG_ADD,
		     CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_BOUNDING_SET,
		     CAP_SYS_CHROOT);
	
	/* Apply the capability changes */
	if (capng_apply(CAPNG_SELECT_BOTH) < 0)
		die("capng_apply");
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

	/* Phase 4: setup pipe to address the race condition of set_cgroup/execv */
	int pipefd[2];
	if (pipe2(pipefd, O_CLOEXEC) < 0)
		die("pipe2 failed");

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		/* Phase 4: close pipe write end in child */
		if (close(pipefd[1]) < 0)
			die("close pipe write end failed");

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

		/* Phase 5: enforce whitelisted capabilities right before exec */
		whitelist_capabilities();
        
		/* 
		 * Phase 4: wait for parent to setup cgroup
		 * block in order to avoid race condition with set_cgroup
		 */
		char c;
		if (read(pipefd[0], &c, 1) < 0)
			die("read from pipe failed");
		
		/* run the requested command */
		execv(argv[2], &argv[2]);

		die("execv failed");
	}
	
	/* Parent Process */
	
	/* Phase 4: close pipe read end in parent */
	if (close(pipefd[0]) < 0)
		die("close pipe read end failed");

	/* Phase 4: Setup cgroup for the child process */
	setup_cgroup(pid);
	
	/*
	 * Phase 4: notify the child to continue by writing to the pipe
	 * and close the write end of the pipe
	 */
	if (write(pipefd[1], "c", 1) < 0)
		die("write to pipe failed");
	
	if (close(pipefd[1]) < 0)
		die("close pipe write end failed");

	/* Phase 4: Resume the child process */
	if (kill(pid, SIGCONT) < 0)
		die("kill(SIGCONT) failed");

    /* parent process waits for child to finish */
	if (waitpid(pid, NULL, 0) < 0)
		die("waitpid failed");
	
	/* Phase 4: cleanup cgroup */
	cleanup_cgroup();
	
	return 0;
}