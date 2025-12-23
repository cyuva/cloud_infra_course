#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

#include <cap-ng.h>

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

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

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		die("mount(/) MS_PRIVATE");

	if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) < 0)
		die("mount(rootfs) MS_BIND");

	if (snprintf(put_old, sizeof(put_old), "%s/.old_root", new_root) >= (int)sizeof(put_old)) {
		errno = ENAMETOOLONG;
		die("snprintf(put_old)");
	}

	if (mkdir(put_old, 0755) < 0 && errno != EEXIST)
		die("mkdir(.old_root)");

	if (pivot_root(new_root, put_old) < 0)
		die("pivot_root");

	if (chdir("/") < 0)
		die("chdir(/)");

	if (umount2("/.old_root", MNT_DETACH) < 0)
		die("umount2(/.old_root)");

	if (rmdir("/.old_root") < 0)
		die("rmdir(/.old_root)");
}

static void mount_proc(void)
{
	if (mkdir("/proc", 0555) < 0 && errno != EEXIST)
		die("mkdir(/proc)");

	if (mount("proc", "/proc", "proc", 0, NULL) < 0)
		die("mount(/proc)");
}

/*
 * Phase 4: best-effort enabling of memory controller. Some systems already
 * enable it or disallow writing subtree_control. Failure here is OK.
 */
static void try_enable_memory_controller(void)
{
	const char *path = "/sys/fs/cgroup/cgroup.subtree_control";
	int fd;
	ssize_t wr;

	if (access(path, F_OK) != 0)
		return;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	wr = write(fd, "+memory\n", 8);
	if (wr < 0) {
		/* ignore */
	}

	if (close(fd) < 0) {
		/* ignore */
	}
}

static void setup_cgroup(pid_t child_pid)
{
	const char *cg_root = "/sys/fs/cgroup";
	const char *cg_name = "simple_container";
	char cg_dir[PATH_MAX];
	char path[PATH_MAX];
	char pidbuf[64];

	try_enable_memory_controller();

	if (snprintf(cg_dir, sizeof(cg_dir), "%s/%s", cg_root, cg_name) >= (int)sizeof(cg_dir)) {
		errno = ENAMETOOLONG;
		die("snprintf(cg_dir)");
	}

	if (mkdir(cg_dir, 0755) < 0 && errno != EEXIST)
		die("mkdir(cgroup)");

	if (snprintf(path, sizeof(path), "%s/memory.max", cg_dir) >= (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		die("snprintf(memory.max)");
	}
	write_file(path, "100000000\n");

	if (snprintf(path, sizeof(path), "%s/cgroup.procs", cg_dir) >= (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		die("snprintf(cgroup.procs)");
	}

	if (snprintf(pidbuf, sizeof(pidbuf), "%d\n", child_pid) >= (int)sizeof(pidbuf)) {
		errno = ENAMETOOLONG;
		die("snprintf(pidbuf)");
	}
	write_file(path, pidbuf);
}

static void cleanup_cgroup(void)
{
	if (rmdir("/sys/fs/cgroup/simple_container") < 0)
		die("rmdir(cgroup)");
}

/*
 * Phase 5: whitelist capabilities.
 * Allowed: CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT
 */
static void drop_caps(void)
{
	capng_clear(CAPNG_SELECT_BOTH);

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

	if (capng_apply(CAPNG_SELECT_BOTH) < 0)
		die("capng_apply");
}

int main(int argc, char **argv)
{
	pid_t pid;
	int status;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <rootfs_path> <command> [args...]\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (unshare(CLONE_NEWPID) < 0)
		die("unshare(CLONE_NEWPID)");

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid == 0) {
		if (unshare(CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWIPC) < 0)
			die("unshare(CLONE_NEWUTS|CLONE_NEWNS|CLONE_NEWIPC)");

		if (sethostname("mycontainer", strlen("mycontainer")) < 0)
			die("sethostname");

		setup_rootfs(argv[1]);
		mount_proc();

		/* Phase 5: drop capabilities right before exec */
		drop_caps();

		execv(argv[2], &argv[2]);
		die("execv");
	}

	setup_cgroup(pid);

	if (waitpid(pid, &status, 0) < 0)
		die("waitpid");

	cleanup_cgroup();

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return EXIT_FAILURE;
}

