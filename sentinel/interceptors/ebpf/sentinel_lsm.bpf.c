// SPDX-License-Identifier: GPL-2.0
/*
 * Agent-Sentinel Kernel LSM Probe
 * Hooks bprm_check_security / sys_enter_execve to intercept unauthorized
 * processes spawned by AI coding agents before they can execute.
 */

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#define BPF_NO_PRESERVE_ACCESS_INDEX
#endif

// Kernel headers placeholder for CO-RE (Compile Once - Run Everywhere)
struct linux_binprm {
    char *filename;
};

#define SEC(name) __attribute__((section(name), used))

struct event_t {
    unsigned int pid;
    unsigned int ppid;
    char comm[16];
    char filename[256];
};

/*
 * BPF LSM hook: bprm_check_security
 * Triggered by Linux kernel every time any process invokes execve()
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(sentinel_bprm_check, struct linux_binprm *bprm)
{
    // In production eBPF deployment:
    // 1. Check if current task's cgroup / PGID belongs to the AI Agent sandbox
    // 2. Extract bprm->filename and argv strings
    // 3. Match against Sentinel L1 fast rule map in eBPF array
    // 4. Return -1 (EPERM) to block execution instantly, or 0 to allow

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
