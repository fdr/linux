#ifndef _LINUX_MMAN_H
#define _LINUX_MMAN_H

#include <asm/mman.h>

#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

#define OVERCOMMIT_GUESS		0
#define OVERCOMMIT_ALWAYS		1
#define OVERCOMMIT_NEVER		2

#ifdef __KERNEL__
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>

#include <linux/percpu_counter.h>

#include <linux/atomic.h>

extern int sysctl_overcommit_memory;
extern int sysctl_overcommit_ratio;
extern struct percpu_counter vm_committed_as;

struct vm_acct_values {
        int overcommit_memory;
        int overcommit_ratio;
        atomic_long_t vm_committed_space;
};

#ifdef CONFIG_CGROUP_MEM_RES_CTLR

extern void mem_cgroup_vm_acct_memory(struct mm_struct *mm, long pages);
extern void vm_acct_get_config(const struct mm_struct *mm,
                               struct vm_acct_values *v);

#else /* CONFIG_CGROUP_MEM_RES_CTLR */

static inline void mem_cgroup_vm_acct(struct mm_struct *mm, long pages);
{
}

static inline void vm_acct_get_config(const struct mm_struct *mm,
                                      struct vm_acct_values *v)
{
        v->overcommit_memory = sysctl_overcommit_memory;
        v->overcommit_ratio = sysctl_overcommit_ratio;
}

#endif /* CONFIG_CGROUP_MEM_RES_CTLR */

static inline void vm_acct_memory(struct mm_struct *mm, long pages)
{
        percpu_counter_add(&vm_committed_as, pages);
        mem_cgroup_vm_acct_memory(mm, pages);
}

static inline void vm_unacct_memory(struct mm_struct *mm, long pages)
{
        vm_acct_memory(mm, -pages);
}

static inline int __vm_enough_memory_guess(struct mm_struct *mm,
                                           long pages,
                                           int cap_sys_admin)

{
        unsigned long free;

        free = global_page_state(NR_FREE_PAGES);
        free += global_page_state(NR_FILE_PAGES);

        /*
         * shmem pages shouldn't be counted as free in this
         * case, they can't be purged, only swapped out, and
         * that won't affect the overall amount of available
         * memory in the system.
         */
        free -= global_page_state(NR_SHMEM);

        free += nr_swap_pages;

        /*
         * Any slabs which are created with the
         * SLAB_RECLAIM_ACCOUNT flag claim to have contents
         * which are reclaimable, under pressure.  The dentry
         * cache and most inode caches should fall into this
         */
        free += global_page_state(NR_SLAB_RECLAIMABLE);

        /*
         * Leave reserved pages. The pages are not for anonymous pages.
         */
        if (free <= totalreserve_pages)
                goto error;
        else
                free -= totalreserve_pages;

        /*
         * Leave the last 3% for root
         */
        if (!cap_sys_admin)
                free -= free / 32;

        if (free > pages)
                return 0;

error:
        return -ENOMEM;

}

static inline int __vm_enough_memory_never(struct mm_struct *mm,
                                           long pages,
                                           int cap_sys_admin)
{
        unsigned long allowed;

        allowed = (totalram_pages - hugetlb_total_pages())
                * sysctl_overcommit_ratio / 100;

        /*
         * Leave the last 3% for root
         */
        if (!cap_sys_admin)
                allowed -= allowed / 32;
        allowed += total_swap_pages;

        /* Don't let a single process grow too big:
           leave 3% of the size of this process for other processes */
        if (mm)
                allowed -= mm->total_vm / 32;

        if (percpu_counter_read_positive(&vm_committed_as) < allowed)
                return 0;

        return -ENOMEM;
}

/*
 * Allow architectures to handle additional protection bits
 */

#ifndef arch_calc_vm_prot_bits
#define arch_calc_vm_prot_bits(prot) 0
#endif

#ifndef arch_vm_get_page_prot
#define arch_vm_get_page_prot(vm_flags) __pgprot(0)
#endif

#ifndef arch_validate_prot
/*
 * This is called from mprotect().  PROT_GROWSDOWN and PROT_GROWSUP have
 * already been masked out.
 *
 * Returns true if the prot flags are valid
 */
static inline int arch_validate_prot(unsigned long prot)
{
	return (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM)) == 0;
}
#define arch_validate_prot arch_validate_prot
#endif

/*
 * Optimisation macro.  It is equivalent to:
 *      (x & bit1) ? bit2 : 0
 * but this version is faster.
 * ("bit1" and "bit2" must be single bits)
 */
#define _calc_vm_trans(x, bit1, bit2) \
  ((bit1) <= (bit2) ? ((x) & (bit1)) * ((bit2) / (bit1)) \
   : ((x) & (bit1)) / ((bit1) / (bit2)))

/*
 * Combine the mmap "prot" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_prot_bits(unsigned long prot)
{
	return _calc_vm_trans(prot, PROT_READ,  VM_READ ) |
	       _calc_vm_trans(prot, PROT_WRITE, VM_WRITE) |
	       _calc_vm_trans(prot, PROT_EXEC,  VM_EXEC) |
	       arch_calc_vm_prot_bits(prot);
}

/*
 * Combine the mmap "flags" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_flag_bits(unsigned long flags)
{
	return _calc_vm_trans(flags, MAP_GROWSDOWN,  VM_GROWSDOWN ) |
	       _calc_vm_trans(flags, MAP_DENYWRITE,  VM_DENYWRITE ) |
	       _calc_vm_trans(flags, MAP_EXECUTABLE, VM_EXECUTABLE) |
	       _calc_vm_trans(flags, MAP_LOCKED,     VM_LOCKED    );
}
#endif /* __KERNEL__ */
#endif /* _LINUX_MMAN_H */
