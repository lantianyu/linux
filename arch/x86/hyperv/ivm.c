// SPDX-License-Identifier: GPL-2.0
/*
 * Hyper-V Isolation VM interface with paravisor and hypervisor
 *
 * Author:
 *  Tianyu Lan <Tianyu.Lan@microsoft.com>
 */

#include <linux/hyperv.h>
#include <linux/types.h>
#include <linux/bitfield.h>
#include <asm/io.h>
#include <asm/mshyperv.h>

/*
 * hv_set_mem_host_visibility - Set host visibility for specified memory.
 */
int hv_set_mem_host_visibility(void *kbuffer, u32 size, u32 visibility)
{
	int i, pfn;
	int pagecount = size >> HV_HYP_PAGE_SHIFT;
	u64 *pfn_array;
	int ret = 0;

	pfn_array = vzalloc(HV_HYP_PAGE_SIZE);
	if (!pfn_array)
		return -ENOMEM;

	for (i = 0, pfn = 0; i < pagecount; i++) {
		pfn_array[pfn] = virt_to_hvpfn(kbuffer + i * HV_HYP_PAGE_SIZE);
		pfn++;

		if (pfn == HV_MAX_MODIFY_GPA_REP_COUNT || i == pagecount - 1) {
			ret = hv_mark_gpa_visibility(pfn, pfn_array, visibility);
			pfn = 0;

			if (ret)
				goto err_free_pfn_array;
		}
	}

 err_free_pfn_array:
	vfree(pfn_array);
	return ret;
}
EXPORT_SYMBOL_GPL(hv_set_mem_host_visibility);

int hv_mark_gpa_visibility(u16 count, const u64 pfn[], u32 visibility)
{
	struct hv_input_modify_sparse_gpa_page_host_visibility **input_pcpu;
	struct hv_input_modify_sparse_gpa_page_host_visibility *input;
	u16 pages_processed;
	u64 hv_status;
	unsigned long flags;

	/* no-op if partition isolation is not enabled */
	if (!hv_is_isolation_supported())
		return 0;

	if (count > HV_MAX_MODIFY_GPA_REP_COUNT) {
		pr_err("Hyper-V: GPA count:%d exceeds supported:%lu\n", count,
			HV_MAX_MODIFY_GPA_REP_COUNT);
		return -EINVAL;
	}

	local_irq_save(flags);
	input_pcpu = (struct hv_input_modify_sparse_gpa_page_host_visibility **)
			this_cpu_ptr(hyperv_pcpu_input_arg);
	input = *input_pcpu;
	if (unlikely(!input)) {
		local_irq_restore(flags);
		return -1;
	}

	input->partition_id = HV_PARTITION_ID_SELF;
	input->host_visibility = visibility;
	input->reserved0 = 0;
	input->reserved1 = 0;
	memcpy((void *)input->gpa_page_list, pfn, count * sizeof(*pfn));
	hv_status = hv_do_rep_hypercall(
			HVCALL_MODIFY_SPARSE_GPA_PAGE_HOST_VISIBILITY, count,
			0, input, &pages_processed);
	local_irq_restore(flags);

	if (!(hv_status & HV_HYPERCALL_RESULT_MASK))
		return 0;

	return hv_status & HV_HYPERCALL_RESULT_MASK;
}
EXPORT_SYMBOL(hv_mark_gpa_visibility);
