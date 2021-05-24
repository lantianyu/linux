// SPDX-License-Identifier: GPL-2.0
/*
 * Hyper-V Isolation VM interface with paravisor and hypervisor
 *
 * Author:
 *  Tianyu Lan <Tianyu.Lan@microsoft.com>
 */

#include <linux/types.h>
#include <linux/bitfield.h>
#include <linux/hyperv.h>
#include <linux/types.h>
#include <linux/bitfield.h>
#include <asm/io.h>
#include <asm/svm.h>
#include <asm/sev-es.h>
#include <asm/mshyperv.h>

union hv_ghcb {
	struct ghcb ghcb;
} __packed __aligned(PAGE_SIZE);

void hv_ghcb_msr_write(u64 msr, u64 value)
{
	union hv_ghcb *hv_ghcb;
	void **ghcb_base;
	unsigned long flags;

	if (!ms_hyperv.ghcb_base)
		return;

	local_irq_save(flags);
	ghcb_base = (void **)this_cpu_ptr(ms_hyperv.ghcb_base);
	hv_ghcb = (union hv_ghcb *)*ghcb_base;
	if (!hv_ghcb) {
		local_irq_restore(flags);
		return;
	}

	memset(hv_ghcb, 0x00, HV_HYP_PAGE_SIZE);

	hv_ghcb->ghcb.protocol_version = 1;
	hv_ghcb->ghcb.ghcb_usage = 0;

	ghcb_set_sw_exit_code(&hv_ghcb->ghcb, SVM_EXIT_MSR);
	ghcb_set_rcx(&hv_ghcb->ghcb, msr);
	ghcb_set_rax(&hv_ghcb->ghcb, lower_32_bits(value));
	ghcb_set_rdx(&hv_ghcb->ghcb, value >> 32);
	ghcb_set_sw_exit_info_1(&hv_ghcb->ghcb, 1);
	ghcb_set_sw_exit_info_2(&hv_ghcb->ghcb, 0);

	VMGEXIT();

	if ((hv_ghcb->ghcb.save.sw_exit_info_1 & 0xffffffff) == 1)
		pr_warn("Fail to write msr via ghcb %llx.\n", msr);

	local_irq_restore(flags);
}

void hv_ghcb_msr_read(u64 msr, u64 *value)
{
	union hv_ghcb *hv_ghcb;
	void **ghcb_base;
	unsigned long flags;

	if (!ms_hyperv.ghcb_base)
		return;

	local_irq_save(flags);
	ghcb_base = (void **)this_cpu_ptr(ms_hyperv.ghcb_base);
	hv_ghcb = (union hv_ghcb *)*ghcb_base;
	if (!hv_ghcb) {
		local_irq_restore(flags);
		return;
	}

	memset(hv_ghcb, 0x00, HV_HYP_PAGE_SIZE);
	hv_ghcb->ghcb.protocol_version = 1;
	hv_ghcb->ghcb.ghcb_usage = 0;

	ghcb_set_sw_exit_code(&hv_ghcb->ghcb, SVM_EXIT_MSR);
	ghcb_set_rcx(&hv_ghcb->ghcb, msr);
	ghcb_set_sw_exit_info_1(&hv_ghcb->ghcb, 0);
	ghcb_set_sw_exit_info_2(&hv_ghcb->ghcb, 0);

	VMGEXIT();

	if ((hv_ghcb->ghcb.save.sw_exit_info_1 & 0xffffffff) == 1)
		pr_warn("Fail to read msr via ghcb %llx.\n", msr);
	else
		*value = (u64)lower_32_bits(hv_ghcb->ghcb.save.rax)
			| ((u64)lower_32_bits(hv_ghcb->ghcb.save.rdx) << 32);
	local_irq_restore(flags);
}

void hv_sint_rdmsrl_ghcb(u64 msr, u64 *value)
{
	hv_ghcb_msr_read(msr, value);
}
EXPORT_SYMBOL_GPL(hv_sint_rdmsrl_ghcb);

void hv_sint_wrmsrl_ghcb(u64 msr, u64 value)
{
	hv_ghcb_msr_write(msr, value);

	/* Write proxy bit vua wrmsrl instruction. */
	if (msr >= HV_X64_MSR_SINT0 && msr <= HV_X64_MSR_SINT15)
		wrmsrl(msr, value | 1 << 20);
}
EXPORT_SYMBOL_GPL(hv_sint_wrmsrl_ghcb);

void hv_signal_eom_ghcb(void)
{
	hv_sint_wrmsrl_ghcb(HV_X64_MSR_EOM, 0);
}
EXPORT_SYMBOL_GPL(hv_signal_eom_ghcb);

enum hv_isolation_type hv_get_isolation_type(void)
{
	if (!(ms_hyperv.priv_high & HV_ISOLATION))
		return HV_ISOLATION_TYPE_NONE;
	return FIELD_GET(HV_ISOLATION_TYPE, ms_hyperv.isolation_config_b);
}
EXPORT_SYMBOL_GPL(hv_get_isolation_type);

bool hv_is_isolation_supported(void)
{
	return hv_get_isolation_type() != HV_ISOLATION_TYPE_NONE;
}
EXPORT_SYMBOL_GPL(hv_is_isolation_supported);

DEFINE_STATIC_KEY_FALSE(isolation_type_snp);

bool hv_isolation_type_snp(void)
{
	return static_branch_unlikely(&isolation_type_snp);
}
EXPORT_SYMBOL_GPL(hv_isolation_type_snp);

/*
 * hv_mark_gpa_visibility - Set pages visible to host via hvcall.
 *
 * In Isolation VM, all guest memory is encripted from host and guest
 * needs to set memory visible to host via hvcall before sharing memory
 * with host.
 */
int hv_mark_gpa_visibility(u16 count, const u64 pfn[], u32 visibility)
{
	struct hv_gpa_range_for_visibility **input_pcpu, *input;
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
	input_pcpu = (struct hv_gpa_range_for_visibility **)
			this_cpu_ptr(hyperv_pcpu_input_arg);
	input = *input_pcpu;
	if (unlikely(!input)) {
		local_irq_restore(flags);
		return -EINVAL;
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

/*
 * hv_set_mem_host_visibility - Set specified memory visible to host.
 *
 * In Isolation VM, all guest memory is encrypted from host and guest
 * needs to set memory visible to host via hvcall before sharing memory
 * with host. This function works as wrap of hv_mark_gpa_visibility()
 * with memory base and size.
 */
int hv_set_mem_host_visibility(void *kbuffer, size_t size,
			       enum vmbus_page_visibility visibility)
{
	int pagecount = size >> HV_HYP_PAGE_SHIFT;
	u64 *pfn_array;
	int ret = 0;
	int i, pfn;

	if (!hv_is_isolation_supported())
		return 0;

	pfn_array = vzalloc(HV_HYP_PAGE_SIZE);
	if (!pfn_array)
		return -ENOMEM;

	for (i = 0, pfn = 0; i < pagecount; i++) {
		pfn_array[pfn] = virt_to_hvpfn(kbuffer + i * HV_HYP_PAGE_SIZE);
		pfn++;

		if (pfn == HV_MAX_MODIFY_GPA_REP_COUNT || i == pagecount - 1) {
			ret |= hv_mark_gpa_visibility(pfn, pfn_array, visibility);
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

