/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Type definitions for the hypervisor host interface to kernel.
 */
#ifndef _UAPI_HV_HVHDK_MINI_H
#define _UAPI_HV_HVHDK_MINI_H

#include "hvgdk_mini.h"

#define HVHVK_MINI_VERSION		(25294)

/*
 * Doorbell connection_info flags.
 */
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_MASK  0x00000007
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_ANY   0x00000000
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_BYTE  0x00000001
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_WORD  0x00000002
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_DWORD 0x00000003
#define HV_DOORBELL_FLAG_TRIGGER_SIZE_QWORD 0x00000004
#define HV_DOORBELL_FLAG_TRIGGER_ANY_VALUE  0x80000000

/* Each generic set contains 64 elements */
#define HV_GENERIC_SET_SHIFT		(6)
#define HV_GENERIC_SET_MASK		(63)

enum hv_generic_set_format {
	HV_GENERIC_SET_SPARSE_4K,
	HV_GENERIC_SET_ALL,
};


/* NOTE: following two #defines are not defined in Hyper-V code */
/* The maximum number of sparse vCPU banks which can be encoded by 'struct hv_vpset' */
#define HV_MAX_SPARSE_VCPU_BANKS (64)
/* The number of vCPUs in one sparse bank */
#define HV_VCPUS_PER_SPARSE_BANK (64)

enum hv_scheduler_type {
	HV_SCHEDULER_TYPE_LP = 1, /* Classic scheduler w/o SMT */
	HV_SCHEDULER_TYPE_LP_SMT = 2, /* Classic scheduler w/ SMT */
	HV_SCHEDULER_TYPE_CORE_SMT = 3, /* Core scheduler */
	HV_SCHEDULER_TYPE_ROOT = 4, /* Root / integrated scheduler */
	HV_SCHEDULER_TYPE_MAX
};

struct hv_vpset {		/* HV_VP_SET */
	__u64 format;
	__u64 valid_bank_mask;
	__u64 bank_contents[];
} __packed;

enum hv_stats_object_type {
	HV_STATS_OBJECT_HYPERVISOR		= 0x00000001,
	HV_STATS_OBJECT_LOGICAL_PROCESSOR	= 0x00000002,
	HV_STATS_OBJECT_PARTITION		= 0x00010001,
	HV_STATS_OBJECT_VP			= 0x00010002
};

union hv_stats_object_identity {
	/* hv_stats_hypervisor */
	struct {
		__u8 reserved[16];
	} __packed hv;

	/* hv_stats_logical_processor */
	struct {
		__u32 lp_index;
		__u8 reserved[12];
	} __packed lp;

	/* hv_stats_partition */
	struct {
		__u64 partition_id;
		__u8  reserved[4];
		__u16 flags;
		__u8  reserved1[2];
	} __packed partition;

	/* hv_stats_vp */
	struct {
		__u64 partition_id;
		__u32 vp_index;
		__u16 flags;
		__u8  reserved[2];
	} __packed vp;
};

enum hv_partition_property_code {
	/* Privilege properties */
	HV_PARTITION_PROPERTY_PRIVILEGE_FLAGS				= 0x00010000,
	HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES			= 0x00010001,

	/* Scheduling properties */
	HV_PARTITION_PROPERTY_SUSPEND					= 0x00020000,
	HV_PARTITION_PROPERTY_CPU_RESERVE				= 0x00020001,
	HV_PARTITION_PROPERTY_CPU_CAP					= 0x00020002,
	HV_PARTITION_PROPERTY_CPU_WEIGHT				= 0x00020003,
	HV_PARTITION_PROPERTY_CPU_GROUP_ID				= 0x00020004,

	/* Time properties */
	HV_PARTITION_PROPERTY_TIME_FREEZE				= 0x00030003,

	/* Debugging properties */
	HV_PARTITION_PROPERTY_DEBUG_CHANNEL_ID				= 0x00040000,

	/* Resource properties */
	HV_PARTITION_PROPERTY_VIRTUAL_TLB_PAGE_COUNT			= 0x00050000,
	HV_PARTITION_PROPERTY_VSM_CONFIG				= 0x00050001,
	HV_PARTITION_PROPERTY_ZERO_MEMORY_ON_RESET			= 0x00050002,
	HV_PARTITION_PROPERTY_PROCESSORS_PER_SOCKET			= 0x00050003,
	HV_PARTITION_PROPERTY_NESTED_TLB_SIZE				= 0x00050004,
	HV_PARTITION_PROPERTY_GPA_PAGE_ACCESS_TRACKING			= 0x00050005,
	HV_PARTITION_PROPERTY_VSM_PERMISSIONS_DIRTY_SINCE_LAST_QUERY	= 0x00050006,
	HV_PARTITION_PROPERTY_SGX_LAUNCH_CONTROL_CONFIG			= 0x00050007,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL0		= 0x00050008,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL1		= 0x00050009,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL2		= 0x0005000a,
	HV_PARTITION_PROPERTY_DEFAULT_SGX_LAUNCH_CONTROL3		= 0x0005000b,
	HV_PARTITION_PROPERTY_ISOLATION_STATE				= 0x0005000c,
	HV_PARTITION_PROPERTY_ISOLATION_CONTROL				= 0x0005000d,
	HV_PARTITION_PROPERTY_RDT_L3_COS_INDEX				= 0x0005000e,
	HV_PARTITION_PROPERTY_RDT_RMID					= 0x0005000f,
	HV_PARTITION_PROPERTY_IMPLEMENTED_PHYSICAL_ADDRESS_BITS		= 0x00050010,
	HV_PARTITION_PROPERTY_NON_ARCHITECTURAL_CORE_SHARING		= 0x00050011,
	HV_PARTITION_PROPERTY_HYPERCALL_DOORBELL_PAGE			= 0x00050012,
	HV_PARTITION_PROPERTY_ISOLATION_POLICY				= 0x00050014,
	HV_PARTITION_PROPERTY_UNIMPLEMENTED_MSR_ACTION                  = 0x00050017,

	/* Compatibility properties */
	HV_PARTITION_PROPERTY_PROCESSOR_VENDOR				= 0x00060000,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES_DEPRECATED		= 0x00060001,
	HV_PARTITION_PROPERTY_PROCESSOR_XSAVE_FEATURES			= 0x00060002,
	HV_PARTITION_PROPERTY_PROCESSOR_CL_FLUSH_SIZE			= 0x00060003,
	HV_PARTITION_PROPERTY_ENLIGHTENMENT_MODIFICATIONS		= 0x00060004,
	HV_PARTITION_PROPERTY_COMPATIBILITY_VERSION			= 0x00060005,
	HV_PARTITION_PROPERTY_PHYSICAL_ADDRESS_WIDTH			= 0x00060006,
	HV_PARTITION_PROPERTY_XSAVE_STATES				= 0x00060007,
	HV_PARTITION_PROPERTY_MAX_XSAVE_DATA_SIZE			= 0x00060008,
	HV_PARTITION_PROPERTY_PROCESSOR_CLOCK_FREQUENCY			= 0x00060009,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES0			= 0x0006000a,
	HV_PARTITION_PROPERTY_PROCESSOR_FEATURES1			= 0x0006000b,

	/* Guest software properties */
	HV_PARTITION_PROPERTY_GUEST_OS_ID				= 0x00070000,

	/* Nested virtualization properties */
	HV_PARTITION_PROPERTY_PROCESSOR_VIRTUALIZATION_FEATURES		= 0x00080000,
};

enum hv_sleep_state {
	HV_SLEEP_STATE_S1 = 1,
	HV_SLEEP_STATE_S2 = 2,
	HV_SLEEP_STATE_S3 = 3,
	HV_SLEEP_STATE_S4 = 4,
	HV_SLEEP_STATE_S5 = 5,
	/*
	 * After hypervisor has reseived this, any follow up sleep
	 * state registration requests will be rejected.
	 */
	HV_SLEEP_STATE_LOCK = 6
};

enum hv_system_property {
	/* Add more values when needed */
	HV_SYSTEM_PROPERTY_SLEEP_STATE = 3,
	HV_SYSTEM_PROPERTY_SCHEDULER_TYPE = 15,
};

struct hv_sleep_state_info {
	__u32 sleep_state; /* enum hv_sleep_state */
	__u8 pm1a_slp_typ;
	__u8 pm1b_slp_typ;
} __packed;

struct hv_input_get_system_property {
	__u32 property_id; /* enum hv_system_property */
	union {
		__u32 as_uint32;
		/* More fields to be filled in when needed */
	};
} __packed;

struct hv_output_get_system_property {
	union {
		__u32 scheduler_type; /* enum hv_scheduler_type */
	};
} __packed;

struct hv_input_set_system_property {
	__u32 property_id; /* enum hv_system_property */
	union {
		/* More fields to be filled in when needed */
		struct hv_sleep_state_info set_sleep_state_info;
	};
} __packed;

struct hv_input_map_stats_page {
	__u32 type; /* enum hv_stats_object_type */
	__u32 padding;
	union hv_stats_object_identity identity;
} __packed;

struct hv_output_map_stats_page {
	__u64 map_location;
} __packed;

struct hv_input_unmap_stats_page {
	__u32 type; /* enum hv_stats_object_type */
	__u32 padding;
	union hv_stats_object_identity identity;
} __packed;



struct hv_proximity_domain_flags {
	__u32 proximity_preferred : 1;
	__u32 reserved : 30;
	__u32 proximity_info_valid : 1;
} __packed;

/* Not a union in windows but useful for zeroing */
union hv_proximity_domain_info {
	struct {
		__u32 domain_id;
		struct hv_proximity_domain_flags flags;
	};
	__u64 as_uint64;
} __packed;

struct hv_input_withdraw_memory {
	__u64 partition_id;
	union hv_proximity_domain_info proximity_domain_info;
} __packed;

struct hv_output_withdraw_memory {
	/* Hack - compiler doesn't like empty array size
	 * in struct with no other members
	 */
	__u64 gpa_page_list[0];
} __packed;

/* HV Map GPA (Guest Physical Address) Flags */
#define HV_MAP_GPA_PERMISSIONS_NONE     0x0
#define HV_MAP_GPA_READABLE             0x1
#define HV_MAP_GPA_WRITABLE             0x2
#define HV_MAP_GPA_KERNEL_EXECUTABLE    0x4
#define HV_MAP_GPA_USER_EXECUTABLE      0x8
#define HV_MAP_GPA_EXECUTABLE           0xC
#define HV_MAP_GPA_PERMISSIONS_MASK     0xF

struct hv_input_map_gpa_pages {
	__u64 target_partition_id;
	__u64 target_gpa_base;
	__u32 map_flags;
	__u32 padding;
	__u64 source_gpa_page_list[];
} __packed;

union hv_gpa_page_access_state_flags {
	struct {
		__u64 clear_accessed : 1;
		__u64 set_access : 1;
		__u64 clear_dirty : 1;
		__u64 set_dirty : 1;
		__u64 reserved : 60;
	} __packed;
	__u64 as_uint64;
};

struct hv_input_get_gpa_pages_access_state {
	__u64  partition_id;
	union hv_gpa_page_access_state_flags flags;
	__u64 hv_gpa_page_number;
} __packed;

union hv_gpa_page_access_state {
	struct {
		__u8 accessed : 1;
		__u8 dirty : 1;
		__u8 reserved: 6;
	};
	__u8 as_uint8;
} __packed;

#endif /* _UAPI_HV_HVHDK_MINI_H */
