/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * shield.h -- one guard source, two builds (shirudo-spike harness).
 *
 * A guard calls SHIELD_ACTIVITY() on every run of its hook and returns
 * SHIELD_REFUSE(<err>) where it would refuse. Built with -DSHIELD_RECORD
 * (shield-k try) the refusal is only counted and 0 is returned, so one run
 * fills the table; built without it (shield-k enforce) the error is
 * returned. Both builds count in shield_hits, so the enforce run reports
 * what it refused. Counters are per-CPU and summed by the harness; a lost
 * increment under preemption only makes a count low, never zero when a
 * refusal happened on the path the run took.
 */
#ifndef SHIELD_H
#define SHIELD_H

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} shield_hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} shield_activity SEC(".maps");

static __always_inline void shield_count(void *map)
{
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(map, &zero);

	if (n)
		(*n)++;
}

#define SHIELD_ACTIVITY()	shield_count(&shield_activity)

#ifdef SHIELD_RECORD
#define SHIELD_MODE_RECORD	1
#define SHIELD_REFUSE(err)	({ shield_count(&shield_hits); 0; })
#else
#define SHIELD_MODE_RECORD	0
#define SHIELD_REFUSE(err)	({ shield_count(&shield_hits); (err); })
#endif

#endif /* SHIELD_H */
