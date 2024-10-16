The following are the supported CXL commands belonging to the Memory Device
command set, as per the latest specification.

<!--ts-->
* [Identify Memory Device (40h)](#identify-memory-device-40h)
   * [Identify Memory Device (400h)](#identify-memory-device-400h)
* [Capacity Configuration and Label Storage (41h)](#capacity-configuration-and-label-storage-41h)
   * [Get Partition Info (4100h)](#get-partition-info-4100h)
   * [Set Partition Info (4101h)](#set-partition-info-4101h)
   * [Get LSA (4102h)](#get-lsa-4102h)
   * [Set LSA (4103h)](#set-lsa-4103h)
* [Health Info and Alerts (42h)](#health-info-and-alerts-42h)
   * [Get Health Info (4200h)](#get-health-info-4200h)
   * [Get Alert Configuration (4201h)](#get-alert-configuration-4201h)
   * [Set Alert Configuration (4202h)](#set-alert-configuration-4202h)
   * [Get Shutdown State (4203h)](#get-shutdown-state-4203h)
   * [Set Shutdown State (4204h)](#set-shutdown-state-4204h)
* [Sanitize and Media Operations (44h)](#sanitize-and-media-operations-44h)
   * [Sanitize (4400h)](#sanitize-4400h)
   * [Secure Erase (4401h)](#secure-erase-4401h)
* [Persistent Memory Data-at-rest Security (45h)](#persistent-memory-data-at-rest-security-45h)
   * [Get Security State (4500h)](#get-security-state-4500h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Thu Jun 20 08:29:07 AM PDT 2024 -->

<!--te-->

# Identify Memory Device (40h)

## Identify Memory Device (400h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_identify {
	char fw_revision[0x10];
	uint64_t total_capacity;
	uint64_t volatile_capacity;
	uint64_t persistent_capacity;
	uint64_t partition_align;
	uint16_t info_event_log_size;
	uint16_t warning_event_log_size;
	uint16_t failure_event_log_size;
	uint16_t fatal_event_log_size;
	uint32_t lsa_size;
	uint8_t poison_list_max_mer[3];
	uint16_t inject_poison_limit;
	uint8_t poison_caps;
	uint8_t qos_telemetry_caps;
	uint16_t dc_event_log_size;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_identify *ret);
</pre>

# Capacity Configuration and Label Storage (41h)

## Get Partition Info (4100h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_partition_info {
	uint64_t active_vmem;
	uint64_t active_pmem;
	uint64_t next_vmem;
	uint64_t next_pmem;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_partition_info *ret);
</pre>

## Set Partition Info (4101h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_set_partition_info {
	uint64_t volatile_capacity;
	uint8_t flags;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_set_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_set_partition_info *in);
</pre>


## Get LSA (4102h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_lsa {
	uint32_t offset;
	uint32_t length;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_lsa *ret);
</pre>

## Set LSA (4103h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_set_lsa {
	uint32_t offset;
	uint32_t rsvd;
	uint8_t data[];
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_set_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_set_lsa *in);
</pre>

# Health Info and Alerts (42h)

## Get Health Info (4200h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_health_info {
	uint8_t health_status;
	uint8_t media_status;
	uint8_t additional_status;
	uint8_t life_used;
	uint16_t device_temperature;
	uint32_t dirty_shutdown_count;
	uint32_t corrected_volatile_error_count;
	uint32_t corrected_persistent_error_count;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_health_info(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_health_info *ret);
</pre>

## Get Alert Configuration (4201h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_alert_config {
	uint8_t valid_alerts;
	uint8_t programmable_alerts;
	uint8_t life_used_critical_alert_threshold;
	uint8_t life_used_programmable_warning_threshold;
	uint16_t device_over_temperature_critical_alert_threshold;
	uint16_t device_under_temperature_critical_alert_threshold;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_alert_config *ret);
</pre>

## Set Alert Configuration (4202h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_set_alert_config {
	uint8_t valid_alert_actions;
	uint8_t enable_alert_actions;
	uint8_t life_used_programmable_warning_threshold;
	uint8_t rsvd1;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_set_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_set_alert_config *in);
</pre>

## Get Shutdown State (4203h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_shutdown_state {
	uint8_t state;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_shutdown_state(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_shutdown_state *ret);
</pre>

## Set Shutdown State (4204h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_set_shutdown_state {
	uint8_t state;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_set_shutdown_state(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_set_shutdown_state *in);
</pre>

# Sanitize and Media Operations (44h)

## Sanitize (4400h)

No payload.

Command name:

<pre>
int cxlmi_cmd_memdev_sanitize(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
</pre>

## Secure Erase (4401h)

No payload.

Command name:

<pre>
int cxlmi_cmd_memdev_secure_erase(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
</pre>


# Persistent Memory Data-at-rest Security (45h)

## Get Security State (4500h)

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_security_state {
	uint32_t security_state;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_security_state(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_security_state *ret);
</pre>


# Dynamic Capacity (48h)

## Get Dynamic Capacity Configuration (4800h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_get_dc_config_req {
	uint8_t region_cnt;
	uint8_t start_region_id;
};
</pre>

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_dc_config_rsp {
	uint8_t num_regions;
	uint8_t regions_returned;
	uint8_t rsvd1[6];
	struct {
		uint64_t base;
		uint64_t decode_len;
		uint64_t region_len;
		uint64_t block_size;
		uint32_t dsmadhandle;
		uint8_t flags;
		uint8_t rsvd2[3];
	} region_configs[];
};
</pre>
<pre>
struct cxlmi_cmd_memdev_get_dc_config_rsp_extra {
	uint32_t num_extents_supported;
	uint32_t num_extents_available;
	uint32_t num_tags_supported;
	uint32_t num_tags_available;
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_dc_config(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_get_dc_config_req *in,
			struct cxlmi_cmd_memdev_get_dc_config_rsp *ret,
			struct cxlmi_cmd_memdev_get_dc_config_rsp_extra *ret_extra);
</pre>

## Get Dynamic Capacity Extent List (4801h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_get_dc_extent_list_req {
	uint32_t extent_cnt;
	uint32_t start_extent_idx;
};
</pre>

Return payload:

<pre>
struct cxlmi_cmd_memdev_get_dc_extent_list_rsp {
	uint32_t num_extents_returned;
	uint32_t total_num_extents;
	uint32_t generation_num;
	uint8_t rsvd[4];
	struct {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t tag[0x10];
		uint16_t shared_seq;
		uint8_t rsvd[0x6];
	} extents[];
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_get_dc_extent_list(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_get_dc_extent_list_req *in,
			struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *ret);
</pre>

## Add Dynamic Capacity Response (4802h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_add_dyn_cap_response {
	uint32_t num_extents_updated;
	uint8_t flags;
	uint8_t rsvd1[3];
	struct {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t rsvd[8];
	} extents[];
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_add_dyn_cap_response(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_add_dyn_cap_response *in);
</pre>

## Release Dynamic Capacity (4803h)

Input payload:

<pre>
struct cxlmi_cmd_memdev_release_dyn_cap {
	uint32_t num_extents_updated;
	uint8_t flags;
	uint8_t rsvd1[3];
	struct {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t rsvd[8];
	} extents[];
};
</pre>

Command name:

<pre>
int cxlmi_cmd_memdev_release_dyn_cap(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_release_dyn_cap *in);
</pre>
