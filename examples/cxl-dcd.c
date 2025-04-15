// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <libcxlmi.h>

#define SIZE_MB (1024 * 1024)

typedef enum CxlExtentSelectionPolicy {
    CXL_EXTENT_SELECTION_POLICY_FREE,
    CXL_EXTENT_SELECTION_POLICY_CONTIGUOUS,
    CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE,
    CXL_EXTENT_SELECTION_POLICY_ENABLE_SHARED_ACCESS,
    CXL_EXTENT_SELECTION_POLICY__MAX,
} CxlExtentSelectionPolicy;

typedef enum CxlExtentRemovalPolicy {
    CXL_EXTENT_REMOVAL_POLICY_TAG_BASED,
    CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE,
    CXL_EXTENT_REMOVAL_POLICY__MAX,
} CxlExtentRemovalPolicy;


static const uint8_t cel_uuid[0x10] = { 0x0d, 0xa9, 0xc0, 0xb5,
					0xbf, 0x41,
					0x4b, 0x78,
					0x8f, 0x79,
					0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17 };

static const uint8_t ven_dbg[0x10] = { 0x5e, 0x18, 0x19, 0xd9,
				       0x11, 0xa9,
				       0x40, 0x0c,
				       0x81, 0x1f,
				       0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86 };

static const uint8_t c_s_dump[0x10] = { 0xb3, 0xfa, 0xb4, 0xcf,
					0x01, 0xb6,
					0x43, 0x32,
					0x94, 0x3e,
					0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67 };

static const int maxlogs = 10; /* Only 7 in CXL r3.1, but let us leave room */
static int parse_supported_logs(struct cxlmi_cmd_get_supported_logs *pl,
				size_t *cel_size)
{
	int i, j;

	*cel_size = 0;
	/* 	printf("Get Supported Logs Response %d\n",
	       pl->num_supported_log_entries);
	 */
	for (i = 0; i < pl->num_supported_log_entries; i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			// printf("\tCommand Effects Log (CEL) available\n");
		}
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != ven_dbg[j])
				break;
		}
		if (j == 0x10)
			printf("\tVendor Debug Log available\n");
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != c_s_dump[j])
				break;
		}
		if (j == 0x10)
			printf("\tComponent State Dump Log available\n");
	}
	if (cel_size == 0) {
		return -1;
	}
	return 0;
}

static int support_opcode(struct cxlmi_endpoint *ep, int cel_size,
		uint16_t opcode, bool *supported)
{
	struct cxlmi_cmd_get_log_req in = {
		.offset = 0,
		.length = cel_size,
	};
	struct cxlmi_cmd_get_log_cel_rsp *ret;
	int i, rc;

	ret = calloc(1, sizeof(*ret) + cel_size);
	if (!ret)
		return -1;

	memcpy(in.uuid, cel_uuid, sizeof(in.uuid));
	rc = cxlmi_cmd_get_log_cel(ep, NULL, &in, ret);
	if (rc)
		goto done;

	for (i = 0; i < cel_size / sizeof(*ret); i++) {
		if (opcode == ret[i].opcode) {
			*supported = true;
			break;
		}
	}
done:
	free(ret);
	return rc;
}

static bool ep_supports_op(struct cxlmi_endpoint *ep, uint16_t opcode)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs *gsl;
	bool op_support = false;

	gsl = calloc(1, sizeof(*gsl) + maxlogs * sizeof(*gsl->entries));
	if (!gsl)
		return op_support;

	rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
	if (rc)
		return op_support;

	rc = parse_supported_logs(gsl, &cel_size);
	if (rc)
		return op_support;
	else {
		/* we know there is a CEL */
		rc = support_opcode(ep, cel_size, opcode, &op_support);
	}

	free(gsl);
	return op_support;
}

static uint32_t get_dc_extent_cnt(struct cxlmi_endpoint *ep, uint16_t host_id)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req;
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
	uint32_t cnt = 0;
	int rc;

	req.host_id = host_id;
	req.extent_count = 0;
	req.start_ext_index = 0;

	rsp = calloc(1, sizeof(*rsp)); 

	if (!rsp) {
		goto out;
	}

	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, NULL, &req, rsp);
	if (rc) {
		printf("get dc extents return error: %d\n", rc);
		goto free_out;
	}

	cnt = rsp->total_extents;
free_out:
	free(rsp);
out:
	return cnt;
}


/* 
 * remove:
 * 0: add;
 * 1: release
 * */
static int send_init_dc_add_remove_req(struct cxlmi_endpoint *ep, bool remove,
				       uint64_t start_dpa, uint64_t size)
{
	struct cxlmi_cmd_fmapi_initiate_dc_add_req* req;
	struct cxlmi_cmd_fmapi_initiate_dc_release_req *rls;
	int rc;

	req = calloc(1, sizeof(*req) + 1 * sizeof(req->extents[0]));
	if (!req) {
		return -1;
	}
	req->host_id = 0;
	req->selection_policy = CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE;// only policy currently supported in QEMU
	req->length = 0;
	req->ext_count = 1;

	req->extents[0].start_dpa = start_dpa;	
	req->extents[0].len = size;

	if (!remove)
		rc = cxlmi_cmd_fmapi_initiate_dc_add(ep, NULL, req);
	else {
		rls = (struct cxlmi_cmd_fmapi_initiate_dc_release_req *)req; 
		rls->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
		rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls);
	}
	free(req);

	sleep(1);

	return rc;
}

#define DO_COMPRESS_SIMULATION 1
#ifdef DO_COMPRESS_SIMULATION
static uint64_t get_device_capacity_cap(struct cxlmi_endpoint *ep)
{
	int rc;
	uint64_t cap = 0;
	struct cxlmi_cmd_fmapi_get_dcd_info *out;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -1;

	rc = cxlmi_cmd_fmapi_get_dcd_info(ep, NULL, out);
	if (rc) {
		rc = -1;
		goto free_out;
	}
	cap = out->total_dynamic_capacity;

free_out:
	free(out);

	return cap;
}

static int check_device_dc_capacity(struct cxlmi_endpoint *ep)
{
	int i, rc;
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req;
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
	uint32_t ext_done = 0, ext_cnt = 0;
	uint64_t total_cap = 0;

	req.host_id = 0;
	req.start_ext_index = 0;
	ext_cnt = get_dc_extent_cnt(ep, 0);
	if (!ext_cnt) {
		printf("Get zero extents due to empty list\n");
		return 0;
	}
	/* Fetch two extents at a time */
	req.extent_count = 2;

	rsp = calloc(1, sizeof(*rsp) + req.extent_count * sizeof(rsp->extents[0]));

	if (!rsp) {
		return -1;
	}

again:
	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, NULL, &req, rsp);
	if (rc) {
		rc = -1;
		goto free_out;
	}

	if (rsp->extents_returned == 0)
		goto free_out;

	for (i = 0; i < rsp->extents_returned; i++) {
		printf("\tExtent %d: [%luMB-%luMB]\n", i + ext_done,
	 rsp->extents[i].start_dpa / SIZE_MB, 
	 rsp->extents[i].start_dpa / SIZE_MB + rsp->extents[i].len / SIZE_MB);
		total_cap += rsp->extents[i].len;
	}

	ext_done += rsp->extents_returned;
	req.start_ext_index += rsp->extents_returned;
	if (ext_done < ext_cnt)
		goto again;

free_out:
	free(rsp);

	printf("Total capcity offered: %luMB, number of offering: %d\n\n",
	total_cap / SIZE_MB, ext_done);
	return rc;
}


/* This function returns extra capacity gained from compression */
static uint64_t do_compression(uint64_t max_cap, uint64_t used_cap)
{
	uint64_t size;
	int num;

	/* Do something here to simulate compression and get extra space */
	if (used_cap >= max_cap) {
		printf("Warning, capacity offered reach the cap!");
		return 0;
	}
	srand(time(NULL));
	num = (rand() % 5) + 1;
	printf("Compressing the data ...\n");
	sleep(num);
	size = num * 128 * SIZE_MB;
	if (size > max_cap - used_cap)
		size = max_cap - used_cap;
	printf("Get %luMB capacity from compression\n", size / SIZE_MB);

	return size;
}

void simulate_compression_operations(struct cxlmi_endpoint *ep)
{
	int rc;
	static int init_add = 1;
	uint64_t init_cap_offer;
	uint64_t cap_offered = 0, cap_gained, max_cap = 0;

	max_cap = get_device_capacity_cap(ep);
	if (max_cap == 0) {
		printf("Get device capacity failed\n");
		return;
	} else {
		printf("Max device capacity: %luMB\n", max_cap / SIZE_MB);
	}
	init_cap_offer = max_cap / 8;
	if (init_add) {
		printf("Assign initial capacity to host: %luMB\n",
	 init_cap_offer / SIZE_MB);
		rc = send_init_dc_add_remove_req(ep, false, 0, init_cap_offer);
		if (rc) {
			printf("Init allocation failed\n");
			return;
		}
		cap_offered = init_cap_offer;
		sleep(1);
		printf("Check capacity assigned: \n");
		check_device_dc_capacity(ep);
		printf("Assign initial capacity succeed\n");
		init_add = 0;
	}

	while (cap_offered < max_cap) {
		cap_gained = do_compression(max_cap, cap_offered);
		if (!cap_gained || cap_gained % (2 *SIZE_MB) != 0)
			break;
		printf("Offering %luMB to the host..\n", cap_gained / SIZE_MB);
		rc = send_init_dc_add_remove_req(ep, false, cap_offered, cap_gained);
		if (rc) {
			printf("Offering cap failed\n");
			return;
		}
		sleep(1);
		check_device_dc_capacity(ep);
		sleep(1);
		cap_offered += cap_gained;
	}
}
#else
void interactive_dc_operation(struct cxlmi_endpoint *ep)
{
	int ch;
	uint64_t dpa, size;
	int out = 0;
	int rc;
	static int init_add = 1;
	uint64_t init_size = (uint64_t)2048 * SIZE_MB;

	print_ext_list(ep, 0, 0, 0);
	if (init_add) {
		printf("assign initial capacity to host: %luMB\n", init_size / SIZE_MB);
		rc = send_init_dc_add_remove_req(ep, false, 0, init_size);
		if (rc) {
			printf("Init allocation failed\n");
			return;
		}
		printf("Assign initial capacity succeed\n");
	}
	while (!out) {
		printf("Exercise add/release DC extents(0: add; 1: release; 2: display extents; 9: exit): ");
		scanf("%d", &ch);
		switch (ch) {
			case 0: 
				printf("Input dpa:size (in MB): ");
				scanf("%lu:%lu", &dpa, &size);
				dpa *= SIZE_MB;
				size *= SIZE_MB;
				if (size == 0) {
					printf("Size cannot be 0\n");
					continue;
				}
				rc = send_init_dc_add_remove_req(ep, false, dpa, size);
				if (rc == 0) {
					printf("Add extent succeed\n");
					print_ext_list(ep, 0, 0, 0);
				}
				break;
			case 1:
				printf("Input dpa:size (in MB): ");
				scanf("%lu:%lu", &dpa, &size);
				dpa *= SIZE_MB;
				size *= SIZE_MB;
				if (size == 0) {
					printf("Size cannot be 0\n");
					continue;
				}
				rc = send_init_dc_add_remove_req(ep, true, dpa, size);
				if (rc == 0) {
					printf("Release extent succeed\n");
					print_ext_list(ep, 0, 0, 0);
				}
				break;
			case 2:
				print_ext_list(ep, 0, 0, 0);
				break;
			case 9: 
				out = 1;
				break;
			default:
			printf("Unkown input\n");
		}
		if (out)
			break;
	}
}
#endif

int main(int argc, char **argv)
{
	struct cxlmi_ctx *ctx;
	struct cxlmi_endpoint *ep, *tmp;
	int rc = EXIT_FAILURE;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		goto exit;
	}

	if (argc == 1) {
		int num_ep = cxlmi_scan_mctp(ctx);

		printf("scanning dbus...\n");

		if (num_ep < 0) {
			fprintf(stderr, "dbus scan error\n");
			goto exit_free_ctx;
		} else if (num_ep == 0) {
			printf("no endpoints found\n");
		} else
			printf("found %d endpoint(s)\n", num_ep);
	} else if (argc == 3) {
		unsigned int nid;
		uint8_t eid;

		nid = atoi(argv[1]);
		eid = atoi(argv[2]);
		printf("ep %d:%d\n", nid, eid);

		ep = cxlmi_open_mctp(ctx, nid, eid);
		if (!ep) {
			fprintf(stderr, "cannot open MCTP endpoint %d:%d\n", nid, eid);
			goto exit_free_ctx;
		}
	} else {
		fprintf(stderr, "must provide MCTP endpoint nid:eid touple\n");
		goto exit_free_ctx;
	}

	cxlmi_for_each_endpoint_safe(ctx, ep, tmp) {
		if (ep_supports_op(ep, 0x5600)) {
#ifdef DO_COMPRESS_SIMULATION
				simulate_compression_operations(ep);
#else
				interactive_dc_operation(ep);
#endif
		}
		cxlmi_close(ep);
	}

exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
