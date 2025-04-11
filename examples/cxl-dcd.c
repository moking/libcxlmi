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


static int show_dc_extents(struct cxlmi_endpoint *ep);

static int issue_dynamic_capacity_operation(struct cxlmi_endpoint *ep, bool add)
{
	struct cxlmi_cmd_memdev_add_dc_response *req;
	uint64_t dpa, len;
	int i = 0, rc = -1;

	req = calloc(1, sizeof(*req) + sizeof(req->extents[0]) * 2);
	if (!req)
		return -1;

	req->updated_extent_list_size = 2;
	req->flags = 0;
	dpa = 0;
	len = 16 * 1024 * 1024;
	for (i = 0; i < 2; i++) {
		req->extents[i].start_dpa = dpa;
		req->extents[i].len = len;
		dpa += len;
	}

	if (add) {
		printf("Send response to device for accepting %d extents\n",
				req->updated_extent_list_size);
		rc = cxlmi_cmd_memdev_add_dc_response(ep, NULL, req);
	} else {
		struct cxlmi_cmd_memdev_release_dc *in;
		in = (struct cxlmi_cmd_memdev_release_dc *)req;
		printf("Notify device to release %d extents\n",
				req->updated_extent_list_size);
		rc = cxlmi_cmd_memdev_release_dc(ep, NULL, in);
	}

    free(req);
	return rc;
}

static int play_with_dcd(struct cxlmi_endpoint *ep)
{
	int i, rc;
	struct cxlmi_cmd_memdev_get_dc_config_req req = {
		.region_cnt = 8,
		.start_region_id = 0,
	};
	struct cxlmi_cmd_memdev_get_dc_config_rsp *out;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -1;

	rc = cxlmi_cmd_memdev_get_dc_config(ep, NULL, &req, out);
	if (rc) {
		rc = -1;
		goto free_out;
	}

	printf("Print out get DC config response: \n");
	printf("# of regions: %d\n", out->num_regions);
	printf("# of regions returned: %d\n", out->regions_returned);

	for (i = 0; i < out->regions_returned; i++) {
		printf("region %d: base %lu decode_len %lu region_len %lu block_size %lu\n",
				req.start_region_id + i,
				out->region_configs[i].base,
				out->region_configs[i].decode_len,
				out->region_configs[i].region_len,
				out->region_configs[i].block_size);
	}

	printf("# of extents supported: %d\n", out->num_extents_supported);
	printf("# of extents available: %d\n", out->num_extents_available);
	printf("# of tags supported: %d\n", out->num_tags_supported);
	printf("# of tags available: %d\n", out->num_tags_available);

	printf("Print out get DC config response: done\n");
	rc = 0;

	if (out->num_regions) {
		rc = show_dc_extents(ep);
		if (rc)
			goto free_out;
		rc = issue_dynamic_capacity_operation(ep, true);
		if (rc)
			goto free_out;
		rc = show_dc_extents(ep);
		if (rc)
			goto free_out;
		rc = issue_dynamic_capacity_operation(ep, false);
		if (rc)
			goto free_out;
		rc = show_dc_extents(ep);
	}

free_out:
	free(out);

	return rc;
}

static int show_dc_extents(struct cxlmi_endpoint *ep)
{
	int i, rc;
	uint64_t total_cnt, extent_returned = 0;
	bool first = true;

	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {
		.extent_cnt = 0,
		.start_extent_idx = 0,
	};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *out;

	out = calloc(1, sizeof(*out) + sizeof(out->extents[0]) * 8);
	if (!out)
		return -1;

	do {
		printf("Try to read %d extents starting with id: %d\n",
				req.extent_cnt, req.start_extent_idx);
		rc = cxlmi_cmd_memdev_get_dc_extent_list(ep, NULL, &req, out);
		if (rc)
			goto free_out;

		if (first) {
			total_cnt = out->total_num_extents;

			printf("# of total extents: %d\n", out->total_num_extents);
			printf("generation number: %d\n", out->generation_num);
			first = false;
		}

		printf("# of extents returned: %u\n", out->num_extents_returned);
		for (i = 0; i < out->num_extents_returned; i++) {
			printf("extent[%u] : [%lx, %lx]\n", i + req.start_extent_idx,
					out->extents[i].start_dpa,
					out->extents[i].len);
		}

		extent_returned += out->num_extents_returned;
		req.start_extent_idx = extent_returned;
		req.extent_cnt = total_cnt - extent_returned;
	} while (extent_returned < total_cnt);

free_out:
	free(out);

	return rc;
}

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
	printf("Get Supported Logs Response %d\n",
	       pl->num_supported_log_entries);

	for (i = 0; i < pl->num_supported_log_entries; i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			printf("\tCommand Effects Log (CEL) available\n");
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

static int test_fmapi_get_dcd_info(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_fmapi_get_dcd_info *out;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -1;

	rc = cxlmi_cmd_fmapi_get_dcd_info(ep, NULL, out);
	if (rc) {
		rc = -1;
		goto free_out;
	}

	printf("0x5600: FMAPI Get DCD Info Response:\n");
	printf("\t# hosts supported: %hhu\n", out->num_hosts);
	printf("\t# dc regions available/host: %hhu\n", out->num_supported_dc_regions);
	printf("\tcapacity_selection_policies: %hu\n", out->capacity_selection_policies);
	printf("\tcapacity_removal_policies: %hu\n", out->capacity_removal_policies);
	printf("\tsanitize_on_release: %hhu\n", out->sanitize_on_release_config_mask);
	printf("\ttotal dynamic capacity: %lu\n", out->total_dynamic_capacity);
	printf("\tregion 0 supported block sizes: %lu\n",
		out->region_0_supported_blk_sz_mask);
	printf("\tregion 1 supported block sizes: %lu\n",
		out->region_1_supported_blk_sz_mask);

free_out:
	free(out);
	return rc;
}

static int test_fmapi_get_host_dc_region_config(struct cxlmi_endpoint *ep)
{
	int i, rc;
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req dc_region_config_req = {
		.host_id = 0,
		.region_cnt = 5,
		.start_region_id = 0,
	};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp *dc_region_config_rsp;

	printf("0x5601: FMAPI Get DC Region Config Response:\n");
	dc_region_config_rsp = calloc(1, sizeof(*dc_region_config_rsp));

	if (!dc_region_config_rsp) {
		return -1;
	}

	rc = cxlmi_cmd_fmapi_get_dc_reg_config(ep, NULL, &dc_region_config_req, dc_region_config_rsp);
	if (rc) {
		rc = -1;
		goto free_out;
	}
	printf("\thost id: %hu\n", dc_region_config_rsp->host_id);
	printf("\tnum available regions: %hhu\n", dc_region_config_rsp->num_regions);
	printf("\tnum regions returned: %hhu\n", dc_region_config_rsp->regions_returned);
	printf("\tnum_extents_supported: %u\n", dc_region_config_rsp->num_extents_supported);
	printf("\tnum_extents_available: %u\n", dc_region_config_rsp->num_extents_available);
	printf("\tnum_tags_supported: %u\n", dc_region_config_rsp->num_tags_supported);

	for (i = 0; i < dc_region_config_rsp->regions_returned; i++) {
		printf("\t\tRegion %d:\n", i);
		printf("\t\t\tBase: %lu\n", dc_region_config_rsp->region_configs->base);
		printf("\t\t\tBlk_sz: %lu\n", dc_region_config_rsp->region_configs->block_size);
		printf("\t\t\tLen: %lu\n", dc_region_config_rsp->region_configs->region_len);
	}

free_out:
	free(dc_region_config_rsp);
	return rc;
}

static int print_ext_list(struct cxlmi_endpoint *ep,
						uint16_t host_id,
						uint32_t ext_cnt,
						uint32_t start_ext_ind)
{
	int i, rc;
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req;
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
	uint32_t ext_done = 0;

	req.host_id = host_id;
	req.extent_count = ext_cnt;
	req.start_ext_index = start_ext_ind;

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

	printf("\tHost Id: %hu\n", rsp->host_id);
	printf("\tStarting Extent Index: %u\n", rsp->start_ext_index);
	printf("\tNumber of Extents Returned: %u\n", rsp->extents_returned);
	printf("\tTotal Extents: %u\n", rsp->total_extents);
	printf("\tExtent List Generation Number: %u\n", rsp->list_generation_num);

	if (rsp->extents_returned == 0)
		goto free_out;

	for (i = 0; i < rsp->extents_returned; i++) {
		printf("\t\tExtent %d Info:\n", i);
		printf("\t\t\tStart DPA: %lu\n", rsp->extents[i].start_dpa);
		printf("\t\t\tLength: %lu\n", rsp->extents[i].len);
	}

	ext_done += rsp->extents_returned;
	if (ext_done < ext_cnt ||
		(ext_cnt == 0 && ext_done < rsp->total_extents))
		goto again;

free_out:
	free(rsp);
	return rc;

}

static int test_fmapi_get_dc_region_extent_list(struct cxlmi_endpoint *ep)
{
	printf("0x5603: FMAPI Get DC Region Extent List\n");
	return print_ext_list(ep, 0, 2, 0);
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
		rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls);
	}
	free(req);

	return rc;
}

static int test_fmapi_initiate_dc_add(struct cxlmi_endpoint *ep)
{
	int rc;

	printf("0x5604: FMAPI Initiate DC Add \n");
	rc = send_init_dc_add_remove_req(ep, false, 0, 128 * SIZE_MB);
	if (rc) {
		printf("0x5604: FMAPI Initiate DC Add FAILED with rc = %d\n",
	 rc);
		return rc;
	}
	printf("FMAPI Initiate DC Add Success\n");
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
	}

	return rc;
}

static int test_fmapi_initiate_dc_release(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_fmapi_initiate_dc_release_req* rls_req = NULL;
	struct cxlmi_cmd_fmapi_initiate_dc_add_req* add_req = NULL;

	printf("0x5605: FMAPI Initiate DC Release \n");

	rls_req = calloc(1, sizeof(*rls_req) + 2 * sizeof(rls_req->extents[0]));

	if (!rls_req) {
		return -1;
	}

	/* First try to release an extent that is not backed by DPA */
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 128;
	rls_req->extents[0].len = 256;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* RC should be 15 (CXL_MBOX_INVALID_PA) */
	if (!rc) {
		printf("\tWas able to release nonexistent extent!\n");
		rc = -1;
		goto cleanup;
	}

	/* Try to release misaligned block */
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 56;
	rls_req->extents[0].len = 7;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* RC should be 30 (CXL_MBOX_INVALID_EXTENT_LIST) */
	if (!rc) {
		printf("\tWas able to release misaligned extent!\n");
		rc = -1;
		goto cleanup;
	}

	/* Try to release overlapping extents */
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 2;
	rls_req->extents[0].start_dpa = 0;
	rls_req->extents[0].len = 128;
	rls_req->extents[1].start_dpa = 56;
	rls_req->extents[1].len = 184;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* RC should be 30 (CXL_MBOX_INVALID_EXTENT_LIST) */
	if (!rc) {
		printf("\tWas able to release overlapping extents!\n");
		rc = -1;
		goto cleanup;
	}

	/* Should still have the same extent previously added from testing initiate add */
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	/* Now release the valid extent added previously from testing initiate add */
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 0;
	rls_req->extents[0].len = 128;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* Extent list should be empty */
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	/* Add one extent (3 blocks long) and release the middle block
	 * Ext_0 = {[0 - 127] [128 - 255] [256 - 384]}
	 */
	add_req = calloc(1, sizeof(*add_req));
	if (!add_req) {
		rc = -1;
		goto cleanup;
	}

	add_req->host_id = 0;
	add_req->selection_policy = CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE;
	add_req->length = 0;
	add_req->ext_count = 1;
	add_req->extents[0].start_dpa = 0;
	add_req->extents[0].len = 384;

	rc = cxlmi_cmd_fmapi_initiate_dc_add(ep, NULL, add_req);
	if (rc) {
		rc = -1;
		goto cleanup;
	}

	/* Should have 1 extent [0 - 384]*/
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 128;
	rls_req->extents[0].len = 128;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	if (rc) {
		rc = -1;
		goto cleanup;
	}

	/* Releasing middle block should result in 2 extents.
	 * [0 - 127] [256 - 384]
	 */
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 4, 0)) {
		rc = -1;
		goto cleanup;
	}

	printf("FMAPI Initiate DC Release Success\n");

cleanup:
	free(rls_req);
	if (add_req) {
		free(add_req);
	}
	return rc;
}

static int test_fmapi_dc_add_reference(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_add_ref req;

	printf("0x5606: FMAPI DC Add Reference\n");
	if (cxlmi_cmd_fmapi_dc_add_reference(ep, NULL, &req)) {
		printf("FMAPI DC Add Reference Error\n");
		return -1;
	}

	printf("FMAPI DC Add Reference Success\n");
	return 0;
}

static int test_fmapi_dc_remove_reference(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_remove_ref req;

	printf("0x5607: FMAPI DC Remove Reference\n");
	if (cxlmi_cmd_fmapi_dc_remove_reference(ep, NULL, &req)) {
		printf("FMAPI DC Remove Reference Error\n");
		return -1;
	}

	printf("FMAPI DC Remove Reference Success\n");
	return 0;
}

static int test_fmapi_dc_list_tags(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {
		.start_idx = 0,
		.tags_count = 2
	};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp * rsp =
			calloc(1, sizeof(*rsp) + sizeof(rsp->tags_list[0]));

	if (!rsp) {
		return -1;
	}

	printf("0x5608: FMAPI DC List Tags\n");
	rc = cxlmi_cmd_fmapi_dc_list_tags(ep, NULL, &req, rsp);
	if (rc) {
		rc = -1;
		goto cleanup;
	}

	printf("\t Generation Num: %u\n", rsp->generation_num);
	printf("\t Max Tags: %u\n", rsp->total_num_tags);
	printf("\t Num Tags Returned: %u\n", rsp->num_tags_returned);

cleanup:
	free(rsp);
	return rc;
}

static int play_with_fmapi_dcd_management(struct cxlmi_endpoint *ep)
{
	if (test_fmapi_get_dcd_info(ep)
		|| test_fmapi_get_host_dc_region_config(ep)
		|| test_fmapi_get_dc_region_extent_list(ep)
		|| test_fmapi_initiate_dc_add(ep)
		|| test_fmapi_initiate_dc_release(ep)
		|| test_fmapi_dc_add_reference(ep)
		|| test_fmapi_dc_remove_reference(ep)
		|| test_fmapi_dc_list_tags(ep)
	)
		return -1;

	return 0;

}

void interactive_dc_operation(struct cxlmi_endpoint *ep)
{
	int ch;
	uint64_t dpa, size;
	int out = 0;
	int rc;

	while (!out) {
		printf("Exercise add/release DC extents(0: add; 1: release; 9: exit: ");
		scanf("%d", &ch);
		switch (ch) {
			case 0: 
				printf("Input dpa:size (in MB): ");
				scanf("%lu:%lu", &dpa, &size);
				dpa *= SIZE_MB;
				size *= SIZE_MB;
				rc = send_init_dc_add_remove_req(ep, false, dpa, size);
				if (rc == 0) {
					printf("Add extent succeed\n");
				}
				break;
			case 1:
				scanf("%lu:%lu", &dpa, &size);
				dpa *= SIZE_MB;
				size *= SIZE_MB;
				rc = send_init_dc_add_remove_req(ep, true, dpa, size);
				if (rc == 0) {
					printf("Release extent succeed\n");
				}
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
		if (ep_supports_op(ep, 0x4800))
			play_with_dcd(ep);

		if (ep_supports_op(ep, 0x5600)) {
			if (0)
				play_with_fmapi_dcd_management(ep);
			else
				interactive_dc_operation(ep);
		}
		cxlmi_close(ep);

		printf("-------------------------------------------------\n");
	}

exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
