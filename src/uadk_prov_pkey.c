// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include "uadk_prov_pkey.h"

#define ECC_TYPE		5
#define CTX_ASYNC		1
#define CTX_SYNC		0
#define UADK_UNINIT		0
#define UADK_INIT_SUCCESS	1
#define UADK_INIT_FAIL		2
#define UADK_DEVICE_ERROR	3
#define KEYMGMT_TYPE		6
#define PROV_SUPPORT		1
#define SIGNATURE_TYPE		3
#define ASYM_CIPHER_TYPE	3

static int p_keymgmt_support_state[KEYMGMT_TYPE];
static int p_signature_support_state[SIGNATURE_TYPE];
static int p_asym_cipher_support_state[ASYM_CIPHER_TYPE];

/* Mapping between a flag and a name */
static const OSSL_ITEM encoding_nameid_map[] = {
	{ OPENSSL_EC_EXPLICIT_CURVE, OSSL_PKEY_EC_ENCODING_EXPLICIT },
	{ OPENSSL_EC_NAMED_CURVE, OSSL_PKEY_EC_ENCODING_GROUP },
};

static const OSSL_ITEM format_nameid_map[] = {
	{ (int)POINT_CONVERSION_UNCOMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED },
	{ (int)POINT_CONVERSION_COMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED },
	{ (int)POINT_CONVERSION_HYBRID, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID },
};

int uadk_prov_keymgmt_get_support_state(int alg_tag)
{
	return p_keymgmt_support_state[alg_tag];
}

static void uadk_prov_keymgmt_set_support_state(int alg_tag, int value)
{
	p_keymgmt_support_state[alg_tag] = value;
}

int uadk_prov_signature_get_support_state(int alg_tag)
{
	return p_signature_support_state[alg_tag];
}

static void uadk_prov_signature_set_support_state(int alg_tag, int value)
{
	p_signature_support_state[alg_tag] = value;
}

int uadk_prov_asym_cipher_get_support_state(int alg_tag)
{
	return p_asym_cipher_support_state[alg_tag];
}
static void uadk_prov_asym_cipher_set_support_state(int alg_tag, int value)
{
	p_asym_cipher_support_state[alg_tag] = value;
}

static int uadk_prov_ecc_get_hw_keybits(int bits)
{
	if (bits > ECC384BITS)
		return ECC521BITS;
	else if (bits > ECC320BITS)
		return ECC384BITS;
	else if (bits > ECC256BITS)
		return ECC320BITS;
	else if (bits > ECC192BITS)
		return ECC256BITS;
	else if (bits > ECC128BITS)
		return ECC192BITS;
	else
		return ECC128BITS;
}

void uadk_prov_ecc_fill_req(struct wd_ecc_req *req, unsigned int op,
		       void *in, void *out)
{
	req->op_type = op;
	req->src = in;
	req->dst = out;
}

int uadk_prov_ecc_get_rand(char *out, size_t out_len, void *usr)
{
	int count = GET_RAND_MAX_CNT;
	BIGNUM *k;
	int ret;

	if (!out) {
		fprintf(stderr, "out is NULL\n");
		return -1;
	}

	k = BN_new();
	if (!k)
		return -ENOMEM;

	do {
		ret = BN_priv_rand_range(k, usr);
		if (!ret) {
			fprintf(stderr, "failed to BN_priv_rand_range\n");
			ret = -EINVAL;
			goto err;
		}

		ret = BN_bn2binpad(k, (void *)out, (int)out_len);
		if (ret < 0) {
			ret = -EINVAL;
			fprintf(stderr, "failed to BN_bn2binpad\n");
			goto err;
		}
	} while (--count >= 0 && BN_is_zero(k));

	ret = 0;
	if (count < 0)
		ret = -1;
err:
	BN_free(k);

	return ret;
}

static void uadk_prov_init_dtb_param(void *dtb, char *start,
			   __u32 dsz, __u32 bsz, __u32 num)
{
	struct wd_dtb *tmp = dtb;
	char *buff = start;
	__u32 i = 0;

	while (i++ < num) {
		tmp->data = buff;
		tmp->dsize = dsz;
		tmp->bsize = bsz;
		tmp += 1;
		buff += bsz;
	}
}

int uadk_prov_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
				BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
# if OPENSSL_VERSION_NUMBER > 0x10101000L
	if (!EC_POINT_get_affine_coordinates(group, p, x, y, ctx))
		return -1;
# else
	if (!EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx))
		return -1;
# endif
	return 0;
}

int uadk_prov_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
		     BIGNUM *b, BN_CTX *ctx)
{
# if OPENSSL_VERSION_NUMBER > 0x10101000L
	if (!EC_GROUP_get_curve(group, p, a, b, ctx))
		return -1;
# else
	if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx))
		return -1;
# endif
	return 0;
}

static void uadk_prov_fill_ecc_cv_param(struct wd_ecc_curve *pparam,
			      struct curve_param *cv_param,
			      BIGNUM *g_x, BIGNUM *g_y)
{
	pparam->p.dsize = BN_bn2bin(cv_param->p, (void *)pparam->p.data);
	pparam->a.dsize = BN_bn2bin(cv_param->a, (void *)pparam->a.data);
	if (!pparam->a.dsize) {
		pparam->a.dsize = 1;
		pparam->a.data[0] = 0;
	}

	pparam->b.dsize = BN_bn2bin(cv_param->b, (void *)pparam->b.data);
	if (!pparam->b.dsize) {
		pparam->b.dsize = 1;
		pparam->b.data[0] = 0;
	}

	pparam->g.x.dsize = BN_bn2bin(g_x, (void *)pparam->g.x.data);
	pparam->g.y.dsize = BN_bn2bin(g_y, (void *)pparam->g.y.data);
	pparam->n.dsize = BN_bn2bin(cv_param->order, (void *)pparam->n.data);
}

static int uadk_prov_set_sess_setup_cv(const EC_GROUP *group,
			     struct wd_ecc_curve_cfg *cv)
{
	struct wd_ecc_curve *pparam = cv->cfg.pparam;
	struct curve_param *cv_param;
	BIGNUM *g_x, *g_y;
	int ret = -1;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (!ctx)
		return ret;

	BN_CTX_start(ctx);

	cv_param = OPENSSL_malloc(sizeof(struct curve_param));
	if (!cv_param)
		goto free_ctx;

	cv_param->p = BN_CTX_get(ctx);
	if (!cv_param->p)
		goto free_cv;

	cv_param->a = BN_CTX_get(ctx);
	if (!cv_param->a)
		goto free_cv;

	cv_param->b = BN_CTX_get(ctx);
	if (!cv_param->b)
		goto free_cv;

	g_x = BN_CTX_get(ctx);
	if (!g_x)
		goto free_cv;

	g_y = BN_CTX_get(ctx);
	if (!g_y)
		goto free_cv;

	ret = uadk_prov_get_curve(group, cv_param->p, cv_param->a, cv_param->b, ctx);
	if (ret)
		goto free_cv;

	cv_param->g = EC_GROUP_get0_generator(group);
	if (!cv_param->g)
		goto free_cv;

	ret = uadk_prov_get_affine_coordinates(group, cv_param->g, g_x, g_y, ctx);
	if (ret)
		goto free_cv;

	cv_param->order = EC_GROUP_get0_order(group);
	if (!cv_param->order)
		goto free_cv;

	uadk_prov_fill_ecc_cv_param(pparam, cv_param, g_x, g_y);
	cv->type = WD_CV_CFG_PARAM;
	ret = 0;

free_cv:
	OPENSSL_free(cv_param);
free_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

handle_t uadk_prov_ecc_alloc_sess(const EC_KEY *eckey, char *alg)
{
	char buff[UADK_ECC_MAX_KEY_BYTES * UADK_ECC_CV_PARAM_NUM];
	struct sched_params sch_p = {0};
	struct wd_ecc_sess_setup sp;
	struct wd_ecc_curve param;
	const EC_GROUP *group;
	const BIGNUM *order;
	int ret, key_bits;
	handle_t sess;

	uadk_prov_init_dtb_param(&param, buff, 0, UADK_ECC_MAX_KEY_BYTES,
				UADK_ECC_CV_PARAM_NUM);

	memset(&sp, 0, sizeof(sp));
	sp.cv.cfg.pparam = &param;
	group = EC_KEY_get0_group(eckey);
	ret = uadk_prov_set_sess_setup_cv(group, &sp.cv);
	if (ret) {
		fprintf(stderr, "failed to set_sess_setup_cv\n");
		return (handle_t)0;
	}

	order = EC_GROUP_get0_order(group);
	if (!order) {
		fprintf(stderr, "failed to get ecc order\n");
		return (handle_t)0;
	}

	key_bits = BN_num_bits(order);
	sp.alg = alg;
	sp.key_bits = uadk_prov_ecc_get_hw_keybits(key_bits);
	sp.rand.cb = uadk_prov_ecc_get_rand;
	sp.rand.usr = (void *)order;
	/* Use the default numa parameters */
	sch_p.numa_id = -1;
	sp.sched_param = &sch_p;
	sess = wd_ecc_alloc_sess(&sp);
	if (!sess)
		fprintf(stderr, "failed to alloc ecc sess\n");

	return sess;
}

void uadk_prov_ecc_cb(void *req_t)
{
	struct wd_ecc_req *req_new = (struct wd_ecc_req *)req_t;
	struct uadk_e_cb_info *cb_param;
	struct wd_ecc_req *req_origin;
	struct async_op *op;

	if (!req_new)
		return;

	cb_param = req_new->cb_param;
	if (!cb_param)
		return;

	req_origin = cb_param->priv;
	if (!req_origin)
		return;

	req_origin->status = req_new->status;

	op = cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		op->ret = 0;
		async_free_poll_task(op->idx, 1);
		async_wake_job(op->job);
	}
}

int uadk_prov_ecc_crypto(handle_t sess, struct wd_ecc_req *req, void *usr)
{
	struct uadk_e_cb_info cb_param;
	struct async_op op;
	int idx, ret;

	ret = async_setup_async_event_notification(&op);
	if (ret == 0) {
		fprintf(stderr, "failed to setup async event notification\n");
		return ret;
	}

	if (op.job == NULL) {
		ret = wd_do_ecc_sync(sess, req);
		if (ret)
			goto err;

		return UADK_P_SUCCESS;
	}

	cb_param.op = &op;
	cb_param.priv = req;
	req->cb = uadk_prov_ecc_cb;
	req->cb_param = &cb_param;
	req->status = -1;

	ret = async_get_free_task(&idx);
	if (ret == 0)
		goto err;

	op.idx = idx;
	do {
		ret = wd_do_ecc_async(sess, req);
		if (ret < 0 && ret != -EBUSY) {
			async_free_poll_task(op.idx, 0);
			goto err;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(usr, &op, ASYNC_TASK_ECC);
	if (!ret)
		goto err;

	if (req->status)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;

err:
	(void)async_clear_async_event_notification();
	return UADK_P_FAIL;
}

int uadk_prov_ecc_poll(void *ctx)
{
	unsigned int recv = 0;
	__u64 rx_cnt = 0;
	int expt = 1;
	int ret;

	do {
		ret = wd_ecc_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < PROV_RECV_MAX_CNT);

	fprintf(stderr, "failed to recv msg: timeout!\n");

	return -ETIMEDOUT;
}

static int set_group(OSSL_PARAM_BLD *bld, struct ec_gen_ctx *gctx)
{
	OSSL_PARAM *params = NULL;
	EC_GROUP *group = NULL;

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		fprintf(stderr, "failed to get params from bld\n");
		return UADK_P_FAIL;
	}

	group = EC_GROUP_new_from_params(params, gctx->libctx, NULL);
	if (group == NULL) {
		fprintf(stderr, "failed to get group from params\n");
		OSSL_PARAM_free(params);
		return UADK_P_FAIL;
	}

	if (gctx->gen_group)
		EC_GROUP_free(gctx->gen_group);

	gctx->gen_group = group;
	OSSL_PARAM_free(params);

	return UADK_P_SUCCESS;
}

static int check_curve_params(OSSL_PARAM_BLD *bld, struct ec_gen_ctx *gctx)
{
	if (gctx->p == NULL || gctx->a == NULL || gctx->b == NULL || gctx->order == NULL
		|| !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, gctx->p)
		|| !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, gctx->a)
		|| !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, gctx->b)
		|| !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER, gctx->order)) {
		fprintf(stderr, "failed to set curve params\n");
		return UADK_P_FAIL;
	}

	if (gctx->cofactor != NULL
		&& !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR, gctx->cofactor)) {
		fprintf(stderr, "failed to set cofactor\n");
		return UADK_P_FAIL;
	}

	if (gctx->seed != NULL
		&& !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED,
		gctx->seed, gctx->seed_len)) {
		fprintf(stderr, "failed to set seed\n");
		return UADK_P_FAIL;
	}

	if (gctx->gen == NULL
		|| !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR,
		gctx->gen, gctx->gen_len)) {
		fprintf(stderr, "failed to set gen params\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int ec_gen_set_group_from_params(struct ec_gen_ctx *gctx)
{
	OSSL_PARAM_BLD *bld;
	int ret = 0;

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		fprintf(stderr, "failed to OSSL_PARAM_BLD_new\n");
		return UADK_P_FAIL;
	}

	if (gctx->encoding != NULL
		&& !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING,
		gctx->encoding, 0)) {
		fprintf(stderr, "failed to set encoding\n");
		goto free_bld;
	}

	if (gctx->pt_format != NULL
		&& !OSSL_PARAM_BLD_push_utf8_string(bld,
		OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, gctx->pt_format, 0)) {
		fprintf(stderr, "failed to set point format\n");
		goto free_bld;
	}

	if (gctx->group_name != NULL) {
		if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
			gctx->group_name, 0)) {
			fprintf(stderr, "failed to set group name\n");
			goto free_bld;
		}
		/* Ignore any other parameters if there is a group name */
		ret = set_group(bld, gctx);
			goto free_bld;
	} else if (gctx->field_type != NULL) {
		if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
			gctx->field_type, 0)) {
			fprintf(stderr, "failed to set filed type\n");
			goto free_bld;
		}
	} else {
		/* No need to continue the setup */
		goto free_bld;
	}

	if (check_curve_params(bld, gctx) == 0)
		goto free_bld;

	ret = UADK_P_SUCCESS;

free_bld:
	OSSL_PARAM_BLD_free(bld);
	return ret;
}

static int ec_gen_assign_group(EC_KEY *ec, EC_GROUP *group)
{
	if (group == NULL) {
		fprintf(stderr, "invalid: ec group is NULL\n");
		return UADK_P_FAIL;
	}

	return EC_KEY_set_group(ec, group) > 0;
}

static int ossl_ec_encoding_name2id(const char *name)
{
	size_t i, sz;

	/* Return the default value if there is no name */
	if (name == NULL)
		return OPENSSL_EC_NAMED_CURVE;

	for (i = 0, sz = OSSL_NELEM(encoding_nameid_map); i < sz; i++) {
		if (OPENSSL_strcasecmp(name, encoding_nameid_map[i].ptr) == 0)
			return encoding_nameid_map[i].id;
	}

	return -1;
}

static int ossl_ec_pt_format_name2id(const char *name)
{
	size_t i, sz;

	/* Return the default value if there is no name */
	if (name == NULL)
		return (int)POINT_CONVERSION_UNCOMPRESSED;

	for (i = 0, sz = OSSL_NELEM(format_nameid_map); i < sz; i++) {
		if (OPENSSL_strcasecmp(name, format_nameid_map[i].ptr) == 0)
			return format_nameid_map[i].id;
	}

	return -1;
}

int uadk_prov_ecc_genctx_check(struct ec_gen_ctx *gctx, EC_KEY *ec)
{
	int ret;

	if (gctx->gen_group == NULL) {
		ret = ec_gen_set_group_from_params(gctx);
		if (ret == 0) {
			fprintf(stderr, "failed to set group from params\n");
			return UADK_P_FAIL;
		}
	} else {
		if (gctx->encoding) {
			/*
			 * If an encoding is specified, the encoding name is converted
			 * to an encoding flag and set into the key group.
			 */
			ret = ossl_ec_encoding_name2id(gctx->encoding);
			if (ret < 0) {
				fprintf(stderr, "failed to encoding name to id\n");
				return UADK_P_FAIL;
			}
			EC_GROUP_set_asn1_flag(gctx->gen_group, ret);
		}
		if (gctx->pt_format) {
			/*
			 * If a point format is specified, the point format name is converted
			 * to a point format flag and set into the key group
			 */
			ret = ossl_ec_pt_format_name2id(gctx->pt_format);
			if (ret < 0) {
				fprintf(stderr, "failed to point format name to id\n");
				return UADK_P_FAIL;
			}
			EC_GROUP_set_point_conversion_form(gctx->gen_group, ret);
		}
	}

	/* We must always assign a group, no matter what */
	ret = ec_gen_assign_group(ec, gctx->gen_group);
	if (ret == 0) {
		fprintf(stderr, "invalid: ec group is NULL\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static bool uadk_prov_support_algorithm(const char *alg)
{
	struct uacce_dev_list *list = wd_get_accel_list(alg);

	if (list) {
		wd_free_list_accels(list);
		return true;
	}

	return false;
}

void uadk_prov_keymgmt_alg(void)
{
	static const char * const keymgmt_alg[] = {"sm2"};
	__u32 i, size;
	bool sp;

	/* Enumerate keymgmt algs to check whether it is supported and set tags */
	size = ARRAY_SIZE(keymgmt_alg);
	for (i = 0; i < size; i++) {
		sp = uadk_prov_support_algorithm(*(keymgmt_alg + i));
		if (sp)
			uadk_prov_keymgmt_set_support_state(i, PROV_SUPPORT);
	}
}

void uadk_prov_signature_alg(void)
{
	static const char * const signature_alg[] = {"sm2"};
	__u32 i, size;
	bool sp;

	/* Enumerate keymgmt algs to check whether it is supported and set tags */
	size = ARRAY_SIZE(signature_alg);
	for (i = 0; i < size; i++) {
		sp = uadk_prov_support_algorithm(*(signature_alg + i));
		if (sp)
			uadk_prov_signature_set_support_state(i, PROV_SUPPORT);
	}
}

int uadk_prov_ecc_set_private_key(handle_t sess, const EC_KEY *eckey)
{
	unsigned char bin[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_key *ecc_key;
	const EC_GROUP *group;
	struct wd_dtb prikey;
	const BIGNUM *d;
	size_t degree;
	int buflen;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (!d) {
		fprintf(stderr, "private key not set\n");
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(eckey);
	if (!group) {
		fprintf(stderr, "failed to get ecc group\n");
		return UADK_P_FAIL;
	}

	degree = EC_GROUP_get_degree(group);
	buflen = BITS_TO_BYTES(degree);
	ecc_key = wd_ecc_get_key(sess);
	prikey.data = (void *)bin;
	prikey.dsize = BN_bn2binpad(d, bin, buflen);

	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

bool uadk_prov_is_all_zero(const unsigned char *data, size_t dlen)
{
	size_t i;

	for (i = 0; i < dlen; i++) {
		if (data[i])
			return false;
	}

	return true;
}

int uadk_prov_ecc_set_public_key(handle_t sess, const EC_KEY *eckey)
{
	unsigned char *point_bin = NULL;
	struct wd_ecc_point pubkey;
	struct wd_ecc_key *ecc_key;
	const EC_POINT *point;
	const EC_GROUP *group;
	int ret, len;

	point = EC_KEY_get0_public_key(eckey);
	if (!point) {
		fprintf(stderr, "pubkey not set!\n");
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(eckey);
	len = EC_POINT_point2buf(group, point, UADK_OCTET_STRING,
				 &point_bin, NULL);
	if (!len) {
		fprintf(stderr, "EC_POINT_point2buf error.\n");
		return UADK_P_FAIL;
	}

	len /= UADK_ECC_PUBKEY_PARAM_NUM;
	pubkey.x.data = (char *)point_bin + 1;
	pubkey.x.dsize = len;
	pubkey.y.data = pubkey.x.data + len;
	pubkey.y.dsize = len;
	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_pubkey(ecc_key, &pubkey);
	if (ret) {
		fprintf(stderr, "failed to set ecc pubkey\n");
		OPENSSL_free(point_bin);
		return UADK_P_FAIL;
	}

	OPENSSL_free(point_bin);

	return UADK_P_SUCCESS;
}

void uadk_prov_asym_cipher_alg(void)
{
	static const char * const asym_cipher_alg[] = {"sm2"};
	__u32 i, size;
	bool sp;

	/* Enumerate keymgmt algs to check whether it is supported and set tags */
	size = ARRAY_SIZE(asym_cipher_alg);
	for (i = 0; i < size; i++) {
		sp = uadk_prov_support_algorithm(*(asym_cipher_alg + i));
		if (sp)
			uadk_prov_asym_cipher_set_support_state(i, PROV_SUPPORT);
	}
}