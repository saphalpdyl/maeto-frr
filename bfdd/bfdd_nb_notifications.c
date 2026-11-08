// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon northbound notifications.
 *
 * Copyright (C) 2026        Saphal K. Poudyal
 */

#include <zebra.h>

#include "lib/northbound.h"
#include "lib/log.h"
#include "lib/lib_errors.h"

#include "bfd.h"
#include "bfdd_nb.h"
#include "lib/iso.h"
#include "lib/yang.h"

static const char *bfd_state_yang_str(int state)
{
	switch (state) {
	case PTM_BFD_ADM_DOWN:
		return "admin-down";
	case PTM_BFD_DOWN:
		return "down";
	case PTM_BFD_INIT:
		return "init";
	case PTM_BFD_UP:
		return "up";

	default:
		return NULL;
	}
}

static const char *bfd_diag_yang_str(uint8_t diag)
{
	switch (diag) {
	case BD_OK:
		return "ok";
	case BD_CONTROL_EXPIRED:
		return "control-expired";
	case BD_ECHO_FAILED:
		return "echo-failed";
	case BD_NEIGHBOR_DOWN:
		return "neighbor-down";
	case BD_FORWARDING_RESET:
		return "forwarding-reset";
	case BD_PATH_DOWN:
		return "path-down";
	case BD_CONCATPATH_DOWN:
		return "concatenated-path-down";
	case BD_ADMIN_DOWN:
		return "administratively-down";
	case BD_REVCONCATPATH_DOWN:
		return "reverse-concat-path-down";

	default:
		return NULL;
	}
}

static LY_ERR bfd_notif_add_common(struct lyd_node *notif, const struct bfd_session *bs)
{
	LY_ERR err;

	/* local-discr */
	char buf[64];
	snprintf(buf, sizeof(buf), "%u", bs->discrs.my_discr);
	err = lyd_new_term(notif, NULL, "local-discr", buf, 0, NULL);
	if (err != LY_SUCCESS)
		goto error;

	/* remote-discr */
	if (bs->discrs.remote_discr != 0) {
		snprintf(buf, sizeof(buf), "%u", bs->discrs.remote_discr);
		err = lyd_new_term(notif, NULL, "remote-discr", buf, 0, NULL);
		if (err != LY_SUCCESS)
			goto error;
	}

	/* new-state */
	const char *new_state_yang_str = bfd_state_yang_str(bs->ses_state);
	if (new_state_yang_str) {
		snprintf(buf, sizeof(buf), "%s", new_state_yang_str);
		err = lyd_new_term(notif, NULL, "new-state", buf, 0, NULL);
		if (err != LY_SUCCESS)
			goto error;
	}

	/*
	 * state-change-reason
	 *
	 * The data plane protocol only reports the remote diagnostic, so the
	 * local reason is unknown for data plane sessions: omit the leaf.
	 */
	const char *state_change_reason_yang_str = NULL;

	if (bs->bdc == NULL)
		state_change_reason_yang_str = bfd_diag_yang_str(bs->local_diag);
	if (state_change_reason_yang_str) {
		snprintf(buf, sizeof(buf), "%s", state_change_reason_yang_str);
		err = lyd_new_term(notif, NULL, "state-change-reason", buf, 0, NULL);
		if (err != LY_SUCCESS)
			goto error;
	}

	/* time-of-last-state-change */
	char *ts = NULL; // State change timestamp is now.
	if (ly_time_time2str(time(NULL), NULL, &ts) == LY_SUCCESS) {
		err = lyd_new_term(notif, NULL, "time-of-last-state-change", ts, 0, NULL);
		free(ts);
		if (err != LY_SUCCESS)
			goto error;
	}

	/* dest-addr */
	char addr[INET6_ADDRSTRLEN];

	if (inet_ntop(bs->key.family, &bs->key.peer, addr, sizeof(addr))) {
		err = lyd_new_term(notif, NULL, "dest-addr", addr, 0, NULL);
		if (err != LY_SUCCESS)
			goto error;
	}


	/* vrf */
	err = lyd_new_term(notif, NULL, "vrf", bs->key.vrfname, 0, NULL);
	if (err != LY_SUCCESS)
		goto error;

	return LY_SUCCESS;

error:
	return err;
}

/*
 * XPath: /frr-bfdd:singlehop-notification
 */
static void bfd_notif_singlehop(const struct bfd_session *bs)
{
	const char *xpath = "/frr-bfdd:singlehop-notification";
	struct lyd_node *notif = NULL;
	LY_ERR err;

	err = lyd_new_path(NULL, ly_native_ctx, xpath, NULL, 0, &notif);
	if (err != LY_SUCCESS)
		goto error;

	err = bfd_notif_add_common(notif, bs);
	if (err != LY_SUCCESS)
		goto error;

	/* source-addr */
	if (memcmp(&bs->key.local, &zero_addr, sizeof(bs->key.local))) {
		char addr[INET6_ADDRSTRLEN];

		if (inet_ntop(bs->key.family, &bs->key.local, addr, sizeof(addr))) {
			err = lyd_new_term(notif, NULL, "source-addr", addr, 0, NULL);
			if (err != LY_SUCCESS)
				goto error;
		}
	}


	/* interface */
	if (bs->key.ifname[0]) {
		err = lyd_new_term(notif, NULL, "interface", bs->key.ifname, 0, NULL);
		if (err != LY_SUCCESS)
			goto error;
	}

	/* echo-enabled */
	err = lyd_new_term(notif, NULL, "echo-enabled",
			   CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO) ? "true" : "false", 0, NULL);
	if (err != LY_SUCCESS)
		goto error;

	/* Send notification with tree; sysrepo won't work with this*/
	nb_notification_tree_send(xpath, notif);

	lyd_free_all(notif);
	return;

error:
	flog_err(EC_LIB_LIBYANG, "%s: failed to build notification: %s", __func__,
		 ly_strerrcode(err));
	lyd_free_all(notif);
}
/*
 * XPath: /frr-bfdd:multihop-notification
 */
static void bfd_notif_multihop(const struct bfd_session *bs)
{
	const char *xpath = "/frr-bfdd:multihop-notification";
	struct lyd_node *notif = NULL;
	LY_ERR err;

	err = lyd_new_path(NULL, ly_native_ctx, xpath, NULL, 0, &notif);
	if (err != LY_SUCCESS)
		goto error;

	err = bfd_notif_add_common(notif, bs);
	if (err != LY_SUCCESS)
		goto error;

	/* source-addr */
	char addr[INET6_ADDRSTRLEN];

	if (inet_ntop(bs->key.family, &bs->key.local, addr, sizeof(addr))) {
		err = lyd_new_term(notif, NULL, "source-addr", addr, 0, NULL);
		if (err != LY_SUCCESS)
			goto error;
	}

	/* Send notification with tree; sysrepo won't work with this*/
	nb_notification_tree_send(xpath, notif);
	lyd_free_all(notif);
	return;


error:
	flog_err(EC_LIB_LIBYANG, "%s: failed to build notification: %s", __func__,
		 ly_strerrcode(err));
	lyd_free_all(notif);
}

void bfd_notif_session_state_change(const struct bfd_session *bs, int old_state)
{
	if (bs->ses_state == old_state)
		return;

	/* SBFD notifications are not supported for now. */
	if (bs->bfd_mode != BFD_MODE_TYPE_BFD)
		return;

	if (bs->key.mhop)
		bfd_notif_multihop(bs);
	else
		bfd_notif_singlehop(bs);
}
