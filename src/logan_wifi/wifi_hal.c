/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
* Material from the TR181 data model is Copyright (c) 2010-2017, Broadband Forum
* Licensed under the BSD-3 license
*/

/*
* This file includes material that is Copyright (c) 2020, Plume Design Inc.
* Licensed under the BSD-3 license
*/

/* Code in rxStatsInfo_callback and other callbacks is credited as follows:
Copyright (c) 2007, 2008	Johannes Berg
Copyright (c) 2007		Andy Lutomirski
Copyright (c) 2007		Mike Kershaw
Copyright (c) 2008-2009		Luis R. Rodriguez
Licensed under the ISC license
*/
#define MTK_IMPL
#define HAL_NETLINK_IMPL
#define _GNU_SOURCE /* needed for strcasestr */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include "wifi_hal.h"

#ifdef HAL_NETLINK_IMPL
#include <errno.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <unl.h>
#include "mtk_vendor_nl80211.h"
#endif

#include <ev.h>
#include <wpa_ctrl.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/sockios.h>

#define MAC_ALEN 6

#define MAX_BUF_SIZE 256
#define MAX_CMD_SIZE 256
#define MAX_SUB_CMD_SIZE 200

#define IF_NAME_SIZE 16
#define CONFIG_PREFIX "/nvram/hostapd"
#define ACL_PREFIX "/nvram/hostapd-acl"
#define DENY_PREFIX "/nvram/hostapd-deny"
//#define ACL_PREFIX "/tmp/wifi_acl_list" //RDKB convention
#define SOCK_PREFIX "/var/run/hostapd/wifi"
#define VAP_STATUS_FILE "/nvram/vap-status"
#define ESSID_FILE "/tmp/essid"
#define GUARD_INTERVAL_FILE "/nvram/guard-interval"
#define CHANNEL_STATS_FILE "/tmp/channel_stats"
#define DFS_ENABLE_FILE "/nvram/dfs_enable.txt"
#define VLAN_FILE "/nvram/hostapd.vlan"
#define PSK_FILE "/nvram/hostapd"
#define MCS_FILE "/tmp/MCS"
#define POWER_PERCENTAGE "/tmp/POWER"
#define MGMT_POWER_CTRL "/tmp/mgmt_power_ctrl"
/*LOGAN_DAT_FILE: may be different on customer's platform.*/
#define LOGAN_DAT_FILE "/etc/wireless/mediatek/mt7990.b"
#define ROM_LOGAN_DAT_FILE "/rom/etc/wireless/mediatek/mt7990.b"

#define NOACK_MAP_FILE "/tmp/NoAckMap"
#define RADIO_RESET_FILE "/nvram/radio_reset"

#define BRIDGE_NAME "brlan0"
#define BASE_PHY_INDEX 1
#define BASE_RADIO_INDEX 0

/*
   MAX_APS - Number of all AP available in system
   2x Home AP
   2x Backhaul AP
   2x Guest AP
   2x Secure Onboard AP
   2x Service AP

*/


#define MAX_APS MAX_NUM_RADIOS*5

#define PREFIX_WIFI2G	"ra"
#define PREFIX_WIFI5G	"rai"
#define PREFIX_WIFI6G	"rax"

#define PREFIX_SSID_2G	"RDKB_2G"
#define PREFIX_SSID_5G	"RDKB_5G"
#define PREFIX_SSID_6G	"RDKB_6G"

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wlan"
#endif

#define MAX_ASSOCIATED_STA_NUM 2007

//Uncomment to enable debug logs
//#define WIFI_DEBUG
enum {
	DEBUG_OFF = 0,
	DEBUG_ERROR = 1,
	DEBUG_WARN = 2,
	DEBUG_NOTICE = 3,
	DEBUG_INFO = 4
};
int wifi_debug_level = DEBUG_NOTICE;
#define wifi_debug(level, fmt, args...) \
{	\
	if (level <= wifi_debug_level)	\
	{ \
		printf("[%s][%d]"fmt"", __func__, __LINE__, ##args);	\
	} \
}

#ifdef WIFI_DEBUG
#define wifi_dbg_printf printf
#define WIFI_ENTRY_EXIT_DEBUG printf
#else
#define wifi_dbg_printf(format, args...)
#define WIFI_ENTRY_EXIT_DEBUG(format, args...)
#endif

#define HOSTAPD_CONF_0 "/nvram/hostapd0.conf"   //private-wifi-2g
#define HOSTAPD_CONF_1 "/nvram/hostapd1.conf"   //private-wifi-5g
#define HOSTAPD_CONF_4 "/nvram/hostapd4.conf"   //public-wifi-2g
#define HOSTAPD_CONF_5 "/nvram/hostapd5.conf"   //public-wifi-5g
#define DEF_HOSTAPD_CONF_0 "/usr/ccsp/wifi/hostapd0.conf"
#define DEF_HOSTAPD_CONF_1 "/usr/ccsp/wifi/hostapd1.conf"
#define DEF_HOSTAPD_CONF_4 "/usr/ccsp/wifi/hostapd4.conf"
#define DEF_HOSTAPD_CONF_5 "/usr/ccsp/wifi/hostapd5.conf"
#define DEF_RADIO_PARAM_CONF "/usr/ccsp/wifi/radio_param_def.cfg"
#define LM_DHCP_CLIENT_FORMAT   "%63d %17s %63s %63s"

#define HOSTAPD_HT_CAPAB "[LDPC][SHORT-GI-20][SHORT-GI-40][MAX-AMSDU-7935]"

#define BW_FNAME "/nvram/bw_file.txt"

#define PS_MAX_TID 16

#define MAX_CARD_INDEX 3

static wifi_radioQueueType_t _tid_ac_index_get[PS_MAX_TID] = {
	WIFI_RADIO_QUEUE_TYPE_BE,	  /* 0 */
	WIFI_RADIO_QUEUE_TYPE_BK,	  /* 1 */
	WIFI_RADIO_QUEUE_TYPE_BK,	  /* 2 */
	WIFI_RADIO_QUEUE_TYPE_BE,	  /* 3 */
	WIFI_RADIO_QUEUE_TYPE_VI,	  /* 4 */
	WIFI_RADIO_QUEUE_TYPE_VI,	  /* 5 */
	WIFI_RADIO_QUEUE_TYPE_VO,	  /* 6 */
	WIFI_RADIO_QUEUE_TYPE_VO,	  /* 7 */
	WIFI_RADIO_QUEUE_TYPE_BE,	  /* 8 */
	WIFI_RADIO_QUEUE_TYPE_BK,	  /* 9 */
	WIFI_RADIO_QUEUE_TYPE_BK,	  /* 10 */
	WIFI_RADIO_QUEUE_TYPE_BE,	  /* 11 */
	WIFI_RADIO_QUEUE_TYPE_VI,	  /* 12 */
	WIFI_RADIO_QUEUE_TYPE_VI,	  /* 13 */
	WIFI_RADIO_QUEUE_TYPE_VO,	  /* 14 */
	WIFI_RADIO_QUEUE_TYPE_VO,	  /* 15 */
};

typedef unsigned long long  u64;

/* Enum to define WiFi Bands */
typedef enum
{
	band_invalid = -1,
	band_2_4 = 0,
	band_5 = 1,
	band_6 = 2,
} wifi_band;

char* wifi_band_str[] = {
	"2G",
	"5G",
	"6G",
};

typedef enum {
	WIFI_MODE_A = 0x01,
	WIFI_MODE_B = 0x02,
	WIFI_MODE_G = 0x04,
	WIFI_MODE_N = 0x08,
	WIFI_MODE_AC = 0x10,
	WIFI_MODE_AX = 0x20,
	WIFI_MODE_BE = 0x40,
} wifi_ieee80211_Mode;

typedef enum {
	HT_BW_20,
	HT_BW_40,
} ht_config_bw;

typedef enum {
	VHT_BW_2040,
	VHT_BW_80,
	VHT_BW_160,
	VHT_BW_8080,
} vht_config_bw;

typedef enum {
	EHT_BW_20,
	EHT_BW_40,
	EHT_BW_80,
	EHT_BW_160,
	EHT_BW_320,
} eht_config_bw;

#ifdef WIFI_HAL_VERSION_3

// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

#ifndef ARRAY_AND_SIZE
#define ARRAY_AND_SIZE(x) (x),ARRAY_SIZE(x)
#endif /* ARRAY_AND_SIZE */

#define WIFI_ITEM_STR(key, str) {0, sizeof(str)-1, (int)key, (intptr_t)str}

typedef struct {
	int32_t value;
	int32_t param;
	intptr_t key;
	intptr_t data;
} wifi_secur_list;

typedef struct GNU_PACKED _wdev_extended_ap_metrics {
	unsigned int uc_tx;
	unsigned int uc_rx;
	unsigned int mc_tx;
	unsigned int mc_rx;
	unsigned int bc_tx;
	unsigned int bc_rx;
} wdev_extended_ap_metric;

typedef struct GNU_PACKED _wdev_ap_metric {
	unsigned char	bssid[6];
	unsigned char	cu;
	unsigned char 	ESPI_AC[4][3];
	wdev_extended_ap_metric ext_ap_metric;
} wdev_ap_metric;


static int util_unii_5g_centerfreq(const char *ht_mode, int channel);
static int util_unii_6g_centerfreq(const char *ht_mode, int channel);
wifi_secur_list *	   wifi_get_item_by_key(wifi_secur_list *list, int list_sz, int key);
wifi_secur_list *	   wifi_get_item_by_str(wifi_secur_list *list, int list_sz, const char *str);
char *				  wifi_get_str_by_key(wifi_secur_list *list, int list_sz, int key);
static int ieee80211_channel_to_frequency(int channel, int *freqMHz);
static void wifi_PrepareDefaultHostapdConfigs(void);
static void wifi_psk_file_reset();
static void wifi_dat_file_reset_by_radio(char radio_idx);
static int util_get_sec_chan_offset(int channel, const char* ht_mode);
int hostapd_raw_add_bss(int apIndex);
int hostapd_raw_remove_bss(int apIndex);

static inline int os_snprintf_error(size_t size, int res)
{
	return res < 0 || (unsigned int) res >= size;
}

/*type define the nl80211 call back func*/
typedef int (*mtk_nl80211_cb) (struct nl_msg *, void *);

/**
*struct mtk_nl80211_param
* init mtk nl80211 using parameters
* @sub_cmd: the cmd define in the mtk_vendor_nl80211.h.
* @if_type: now only support the NL80211_ATTR_IFINDEX/NL80211_ATTR_WIPHY.
* @if_idx: the index should match the interface or wiphy.
* Note: NA
**/
struct mtk_nl80211_param {
	unsigned int sub_cmd;
	int if_type;
	int if_idx;
};

/**
*struct mtk_nl80211_cb_data
* init mtk nl80211 call back parameters
* @out_buf: store the mtk vendor output msg for wifi hal buffer.
* @out_len: the output buffer length.
* Note: NA
**/
struct mtk_nl80211_cb_data {
	char * out_buf;
	unsigned int out_len;
};

/**
*mtk_nl80211_init
* init mtk nl80211 netlink and init the vendor msg common part.
* @nl: netlink, just init it.
* @msg: netlink message will alloc it.
*		the msg send success/fails is not free by app
*		only the nla_put etc api fails should use nlmsg_free.
* @msg_data: vendor data msg attr pointer.
* @param: init using interface and sub_cmd parameter.
*
*init the netlink context and mtk netlink vendor msg.
*
*return:
*	0: success
*	other: fail
**/

int mtk_nl80211_init(struct unl *nl, struct nl_msg **msg,
	struct nlattr **msg_data, struct mtk_nl80211_param *param) {
	/*sanity check here*/
	if (!nl || !param) {
		(void)fprintf(stderr,
		"[%s][%d]:nl(%p) or param(%p) is null, error!\n",
		__func__, __LINE__, nl, param);
		return -1;
	}
	/*if_type check*/
	if ( param->if_type != NL80211_ATTR_IFINDEX && param->if_type != NL80211_ATTR_WIPHY) {
		(void)fprintf(stderr,
			"[%s][%d]:if_type(0x%x) is not supported, only 0x%x and 0x%x supported.\n",
			__func__, __LINE__, param->if_type, NL80211_ATTR_IFINDEX, NL80211_ATTR_WIPHY);
		return -1;
	}
	/*init the nl*/
	if (unl_genl_init(nl, "nl80211") < 0) {
		(void)fprintf(stderr, "[%s][%d]::Failed to connect to nl80211\n",
			__func__, __LINE__);
		return -1;
	}
	/*init the msg*/
	*msg = unl_genl_msg(nl, NL80211_CMD_VENDOR, false);

	if (nla_put_u32(*msg, param->if_type, param->if_idx) ||
		nla_put_u32(*msg, NL80211_ATTR_VENDOR_ID, MTK_NL80211_VENDOR_ID) ||
		nla_put_u32(*msg, NL80211_ATTR_VENDOR_SUBCMD, param->sub_cmd)) {
		(void)fprintf(stderr,
		"[%s][%d]:Nla put error: if_type: 0x%x, if_idx: 0x%x, sub_cmd: 0x%x\n",
		__func__, __LINE__, param->if_type, param->if_idx, param->sub_cmd);
		goto err;
	}

	*msg_data = nla_nest_start(*msg, NL80211_ATTR_VENDOR_DATA);
	if (!*msg_data) {
		(void)fprintf(stderr, "[%s][%d]:Nla put NL80211_ATTR_VENDOR_DATA start error\n",
			__func__, __LINE__);
		goto err;
	}

	return 0;
err:
	nlmsg_free(*msg);
	unl_free(nl);
	return -1;
}

/**
*mtk_nl80211_send
* set the vendor cmd call back and sent the vendor msg.
* @nl: netlink.
* @msg: netlink message.
* @msg_data: vendor data msg attr pointer.
* @handler: if the msg have call back shoud add the call back func
*			the event msg will handle by the call back func(exp:get cmd)
*			other set it as NULL(exp:set cmd).
* @arg:call back func arg parameter.
*add end of the netlink msg, set the call back and send msg
*
*return:
*	0: success
*	other: fail
**/
int mtk_nl80211_send(struct unl *nl, struct nl_msg *msg,
	struct nlattr *msg_data, mtk_nl80211_cb handler, void *arg) {
	int ret = 0;
	/*sanity check*/
	if (!nl || !msg || !msg_data) {
		(void)fprintf(stderr,
		"[%s][%d]:nl(%p),msg(%p) or msg_data(%p) is null, error!\n",
		__func__, __LINE__, nl, msg, msg_data);
		return -1;
	}
	/*end the msg attr of vendor data*/
	nla_nest_end(msg, msg_data);
	/*send the msg and set call back */
	ret = unl_genl_request(nl, msg, handler, arg);
	if (ret)
		(void)fprintf(stderr, "send nl80211 cmd fails\n");
	return ret;
}

/**
*mtk_nl80211_deint
* deinit the netlink.
* @nl: netlink.
*
*free deinit the netlink.
*
*return:
*	0: success
**/

int mtk_nl80211_deint(struct unl *nl) {
	unl_free(nl);
	return 0;
}

wifi_secur_list * wifi_get_item_by_key(wifi_secur_list *list, int list_sz, int key)
{
	wifi_secur_list	*item;
	int	i;

	for (item = list,i = 0;i < list_sz; item++, i++) {
		if ((int)(item->key) == key) {
			return item;
		}
	}

	return NULL;
}

char * wifi_get_str_by_key(wifi_secur_list *list, int list_sz, int key)
{
	wifi_secur_list	*item = wifi_get_item_by_key(list, list_sz, key);

	if (!item) {
		return "";
	}

	return (char *)(item->data);
}

wifi_secur_list * wifi_get_item_by_str(wifi_secur_list *list, int list_sz, const char *str)
{
	wifi_secur_list	*item;
	int	i;

	for (item = list,i = 0;i < list_sz; item++, i++) {
		if (strcmp((char *)(item->data), str) == 0) {
			return item;
		}
	}

	return NULL;
}
#endif /* WIFI_HAL_VERSION_3 */


static char l1profile[32] = "/etc/wireless/l1profile.dat";
char main_prefix[MAX_NUM_RADIOS][IFNAMSIZ];
char ext_prefix[MAX_NUM_RADIOS][IFNAMSIZ];
#define MAX_SSID_LEN  64
char default_ssid[MAX_NUM_RADIOS][MAX_SSID_LEN];;
int radio_band[MAX_NUM_RADIOS];

static int array_index_to_vap_index(UINT radioIndex, int arrayIndex);
static int vap_index_to_array_index(int vapIndex, int *radioIndex, int *arrayIndex);


static int
get_value(const char *conf_file, const char *param, char *value, int len)
{
	FILE *fp;
	int ret = -1;
	int param_len = strlen(param);
	int buf_len;
	char buf[256];

	fp = fopen(conf_file, "r");
	if (!fp) {
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		buf_len = strlen(buf);
		if (buf[buf_len - 1] == '\n') {
			buf_len--;
			buf[buf_len] = '\0';
		}
		if ((buf_len > param_len) &&
			(strncmp(buf, param, param_len) == 0) &&
			(buf[param_len] == '=')) {

			if (buf_len == (param_len + 1)) {
				value[0] = '\0';
				ret = 0;
			} else {
				ret = snprintf(value, len, "%s", buf + (param_len + 1));
				if (os_snprintf_error(len, ret)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				}
			}
			fclose(fp);
			return ret;
		}
	}
	fclose(fp);
	return -1;
}

static int
get_value_by_idx(const char *conf_file, const char *param, int idx, char *value, int len)
{
	char buf[256];
	int ret;
	char *save_ptr = NULL;
	char *tok = NULL;

	ret = get_value(conf_file, param, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	tok = strtok_r(buf, ";", &save_ptr);
	do {
		if (idx == 0 || tok == NULL)
			break;
		else
			idx--;

		tok = strtok_r(NULL, ";", &save_ptr);
	} while (tok != NULL);

	if (tok) {
		ret = snprintf(value, len, "%s", tok);
		if (os_snprintf_error(len, ret)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return -1;
		}
	} else {
		ret = 0;
		value[0] = '\0';
	}

	return ret;
}


#ifdef HAL_NETLINK_IMPL
typedef struct {
	int id;
	struct nl_sock* socket;
	struct nl_cb* cb;
} Netlink;

static int mac_addr_aton(unsigned char *mac_addr, char *arg)
{
	unsigned char mac_addr_int[6]={};
	unsigned int recv;

	recv = sscanf(arg, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac_addr_int+0, mac_addr_int+1, mac_addr_int+2, mac_addr_int+3, mac_addr_int+4, mac_addr_int+5);

	if (recv != 6) {
		wifi_debug(DEBUG_ERROR, "sscanf format error.\n");
		return -1;
	}
	mac_addr[0] = mac_addr_int[0];
	mac_addr[1] = mac_addr_int[1];
	mac_addr[2] = mac_addr_int[2];
	mac_addr[3] = mac_addr_int[3];
	mac_addr[4] = mac_addr_int[4];
	mac_addr[5] = mac_addr_int[5];
	return 0;
}

static void mac_addr_ntoa(char *mac_addr, unsigned char *arg)
{
	unsigned int mac_addr_int[6]={};
	int res;

	mac_addr_int[0] = arg[0];
	mac_addr_int[1] = arg[1];
	mac_addr_int[2] = arg[2];
	mac_addr_int[3] = arg[3];
	mac_addr_int[4] = arg[4];
	mac_addr_int[5] = arg[5];
	res = snprintf(mac_addr, 20, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac_addr_int[0], mac_addr_int[1],mac_addr_int[2],mac_addr_int[3],mac_addr_int[4],mac_addr_int[5]);
	if (os_snprintf_error(20, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
	}
	return;
}

static int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	/* see 802.11ax D6.1 27.3.23.2 and Annex E */
	else if (freq == 5935)
		return 2;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq < 5950)
		return (freq - 5000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		/* see 802.11ax D6.1 27.3.23.2 */
		return (freq - 5950) / 5;
	else if (freq >= 58320 && freq <= 70200)
		return (freq - 56160) / 2160;
	else
		return 0;
}

static int initSock80211(Netlink* nl) {
	nl->socket = nl_socket_alloc();
	if (!nl->socket) {
		wifi_debug(DEBUG_ERROR, "Failing to allocate the  sock\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(nl->socket, 8192, 8192);

	if (genl_connect(nl->socket)) {
		wifi_debug(DEBUG_ERROR, "Failed to connect\n");
		nl_close(nl->socket);
		nl_socket_free(nl->socket);
		return -ENOLINK;
	}

	nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
	if (nl->id< 0) {
		wifi_debug(DEBUG_ERROR, "interface not found.\n");
		nl_close(nl->socket);
		nl_socket_free(nl->socket);
		return -ENOENT;
	}

	nl->cb = nl_cb_alloc(NL_CB_DEFAULT);
	if ((!nl->cb)) {
		wifi_debug(DEBUG_ERROR, "Failed to allocate netlink callback.\n");
		nl_close(nl->socket);
		nl_socket_free(nl->socket);
		return ENOMEM;
	}

	return nl->id;
}

static int nlfree(Netlink *nl)
{
	nl_cb_put(nl->cb);
	nl_close(nl->socket);
	nl_socket_free(nl->socket);
	return 0;
}

static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
	[NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
	[NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
	[NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED }
};

static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
};

static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
};

typedef struct _wifi_channelStats_loc {
	INT array_size;
	INT  ch_number;
	BOOL ch_in_pool;
	INT  ch_noise;
	BOOL ch_radar_noise;
	INT  ch_max_80211_rssi;
	INT  ch_non_80211_noise;
	INT  ch_utilization;
	ULLONG ch_utilization_total;
	ULLONG ch_utilization_busy;
	ULLONG ch_utilization_busy_tx;
	ULLONG ch_utilization_busy_rx;
	ULLONG ch_utilization_busy_self;
	ULLONG ch_utilization_busy_ext;
} wifi_channelStats_t_loc;

typedef struct wifi_device_info {
	INT  wifi_devIndex;
	UCHAR wifi_devMacAddress[6];
	CHAR wifi_devIPAddress[64];
	BOOL wifi_devAssociatedDeviceAuthentiationState;
	INT  wifi_devSignalStrength;
	INT  wifi_devTxRate;
	INT  wifi_devRxRate;
} wifi_device_info_t;

#endif

//For 5g Alias Interfaces
static BOOL Radio_flag = TRUE;
//wifi_setApBeaconRate(1, beaconRate);

BOOL multiple_set = FALSE;

struct params
{
	char * name;
	char * value;
};

static int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
	FILE *f;
	char *ptr = retBuf;
	int bufSize=retBufSize, bufbytes=0, readbytes=0, cmd_ret=0;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if((f = popen(cmd, "r")) == NULL) {
		wifi_debug(DEBUG_ERROR, "\npopen %s error\n", cmd);
		return RETURN_ERR;
	}

	while(!feof(f))
	{
		*ptr = 0;
		if(bufSize>=128) {
			bufbytes=128;
		} else {
			bufbytes=bufSize-1;
		}

		fgets(ptr,bufbytes,f);
		readbytes=strlen(ptr);

		if(!readbytes)
			break;

		bufSize-=readbytes;
		ptr += readbytes;
	}
	cmd_ret = pclose(f);
	retBuf[retBufSize-1]=0;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return cmd_ret >> 8;
}

INT radio_index_to_phy(int radioIndex)
{
	/* TODO */
	return radioIndex;
}

INT wifi_getMaxRadioNumber(INT *max_radio_num)
{
	char cmd[64] = {0};
	char buf[4] = {0};
	int res;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	res = snprintf(cmd, sizeof(cmd), "iw list | grep Wiphy | wc -l");
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	*max_radio_num = strtoul(buf, NULL, 10) > MAX_NUM_RADIOS ? MAX_NUM_RADIOS:strtoul(buf, NULL, 10);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

wifi_band radio_index_to_band(int radioIndex)
{
	return radio_band[radioIndex];
}

wifi_band wifi_index_to_band(int apIndex)
{
	char cmd[128] = {0};
	char buf[64] = {0};
	int nl80211_band = 0;
	int i = 0;
	int phyIndex = 0;
	int radioIndex = 0;
	int max_radio_num = 0;
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	radioIndex = apIndex % max_radio_num;
	phyIndex = radio_index_to_phy(radioIndex);
	while(i < 10){
		res = snprintf(cmd, sizeof(cmd), "iw phy%d info | grep 'Band .:' | tail -n 1 | tr -d ':\\n' | awk '{print $2}'", phyIndex);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		}
		_syscmd(cmd, buf, sizeof(buf));
		nl80211_band = strtol(buf, NULL, 10);
		if (nl80211_band == 1)
			band = band_2_4;
		else if (nl80211_band == 2)
			band = band_5;
		else if (nl80211_band == 4)	 // band == 3 is 60GHz
			band = band_6;

		if(band != band_invalid)
			break;

		i++;
		sleep(1);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return band;
}

static int wifi_hostapdRead(char *conf_file, char *param, char *output, int output_size)
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res = 0;

	res = snprintf(cmd, MAX_CMD_SIZE, "cat %s 2> /dev/null | grep \"^%s=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"",
		conf_file, param);

	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = _syscmd(cmd, buf, sizeof(buf));
	if ((res != 0) && (strlen(buf) == 0)) {
		printf("%s: _syscmd error!", __func__);
		return -1;
	}

	res = snprintf(output, output_size, "%s", buf);
	if (os_snprintf_error(output_size, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return 0;
}

static int wifi_hostapdWrite(char *conf_file, struct params *list, int item_count)
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;

	for (int i = 0; i < item_count; i++) {
		wifi_hostapdRead(conf_file, list[i].name, buf, sizeof(buf));
		if (strlen(buf) == 0) /*no such item, insert it*/
			res = snprintf(cmd, sizeof(cmd), "sed -i -e '$a %s=%s' %s", list[i].name, list[i].value, conf_file);
		else /*find the item, update it*/
			res = snprintf(cmd, sizeof(cmd), "sed -i \"s/^%s=.*/%s=%s/\" %s", list[i].name, list[i].name, list[i].value, conf_file);

		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		if(_syscmd(cmd, buf, sizeof(buf)))
			return -1;
	}

	return 0;
}

static int wifi_datfileRead(char *conf_file, char *param, char *output, int output_size)
{
	char cmd[MAX_CMD_SIZE] = {0};
	int res = 0;
	int len;

	res = snprintf(cmd, sizeof(cmd), "datconf -f %s get %s", conf_file, param);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}


	res = _syscmd(cmd, output, output_size);
	if ((res != 0) && (strlen(output) == 0)) {
		printf("%s: _syscmd error!", __func__);
		return -1;
	}

	len = strlen(output);
	if ((len > 0) && (output[len - 1] == '\n')) {
		output[len - 1] = '\0';
	}

	return 0;
}

static int wifi_datfileWrite(char *conf_file, struct params *list, int item_count)
{
	int res;
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};

	for (int i = 0; i < item_count; i++) {
		res = snprintf(cmd, sizeof(cmd), "datconf -f %s set %s \"%s\"", conf_file, list[i].name, list[i].value);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		if(_syscmd(cmd, buf, sizeof(buf)))
			return -1;
	}

	return 0;
}

static int wifi_l1ProfileRead(char *param, char *output, int output_size)
{
	int ret;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (!param || !output || (output_size <= 0)) {
		wifi_debug(DEBUG_ERROR, "invalid parameters");
		return RETURN_ERR;
	}

	ret = wifi_datfileRead(l1profile, param, output, output_size);
	if (ret != 0) {
		wifi_debug(DEBUG_ERROR, "wifi_datfileRead %s from %s failed, ret:%d", param, l1profile, ret);
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

static int wifi_CardProfileRead(int card_idx, char *param, char *output, int output_size)
{
	char option[64];
	char card_profile_path[64];
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (!param || !output || (output_size <= 0)) {
		wifi_debug(DEBUG_ERROR, "invalid parameters");
		return RETURN_ERR;
	}

	res = snprintf(option, sizeof(option), "INDEX%d_profile_path", card_idx);
	if (os_snprintf_error(sizeof(option), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	res = wifi_l1ProfileRead(option, card_profile_path, sizeof(card_profile_path));
	if (res != 0) {
		wifi_debug(DEBUG_ERROR, "wifi_l1ProfileRead %s failed, ret:%d", option,  res);
		return RETURN_ERR;
	}

	res = wifi_datfileRead(card_profile_path, param, output, output_size);
	if (res != 0) {
		wifi_debug(DEBUG_ERROR, "wifi_datfileRead %s from %s failed, ret:%d", param, card_profile_path, res);
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

static int wifi_BandProfileRead(int card_idx,
								int radio_idx,
								char *param,
								char *output,
								int output_size,
								char *default_value)
{
	char option[64];
	char band_profile_path[64];
	int ret, res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (!param || !output || (output_size <= 0)) {
		wifi_debug(DEBUG_ERROR, "invalid parameters");
		return RETURN_ERR;
	}

	res = snprintf(option, sizeof(option), "BN%d_profile_path", radio_idx);
	if (os_snprintf_error(sizeof(option), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret = wifi_CardProfileRead(card_idx, option, band_profile_path, sizeof(band_profile_path));
	if (ret != 0) {
		wifi_debug(DEBUG_ERROR, "wifi_CardProfileRead %s failed, ret:%d", option, ret);
		return RETURN_ERR;
	}

	ret = wifi_datfileRead(band_profile_path, param, output, output_size);
	if (ret != 0) {
		if (default_value) {
			res = snprintf(output, output_size, "%s", default_value);
			if (os_snprintf_error(output_size, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
		} else {
			output[0] = '\0';
		}
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//For Getting Current Interface Name from corresponding hostapd configuration
static int wifi_GetInterfaceName(int apIndex, char *interface_name)
{
	char config_file[128] = {0};
	int res;

	if (interface_name == NULL)
		return RETURN_ERR;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "interface", interface_name, 16);
	if (strlen(interface_name) == 0)
		return RETURN_ERR;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

static UCHAR get_bssnum_byindex(INT radio_index, UCHAR *bss_cnt)
{
	char interface_name[IF_NAME_SIZE] = {0};
	char cmd[MAX_BUF_SIZE]={'\0'};
	char buf[MAX_CMD_SIZE]={'\0'};
	UCHAR channel = 0;
	int res;

	if (wifi_GetInterfaceName(radio_index, interface_name) != RETURN_OK)
		return RETURN_ERR;
	/*interface name to channel number*/
	res = snprintf(cmd, sizeof(cmd),  "iw dev %s info | grep -i 'channel' | cut -d ' ' -f2", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	channel = atoi(buf);
	WIFI_ENTRY_EXIT_DEBUG("%s:channel=%d\n", __func__, channel);
	/*count dev number with the same channel*/
	res = snprintf(cmd, sizeof(cmd),  "iw dev | grep -i 'channel %d' | wc -l", channel);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	*bss_cnt = atoi(buf) - 1;/*1 for apcli interface*/
	WIFI_ENTRY_EXIT_DEBUG("%s:bss_cnt=%d\n", __func__, *bss_cnt);
	return RETURN_OK;
}

static int wifi_hostapdProcessUpdate(int apIndex, struct params *list, int item_count)
{
	char interface_name[16] = {0};
	if (multiple_set == TRUE)
		return RETURN_OK;
	char cmd[MAX_CMD_SIZE]="", output[32]="";
	FILE *fp;
	int i, res;
	//NOTE RELOAD should be done in ApplySSIDSettings
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	for (i=0; i<item_count; i++, list++) {
		res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s SET %s %s", interface_name, list->name, list->value);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		if ((fp = popen(cmd, "r"))==NULL) {
			perror("popen failed");
			return -1;
		}
		if (!fgets(output, sizeof(output), fp) || strncmp(output, "OK", 2)) {
			pclose(fp);
			perror("fgets failed");
			return -1;
		}
		pclose(fp);
	}
	return 0;
}

static int wifi_quick_reload_ap(int apIndex)
{
	char interface_name[IF_NAME_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;

	if (multiple_set == TRUE)
		return RETURN_OK;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s reload", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
		return RETURN_ERR;

	return RETURN_OK;
}

static int wifi_reloadAp(int apIndex)
{
	char interface_name[16] = {0};
	int res;

	if (multiple_set == TRUE)
		return RETURN_OK;
	char cmd[MAX_CMD_SIZE]="";
	char buf[MAX_BUF_SIZE]="";

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s reload", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s disable", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s enable", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
		return RETURN_ERR;

	return RETURN_OK;
}

INT File_Reading(CHAR *file, char *Value)
{
	FILE *fp = NULL;
	char buf[MAX_CMD_SIZE] = {0}, copy_buf[MAX_CMD_SIZE] ={0};
	int count = 0;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	fp = popen(file,"r");
	if(fp == NULL)
		return RETURN_ERR;

	if(fgets(buf,sizeof(buf) -1,fp) != NULL)
	{
		for(count=0;buf[count]!='\n';count++)
			copy_buf[count]=buf[count];
		copy_buf[count]='\0';
	}
	strcpy(Value,copy_buf);
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

void wifi_RestartHostapd_2G()
{
	int Public2GApIndex = 4;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	wifi_setApEnable(Public2GApIndex, FALSE);
	wifi_setApEnable(Public2GApIndex, TRUE);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartHostapd_5G()
{
	int Public5GApIndex = 5;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	wifi_setApEnable(Public5GApIndex, FALSE);
	wifi_setApEnable(Public5GApIndex, TRUE);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_2G()
{
	int PrivateApIndex = 0;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	wifi_setApEnable(PrivateApIndex, FALSE);
	wifi_setApEnable(PrivateApIndex, TRUE);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_5G()
{
	int Private5GApIndex = 1;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	wifi_setApEnable(Private5GApIndex, FALSE);
	wifi_setApEnable(Private5GApIndex, TRUE);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

static int writeBandWidth(int radioIndex,char *bw_value)
{
	char buf[MAX_BUF_SIZE];
	char cmd[MAX_CMD_SIZE];
	int res;

	res = snprintf(cmd, sizeof(cmd), "grep SET_BW%d %s", radioIndex, BW_FNAME);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (_syscmd(cmd, buf, sizeof(buf))) {
		res = snprintf(cmd, sizeof(cmd), "echo SET_BW%d=%s >> %s", radioIndex, bw_value, BW_FNAME);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		return RETURN_OK;
	}

	res = snprintf(cmd, sizeof(cmd), "sed -i 's/^SET_BW%d=.*$/SET_BW%d=%s/' %s",radioIndex,radioIndex,bw_value,BW_FNAME);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf,sizeof(buf));
	return RETURN_OK;
}

// Input could be "1Mbps"; "5.5Mbps"; "6Mbps"; "2Mbps"; "11Mbps"; "12Mbps"; "24Mbps"
INT wifi_setApBeaconRate(INT radioIndex,CHAR *beaconRate)
{
	struct params params={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	// Copy the numeric value
	if (strlen (beaconRate) >= 5) {
		strncpy(buf, beaconRate, strlen(beaconRate) - 4);
		buf[strlen(beaconRate) - 4] = '\0';
	} else if (strlen(beaconRate) > 0){
		strncpy(buf, beaconRate,sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
	} else
		return RETURN_ERR;

	params.name = "beacon_rate";
	// hostapd config unit is 100 kbps. To convert Mbps to 100kbps, the value need to multiply 10.
	if (strncmp(buf, "5.5", 3) == 0) {
		res = snprintf(buf, sizeof(buf), "55");
		if (os_snprintf_error(sizeof(buf), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		params.value = buf;
	} else {
		if (strlen(buf) >= (MAX_BUF_SIZE - 1)) {
			wifi_debug(DEBUG_ERROR, "not enough room in buf\n");
			return RETURN_ERR;
		}
		strncat(buf, "0", sizeof(buf) - strlen(buf) - 1);
		params.value = buf;
	}

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(radioIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getApBeaconRate(INT radioIndex, CHAR *beaconRate)
{
	char config_file[128] = {'\0'};
	char temp_output[MAX_BUF_SIZE] = {'\0'};
	char buf[128] = {'\0'};
	char cmd[128] = {'\0'};
	int rate = 0;
	int phyId = 0, res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == beaconRate)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "beacon_rate", buf, sizeof(buf));
	phyId = radio_index_to_phy(radioIndex);
	// Hostapd unit is 100kbps. To convert to 100kbps to Mbps, the value need to divide 10.
	if(strlen(buf) > 0) {
		if (strncmp(buf, "55", 2) == 0)
			res = snprintf(temp_output, sizeof(temp_output), "5.5Mbps");
		else {
			rate = strtol(buf, NULL, 10)/10;
			res = snprintf(temp_output, sizeof(temp_output), "%dMbps", rate);
		}
		if (os_snprintf_error(sizeof(temp_output), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else {
		// config not set, so we would use lowest rate as default
		res = snprintf(cmd, sizeof(cmd), "iw phy%d info | grep Bitrates -A1 | tail -n 1 | awk '{print $2}' | tr -d '.0\\n'", phyId);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		res = snprintf(temp_output, sizeof(temp_output), "%sMbps", buf);
		if (os_snprintf_error(sizeof(temp_output), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	}

	strncpy(beaconRate, temp_output, strlen(temp_output));
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_setLED(INT radioIndex, BOOL enable)
{
   return 0;
}
INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds)
{
   return RETURN_OK;
}
/**********************************************************************************
 *
 *  Wifi Subsystem level function prototypes
 *
**********************************************************************************/
//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string)   //RDKB
{
	int res;

	if(!output_string)
		return RETURN_ERR;
	res = snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}


/* wifi_factoryReset() function */
/**
* @description Clears internal variables to implement a factory reset of the Wi-Fi
* subsystem. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryReset()
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;

	/*delete running hostapd conf files*/
	wifi_dbg_printf("\n[%s]: deleting hostapd conf file.", __func__);
	res = snprintf(cmd, MAX_CMD_SIZE, "rm -rf /nvram/*.conf");
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	wifi_PrepareDefaultHostapdConfigs();
	wifi_psk_file_reset();

	memset(cmd, 0, MAX_CMD_SIZE);
	memset(buf, 0, MAX_BUF_SIZE);

	res = snprintf(cmd, MAX_CMD_SIZE, "systemctl restart hostapd.service");
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

/* wifi_factoryResetRadios() function */
/**
* @description Restore all radio parameters without touching access point parameters. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
*
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadios()
{
	if((RETURN_OK == wifi_factoryResetRadio(0)) && (RETURN_OK == wifi_factoryResetRadio(1)))
		return RETURN_OK;

	return RETURN_ERR;
}

ULONG get_radio_reset_cnt(int radioIndex)
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	ULONG reset_count = 0;
	int res;

	res = snprintf(cmd, MAX_CMD_SIZE, "cat %s 2> /dev/null | grep \"^reset%d=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"",
		RADIO_RESET_FILE, radioIndex);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	if (strlen(buf) == 0)
		return 0;
	else {
		reset_count = atol(buf);
		return reset_count;
	}
}
void update_radio_reset_cnt(int radioIndex)
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	ULONG reset_count = 0;
	int res;

	res = snprintf(cmd, MAX_CMD_SIZE, "cat %s 2> /dev/null | grep \"^reset%d=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"",
		RADIO_RESET_FILE, radioIndex);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}

	_syscmd(cmd, buf, sizeof(buf));

	if (strlen(buf) == 0)
		res = snprintf(cmd, sizeof(cmd), "sed -i -e '$a reset%d=1' %s", radioIndex, RADIO_RESET_FILE);
	else {
		reset_count = atol(buf);
		reset_count++;
		res = snprintf(cmd, sizeof(cmd), "sed -i \"s/^reset%d=.*/reset%d=%lu/\" %s", radioIndex, radioIndex, reset_count, RADIO_RESET_FILE);
	}
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}
	_syscmd(cmd, buf, sizeof(buf));
}

/* wifi_factoryResetRadio() function */
/**
* @description Restore selected radio parameters without touching access point parameters
*
* @param radioIndex - Index of Wi-Fi Radio channel
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadio(int radioIndex) 	//RDKB
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	wifi_dat_file_reset_by_radio(radioIndex);

	/*reset gi setting*/
	res = snprintf(cmd, sizeof(cmd), "echo 'Auto' > %s%d.txt", GUARD_INTERVAL_FILE, radioIndex);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	/*TBD: check mbss issue*/
	wifi_factoryResetAP(radioIndex);
	update_radio_reset_cnt(radioIndex);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

/* wifi_initRadio() function */
/**
* Description: This function call initializes the specified radio.
*  Implementation specifics may dictate the functionality since
*  different hardware implementations may have different initilization requirements.
* Parameters : radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1   - type INT
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_initRadio(INT radioIndex)
{
	//TODO: Initializes the wifi subsystem (for specified radio)
	return RETURN_OK;
}

static void
wifi_ParseProfile(void)
{
	int i, res;
	int max_radio_num = 0;
	int card_idx;
	int band_idx;
	int phy_idx = 0;
	int wireless_mode = 0;
	char buf[MAX_BUF_SIZE] = {0};
	char chip_name[12];
	char card_profile[MAX_BUF_SIZE] = {0};
	char band_profile[MAX_BUF_SIZE] = {0};

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	memset(main_prefix, 0, sizeof(main_prefix));
	memset(ext_prefix, 0, sizeof(ext_prefix));
	memset(default_ssid, 0, sizeof(default_ssid));
	for (i = 0; i < MAX_NUM_RADIOS; i++)
		radio_band[i] = band_invalid;

	if (wifi_getMaxRadioNumber(&max_radio_num) != RETURN_OK) {
		/* LOG */
	return;
	}

	for (card_idx = 0; card_idx < 3; card_idx++) {
		res = snprintf(buf, sizeof(buf), "INDEX%d", card_idx);
		if (os_snprintf_error(sizeof(buf), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}
		if (get_value(l1profile, buf, chip_name, sizeof(chip_name)) < 0) {
			break;
		}
		res = snprintf(buf, sizeof(buf), "INDEX%d_profile_path", card_idx);
		if (os_snprintf_error(sizeof(buf), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}
		if (get_value(l1profile, buf, card_profile, sizeof(card_profile)) < 0) {
			break;
		}
		for (band_idx = 0; band_idx < 3; band_idx++) {
			res = snprintf(buf, sizeof(buf), "BN%d_profile_path", band_idx);
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			if (get_value(card_profile, buf, band_profile, sizeof(band_profile)) < 0) {
				/* LOG */
				break;
			}

			res = snprintf(buf, sizeof(buf), "INDEX%d_main_ifname", card_idx);
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			if (get_value_by_idx(l1profile, buf, band_idx, main_prefix[phy_idx], IFNAMSIZ) < 0) {
				/* LOG */
			}

			res = snprintf(buf, sizeof(buf), "INDEX%d_ext_ifname", card_idx);
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			if (get_value_by_idx(l1profile, buf, band_idx, ext_prefix[phy_idx], IFNAMSIZ) < 0) {
				/* LOG */
			}

			if (get_value(band_profile, "SSID1", default_ssid[phy_idx], sizeof(default_ssid[phy_idx])) < 0) {
				/* LOG */
			}
			if (get_value(band_profile, "WirelessMode", buf, sizeof(buf)) < 0) {
				/* LOG */
			}

			wireless_mode = atoi(buf);
			switch (wireless_mode) {
			case 22:
			case 16:
			case 6:
			case 4:
			case 1:
				radio_band[phy_idx] = band_2_4;
				break;
			case 23:
			case 17:
			case 14:
			case 11:
			case 2:
				radio_band[phy_idx] = band_5;
				break;
			case 24:
			case 18:
				radio_band[phy_idx] = band_6;
				break;
			}
			phy_idx++;
		}
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

static void
wifi_PrepareDefaultHostapdConfigs(void)
{
	int radio_idx, res;
	int bss_idx;
	int ap_idx;
	char buf[MAX_BUF_SIZE] = {0};
	char config_file[MAX_SUB_CMD_SIZE] = {0};
	char ssid[MAX_BUF_SIZE] = {0};
	char interface[32] = {0};
	char ret_buf[MAX_BUF_SIZE] = {0};
	char psk_file[64] = {0};
	struct params params[3];

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	for (radio_idx = 0; radio_idx < MAX_NUM_RADIOS; radio_idx++) {

		for (bss_idx = 0; bss_idx < 5; bss_idx++) {
			ap_idx = array_index_to_vap_index(radio_idx, bss_idx);

			res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_idx);
			if (os_snprintf_error(sizeof(config_file), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			res = snprintf(buf, sizeof(buf), "cp /etc/hostapd-%s.conf %s", wifi_band_str[radio_idx], config_file);
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			_syscmd(buf, ret_buf, sizeof(ret_buf));

			if (radio_idx == band_2_4) {
				res = snprintf(ssid, sizeof(ssid), "%s_%d", PREFIX_SSID_2G, bss_idx);
				if (os_snprintf_error(sizeof(ssid), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return;
				}
				res = snprintf(interface, sizeof(interface), "%s%d", PREFIX_WIFI2G, bss_idx);
				if (os_snprintf_error(sizeof(interface), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return;
				}
			} else if (radio_idx == band_5) {
				res = snprintf(ssid, sizeof(ssid), "%s_%d", PREFIX_SSID_5G, bss_idx);
				if (os_snprintf_error(sizeof(ssid), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return;
				}
				res = snprintf(interface, sizeof(interface), "%s%d", PREFIX_WIFI5G, bss_idx);
				if (os_snprintf_error(sizeof(interface), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return;
				}
			} else if (radio_idx == band_6) {
				res = snprintf(ssid, sizeof(ssid), "%s_%d", PREFIX_SSID_6G, bss_idx);
				if (os_snprintf_error(sizeof(ssid), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return;
				}
				res = snprintf(interface, sizeof(interface), "%s%d", PREFIX_WIFI6G, bss_idx);
				if (os_snprintf_error(sizeof(interface), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return;
				}
			}

			/* fix wpa_psk_file path */
			res = snprintf(psk_file, sizeof(psk_file), "\\/nvram\\/hostapd%d.psk", ap_idx);
			if (os_snprintf_error(sizeof(psk_file), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}

			params[0].name = "ssid";
			params[0].value = ssid;
			params[1].name = "interface";
			params[1].value = interface;
			params[2].name = "wpa_psk_file";
			params[2].value = psk_file;

			wifi_hostapdWrite(config_file, params, 3);
		}
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

static void
wifi_BringDownInterfacesForRadio(int radio_idx)
{
	char cmd[MAX_BUF_SIZE] = {0};
	char ret_buf[MAX_BUF_SIZE]={'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw REMOVE %s", main_prefix[radio_idx]);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}
	_syscmd(cmd, ret_buf, sizeof(ret_buf));

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}


static void
wifi_BringDownInterfaces(void)
{
	int radio_idx;
	int band_idx;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	for (radio_idx = 0; radio_idx < MAX_NUM_RADIOS; radio_idx++) {
		band_idx = radio_index_to_band(radio_idx);
		if (band_idx < 0) {
			break;
		}
		wifi_BringDownInterfacesForRadio(radio_idx);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

static void wifi_dat_file_reset_by_radio(char radio_idx)
{
	char cmd[MAX_CMD_SIZE * 2] = {0};
	char ret_buf[MAX_BUF_SIZE] = {0};
	char rom_dat_file[MAX_SUB_CMD_SIZE]= {0};
	char dat_file[MAX_SUB_CMD_SIZE]= {0};
	int res;

	res = snprintf(rom_dat_file, sizeof(rom_dat_file), "%s%d.dat", ROM_LOGAN_DAT_FILE, radio_idx);
	if (os_snprintf_error(sizeof(rom_dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, radio_idx);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}
	res = snprintf(cmd, (MAX_CMD_SIZE * 2), "cp -rf %s %s", rom_dat_file, dat_file);
	if (os_snprintf_error((MAX_CMD_SIZE * 2), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}
	_syscmd(cmd, ret_buf, sizeof(ret_buf));

}

static void wifi_psk_file_reset()
{
	char cmd[MAX_CMD_SIZE] = {0};
	char ret_buf[MAX_BUF_SIZE] = {0};
	char psk_file[MAX_SUB_CMD_SIZE]= {0};
	char vap_idx = 0;
	int res;

	for (vap_idx = 0; vap_idx < MAX_APS; vap_idx++) {
		res = snprintf(psk_file, sizeof(psk_file), "%s%d.psk", PSK_FILE, vap_idx);
		if (os_snprintf_error(sizeof(psk_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}

		if (access(psk_file, F_OK) != 0) {
			res = snprintf(cmd, MAX_CMD_SIZE, "touch %s", psk_file);
			if (os_snprintf_error(MAX_CMD_SIZE, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			_syscmd(cmd, ret_buf, sizeof(ret_buf));
		} else {
			res = snprintf(cmd, MAX_CMD_SIZE, "echo '' > %s", psk_file);
			if (os_snprintf_error(MAX_CMD_SIZE, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}

			_syscmd(cmd, ret_buf, sizeof(ret_buf));
		}
	}
}

static void wifi_vap_status_reset()
{
	char cmd[MAX_CMD_SIZE] = {0};
	char ret_buf[MAX_BUF_SIZE] = {0};
	int radio_idx = 0;
	char bss_idx = 0;
	int res;

	if (access(VAP_STATUS_FILE, F_OK) != 0) {
		res = snprintf(cmd, MAX_CMD_SIZE, "touch %s", VAP_STATUS_FILE);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}
		_syscmd(cmd, ret_buf, sizeof(ret_buf));
	} else {
		res = snprintf(cmd, MAX_CMD_SIZE, "echo '' > %s", VAP_STATUS_FILE);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}
		_syscmd(cmd, ret_buf, sizeof(ret_buf));
	}

	memset(cmd, 0, MAX_CMD_SIZE);
	memset(ret_buf, 0, MAX_BUF_SIZE);

	for (radio_idx = 0; radio_idx < MAX_NUM_RADIOS; radio_idx++)
		for (bss_idx = 0; bss_idx < 5; bss_idx++) {
			res = snprintf(cmd, MAX_CMD_SIZE, "echo %s%d=0 >> %s", ext_prefix[radio_idx], bss_idx, VAP_STATUS_FILE);
			if (os_snprintf_error(MAX_CMD_SIZE, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			_syscmd(cmd, ret_buf, sizeof(ret_buf));
		}

}

static void wifi_radio_reset_count_reset()
{
	char cmd[MAX_CMD_SIZE] = {0};
	char ret_buf[MAX_BUF_SIZE] = {0};
	int res;

	if (access(VAP_STATUS_FILE, F_OK) != 0) {
		res = snprintf(cmd, MAX_CMD_SIZE, "touch %s", RADIO_RESET_FILE);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}
		_syscmd(cmd, ret_buf, sizeof(ret_buf));
	} else {
		res = snprintf(cmd, MAX_CMD_SIZE, "echo '' > %s", RADIO_RESET_FILE);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return;
		}
		_syscmd(cmd, ret_buf, sizeof(ret_buf));
	}
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()							//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	static int CallOnce = 1;
	//Not intitializing macfilter for Turris-Omnia Platform for now
	//macfilter_init();
	if (CallOnce) {
		wifi_ParseProfile();
		wifi_PrepareDefaultHostapdConfigs();
		wifi_psk_file_reset();
		//system("/usr/sbin/iw reg set US");
		system("systemctl start hostapd.service");
		sleep(2);

		wifi_vap_status_reset();
		wifi_radio_reset_count_reset();
		CallOnce = 0;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

/* wifi_reset() function */
/**
* Description: Resets the Wifi subsystem.  This includes reset of all AP varibles.
*  Implementation specifics may dictate what is actualy reset since
*  different hardware implementations may have different requirements.
* Parameters : None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_reset()
{

	wifi_BringDownInterfaces();
	sleep(2);

	//TODO: resets the wifi subsystem, deletes all APs
	system("systemctl stop hostapd.service");
	sleep(2);

	system("systemctl start hostapd.service");
	sleep(5);

	wifi_PrepareDefaultHostapdConfigs();
	wifi_psk_file_reset();
	sleep(2);

	wifi_vap_status_reset();

	return RETURN_OK;
}

/* wifi_down() function */
/**
* @description Turns off transmit power for the entire Wifi subsystem, for all radios.
* Implementation specifics may dictate some functionality since
* different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_down()
{
	//TODO: turns off transmit power for the entire Wifi subsystem, for all radios
	int max_num_radios = 0;
	wifi_getMaxRadioNumber(&max_num_radios);

	for (int radioIndex = 0; radioIndex < max_num_radios; radioIndex++)
		wifi_setRadioEnable(radioIndex, FALSE);

	return RETURN_OK;
}


/* wifi_createInitialConfigFiles() function */
/**
* @description This function creates wifi configuration files. The format
* and content of these files are implementation dependent.  This function call is
* used to trigger this task if necessary. Some implementations may not need this
* function. If an implementation does not need to create config files the function call can
* do nothing and return RETURN_OK.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_createInitialConfigFiles()
{
	//TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
	return RETURN_OK;
}

/* outputs the country code to a max 64 character string */
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
	int ret;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	ret = wifi_BandProfileRead(0, radioIndex, "CountryCode", output_string, 64, NULL);
	if (ret != 0) {
		wifi_debug(DEBUG_ERROR, "wifi_BandProfileRead CountryCode failed\n");
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
	/*Set wifi config. Wait for wifi reset to apply*/
	struct params params;
	char config_file[MAX_BUF_SIZE] = {0};
	int ret = 0, res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	if(NULL == CountryCode || strlen(CountryCode) >= 32 ) {
		printf("%s: input para error!!!\n", __func__);
		return RETURN_ERR;
	}

	if (!strlen(CountryCode)) {
		memcpy(CountryCode, "US", strlen("US")); /*default set the code to US*/
		CountryCode[2] = '\0';
	}

	params.name = "country_code";
	params.value = CountryCode;

	res = snprintf(config_file, MAX_BUF_SIZE, "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(MAX_BUF_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret = wifi_hostapdWrite(config_file, &params, 1);

	if (ret) {
		WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdWrite() return %d\n",
			__func__, ret);
	}

	ret = wifi_hostapdProcessUpdate(radioIndex, &params, 1);

	if (ret) {
		WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdProcessUpdate() return %d\n",
			__func__, ret);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getRadioChannelStats2(INT radioIndex, wifi_channelStats2_t *outputChannelStats2)
{
	char interface_name[16] = {0};
	char channel_util_file[64] = {0};
	char cmd[128] =  {0};
	char buf[128] = {0};
	char *line = NULL;
	char *param = NULL, *value = NULL;
	int read = 0, res;
	unsigned int ActiveTime = 0, BusyTime = 0, TransmitTime = 0;
	unsigned int preActiveTime = 0, preBusyTime = 0, preTransmitTime = 0;
	size_t len = 0;
	FILE *f = NULL;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "iw %s scan | grep signal | awk '{print $2}' | sort -n | tail -n1", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	outputChannelStats2->ch_Max80211Rssi = strtol(buf, NULL, 10);

	memset(cmd, 0, sizeof(cmd));
	memset(buf, 0, sizeof(buf));
	res = snprintf(cmd, sizeof(cmd), "iw %s survey dump | grep 'in use' -A6", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if ((f = popen(cmd, "r")) == NULL) {
		wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
		return RETURN_ERR;
	}

	read = getline(&line, &len, f);
	while (read != -1) {
		param = strtok(line, ":\t");
		value = strtok(NULL, " ");
		if(strstr(param, "frequency") != NULL) {
			outputChannelStats2->ch_Frequency = strtol(value, NULL, 10);
		}
		if(strstr(param, "noise") != NULL) {
			outputChannelStats2->ch_NoiseFloor = strtol(value, NULL, 10);
			outputChannelStats2->ch_Non80211Noise = strtol(value, NULL, 10);
		}
		if(strstr(param, "channel active time") != NULL) {
			ActiveTime = strtol(value, NULL, 10);
		}
		if(strstr(param, "channel busy time") != NULL) {
			BusyTime = strtol(value, NULL, 10);
		}
		if(strstr(param, "channel transmit time") != NULL) {
			TransmitTime = strtol(value, NULL, 10);
		}
		read = getline(&line, &len, f);
	}
	pclose(f);

	// The file should store the last active, busy and transmit time
	res = snprintf(channel_util_file, sizeof(channel_util_file), "%s%d.txt", CHANNEL_STATS_FILE, radioIndex);
	if (os_snprintf_error(sizeof(channel_util_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	f = fopen(channel_util_file, "r");
	if (f != NULL) {
		read = getline(&line, &len, f);
		preActiveTime = strtol(line, NULL, 10);
		read = getline(&line, &len, f);
		preBusyTime = strtol(line, NULL, 10);
		read = getline(&line, &len, f);
		preTransmitTime = strtol(line, NULL, 10);
		fclose(f);
	}

	outputChannelStats2->ch_ObssUtil = (BusyTime - preBusyTime)*100/(ActiveTime - preActiveTime);
	outputChannelStats2->ch_SelfBssUtil = (TransmitTime - preTransmitTime)*100/(ActiveTime - preActiveTime);

	f = fopen(channel_util_file, "w");
	if (f != NULL) {
		fprintf(f, "%u\n%u\n%u\n", ActiveTime, BusyTime, TransmitTime);
		fclose(f);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

/**********************************************************************************
 *
 *  Wifi radio level function prototypes
 *
**********************************************************************************/

//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output) //Tr181
{
	if (NULL == output)
		return RETURN_ERR;
	*output = MAX_NUM_RADIOS;

	return RETURN_OK;
}

//Get the total number of SSID entries in this wifi subsystem
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
	if (NULL == output)
		return RETURN_ERR;
	*output = MAX_APS;

	return RETURN_OK;
}

//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)	  //RDKB
{
	char interface_name[16] = {0};
	char buf[128] = {0}, cmd[128] = {0};
	int apIndex;
	int max_radio_num = 0;
	int res;

	if (NULL == output_bool)
		return RETURN_ERR;

	*output_bool = FALSE;

	wifi_getMaxRadioNumber(&max_radio_num);

	if (radioIndex >= max_radio_num)
		return RETURN_ERR;

	/* loop all interface in radio, if any is enable, reture true, else return false */
	for(apIndex = radioIndex; apIndex < MAX_APS; apIndex += max_radio_num)
	{
		if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
			continue;
		memset(cmd, 0, sizeof(cmd));
		res = snprintf(cmd, sizeof(cmd), "ifconfig %s 2> /dev/null | grep UP", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		*output_bool = _syscmd(cmd, buf, sizeof(buf)) ? FALSE : TRUE;
		if (*output_bool == TRUE)
			break;
	}

	return RETURN_OK;
}

typedef long time_t;
static time_t radio_up_time[MAX_NUM_RADIOS];

INT wifi_setRadioEnable(INT radioIndex, BOOL enable)
{
	char interface_name[16] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int apIndex;
	int max_radio_num = 0;
	int phyId = 0, res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	phyId = radio_index_to_phy(radioIndex);

	wifi_getMaxRadioNumber(&max_radio_num);

	if(enable == FALSE) {

		if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
			return RETURN_ERR;

		res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw REMOVE %s", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));
		memset(cmd, 0, sizeof(cmd));
		res = snprintf(cmd, MAX_CMD_SIZE, "ifconfig %s down", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		if(strncmp(buf, "OK", 2))
			wifi_debug(DEBUG_ERROR, "Could not detach %s from hostapd daemon", interface_name);
	} else {
		for (apIndex = radioIndex; apIndex < MAX_APS; apIndex += max_radio_num) {
			if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
				return RETURN_ERR;

			memset(cmd, 0, MAX_CMD_SIZE);
			memset(buf, 0, MAX_BUF_SIZE);

			res = snprintf(cmd, sizeof(cmd), "cat %s | grep %s | cut -d'=' -f2", VAP_STATUS_FILE, interface_name);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			_syscmd(cmd, buf, sizeof(buf));

			if(*buf == '1') {
				res = snprintf(cmd, MAX_CMD_SIZE, "ifconfig %s up", interface_name);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}
				_syscmd(cmd, buf, sizeof(buf));

				memset(cmd, 0, MAX_CMD_SIZE);
				memset(buf, 0, MAX_BUF_SIZE);

				res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw ADD bss_config=phy%d:/nvram/hostapd%d.conf",
							  phyId, apIndex);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}
				_syscmd(cmd, buf, sizeof(buf));

			}
		}
		time(&radio_up_time[radioIndex]);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the Radio enable status
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool)	//RDKB
{
	if (NULL == output_bool)
		return RETURN_ERR;

	return wifi_getRadioEnable(radioIndex, output_bool);
}

//Get the Radio Interface name from platform, eg "wlan0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string || radioIndex>=MAX_NUM_RADIOS || radioIndex<0)
		return RETURN_ERR;
	return wifi_GetInterfaceName(radioIndex, output_string);
}

int mtk_get_vow_info_callback(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_AP_VOW_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;
	struct vow_info *vow_info = NULL;
	struct mtk_nl80211_cb_data *cb_data = data;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		wifi_debug(DEBUG_ERROR, "get NL80211_ATTR_MAX fails\n");
		return err;
	}

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_AP_VOW_ATTR_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0){
			wifi_debug(DEBUG_ERROR, "get MTK_NL80211_VENDOR_AP_VOW_ATTR_MAX fails\n");
			return err;
		}

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_AP_VOW_GET_INFO]) {
			vow_info = (struct vow_info *)nla_data(vndr_tb[MTK_NL80211_VENDOR_ATTR_AP_VOW_GET_INFO]);
			memmove(cb_data->out_buf, vow_info, sizeof(struct vow_info));
		}
	}

	return 0;
}

INT mtk_wifi_set_air_time_management(
	INT apIndex, INT vendor_data_attr, mtk_nl80211_cb call_back,
	char* data, INT len, void *output)
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_AP_VOW;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put(msg, vendor_data_attr, len, data)) {
		wifi_debug(DEBUG_ERROR, "Nla put vendor_data_attr(%d) attribute error\n", vendor_data_attr);
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, call_back, output);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_INFO, "send cmd success.\n");

	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

//Get the ATM(Air Time Management) Capable.
INT wifi_getATMCapable(BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
    *output_bool = TRUE;

    return RETURN_OK;
}

INT wifi_setATMEnable(BOOL enable)
{
	int max_radio_num = 0;
	int radio_idx = 0;
	char dat_file[MAX_BUF_SIZE] = {0};
	int res;
	struct params params[2];

	wifi_getMaxRadioNumber(&max_radio_num);
	for (radio_idx = 0; radio_idx < max_radio_num; radio_idx++) {
		if (mtk_wifi_set_air_time_management
			(radio_idx, MTK_NL80211_VENDOR_ATTR_AP_VOW_ATF_EN_INFO,
			NULL, (char *)&enable, 1, NULL)!= RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_ATF_EN_INFO cmd fails\n");
			return RETURN_ERR;
		}

		if (mtk_wifi_set_air_time_management
			(radio_idx, MTK_NL80211_VENDOR_ATTR_AP_VOW_BW_EN_INFO,
			NULL, (char *)&enable, 1, NULL)!= RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_ATF_EN_INFO cmd fails\n");
			return RETURN_ERR;
		}

		params[0].name = "VOW_Airtime_Fairness_En";
		params[0].value = enable ? "1" : "0";
		params[1].name = "VOW_BW_Ctrl";
		params[1].value = enable ? "1" : "0";

		res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, radio_idx);
		if (os_snprintf_error(sizeof(dat_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_datfileWrite(dat_file, params, 2);
	}

    return RETURN_OK;
}

INT wifi_getATMEnable(BOOL *output_enable)
{
	int max_radio_num = 0;
	int radio_idx = 0;
	struct vow_info vow_info;
	struct vow_info get_vow_info;
	struct mtk_nl80211_cb_data cb_data;

	if (output_enable == NULL)
		return RETURN_ERR;

	wifi_getMaxRadioNumber(&max_radio_num);

	*output_enable = FALSE;

	memset(&vow_info, 0, sizeof(struct vow_info));

	cb_data.out_buf = (char *)&vow_info;
	cb_data.out_len = sizeof(struct vow_info);

	for (radio_idx = 0; radio_idx < max_radio_num; radio_idx++) {
		if (mtk_wifi_set_air_time_management
			(radio_idx, MTK_NL80211_VENDOR_ATTR_AP_VOW_GET_INFO,
			mtk_get_vow_info_callback, (char *)&get_vow_info, sizeof(struct vow_info), &cb_data)!= RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_GET_INFO cmd fails\n");
			return RETURN_ERR;
		}

		if (vow_info.atf_en == TRUE || vow_info.bw_en == TRUE) {
			*output_enable = TRUE;
			break;
		}
	}

    return RETURN_OK;
}

UINT apidx_to_group(INT apIndex)
{
	int max_radio_num = 0;
	unsigned int group = 0;

	wifi_getMaxRadioNumber(&max_radio_num);
    group = apIndex / max_radio_num + 5 * (apIndex % max_radio_num);

	return group;
}

INT wifi_setApATMAirTimePercent(INT apIndex, UINT ap_AirTimePercent)
{
	struct vow_group_en_param atc_en_param;
	struct vow_ratio_param radio_param;
	unsigned int group = 0;
	//BOOL ATM_enable = FALSE;

	if (ap_AirTimePercent < 5 || ap_AirTimePercent > 100) {
		wifi_debug(DEBUG_ERROR, "invalid ait time percent!\n");
		return RETURN_ERR;
	}

	/* mt7990 support 15 group now*/
	group = apidx_to_group(apIndex);

	if (group > 15) {
		wifi_debug(DEBUG_ERROR, "invalid group!\n");
		return RETURN_ERR;
	}

	atc_en_param.group = group;
	atc_en_param.en = 1;
	if (mtk_wifi_set_air_time_management
		(apIndex, MTK_NL80211_VENDOR_ATTR_AP_VOW_ATC_EN_INFO,
		NULL, (char *)&atc_en_param, sizeof(struct vow_group_en_param), NULL)!= RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_ATC_EN_INFO cmd fails\n");
		return RETURN_ERR;
	}

	radio_param.group = group;
	radio_param.ratio = ap_AirTimePercent;
	if (mtk_wifi_set_air_time_management
		(apIndex, MTK_NL80211_VENDOR_ATTR_AP_VOW_MIN_RATIO_INFO,
		NULL, (char *)&radio_param, sizeof(struct vow_ratio_param), NULL)!= RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_MIN_RATIO_INFO cmd fails\n");
		return RETURN_ERR;
	}

	if (mtk_wifi_set_air_time_management
		(apIndex, MTK_NL80211_VENDOR_ATTR_AP_VOW_MAX_RATIO_INFO,
		NULL, (char *)&radio_param, sizeof(struct vow_ratio_param), NULL)!= RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_MAX_RATIO_INFO cmd fails\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

INT wifi_getApATMAirTimePercent(INT apIndex, UINT *output_ap_AirTimePercent)
{
	unsigned int group = 0;
	struct vow_info get_vow_info, vow_info;
	struct mtk_nl80211_cb_data cb_data;

	if (output_ap_AirTimePercent == NULL)
		return RETURN_ERR;

	group = apidx_to_group(apIndex);
	if (group > 15) {
		wifi_debug(DEBUG_ERROR, "invalid group!\n");
		return RETURN_ERR;
	}

	memset(&vow_info, 0, sizeof(struct vow_info));
	memset(&get_vow_info, 0, sizeof(struct vow_info));

	cb_data.out_buf = (char *)&vow_info;
	cb_data.out_len = sizeof(struct vow_info);

	get_vow_info.group = group;

	if (mtk_wifi_set_air_time_management
		(apIndex, MTK_NL80211_VENDOR_ATTR_AP_VOW_GET_INFO,
		mtk_get_vow_info_callback, (char *)&get_vow_info, sizeof(struct vow_info), &cb_data)!= RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_AP_VOW_GET_INFO cmd fails\n");
		return RETURN_ERR;
	}

	*output_ap_AirTimePercent = vow_info.ratio;

	return RETURN_ERR;
}


//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) //RDKB
{
	// The formula to coculate bit rate is "Subcarriers * Modulation * Coding rate * Spatial stream / (Data interval + Guard interval)"
	// For max bit rate, we should always choose the best MCS
	char mode[64] = {0};
	char channel_bandwidth_str[64] = {0};
	UINT mode_map = 0;
	UINT num_subcarrier = 0;
	UINT code_bits = 0;
	float code_rate = 0;	// use max code rate
	int NSS = 0;
	UINT Symbol_duration = 0;
	UINT GI_duration = 0;
	wifi_guard_interval_t gi = wifi_guard_interval_auto;
	BOOL enable = FALSE;
	float bit_rate = 0;
	int ant_bitmap = 0, res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;

	wifi_getRadioEnable(radioIndex, &enable);
	if (enable == FALSE) {
		res = snprintf(output_string, 64, "0 Mb/s");
		if (os_snprintf_error(64, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		return RETURN_OK;
	}

	if (wifi_getRadioMode(radioIndex, mode, &mode_map) == RETURN_ERR) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioMode return error.\n");
		return RETURN_ERR;
	}

	if (wifi_getGuardInterval(radioIndex, &gi) == RETURN_ERR) {
		wifi_debug(DEBUG_ERROR, "wifi_getGuardInterval return error.\n");
		return RETURN_ERR;
	}

	if (gi == wifi_guard_interval_3200)
		GI_duration = 32;
	else if (gi == wifi_guard_interval_1600)
		GI_duration = 16;
	else if (gi == wifi_guard_interval_800)
		GI_duration = 8;
	else	// auto, 400
		GI_duration = 4;

	if (wifi_getRadioOperatingChannelBandwidth(radioIndex, channel_bandwidth_str) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioOperatingChannelBandwidth return error\n");
		return RETURN_ERR;
	}

	if (strstr(channel_bandwidth_str, "80+80") != NULL)
		memcpy(channel_bandwidth_str, "160", strlen("160"));

	if (mode_map & WIFI_MODE_AX) {
		if (strstr(channel_bandwidth_str, "160") != NULL)
			num_subcarrier = 1960;
		else if (strstr(channel_bandwidth_str, "80") != NULL)
			num_subcarrier = 980;
		else if (strstr(channel_bandwidth_str, "40") != NULL)
			num_subcarrier = 468;
		else if (strstr(channel_bandwidth_str, "20") != NULL)
			num_subcarrier = 234;
		code_bits = 10;
		code_rate = (float)5/6;
		Symbol_duration = 128;
		GI_duration = 8;/*HE no GI 400ns*/
	} else if (mode_map & WIFI_MODE_AC) {
		if (strstr(channel_bandwidth_str, "160") != NULL)
			num_subcarrier = 468;
		else if (strstr(channel_bandwidth_str, "80") != NULL)
			num_subcarrier = 234;
		else if (strstr(channel_bandwidth_str, "40") != NULL)
			num_subcarrier = 108;
		else if (strstr(channel_bandwidth_str, "20") != NULL)
			num_subcarrier = 52;
		code_bits = 8;
		code_rate = (float)5/6;
		Symbol_duration = 32;
	} else if (mode_map & WIFI_MODE_N) {
		if (strstr(channel_bandwidth_str, "160") != NULL)
			num_subcarrier = 468;
		else if (strstr(channel_bandwidth_str, "80") != NULL)
			num_subcarrier = 234;
		else if (strstr(channel_bandwidth_str, "40") != NULL)
			num_subcarrier = 108;
		else if (strstr(channel_bandwidth_str, "20") != NULL)
			num_subcarrier = 52;
		code_bits = 6;
		code_rate = (float)3/4;
		Symbol_duration = 32;
	} else if ((mode_map & WIFI_MODE_G || mode_map & WIFI_MODE_B) || mode_map & WIFI_MODE_A) {
		// mode b must run with mode g, so we output mode g bitrate in 2.4 G.
		res = snprintf(output_string, 64, "65 Mb/s");
		if (os_snprintf_error(64, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		return RETURN_OK;
	} else {
		res = snprintf(output_string, 64, "0 Mb/s");
		if (os_snprintf_error(64, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		return RETURN_OK;
	}

	// Spatial streams
	if (wifi_getRadioTxChainMask(radioIndex, &ant_bitmap) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioTxChainMask return error\n");
		return RETURN_ERR;
	}
	for (; ant_bitmap > 0; ant_bitmap >>= 1)
		NSS += ant_bitmap & 1;

	// multiple 10 is to align duration unit (0.1 us)
	bit_rate = (num_subcarrier * code_bits * code_rate * NSS) / (Symbol_duration + GI_duration) * 10;
	res = snprintf(output_string, 64, "%.1f Mb/s", bit_rate);
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("%s:num_subcarrier=%d, code_bits=%d, code_rate=%.3f, nss=%d, symbol time=%u, %.1f Mb/s\n",
		__func__, num_subcarrier, code_bits, code_rate, NSS, Symbol_duration + GI_duration, bit_rate);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)	//RDKB
{
	wifi_band band = band_invalid;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;

	band = wifi_index_to_band(radioIndex);

	memset(output_string, 0, 10);
	if (band == band_2_4)
		memcpy(output_string, "2.4GHz", strlen("2.4GHz"));
	else if (band == band_5)
		memcpy(output_string, "5GHz", strlen("5GHz"));
	else if (band == band_6)
		memcpy(output_string, "6GHz", strlen("6GHz"));
	else
		return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) //Tr181
{
	wifi_band band = band_invalid;
	int res = -1;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;
	band = wifi_index_to_band(radioIndex);

	if (band == band_2_4)
		res = snprintf(output_string, 64, "2.4GHz");
	else if (band == band_5)
		res = snprintf(output_string, 64, "5GHz");
	else if (band == band_6)
		res = snprintf(output_string, 64, "6GHz");

	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) //Tr181
{
	char cmd[128]={0};
	char buf[128]={0};
	char temp_output[128] = {0};
	wifi_band band;
	int phyId = 0, res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;

	band = wifi_index_to_band(radioIndex);
	if (band == band_2_4) {
		strncat(temp_output, "b,g,", sizeof(temp_output) - strlen(temp_output) - 1);
	} else if (band == band_5) {
		strncat(temp_output, "a,", sizeof(temp_output) - strlen(temp_output) - 1);
	}
	phyId = radio_index_to_phy(radioIndex);
	// ht capabilities
	res = snprintf(cmd, sizeof(cmd),  "iw phy%d info | grep '[^PHY|MAC|VHT].Capabilities' | head -n 1 | cut -d ':' -f2 | sed 's/^.//' | tr -d '\\n'", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) >= 4 && strncmp(buf, "0x00", 4) != 0) {
		if (strlen(temp_output) >= sizeof(temp_output) - 2)
			return RETURN_ERR;
		strncat(temp_output, "n,", sizeof(temp_output) - strlen(temp_output) - 1);
	}

	// vht capabilities
	if (band == band_5) {
		res = snprintf(cmd, sizeof(cmd),  "iw phy%d info | grep 'VHT Capabilities' | cut -d '(' -f2 | cut -c1-10 | tr -d '\\n'", phyId);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		if (strlen(buf) >= 10 && strncmp(buf, "0x00000000", 10) != 0) {
			if (strlen(temp_output) >= sizeof(temp_output) - 3)
				return RETURN_ERR;
			strcat(temp_output, "ac,");
		}
	}

	// he capabilities
	res = snprintf(cmd, sizeof(cmd),  "iw phy%d info | grep 'HE MAC Capabilities' | head -n 2 | tail -n 1 | cut -d '(' -f2 | cut -c1-6 | tr -d '\\n'", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) >= 6 && strncmp (buf, "0x0000", 6) != 0) {
		if (strlen(temp_output) >= sizeof(temp_output) - 3)
			return RETURN_ERR;
		strncat(temp_output, "ax,", sizeof(temp_output) - strlen(temp_output) - 1);
	}

	// eht capabilities
	res = snprintf(cmd, sizeof(cmd),  "iw phy%d info | grep 'EHT MAC Capabilities' | head -n 2 | tail -n 1 | cut -d '(' -f2 | cut -c1-6 | tr -d '\\n'", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) >= 6 && strncmp (buf, "0x0000", 6) != 0) {
		if (strlen(temp_output) >= sizeof(temp_output) - 3)
			return RETURN_ERR;
		strncat(temp_output, "be,", sizeof(temp_output) - strlen(temp_output) - 1);
	}

	// Remove the last comma
	if (strlen(temp_output) != 0)
		temp_output[strlen(temp_output)-1] = '\0';
	strncpy(output_string, temp_output, strlen(temp_output));
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//RDKB
{
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;

	if (radioIndex == 0) {
		res = snprintf(output_string, 64, "n");			   //"ht" needs to be translated to "n" or others
		if (os_snprintf_error(64, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		*gOnly = FALSE;
		*nOnly = TRUE;
		*acOnly = FALSE;
	} else {
		res = snprintf(output_string, 64, "ac");			  //"vht" needs to be translated to "ac"
		if (os_snprintf_error(64, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		*gOnly = FALSE;
		*nOnly = FALSE;
		*acOnly = FALSE;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

enum WIFI_MODE {
	WMODE_INVALID = 0,
	WMODE_A = 1 << 0,
	WMODE_B = 1 << 1,
	WMODE_G = 1 << 2,
	WMODE_GN = 1 << 3,
	WMODE_AN = 1 << 4,
	WMODE_AC = 1 << 5,
	WMODE_AX_24G = 1 << 6,
	WMODE_AX_5G = 1 << 7,
	WMODE_AX_6G = 1 << 8,
	WMODE_BE_24G = 1 << 9,
	WMODE_BE_5G = 1 << 10,
	WMODE_BE_6G = 1 << 11,
	/*
	 * total types of supported wireless mode,
	 * add this value once yow add new type
	 */
	WMODE_COMP = 12,
};

#define RADIO_MODE_LEN 32

int get_radio_mode_handler(struct nl_msg *msg, void *cb)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	unsigned int *phymode;
	int err = 0;
	struct mtk_nl80211_cb_data *cb_data = cb;

	if (!msg || !cb_data) {
		wifi_debug(DEBUG_ERROR, "msg(%p) or cb_data(%p) is null,error.\n", msg, cb_data);
		return NL_SKIP;
	}

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		wifi_debug(DEBUG_ERROR, "nla_parse radio nl80211 msg fails,error.\n");
		return NL_SKIP;
	}

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return NL_SKIP;

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_WMODE]) {
			phymode = (unsigned int *)nla_data(vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_WMODE]);

			memset(cb_data->out_buf, 0, cb_data->out_len);
			memmove(cb_data->out_buf, phymode, sizeof(unsigned int));
		}
	} else
		wifi_debug(DEBUG_ERROR, "No Stats from driver.\n");

	return NL_OK;
}

void phymode_to_puremode(INT radioIndex, CHAR *output_string, UINT *pureMode, UINT phymode)
{
	wifi_band band;
	unsigned char radio_mode_tem_len;
	int res;

	band = wifi_index_to_band(radioIndex);
	// puremode is a bit map
	*pureMode = 0;
	memset(output_string, 0, RADIO_MODE_LEN);

	radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);

	switch (band) {
	case band_2_4:
		if (phymode & WMODE_B) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "b,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_B;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "g,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_G;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_GN) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "n,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_N;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_AX_24G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "ax,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_AX;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_BE_24G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "be,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_BE;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		break;
	case band_5:
		if (phymode & WMODE_A) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "a,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_A;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_AN) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "n,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_N;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_AC) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "ac,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_AC;
		}
		if (phymode & WMODE_AX_5G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "ax,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_AX;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_BE_5G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "be,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_BE;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		break;
	case band_6:
		if (phymode & WMODE_AX_6G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "ax,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_AX;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		if (phymode & WMODE_BE_6G) {
			res = snprintf(output_string + strlen(output_string), radio_mode_tem_len, "%s", "be,");
			if (os_snprintf_error(radio_mode_tem_len, res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return;
			}
			*pureMode |= WIFI_MODE_BE;
			radio_mode_tem_len = RADIO_MODE_LEN - strlen(output_string);
		}
		break;
	default:
		fprintf(stderr, "%s band_idx invalid\n", __func__);
		break;
	}

	/* Remove the last comma */
	if (strlen(output_string) != 0)
		output_string[strlen(output_string)-1] = '\0';

}

INT wifi_getRadioMode(INT radioIndex, CHAR *output_string, UINT *pureMode)
{
	unsigned int phymode;
	char interface_name[IF_NAME_SIZE] = {0};
	int ret = -1;
	unsigned int if_idx = 0;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct mtk_nl80211_cb_data cb_data;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string || NULL == pureMode)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", interface_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/
	if (nla_put_u16(msg, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_WMODE, 0)) {
		wifi_debug(DEBUG_ERROR, "Nla put GET_RUNTIME_INFO_GET_WMODE attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	cb_data.out_buf = (char *)&phymode;
	cb_data.out_len = sizeof(unsigned int);

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, get_radio_mode_handler, &cb_data);

	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);

	phymode_to_puremode(radioIndex, output_string, pureMode, phymode);
	wifi_debug(DEBUG_INFO,"send cmd success\n");

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

// Set the radio operating mode, and pure mode flag.
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s_%s_%d_%d:%d\n",__func__,channelMode,nOnlyFlag,gOnlyFlag,__LINE__);
	if (strcmp (channelMode,"11A") == 0)
	{
		writeBandWidth(radioIndex,"20MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11a (5GHz)\n");
	}
	else if (strcmp (channelMode,"11NAHT20") == 0)
	{
		writeBandWidth(radioIndex,"20MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11n-20MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11NAHT40PLUS") == 0)
	{
		writeBandWidth(radioIndex,"40MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
		printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11NAHT40MINUS") == 0)
	{
		writeBandWidth(radioIndex,"40MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
		printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11ACVHT20") == 0)
	{
		writeBandWidth(radioIndex,"20MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11ac-20MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11ACVHT40PLUS") == 0)
	{
		writeBandWidth(radioIndex,"40MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
		printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11ACVHT40MINUS") == 0)
	{
		writeBandWidth(radioIndex,"40MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
		printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11ACVHT80") == 0)
	{
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"80MHz");
		printf("\nChannel Mode is 802.11ac-80MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11ACVHT160") == 0)
	{
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"160MHz");
		printf("\nChannel Mode is 802.11ac-160MHz(5GHz)\n");
	}
	else if (strcmp (channelMode,"11B") == 0)
	{
		writeBandWidth(radioIndex,"20MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11b(2.4GHz)\n");
	}
	else if (strcmp (channelMode,"11G") == 0)
	{
		writeBandWidth(radioIndex,"20MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11g(2.4GHz)\n");
	}
	else if (strcmp (channelMode,"11NGHT20") == 0)
	{
		writeBandWidth(radioIndex,"20MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11n-20MHz(2.4GHz)\n");
	}
	else if (strcmp (channelMode,"11NGHT40PLUS") == 0)
	{
		writeBandWidth(radioIndex,"40MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
		printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
	}
	else if (strcmp (channelMode,"11NGHT40MINUS") == 0)
	{
		writeBandWidth(radioIndex,"40MHz");
		wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
		printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
	}
	else
	{
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

typedef enum _RT_802_11_PHY_MODE {
	PHY_11BG_MIXED = 0,
	PHY_11B = 1,
	PHY_11A = 2,
	PHY_11ABG_MIXED = 3,
	PHY_11G = 4,
	PHY_11ABGN_MIXED = 5,	/* both band   5 */
	PHY_11N_2_4G = 6,		/* 11n-only with 2.4G band	  6 */
	PHY_11GN_MIXED = 7,		/* 2.4G band	  7 */
	PHY_11AN_MIXED = 8,		/* 5G  band	   8 */
	PHY_11BGN_MIXED = 9,	/* if check 802.11b.	  9 */
	PHY_11AGN_MIXED = 10,	/* if check 802.11b.	  10 */
	PHY_11N_5G = 11,		/* 11n-only with 5G band				11 */
	PHY_11VHT_N_ABG_MIXED = 12, /* 12 -> AC/A/AN/B/G/GN mixed */
	PHY_11VHT_N_AG_MIXED = 13, /* 13 -> AC/A/AN/G/GN mixed  */
	PHY_11VHT_N_A_MIXED = 14, /* 14 -> AC/AN/A mixed in 5G band */
	PHY_11VHT_N_MIXED = 15, /* 15 -> AC/AN mixed in 5G band */
	PHY_11AX_24G = 16,
	PHY_11AX_5G = 17,
	PHY_11AX_6G = 18,
	PHY_11AX_24G_6G = 19,
	PHY_11AX_5G_6G = 20,
	PHY_11AX_24G_5G_6G = 21,
	PHY_11BE_24G = 22,
	PHY_11BE_5G = 23,
	PHY_11BE_6G = 24,
	PHY_11BE_24G_6G = 25,
	PHY_11BE_5G_6G = 26,
	PHY_11BE_24G_5G_6G = 27,
	PHY_MODE_MAX,
} RT_802_11_PHY_MODE;

unsigned int puremode_to_wireless_mode(INT radioIndex, UINT pureMode)
{
	int band_idx = 0;
	unsigned char wireless_mode = PHY_MODE_MAX;

	band_idx = radio_index_to_band(radioIndex);

	switch (band_idx) {
	case band_2_4:
		if (pureMode == (WIFI_MODE_G | WIFI_MODE_N))
			wireless_mode = PHY_11GN_MIXED;
		if (pureMode == (WIFI_MODE_B | WIFI_MODE_G | WIFI_MODE_N))
			wireless_mode = PHY_11BGN_MIXED;
		if (pureMode & WIFI_MODE_AX)
			wireless_mode = PHY_11AX_24G;
		if (pureMode & WIFI_MODE_BE)
			wireless_mode = PHY_11BE_24G;
		break;
	case band_5:
		if (pureMode == WIFI_MODE_N)
			wireless_mode = PHY_11N_5G;
		if ((pureMode == WIFI_MODE_AC) || (pureMode == (WIFI_MODE_N | WIFI_MODE_AC)))
			wireless_mode = PHY_11VHT_N_MIXED;
		if (pureMode == (WIFI_MODE_A | WIFI_MODE_N | WIFI_MODE_AC))
			wireless_mode = PHY_11VHT_N_A_MIXED;
		if (pureMode & WIFI_MODE_AX)
			wireless_mode = PHY_11AX_5G;
		if (pureMode & WIFI_MODE_BE)
			wireless_mode = PHY_11BE_5G;
		break;
	case band_6:
		if (pureMode & WIFI_MODE_AX)
			wireless_mode = PHY_11AX_6G;
		if (pureMode & WIFI_MODE_BE)
			wireless_mode = PHY_11BE_6G;
		break;
	default:
		fprintf(stderr, "%s band_idx invalid\n", __func__);
		break;
	}

	return wireless_mode;
}

// Set the radio operating mode, and pure mode flag.
INT wifi_setRadioMode(INT radioIndex, CHAR *channelMode, UINT pureMode)
{
	unsigned char wireless_mode = PHY_MODE_MAX;

	char interface_name[IF_NAME_SIZE] = {0};
	int ret = -1;
	unsigned int if_idx = 0;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s_%d:%d\n", __func__, channelMode, pureMode, __LINE__);

	wireless_mode = puremode_to_wireless_mode(radioIndex, pureMode);

	if (wireless_mode == PHY_MODE_MAX) {
		wifi_debug(DEBUG_ERROR, "invalid pureMode = %x\n", pureMode);
		return RETURN_ERR;
	}

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", interface_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_AP_BSS;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/
	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_AP_WIRELESS_MODE, wireless_mode)) {
		wifi_debug(DEBUG_ERROR, "Nla put AP_WIRELESS_MODE attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

INT wifi_setRadioMode_by_dat(INT radioIndex, UINT pureMode)
{
	unsigned char wireless_mode = PHY_MODE_MAX;
	char buf[MAX_BUF_SIZE] = {0};
	char dat_file[MAX_BUF_SIZE] = {0};
	struct params params={0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s_%d:%d\n", __func__, pureMode, __LINE__);

	wireless_mode = puremode_to_wireless_mode(radioIndex, pureMode);

	if (wireless_mode == PHY_MODE_MAX) {
		wifi_debug(DEBUG_ERROR, "invalid pureMode = %x\n", pureMode);
		return RETURN_ERR;
	}

	params.name = "WirelessMode";
	res = snprintf(buf, sizeof(buf), "%d", wireless_mode);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	params.value = buf;

	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, radioIndex);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_datfileWrite(dat_file, &params, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_setRadioHwMode(INT radioIndex, CHAR *hw_mode) {

	char config_file[64] = {0};
	char buf[64] = {0};
	struct params params = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	band = wifi_index_to_band(radioIndex);

	if (strncmp(hw_mode, "a", 1) == 0 && (band != band_5 && band != band_6))
		return RETURN_ERR;
	else if ((strncmp(hw_mode, "b", 1) == 0 || strncmp(hw_mode, "g", 1) == 0) && band != band_2_4)
		return RETURN_ERR;
	else if ((strncmp(hw_mode, "a", 1) && strncmp(hw_mode, "b", 1) && strncmp(hw_mode, "g", 1)) || band == band_invalid)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.name = "hw_mode";
	params.value = hw_mode;
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(radioIndex, &params, 1);

	if (band == band_2_4) {
		if (strncmp(hw_mode, "b", 1) == 0) {
			wifi_setRadioMode(radioIndex, "20MHz", WIFI_MODE_B);
			res = snprintf(buf, sizeof(buf), "%s", "1,2,5.5,11");
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			wifi_setRadioOperationalDataTransmitRates(radioIndex, buf);
			res = snprintf(buf, sizeof(buf), "%s", "1,2");
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			wifi_setRadioBasicDataTransmitRates(radioIndex, buf);
		} else {
			// We don't set mode here, because we don't know whitch mode should be set (g, n or ax?).

			res = snprintf(buf, sizeof(buf), "%s", "6,9,12,18,24,36,48,54");
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			wifi_setRadioOperationalDataTransmitRates(radioIndex, buf);
			res = snprintf(buf, sizeof(buf), "%s", "6,12,24");
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			wifi_setRadioBasicDataTransmitRates(radioIndex, buf);
		}
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setNoscan(INT radioIndex, CHAR *noscan)
{
	char config_file[64] = {0};
	struct params params = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	band = wifi_index_to_band(radioIndex);
	if (band != band_2_4)
		return RETURN_OK;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.name = "noscan";
	params.value = noscan;
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(radioIndex, &params, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;
	char cmd[256] = {0};
	char buf[128] = {0};
	BOOL dfs_enable = false;
	int phyId = 0, res;

	// Parse possible channel number and separate them with commas.
	wifi_getRadioDfsEnable(radioIndex, &dfs_enable);
	phyId = radio_index_to_phy(radioIndex);
	// Channel 68 and 96 only allow bandwidth 20MHz, so we remove them with their frequency.
	if (dfs_enable)
		res = snprintf(cmd, sizeof(cmd), "iw phy phy%d info | grep -e '\\*.*MHz .*dBm' | grep -v 'no IR\\|5340\\|5480' | cut -d '[' -f2 | cut -d ']' -f1 | tr '\\n' ',' | sed 's/.$//'", phyId);
	else
		res = snprintf(cmd, sizeof(cmd), "iw phy phy%d info | grep -e '\\*.*MHz .*dBm' | grep -v 'radar\\|no IR\\|5340\\|5480' | cut -d '[' -f2 | cut -d ']' -f1 | tr '\\n' ',' | sed 's/.$//'", phyId);

	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf,sizeof(buf));
	strncpy(output_string, buf, strlen(buf) < sizeof(buf) ? strlen(buf) : sizeof(buf));

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Getting current radio extension channel
INT wifi_halgetRadioExtChannel(CHAR *file,CHAR *Value)
{
	CHAR buf[150] = {0};
	int len;

	wifi_datfileRead(file, "HT_EXTCHA", buf, sizeof(buf));
	if (strncmp(buf, "Below", 5) == 0) {
		len = strlen("BelowControlChannel");
		memcpy(Value, "BelowControlChannel", len);
	}
	else if(strncmp(buf, "Above", 5) == 0) {
		len = strlen("AboveControlChannel");
		memcpy(Value, "AboveControlChannel", len);
	}
	Value[len] = '\0';
	return RETURN_OK;
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//RDKB
{
	char interface_name[16] = {0};
	char cmd[128] = {0};
	char buf[128] = {0};
	char config_file[64] = {0};
	int channel = 0;
	int freq = 0;
	int bandwidth = 0;
	int center_freq = 0;
	int center_channel = 0;
	int channel_delta = 0;
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	if (NULL == output_string)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "iw %s info | grep channel | sed -e 's/[^0-9 ]//g'", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) == 0) {
		wifi_debug(DEBUG_ERROR, "failed to get channel information from iw.\n");
		return RETURN_ERR;
	}
	sscanf(buf, "%d %d %d %*d %d", &channel, &freq, &bandwidth, &center_freq);

	if (bandwidth == 20) {
		res = snprintf(output_string, 256, "%d", channel);
		if (os_snprintf_error(256, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		return RETURN_OK;
	}

	center_channel = ieee80211_frequency_to_channel(center_freq);

	band = wifi_index_to_band(radioIndex);
	if (band == band_2_4 && bandwidth == 40) {
		res = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		memset(buf, 0, sizeof(buf));
		wifi_halgetRadioExtChannel(config_file, buf);	   // read ht_capab for HT40+ or -

		if (strncmp(buf, "AboveControlChannel", strlen("AboveControlChannel")) == 0 && channel < 10) {
			res = snprintf(output_string, 256, "%d,%d", channel, channel+4);
		} else if (strncmp(buf, "BelowControlChannel", strlen("BelowControlChannel")) == 0 && channel > 4) {
			res = snprintf(output_string, 256, "%d,%d", channel-4, channel);
		} else {
			fprintf(stderr, "%s: invalid channel %d set with %s\n.", __func__, channel, buf);
			return RETURN_ERR;
		}

		if (os_snprintf_error(256, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else if (band == band_5 || band == band_6){
		// to minus 20 is an offset, because frequence of a channel have a range. We need to use offset to calculate correct channel.
		// example: bandwidth 80: center is 42 (5210), channels are "36,40,44,48" (5170-5250). The delta should be 6.
		channel_delta = (bandwidth-20)/10;
		memset(output_string, 0, 256);
		for (int i = center_channel-channel_delta; i <= center_channel+channel_delta; i+=4) {
			// If i is not the last channel, we add a comma.
			res = snprintf(buf, sizeof(buf), "%d%s", i, i==center_channel+channel_delta?"":",");
			
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			strncat(output_string, buf, sizeof(output_string) - strlen(output_string) - 1);
		}
	} else
		return RETURN_ERR;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

//Get the running channel number
INT wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong)	//RDKB
{
	char channel_str[16] = {0};
	char config_file[128] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char interface_name[IF_NAME_SIZE] = {0};
	wifi_band band = band_invalid;
	ULONG iwChannel = 0;
	int res;

	if (output_ulong == NULL)
		return RETURN_ERR;
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileRead(config_file, "Channel", channel_str, sizeof(channel_str));
	*output_ulong = strtoul(channel_str, NULL, 10);
	if (*output_ulong == 0) {
		if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
			return RETURN_ERR;
		res = snprintf(cmd, sizeof(cmd), "iw dev %s info |grep channel | cut -d ' ' -f2", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd,buf,sizeof(buf));
		sscanf(buf, "%lu", &iwChannel);
		*output_ulong = iwChannel;
	}

	return RETURN_OK;
}

INT wifi_getApChannel(INT apIndex,ULONG *output_ulong) //RDKB
{
	char cmd[1024] = {0}, buf[5] = {0};
	char interface_name[16] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_ulong)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "iw dev %s info |grep channel | cut -d ' ' -f2", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf,sizeof(buf));
	*output_ulong = (strlen(buf) >= 1)? atol(buf): 0;
	if (*output_ulong == 0) {
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Storing the previous channel value
INT wifi_storeprevchanval(INT radioIndex)
{
	char buf[256] = {0};
	char output[4]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	wifi_band band = band_invalid;
	int res;

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid) {
		return RETURN_ERR;
		wifi_dbg_printf("[%s]: Invalid radio index", __func__);
	}
	res = snprintf(config_file, sizeof(config_file), "%s%d.dat",LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileRead(config_file, "Channel", output, sizeof(output));

	if(band == band_2_4)
		res = snprintf(buf, sizeof(buf), "%s%s%s","echo ",output," > /var/prevchanval2G_AutoChannelEnable");
	else if(band == band_5)
		res = snprintf(buf, sizeof(buf), "%s%s%s","echo ",output," > /var/prevchanval5G_AutoChannelEnable");
	else
		res = snprintf(buf, sizeof(buf), "%s%s%s","echo ",output," > /var/prevchanval6G_AutoChannelEnable");

	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	system(buf);
	Radio_flag = FALSE;
	return RETURN_OK;
}

//Set the running channel number
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	//RDKB	//AP only
{
	// We only write hostapd config here
	char str_channel[8]={0};
	char *list_channel;
	char possible_channels[256] = {0};
	char config_file_dat[128] = {0};
	struct params dat = {0};
	struct params acs = {0};
	wifi_band band = band_invalid;
	bool acs_channel = false;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (channel == 0)
		acs_channel = true;
	// Check valid
	res = snprintf(str_channel, sizeof(str_channel), "%lu", channel);
	if (os_snprintf_error(sizeof(str_channel), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_getRadioPossibleChannels(radioIndex, possible_channels);
	list_channel = strtok(possible_channels, ",");
	while(true)
	{
		if(list_channel == NULL) {   // input not in the list
			wifi_debug(DEBUG_ERROR, "Channel %s is not in possible list\n", str_channel);
			return RETURN_ERR;
		}
		if (strncmp(str_channel, list_channel, strlen(list_channel)) == 0 || strncmp(str_channel, "0", 1) == 0)
			break;
		list_channel = strtok(NULL, ",");
	}
	/*
	list.name = "channel";
	list.value = str_channel;
	wifi_getMaxRadioNumber(&max_radio_num);
	for(int i=0; i<=MAX_APS/max_radio_num;i++)
	{
		sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex+(max_radio_num*i));
		wifi_hostapdWrite(config_file, &list, 1);
	}
	*/
	dat.name = "Channel";
	dat.value = str_channel;
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file_dat, sizeof(config_file_dat), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file_dat), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileWrite(config_file_dat, &dat, 1);
	if (acs_channel == true) {
		acs.name = "AutoChannelSelect";
		acs.value = "3";
	} else {
		acs.name = "AutoChannelSelect";
		acs.value = "0";
	}
	wifi_datfileWrite(config_file_dat, &acs, 1);
	wifi_reloadAp(radioIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setRadioCenterChannel(INT radioIndex, ULONG channel)
{
	struct params list[2];
	char str_idx[16];
	char config_file[64];
	int max_num_radios = 0, res;
	wifi_band band = band_invalid;

	band = wifi_index_to_band(radioIndex);
	if (band == band_2_4)
		return RETURN_OK;

	res = snprintf(str_idx, sizeof(str_idx), "%lu", channel);
	if (os_snprintf_error(sizeof(str_idx), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	list[0].name = "vht_oper_centr_freq_seg0_idx";
	list[0].value = str_idx;
	list[1].name = "he_oper_centr_freq_seg0_idx";
	list[1].value = str_idx;

	wifi_getMaxRadioNumber(&max_num_radios);
	if(max_num_radios== 0){
		return RETURN_ERR;
	}
	for(int i=0; i<=MAX_APS/max_num_radios; i++)
	{
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex+(max_num_radios*i));
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		if (band == band_6)
			wifi_hostapdWrite(config_file, &list[1], 1);
		else
			wifi_hostapdWrite(config_file, list, 2);
	}

	return RETURN_OK;
}

//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //RDKB
{
	//Set to wifi config only. Wait for wifi reset to apply.
	ULONG Value = 0;
	char config_file_dat[128] = {0};
	struct params acs = {0};
	wifi_band band = band_invalid;
	int res;

	if(enable == TRUE) {
		wifi_setRadioChannel(radioIndex,Value);
	} else {
		acs.name = "AutoChannelSelect";
		acs.value = "0";
		band = wifi_index_to_band(radioIndex);
		res = snprintf(config_file_dat, sizeof(config_file_dat), "%s%d.dat", LOGAN_DAT_FILE, band);
		if (os_snprintf_error(sizeof(config_file_dat), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_datfileWrite(config_file_dat, &acs, 1);
	}
	return RETURN_OK;
}

INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool)
{
	if (output_bool == NULL)
		return RETURN_ERR;

	*output_bool = TRUE;

	return RETURN_OK;
}

INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool) 	//RDKB
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool=TRUE;
	return RETURN_OK;
}

INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool)		//RDKB
{
	unsigned long period = 0;

	if (NULL == output_bool)
		return RETURN_ERR;

	if (wifi_getRadioAutoChannelRefreshPeriod(radioIndex, &period) != RETURN_OK)
		return RETURN_OK;

	*output_bool = (period > 0) ? TRUE : FALSE;

	return RETURN_OK;
}

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)            //RDKB
{
	ULONG period = 1800;

	if (enable == TRUE) {
		if (wifi_setRadioAutoChannelRefreshPeriod(radioIndex, period) != RETURN_OK)
		return RETURN_ERR;
	}
	else {
		if (wifi_setRadioAutoChannelRefreshPeriod(radioIndex, 0) != RETURN_OK)
		return RETURN_ERR;
	}
	return RETURN_OK;
}

INT wifi_setApEnableOnLine(ULONG wlanIndex,BOOL enable)
{
	return RETURN_OK;
}

INT wifi_factoryResetAP(int apIndex)
{
	char ap_config_file[MAX_SUB_CMD_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char ret_buf[MAX_BUF_SIZE] = {0};
	int radio_idx = 0;
	int bss_idx = 0;
	char ssid[32] = {0};
	char interface[IF_NAME_SIZE] = {0};
	char psk_file[MAX_SUB_CMD_SIZE] = {0};
	struct params params[3] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	/*del old config file*/
	res = snprintf(ap_config_file, sizeof(ap_config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, MAX_CMD_SIZE, "rm %s", ap_config_file);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, ret_buf, sizeof(ret_buf));

	memset(cmd, 0, sizeof(cmd));
	memset(ret_buf, 0, sizeof(ret_buf));

	vap_index_to_array_index(apIndex, &radio_idx, &bss_idx);

	/*prepare new config file*/
	res = snprintf(cmd, sizeof(cmd), "cp /etc/hostapd-%s.conf %s", wifi_band_str[radio_idx], ap_config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, ret_buf, sizeof(ret_buf));

	if (radio_idx == band_2_4) {
		res = snprintf(ssid, sizeof(ssid), "%s_%d", PREFIX_SSID_2G, bss_idx);
		if (os_snprintf_error(sizeof(ssid), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		res = snprintf(interface, sizeof(interface), "%s%d", PREFIX_WIFI2G, bss_idx);
		if (os_snprintf_error(sizeof(interface), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else if (radio_idx == band_5) {
		res = snprintf(ssid, sizeof(ssid), "%s_%d", PREFIX_SSID_5G, bss_idx);
		if (os_snprintf_error(sizeof(ssid), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		res = snprintf(interface, sizeof(interface), "%s%d", PREFIX_WIFI5G, bss_idx);
		if (os_snprintf_error(sizeof(interface), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else if (radio_idx == band_6) {
		res = snprintf(ssid, sizeof(ssid), "%s_%d", PREFIX_SSID_6G, bss_idx);
		if (os_snprintf_error(sizeof(ssid), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		res = snprintf(interface, sizeof(interface), "%s%d", PREFIX_WIFI6G, bss_idx);
		if (os_snprintf_error(sizeof(interface), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	}

	/* fix wpa_psk_file path */
	res = snprintf(psk_file, sizeof(psk_file), "\\/nvram\\/hostapd%d.psk", apIndex);
	if (os_snprintf_error(sizeof(psk_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	params[0].name = "ssid";
	params[0].value = ssid;
	params[1].name = "interface";
	params[1].value = interface;
	params[2].name = "wpa_psk_file";
	params[2].value = psk_file;

	wifi_hostapdWrite(ap_config_file, params, 3);

	/*clear psk file*/
	memset(cmd, 0, sizeof(cmd));
	memset(ret_buf, 0, sizeof(ret_buf));

	res = snprintf(psk_file, sizeof(psk_file), "%s%d.psk", PSK_FILE, apIndex);
	if (os_snprintf_error(sizeof(psk_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (access(psk_file, F_OK) != 0) {
		res = snprintf(cmd, MAX_CMD_SIZE, "touch %s", psk_file);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, ret_buf, sizeof(ret_buf));
	} else {
		res = snprintf(cmd, MAX_CMD_SIZE, "echo '' > %s", psk_file);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, ret_buf, sizeof(ret_buf));
	}

	wifi_setApEnable(apIndex, FALSE);
	wifi_setApEnable(apIndex, TRUE);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_setBandSteeringApGroup(char *ApGroup)
{
	return RETURN_OK;
}

INT wifi_getApDTIMInterval(INT apIndex, INT *dtimInterval)
{
	char config_file[128] = {'\0'};
	char buf[128] = {'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (dtimInterval == NULL)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdRead(config_file, "dtim_period", buf, sizeof(buf));

	if (strlen(buf) == 0) {
		*dtimInterval = 2;
	} else {
		*dtimInterval = strtoul(buf, NULL, 10);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setApDTIMInterval(INT apIndex, INT dtimInterval)
{
	struct params params={0};
	char config_file[MAX_BUF_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (dtimInterval < 1 || dtimInterval > 255) {
		WIFI_ENTRY_EXIT_DEBUG("Invalid dtimInterval: %d\n", dtimInterval);
		return RETURN_ERR;
	}

	params.name = "dtim_period";
	res = snprintf(buf, sizeof(buf), "%d", dtimInterval);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.value = buf;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(apIndex, &params, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Check if the driver support the Dfs
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool) //Tr181
{
	wifi_band band = band_invalid;
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool=FALSE;

	band = wifi_index_to_band(radioIndex);
	if (band == band_5)
		*output_bool = TRUE;
	return RETURN_OK;
}

//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool)			//RDKB
{

	#define CHANNEL_AVAILABLE 0
	#define CHANNEL_INVALID 1
	#define CHANNEL_LIST_MAX_LENGTH 256
	#define MAX_CHANNEL_NUMBER 255

	char config_file[MAX_BUF_SIZE] = {0};
	char possible_channels[CHANNEL_LIST_MAX_LENGTH] = {0};
	char skip_list[CHANNEL_LIST_MAX_LENGTH] = {0};
	int skip_table[MAX_CHANNEL_NUMBER +1] = {0};
	wifi_band band = band_invalid;
	char *token_channel = NULL, *token_skip = NULL;
	int res;

	if (NULL == output_pool)
		return RETURN_ERR;
	// get skiplist, possible_channels list
	wifi_getRadioPossibleChannels(radioIndex, possible_channels);
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_datfileRead(config_file, "AutoChannelSkipList", skip_list, sizeof(skip_list));

	if (skip_list[0] != '\0') {
		int len = strlen(skip_list);
		for (int i = 0; i < len; i++) {
			if (skip_list[i] == ';') {
				skip_list[i] = ',';
			}
		}
		// skip list
		token_skip = strtok(skip_list, ",");
		while (token_skip != NULL) {
			int channel = atoi(token_skip);
			if (channel <= MAX_CHANNEL_NUMBER && strstr(possible_channels, token_skip) != NULL)
				skip_table[atoi(token_skip)] = CHANNEL_INVALID;
			token_skip = strtok(NULL, ",");
		}
	}

	int count = 0;
	token_channel = strtok(possible_channels, ",");
	while (token_channel != NULL) {
		int channel = atoi(token_channel);
		if (channel <= MAX_CHANNEL_NUMBER  && skip_table[channel] == CHANNEL_AVAILABLE) {
			count += snprintf(&output_pool[count], CHANNEL_LIST_MAX_LENGTH-count, "%d,", channel);
			if (count >= CHANNEL_LIST_MAX_LENGTH-1)
				break;
		}
		token_channel = strtok(NULL, ",");
	}
	//delete the last one ','
	if (count >0 && output_pool[count-1] == ',')
		output_pool[count-1] = '\0';
	return RETURN_OK;
}

INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool)			//RDKB
{
	char config_file_dat[128] = {0};
	struct params dat = {0};
	wifi_band band = band_invalid;
	char new_pool[128] = {0};
	int res;

	if (NULL == pool)
		return RETURN_ERR;

	strncpy(new_pool, pool, sizeof(new_pool) - 1);
	new_pool[sizeof(new_pool) - 1] = '\0';
	for (int i = 0; new_pool[i] != '\0'; i++) {
		if (new_pool[i] == ',')
			new_pool[i] = ';';
	}

	dat.name = "AutoChannelSkipList";
	dat.value = new_pool;
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file_dat, sizeof(config_file_dat), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file_dat), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (wifi_datfileWrite(config_file_dat, &dat, 1) != 0)
		return RETURN_ERR;
	wifi_reloadAp(radioIndex);

	return RETURN_OK;
}

INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds)
{
	if (NULL == output_interval_seconds || NULL == output_dwell_milliseconds)
		return RETURN_ERR;
	//Should refresh period time be filled in here? output_interval_seconds is INT type
	//wifi_getRadioAutoChannelRefreshPeriod is Ulong type
	*output_interval_seconds = 1800;
	*output_dwell_milliseconds = 200;

	return RETURN_OK;
}

INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds)
{
	//Set to wifi config. And apply instantly.
	return RETURN_OK;
}

INT wifi_getRadioDfsAtBootUpEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
	if (output_bool == NULL)
		 return RETURN_ERR;
	 *output_bool = true;
	return RETURN_OK;
}

INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable)	//Tr181
{
	return RETURN_OK;
}

//Get the Dfs enable status
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
	char buf[16] = {0};
	char config_file_dat[128] = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (output_bool == NULL)
		return RETURN_ERR;
	*output_bool = TRUE;		// default
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file_dat, sizeof(config_file_dat), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file_dat), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileRead(config_file_dat, "DfsEnable", buf, sizeof(buf));

	if (strncmp(buf, "0", 1) == 0)
		*output_bool = FALSE;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set the Dfs enable status
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable)	//Tr181
{
	char config_dat_file[128] = {0};
	FILE *f = NULL;
	struct params dat = {0};
	wifi_band band = band_invalid;
	int res, ret;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	f = fopen(DFS_ENABLE_FILE, "w");
	if (f == NULL)
		return RETURN_ERR;
	ret = fprintf(f, "%d", enable);
	if (ret < 0)
		wifi_debug(DEBUG_ERROR, "fprintf fail\n");
	fclose(f);

	wifi_setRadioIEEE80211hEnabled(radioIndex, enable);

	dat.name = "DfsEnable";
	dat.value = enable?"1":"0";
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_dat_file, sizeof(config_dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileWrite(config_dat_file, &dat, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Check if the driver support the AutoChannelRefreshPeriod
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;

	return RETURN_OK;
}


int get_ACS_RefreshPeriod_callback(struct nl_msg *msg, void *arg)
{
	ULONG *data = (ULONG *)arg;
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return NL_SKIP;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return NL_SKIP;

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_ACS_REFRESH_PERIOD]) {
			*data = nla_get_u32(vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_ACS_REFRESH_PERIOD]);
		}
	}

	return NL_OK;
}

//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) //Tr181
{
	char interface_name[IF_NAME_SIZE] = {0};
	int ret = -1;
	unsigned int if_idx = 0;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	unsigned long checktime = 0;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_ulong)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", interface_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/
	if (nla_put_u32(msg, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_ACS_REFRESH_PERIOD, 0)) {
		wifi_debug(DEBUG_ERROR, "Nla put GET_RUNTIME_INFO_GET_ACS_REFRESH_PERIOD attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, get_ACS_RefreshPeriod_callback, &checktime);

	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	*output_ulong = checktime;
	wifi_debug(DEBUG_NOTICE,"send cmd success\n");

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;

}

//Set the ACS refresh period in seconds
INT wifi_setRadioDfsRefreshPeriod(INT radioIndex, ULONG seconds) //Tr181
{
	char interface_name[IF_NAME_SIZE] = {0};
	int ret = -1;
	unsigned int if_idx = 0;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", interface_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_AUTO_CH_SEL;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/
	if (nla_put_u32(msg, MTK_NL80211_VENDOR_ATTR_AUTO_CH_CHECK_TIME, seconds)) {
		wifi_debug(DEBUG_ERROR, "Nla put MTK_NL80211_VENDOR_ATTR_AUTO_CH_CHECK_TIME attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);

	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE,"send cmd success\n");

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181
{
	char cmd[MAX_CMD_SIZE] = {0}, buf[32] = {0};
	char extchannel[128] = {0};
	char interface_name[64] = {0};
	int ret = 0, len=0, res;
	BOOL radio_enable = FALSE;
	wifi_band band;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (NULL == output_string) {
		WIFI_ENTRY_EXIT_DEBUG("output_string is nuill %s: %d \n", __func__, __LINE__);
		return RETURN_ERR;
	}
	if (wifi_getRadioEnable(radioIndex, &radio_enable) == RETURN_ERR) {
		WIFI_ENTRY_EXIT_DEBUG("wifi_getRadioEnable failed %s: %d \n", __func__, __LINE__);
		return RETURN_ERR;
	}
	if (radio_enable != TRUE) {
		WIFI_ENTRY_EXIT_DEBUG("Radio %d is not enable failed %s: %d \n", radioIndex, __func__, __LINE__);
		return RETURN_OK;
	}
	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	/*IW command get BW320 to do*/

	res = snprintf(cmd, sizeof(cmd),"iw dev %s info | grep 'width' | cut -d  ' ' -f6 | tr -d '\\n'", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret = _syscmd(cmd, buf, sizeof(buf));
	len = strlen(buf);
	if((ret != 0) || (len == 0))
	{
		WIFI_ENTRY_EXIT_DEBUG("failed with Command %s %s:%d\n",cmd,__func__, __LINE__);
		return RETURN_ERR;
	}

	band = wifi_index_to_band(radioIndex);
	if (band == band_2_4 && strncmp(buf, "20", 2) == 0) {
		wifi_getRadioExtChannel(radioIndex, extchannel);
		if (strncmp(extchannel, "Auto", 4) != 0) {
			res = snprintf(buf, sizeof(buf), "40");
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
		}
	}
	res = snprintf(output_string, 64, "%sMHz", buf);
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

enum mwctl_chan_width {
	MWCTL_CHAN_WIDTH_20,
	MWCTL_CHAN_WIDTH_40,
	MWCTL_CHAN_WIDTH_80,
	MWCTL_CHAN_WIDTH_160,
	MWCTL_CHAN_WIDTH_320,
};

struct bw_option  {
	unsigned int bandwith;
	enum mwctl_chan_width mode;
};

struct bw_option bw_opt[] = {
	{20, MWCTL_CHAN_WIDTH_20},
	{40, MWCTL_CHAN_WIDTH_40},
	{80, MWCTL_CHAN_WIDTH_80},
	{160, MWCTL_CHAN_WIDTH_160},
	{320, MWCTL_CHAN_WIDTH_320},
};

INT wifi_setChannel_netlink(INT radioIndex, UINT* channel, UINT *bandwidth)
{
	int ret = -1;
	int i;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	bool b_match = FALSE;

	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_CHANNEL;
	param.if_type = NL80211_ATTR_WIPHY;
	param.if_idx = radio_index_to_phy(radioIndex);

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/
	if (channel != NULL)
		if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_CHAN_SET_NUM, *channel)) {
			wifi_debug(DEBUG_ERROR, "Nla put CHAN_SET_NUM attribute error\n");
			nlmsg_free(msg);
			goto err;
		}

	if (bandwidth != NULL) {
		for (i = 0; i < (sizeof(bw_opt)/sizeof(bw_opt[0])); i++) {
			if (bw_opt[i].bandwith == *bandwidth) {
				b_match = true;
				if (nla_put_u32(msg, MTK_NL80211_VENDOR_ATTR_CHAN_SET_BW, bw_opt[i].mode)) {
					wifi_debug(DEBUG_ERROR, "Nla put CHAN_SET_BW attribute error\n");
					nlmsg_free(msg);
					goto err;
				}
				break;
			}
		}

		if (!b_match) {
			wifi_debug(DEBUG_ERROR, "Cannot find bandwith error\n");
			nlmsg_free(msg);
			goto err;
		}
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) //Tr181	//AP only
{
	char config_file[128];
	char ht_value[16];
	char vht_value[16];
	char eht_value[16];
	struct params dat[3];
	wifi_band band = band_invalid;
	unsigned int bw = 20;
	int ret = 0, res1, res2, res3;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if(NULL == bandwidth)
		return RETURN_ERR;
	band = wifi_index_to_band(radioIndex);

	if(strstr(bandwidth,"320") != NULL) {
		res1 = snprintf(ht_value, sizeof(ht_value), "%d", HT_BW_40);
		res2 = snprintf(vht_value, sizeof(vht_value), "%d", VHT_BW_160);
		res3 = snprintf(eht_value, sizeof(eht_value), "%d", EHT_BW_320);
		bw = 320;
	} else if(strstr(bandwidth,"160") != NULL) {
		res1 = snprintf(ht_value, sizeof(ht_value), "%d", HT_BW_40);
		res2 = snprintf(vht_value, sizeof(vht_value), "%d", VHT_BW_160);
		res3 = snprintf(eht_value, sizeof(eht_value), "%d", EHT_BW_160);
		bw = 160;
	} else if(strstr(bandwidth,"80") != NULL) {
		res1 = snprintf(ht_value, sizeof(ht_value), "%d", HT_BW_40);
		res2 = snprintf(vht_value, sizeof(vht_value), "%d", VHT_BW_80);
		res3 = snprintf(eht_value, sizeof(eht_value), "%d", EHT_BW_80);
		bw = 80;
	} else if(strstr(bandwidth,"40") != NULL) {
		res1 = snprintf(ht_value, sizeof(ht_value), "%d", HT_BW_40);
		res2 = snprintf(vht_value, sizeof(vht_value), "%d", VHT_BW_2040);
		res3 = snprintf(eht_value, sizeof(eht_value), "%d", EHT_BW_40);
		bw = 40;
	} else if(strstr(bandwidth,"20") != NULL) {
		res1 = snprintf(ht_value, sizeof(ht_value), "%d", HT_BW_20);
		res2 = snprintf(vht_value, sizeof(vht_value), "%d", VHT_BW_2040);
		res3 = snprintf(eht_value, sizeof(eht_value), "%d", EHT_BW_20);
		bw = 20;
	} else {
		fprintf(stderr, "%s: Invalid Bandwidth %s\n", __func__, bandwidth);
		return RETURN_ERR;
	}

	if (os_snprintf_error(sizeof(ht_value), res1)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (os_snprintf_error(sizeof(vht_value), res2)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (os_snprintf_error(sizeof(eht_value), res3)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res1 = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res1)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	dat[0].name = "HT_BW";
	dat[0].value = ht_value;
	dat[1].name = "VHT_BW";
	dat[1].value = vht_value;
	dat[2].name = "EHT_ApBw";
	dat[2].value = eht_value;
	wifi_datfileWrite(config_file, dat, 3);
	ret = wifi_setChannel_netlink(radioIndex, NULL, &bw);
	if (ret != RETURN_OK) {
		fprintf(stderr, "%s: wifi_setChannel return error.\n", __func__);
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) //Tr181
{
	char config_file[64] = {0};
	char config_dat_file[64] = {0};
	char mode_str[16] = {0};
	char buf[64] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char interface_name[64] = {0};
	int ret = 0, len=0;
	wifi_band band;
	ULONG channel = 0;
	int centr_channel = 0;
	UINT mode_map = 0;
	int freq=0, res;

	if (output_string == NULL)
		return RETURN_ERR;

	wifi_getRadioMode(radioIndex, mode_str, &mode_map);

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid)
		return RETURN_ERR;
	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(output_string, 64, "Auto");
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (band == band_2_4 || (!(mode_map&WIFI_MODE_AC) && !(mode_map&WIFI_MODE_AX))) {
		// 2G band or ac and ax mode is disable, we will check HT_EXTCHA
		res = snprintf(config_dat_file, sizeof(config_dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
		if (os_snprintf_error(sizeof(config_dat_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		wifi_halgetRadioExtChannel(config_dat_file, output_string);
		if (!(mode_map&WIFI_MODE_N))
			res = snprintf(output_string, 64, "Auto");
	} else {
		// 5G and 6G band with ac or ax mode.
		wifi_getRadioChannel(radioIndex, &channel);
		res = snprintf(cmd, sizeof(cmd),"iw dev %s info | grep 'center1' | cut -d  ' ' -f9 | tr -d '\\n'", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		ret = _syscmd(cmd, buf, sizeof(buf));
		len = strlen(buf);
		if((ret != 0) || (len == 0))
		{
			WIFI_ENTRY_EXIT_DEBUG("failed with Command %s %s:%d\n",cmd,__func__, __LINE__);
			return RETURN_ERR;
		}
		sscanf(buf, "%d", &freq);
		centr_channel = ieee80211_frequency_to_channel(freq);
		if (centr_channel > (int)channel)
			res = snprintf(output_string, 64, "AboveControlChannel");
		else
			res = snprintf(output_string, 64, "BelowControlChannel");

		if (os_snprintf_error(64, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	}

	return RETURN_OK;
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//AP only
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={0};
	char config_file[64] = {0};
	char config_dat_file[64] = {0};
	char ext_channel[64] = {0};
	char buf[128] = {0};
	char cmd[128] = {0};
	int max_radio_num =0, ret = 0, bandwidth = 0;
	unsigned long channel = 0;
	bool stbcEnable = FALSE;
	params.name = "ht_capab";
	wifi_band band;
	int res;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "cat %s | grep STBC", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) != 0)
		stbcEnable = TRUE;
	if (wifi_getRadioOperatingChannelBandwidth(radioIndex, buf) != RETURN_OK)
		return RETURN_ERR;
	bandwidth = strtol(buf, NULL, 10);
	// TDK expected to get error with 20MHz
	// we handle 20MHz in function wifi_RemoveRadioExtChannel().
	if (bandwidth == 20 || strstr(buf, "80+80") != NULL)
		return RETURN_ERR;

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid)
		return RETURN_ERR;

	if (wifi_getRadioChannel(radioIndex, &channel) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(buf, sizeof(buf), "HT%d", bandwidth);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret = util_get_sec_chan_offset(channel, buf);
	if (ret == -EINVAL)
		return RETURN_ERR;

	if(NULL!= strstr(string,"Above")) {
		if ((band == band_2_4 && channel > 9) || (band == band_5 && ret == -1))
			return RETURN_OK;
		memcpy(ext_channel, "Above", strlen("Above"));
	} else if(NULL!= strstr(string,"Below")) {
		if ((band == band_2_4 && channel < 5) || (band == band_5 && ret == -1))
			return RETURN_OK;
		memcpy(ext_channel, "Below", strlen("Below"));
	} else {
		printf("%s: invalid EXT_CHA:%s\n", __func__, string);
	return RETURN_ERR;
	}
	params.name = "HT_EXTCHA";
	params.value = ext_channel;

	snprintf (config_dat_file, sizeof(config_dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_datfileWrite(config_dat_file, &params, 1);

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num== 0){
		return RETURN_ERR;
	}
	for(int i=0; i<=MAX_APS/max_radio_num; i++)
	{
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,radioIndex+(max_radio_num*i));
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_setRadioSTBCEnable(radioIndex+(max_radio_num*i), stbcEnable);
	}

	//Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the guard interval value. eg "400nsec" or "800nsec"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)	//Tr181
{
	wifi_guard_interval_t GI;
	unsigned long len;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (output_string == NULL || wifi_getGuardInterval(radioIndex, &GI) == RETURN_ERR)
		return RETURN_ERR;

	if (GI == wifi_guard_interval_400) {
		len = strlen("400nsec");
		memcpy(output_string, "400nsec", len);
	} else if (GI == wifi_guard_interval_800) {	
		len = strlen("800nsec");
		memcpy(output_string, "800nsec", strlen("800nsec"));
	} else if (GI == wifi_guard_interval_1600) {
		len = strlen("1600nsec");
		memcpy(output_string, "1600nsec", strlen("1600nsec"));
	} else if (GI == wifi_guard_interval_3200) {
		len = strlen("3200nsec");
		memcpy(output_string, "3200nsec", strlen("3200nsec"));
	} else {
		len = strlen("Auto");
		memcpy(output_string, "Auto", strlen("Auto"));
	}
	output_string[len] = '\0';
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set the guard interval value.
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string)	//Tr181
{
	wifi_guard_interval_t GI;
	int ret = 0;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (strcmp(string, "400nsec") == 0)
		GI = wifi_guard_interval_400;
	else if (strcmp(string , "800nsec") == 0)
		GI = wifi_guard_interval_800;
	else if (strcmp(string , "1600nsec") == 0)
		GI = wifi_guard_interval_1600;
	else if (strcmp(string , "3200nsec") == 0)
		GI = wifi_guard_interval_3200;
	else
		GI = wifi_guard_interval_auto;

	ret = wifi_setGuardInterval(radioIndex, GI);

	if (ret == RETURN_ERR) {
		wifi_dbg_printf("%s: wifi_setGuardInterval return error\n", __func__);
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_int) //Tr181
{
	char buf[32]={0};
	char mcs_file[64] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	UINT mode_bitmap = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(output_int == NULL)
		return RETURN_ERR;
	res = snprintf(mcs_file, sizeof(mcs_file), "%s%d.txt", MCS_FILE, radioIndex);
	if (os_snprintf_error(sizeof(mcs_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "cat %s 2> /dev/null", mcs_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0)
		*output_int = strtol(buf, NULL, 10);
	else {
		// output the max MCS for the current radio mode
		if (wifi_getRadioMode(radioIndex, buf, &mode_bitmap) == RETURN_ERR) {
			wifi_dbg_printf("%s: wifi_getradiomode return error.\n", __func__);
			return RETURN_ERR;
		}
		if (mode_bitmap & WIFI_MODE_AX) {
			*output_int = 11;
		} else if (mode_bitmap & WIFI_MODE_AC) {
			*output_int = 9;
		} else if (mode_bitmap & WIFI_MODE_N) {
			*output_int = 7;
		}
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS) //Tr181
{
	/*Only HE mode can specify MCS capability. We don't support MCS in HT mode,
	because that would be ambiguous (MCS code 8~11 refer to 2 NSS in HT but 1 NSS in HE adn VHT).*/
	char config_file[64] = {0};
	char set_value[16] = {0};
	char mcs_file[32] = {0};
	struct params set_config = {0};
	FILE *f = NULL;
	INT nss = 0;
	int ant_bitmap = 0;
	unsigned short cal_value = 0;
	UCHAR tval = 0, i = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	// -1 means auto
	if (MCS > 15 || MCS < -1) {
		wifi_debug(DEBUG_ERROR, "invalid MCS %d\n", MCS);
		return RETURN_ERR;
	}
	wifi_getRadioTxChainMask(radioIndex, &ant_bitmap);/*nss is a bit map value,1111*/
	for(; ant_bitmap > 0; ant_bitmap >>= 1)
	nss += 1;
	//printf("%s:nss = %d\n", __func__, nss);
	/*16-bit combination of 2-bit values of Max HE-MCS For 1..8 SS;each 2-bit value have following meaning:
	0 = HE-MCS 0-7, 1 = HE-MCS 0-9, 2 = HE-MCS 0-11, 3 = not supported*/
	if (MCS > 9 || MCS == -1)
		tval = 2;/*one stream value*/
	else if (MCS > 7)
		tval = 1;
	else
		tval = 0;
	for (i = 0; i < nss; i++)
	   cal_value |= (tval << (2*i));
	res = snprintf(set_value, sizeof(set_value), "%x", cal_value);
	if (os_snprintf_error(sizeof(set_value), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("%s:set=%s, cal=%x\n", __func__, set_value, cal_value);
	set_config.name = "he_basic_mcs_nss_set";/*He capability in beacon or response*/
	set_config.value = set_value;

	wifi_hostapdWrite(config_file, &set_config, 1);
	wifi_hostapdProcessUpdate(radioIndex, &set_config, 1);

	// For pass tdk test, we need to record last MCS setting. No matter whether it is effective or not.
	res = snprintf(mcs_file, sizeof(mcs_file), "%s%d.txt", MCS_FILE, radioIndex);
	if (os_snprintf_error(sizeof(mcs_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	f = fopen(mcs_file, "w");
	if (f == NULL) {
		fprintf(stderr, "%s: fopen failed\n", __func__);
		return RETURN_ERR;
	}
	fprintf(f, "%d", MCS);
	fclose(f);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get supported Transmit Power list, eg : "0,25,50,75,100"
//The output_list is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) //Tr181
{
	int res;
	if (NULL == output_list)
		return RETURN_ERR;
	res = snprintf(output_list, 64,"0,25,50,75,100");
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

//Get current Transmit Power in dBm units.
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)	//RDKB
{
	char interface_name[16] = {0};
	char cmd[MAX_CMD_SIZE]={0};
	char buf[16]={0};
	char pwr_file[128]={0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if(output_ulong == NULL)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(pwr_file, sizeof(pwr_file), "%s%d.txt", POWER_PERCENTAGE, radioIndex);
	if (os_snprintf_error(sizeof(pwr_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "cat %s 2> /dev/null", pwr_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0)
		*output_ulong = strtol(buf, NULL, 10);
	else
		*output_ulong = 100;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//RDKB
{
	char interface_name[16] = {0};
	char *support;
	char buf[128]={0};
	char txpower_str[64] = {0};
	char pwr_file[128]={0};
	FILE *f = NULL;
	int if_idx, ret = 0;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	// Get the Tx power supported list and check that is the input in the list
	res = snprintf(txpower_str, sizeof(txpower_str), "%lu", TransmitPower);
	if (os_snprintf_error(sizeof(txpower_str), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_getRadioTransmitPowerSupported(radioIndex, buf);
	support = strtok(buf, ",");
	while(true)
	{
		if(support == NULL) {   // input not in the list
			wifi_dbg_printf("Input value is invalid.\n");
			return RETURN_ERR;
		}
		if (strncmp(txpower_str, support, strlen(support)) == 0) {
			break;
		}
		support = strtok(NULL, ",");
	}

	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_TXPOWER;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_TXPWR_PERCENTAGE_EN, 1)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_TXPWR_DROP_CTRL, TransmitPower)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");

	res = snprintf(pwr_file, sizeof(pwr_file), "%s%d.txt", POWER_PERCENTAGE, radioIndex);
	if (os_snprintf_error(sizeof(pwr_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	f = fopen(pwr_file, "w");
	if (f == NULL) {
		fprintf(stderr, "%s: fopen failed\n", __func__);
		return RETURN_ERR;
	}
	fprintf(f, "%lu", TransmitPower);
	fclose(f);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

//get 80211h Supported.  80211h solves interference with satellites and radar using the same 5 GHz frequency band
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported)  //Tr181
{
	if (NULL == Supported)
		return RETURN_ERR;
	*Supported = TRUE;

	return RETURN_OK;
}

//Get 80211h feature enable
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) //Tr181
{
	char buf[64]={'\0'};
	char config_file[64] = {'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(enable == NULL)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	/* wifi_hostapdRead(config_file, "ieee80211h", buf, sizeof(buf)); */
	wifi_datfileRead(config_file, "IEEE80211H", buf, sizeof(buf));

	if (strncmp(buf, "1", 1) == 0)
		*enable = TRUE;
	else
		*enable = FALSE;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set 80211h feature enable
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable)  //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={'\0'};
	struct params dat={0};
	char config_file[MAX_BUF_SIZE] = {0};
	char config_dat_file[MAX_BUF_SIZE] = {0};
	wifi_band band = band_invalid;
	int res;

	params.name = "ieee80211h";

	if (enable) {
		params.value = "1";
	} else {
		params.value = "0";
	}

	dat.name = "IEEE80211H";
	dat.value = params.value;

	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(config_dat_file, sizeof(config_dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file, &params, 1);
	wifi_datfileWrite(config_dat_file, &dat, 1);
	wifi_hostapdProcessUpdate(radioIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output)  //P3
{
	if (NULL == output)
		return RETURN_ERR;
	*output=100;

	return RETURN_OK;
}

//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output)	//P3
{
	if (NULL == output)
		return RETURN_ERR;
	*output = -99;

	return RETURN_OK;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold)	//P3
{
	return RETURN_ERR;
}


//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output)
{
	char interface_name[16] = {0};
	char cmd[MAX_BUF_SIZE]={'\0'};
	char buf[MAX_CMD_SIZE]={'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(output == NULL)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd),  "hostapd_cli -i %s status | grep beacon_int | cut -d '=' -f2 | tr -d '\n'", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	*output = atoi(buf);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	char config_file[MAX_BUF_SIZE] = {'\0'};
	int res;

	if (BeaconPeriod < 15 || BeaconPeriod > 65535)
		return RETURN_ERR;

	params.name = "beacon_int";
	res = snprintf(buf, sizeof(buf), "%u", BeaconPeriod);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	params.value = buf;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);

	wifi_hostapdProcessUpdate(radioIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output)
{
	//TODO: need to revisit below implementation
	char *temp;
	char temp_output[128] = {0};
	char temp_TransmitRates[64] = {0};
	char config_file[64] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file,"basic_rates",temp_TransmitRates,64);

	if (strlen(temp_TransmitRates) == 0) {  // config not set, use supported rate
		wifi_getRadioSupportedDataTransmitRates(radioIndex, output);
	} else {
		temp = strtok(temp_TransmitRates," ");
		while(temp!=NULL)
		{
			// Convert 100 kbps to Mbps
			temp[strlen(temp)-1]=0;
			if((temp[0]=='5') && (temp[1]=='\0'))
			{
				temp="5.5";
			}
			if (strlen(temp) >= sizeof(temp_output))
				return RETURN_ERR;
			strncat(temp_output, temp, sizeof(temp_output) - strlen(temp_output) - 1);
			temp = strtok(NULL," ");
			if(temp!=NULL)
			{
				if (strlen(temp_output) >= (sizeof(temp_output) - 1))
				strncat(temp_output, ",", sizeof(temp_output) - strlen(temp_output) - 1);
			}
		}
		memcpy(output, temp_output, strlen(temp_output));
		output[strlen(temp_output)] = '\0';
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
	char *temp;
	char temp1[128] = {0};
	char temp_output[128] = {0};
	char temp_TransmitRates[128] = {0};
	char set[128] = {0};
	char sub_set[128] = {0};
	int set_count=0,subset_count=0;
	int set_index=0,subset_index=0;
	char *token;
	int flag=0, i=0;
	struct params params={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	wifi_band band = wifi_index_to_band(radioIndex);
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(NULL == TransmitRates)
		return RETURN_ERR;
	if (strlen(TransmitRates) >= sizeof(sub_set))
		return RETURN_ERR;

	memcpy(sub_set, TransmitRates, strlen(TransmitRates));

	//Allow only supported Data transmit rate to be set
	wifi_getRadioSupportedDataTransmitRates(radioIndex,set);
	token = strtok(sub_set,",");
	while( token != NULL  )  /* split the basic rate to be set, by comma */
	{
		sub_set[subset_count]=atoi(token);
		subset_count++;
		token=strtok(NULL,",");
	}
	token=strtok(set,",");
	while(token!=NULL)   /* split the supported rate by comma */
	{
		set[set_count]=atoi(token);
		set_count++;
		token=strtok(NULL,",");
	}
	for(subset_index=0;subset_index < subset_count;subset_index++) /* Compare each element of subset and set */
	{
		for(set_index=0;set_index < set_count;set_index++)
		{
			flag=0;
			if(sub_set[subset_index]==set[set_index])
				break;
			else
				flag=1; /* No match found */
		}
		if(flag==1)
			return RETURN_ERR; //If value not found return Error
	}
	
	if (strlen(TransmitRates) >= sizeof(temp_TransmitRates))
		return RETURN_ERR;

	memcpy(temp_TransmitRates, TransmitRates, strlen(TransmitRates));

	for(i=0;i<strlen(temp_TransmitRates);i++)
	{
	//if (((temp_TransmitRates[i]>=48) && (temp_TransmitRates[i]<=57)) | (temp_TransmitRates[i]==32))
		if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) || (temp_TransmitRates[i]==' ') || (temp_TransmitRates[i]=='.') || (temp_TransmitRates[i]==','))
		{
			continue;
		}
		else
		{
			return RETURN_ERR;
		}
	}
	temp = strtok(temp_TransmitRates,",");
	while(temp!=NULL)
	{
		if (strlen(temp) >= sizeof(temp1))
			return RETURN_ERR;
		strncpy(temp1, temp, strlen(temp));
		if(band == band_5)
		{
			if((strcmp(temp,"1")==0) || (strcmp(temp,"2")==0) || (strcmp(temp,"5.5")==0))
			{
				return RETURN_ERR;
			}
		}

		if(strcmp(temp,"5.5")==0)
		{
			memcpy(temp1, "55", 2);
		}
		else
		{
			if (strlen(temp1) >= (sizeof(temp1) - 1))
				return RETURN_ERR;
			strncat(temp1, "0", sizeof(temp1) - strlen(temp1) - 1);
		}
		if (strlen(temp1) >= (sizeof(temp_output) - strlen(temp_output)))
			return RETURN_ERR;
		strncat(temp_output, temp1, sizeof(temp_output) - strlen(temp_output) - 1);
		temp = strtok(NULL,",");
		if(temp!=NULL)
		{
			if (strlen(temp_output) >= (sizeof(temp_output) - 1))
				return RETURN_ERR;
			strncat(temp_output," ", sizeof(temp_output) - strlen(temp_output) - 1);
		}
	}
	memcpy(TransmitRates, temp_output, strlen(temp_output));
	TransmitRates[strlen(temp_output)] = '\0';
	
	params.name= "basic_rates";
	params.value =TransmitRates;

	wifi_dbg_printf("\n%s:",__func__);
	wifi_dbg_printf("\nparams.value=%s\n",params.value);
	wifi_dbg_printf("\n******************Transmit rates=%s\n",TransmitRates);
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	
	wifi_hostapdWrite(config_file,&params,1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//passing the hostapd configuration file and get the virtual interface of xfinity(2g)
INT wifi_GetInterfaceName_virtualInterfaceName_2G(char interface_name[50])
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	FILE *fp = NULL;
	char path[256] = {0}, output_string[256] = {0};
	int count = 0;
	char *interface = NULL;

	fp = popen("cat /nvram/hostapd0.conf | grep -w bss", "r");
	if (fp == NULL)
	{
		printf("Failed to run command in Function %s\n", __FUNCTION__);
		return RETURN_ERR;
	}
	if (fgets(path, sizeof(path) - 1, fp) != NULL)
	{
		interface = strchr(path, '=');

		if (interface != NULL)
		{
			strncpy(output_string, interface + 1, sizeof(output_string) - 1);
			output_string[sizeof(output_string) - 1] = '\0';
			for (count = 0; output_string[count] != '\n' || output_string[count] != '\0'; count++)
				interface_name[count] = output_string[count];

			interface_name[count] = '\0';
		}
	}
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_halGetIfStatsNull(wifi_radioTrafficStats2_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	output_struct->radio_BytesSent = 0;
	output_struct->radio_BytesReceived = 0;
	output_struct->radio_PacketsSent = 0;
	output_struct->radio_PacketsReceived = 0;
	output_struct->radio_ErrorsSent = 0;
	output_struct->radio_ErrorsReceived = 0;
	output_struct->radio_DiscardPacketsSent = 0;
	output_struct->radio_DiscardPacketsReceived = 0;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}


INT wifi_halGetIfStats(char *ifname, wifi_radioTrafficStats2_t *pStats)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	CHAR buf[MAX_CMD_SIZE] = {0};
	CHAR Value[MAX_BUF_SIZE] = {0};
	FILE *fp = NULL;
	int res;

	if (ifname == NULL || strlen(ifname) <= 1)
		return RETURN_OK;

	res = snprintf(buf, sizeof(buf), "ifconfig -a %s > /tmp/Radio_Stats.txt", ifname);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	system(buf);

	fp = fopen("/tmp/Radio_Stats.txt", "r");
	if(fp == NULL)
	{
		printf("/tmp/Radio_Stats.txt not exists \n");
		return RETURN_ERR;
	}
	fclose(fp);

	res = snprintf(buf, sizeof(buf), "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	File_Reading(buf, Value);
	pStats->radio_PacketsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_PacketsSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_BytesReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_BytesSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_ErrorsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_ErrorsSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_DiscardPacketsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_DiscardPacketsSent = strtoul(Value, NULL, 10);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT GetIfacestatus(CHAR *interface_name, CHAR *status)
{
	CHAR buf[MAX_CMD_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	if (interface_name != NULL && (strlen(interface_name) > 1) && status != NULL) {
		res = snprintf(buf, sizeof(buf), "%s%s%s%s%s", "ifconfig -a ",
			interface_name, " | grep ", interface_name, " | wc -l");

		if (os_snprintf_error(sizeof(buf), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		File_Reading(buf, status);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

//Get detail radio traffic static info
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct) //Tr181
{
	CHAR interface_name[64] = {0};
	BOOL iface_status = FALSE;
	wifi_radioTrafficStats2_t radioTrafficStats = {0};

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	if (NULL == output_struct)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	wifi_getApEnable(radioIndex, &iface_status);

	if (iface_status == TRUE)
		wifi_halGetIfStats(interface_name, &radioTrafficStats);
	else
		wifi_halGetIfStatsNull(&radioTrafficStats);	 // just set some transmission statistic value to 0

	output_struct->radio_BytesSent = radioTrafficStats.radio_BytesSent;
	output_struct->radio_BytesReceived = radioTrafficStats.radio_BytesReceived;
	output_struct->radio_PacketsSent = radioTrafficStats.radio_PacketsSent;
	output_struct->radio_PacketsReceived = radioTrafficStats.radio_PacketsReceived;
	output_struct->radio_ErrorsSent = radioTrafficStats.radio_ErrorsSent;
	output_struct->radio_ErrorsReceived = radioTrafficStats.radio_ErrorsReceived;
	output_struct->radio_DiscardPacketsSent = radioTrafficStats.radio_DiscardPacketsSent;
	output_struct->radio_DiscardPacketsReceived = radioTrafficStats.radio_DiscardPacketsReceived;

	output_struct->radio_PLCPErrorCount = 0;				  //The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.
	output_struct->radio_FCSErrorCount = 0;					  //The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
	output_struct->radio_InvalidMACCount = 0;				  //The number of packets that were received with a detected invalid MAC header error.
	output_struct->radio_PacketsOtherReceived = 0;			  //The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
	output_struct->radio_NoiseFloor = -99;					  //The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
	output_struct->radio_ChannelUtilization = 35;			  //Percentage of time the channel was occupied by the radio\92s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
	output_struct->radio_ActivityFactor = 2;				  //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_CarrierSenseThreshold_Exceeded = 20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_RetransmissionMetirc = 0;			  //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

	output_struct->radio_MaximumNoiseFloorOnChannel = -1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
	output_struct->radio_MinimumNoiseFloorOnChannel = -1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_MedianNoiseFloorOnChannel = -1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_StatisticsStartTime = 0;		  //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

//Set radio traffic static Measureing rules
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) //Tr181
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(radioIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_RADIO_STATS;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_RADIO_SET_STATS_MEASURING_METHOD,
        sizeof(wifi_radioTrafficStatsMeasure_t), input_struct)) {
		wifi_debug(DEBUG_ERROR, "Nla put vendor_data_attr(%d) attribute error\n",
            MTK_NL80211_VENDOR_ATTR_RADIO_SET_STATS_MEASURING_METHOD);
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

//To start or stop RadioTrafficStats
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable)
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(radioIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_RADIO_STATS;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_RADIO_SET_MEASURE_ENABEL, enable)) {
		wifi_debug(DEBUG_ERROR, "Nla put vendor_data_attr(%d) attribute error\n",
            MTK_NL80211_VENDOR_ATTR_RADIO_SET_MEASURE_ENABEL);
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the client?s current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected client?s current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histogram?s bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval?. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) //Tr181
{
	if (NULL == SignalLevel)
		return RETURN_ERR;

	*SignalLevel = -19;

	return RETURN_OK;
}

//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex)
{
	return RETURN_OK;
}

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex)
{
	if(NULL == radioIndex)
		return RETURN_ERR;
	int max_radio_num = 0;
	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	*radioIndex = ssidIndex%max_radio_num;
	return RETURN_OK;
}

//Device.WiFi.SSID.{i}.Enable
//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool)
		return RETURN_ERR;

	return wifi_getApEnable(ssidIndex, output_bool);
}

//Device.WiFi.SSID.{i}.Enable
//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) //Tr181
{
	return wifi_setApEnable(ssidIndex, enable);
}

//Device.WiFi.SSID.{i}.Status
//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) //Tr181
{
	BOOL output_bool = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string)
		return RETURN_ERR;

	wifi_getApEnable(ssidIndex,&output_bool);
	res = snprintf(output_string, 32, output_bool==1?"Enabled":"Disabled");
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// Outputs a 32 byte or less string indicating the SSID name.  Sring buffer must be preallocated by the caller.
INT wifi_getSSIDName(INT apIndex, CHAR *output)
{
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	if (NULL == output)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file,"ssid",output,32);

	wifi_dbg_printf("\n[%s]: SSID Name is : %s",__func__,output);
	return RETURN_OK;
}

// Set a max 32 byte string and sets an internal variable to the SSID name
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string)
{
	struct params params;
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(NULL == ssid_string || strlen(ssid_string) >= 32 || strlen(ssid_string) == 0 )
		return RETURN_ERR;

	params.name = "ssid";
	params.value = ssid_string;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(apIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//Get the BSSID
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string)	//RDKB
{
	char cmd[MAX_CMD_SIZE] = {0};
	char inf_name[IF_NAME_SIZE] = {0};
	int res;

	if (!output_string)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(ssidIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;

	if (ssidIndex < 0 || ssidIndex > MAX_APS) {
		wifi_debug(DEBUG_ERROR, "innvalide ssidIdex(%d)\n", ssidIndex);
		strncpy(output_string, "\0", 1);
		return RETURN_ERR;
	}
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s get_config | grep bssid | cut -d '=' -f2 | tr -d '\\n'", inf_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, output_string, 64);

	/* if hostapd does not control interface even if this interface has been brought up,
	 * try to get its mac address by iw command.
	 */
	if(strlen(output_string) == 0) {
		memset(cmd, 0, sizeof(cmd));
		res = snprintf(cmd, sizeof(cmd), "iw dev %s info | grep \"addr\" | awk \'{print $2}\'", inf_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, output_string, 64);
	}

	return RETURN_OK;
}

//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) //Tr181
{
	wifi_getBaseBSSID(ssidIndex,output_string);
	return RETURN_OK;
}

//Get the basic SSID traffic static info
//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex)
{
	char interface_name[16] = {0};
	BOOL status = false;
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_CMD_SIZE] = {0};
	int apIndex, ret;
	int max_radio_num = 0;
	int radioIndex = 0;
	int res;

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	radioIndex = ssidIndex % max_radio_num;

	wifi_getApEnable(ssidIndex,&status);
	// Do not apply when ssid index is disabled
	if (status == false)
		return RETURN_OK;

	/* Doing full remove and add for ssid Index
	 * Not all hostapd options are supported with reload
	 * for example macaddr_acl
	 */
	if(wifi_setApEnable(ssidIndex,false) != RETURN_OK)
		   return RETURN_ERR;

	ret = wifi_setApEnable(ssidIndex,true);

	/* Workaround for hostapd issue with multiple bss definitions
	 * when first created interface will be removed
	 * then all vaps other vaps on same phy are removed
	 * after calling setApEnable to false readd all enabled vaps */
	for(int i=0; i < MAX_APS/max_radio_num; i++) {
		apIndex = max_radio_num*i+radioIndex;
		if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
			return RETURN_ERR;
		res = snprintf(cmd, sizeof(cmd), "cat %s | grep %s | cut -d'=' -f2", VAP_STATUS_FILE, interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));
		if(*buf == '1')
			   wifi_setApEnable(apIndex, true);
	}

	return ret;
}

struct channels_noise {
	int channel;
	int noise;
};

// Return noise array for each channel
int get_noise(int radioIndex, struct channels_noise *channels_noise_arr, int channels_num)
{
	char interface_name[16] = {0};
	FILE *f = NULL;
	char cmd[128] = {0};
	char line[256] = {0};
	int tmp = 0, arr_index = -1, res;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "iw dev %s survey dump | grep 'frequency\\|noise' | awk '{print $2}'", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if ((f = popen(cmd, "r")) == NULL) {
		wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
		return RETURN_ERR;
	}

	while(fgets(line, sizeof(line), f) != NULL) {
		if(arr_index < channels_num){
			sscanf(line, "%d", &tmp);
			if (tmp > 0) {	  // channel frequency, the first line must be frequency
				arr_index++;
				channels_noise_arr[arr_index].channel = ieee80211_frequency_to_channel(tmp);
			} else {			// noise
				channels_noise_arr[arr_index].noise = tmp;
			}
		}else{
			break;
		}
	}
	pclose(f);
	return RETURN_OK;
}

//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size) //Tr181
{
	int index = -1;
	wifi_neighbor_ap2_t *scan_array = NULL;
	char cmd[256]={0};
	char buf[128]={0};
	char file_name[32] = {0};
	char filter_SSID[32] = {0};
	char line[256] = {0};
	char interface_name[16] = {0};
	char *ret = NULL;
	int freq=0;
	FILE *f = NULL;
	int channels_num = 0;
	int vht_channel_width = 0;
	int get_noise_ret = RETURN_ERR;
	bool filter_enable = false;
	bool filter_BSS = false;	 // The flag determine whether the BSS information need to be filterd.
	int phyId = 0, res;
	unsigned long len;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s: %d\n", __func__, __LINE__);

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, radioIndex);
	if (os_snprintf_error(sizeof(file_name), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	f = fopen(file_name, "r");
	if (f != NULL) {
		fgets(buf, sizeof(file_name), f);
		if ((strncmp(buf, "0", 1)) != 0) {
			fgets(filter_SSID, sizeof(file_name), f);
			if (strlen(filter_SSID) != 0)
				filter_enable = true;
		}
		fclose(f);
	}

	phyId = radio_index_to_phy(radioIndex);
	res = snprintf(cmd, sizeof(cmd), "iw phy phy%d channels | grep * | grep -v disable | wc -l", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	channels_num = strtol(buf, NULL, 10);

	res = snprintf(cmd, sizeof(cmd), "iw dev %s scan | grep '%s\\|SSID\\|freq\\|beacon interval\\|capabilities\\|signal\\|Supported rates\\|DTIM\\| \
	// WPA\\|RSN\\|Group cipher\\|HT operation\\|secondary channel offset\\|channel width\\|HE.*GHz' | grep -v -e '*.*BSS'", interface_name, interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fprintf(stderr, "cmd: %s\n", cmd);
	if ((f = popen(cmd, "r")) == NULL) {
		wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
		return RETURN_ERR;
	}
	struct channels_noise *channels_noise_arr = NULL;
	if(channels_num > 0 && channels_num <= 243){
		channels_noise_arr = calloc(channels_num, sizeof(struct channels_noise));
	} else{
		return RETURN_ERR;
	}
	
	if(channels_noise_arr != NULL){
		get_noise_ret = get_noise(radioIndex, channels_noise_arr, channels_num);
	} else{
		fclose(f);
		return RETURN_ERR;
	}
	

	ret = fgets(line, sizeof(line), f);
	while (ret != NULL) {
		if(strstr(line, "BSS") != NULL) {	// new neighbor info
			// The SSID field is not in the first field. So, we should store whole BSS informations and the filter flag.
			// And we will determine whether we need the previous BSS infomation when parsing the next BSS field or end of while loop.
			// If we don't want the BSS info, we don't realloc more space, and just clean the previous BSS.

			if (!filter_BSS) {
				index++;
				wifi_neighbor_ap2_t *tmp;
				tmp = realloc(scan_array, sizeof(wifi_neighbor_ap2_t)*(index+1));
				if (tmp == NULL) {			  // no more memory to use
					index--;
					wifi_dbg_printf("%s: realloc failed\n", __func__);
					break;
				}
				scan_array = tmp;
			}
			memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));

			filter_BSS = false;
			sscanf(line, "BSS %17s", scan_array[index].ap_BSSID);
			memset(scan_array[index].ap_Mode, 0, sizeof(scan_array[index].ap_Mode));
			memcpy(scan_array[index].ap_Mode, "Infrastructure", strlen("Infrastructure"));
			memset(scan_array[index].ap_SecurityModeEnabled, 0, sizeof(scan_array[index].ap_SecurityModeEnabled));
			memcpy(scan_array[index].ap_SecurityModeEnabled, "None", strlen("None"));
			memset(scan_array[index].ap_EncryptionMode, 0, sizeof(scan_array[index].ap_EncryptionMode));
			memcpy(scan_array[index].ap_EncryptionMode, "None", strlen("None"));
		} else if (strstr(line, "freq") != NULL) {
			sscanf(line,"	freq: %d", &freq);
			scan_array[index].ap_Channel = ieee80211_frequency_to_channel(freq);

			if (freq >= 2412 && freq <= 2484) {
				memset(scan_array[index].ap_OperatingFrequencyBand, 0, sizeof(scan_array[index].ap_OperatingFrequencyBand));
				memcpy(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz"));
				memset(scan_array[index].ap_SupportedStandards, 0, sizeof(scan_array[index].ap_SupportedStandards));
				memcpy(scan_array[index].ap_SupportedStandards, "b,g", strlen("b,g"));
				memset(scan_array[index].ap_OperatingStandards, 0, sizeof(scan_array[index].ap_OperatingStandards));
				memcpy(scan_array[index].ap_OperatingStandards, "g", strlen("g"));
			}
			else if (freq >= 5160 && freq <= 5805) {
				memset(scan_array[index].ap_OperatingFrequencyBand, 0, sizeof(scan_array[index].ap_OperatingFrequencyBand));
				memcpy(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz"));
				memset(scan_array[index].ap_SupportedStandards, 0, sizeof(scan_array[index].ap_SupportedStandards));
				memcpy(scan_array[index].ap_SupportedStandards, "a", strlen("a"));
				memset(scan_array[index].ap_OperatingStandards, 0, sizeof(scan_array[index].ap_OperatingStandards));
				memcpy(scan_array[index].ap_OperatingStandards, "a", strlen("a"));
			}

			scan_array[index].ap_Noise = 0;
			if (get_noise_ret == RETURN_OK) {
				for (int i = 0; i < channels_num; i++) {
					if (scan_array[index].ap_Channel == channels_noise_arr[i].channel) {
						scan_array[index].ap_Noise = channels_noise_arr[i].noise;
						break;
					}
				}
			}
		} else if (strstr(line, "beacon interval") != NULL) {
			sscanf(line,"	beacon interval: %d TUs", &(scan_array[index].ap_BeaconPeriod));
		} else if (strstr(line, "signal") != NULL) {
			sscanf(line,"	signal: %d", &(scan_array[index].ap_SignalStrength));
		} else if (strstr(line,"SSID") != NULL) {
			sscanf(line,"	SSID: %32s", scan_array[index].ap_SSID);
			if (filter_enable && strcmp(scan_array[index].ap_SSID, filter_SSID) != 0) {
				filter_BSS = true;
			}
		} else if (strstr(line, "Supported rates") != NULL) {
			char SRate[80] = {0}, *tmp = NULL;
			memset(buf, 0, sizeof(buf));
			if (strlen(line) >= sizeof(SRate))
				return RETURN_ERR;
			strncpy(SRate, line, strlen(line));
			tmp = strtok(SRate, ":");
			tmp = strtok(NULL, ":");
			if (strlen(tmp) >= sizeof(buf))
				return RETURN_ERR;
			strncpy(buf, tmp, strlen(tmp));
			memset(SRate, 0, sizeof(SRate));

			tmp = strtok(buf, " \n");
			while (tmp != NULL) {
				if (strlen(tmp) >= (sizeof(SRate) - strlen(SRate)))
					return RETURN_ERR;
				strncat(SRate, tmp, sizeof(SRate) - strlen(SRate) - 1);
				if (SRate[strlen(SRate) - 1] == '*') {
					SRate[strlen(SRate) - 1] = '\0';
				}
				if (strlen(SRate) >= (sizeof(SRate) - 1))
					return RETURN_ERR;
				strncat(SRate, ",", sizeof(SRate) - strlen(SRate) - 1);

				tmp = strtok(NULL, " \n");
			}
			SRate[strlen(SRate) - 1] = '\0';
			if (sizeof(scan_array[index].ap_SupportedDataTransferRates) <= strlen(SRate))
				return RETURN_ERR;
			strncpy(scan_array[index].ap_SupportedDataTransferRates, SRate, strlen(SRate));
		} else if (strstr(line, "DTIM") != NULL) {
			sscanf(line,"DTIM Period %u", &(scan_array[index].ap_DTIMPeriod));
		} else if (strstr(line, "VHT capabilities") != NULL) {
			if (sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) <= 4)
				return RETURN_ERR;
			strncat(scan_array[index].ap_SupportedStandards, ",ac",
				sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) - 1);
			memcpy(scan_array[index].ap_OperatingStandards, "ac", 2);
			scan_array[index].ap_OperatingStandards[2] = '\0';
		} else if (strstr(line, "HT capabilities") != NULL) {
			strncat(scan_array[index].ap_SupportedStandards, ",n", sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) - 1);
			memcpy(scan_array[index].ap_OperatingStandards, "n", 1);
			scan_array[index].ap_OperatingStandards[1] = '\0';
		} else if (strstr(line, "VHT operation") != NULL) {
			ret = fgets(line, sizeof(line), f);
			sscanf(line,"		 * channel width: %d", &vht_channel_width);
			if(vht_channel_width == 1) {
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT80");
			} else {
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT40");
			}
			if (os_snprintf_error(sizeof(scan_array[index].ap_OperatingChannelBandwidth), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				free(channels_noise_arr);
				fclose(f);
				return RETURN_ERR;
			}

			if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
				continue;
		} else if (strstr(line, "HT operation") != NULL) {
			ret = fgets(line, sizeof(line), f);
			sscanf(line,"		 * secondary channel offset: %s", buf);
			if (!strcmp(buf, "above")) {
				//40Mhz +
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40PLUS", radioIndex%1 ? "A": "G");
			}
			else if (!strcmp(buf, "below")) {
				//40Mhz -
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40MINUS", radioIndex%1 ? "A": "G");
			} else {
				//20Mhz
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT20", radioIndex%1 ? "A": "G");
			}
			if (os_snprintf_error(sizeof(scan_array[index].ap_OperatingChannelBandwidth), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				free(channels_noise_arr);
				fclose(f);
				return RETURN_ERR;
			}

			if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
				continue;
		} else if (strstr(line, "HE capabilities") != NULL) {
			strncat(scan_array[index].ap_SupportedStandards, ",ax",
				sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) - 1);
			memcpy(scan_array[index].ap_OperatingStandards, "ax", 2);
			scan_array[index].ap_OperatingStandards[2] = '\0';
			ret = fgets(line, sizeof(line), f);
			if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz")) == 0) {
				if (strstr(line, "HE40/2.4GHz") != NULL) {
					len = strlen("11AXHE40PLUS");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE40PLUS", len);
				} else {
					len = strlen("11AXHE20");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE20", len);
				}
				scan_array[index].ap_OperatingChannelBandwidth[len] = '\0';
			} else if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz")) == 0) {
				if (strstr(line, "HE80/5GHz") != NULL) {
					len = strlen("11AXHE80");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE80", len);
					scan_array[index].ap_OperatingChannelBandwidth[len] = '\0';
					ret = fgets(line, sizeof(line), f);
				} else
					continue;
				if (strstr(line, "HE160/5GHz") != NULL) {
					len = strlen("11AXHE160");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE160", len);
					scan_array[index].ap_OperatingChannelBandwidth[len] = '\0';
				}
			}
			continue;
		} else if (strstr(line, "WPA") != NULL) {
			memcpy(scan_array[index].ap_SecurityModeEnabled, "WPA", 3);
			scan_array[index].ap_SecurityModeEnabled[3] = '\0';
		} else if (strstr(line, "RSN") != NULL) {
			memcpy(scan_array[index].ap_SecurityModeEnabled, "RSN", 3);
			scan_array[index].ap_SecurityModeEnabled[3] = '\0';
		} else if (strstr(line, "Group cipher") != NULL) {
			sscanf(line, "		 * Group cipher: %64s", scan_array[index].ap_EncryptionMode);
			if (strncmp(scan_array[index].ap_EncryptionMode, "CCMP", strlen("CCMP")) == 0) {
				memcpy(scan_array[index].ap_EncryptionMode, "AES", 3);
				scan_array[index].ap_EncryptionMode[3] = '\0';
			}
		}
		ret = fgets(line, sizeof(line), f);
	}

	if (!filter_BSS) {
		*output_array_size = index + 1;
	} else {
		memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));
		*output_array_size = index;
	}
	*neighbor_ap_array = scan_array;
	pclose(f);
	free(channels_noise_arr);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//>> Deprecated: used for old RDKB code.
INT wifi_getRadioWifiTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct)
{
	INT status = RETURN_ERR;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	output_struct->wifi_PLCPErrorCount = 0;
	output_struct->wifi_FCSErrorCount = 0;
	output_struct->wifi_InvalidMACCount = 0;
	output_struct->wifi_PacketsOtherReceived = 0;
	output_struct->wifi_Noise = 0;
	status = RETURN_OK;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return status;
}

INT wifi_getBasicTrafficStats(INT apIndex, wifi_basicTrafficStats_t *output_struct)
{
	char interface_name[16] = {0};
	char cmd[128] = {0};
	char buf[1280] = {0};
	char *pos = NULL;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_struct)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

	res = snprintf(cmd, sizeof(cmd), "ifconfig %s", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	pos = buf;
	if ((pos = strstr(pos, "RX packets:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_PacketsReceived = atoi(pos+strlen("RX packets:"));

	if ((pos = strstr(pos, "TX packets:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_PacketsSent = atoi(pos+strlen("TX packets:"));

	if ((pos = strstr(pos, "RX bytes:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_BytesReceived = atoi(pos+strlen("RX bytes:"));

	if ((pos = strstr(pos, "TX bytes:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_BytesSent = atoi(pos+strlen("TX bytes:"));

	sprintf(cmd, "hostapd_cli -i %s list_sta | wc -l | tr -d '\n'", interface_name);
	_syscmd(cmd, buf, sizeof(buf));
	sscanf(buf, "%lu", &output_struct->wifi_Associations);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct)
{
	char interface_name[IF_NAME_SIZE] = {0};
	char interface_status[MAX_BUF_SIZE] = {0};
	char Value[MAX_BUF_SIZE] = {0};
	char buf[MAX_CMD_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	FILE *fp = NULL;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_struct)
		return RETURN_ERR;

	memset(output_struct, 0, sizeof(wifi_trafficStats_t));

	if (wifi_GetInterfaceName(apIndex,interface_name) != RETURN_OK)
		return RETURN_ERR;
	GetIfacestatus(interface_name, interface_status);

	if(0 != strcmp(interface_status, "1"))
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	system(cmd);

	fp = fopen("/tmp/SSID_Stats.txt", "r");
	if(fp == NULL)
	{
		printf("/tmp/SSID_Stats.txt not exists \n");
		return RETURN_ERR;
	}
	fclose(fp);

	sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	output_struct->wifi_ErrorsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	output_struct->wifi_ErrorsSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	output_struct->wifi_DiscardedPacketsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	output_struct->wifi_DiscardedPacketsSent = strtoul(Value, NULL, 10);

	output_struct->wifi_UnicastPacketsSent = 0;
	output_struct->wifi_UnicastPacketsReceived = 0;
	output_struct->wifi_MulticastPacketsSent = 0;
	output_struct->wifi_MulticastPacketsReceived = 0;
	output_struct->wifi_BroadcastPacketsSent = 0;
	output_struct->wifi_BroadcastPacketsRecevied = 0;
	output_struct->wifi_UnknownPacketsReceived = 0;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getSSIDTrafficStats(INT apIndex, wifi_ssidTrafficStats_t *output_struct)
{
	INT status = RETURN_ERR;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//Below values should get updated from hal
	output_struct->wifi_RetransCount=0;
	output_struct->wifi_FailedRetransCount=0;
	output_struct->wifi_RetryCount=0;
	output_struct->wifi_MultipleRetryCount=0;
	output_struct->wifi_ACKFailureCount=0;
	output_struct->wifi_AggregatedPacketCount=0;

	status = RETURN_OK;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return status;
}

INT wifi_getNeighboringWiFiDiagnosticResult(wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size)
{
	INT status = RETURN_ERR;
	UINT index;
	wifi_neighbor_ap_t *pt=NULL;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	*output_array_size=2;
	//zqiu: HAL alloc the array and return to caller. Caller response to free it.
	*neighbor_ap_array=(wifi_neighbor_ap_t *)calloc(sizeof(wifi_neighbor_ap_t), *output_array_size);
	for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) {
		pt->ap_Radio[0] = '\0';
		pt->ap_SSID[0] = '\0';
		pt->ap_BSSID[0] = '\0';
		pt->ap_Mode[0] = '\0';
		pt->ap_Channel=1;
		pt->ap_SignalStrength=0;
		pt->ap_SecurityModeEnabled[0] = '\0';
		pt->ap_EncryptionMode[0] = '\0';
		pt->ap_OperatingFrequencyBand[0] = '\0';
		pt->ap_SupportedStandards[0] = '\0';
		pt->ap_OperatingStandards[0] = '\0';
		pt->ap_OperatingChannelBandwidth[0] = '\0';
		pt->ap_BasicDataTransferRates[0] = '\0';
		pt->ap_SupportedDataTransferRates[0] = '\0';
		pt->ap_BeaconPeriod=1;
		pt->ap_Noise=0;
		pt->ap_DTIMPeriod=1;
		pt->ap_ChannelUtilization = 1;
	}

	status = RETURN_OK;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return status;
}

//----------------- AP HAL -------------------------------

//>> Deprecated: used for old RDKB code.
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong, wifi_device_t **output_struct)
{
	if (NULL == output_ulong || NULL == output_struct)
		return RETURN_ERR;
	*output_ulong = 0;
	*output_struct = NULL;
	return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int AssoDevInfo_callback(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	char mac_addr[20];
	static int count=0;
	int rate=0;

	wifi_device_info_t *out = (wifi_device_info_t*)arg;

	nla_parse(tb,
			  NL80211_ATTR_MAX,
			  genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0),
			  NULL);

	if(!tb[NL80211_ATTR_STA_INFO]) {
		wifi_debug(DEBUG_ERROR, "sta stats missing!\n");
		return NL_SKIP;
	}


	if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
		wifi_debug(DEBUG_ERROR, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	//devIndex starts from 1
	if( ++count == out->wifi_devIndex )
	{
		mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
		//Getting the mac addrress
		mac_addr_aton(out->wifi_devMacAddress,mac_addr);

		if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
			wifi_debug(DEBUG_ERROR, "failed to parse nested rate attributes!");
			return NL_SKIP;
		}

		if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
			if(rinfo[NL80211_RATE_INFO_BITRATE]) {
				rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
				out->wifi_devTxRate = rate/10;
			}
		}

		if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy)) {
			wifi_debug(DEBUG_ERROR, "failed to parse nested rate attributes!");
			return NL_SKIP;
		}

		if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
			if(rinfo[NL80211_RATE_INFO_BITRATE]) {
				rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
				out->wifi_devRxRate = rate/10;
			}
		}
		if(sinfo[NL80211_STA_INFO_SIGNAL_AVG])
			out->wifi_devSignalStrength = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

		out->wifi_devAssociatedDeviceAuthentiationState = 1;
		count = 0; //starts the count for next cycle
		return NL_STOP;
	}

	return NL_SKIP;

}
#endif

INT wifi_getAssociatedDeviceDetail(INT apIndex, INT devIndex, wifi_device_t *output_struct)
{
	Netlink nl = {0};
	char if_name[IF_NAME_SIZE] = {0};
	char interface_name[16] = {0};
	int res;

	wifi_device_info_t info = {0};
	info.wifi_devIndex = devIndex;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(if_name,sizeof(if_name),"%s", interface_name);
	if (os_snprintf_error(sizeof(if_name), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	nl.id = initSock80211(&nl);

	if (nl.id < 0) {
		wifi_debug(DEBUG_ERROR, "Error initializing netlink \n");
		return -1;
	}

	struct nl_msg* msg = nlmsg_alloc();

	if (!msg) {
		wifi_debug(DEBUG_ERROR, "Failed to allocate netlink message.\n");
		nlfree(&nl);
		return -2;
	}

	genlmsg_put(msg,
				NL_AUTO_PID,
				NL_AUTO_SEQ,
				nl.id,
				0,
				NLM_F_DUMP,
				NL80211_CMD_GET_STATION,
				0);

	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
	nl_send_auto_complete(nl.socket, msg);
	nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,AssoDevInfo_callback,&info);
	nl_recvmsgs(nl.socket, nl.cb);
	nlmsg_free(msg);
	nlfree(&nl);

	output_struct->wifi_devAssociatedDeviceAuthentiationState = info.wifi_devAssociatedDeviceAuthentiationState;
	output_struct->wifi_devRxRate = info.wifi_devRxRate;
	output_struct->wifi_devTxRate = info.wifi_devTxRate;
	output_struct->wifi_devSignalStrength = info.wifi_devSignalStrength;
	memcpy(&output_struct->wifi_devMacAddress, &info.wifi_devMacAddress, sizeof(info.wifi_devMacAddress));
	return RETURN_OK;
}

INT wifi_kickAssociatedDevice(INT apIndex, wifi_device_t *device)
{
	if (NULL == device)
		return RETURN_ERR;
	return RETURN_OK;
}
//<<


//--------------wifi_ap_hal-----------------------------
//enables CTS protection for the radio used by this AP
INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable)
{
	//save config and Apply instantly
	return RETURN_ERR;
}

// enables OBSS Coexistence - fall back to 20MHz if necessary for the radio used by this ap
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable)
{
	char config_file[64] = {'\0'};
	char config_dat_file[64] = {'\0'};
	char buf[64] = {'\0'};
	struct params list = {0};
	struct params dat = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	list.name = "ht_coex";
	res = snprintf(buf, sizeof(buf), "%d", enable);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	list.value = buf;

	dat.name = "HT_BSSCoexistence";
	dat.value = buf;

	band = wifi_index_to_band(apIndex);
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(config_dat_file, sizeof(config_dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file, &list, 1);
	wifi_datfileWrite(config_dat_file, &dat, 1);
	wifi_hostapdProcessUpdate(apIndex, &list, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//P3 // sets the fragmentation threshold in bytes for the radio used by this ap
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold)
{
	char config_file[MAX_BUF_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	struct params list;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (threshold < 256 || threshold > 2346 )
		return RETURN_ERR;
	list.name = "fragm_threshold";
	res = snprintf(buf, sizeof(buf), "%d", threshold);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	list.value = buf;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file, &list, 1);
	wifi_hostapdProcessUpdate(apIndex, &list, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// enable STBC mode in the hardwarwe, 0 == not enabled, 1 == enabled
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable)
{
	char config_file[64] = {'\0'};
	char cmd[512] = {'\0'};
	char buf[512] = {'\0'};
	char stbc_config[16] = {'\0'};
	wifi_band band;
	int iterator = 0;
	BOOL current_stbc = FALSE;
	int ant_count = 0;
	int ant_bitmap = 0;
	struct params list;
	char dat_file[64] = {'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid)
		return RETURN_ERR;

	if (band == band_2_4)
		iterator = 1;
	else if ((band == band_5) || (band == band_6))
		iterator = 2;
	else
		return RETURN_OK;

	wifi_getRadioTxChainMask(radioIndex, &ant_bitmap);
	for (; ant_bitmap > 0; ant_bitmap >>= 1)
		ant_count += ant_bitmap & 1;

	if (ant_count == 1 && STBC_Enable == TRUE) {
		wifi_debug(DEBUG_ERROR, "can not enable STBC when using only one antenna\n");
		return RETURN_OK;
	}

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	// set ht and vht config
	for (int i = 0; i < iterator; i++) {
		memset(stbc_config, 0, sizeof(stbc_config));
		memset(cmd, 0, sizeof(cmd));
		memset(buf, 0, sizeof(buf));
		list.name = (i == 0)?"ht_capab":"vht_capab";
		res = snprintf(stbc_config, sizeof(stbc_config), "%s", list.name);
		if (os_snprintf_error(sizeof(stbc_config), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		res = snprintf(cmd, sizeof(cmd), "cat %s | grep -E '^%s' | grep 'STBC'", config_file, stbc_config);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));
		if (strlen(buf) != 0)
			current_stbc = TRUE;
		if (current_stbc == STBC_Enable)
			continue;

		if (STBC_Enable == TRUE) {
			// Append the STBC flags in capab config
			memset(cmd, 0, sizeof(cmd));
			if (i == 0)
				res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^ht_capab=.*/s/$/[TX-STBC][RX-STBC1]/' %s", config_file);
			else
				res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[TX-STBC-2BY1][RX-STBC-1]/' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
		} else if (STBC_Enable == FALSE) {
			// Remove the STBC flags and remain other flags in capab
			memset(cmd, 0, sizeof(cmd));
			res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[TX-STBC(-2BY1)?*\\]//' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
			memset(cmd, 0, sizeof(cmd));
			res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[RX-STBC-?[1-3]*\\]//' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
		}
		wifi_hostapdRead(config_file, list.name, buf, sizeof(buf));
		list.value = buf;
		wifi_hostapdProcessUpdate(radioIndex, &list, 1);
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/^HT_STBC=.*/HT_STBC=%d/g' %s", STBC_Enable, dat_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	if ((band == band_5) || (band == band_6)) {
		res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/^VHT_STBC=.*/VHT_STBC=%d/g' %s", STBC_Enable, dat_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));
	}
	/*wifi_reloadAp(radioIndex);
	the caller do this.*/

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// outputs A-MSDU enable status, 0 == not enabled, 1 == enabled
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool)
{
	char dat_file[128] = {0};
	wifi_band band;
	char amdus_buff[8] = {'\0'};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid) {
		printf("%s:Band Error\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileRead(dat_file, "HT_AMSDU", amdus_buff, sizeof(amdus_buff));
	if (strncmp(amdus_buff, "1", 1) == 0)
		*output_bool = TRUE;
	else
		*output_bool = FALSE;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// enables A-MSDU in the hardware, 0 == not enabled, 1 == enabled
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable)
{
	char dat_file[128] = {0};
	BOOL enable;
	wifi_band band;
	char amdus_buff[8] = {'\0'};
	struct params params = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid) {
		printf("%s:Band Error\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileRead(dat_file, "HT_AMSDU", amdus_buff, sizeof(amdus_buff));
	if (strncmp(amdus_buff, "1", 1) == 0)
		enable = TRUE;
	else
		enable = FALSE;
	if (amsduEnable == enable)
		return RETURN_OK;

	params.name = "HT_AMSDU";
	if (amsduEnable)
		params.value = "1";
	else
		params.value = "0";
	wifi_datfileWrite(dat_file, &params, 1);
	wifi_reloadAp(radioIndex);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//P2  // outputs the number of Tx streams
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int)
{
	char buf[8] = {0};
	char cmd[128] = {0};
	int phyId = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	phyId = radio_index_to_phy(radioIndex);
	res = snprintf(cmd, sizeof(cmd), "iw phy%d info | grep 'Configured Antennas' | awk '{print $4}'", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	*output_int = (INT)strtol(buf, NULL, 16);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT fitChainMask(INT radioIndex, int antcount)
{
	char buf[128] = {0};
	char cmd[128] = {0};
	char config_file[64] = {0};
	wifi_band band;
	struct params list[2] = {0};
	int res;

	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid)
		return RETURN_ERR;

	list[0].name = "he_mu_beamformer";
	list[1].name = "he_su_beamformer";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (antcount == 1) {
		// remove config about multiple antennas
		res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[TX-STBC(-2BY1)?*\\]//' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));

		res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[SOUNDING-DIMENSION-.\\]//' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));

		res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[SU-BEAMFORMER\\]//' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));

		res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[MU-BEAMFORMER\\]//' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));

		list[0].value = "0";
		list[1].value = "0";
	} else {
		// If we only set RX STBC means STBC is enable and TX STBC is disable when last time set one antenna. so we need to add it back.
		if (band == band_2_4 || band == band_5) {
			res = snprintf(cmd, sizeof(cmd), "cat %s | grep '^ht_capab=.*RX-STBC' | grep -v 'TX-STBC'", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
			if (strlen(buf) > 0) {
				res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^ht_capab=.*/s/$/[TX-STBC]/' %s", config_file);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}

				_syscmd(cmd, buf, sizeof(buf));
			}
		}
		if (band == band_5) {
			res = snprintf(cmd, sizeof(cmd), "cat %s | grep '^vht_capab=.*RX-STBC' | grep -v 'TX-STBC'", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
			if (strlen(buf) > 0) {
				res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[TX-STBC-2BY1]/' %s", config_file);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}

				_syscmd(cmd, buf, sizeof(buf));
			}
		}

		res = snprintf(cmd, sizeof(cmd), "cat %s | grep '\\[SU-BEAMFORMER\\]'", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));
		if (strlen(buf) == 0) {
			res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[SU-BEAMFORMER]/' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
		}

		res = snprintf(cmd, sizeof(cmd), "cat %s | grep '\\[MU-BEAMFORMER\\]'", config_file);
		_syscmd(cmd, buf, sizeof(buf));
		if (strlen(buf) == 0) {
			res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[MU-BEAMFORMER]/' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			_syscmd(cmd, buf, sizeof(buf));
		}

		res = snprintf(cmd, sizeof(cmd), "cat %s | grep '\\[SOUNDING-DIMENSION-.\\]'", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));
		if (strlen(buf) == 0) {
			res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[SOUNDING-DIMENSION-%d]/' %s", antcount, config_file);
		} else {
			res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/(SOUNDING-DIMENSION-)./\\1%d/' %s", antcount, config_file);
		}
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		_syscmd(cmd, buf, sizeof(buf));

		list[0].value = "1";
		list[1].value = "1";
	}
	wifi_hostapdWrite(config_file, list, 2);
	return RETURN_OK;
}

//P2  // sets the number of Tx streams to an enviornment variable
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams)
{
	char cmd[128] = {0};
	char buf[128] = {0};
	int phyId = 0;
	int cur_mask = 0;
	int antcountmsk = 0;
	INT cur_nss = 0;
	CHAR dat_file[64] = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (numStreams <= 0) {
		wifi_debug(DEBUG_ERROR, "chainmask is not supported %d.\n", numStreams);
		return RETURN_ERR;
	}

	wifi_getRadioTxChainMask(radioIndex, &cur_mask);//this is mask value
	for(; cur_mask > 0; cur_mask >>= 1)//convert to number of streams.
		cur_nss += 1;
	WIFI_ENTRY_EXIT_DEBUG("%s:cur_nss=%d, new_nss=%d\n", __func__, cur_nss, numStreams);
	if (cur_nss == numStreams)
		return RETURN_OK;

	wifi_setRadioEnable(radioIndex, FALSE);

	phyId = radio_index_to_phy(radioIndex);
	//iw need mask value.
	for (;numStreams > 0; numStreams--)
		antcountmsk |= 0x1 << (numStreams - 1);
	res = snprintf(cmd, sizeof(cmd), "iw phy%d set antenna 0x%x 2>&1", phyId, antcountmsk);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0) {
		wifi_debug(DEBUG_ERROR, "cmd %s error, output: %s\n", cmd, buf);
		return RETURN_ERR;
	}
	band = wifi_index_to_band(radioIndex);
	if (band == band_invalid) {
		printf("%s:Band Error\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/^HT_TxStream=.*/HT_TxStream=%d/g' %s", numStreams, dat_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0) {
		wifi_debug(DEBUG_ERROR, "cmd %s error, output: %s\n", cmd, buf);
		return RETURN_ERR;
	}
	res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/^HT_RxStream=.*/HT_RxStream=%d/g' %s", numStreams, dat_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0) {
		wifi_debug(DEBUG_ERROR, "cmd %s error, output: %s\n", cmd, buf);
		return RETURN_ERR;
	}
	fitChainMask(radioIndex, numStreams);
	wifi_setRadioEnable(radioIndex, TRUE);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//P2  // outputs the number of Rx streams
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int)
{
	char buf[8] = {0};
	char cmd[128] = {0};
	int phyId = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	phyId = radio_index_to_phy(radioIndex);

	res = snprintf(cmd, sizeof(cmd), "iw phy%d info | grep 'Configured Antennas' | awk '{print $6}'", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	*output_int = (INT)strtol(buf, NULL, 16);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//P2  // sets the number of Rx streams to an enviornment variable
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (wifi_setRadioTxChainMask(radioIndex, numStreams) == RETURN_ERR) {
		wifi_debug(DEBUG_ERROR, "wifi_setRadioTxChainMask return error.\n");
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_ERR;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;

	*output_bool = TRUE;
	return RETURN_OK;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool)
{
	char rdg_status[2] = {0};
	char dat_file[MAX_CMD_SIZE] = {0};
	int res;

	if (NULL == output_bool)
		return RETURN_ERR;

	/*prepare dat file path*/
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, radioIndex);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_datfileRead(dat_file, "HT_RDG", rdg_status, sizeof(rdg_status));
	if (!strncmp(rdg_status, "1", sizeof(rdg_status)))
		*output_bool = TRUE;
	else
		*output_bool = FALSE;

	return RETURN_OK;
}

//Set radio RDG enable setting
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable)
{
	char dat_file[MAX_CMD_SIZE] = {0};
	struct params params = {0};
	int res;

	/*prepare dat file path*/
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, radioIndex);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	params.name = "HT_RDG";

	if (enable) {
		params.value = "1";
	} else {
		params.value = "0";
	}

	wifi_datfileWrite(dat_file, &params, 1);

	return RETURN_OK;
}


int mtk_get_ba_auto_status_callback(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_AP_BA_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	unsigned char status;
	unsigned char *out_status = data;
	int err = 0;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0){
		wifi_debug(DEBUG_ERROR, "get NL80211_ATTR_MAX fails\n");
		return err;
	}

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_AP_BA_ATTR_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0){
			wifi_debug(DEBUG_ERROR, "get MTK_NL80211_VENDOR_AP_BA_ATTR_MAX fails\n");
			return err;
		}

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO]) {
			status = nla_get_u8(vndr_tb[MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO]);
			if (status == 0) {
				wifi_debug(DEBUG_NOTICE, "disabled\n");
			} else {
				wifi_debug(DEBUG_NOTICE, "enabled\n");
			}
			*out_status = status;
		}
	}

	return 0;
}

int mtk_get_ba_decline_status_callback(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_AP_BA_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	unsigned char status;
	unsigned char *out_status = data;
	int err = 0;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		wifi_debug(DEBUG_ERROR, "get NL80211_ATTR_MAX fails\n");
		return err;
	}

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_AP_BA_ATTR_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0) {
			wifi_debug(DEBUG_ERROR, "get MTK_NL80211_VENDOR_AP_BA_ATTR_MAX fails\n");
			return err;
		}

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_AP_BA_DECLINE_INFO]) {
			status = nla_get_u8(vndr_tb[MTK_NL80211_VENDOR_ATTR_AP_BA_DECLINE_INFO]);
			if (status == 0) {
				wifi_debug(DEBUG_NOTICE, "disabled\n");
			} else {
				wifi_debug(DEBUG_NOTICE, "enabled\n");
			}
			*out_status = status;
		}
	}

	return NL_OK;
}

INT mtk_wifi_get_ba_decl_auto_status(
	INT apIndex, INT vendor_data_attr, mtk_nl80211_cb call_back, BOOL *output_bool)
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_BA;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_u8(msg, vendor_data_attr, 0xf)) {
		wifi_debug(DEBUG_ERROR, "Nla put vendor_data_attr(%d) attribute error\n", vendor_data_attr);
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, call_back, output_bool);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE,"send cmd success, get output_bool:%d\n", *output_bool);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

INT mtk_wifi_set_auto_ba_en(
	INT apIndex, INT vendor_data_attr, BOOL enable)
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_BA;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_u8(msg, vendor_data_attr, enable)) {
		wifi_debug(DEBUG_ERROR, "Nla put vendor_data_attr(%d) attribute error\n", vendor_data_attr);
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

//Get radio ADDBA enable setting
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool)
{
	if (output_bool == NULL) {
		wifi_debug(DEBUG_ERROR, "invalid: output_bool is null\n");
		return RETURN_ERR;
	}
	if (mtk_wifi_get_ba_decl_auto_status(radioIndex,
	 	MTK_NL80211_VENDOR_ATTR_AP_BA_DECLINE_INFO, mtk_get_ba_decline_status_callback, output_bool) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "cmd MTK_NL80211_VENDOR_ATTR_AP_BA_DECLINE_INFO(0x%x) fails\n",
			MTK_NL80211_VENDOR_ATTR_AP_BA_DECLINE_INFO);
		return RETURN_ERR;
	}
	wifi_debug(DEBUG_NOTICE, "cmd success:output_bool(%d)\n", *output_bool);
	return RETURN_OK;
}

//Set radio ADDBA enable setting
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio auto block ack enable setting
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool)
{
	if (output_bool == NULL) {
		wifi_debug(DEBUG_ERROR, "invalid: output_bool is null\n");
		return RETURN_ERR;
	}

	if (mtk_wifi_get_ba_decl_auto_status(radioIndex,
	 	MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO,
	 	mtk_get_ba_auto_status_callback, output_bool) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "cmd  MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO(0x%x) fails\n",
			MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO);
		return RETURN_ERR;
	}
	wifi_debug(DEBUG_NOTICE, "cmd success:output_bool(%d)\n", *output_bool);
	return RETURN_OK;
}

//Set radio auto block ack enable setting
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable)
{
	if (mtk_wifi_set_auto_ba_en
		(radioIndex, MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO, enable) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send  MTK_NL80211_VENDOR_ATTR_AP_BA_EN_INFO cmd fails\n");
		return RETURN_ERR;
	}
	wifi_debug(DEBUG_ERROR, "send cmd success: set auto ba enable(%d)\n", enable);
	return RETURN_OK;
}

//Get radio 11n pure mode enable support
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Get radio 11n pure mode enable setting
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Set radio 11n pure mode enable setting
{
//save the vlanID to config and wait for wifi reset to apply (wifi up module would read this parameters and tag the AP with vlan id)
	char interface_name[16] = {0};
	int if_idx, ret = 0;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;

	if (radioIndex > MAX_APS) {
		wifi_debug(DEBUG_ERROR, "Invalid apIndex %d\n", radioIndex);
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	/*step 1. mwctl dev %s set vlan_tag 0*/
	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_AP_BSS;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_AP_HT_OP_MODE, enable)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	//wifi_debug(DEBUG_NOTICE, "set Gf cmd success.\n");
	printf("set gf=%d cmd success.\n", enable);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

int mtk_get_igmp_status_callback(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_MCAST_SNOOP_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	unsigned char status = 0, *out_status = data;
	int err = 0;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		wifi_debug(DEBUG_ERROR, "get NL80211_ATTR_MAX fails\n");
		return err;
	}

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_MCAST_SNOOP_ATTR_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0){
			wifi_debug(DEBUG_ERROR, "get MTK_NL80211_VENDOR_MCAST_SNOOP_ATTR_MAX fails\n");
			return err;
		}

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_MCAST_SNOOP_ENABLE]) {
			status = nla_get_u8(vndr_tb[MTK_NL80211_VENDOR_ATTR_MCAST_SNOOP_ENABLE]);
			if (status == 0) {
				wifi_debug(DEBUG_NOTICE, "disabled\n");
			} else {
				wifi_debug(DEBUG_NOTICE, "enabled\n");
			}
			*out_status = status;
			wifi_debug(DEBUG_NOTICE, "status: %d\n", *out_status);
		}
	}

	return 0;
}

INT mtk_wifi_set_igmp_en_status(
	INT apIndex, INT vendor_data_attr, mtk_nl80211_cb call_back,
	unsigned char in_en_stat, BOOL *output_bool)
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_MULTICAST_SNOOPING;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_u8(msg, vendor_data_attr, in_en_stat)) {
		wifi_debug(DEBUG_ERROR, "Nla put vendor_data_attr(%d) attribute error\n", vendor_data_attr);
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, call_back, output_bool);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	if (output_bool) {
		wifi_debug(DEBUG_NOTICE, "send cmd success, get output_bool:%d\n", *output_bool);
	} else {
		wifi_debug(DEBUG_NOTICE, "send cmd success.\n");
	}
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}


//Get radio IGMP snooping enable setting
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool)
{
	if (output_bool == NULL) {
		wifi_debug(DEBUG_ERROR, "invalid: output_bool is null\n");
		return RETURN_ERR;
	}
	if (mtk_wifi_set_igmp_en_status
		(radioIndex, MTK_NL80211_VENDOR_ATTR_MCAST_SNOOP_ENABLE,
		mtk_get_igmp_status_callback, 0xf, output_bool)!= RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send MTK_NL80211_VENDOR_ATTR_MCAST_SNOOP_ENABLE cmd fails\n");
		return RETURN_ERR;
	}
	wifi_debug(DEBUG_ERROR, "send cmd success: get igmp status:(%d)\n", *output_bool);
	return RETURN_OK;
}

//Set radio IGMP snooping enable setting
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable)
{
	if (mtk_wifi_set_igmp_en_status
		(radioIndex, MTK_NL80211_VENDOR_ATTR_MCAST_SNOOP_ENABLE,
		NULL, enable, NULL) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "send  MTK_NL80211_VENDOR_ATTR_MCAST_SNOOP_ENABLE cmd fails\n");
		return RETURN_ERR;
	}
	wifi_debug(DEBUG_ERROR, "send cmd success: set igmp enable(%d)\n", enable);
	return RETURN_OK;
}

//Get the Reset count of radio
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int)
{
	if (NULL == output_int)
		return RETURN_ERR;
	*output_int = get_radio_reset_cnt(radioIndex);

	return RETURN_OK;
}


//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------

// creates a new ap and pushes these parameters to the hardware
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid)
{
	// Deprecated when use hal version 3, use wifi_createVap() instead.
	return RETURN_OK;
}

// deletes this ap entry on the hardware, clears all internal variables associaated with this ap
INT wifi_deleteAp(INT apIndex)
{
	char interface_name[16] = {0};
	char buf[MAX_BUF_SIZE];
	char cmd[MAX_CMD_SIZE];
	int res;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, MAX_CMD_SIZE, "hostapd_cli -i global raw REMOVE %s", interface_name);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	wifi_removeApSecVaribles(apIndex);

	return RETURN_OK;
}

// Outputs a 16 byte or less name assocated with the AP.  String buffer must be pre-allocated by the caller
INT wifi_getApName(INT apIndex, CHAR *output_string)
{
	char interface_name[IF_NAME_SIZE] = {0};
	int radio_idx = 0;
	int bss_idx = 0;
	int res;

	if(!output_string)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK) {
		vap_index_to_array_index(apIndex, &radio_idx, &bss_idx);

		res = snprintf(output_string, IF_NAME_SIZE, "%s%d", ext_prefix[radio_idx], bss_idx);	// For wifiagent generating data model.
	} else
		res = snprintf(output_string, IF_NAME_SIZE, "%s", interface_name);

	if (os_snprintf_error(IF_NAME_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

// Outputs the index number in that corresponds to the SSID string
INT wifi_getIndexFromName(CHAR *inputSsidString, INT *output_int)
{
	char cmd [128] = {0};
	char buf[32] = {0};
	char ap_idx = 0;
	char *apIndex_str = NULL;
	char radio_idx = 0;
	char bss_idx = 0;
	int res;

	res = snprintf(cmd, sizeof(cmd), "grep -rn ^interface=%s$ /nvram/hostapd*.conf | cut -d '.' -f1 | cut -d 'd' -f2 | tr -d '\\n'",
		inputSsidString);

	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	if (strlen(buf)) {
		apIndex_str = strtok(buf, "\n");
		*output_int = strtoul(apIndex_str, NULL, 10);
		return RETURN_OK;
	}

	/* If interface name is not in hostapd config, the caller maybe wifi agent to generate data model.*/
	if (strstr(inputSsidString, PREFIX_WIFI6G)) {
		bss_idx = atoi(inputSsidString + strlen(PREFIX_WIFI6G));
		radio_idx = 2;
	} else if (strstr(inputSsidString, PREFIX_WIFI5G)) {
		bss_idx = atoi(inputSsidString + strlen(PREFIX_WIFI5G));
		radio_idx = 1;
	} else if (strstr(inputSsidString, PREFIX_WIFI2G)) {
		bss_idx = atoi(inputSsidString + strlen(PREFIX_WIFI2G));
		radio_idx = 0;
	} else {
		printf("%s: hostapd conf not find, unknow inf(%s), return ERROR!!!(%d).\n",
			__func__, inputSsidString, ap_idx);
		*output_int = -1;
		return RETURN_ERR;
	}

	ap_idx = array_index_to_vap_index(radio_idx, bss_idx);

	if (ap_idx >= 0 && ap_idx < MAX_VAP) {
		printf("%s: hostapd conf not find, inf(%s), use inf idx(%d).\n",
			__func__, inputSsidString, ap_idx);
		*output_int = ap_idx;
		return RETURN_OK;
	}

	return RETURN_ERR;
}

INT wifi_getApIndexFromName(CHAR *inputSsidString, INT *output_int)
{
	return wifi_getIndexFromName(inputSsidString, output_int);
}

// Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string)
{
	char buf[MAX_BUF_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	if(NULL == output_string)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "wpa", buf, sizeof(buf));
	if((strcmp(buf,"3")==0))
		res = snprintf(output_string, 32, "WPAand11i");
	else if((strcmp(buf,"2")==0))
		res = snprintf(output_string, 32, "11i");
	else if((strcmp(buf,"1")==0))
		res = snprintf(output_string, 32, "WPA");
	else
		res = snprintf(output_string, 32, "None");
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

// Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString)
{
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	if (NULL == beaconTypeString)
		return RETURN_ERR;
	list.name = "wpa";
	list.value = "0";

	if((strcmp(beaconTypeString,"WPAand11i")==0))
		list.value="3";
	else if((strcmp(beaconTypeString,"11i")==0))
		list.value="2";
	else if((strcmp(beaconTypeString,"WPA")==0))
		list.value="1";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);
	wifi_hostapdProcessUpdate(apIndex, &list, 1);
	//save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
	return RETURN_OK;
}

// sets the beacon interval on the hardware for this AP
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	char config_file[MAX_BUF_SIZE] = {'\0'};
	int res;

	params.name = "beacon_int";
	res = snprintf(buf, sizeof(buf), "%u", beaconInterval);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.value = buf;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);

	wifi_hostapdProcessUpdate(apIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setDTIMInterval(INT apIndex, INT dtimInterval)
{
	if (wifi_setApDTIMInterval(apIndex, dtimInterval) != RETURN_OK)
		return RETURN_ERR;
	return RETURN_OK;
}

// Get the packet size threshold supported.
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool)
{
	//save config and apply instantly
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

// sets the packet size threshold in bytes to apply RTS/CTS backoff rules.
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold)
{
	char buf[16] = {0};
	char config_file[128] = {0};
	struct params param = {0};
	int res;

	if (threshold > 65535) {
		wifi_debug(DEBUG_ERROR, "rts threshold %u is too big.\n", threshold);
		return RETURN_ERR;
	}

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(buf, sizeof(buf), "%u", threshold);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	param.name = "rts_threshold";
	param.value = buf;
	wifi_hostapdWrite(config_file, &param, 1);
	wifi_hostapdProcessUpdate(apIndex, &param, 1);
	wifi_reloadAp(apIndex);

	return RETURN_OK;
}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string)
{
	int res;

	if (NULL == output_string)
		return RETURN_ERR;
	res = snprintf(output_string, 32, "TKIPandAESEncryption");
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	return RETURN_OK;

}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptionMode(INT apIndex, CHAR *output_string)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char *param_name = NULL;
	char buf[32] = {0}, config_file[MAX_BUF_SIZE] = {0};
	unsigned int len;
	int res;

	if(NULL == output_string)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdRead(config_file,"wpa",buf,sizeof(buf));

	if(strcmp(buf,"0")==0)
	{
		printf("%s: wpa_mode is %s ......... \n", __func__, buf);
		res = snprintf(output_string, 32, "None");
		if (os_snprintf_error(32, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		return RETURN_OK;
	}
	else if((strcmp(buf,"3")==0) || (strcmp(buf,"2")==0))
		param_name = "rsn_pairwise";
	else if((strcmp(buf,"1")==0))
		param_name = "wpa_pairwise";
	else
		return RETURN_ERR;
	memset(output_string,'\0',32);
	wifi_hostapdRead(config_file,param_name,output_string,32);
	if (strlen(output_string) == 0) {	   // rsn_pairwise is optional. When it is empty use wpa_pairwise instead.
		param_name = "wpa_pairwise";
		memset(output_string, '\0', 32);
		wifi_hostapdRead(config_file, param_name, output_string, 32);
	}
	wifi_dbg_printf("\n%s output_string=%s",__func__,output_string);

	if(strcmp(output_string,"TKIP CCMP") == 0) {
		len = strlen("TKIPandAESEncryption");
		memcpy(output_string,"TKIPandAESEncryption", len);
		output_string[len] = '\0';
	} else if(strcmp(output_string,"TKIP") == 0) {
		len = strlen("TKIPEncryption");
		memcpy(output_string,"TKIPEncryption", len);
		output_string[len] = '\0';
	} else if(strcmp(output_string,"CCMP") == 0) {
		len = strlen("AESEncryption");
		memcpy(output_string,"AESEncryption", len);
		output_string[len] = '\0';
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// sets the encyption mode enviornment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={'\0'};
	char output_string[32];
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	memset(output_string,'\0',32);
	wifi_getApBeaconType(apIndex,output_string);

	if(strcmp(encMode, "TKIPEncryption") == 0)
		params.value = "TKIP";
	else if(strcmp(encMode,"AESEncryption") == 0)
		params.value = "CCMP";
	else if(strcmp(encMode,"TKIPandAESEncryption") == 0)
		params.value = "TKIP CCMP";

	if((strcmp(output_string,"WPAand11i")==0))
	{
		params.name = "wpa_pairwise";
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_hostapdWrite(config_file, &params, 1);
		wifi_hostapdProcessUpdate(apIndex, &params, 1);

		params.name = "rsn_pairwise";
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_hostapdWrite(config_file, &params, 1);
		wifi_hostapdProcessUpdate(apIndex, &params, 1);

		return RETURN_OK;
	}
	else if((strcmp(output_string,"11i")==0))
	{
		params.name = "rsn_pairwise";
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_hostapdWrite(config_file, &params, 1);
		wifi_hostapdProcessUpdate(apIndex, &params, 1);
		return RETURN_OK;
	}
	else if((strcmp(output_string,"WPA")==0))
	{
		params.name = "wpa_pairwise";
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_hostapdWrite(config_file, &params, 1);
		wifi_hostapdProcessUpdate(apIndex, &params, 1);
		return RETURN_OK;
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// deletes internal security varable settings for this ap
INT wifi_removeApSecVaribles(INT apIndex)
{
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	list.name = "wpa";
	list.value = "0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);

	return RETURN_OK;
}

// changes the hardware settings to disable encryption on this ap
INT wifi_disableApEncryption(INT apIndex)
{
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	list.name = "wpa";
	list.value = "0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);
	wifi_hostapdProcessUpdate(apIndex, &list, 1);
	wifi_reloadAp(apIndex);

	return RETURN_OK;
}

// set the authorization mode on this ap
// mode mapping as: 1: open, 2: shared, 4:auto
INT wifi_setApAuthMode(INT apIndex, INT mode)
{
	struct params params={0};
	char config_file[64] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	wifi_dbg_printf("\n%s algo_mode=%d", __func__, mode);
	params.name = "auth_algs";

	if ((mode & 1 && mode & 2) || mode & 4)
		params.value = "3";
	else if (mode & 2)
		params.value = "2";
	else if (mode & 1)
		params.value = "1";
	else
		params.value = "0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(apIndex, &params, 1);
	wifi_reloadAp(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
	//save to wifi config, and wait for wifi restart to apply
	struct params params={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int ret;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(authMode ==  NULL)
		return RETURN_ERR;

	wifi_dbg_printf("\n%s AuthMode=%s",__func__,authMode);
	params.name = "wpa_key_mgmt";

	if((strcmp(authMode,"PSKAuthentication") == 0) || (strcmp(authMode,"SharedAuthentication") == 0))
		params.value = "WPA-PSK";
	else if(strcmp(authMode,"EAPAuthentication") == 0)
		params.value = "WPA-EAP";
	else if (strcmp(authMode, "SAEAuthentication") == 0)
		params.value = "SAE";
	else if (strcmp(authMode, "EAP_192-bit_Authentication") == 0)
		params.value = "WPA-EAP-SUITE-B-192";
	else if (strcmp(authMode, "PSK-SAEAuthentication") == 0)
		params.value = "WPA-PSK WPA-PSK-SHA256 SAE";
	else if (strcmp(authMode, "Enhanced_Open") == 0)
		params.value = "OWE";
	else if(strcmp(authMode,"None") == 0) //Donot change in case the authMode is None
		return RETURN_OK;			  //This is taken careof in beaconType

	ret = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
	if (os_snprintf_error(sizeof(config_file), ret)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret=wifi_hostapdWrite(config_file,&params,1);
	if(!ret)
		ret=wifi_hostapdProcessUpdate(apIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return ret;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_getApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
	//save to wifi config, and wait for wifi restart to apply
	char BeaconType[50] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;
	unsigned long len;

	*authMode = 0;
	wifi_getApBeaconType(apIndex,BeaconType);
	printf("%s____%s \n",__FUNCTION__,BeaconType);

	if(strcmp(BeaconType,"None") == 0) {
		memcpy(authMode, "None", 4);
		authMode[4] = '\0';
	} else {
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wifi_hostapdRead(config_file, "wpa_key_mgmt", authMode, 32);
		wifi_dbg_printf("\n[%s]: AuthMode Name is : %s",__func__,authMode);
		if(strcmp(authMode,"WPA-PSK") == 0) {
			len = strlen("SharedAuthentication");
			memcpy(authMode, "SharedAuthentication", len);
			authMode[len] = '\0';
		} else if(strcmp(authMode,"WPA-EAP") == 0) {
			len = strlen("EAPAuthentication");
			memcpy(authMode, "EAPAuthentication", len);
			authMode[len] = '\0';
		}
	}

	return RETURN_OK;
}

// Outputs the number of stations associated per AP
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
	char interface_name[16] = {0};
	char cmd[128]={0};
	char buf[128]={0};
	BOOL status = false;
	int res;

	if(apIndex > MAX_APS)
		return RETURN_ERR;

	wifi_getApEnable(apIndex,&status);
	if (!status)
		return RETURN_OK;

	//sprintf(cmd, "iw dev %s station dump | grep Station | wc -l", interface_name);//alternate method
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s list_sta | wc -l", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	sscanf(buf,"%lu", output_ulong);

	return RETURN_OK;
}

// manually removes any active wi-fi association with the device specified on this ap
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac)
{
	char inf_name[16] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd),"hostapd_cli -i %s disassociate %s", inf_name, client_mac);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

// outputs the radio index for the specified ap. similar as wifi_getSsidRadioIndex
INT wifi_getApRadioIndex(INT apIndex, INT *output_int)
{
	int max_radio_num = 0;

	if(NULL == output_int)
		return RETURN_ERR;

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	*output_int = apIndex % max_radio_num;

	return RETURN_OK;
}

// sets the radio index for the specific ap
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex)
{
	//set to config only and wait for wifi reset to apply settings
	return RETURN_ERR;
}

int mtk_get_ap_metrics(struct nl_msg *msg, void *cb)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_STATISTIC_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	wdev_ap_metric ap_metric;
	wdev_ap_metric *p_ap_metric = &ap_metric;
	int err = 0;
	struct mtk_nl80211_cb_data *cb_data = cb;

	if (!msg || !cb_data) {
		wifi_debug(DEBUG_ERROR, "msg(%p) or cb_data(%p) is null,error.\n", msg, cb_data);
		return NL_SKIP;
	}

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		wifi_debug(DEBUG_ERROR, "nla_parse ap_metrics nl80211 msg fails,error.\n");
		return err;
	}

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_ATTR_GET_STATISTIC_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0) {
			wifi_debug(DEBUG_ERROR, "GET_STATISTIC_MAX fails,error.\n");
			return err;
		}

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_AP_METRICS]) {
			p_ap_metric = nla_data(vndr_tb[MTK_NL80211_VENDOR_ATTR_GET_AP_METRICS]);
			if (p_ap_metric) {
				memcpy(cb_data->out_buf , &p_ap_metric->cu, sizeof(unsigned char));
			}
		}
	}

	return NL_OK;
}


#define MAX_ACL_DUMP_LEN 4096
int mtk_acl_list_dump_callback(struct nl_msg *msg, void *cb)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_AP_ACL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	char *show_str = NULL;
	int err = 0;
	unsigned short acl_result_len = 0;
	struct mtk_nl80211_cb_data *cb_data = cb;
	if (!msg || !cb_data) {
		wifi_debug(DEBUG_ERROR, "msg(%p) or cb_data(%p) is null,error.\n", msg, cb_data);
		return NL_SKIP;
	}
	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		wifi_debug(DEBUG_ERROR, "nla_parse acl list nl80211 msg fails,error.\n");
		return NL_SKIP;
	}
	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_AP_ACL_ATTR_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return NL_SKIP;
		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_ACL_LIST_INFO]) {
			acl_result_len = nla_len(vndr_tb[MTK_NL80211_VENDOR_ATTR_ACL_LIST_INFO]);
			show_str = nla_data(vndr_tb[MTK_NL80211_VENDOR_ATTR_ACL_LIST_INFO]);
			if (acl_result_len > MAX_ACL_DUMP_LEN) {
				wifi_debug(DEBUG_ERROR,"the scan result len is invalid !!!\n");
				return NL_SKIP;
			} else if (*(show_str + acl_result_len - 1) != '\0') {
				wifi_debug(DEBUG_INFO, "the result string is not ended with right terminator, handle it!!!\n");
				*(show_str + acl_result_len - 1) = '\0';
			}
			wifi_debug(DEBUG_INFO, "driver msg:%s\n", show_str);

			if (cb_data->out_len >= acl_result_len) {
				memset(cb_data->out_buf, 0, cb_data->out_len);
				/*skip the first line: 'policy=1\n' to find the acl mac addrs*/
				memmove(cb_data->out_buf, show_str, acl_result_len);
				wifi_debug(DEBUG_INFO, "out buff:%s\n", cb_data->out_buf);
			} else {
				memset(cb_data->out_buf, 0, cb_data->out_len);
			}
		} else
			wifi_debug(DEBUG_ERROR, "no acl result attr\n");
	} else
		wifi_debug(DEBUG_ERROR, "no any acl result from driver\n");
	return NL_OK;
}
// Get the ACL MAC list per AP
INT mtk_wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned int if_idx = 0;
	int ret = -1;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct mtk_nl80211_cb_data cb_data;
	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_ACL;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_flag(msg, MTK_NL80211_VENDOR_ATTR_ACL_SHOW_ALL)) {
		wifi_debug(DEBUG_ERROR, "Nla put ACL_SHOW_ALL attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	cb_data.out_buf = macArray;
	cb_data.out_len = buf_size;

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, mtk_acl_list_dump_callback, &cb_data);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE,"send cmd success, get out_buf:%s\n", macArray);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR,"send cmd fails\n");
	return RETURN_ERR;
}

INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{
	char *mac_arry_buf = NULL;

	mac_arry_buf =  malloc(buf_size);
	if (!mac_arry_buf) {
		wifi_debug(DEBUG_ERROR,"malloc mac_arry_buf fails\n");
		return RETURN_ERR;
	}
	memset(mac_arry_buf, 0, buf_size);
	if (mtk_wifi_getApAclDevices(apIndex, mac_arry_buf, buf_size) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR,"mtk_wifi_getApAclDevices get fails\n");
		free(mac_arry_buf);
		mac_arry_buf = NULL;
		return RETURN_ERR;
	}
	/*
	mtk format to wifi hal format:
	"policy=1
	 00:11:22:33:44:55
	 00:11:22:33:44:66
	"
	-->
	"00:11:22:33:44:55
	00:11:22:33:44:66
	"
	*/
	memset(macArray, 0, buf_size);
	if (*mac_arry_buf != '\0' && strchr(mac_arry_buf,'\n')) {
		memmove(macArray, strchr(mac_arry_buf,'\n')+1, strlen(strchr(mac_arry_buf,'\n')+1)+1);
		wifi_debug(DEBUG_NOTICE,"macArray:\n%s\n", macArray);
	}
	free(mac_arry_buf);
	mac_arry_buf = NULL;
	return RETURN_OK;
}

INT wifi_getApDenyAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{

	wifi_getApAclDevices(apIndex, macArray, buf_size);

	return RETURN_OK;
}


// Get the list of stations associated per AP
INT wifi_getApDevicesAssociated(INT apIndex, CHAR *macArray, UINT buf_size)
{
	char interface_name[IF_NAME_SIZE] = {0};
	char cmd[MAX_CMD_SIZE];
	int res;

	if(apIndex > 3) //Currently supporting apIndex upto 3
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s list_sta", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, macArray, buf_size);
	return RETURN_OK;
}

int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/**
 * hwaddr_aton2 - Convert ASCII string to MAC address (in any known format)
 * @txt: MAC address as a string (e.g., 00:11:22:33:44:55 or 0011.2233.4455)
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: Characters used (> 0) on success, -1 on failure
 */
int hwaddr_aton2(const char *txt, unsigned char *addr)
{
	int i;
	const char *pos = txt;

	for (i = 0; i < 6; i++) {
		int a, b;

		while (*pos == ':' || *pos == '.' || *pos == '-')
			pos++;

		a = hex2num(*pos++);
		if (a < 0)
			return -1;
		b = hex2num(*pos++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
	}

	return pos - txt;
}

// adds the mac address to the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
	char inf_name[IF_NAME_SIZE] = {0};
	int if_idx, ret = 0;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	unsigned char mac[ETH_ALEN] = {0x00, 0x0c, 0x43, 0x11, 0x22, 0x33};
	struct unl unl_ins;
	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if (!DeviceMacAddress)
		return RETURN_ERR;
	if (hwaddr_aton2(DeviceMacAddress, mac) < 0) {
		wifi_debug(DEBUG_ERROR, "error device mac address=%s\n", DeviceMacAddress);
		return RETURN_ERR;
	}
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_ACL;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_ACL_ADD_MAC, ETH_ALEN, mac)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

// deletes the mac address from the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
	struct unl unl_ins;
	int if_idx = 0, ret = 0;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	char inf_name[IF_NAME_SIZE] = {0};
	unsigned char mac[ETH_ALEN] = {0};

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;

	if (!DeviceMacAddress)
		return RETURN_ERR;

	if (hwaddr_aton2(DeviceMacAddress, mac) < 0) {
		wifi_debug(DEBUG_ERROR, "error device mac address=%s\n", DeviceMacAddress);
		return RETURN_ERR;
	}

	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_ACL;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_ACL_DEL_MAC, ETH_ALEN, mac)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

// outputs the number of devices in the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint)
{
	char *mac_arry = NULL, *ptr = NULL, mac_str[18] = {0};
	UINT buf_size = 1024;
	UINT sta_num = 0;
	unsigned char mac[ETH_ALEN] = {0};
	if(output_uint == NULL)
		return RETURN_ERR;

	mac_arry = (char *)malloc(buf_size);
	if (mac_arry == NULL) {
		wifi_debug(DEBUG_ERROR, "malloc mac_arry fails\n");
		return RETURN_ERR;
	}
	memset(mac_arry, 0, buf_size);
	/*mac_arry str format: 00:11:22:33:44:55\n00:11:22:33:44:66\0*/
	if (wifi_getApAclDevices(apIndex, mac_arry, buf_size)!= RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "get acl list entries fails\n");
		free(mac_arry);
		return RETURN_ERR;
	}
	/*count the acl str nums:*/
	wifi_debug(DEBUG_NOTICE, "mac_arry: %s\n", mac_arry);

	/*mac addr string format:
	exp1: 00:11:22:33:44:55\0
	exp2: 00:11:22:33:44:55\n00:11:22:33:44:66\0
	*/
	ptr = mac_arry;
	while (sscanf(ptr, "%17s", mac_str) == 1) {
		if (hwaddr_aton2(mac_str, mac) >= 0)
			sta_num++;
		ptr = strstr(ptr, mac_str) + strlen(mac_str);
	}
	*output_uint = sta_num;
	wifi_debug(DEBUG_NOTICE, "output_uint: %d\n", *output_uint);
	free(mac_arry);
	mac_arry = NULL;
	return RETURN_OK;
}

INT apply_rules(INT apIndex, CHAR *client_mac,CHAR *action,CHAR *interface)
{
	char buf[128]={'\0'};
	int res;

	if(strcmp(action,"DENY")==0)
	{
		res = snprintf(buf, sizeof(buf),
			"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",
			apIndex, interface, client_mac);
		if (os_snprintf_error(sizeof(buf), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		system(buf);
		return RETURN_OK;
	}

	if(strcmp(action,"ALLOW")==0)
	{
		res = snprintf(buf, sizeof(buf), 
			"iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",
			apIndex, interface, client_mac);
		if (os_snprintf_error(sizeof(buf), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		system(buf);
		return RETURN_OK;
	}

	return RETURN_ERR;

}

// enable kick for devices on acl black list
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable)
{
	char aclArray[MAX_BUF_SIZE] = {0}, *acl = NULL;
	char assocArray[MAX_BUF_SIZE] = {0};

	wifi_getApDenyAclDevices(apIndex, aclArray, sizeof(aclArray));
	wifi_getApDevicesAssociated(apIndex, assocArray, sizeof(assocArray));

	/* if there are no devices connected there is nothing to do */
	if (strlen(assocArray) < 17)
		return RETURN_OK;

	if (enable == TRUE) {
		/* kick off the MAC which is in ACL array (deny list) */
		acl = strtok(aclArray, "\n");
		while (acl != NULL) {
			if (strlen(acl) >= 17 && strcasestr(assocArray, acl))
				wifi_kickApAssociatedDevice(apIndex, acl);

			acl = strtok(NULL, "\n");
		}
		wifi_setApMacAddressControlMode(apIndex, 2);
	} else
		wifi_setApMacAddressControlMode(apIndex, 0);

	return RETURN_OK;
}

INT wifi_setPreferPrivateConnection(BOOL enable)
{
	return RETURN_OK;
}

// sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
	int if_idx = 0, ret = 0;
	struct unl unl_ins;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	int acl_policy = -1;
	char inf_name[IF_NAME_SIZE] = {0};

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_ACL;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (filterMode == 0) {
		acl_policy = MTK_NL80211_VENDOR_ATTR_ACL_DISABLE;
	} else if (filterMode == 1) {
		acl_policy = MTK_NL80211_VENDOR_ATTR_ACL_ENABLE_WHITE_LIST;
	} else if (filterMode == 2) {
		acl_policy = MTK_NL80211_VENDOR_ATTR_ACL_ENABLE_BLACK_LIST;
	} else {
		wifi_debug(DEBUG_ERROR, "filtermode(%d) not support error\n", filterMode);
		nlmsg_free(msg);
		goto err;
	}
	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_ACL_POLICY, acl_policy)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

// enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE.
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled)
{
	return RETURN_ERR;
}

// gets the vlan ID for this ap from an internal enviornment variable
INT wifi_getApVlanID(INT apIndex, INT *output_int)
{
	if(apIndex==0)
	{
		*output_int=100;
		return RETURN_OK;
	}

	return RETURN_ERR;
}

// sets the vlan ID for this ap to an internal enviornment variable
INT wifi_setApVlanID(INT apIndex, INT vlanId)
{
	//save the vlanID to config and wait for wifi reset to apply (wifi up module would read this parameters and tag the AP with vlan id)
	char interface_name[16] = {0};
	int if_idx, ret = 0;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;

	if (apIndex > MAX_APS) {
		wifi_debug(DEBUG_ERROR, "Invalid apIndex %d\n", apIndex);
		return RETURN_ERR;
	}
	if (vlanId > 4095 || vlanId < 1) {
		wifi_debug(DEBUG_ERROR, "Invalid vlanId %d\n", vlanId);
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	/*step 1. mwctl dev %s set vlan_tag 0*/
	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_VLAN;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	if (nla_put_u16(msg, MTK_NL80211_VENDOR_ATTR_VLAN_ID_INFO, vlanId)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	//wifi_debug(DEBUG_NOTICE, "set vlanId cmd success.\n", vlanId);
	printf("set vlanId=%d cmd success.\n", vlanId);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

char br_name[IFNAMSIZ] = "brlan0";

// gets bridgeName, IP address and Subnet. bridgeName is a maximum of 32 characters,
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	struct sockaddr_in *sin;

	memcpy(bridgeName, br_name, strlen(br_name));

	if (sock == -1) {
		wifi_debug(DEBUG_ERROR, "socket failed");
		return RETURN_ERR;
	}

	strncpy(ifr.ifr_name, br_name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCGIFADDR) failed, %s, bridge_name=%s\n",
			strerror(errno), br_name);
		close(sock);
		return RETURN_ERR;
	}

	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	wifi_debug(DEBUG_ERROR, "Bridge device %s has IP address: %s\n", br_name, inet_ntoa(sin->sin_addr));
	memcpy(IP, inet_ntoa(sin->sin_addr), strlen(inet_ntoa(sin->sin_addr)));

	if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCGIFNETMASK) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}

	wifi_debug(DEBUG_ERROR, "Bridge device %s has subnet mask: %s\n", br_name, inet_ntoa(sin->sin_addr));
	memcpy(subnet, inet_ntoa(sin->sin_addr), strlen(inet_ntoa(sin->sin_addr)));
	close(sock);

	return RETURN_OK;
}

//sets bridgeName, IP address and Subnet to internal enviornment variables. bridgeName is a maximum of 32 characters
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
	//save settings, wait for wifi reset or wifi_pushBridgeInfo to apply.
	struct ifreq ifr;
	struct sockaddr_in sin;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (strlen(bridgeName) >= IFNAMSIZ) {
		wifi_debug(DEBUG_ERROR, "invalide bridgeName length=%ld\n", strlen(bridgeName));
		close(sock);
		return RETURN_ERR;
	}

	if (strlen(br_name) >= IFNAMSIZ) {
		wifi_debug(DEBUG_ERROR, "invalide br_name length=%ld in strorage\n", strlen(br_name));
		close(sock);
		return RETURN_ERR;
	}

	if (sock == -1) {
		wifi_debug(DEBUG_ERROR, "socket failed");
		return RETURN_ERR;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, br_name, strlen(br_name));
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCGIFFLAGS) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}

	ifr.ifr_flags = (short)(ifr.ifr_flags & ~IFF_UP);
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCSIFFLAGS) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, br_name, IFNAMSIZ);
	strncpy(ifr.ifr_newname, bridgeName, IFNAMSIZ);
	if (ioctl(sock, SIOCSIFNAME, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCSIFNAME) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}

	memset(br_name, 0, sizeof(br_name));
	memcpy(br_name, bridgeName, strlen(bridgeName));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, bridgeName, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCGIFFLAGS) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}
	ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP);
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCSIFFLAGS) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, bridgeName, strlen(bridgeName));

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	if (inet_aton(IP, &(sin.sin_addr)) == 0) {
		wifi_debug(DEBUG_ERROR, "inet_aton failed");
		close(sock);
		return RETURN_ERR;
	}
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr_in));
	if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCSIFADDR) failed, %s", strerror(errno));
		close(sock);
		return RETURN_ERR;
	}

	if (inet_aton(subnet, &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr) == 0) {
		wifi_debug(DEBUG_ERROR, "inet_aton failed");
		return RETURN_ERR;
	}
	if (ioctl(sock, SIOCSIFNETMASK, &ifr) < -1) {
		wifi_debug(DEBUG_ERROR, "ioctl(SIOCSIFNETMASK) failed, %s", strerror(errno));
		return RETURN_ERR;
	}

	close(sock);
	return RETURN_ERR;
}

// reset the vlan configuration for this ap
INT wifi_resetApVlanCfg(INT apIndex)
{
	char interface_name[16] = {0};
	int if_idx, ret = 0;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;
	struct vlan_policy_param vlan_param;

	if (apIndex > MAX_APS) {
		wifi_debug(DEBUG_ERROR, "Invalid apIndex %d\n", apIndex);
		return RETURN_ERR;
	}

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	/*step 1. mwctl dev %s set vlan_tag 0*/
	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_VLAN;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);

	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_VLAN_TAG_INFO, 0)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set vlan_tag 0 cmd success.\n");

	/*step 2. mwctl dev %s set vlan_priority 0*/
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_VLAN_PRIORITY_INFO, 0)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set vlan_priority 0 cmd success.\n");

	/*step 3. mwctl dev %s set vlan_id 0*/
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put_u16(msg, MTK_NL80211_VENDOR_ATTR_VLAN_ID_INFO, 0)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set vlan_id cmd success.\n");

	/*step 4. mwctl dev %s set vlan_en 0*/
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_VLAN_EN_INFO, 0)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set vlan_id cmd success.\n");

	/*step 5. mwctl dev %s set vlan_policy 0:4*/
	vlan_param.direction = 0;
	vlan_param.policy = 4;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_VLAN_POLICY_INFO, sizeof(vlan_param), &vlan_param)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set vlan_policy 0:4 cmd success.\n");

	/*step 6. mwctl dev %s set vlan_policy 1:0*/
	vlan_param.direction = 1;
	vlan_param.policy = 0;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_VLAN_POLICY_INFO, sizeof(vlan_param), &vlan_param)) {
		printf("Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set vlan_policy 1:0 cmd success.\n");

	/*TODO need to modify VLAN config in dat file*/
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

// creates configuration variables needed for WPA/WPS.  These variables are implementation dependent and in some implementations these variables are used by hostapd when it is started.  Specific variables that are needed are dependent on the hostapd implementation. These variables are set by WPA/WPS security functions in this wifi HAL.  If not needed for a particular implementation this function may simply return no error.
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg)
{
	return RETURN_OK;
}

// starts hostapd, uses the variables in the hostapd config with format compatible with the specific hostapd implementation
INT wifi_startHostApd()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	system("systemctl start hostapd.service");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
	//sprintf(cmd, "hostapd  -B `cat /tmp/conf_filename` -e /nvram/etc/wpa2/entropy -P /tmp/hostapd.pid 1>&2");
}

// stops hostapd
INT wifi_stopHostApd()
{
	char cmd[128] = {0};
	char buf[128] = {0};
	int res;

	res = snprintf(cmd, sizeof(cmd), "systemctl stop hostapd");
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

// restart hostapd dummy function
INT wifi_restartHostApd()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	system("systemctl restart hostapd-global");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// sets the AP enable status variable for the specified ap.
INT wifi_setApEnable(INT apIndex, BOOL enable)
{
	char interface_name[16] = {0};
	char config_file[MAX_SUB_CMD_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	BOOL status = FALSE;
	int  max_radio_num = 0;
	int phyId = 0;
	int res;

	wifi_getApEnable(apIndex, &status);

	wifi_getMaxRadioNumber(&max_radio_num);
	if (enable == status)
		return RETURN_OK;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if (enable == TRUE) {
		int radioIndex = apIndex % max_radio_num;
		phyId = radio_index_to_phy(radioIndex);
		res = snprintf(cmd, MAX_CMD_SIZE, "ifconfig %s up", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));

		res = snprintf(config_file, MAX_BUF_SIZE, "%s%d.conf", CONFIG_PREFIX, apIndex);
		if (os_snprintf_error(MAX_BUF_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		res = snprintf(cmd, MAX_CMD_SIZE, "hostapd_cli -i global raw ADD bss_config=phy%d:%s", phyId, config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
	} else {
		res = snprintf(cmd, MAX_CMD_SIZE, "hostapd_cli -i global raw REMOVE %s", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		res = snprintf(cmd, MAX_CMD_SIZE, "ifconfig %s down", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
	}
	res = snprintf(cmd, MAX_CMD_SIZE, "sed -i -n -e '/^%s=/!p' -e '$a%s=%d' %s",
				interface_name, interface_name, enable, VAP_STATUS_FILE);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	//Wait for wifi up/down to apply
	return RETURN_OK;
}

// Outputs the setting of the internal variable that is set by wifi_setApEnable().
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
	char interface_name[IF_NAME_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;

	if ((!output_bool) || (apIndex < 0) || (apIndex >= MAX_APS))
		return RETURN_ERR;

	*output_bool = 0;

	if ((apIndex >= 0) && (apIndex < MAX_APS)) {
		if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK) {
			*output_bool = FALSE;
			return RETURN_OK;
		}

		res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s status | grep state | cut -d '=' -f2", interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));

		if(strncmp(buf, "ENABLED", 7) == 0 || strncmp(buf, "ACS", 3) == 0 ||
			strncmp(buf, "HT_SCAN", 7) == 0 || strncmp(buf, "DFS", 3) == 0) {
			*output_bool = TRUE;
		}
	}

	return RETURN_OK;
}

// Outputs the AP "Enabled" "Disabled" status from driver
INT wifi_getApStatus(INT apIndex, CHAR *output_string)
{
	BOOL output_bool = 0;
	int res;

	if (!output_string) {
		printf("%s: null pointer!", __func__);
		return RETURN_ERR;
	}

	wifi_getApEnable(apIndex, &output_bool);

	if(output_bool == 1)
		res = snprintf(output_string, 32, "Up");
	else
		res = snprintf(output_string, 32, "Disable");
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

//Indicates whether or not beacons include the SSID name.
// outputs a 1 if SSID on the AP is enabled, else outputs 0
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output)
{
	//get the running status
	char config_file[MAX_BUF_SIZE] = {0};
	char buf[16] = {0};
	int res;

	if (!output)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file),
		"%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "ignore_broadcast_ssid", buf, sizeof(buf));
	// default is enable
	if (strlen(buf) == 0 || strncmp("0", buf, 1) == 0)
		*output = TRUE;

	return RETURN_OK;
}

// sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
	//store the config, apply instantly
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	list.name = "ignore_broadcast_ssid";
	list.value = enable?"0":"1";

	res = snprintf(config_file, sizeof(config_file),
		"%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);
	wifi_hostapdProcessUpdate(apIndex, &list, 1);
	//TODO: call hostapd_cli for dynamic_config_control
	wifi_reloadAp(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output_uint)
{
	/* get the running status */
	if(!output_uint)
		return RETURN_ERR;

	*output_uint = 15;
	return RETURN_OK;
}

/*Do not support AP retry limit fix*/
INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
	return RETURN_ERR;
}

int get_wmm_cap_status_callback(struct nl_msg *msg, void *data)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *vndr_tb[MTK_NL80211_VENDOR_WMM_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	unsigned char *status = (unsigned char *)data;
	int err = 0;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(vndr_tb, MTK_NL80211_VENDOR_WMM_ATTR_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;

		if (vndr_tb[MTK_NL80211_VENDOR_ATTR_WMM_AP_CAP_INFO]) {
			*status = nla_get_u8(vndr_tb[MTK_NL80211_VENDOR_ATTR_WMM_AP_CAP_INFO]);
		}
	}

	return 0;
}

//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, BOOL *output)
{
	int if_idx, ret = 0;
	char interface_name[16] = {0};
	unsigned char status = 0;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output)
		return RETURN_ERR;

	if (apIndex > MAX_APS) {
		wifi_debug(DEBUG_ERROR, "Invalid apIndex %d\n", apIndex);
		return RETURN_ERR;
	}

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_WMM;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);

	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_WMM_AP_CAP_INFO, 0xf)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, get_wmm_cap_status_callback,
		(void *)&status);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);

	*output = status == 0 ? FALSE : TRUE;
	wifi_debug(DEBUG_NOTICE, "wmm cap (%u).\n", (unsigned int)(*output));

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}

//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output)
{
	//get the running status from driver
	char cmd[128] = {0};
	char buf[128] = {0};
	int max_radio_num = 0, radioIndex = 0;
	int phyId = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	radioIndex = apIndex % max_radio_num;
	phyId = radio_index_to_phy(radioIndex);
	res = snprintf(cmd, sizeof(cmd), "iw phy phy%d info | grep u-APSD", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf, sizeof(buf));

	if (strlen(buf) > 0)
		*output = true;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//Whether WMM support is currently enabled. When enabled, this is indicated in beacon frames.
INT wifi_getApWmmEnable(INT apIndex, BOOL *output)
{
	return wifi_getApWMMCapability(apIndex, output);
}

// enables/disables WMM on the hardwawre for this AP.  enable==1, disable == 0
INT wifi_setApWmmEnable(INT apIndex, BOOL enable)
{
	int if_idx, ret = 0;
	char interface_name[16] = {0};
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (apIndex > MAX_APS) {
		wifi_debug(DEBUG_ERROR, "Invalid apIndex %d\n", apIndex);
		return RETURN_ERR;
	}

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_WMM;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);

	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_WMM_AP_CAP_INFO, enable ? 1 : 0)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vendor msg fails\n");
		goto err;
	}
	mtk_nl80211_deint(&unl_ins);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}


//Whether U-APSD support is currently enabled. When enabled, this is indicated in beacon frames. Note: U-APSD can only be enabled if WMM is also enabled.
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output)
{
	int res;

	//get the running status from driver
	if(!output)
		return RETURN_ERR;

	char config_file[128] = {0};
	char buf[16] = {0};

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "uapsd_advertisement_enabled", buf, sizeof(buf));
	if (strlen(buf) == 0 || strncmp("1", buf, 1) == 0)
		*output = TRUE;
	else
		*output = FALSE;

	return RETURN_OK;
}

// enables/disables Automatic Power Save Delivery on the hardwarwe for this AP
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable)
{
	//save config and apply instantly.
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	list.name = "uapsd_advertisement_enabled";
	list.value = enable?"1":"0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);
	wifi_hostapdProcessUpdate(apIndex, &list, 1);
	wifi_quick_reload_ap(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// Sets the WMM ACK policy on the hardware. AckPolicy false means do not acknowledge, true means acknowledge
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT class, BOOL ackPolicy)  //RDKB
{
	char interface_name[16] = {0};
	// assume class 0->BE, 1->BK, 2->VI, 3->VO
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[128] = {0};
	char ack_filepath[128] = {0};
	uint16_t bitmap = 0;
	uint16_t class_map[4] = {0x0009, 0x0006, 0x0030, 0x00C0};
	FILE *f = NULL;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	// Get current setting
	res = snprintf(ack_filepath, sizeof(ack_filepath), "%s%d.txt", NOACK_MAP_FILE, apIndex);
	if (os_snprintf_error(sizeof(ack_filepath), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	res = snprintf(cmd, sizeof(cmd), "cat %s 2> /dev/null", ack_filepath);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0)
		bitmap = strtoul(buf, NULL, 10);

	//bitmap = strtoul(buf, NULL, 10);

	if (ackPolicy == TRUE) {	// True, unset this class
		bitmap &= ~class_map[class];
	} else {					// False, set this class
		bitmap |= class_map[class];
	}

	f = fopen(ack_filepath, "w");
	if (f == NULL) {
		fprintf(stderr, "%s: fopen failed\n", __func__);
		return RETURN_ERR;
	}
	fprintf(f, "%hu", bitmap);
	fclose(f);

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "iw dev %s set noack_map 0x%04x\n", interface_name, bitmap);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

//The maximum number of devices that can simultaneously be connected to the access point. A value of 0 means that there is no specific limit.
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output_uint)
{
	int res;

	//get the running status from driver
	if(!output_uint)
		return RETURN_ERR;

	char output[16]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "max_num_sta", output, sizeof(output));
	if (strlen(output) == 0) *output_uint = MAX_ASSOCIATED_STA_NUM;
	else {
		int device_num = atoi(output);
		if (device_num > MAX_ASSOCIATED_STA_NUM || device_num < 0) {
			wifi_dbg_printf("\n[%s]: get max_num_sta error: %d", __func__, device_num);
			return RETURN_ERR;
		}
		else {
			*output_uint = device_num;
		}
	}

	return RETURN_OK;
}

INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number)
{
	//store to wifi config, apply instantly
	char str[MAX_BUF_SIZE]={'\0'};
	struct params params;
	char config_file[MAX_BUF_SIZE] = {0};
	int res, ret;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (number > MAX_ASSOCIATED_STA_NUM) {
		WIFI_ENTRY_EXIT_DEBUG("%s: Invalid input\n",__func__);
		return RETURN_ERR;
	}
	res = snprintf(str, sizeof(str), "%d", number);
	if (os_snprintf_error(sizeof(str), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.name = "max_num_sta";
	params.value = str;

	res = snprintf(config_file,
		sizeof(config_file), "%s%d.conf",CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret = wifi_hostapdWrite(config_file, &params, 1);
	if (ret) {
		WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdWrite() return %d\n"
				,__func__, ret);
	}

	ret = wifi_hostapdProcessUpdate(apIndex, &params, 1);
	if (ret) {
		WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdProcessUpdate() return %d\n"
				,__func__, ret);
	}
	wifi_reloadAp(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

//The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices. Setting this parameter does not actually limit the number of clients that can associate with this access point as that is controlled by MaxAssociatedDevices.	MaxAssociatedDevices or 50. The default value of this parameter should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50. A value of 0 means that there is no specific limit and Watermark calculation algorithm should be turned off.
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output_uint)
{
	//get the current threshold
	if(!output_uint)
		return RETURN_ERR;
	wifi_getApMaxAssociatedDevices(apIndex, output_uint);
	if (*output_uint == 0)
		*output_uint = 50;
	return RETURN_OK;
}

INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold)
{
	//store the config, reset threshold, reset AssociatedDevicesHighWatermarkThresholdReached, reset AssociatedDevicesHighWatermarkDate to current time
	if (!wifi_setApMaxAssociatedDevices(apIndex, Threshold))
		return RETURN_OK;
	return RETURN_ERR;
}

//Number of times the current total number of associated device has reached the HighWatermarkThreshold value. This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well. Implementation specifics about this parameter are left to the product group and the device vendors. It can be updated whenever there is a new client association request to the access point.
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output_uint)
{
	if(!output_uint)
		return RETURN_ERR;
	*output_uint = 3;
	return RETURN_OK;
}

//Maximum number of associated devices that have ever associated with the access point concurrently since the last reset of the device or WiFi module.
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output_uint)
{
	if(!output_uint)
		return RETURN_ERR;
	*output_uint = 3;
	return RETURN_OK;
}

//Date and Time at which the maximum number of associated devices ever associated with the access point concurrenlty since the last reset of the device or WiFi module (or in short when was X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This dateTime value is in UTC.
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds)
{
	if(!output_in_seconds)
		return RETURN_ERR;
	*output_in_seconds = 0;
	return RETURN_OK;
}

//Comma-separated list of strings. Indicates which security modes this AccessPoint instance is capable of supporting. Each list item is an enumeration of: None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output)
{
	int res;

	if(!output || apIndex>=MAX_APS)
		return RETURN_ERR;
	//res = snprintf(output, 128, "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise");
	res = snprintf(output, 128, "None,WPA2-Personal,WPA-WPA2-Personal,WPA2-Enterprise,WPA-WPA2-Enterprise,WPA3-Personal,WPA3-Enterprise");
	if (os_snprintf_error(128, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	return RETURN_OK;
}

//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output)
{
	char config_file[128] = {0};
	char wpa[16] = {0};
	char key_mgmt[64] = {0};
	int res = -1;

	if (!output)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "wpa", wpa, sizeof(wpa));

	memcpy(output, "None", 4);//Copying "None" to output string for default case
	output[4] = '\0';
	wifi_hostapdRead(config_file, "wpa_key_mgmt", key_mgmt, sizeof(key_mgmt));
	if (strstr(key_mgmt, "WPA-PSK") && strstr(key_mgmt, "SAE") == NULL) {
		if (!strcmp(wpa, "1"))
			res = snprintf(output, 32, "WPA-Personal");
		else if (!strcmp(wpa, "2"))
			res = snprintf(output, 32, "WPA2-Personal");
		else if (!strcmp(wpa, "3"))
			res = snprintf(output, 32, "WPA-WPA2-Personal");

	} else if (strstr(key_mgmt, "WPA-EAP-SUITE-B-192")) {
		res = snprintf(output, 32, "WPA3-Enterprise");
	} else if (strstr(key_mgmt, "WPA-EAP")) {
		if (!strcmp(wpa, "1"))
			res = snprintf(output, 32, "WPA-Enterprise");
		else if (!strcmp(wpa, "2"))
			res = snprintf(output, 32, "WPA2-Enterprise");
		else if (!strcmp(wpa, "3"))
			res = snprintf(output, 32, "WPA-WPA2-Enterprise");
	} else if (strstr(key_mgmt, "SAE")) {
		if (strstr(key_mgmt, "WPA-PSK") == NULL)
			res = snprintf(output, 32, "WPA3-Personal");
		else
			res = snprintf(output, 32, "WPA3-Personal-Transition");
	}
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	//save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
	return RETURN_OK;
}

INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode)
{
	char securityType[32] = {0};
	char authMode[32] = {0};
	unsigned long len_sec, len_auth;
	//store settings and wait for wifi up to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!encMode)
		return RETURN_ERR;

	if (strcmp(encMode, "None")==0)
	{
		len_sec = strlen("None");
		len_auth = strlen("None");
		memcpy(securityType, "None", len_sec);
		memcpy(authMode, "None", len_auth);
	} else if (strcmp(encMode, "WPA-WPA2-Personal")==0) {
		len_sec = strlen("WPAand11i");
		memcpy(securityType, "WPAand11i", len_sec);
		len_auth = strlen("PSKAuthentication");
		memcpy(authMode, "PSKAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA-WPA2-Enterprise")==0) {
		len_sec = strlen("WPAand11i");
		memcpy(securityType, "WPAand11i", len_sec);
		len_auth = strlen("EAPAuthentication");
		memcpy(authMode, "EAPAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA-Personal")==0) {
		len_sec = strlen("WPA");
		memcpy(securityType, "WPA", len_sec);
		len_auth = strlen("PSKAuthentication");
		memcpy(authMode, "PSKAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA-Enterprise")==0) {
		len_sec = strlen("WPA");
		memcpy(securityType, "WPA", len_sec);
		len_auth = strlen("EAPAuthentication");
		memcpy(authMode, "EAPAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA2-Personal")==0) {
		len_sec = strlen("11i");
		memcpy(securityType, "11i", len_sec);
		len_auth = strlen("PSKAuthentication");
		memcpy(authMode, "PSKAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA2-Enterprise")==0) {
		len_sec = strlen("11i");
		memcpy(securityType, "11i", len_sec);
		len_auth = strlen("EAPAuthentication");
		memcpy(authMode, "EAPAuthentication", len_auth);
 	} else if (strcmp(encMode, "WPA3-Personal") == 0) {
		len_sec = strlen("11i");
		memcpy(securityType, "11i", len_sec);
		len_auth = strlen("SAEAuthentication");
		memcpy(authMode, "SAEAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA3-Personal-Transition") == 0) {
		len_sec = strlen("11i");
		memcpy(securityType, "11i", len_sec);
		len_auth = strlen("PSK-SAEAuthentication");
		memcpy(authMode, "PSK-SAEAuthentication", len_auth);
	} else if (strcmp(encMode, "WPA3-Enterprise") == 0) {
		len_sec = strlen("11i");
		memcpy(securityType, "11i", len_sec);
		len_auth = strlen("EAP_192-bit_Authentication");
		memcpy(authMode, "EAP_192-bit_Authentication", len_auth);
	} else if (strcmp(encMode, "OWE") == 0) {
		len_sec = strlen("11i");
		memcpy(securityType, "11i", len_sec);
		len_auth = strlen("Enhanced_Open");
		memcpy(authMode, "Enhanced_Open", len_auth);
 	} else {
		len_sec = strlen("None");
		memcpy(securityType, "None", len_sec);
		len_auth = strlen("None");
		memcpy(authMode, "None", len_auth);
	}
	securityType[len_sec] = '\0';
	authMode[len_auth] = '\0';
	wifi_setApBeaconType(apIndex, securityType);
	wifi_setApBasicAuthenticationMode(apIndex, authMode);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}


//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
// output_string must be pre-allocated as 64 character string by caller
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string)
{
	char buf[16] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	if(output_string==NULL)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file,"wpa",buf,sizeof(buf));

	if(strcmp(buf,"0")==0)
	{
		printf("wpa_mode is %s ......... \n",buf);
		return RETURN_ERR;
	}

	wifi_dbg_printf("\nFunc=%s\n",__func__);
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file,"wpa_psk",output_string,65);
	wifi_dbg_printf("\noutput_string=%s\n",output_string);

	return RETURN_OK;
}

// sets an enviornment variable for the psk. Input string preSharedKey must be a maximum of 64 characters
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey)
{
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	struct params params={'\0'};
	int ret;
	char config_file[MAX_BUF_SIZE] = {0};

	if(NULL == preSharedKey)
		return RETURN_ERR;

	params.name = "wpa_psk";

	if(strlen(preSharedKey) != 64)
	{
		wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 64 chars\n");
		return RETURN_ERR;
	}
	params.value = preSharedKey;
	ret = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), ret)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret = wifi_hostapdWrite(config_file, &params, 1);
	if(!ret) {
		ret = wifi_hostapdProcessUpdate(apIndex, &params, 1);
		wifi_reloadAp(apIndex);
	}
	return ret;
	//TODO: call hostapd_cli for dynamic_config_control
}

//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
// outputs the passphrase, maximum 63 characters
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string)
{
	char config_file[MAX_BUF_SIZE] = {0}, buf[32] = {0};
	int res;

	wifi_dbg_printf("\nFunc=%s\n",__func__);
	if (NULL == output_string)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdRead(config_file,"wpa",buf,sizeof(buf));
	if(strcmp(buf,"0")==0)
	{
		printf("wpa_mode is %s ......... \n",buf);
		return RETURN_ERR;
	}

	wifi_hostapdRead(config_file,"wpa_passphrase",output_string,64);
	wifi_dbg_printf("\noutput_string=%s\n",output_string);

	return RETURN_OK;
}

// sets the passphrase enviornment variable, max 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase)
{
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	struct params params={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int ret;

	if(NULL == passPhrase)
		return RETURN_ERR;

	if(strlen(passPhrase)<8 || strlen(passPhrase)>63)
	{
		wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
		return RETURN_ERR;
	}
	params.name = "wpa_passphrase";
	params.value = passPhrase;
	ret = snprintf(config_file, sizeof(config_file),
		"%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), ret)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	ret=wifi_hostapdWrite(config_file,&params,1);
	if(!ret) {
		wifi_hostapdProcessUpdate(apIndex, &params, 1);
		wifi_reloadAp(apIndex);
	}

	return ret;
}

//When set to true, this AccessPoint instance's WiFi security settings are reset to their factory default values. The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
INT wifi_setApSecurityReset(INT apIndex)
{
	char original_config_file[64] = {0};
	char current_config_file[64] = {0};
	char buf[64] = {0};
	char cmd[64] = {0};
	char wpa[4] = {0};
	char wpa_psk[64] = {0};
	char wpa_passphrase[64] = {0};
	char wpa_psk_file[128] = {0};
	char wpa_key_mgmt[64] = {0};
	char wpa_pairwise[32] = {0};
	wifi_band band;
	struct params list[6];
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	band = wifi_index_to_band(apIndex);
	if (band == band_2_4)
		sprintf(original_config_file, "/etc/hostapd-2G.conf");
	else if (band == band_5)
		sprintf(original_config_file, "/etc/hostapd-5G.conf");
	else if (band == band_6)
		sprintf(original_config_file, "/etc/hostapd-6G.conf");
	else
		return RETURN_ERR;

	wifi_hostapdRead(original_config_file, "wpa", wpa, sizeof(wpa));
	list[0].name = "wpa";
	list[0].value = wpa;

	wifi_hostapdRead(original_config_file, "wpa_psk", wpa_psk, sizeof(wpa_psk));
	list[1].name = "wpa_psk";
	list[1].value = wpa_psk;

	wifi_hostapdRead(original_config_file, "wpa_passphrase", wpa_passphrase, sizeof(wpa_passphrase));
	list[2].name = "wpa_passphrase";
	list[2].value = wpa_passphrase;

	wifi_hostapdRead(original_config_file, "wpa_psk_file", wpa_psk_file, sizeof(wpa_psk_file));

	if (strlen(wpa_psk_file) == 0)
		memcpy(wpa_psk_file, PSK_FILE, strlen(PSK_FILE));

	if (access(wpa_psk_file, F_OK) != 0) {
		res = snprintf(cmd, MAX_CMD_SIZE, "touch %s", wpa_psk_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
	}
	list[3].name = "wpa_psk_file";
	list[3].value = wpa_psk_file;

	wifi_hostapdRead(original_config_file, "wpa_key_mgmt", wpa_key_mgmt, sizeof(wpa_key_mgmt));
	list[4].name = "wpa_key_mgmt";
	list[4].value = wpa_key_mgmt;

	wifi_hostapdRead(original_config_file, "wpa_pairwise", wpa_pairwise, sizeof(wpa_pairwise));
	list[5].name = "wpa_pairwise";
	list[5].value = wpa_pairwise;

	res = snprintf(current_config_file, sizeof(current_config_file),
		"%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(current_config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(current_config_file, list, 6);

	wifi_setApEnable(apIndex, FALSE);
	wifi_setApEnable(apIndex, TRUE);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//The IP Address and port number of the RADIUS server used for WLAN security. RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
	char config_file[64] = {0};
	char buf[64] = {0};
	char cmd[256] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if(!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;

	// Read the first matched config
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	res = snprintf(cmd, sizeof(cmd),
		"cat %s | grep \"^auth_server_addr=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	strncpy(IP_output, buf, 64);

	memset(buf, 0, sizeof(buf));
	res = snprintf(cmd, sizeof(cmd), "cat %s | grep \"^auth_server_port=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	*Port_output = atoi(buf);

	memset(buf, 0, sizeof(buf));
	res = snprintf(cmd, sizeof(cmd), "cat %s | grep \"^auth_server_shared_secret=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	strncpy(RadiusSecret_output, buf, 64);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
	char config_file[64] = {0};
	char port_str[8] = {0};
	char cmd[256] = {0};
	char buf[128] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_getApSecurityModeEnabled(apIndex, buf) != RETURN_OK)
		return RETURN_ERR;

	if (strstr(buf, "Enterprise") == NULL)  // non Enterprise mode sould not set radius server info
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "cat %s | grep '# radius 1'", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	memset(cmd, 0, sizeof(cmd));

	res = snprintf(port_str, sizeof(port_str), "%d", port);
	if (strlen(buf) == 0) {
		// Append
		res = snprintf(cmd, sizeof(cmd), "echo -e '# radius 1\\n"
								"auth_server_addr=%s\\n"
								"auth_server_port=%s\\n"
								"auth_server_shared_secret=%s' >> %s", IPAddress, port_str, RadiusSecret, config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else {
		// Delete the three lines setting after the "# radius 1" comment
		res = snprintf(cmd, sizeof(cmd), "sed -i '/# radius 1/{n;N;N;d}' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		memset(cmd, 0, sizeof(cmd));
		// Use "# radius 1" comment to find the location to insert the radius setting
		res = snprintf(cmd, sizeof(cmd), "sed -i 's/# radius 1/"
								"# radius 1\\n"
								"auth_server_addr=%s\\n"
								"auth_server_port=%s\\n"
								"auth_server_shared_secret=%s/' %s", IPAddress, port_str, RadiusSecret, config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	}
	if(_syscmd(cmd, buf, sizeof(buf))) {
		wifi_dbg_printf("%s: command failed, cmd: %s\n", __func__, cmd);
		return RETURN_ERR;
	}

	wifi_reloadAp(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
	char config_file[64] = {0};
	char buf[64] = {0};
	char cmd[256] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if(!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;

	// Read the second matched config
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd),
		"cat %s | grep \"^auth_server_addr=\" | cut -d \"=\" -f 2 | tail -n +2 | head -n1 | tr -d \"\\n\"",
		config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	strncpy(IP_output, buf, 64);

	memset(buf, 0, sizeof(buf));
	res = snprintf(cmd, sizeof(cmd),
		"cat %s | grep \"^auth_server_port=\" | cut -d \"=\" -f 2 | tail -n +2 | head -n1 | tr -d \"\\n\"",
		config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	*Port_output = atoi(buf);

	memset(buf, 0, sizeof(buf));
	res = snprintf(cmd, sizeof(cmd),
		"cat %s | grep \"^auth_server_shared_secret=\" | cut -d \"=\" -f 2 | tail -n +2 | head -n1 | tr -d \"\\n\"",
		config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	strncpy(RadiusSecret_output, buf, 64);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
	char config_file[64] = {0};
	char port_str[8] = {0};
	char cmd[256] = {0};
	char buf[128] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_getApSecurityModeEnabled(apIndex, buf) != RETURN_OK)
		return RETURN_ERR;

	if (strstr(buf, "Enterprise") == NULL)  // non Enterprise mode sould not set radius server info
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "cat %s | grep '# radius 2'", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	memset(cmd, 0, sizeof(cmd));

	res = snprintf(port_str, sizeof(port_str), "%d", port);
	if (os_snprintf_error(sizeof(port_str), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (strlen(buf) == 0) {
		// Append
		res = snprintf(cmd, sizeof(cmd), "echo -e '# radius 2\\n"
								"auth_server_addr=%s\\n"
								"auth_server_port=%s\\n"
								"auth_server_shared_secret=%s' >> %s", IPAddress, port_str, RadiusSecret, config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else {
		// Delete the three lines setting after the "# radius 2" comment
		res = snprintf(cmd, sizeof(cmd), "sed -i '/# radius 2/{n;N;N;d}' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
		memset(cmd, 0, sizeof(cmd));
		// Use "# radius 2" comment to find the location to insert the radius setting
		res = snprintf(cmd, sizeof(cmd), "sed -i 's/# radius 2/"
								"# radius 2\\n"
								"auth_server_addr=%s\\n"
								"auth_server_port=%s\\n"
								"auth_server_shared_secret=%s/' %s", IPAddress, port_str, RadiusSecret, config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	}
	if(_syscmd(cmd, buf, sizeof(buf))) {
		wifi_dbg_printf("%s: command failed, cmd: %s\n", __func__, cmd);
		return RETURN_ERR;
	}

	wifi_reloadAp(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//RadiusSettings
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output)
{
	if(!output)
		return RETURN_ERR;

	output->RadiusServerRetries = 3; 				//Number of retries for Radius requests.
	output->RadiusServerRequestTimeout = 5; 		//Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.
	output->PMKLifetime = 28800; 					//Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).
	output->PMKCaching = FALSE; 					//Enable or disable caching of PMK.
	output->PMKCacheInterval = 300; 				//Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).
	output->MaxAuthenticationAttempts = 3; 		//Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
	output->BlacklistTableTimeout = 600; 			//Time interval in seconds for which a client will continue to be blacklisted once it is marked so.
	output->IdentityRequestRetryInterval = 5; 	//Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.
	output->QuietPeriodAfterFailedAuthentication = 5;  	//The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.
	//res = snprintf(output->RadiusSecret, 64, "12345678");		//The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

	return RETURN_OK;
}

INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input)
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

//Device.WiFi.AccessPoint.{i}.WPS.Enable
//Enables or disables WPS functionality for this access point.
// outputs the WPS enable state of this ap in output_bool
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool)
{
	char interface_name[16] = {0};
	char buf[MAX_BUF_SIZE] = {0}, cmd[MAX_CMD_SIZE] = {0};
	int res;

	if(!output_bool)
		return RETURN_ERR;
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd),
		"hostapd_cli -i %s get_config | grep wps_state | cut -d '=' -f2",
		interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if(strstr(buf, "configured"))
		*output_bool=TRUE;
	else
		*output_bool=FALSE;

	return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.Enable
// sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled
INT wifi_setApWpsEnable(INT apIndex, BOOL enable)
{
	char config_file[MAX_BUF_SIZE] = {0};
	char buf[128] = {0};
	struct params params;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//store the paramters, and wait for wifi up to apply
	params.name = "wps_state";
	if (enable == TRUE) {
		wifi_getApBeaconType(apIndex, buf);
		if (strncmp(buf, "None", 4) == 0)   // If ap didn't set encryption
			params.value = "1";
		else								// If ap set encryption
			params.value = "2";
	} else {
		params.value = "0";
	}

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(apIndex, &params, 1);
	wifi_reloadAp(apIndex);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output)
{
	int res;
	if(!output)
		return RETURN_ERR;
	res = snprintf(output, 128, "PushButton,PIN");
	if (os_snprintf_error(128, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled
//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
// Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output)
{
	int res;
	if(!output)
		return RETURN_ERR;
	res = snprintf(output, 64, "PushButton,PIN");//Currently, supporting these two methods
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled
// sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString)
{
	//apply instantly. No setting need to be stored.
	char methods[MAX_BUF_SIZE], *token, *next_token;
	char config_file[MAX_BUF_SIZE], config_methods[MAX_BUF_SIZE] = {0};
	struct params params;
	int res;

	if(!methodString)
		return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//store the paramters, and wait for wifi up to apply

	res = snprintf(methods, sizeof(methods), "%s", methodString);
	if (os_snprintf_error(sizeof(methods), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	for(token=methods; *token; token=next_token) {
		strtok_r(token, ",", &next_token);
		if(*token=='U' && !strcmp(methods, "USBFlashDrive"))
			res = snprintf(config_methods, sizeof(config_methods), "%s ", "usba");
		else if(*token=='E')
		{
			if(!strcmp(methods, "Ethernet"))
				res = snprintf(config_methods, sizeof(config_methods), "%s ", "ethernet");
			else if(!strcmp(methods, "ExternalNFCToken"))
				res = snprintf(config_methods, sizeof(config_methods), "%s ", "ext_nfc_token");
			else
				printf("%s: Unknown WpsConfigMethod\n", __func__);
		}
		else if(*token=='I' && !strcmp(token, "IntegratedNFCToken"))
			res = snprintf(config_methods, sizeof(config_methods), "%s ", "int_nfc_token");
		else if(*token=='N' && !strcmp(token, "NFCInterface"))
			res = snprintf(config_methods, sizeof(config_methods), "%s ", "nfc_interface");
		else if(*token=='P' )
		{
			if(!strcmp(token, "PushButton"))
				res = snprintf(config_methods, sizeof(config_methods), "%s ", "push_button");
			else if(!strcmp(token, "PIN"))
				res = snprintf(config_methods, sizeof(config_methods), "%s ", "keypad");
			else
				printf("%s: Unknown WpsConfigMethod\n", __func__);
		}
		else
			printf("%s: Unknown WpsConfigMethod\n", __func__);
	}
	if (os_snprintf_error(sizeof(config_methods), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	params.name = "config_methods";
	params.value = config_methods;
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(apIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	int res;

	if(!output_ulong)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "cat %s%d.conf | grep ap_pin | cut -d '=' -f2", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if(strlen(buf) > 0)
		*output_ulong=strtoul(buf, NULL, 10);

	return RETURN_OK;
}

// set an enviornment variable for the WPS pin for the selected AP. Normally, Device PIN should not be changed.
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin)
{
	//set the pin to wifi config and hostpad config. wait for wifi reset or hostapd reset to apply
	char ap_pin[16] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	struct params params;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	res = snprintf(ap_pin, sizeof(ap_pin), "%lu", pin);
	if (os_snprintf_error(sizeof(ap_pin), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.name = "ap_pin";
	params.value = ap_pin;
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);
	wifi_hostapdProcessUpdate(apIndex, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// Output string is either Not configured or Configured, max 32 characters
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string)
{
	char interface_name[16] = {0};
	char cmd[MAX_CMD_SIZE];
	char buf[MAX_BUF_SIZE]={0};
	int res;

	if(!output_string)
		return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	res = snprintf(output_string, 32, "Not configured");
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s get_config | grep wps_state | cut -d'=' -f2", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	if(!strncmp(buf, "configured", 10))
		res = snprintf(output_string, 32, "Configured");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

// sets the WPS pin for this AP
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin)
{
	char interface_name[16] = {0};
	char cmd[MAX_CMD_SIZE];
	char buf[MAX_BUF_SIZE]={0};
	BOOL enable = 0;
	int res;

	wifi_getApEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;
	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s wps_pin any %s", interface_name, pin);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if((strstr(buf, "OK"))!=NULL)
		return RETURN_OK;

	return RETURN_ERR;
}

// This function is called when the WPS push button has been pressed for this AP
INT wifi_setApWpsButtonPush(INT apIndex)
{
	char cmd[MAX_CMD_SIZE];
	char buf[MAX_BUF_SIZE]={0};
	char interface_name[16] = {0};
	BOOL enable=FALSE;
	int res;

	wifi_getApEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s wps_cancel; hostapd_cli -i%s wps_pbc", interface_name, interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	if((strstr(buf, "OK"))!=NULL)
		return RETURN_OK;
	return RETURN_ERR;
}

// cancels WPS mode for this AP
INT wifi_cancelApWPS(INT apIndex)
{
	char interface_name[16] = {0};
	char cmd[MAX_CMD_SIZE];
	char buf[MAX_BUF_SIZE]={0};
	int res;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s wps_cancel", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf, sizeof(buf));

	if((strstr(buf, "OK"))!=NULL)
		return RETURN_OK;
	return RETURN_ERR;
}

//Device.WiFi.AccessPoint.{i}.AssociatedDevice.*
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
	char interface_name[16] = {0};
	FILE *f = NULL;
	int read_flag=0, auth_temp=0, mac_temp=0;
	char cmd[256] = {0}, buf[2048] = {0};
	char *param = NULL, *value = NULL, *line=NULL;
	size_t len = 0;
	wifi_associated_dev_t *dev=NULL;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	*associated_dev_array = NULL;
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s all_sta | grep AUTHORIZED | wc -l", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf,sizeof(buf));
	*output_array_size = atoi(buf);

	if (*output_array_size <= 0)
		return RETURN_OK;

	dev=(wifi_associated_dev_t *) calloc (*output_array_size, sizeof(wifi_associated_dev_t));
	*associated_dev_array = dev;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s all_sta > /tmp/connected_devices.txt" , interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf,sizeof(buf));
	f = fopen("/tmp/connected_devices.txt", "r");
	if (f==NULL)
	{
		*output_array_size=0;
		return RETURN_ERR;
	}
	while ((getline(&line, &len, f)) != -1)
	{
		param = strtok(line,"=");
		value = strtok(NULL,"=");

		if( strcmp("flags",param) == 0 )
		{
			value[strlen(value)-1]='\0';
			if(strstr (value,"AUTHORIZED") != NULL )
			{
				dev[auth_temp].cli_AuthenticationState = 1;
				dev[auth_temp].cli_Active = 1;
				auth_temp++;
				read_flag=1;
			}
		}
		if(read_flag==1)
		{
			if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
			{
				value[strlen(value)-1]='\0';
				sscanf(value, "%x:%x:%x:%x:%x:%x",
						(unsigned int *)&dev[mac_temp].cli_MACAddress[0],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[1],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[2],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[3],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[4],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[5] );
				mac_temp++;
				read_flag=0;
			}
		}
	}
	*output_array_size = auth_temp;
	auth_temp=0;
	mac_temp=0;
	free(line);
	fclose(f);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

#define MACADDRESS_SIZE 6

INT wifihal_AssociatedDevicesstats3(INT apIndex,CHAR *interface_name,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	FILE *fp = NULL;
	char str[MAX_BUF_SIZE] = {0};
	int wificlientindex = 0 ;
	int count = 0;
	int signalstrength = 0;
	int arr[MACADDRESS_SIZE] = {0};
	unsigned char mac[MACADDRESS_SIZE] = {0};
	UINT wifi_count = 0;
	char pipeCmd[MAX_CMD_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	*output_array_size = 0;
	*associated_dev_array = NULL;

	res = snprintf(pipeCmd, sizeof(pipeCmd),
		"iw dev %s station dump | grep %s | wc -l", interface_name,
		interface_name);
	if (os_snprintf_error(sizeof(pipeCmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fp = popen(pipeCmd, "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__ );
		return RETURN_ERR;
	}

	/* Read the output a line at a time - output it. */
	fgets(str, sizeof(str)-1, fp);
	wifi_count = (unsigned int) atoi ( str );
	*output_array_size = wifi_count;
	printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
	pclose(fp);

	if(wifi_count == 0)
	{
		return RETURN_OK;
	}
	else
	{
		wifi_associated_dev3_t* temp = NULL;
		if(wifi_count <= 0 || wifi_count >  MAX_ASSOCIATED_STA_NUM){
			return RETURN_ERR;
		}
		temp = (wifi_associated_dev3_t*)calloc(1, sizeof(wifi_associated_dev3_t)*wifi_count) ;
		if(temp == NULL)
		{
			printf("Error Statement. Insufficient memory \n");
			return RETURN_ERR;
		}

		res = snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
		if (os_snprintf_error(sizeof(pipeCmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			free(temp);
			return RETURN_ERR;
		}
		system(pipeCmd);
		memset(pipeCmd,0,sizeof(pipeCmd));
		if(apIndex == 0)
			res = snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_2G.txt", interface_name);
		else if(apIndex == 1)
			res = snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_5G.txt", interface_name);
		if (os_snprintf_error(sizeof(pipeCmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			free(temp);
			return RETURN_ERR;
		}
		system(pipeCmd);

		fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
		if(fp == NULL)
		{
			printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
			free(temp);
			return RETURN_ERR;
		}
		fclose(fp);

		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2");
		fp = popen(pipeCmd, "r");
		if(fp)
		{
			for(count =0 ; count < wifi_count; count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_AuthenticationState = 1; //TODO
				temp[count].cli_Active = 1; //TODO
			}
			pclose(fp);
		}

		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt");
		fp = popen(pipeCmd, "r");
		if(fp)
		{
			pclose(fp);
		}
		fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				signalstrength = atoi(str);
				temp[count].cli_SignalStrength = signalstrength;
				temp[count].cli_RSSI = signalstrength;
				temp[count].cli_SNR = signalstrength + 95;
			}
			pclose(fp);
		}


		if((apIndex == 0) || (apIndex == 4))
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				memcpy(temp[count].cli_OperatingStandard,"g", 1);
				temp[count].cli_OperatingStandard[1] = '\0';
				memcpy(temp[count].cli_OperatingChannelBandwidth, "20MHz", 5);
				temp[count].cli_OperatingChannelBandwidth[5] = '\0';
			}

			//BytesSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt");
			fp = popen(pipeCmd, "r");
			if(fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bytes_Send.txt | tr -s ' ' | cut -f 2","r");
			if(fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_BytesSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//BytesReceived
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bytes_Received.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_BytesReceived = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//PacketsSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Send.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}

			fp = popen("cat /tmp/Ass_Packets_Send.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_PacketsSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//PacketsReceived
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Received.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Packets_Received.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_PacketsReceived = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//ErrorsSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//ErrorsSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//LastDataDownlinkRate
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
					temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
				}
				pclose(fp);
			}

			//LastDataUplinkRate
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt");
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
					temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
				}
				pclose(fp);
			}

		}
		else if ((apIndex == 1) || (apIndex == 5))
		{
			for (count = 0; count < wifi_count; count++)
			{
				memcpy(temp[count].cli_OperatingStandard, "a", 1);
				temp[count].cli_OperatingStandard[1] = '\0';
				memcpy(temp[count].cli_OperatingChannelBandwidth, "20MHz", 5);
				temp[count].cli_OperatingChannelBandwidth[5] = '\0';
				temp[count].cli_BytesSent = 0;
				temp[count].cli_BytesReceived = 0;
				temp[count].cli_LastDataUplinkRate = 0;
				temp[count].cli_LastDataDownlinkRate = 0;
				temp[count].cli_PacketsSent = 0;
				temp[count].cli_PacketsReceived = 0;
				temp[count].cli_ErrorsSent = 0;
			}
		}

		for (count = 0; count < wifi_count; count++)
		{
			temp[count].cli_Retransmissions = 0;
			temp[count].cli_DataFramesSentAck = 0;
			temp[count].cli_DataFramesSentNoAck = 0;
			temp[count].cli_MinRSSI = 0;
			temp[count].cli_MaxRSSI = 0;
			strncpy(temp[count].cli_InterferenceSources, "", 64);
			memset(temp[count].cli_IPAddress, 0, 64);
			temp[count].cli_RetransCount = 0;
			temp[count].cli_FailedRetransCount = 0;
			temp[count].cli_RetryCount = 0;
			temp[count].cli_MultipleRetryCount = 0;
		}
		*associated_dev_array = temp;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

int wifihal_interfacestatus(CHAR *wifi_status, CHAR *interface_name)
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int res;
	unsigned long len;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	res = snprintf(cmd, MAX_CMD_SIZE, "ifconfig %s | grep RUNNING | tr -s ' ' | cut -d ' ' -f4 | tr -d '\\n'",
		interface_name);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, MAX_BUF_SIZE);

	len = strlen(buf);
	if (len >= sizeof(buf)) {
		wifi_debug(DEBUG_ERROR, "Unexpected buf size\n");
		return RETURN_ERR;
	}
	strncpy(wifi_status, buf, len); /* TBD: check wifi_status mem lenth and replace with strcpy later */
	wifi_status[len] = '\0';

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

static const char *get_line_from_str_buf(const char *buf, char *line)
{
	int i;
	int n = strlen(buf);

	for (i = 0; i < n; i++) {
		line[i] = buf[i];
		if (buf[i] == '\n') {
			line[i] = '\0';
			return &buf[i + 1];
		}
	}

	return NULL;
}

INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	char interface_name[16] = {0};
	FILE *f = NULL;
	int auth_temp= -1;
	char cmd[256] = {0}, buf[2048] = {0};
	char *param = NULL, *value = NULL, *line=NULL;
	size_t len = 0;
	wifi_associated_dev3_t *dev=NULL;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	*associated_dev_array = NULL;
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s all_sta | grep AUTHORIZED | wc -l", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	*output_array_size = atoi(buf);

	if (*output_array_size <= 0)
		return RETURN_OK;

	dev=(wifi_associated_dev3_t *) calloc (*output_array_size, sizeof(wifi_associated_dev3_t));
	*associated_dev_array = dev;
	res = snprintf(cmd, sizeof(cmd),
		"hostapd_cli -i%s all_sta > /tmp/diagnostic3_devices.txt" , interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd,buf,sizeof(buf));
	f = fopen("/tmp/diagnostic3_devices.txt", "r");
	if (f == NULL)
	{
		*output_array_size=0;
		return RETURN_ERR;
	}
	while ((getline(&line, &len, f)) != -1)
	{
		param = strtok(line, "=");
		value = strtok(NULL, "=");

		if( strcmp("flags",param) == 0 )
		{
			value[strlen(value)-1]='\0';
			if(strstr (value,"AUTHORIZED") != NULL )
			{
				auth_temp++;
				dev[auth_temp].cli_AuthenticationState = 1;
				dev[auth_temp].cli_Active = 1;
			}
		} else if (auth_temp < 0) {
			continue;
		} else if( strcmp("dot11RSNAStatsSTAAddress", param) == 0 )
		{
			value[strlen(value)-1]='\0';
			sscanf(value, "%x:%x:%x:%x:%x:%x",
					(unsigned int *)&dev[auth_temp].cli_MACAddress[0],
					(unsigned int *)&dev[auth_temp].cli_MACAddress[1],
					(unsigned int *)&dev[auth_temp].cli_MACAddress[2],
					(unsigned int *)&dev[auth_temp].cli_MACAddress[3],
					(unsigned int *)&dev[auth_temp].cli_MACAddress[4],
					(unsigned int *)&dev[auth_temp].cli_MACAddress[5]);
		} else if (strcmp("signal", param) == 0) {
			value[strlen(value)-1]='\0';
			sscanf(value, "%d", &dev[auth_temp].cli_RSSI);
			dev[auth_temp].cli_SNR = 95 + dev[auth_temp].cli_RSSI;
		}
	}
	if (line)
		free(line);
	fclose(f);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

/* getIPAddress function */
/**
* @description Returning IpAddress of the Matched String
*
* @param
* @str Having MacAddress
* @ipaddr Having ipaddr
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT getIPAddress(char *str,char *ipaddr)
{
	FILE *fp = NULL;
	char buf[1024] = {0},ipAddr[50] = {0},phyAddr[100] = {0},hostName[100] = {0};
	int LeaseTime = 0,ret = 0;
	unsigned long len;

	if ( (fp=fopen("/nvram/dnsmasq.leases", "r")) == NULL )
	{
		return RETURN_ERR;
	}

	while ( fgets(buf, sizeof(buf), fp)!= NULL )
	{
		/*
		Sample:sss
		1560336751 00:cd:fe:f3:25:e6 10.0.0.153 NallamousiPhone 01:00:cd:fe:f3:25:e6
		1560336751 12:34:56:78:9a:bc 10.0.0.154 NallamousiPhone 01:00:cd:fe:f3:25:e6
		*/
		ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
			&(LeaseTime),
			phyAddr,
			ipAddr,
			hostName
			);
		if(ret != 4)
			continue;
		if (strcmp(str,phyAddr) == 0) {
			len = strlen(ipAddr);
			strncpy(ipaddr, ipAddr, len);
			ipaddr[len] = '\0';
		}
	}
	fclose(fp);
	return RETURN_OK;
}

/* wifi_getApInactiveAssociatedDeviceDiagnosticResult function */
/**
* @description Returning Inactive wireless connected clients informations
*
* @param
* @filename Holding private_wifi 2g/5g content files
* @associated_dev_array  Having inactiv wireless clients informations
* @output_array_size Returning Inactive wireless counts
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT wifi_getApInactiveAssociatedDeviceDiagnosticResult(char *filename,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	int count = 0,maccount = 0,i = 0,wificlientindex = 0;
	FILE *fp = NULL;
	int res;
	int arr[MACADDRESS_SIZE] = {0};
	unsigned char mac[MACADDRESS_SIZE] = {0};
	char path[1024] = {0},str[1024] = {0},ipaddr[50] = {0},buf[512] = {0};
	sprintf(buf,"cat %s | grep Station | sort | uniq | wc -l",filename);
	fp = popen(buf,"r");
	if(fp == NULL)
		return RETURN_ERR;
	else
	{
		fgets(path,sizeof(path),fp);
		maccount = atoi(path);
	}
	pclose(fp);
	*output_array_size = maccount;
	wifi_associated_dev3_t* temp = NULL;
	if(*output_array_size > 0 && *output_array_size < MAX_ASSOCIATED_STA_NUM){
		temp = (wifi_associated_dev3_t *) calloc (*output_array_size, sizeof(wifi_associated_dev3_t));
	} else {
		return RETURN_ERR;
	}
	
	*associated_dev_array = temp;
	if(temp == NULL)
	{
		printf("Error Statement. Insufficient memory \n");
		return RETURN_ERR;
	}
	memset(buf,0,sizeof(buf));
	res = snprintf(buf, sizeof(buf),
		"cat %s | grep Station | cut -d ' ' -f2 | sort | uniq",filename);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fp = popen(buf,"r");
	if (fp == NULL) {
		fprintf(stderr, "%s: failed pipe command %s.\n", __func__, buf);
		return RETURN_ERR;
	}
	for(count = 0; count < maccount ; count++)
	{
		fgets(path,sizeof(path),fp);
		for(i = 0; path[i]!='\n';i++)
			str[i]=path[i];
		str[i]='\0';
		getIPAddress(str,ipaddr);
		memset(buf,0,sizeof(buf));
		if(strlen(ipaddr) > 0)
		{
			res = snprintf(buf, sizeof(buf), "ping -q -c 1 -W 1  \"%s\"  > /dev/null 2>&1", ipaddr);
			if (os_snprintf_error(sizeof(buf), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			if (WEXITSTATUS(system(buf)) != 0)  //InActive wireless clients info
			{
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					fprintf(stderr,"%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__,count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_AuthenticationState = 0; //TODO
				temp[count].cli_Active = 0; //TODO
				temp[count].cli_SignalStrength = 0;
			}
			else //Active wireless clients info
			{
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					fprintf(stderr,"%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__,count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_Active = 1;
			}
		}
		memset(ipaddr,0,sizeof(ipaddr));
	}
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering object
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Capability bool r/o
//To get Band Steering Capability
INT wifi_getBandSteeringCapability(BOOL *support)
{
	*support = FALSE;
	return RETURN_OK;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable bool r/w
//To get Band Steering enable status
INT wifi_getBandSteeringEnable(BOOL *enable)
{
	*enable = FALSE;
	return RETURN_OK;
}

//To turn on/off Band steering
INT wifi_setBandSteeringEnable(BOOL enable)
{
	return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.APGroup string r/w
//To get Band Steering AP group
INT wifi_getBandSteeringApGroup(char *output_ApGroup)
{
	if (NULL == output_ApGroup)
		return RETURN_ERR;

	memcpy(output_ApGroup, "1,2", 3);
	output_ApGroup[3] = '\0';
	return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.UtilizationThreshold int r/w
//to set and read the band steering BandUtilizationThreshold parameters
INT wifi_getBandSteeringBandUtilizationThreshold (INT radioIndex, INT *pBuThreshold)
{
	return RETURN_ERR;
}

INT wifi_setBandSteeringBandUtilizationThreshold (INT radioIndex, INT buThreshold)
{
	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.RSSIThreshold int r/w
//to set and read the band steering RSSIThreshold parameters
INT wifi_getBandSteeringRSSIThreshold (INT radioIndex, INT *pRssiThreshold)
{
	return RETURN_ERR;
}

INT wifi_setBandSteeringRSSIThreshold (INT radioIndex, INT rssiThreshold)
{
	return RETURN_ERR;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.PhyRateThreshold int r/w
//to set and read the band steering physical modulation rate threshold parameters
INT wifi_getBandSteeringPhyRateThreshold (INT radioIndex, INT *pPrThreshold)
{
	//If chip is not support, return -1
	return RETURN_ERR;
}

INT wifi_setBandSteeringPhyRateThreshold (INT radioIndex, INT prThreshold)
{
	//If chip is not support, return -1
	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.OverloadInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under overload condition
INT wifi_getBandSteeringOverloadInactiveTime(INT radioIndex, INT *pPrThreshold)
{
	return RETURN_ERR;
}

INT wifi_setBandSteeringOverloadInactiveTime(INT radioIndex, INT prThreshold)
{
	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.IdleInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under Idle condition
INT wifi_getBandSteeringIdleInactiveTime(INT radioIndex, INT *pPrThreshold)
{
	return RETURN_ERR;
}

INT wifi_setBandSteeringIdleInactiveTime(INT radioIndex, INT prThreshold)
{
	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.History string r/o
//pClientMAC[64]
//pSourceSSIDIndex[64]
//pDestSSIDIndex[64]
//pSteeringReason[256]
INT wifi_getBandSteeringLog(INT record_index, ULONG *pSteeringTime, CHAR *pClientMAC, INT *pSourceSSIDIndex, INT *pDestSSIDIndex, INT *pSteeringReason)
{
	//if no steering or redord_index is out of boundary, return -1. pSteeringTime returns the UTC time in seconds. pClientMAC is pre allocated as 64bytes. pSteeringReason returns the predefined steering trigger reason
	*pSteeringTime=time(NULL);
	*pSteeringReason = 0; //TODO: need to assign correct steering reason (INT numeric, i suppose)
	return RETURN_OK;
}

INT wifi_ifConfigDown(INT apIndex)
{
	INT status = RETURN_OK;
	char cmd[64];
	int res;

	res = snprintf(cmd, sizeof(cmd), "ifconfig ath%d down", apIndex);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	printf("%s: %s\n", __func__, cmd);
	system(cmd);

	return status;
}

INT wifi_ifConfigUp(INT apIndex)
{
	char interface_name[16] = {0};
	char cmd[128];
	char buf[1024];
	int res;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "ifconfig %s up 2>/dev/null", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	return 0;
}

//>> Deprecated. Replace with wifi_applyRadioSettings
INT wifi_pushBridgeInfo(INT apIndex)
{
	char ip[32] = {0};
	char subnet[32] = {0};
	char bridge[32] = {0};
	char cmd[128] = {0};
	char buf[1024] = {0};
	int res;

	wifi_getApBridgeInfo(apIndex, bridge, ip, subnet);

	res = snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %s ", bridge, ip, subnet);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	return 0;
}

INT wifi_pushChannel(INT radioIndex, UINT channel)
{
	char interface_name[16] = {0};
	char cmd[128];
	char buf[1024];
	int res;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "iwconfig %s freq %d",interface_name,channel);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd,buf, sizeof(buf));

	return 0;
}

INT wifi_pushChannelMode(INT radioIndex)
{
	//Apply Channel mode, pure mode, etc that been set by wifi_setRadioChannelMode() instantly
	return RETURN_ERR;
}

INT wifi_pushDefaultValues(INT radioIndex)
{
	//Apply Comcast specified default radio settings instantly
	//AMPDU=1
	//AMPDUFrames=32
	//AMPDULim=50000
	//txqueuelen=1000

	return RETURN_ERR;
}

INT wifi_pushTxChainMask(INT radioIndex)
{
	//Apply default TxChainMask instantly
	return RETURN_ERR;
}

INT wifi_pushRxChainMask(INT radioIndex)
{
	//Apply default RxChainMask instantly
	return RETURN_ERR;
}

INT wifi_pushSSID(INT apIndex, CHAR *ssid)
{
	INT status;

	status = wifi_setSSIDName(apIndex, ssid);
	wifi_quick_reload_ap(apIndex);

	return status;
}

INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
	int ret;
	ret = wifi_setApSsidAdvertisementEnable(apIndex, enable);

	return ret;
}

INT wifi_getRadioUpTime(INT radioIndex, ULONG *output)
{
	time_t now;

	time(&now);
	if (now > radio_up_time[radioIndex])
		*output = now - radio_up_time[radioIndex];
	else {
		*output = 0;
		return RETURN_ERR;
	}

	return RETURN_OK;
}

INT wifi_getApEnableOnLine(INT wlanIndex, BOOL *enabled)
{
	return RETURN_OK;
}

INT wifi_getApSecurityWpaRekeyInterval(INT apIndex, INT *output_int)
{
	return RETURN_OK;
}

//To-do
INT wifi_getApSecurityMFPConfig(INT apIndex, CHAR *output_string)
{
	char output[16]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	if (!output_string)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "ieee80211w", output, sizeof(output));

	if (strlen(output) == 0)
		res = snprintf(output_string, 64, "Disabled");
	else if (strncmp(output, "0", 1) == 0)
		res = snprintf(output_string, 64, "Disabled");
	else if (strncmp(output, "1", 1) == 0)
		res = snprintf(output_string, 64, "Optional");
	else if (strncmp(output, "2", 1) == 0)
		res = snprintf(output_string, 64, "Required");
	else {
		wifi_dbg_printf("\n[%s]: Unexpected ieee80211w=%s", __func__, output);
		return RETURN_ERR;
	}
	if (os_snprintf_error(64, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_dbg_printf("\n[%s]: ieee80211w is : %s", __func__, output);
	return RETURN_OK;
}
INT wifi_setApSecurityMFPConfig(INT apIndex, CHAR *MfpConfig)
{
	struct params params;
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(NULL == MfpConfig || strlen(MfpConfig) >= 32 )
		return RETURN_ERR;

	params.name = "ieee80211w";
	if (strncmp(MfpConfig, "Disabled", strlen("Disabled")) == 0)
		params.value = "0";
	else if (strncmp(MfpConfig, "Optional", strlen("Optional")) == 0)
		params.value = "1";
	else if (strncmp(MfpConfig, "Required", strlen("Required")) == 0)
		params.value = "2";
	else{
		wifi_dbg_printf("%s: invalid MfpConfig. Input has to be Disabled, Optional or Required \n", __func__);
		return RETURN_ERR;
	}

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool)
{
	char output[16]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_datfileRead(config_file, "AutoChannelSelect" , output, sizeof(output));

	if (strncmp(output, "0", 1) == 0)
		*output_bool = FALSE;
	else if (strncmp(output, "1", 1) == 0)
		*output_bool = TRUE;
	else if (strncmp(output, "2", 1) == 0)
		*output_bool = TRUE;
	else if (strncmp(output, "3", 1) == 0)
		*output_bool = TRUE;
	else
		*output_bool = FALSE;
	WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getRouterEnable(INT wlanIndex, BOOL *enabled)
{
	return RETURN_OK;
}

INT wifi_setApSecurityWpaRekeyInterval(INT apIndex, INT *rekeyInterval)
{
	return RETURN_OK;
}

INT wifi_setRouterEnable(INT wlanIndex, INT *RouterEnabled)
{
	return RETURN_OK;
}

INT wifi_getRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char config_file[MAX_BUF_SIZE] = {0};
	char tmp_output[MAX_BUF_SIZE] = {0};
	int res;

	if (NULL == output)
		return RETURN_ERR;
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,wlanIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file,"hw_mode",output,64);

	if(strcmp(output,"b")==0) {
		res = snprintf(tmp_output, sizeof(tmp_output), "%s", "1,2,5.5,11");
		if (os_snprintf_error(sizeof(tmp_output), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	} else if (strcmp(output,"a")==0) {
		res = snprintf(tmp_output, sizeof(tmp_output), "%s", "6,9,11,12,18,24,36,48,54");
		if (os_snprintf_error(sizeof(tmp_output), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}		
	} else if ((strcmp(output,"n")==0) | (strcmp(output,"g")==0)) {
		res = snprintf(tmp_output, sizeof(tmp_output), "%s", "1,2,5.5,6,9,11,12,18,24,36,48,54");
		if (os_snprintf_error(sizeof(tmp_output), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
	}
	memcpy(output, tmp_output, strlen(tmp_output));
	output[strlen(tmp_output)] = '\0';

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char *temp;
	char temp_output[128] = {0};
	char temp_TransmitRates[128] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;
	unsigned long len;

	if (NULL == output)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,wlanIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file,"supported_rates",output,64);

	if (strlen(output) == 0) {
		wifi_getRadioSupportedDataTransmitRates(wlanIndex, output);
		return RETURN_OK;
	}
	len = strlen(output);
	if (len >= sizeof(temp_TransmitRates)) {
		wifi_debug(DEBUG_ERROR, "Unexpected strlen(output)\n");
		return RETURN_ERR;
	}
	strncpy(temp_TransmitRates, output, len);
	temp = strtok(temp_TransmitRates," ");
	while(temp!=NULL)
	{
		temp[strlen(temp)-1]=0;
		if((temp[0]=='5') && (temp[1]=='\0'))
		{
			temp="5.5";
		}
		if ((sizeof(temp_output) - strlen(temp_output)) <= strlen(temp)) {
			wifi_debug(DEBUG_ERROR, "not enough room in temp_output\n");
			return RETURN_ERR;
		}
		strncat(temp_output, temp, sizeof(temp_output) - strlen(temp_output) - 1);
		temp = strtok(NULL," ");
		if(temp!=NULL)
		{
			if ((sizeof(temp_output) - strlen(temp_output)) <= 1) {
				wifi_debug(DEBUG_ERROR, "not enough room in temp_output\n");
				return RETURN_ERR;
			}
			strncat(temp_output, ",", sizeof(temp_output) - strlen(temp_output) - 1);
		}
	}
	len = strlen(temp_output);
	strncpy(output, temp_output, len);
	output[len] = '\0';
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_setRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
		return RETURN_OK;
}


INT wifi_setRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
	int i=0;
	char *temp;
	char temp1[128] = {0};
	char temp_output[128] = {0};
	char temp_TransmitRates[128] = {0};
	struct params params={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	wifi_band band = wifi_index_to_band(wlanIndex);
	unsigned long len;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(NULL == output)
		return RETURN_ERR;

	len = strlen(output);
	if (len >= sizeof(temp_TransmitRates)) {
		wifi_debug(DEBUG_ERROR, "not enough room in temp_TransmitRates\n");
		return RETURN_ERR;
	}
	strncpy(temp_TransmitRates, output, len);
	temp_TransmitRates[len] = '\0';

	for(i=0;i<strlen(temp_TransmitRates);i++)
	{
		if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) || (temp_TransmitRates[i]==' ') || (temp_TransmitRates[i]=='.') || (temp_TransmitRates[i]==','))
		{
			continue;
		}
		else
		{
			return RETURN_ERR;
		}
	}
	temp = strtok(temp_TransmitRates,",");
	while(temp!=NULL)
	{
		len = strlen(temp);
		if (len >= sizeof(temp1)) {
			wifi_debug(DEBUG_ERROR, "not enough room in temp1\n");
			return RETURN_ERR;
		}
		strncpy(temp1, temp, len);
		temp1[len] = '\0';
		if(band == band_5)
		{
			if((strcmp(temp,"1")==0) || (strcmp(temp,"2")==0) || (strcmp(temp,"5.5")==0))
			{
				return RETURN_ERR;
			}
		}

		if(strcmp(temp,"5.5")==0) {
			strncpy(temp1, "55", 2);
			temp1[2] = '\0';
		} else {
			if ((sizeof(temp1) - strlen(temp1)) <= 1) {
				wifi_debug(DEBUG_ERROR, "not enough room in temp1\n");
				return RETURN_ERR;
			}
			strncat(temp1, "0", sizeof(temp1) - strlen(temp1) - 1);
		}
		
		if ((sizeof(temp_output) - strlen(temp_output)) <= strlen(temp1)) {
			wifi_debug(DEBUG_ERROR, "not enough room in temp_output\n");
			return RETURN_ERR;
		}
		strncat(temp_output, temp1, sizeof(temp_output) - strlen(temp_output) - 1);
		temp = strtok(NULL,",");
		if(temp!=NULL)
		{
			if ((sizeof(temp_output) - strlen(temp_output)) <= 1) {
				wifi_debug(DEBUG_ERROR, "not enough room in temp1\n");
				return RETURN_ERR;
			}
			strncat(temp_output, " ", sizeof(temp_output) - strlen(temp_output) - 1);
		}
	}
	len = strlen(temp_output);
	strncpy(output, temp_output, len);
	output[len] = '\0';

	params.name = "supported_rates";
	params.value = output;

	wifi_dbg_printf("\n%s:",__func__);
	wifi_dbg_printf("params.value=%s\n",params.value);
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,wlanIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}		
	wifi_hostapdWrite(config_file,&params,1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}


static char *sncopy(char *dst, int dst_sz, const char *src)
{
	if (src && dst && dst_sz > 0) {
		strncpy(dst, src, dst_sz);
		dst[dst_sz - 1] = '\0';
	}
	return dst;
}

static int util_get_sec_chan_offset(int channel, const char* ht_mode)
{
	if (0 == strcmp(ht_mode, "HT40") ||
		0 == strcmp(ht_mode, "HT80") ||
		0 == strcmp(ht_mode, "HT160")) {
		switch (channel) {
			case 1 ... 7:
			case 36:
			case 44:
			case 52:
			case 60:
			case 100:
			case 108:
			case 116:
			case 124:
			case 132:
			case 140:
			case 149:
			case 157:
				return 1;
			case 8 ... 13:
			case 40:
			case 48:
			case 56:
			case 64:
			case 104:
			case 112:
			case 120:
			case 128:
			case 136:
			case 144:
			case 153:
			case 161:
				return -1;
			default:
				return -EINVAL;
		}
	}

	return -EINVAL;
}

static int util_get_6g_sec_chan_offset(int channel, const char* ht_mode)
{
	int idx = channel%8;
	if (0 == strcmp(ht_mode, "HT40") ||
		0 == strcmp(ht_mode, "HT80") ||
		0 == strcmp(ht_mode, "HT160")) {
		switch (idx) {
			case 1:
				return 1;
			case 5:
				return -1;
			default:
				return -EINVAL;
		}
	}

	return -EINVAL;
}
static void util_hw_mode_to_bw_mode(const char* hw_mode, char *bw_mode, int bw_mode_len)
{
	if (NULL == hw_mode) return;

	if (0 == strcmp(hw_mode, "ac"))
		sncopy(bw_mode, bw_mode_len, "ht vht");

	if (0 == strcmp(hw_mode, "n"))
		sncopy(bw_mode, bw_mode_len, "ht");

	return;
}

static int util_chan_to_freq(int chan)
{
	if (chan == 14)
		return 2484;
	else if (chan < 14)
		return 2407 + chan * 5;
	else if (chan >= 182 && chan <= 196)
		return 4000 + chan * 5;
	else
		return 5000 + chan * 5;
	return 0;
}

static int util_6G_chan_to_freq(int chan)
{
	if (chan)
		return 5950 + chan * 5;
	else
		return 0;

}
const int *util_unii_5g_chan2list(int chan, int width)
{
	static const int lists[] = {
		// <width>, <chan1>, <chan2>..., 0,
		20, 36, 0,
		20, 40, 0,
		20, 44, 0,
		20, 48, 0,
		20, 52, 0,
		20, 56, 0,
		20, 60, 0,
		20, 64, 0,
		20, 100, 0,
		20, 104, 0,
		20, 108, 0,
		20, 112, 0,
		20, 116, 0,
		20, 120, 0,
		20, 124, 0,
		20, 128, 0,
		20, 132, 0,
		20, 136, 0,
		20, 140, 0,
		20, 144, 0,
		20, 149, 0,
		20, 153, 0,
		20, 157, 0,
		20, 161, 0,
		20, 165, 0,
		40, 36, 40, 0,
		40, 44, 48, 0,
		40, 52, 56, 0,
		40, 60, 64, 0,
		40, 100, 104, 0,
		40, 108, 112, 0,
		40, 116, 120, 0,
		40, 124, 128, 0,
		40, 132, 136, 0,
		40, 140, 144, 0,
		40, 149, 153, 0,
		40, 157, 161, 0,
		80, 36, 40, 44, 48, 0,
		80, 52, 56, 60, 64, 0,
		80, 100, 104, 108, 112, 0,
		80, 116, 120, 124, 128, 0,
		80, 132, 136, 140, 144, 0,
		80, 149, 153, 157, 161, 0,
		160, 36, 40, 44, 48, 52, 56, 60, 64, 0,
		160, 100, 104, 108, 112, 116, 120, 124, 128, 0,
		-1 // final delimiter
	};
	const int *start;
	const int *p;

	for (p = lists; *p != -1; p++) {
		if (*p == width) {
			for (start = ++p; *p != 0; p++) {
				if (*p == chan)
					return start;
			}
		}
		// move to the end of channel list of given width
		while (*p != 0) {
			p++;
		}
	}

	return NULL;
}

static int util_unii_5g_centerfreq(const char *ht_mode, int channel)
{
	if (NULL == ht_mode)
		return 0;

	const int width = atoi(strlen(ht_mode) > 2 ? ht_mode + 2 : "20");
	const int *chans = util_unii_5g_chan2list(channel, width);
	int sum = 0;
	int cnt = 0;

	if (NULL == chans)
		return 0;

	while (*chans) {
		sum += *chans;
		cnt++;
		chans++;
	}
	if (cnt == 0)
		return 0;
	return sum / cnt;
}

static int util_unii_6g_centerfreq(const char *ht_mode, int channel)
{
	if (NULL == ht_mode)
		return 0;

	int width = strtol((ht_mode + 2), NULL, 10);

	int idx = 0 ;
	int centerchan = 0;
	int chan_ofs = 1;

	if (width == 40){
		idx = ((channel/4) + chan_ofs)%2;
		switch (idx) {
			case 0:
				centerchan = (channel - 2);
				break;
			case 1:
				centerchan = (channel + 2);
				break;
			default:
				return -EINVAL;
		}
	}else if (width == 80){
		idx = ((channel/4) + chan_ofs)%4;
		switch (idx) {
			case 0:
				centerchan = (channel - 6);
				break;
			case 1:
				centerchan = (channel + 6);
				break;
			case 2:
				centerchan = (channel + 2);
				break;
			case 3:
				centerchan = (channel - 2);
				break;
			default:
				return -EINVAL;
		}
	}else if (width == 160){
		switch (channel) {
			case 1 ... 29:
				centerchan = 15;
				break;
			case 33 ... 61:
				centerchan = 47;
				break;
			case 65 ... 93:
				centerchan = 79;
				break;
			case 97 ... 125:
				centerchan = 111;
				break;
			case 129 ... 157:
				centerchan = 143;
				break;
			case 161 ... 189:
				centerchan = 175;
				break;
			case 193 ... 221:
				centerchan = 207;
				break;
			default:
				return -EINVAL;
		}
	}
	return centerchan;
}
static int util_radio_get_hw_mode(int radioIndex, char *hw_mode, int hw_mode_size)
{
	BOOL onlyG, onlyN, onlyA;
	CHAR tmp[64];
	int ret = wifi_getRadioStandard(radioIndex, tmp, &onlyG, &onlyN, &onlyA);
	if (ret == RETURN_OK) {
		sncopy(hw_mode, hw_mode_size, tmp);
	}
	return ret;
}

INT wifi_pushRadioChannel2(INT radioIndex, UINT channel, UINT channel_width_MHz, UINT csa_beacon_count)
{
	// Sample commands:
	//   hostapd_cli -i wifi1 chan_switch 30 5200 sec_channel_offset=-1 center_freq1=5190 bandwidth=40 ht vht
	//   hostapd_cli -i wifi0 chan_switch 30 2437
	int ret = 0;
	char center_freq1_str[32] = ""; // center_freq1=%d
	char opt_chan_info_str[32] = ""; // bandwidth=%d ht vht
	char sec_chan_offset_str[32] = ""; // sec_channel_offset=%d
	char hw_mode[16] = ""; // n|ac
	char bw_mode[16] = ""; // ht|ht vht
	char ht_mode[16] = ""; // HT20|HT40|HT80|HT160
	char interface_name[16] = {0};
	int sec_chan_offset;
	int width;
	char config_file[64] = {0};
	char *ext_str = "None";
	wifi_band band = band_invalid;
	int center_chan = 0;
	int center_freq1 = 0;
	int res;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	band = wifi_index_to_band(radioIndex);

	width = channel_width_MHz > 20 ? channel_width_MHz : 20;

	// Get radio mode HT20|HT40|HT80 etc.
	if (channel){
		res = snprintf(ht_mode, sizeof(ht_mode), "HT%d", width);
		if (os_snprintf_error(sizeof(ht_mode), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		// Provide bandwith if specified
		if (channel_width_MHz > 20) {
			// Select bandwidth mode from hardware n --> ht | ac --> ht vht
			util_radio_get_hw_mode(radioIndex, hw_mode, sizeof(hw_mode));
			util_hw_mode_to_bw_mode(hw_mode, bw_mode, sizeof(bw_mode));

			res = snprintf(opt_chan_info_str, sizeof(opt_chan_info_str), "bandwidth=%d %s", width, bw_mode);
		}else if (channel_width_MHz == 20){
			res = snprintf(opt_chan_info_str, sizeof(opt_chan_info_str), "bandwidth=%d ht", width);
		}

		if (os_snprintf_error(sizeof(opt_chan_info_str), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		if (channel_width_MHz > 20) {
			if (band == band_6){
				center_chan = util_unii_6g_centerfreq(ht_mode, channel);
				if(center_chan){
					center_freq1 = util_6G_chan_to_freq(center_chan);
				}
			}else{
				center_chan = util_unii_5g_centerfreq(ht_mode, channel);
				if(center_chan){
					center_freq1 = util_chan_to_freq(center_chan);
				}
			}

			if (center_freq1)
				res = snprintf(center_freq1_str, sizeof(center_freq1_str), "center_freq1=%d", center_freq1);

		}
		if (os_snprintf_error(sizeof(center_freq1_str), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		// Find channel offset +1/-1 for wide modes (HT40|HT80|HT160)
		if (band == band_6){
			sec_chan_offset = util_get_6g_sec_chan_offset(channel, ht_mode);
		}else{
			sec_chan_offset = util_get_sec_chan_offset(channel, ht_mode);
		}
		if (sec_chan_offset != -EINVAL) {
			res = snprintf(sec_chan_offset_str, sizeof(sec_chan_offset_str), "sec_channel_offset=%d", sec_chan_offset);
			if (os_snprintf_error(sizeof(sec_chan_offset_str), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
		}
		// Only the first AP, other are hanging on the same radio
		ret = wifi_setChannel_netlink(radioIndex, &channel, NULL);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setChannel return error.\n", __func__);
			return RETURN_ERR;
		}
		/* wifi_dbg_printf("execute: '%s'\n", cmd);
		ret = _syscmd(cmd, buf, sizeof(buf));
		wifi_reloadAp(radioIndex); */

		ret = wifi_setRadioChannel(radioIndex, channel);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setRadioChannel return error.\n", __func__);
			return RETURN_ERR;
		}

		if (sec_chan_offset == 1)
			ext_str = "Above";
		else if (sec_chan_offset == -1)
			ext_str = "Below";

		/*wifi_setRadioCenterChannel(radioIndex, center_chan); */

	} else {
		if (channel_width_MHz > 20)
			ext_str = "Above";
	}

	wifi_setRadioExtChannel(radioIndex, ext_str);

	char mhz_str[16];
	res = snprintf(mhz_str, sizeof(mhz_str), "%dMHz", width);
	if (os_snprintf_error(sizeof(mhz_str), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_setRadioOperatingChannelBandwidth(radioIndex, mhz_str);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
	int index = -1;
	wifi_neighbor_ap2_t *scan_array = NULL;
	char cmd[256]={0};
	char buf[128]={0};
	char file_name[32] = {0};
	char filter_SSID[32] = {0};
	char line[256] = {0};
	char interface_name[16] = {0};
	char *ret = NULL;
	int freq=0;
	FILE *f = NULL;
	int channels_num = 0;
	int vht_channel_width = 0;
	int get_noise_ret = RETURN_ERR;
	bool filter_enable = false;
	bool filter_BSS = false;	 // The flag determine whether the BSS information need to be filterd.
	int phyId = 0;
	int res;
	unsigned long len;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s: %d\n", __func__, __LINE__);

	res = snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, radio_index);
	if (os_snprintf_error(sizeof(file_name), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}	
	f = fopen(file_name, "r");
	if (f != NULL) {
		fgets(filter_SSID, sizeof(file_name), f);
		if (strlen(filter_SSID) != 0)
			filter_enable = true;
		fclose(f);
	}

	if (wifi_GetInterfaceName(radio_index, interface_name) != RETURN_OK)
		return RETURN_ERR;

	phyId = radio_index_to_phy(radio_index);

	res = snprintf(cmd, sizeof(cmd), "iw phy phy%d channels | grep * | grep -v disable | wc -l", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	channels_num = strtol(buf, NULL, 10);

	res = snprintf(cmd, sizeof(cmd), "iw dev %s scan dump | grep '%s\\|SSID\\|freq\\|beacon interval\\|capabilities\\|signal\\|Supported rates\\|DTIM\\| \
	// WPA\\|RSN\\|Group cipher\\|HT operation\\|secondary channel offset\\|channel width\\|HE.*GHz' | grep -v -e '*.*BSS'", interface_name, interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}	

	fprintf(stderr, "cmd: %s\n", cmd);
	if ((f = popen(cmd, "r")) == NULL) {
		wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
		return RETURN_ERR;
	}

	struct channels_noise *channels_noise_arr = calloc(channels_num, sizeof(struct channels_noise));
	if(channels_noise_arr != NULL){
		get_noise_ret = get_noise(radio_index, channels_noise_arr, channels_num);
	} else{
		fclose(f);
		return RETURN_ERR;
	}
	ret = fgets(line, sizeof(line), f);
	while (ret != NULL) {
		if(strstr(line, "BSS") != NULL) {	// new neighbor info
			// The SSID field is not in the first field. So, we should store whole BSS informations and the filter flag.
			// And we will determine whether we need the previous BSS infomation when parsing the next BSS field or end of while loop.
			// If we don't want the BSS info, we don't realloc more space, and just clean the previous BSS.

			if (!filter_BSS) {
				index++;
				wifi_neighbor_ap2_t *tmp;
				tmp = realloc(scan_array, sizeof(wifi_neighbor_ap2_t)*(index+1));
				if (tmp == NULL) {			  // no more memory to use
					index--;
					wifi_dbg_printf("%s: realloc failed\n", __func__);
					break;
				}
				scan_array = tmp;
			}
			memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));

			filter_BSS = false;
			sscanf(line, "BSS %17s", scan_array[index].ap_BSSID);
			memset(scan_array[index].ap_Mode, 0, sizeof(scan_array[index].ap_Mode));
			memcpy(scan_array[index].ap_Mode, "Infrastructure", strlen("Infrastructure"));
			memset(scan_array[index].ap_SecurityModeEnabled, 0, sizeof(scan_array[index].ap_SecurityModeEnabled));
			memcpy(scan_array[index].ap_SecurityModeEnabled, "None", strlen("None"));
			memset(scan_array[index].ap_EncryptionMode, 0, sizeof(scan_array[index].ap_EncryptionMode));
			memcpy(scan_array[index].ap_EncryptionMode, "None", strlen("None"));
		} else if (strstr(line, "freq") != NULL) {
			sscanf(line,"	freq: %d", &freq);
			scan_array[index].ap_Channel = ieee80211_frequency_to_channel(freq);

			if (freq >= 2412 && freq <= 2484) {
				memset(scan_array[index].ap_OperatingFrequencyBand, 0, sizeof(scan_array[index].ap_OperatingFrequencyBand));
				memcpy(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz"));
				memset(scan_array[index].ap_SupportedStandards, 0, sizeof(scan_array[index].ap_SupportedStandards));
				memcpy(scan_array[index].ap_SupportedStandards, "b,g", strlen("b,g"));
				memset(scan_array[index].ap_OperatingStandards, 0, sizeof(scan_array[index].ap_OperatingStandards));
				memcpy(scan_array[index].ap_OperatingStandards, "g", strlen("g"));
			}
			else if (freq >= 5160 && freq <= 5805) {
				memset(scan_array[index].ap_OperatingFrequencyBand, 0, sizeof(scan_array[index].ap_OperatingFrequencyBand));
				memcpy(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz"));
				memset(scan_array[index].ap_SupportedStandards, 0, sizeof(scan_array[index].ap_SupportedStandards));
				memcpy(scan_array[index].ap_SupportedStandards, "a", strlen("a"));
				memset(scan_array[index].ap_OperatingStandards, 0, sizeof(scan_array[index].ap_OperatingStandards));
				memcpy(scan_array[index].ap_OperatingStandards, "a", strlen("a"));
			}

			scan_array[index].ap_Noise = 0;
			if (get_noise_ret == RETURN_OK) {
				for (int i = 0; i < channels_num; i++) {
					if (scan_array[index].ap_Channel == channels_noise_arr[i].channel) {
						scan_array[index].ap_Noise = channels_noise_arr[i].noise;
						break;
					}
				}
			}
		} else if (strstr(line, "beacon interval") != NULL) {
			sscanf(line,"	beacon interval: %d TUs", &(scan_array[index].ap_BeaconPeriod));
		} else if (strstr(line, "signal") != NULL) {
			sscanf(line,"	signal: %d", &(scan_array[index].ap_SignalStrength));
		} else if (strstr(line,"SSID") != NULL) {
			sscanf(line,"	SSID: %63s", scan_array[index].ap_SSID);
			if (filter_enable && strcmp(scan_array[index].ap_SSID, filter_SSID) != 0) {
				filter_BSS = true;
			}
		} else if (strstr(line, "Supported rates") != NULL) {
			char SRate[80] = {0}, *tmp = NULL;
			memset(buf, 0, sizeof(buf));
			len = strlen(line);
			if (len >= sizeof(SRate)) {
				wifi_debug(DEBUG_ERROR, "not enough room in SRate\n");
				return RETURN_ERR;				
			}
			strncpy(SRate, line, len);
			tmp = strtok(SRate, ":");
			tmp = strtok(NULL, ":");
			len = strlen(tmp);
			if (len >= sizeof(buf)) {
				wifi_debug(DEBUG_ERROR, "not enough room in buf\n");
				return RETURN_ERR;				
			}
			strncpy(buf, tmp, len);
			memset(SRate, 0, sizeof(SRate));

			tmp = strtok(buf, " \n");
			while (tmp != NULL) {
				if ((sizeof(SRate) - strlen(SRate)) <= strlen(tmp)) {
					wifi_debug(DEBUG_ERROR, "not enough room in SRate\n");
					return RETURN_ERR;				
				}
				strncat(SRate, tmp, sizeof(SRate) - strlen(SRate) - 1);
				if (SRate[strlen(SRate) - 1] == '*') {
					SRate[strlen(SRate) - 1] = '\0';
				}
				if ((sizeof(SRate) - strlen(SRate)) <= 1) {
					wifi_debug(DEBUG_ERROR, "not enough room in SRate\n");
					return RETURN_ERR;				
				}
				strncat(SRate, ",", sizeof(SRate) - strlen(SRate) - 1);

				tmp = strtok(NULL, " \n");
			}
			SRate[strlen(SRate) - 1] = '\0';
			len = strlen(SRate);
			if (len >= sizeof(scan_array[index].ap_SupportedDataTransferRates)) {
				wifi_debug(DEBUG_ERROR, "not enough room in scan_array[index].ap_SupportedDataTransferRates\n");
				return RETURN_ERR;				
			}
			strncpy(scan_array[index].ap_SupportedDataTransferRates, SRate, len);
			scan_array[index].ap_SupportedDataTransferRates[len] = '\0';
		} else if (strstr(line, "DTIM") != NULL) {
			sscanf(line,"DTIM Period %u", &(scan_array[index].ap_DTIMPeriod));
		} else if (strstr(line, "VHT capabilities") != NULL) {
			if ((sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards)) <= 3) {
				wifi_debug(DEBUG_ERROR, "not enough room in scan_array[index].ap_SupportedStandards\n");
				return RETURN_ERR;				
			}
			strncat(scan_array[index].ap_SupportedStandards, ",ac",
				sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) - 1);
			memcpy(scan_array[index].ap_OperatingStandards, "ac", 2);
			scan_array[index].ap_OperatingStandards[2] = '\0';
		} else if (strstr(line, "HT capabilities") != NULL) {
			if ((sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards)) <= 2) {
				wifi_debug(DEBUG_ERROR, "not enough room in scan_array[index].ap_SupportedStandards\n");
				return RETURN_ERR;				
			}
			strncat(scan_array[index].ap_SupportedStandards, ",n",
				sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) - 1);
			memcpy(scan_array[index].ap_OperatingStandards, "n", 1);
			scan_array[index].ap_OperatingStandards[1] = '\0';
		} else if (strstr(line, "VHT operation") != NULL) {
			ret = fgets(line, sizeof(line), f);
			sscanf(line,"		 * channel width: %d", &vht_channel_width);
			if(vht_channel_width == 1) {
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT80");
			} else {
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT40");
			}
			if (os_snprintf_error(sizeof(scan_array[index].ap_OperatingChannelBandwidth), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				free(channels_noise_arr);
				fclose(f);
				free(scan_array);
				return RETURN_ERR;
			}	

			if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
				continue;
		} else if (strstr(line, "HT operation") != NULL) {
			ret = fgets(line, sizeof(line), f);
			sscanf(line,"		 * secondary channel offset: %127s", buf);
			if (!strcmp(buf, "above")) {
				//40Mhz +
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40PLUS", radio_index%1 ? "A": "G");
			}
			else if (!strcmp(buf, "below")) {
				//40Mhz -
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40MINUS", radio_index%1 ? "A": "G");
			} else {
				//20Mhz
				res = snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT20", radio_index%1 ? "A": "G");
			}
			if (os_snprintf_error(sizeof(scan_array[index].ap_OperatingChannelBandwidth), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}	

			if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
				continue;
		} else if (strstr(line, "HE capabilities") != NULL) {
			if ((sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards)) <= 3) {
				wifi_debug(DEBUG_ERROR, "not enough room in scan_array[index].ap_SupportedStandards\n");
				return RETURN_ERR;				
			}
			strncat(scan_array[index].ap_SupportedStandards, ",ax",
				sizeof(scan_array[index].ap_SupportedStandards) - strlen(scan_array[index].ap_SupportedStandards) - 1);
			memcpy(scan_array[index].ap_OperatingStandards, "ax", 2);
			scan_array[index].ap_OperatingStandards[2] = '\0';
			ret = fgets(line, sizeof(line), f);
			if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz")) == 0) {
				if (strstr(line, "HE40/2.4GHz") != NULL) {
					len = strlen("11AXHE40PLUS");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE40PLUS", len);
				} else {
					len = strlen("11AXHE20");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE20", len);
				}
				scan_array[index].ap_OperatingChannelBandwidth[len] = '\0';
			} else if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz")) == 0) {
				if (strstr(line, "HE80/5GHz") != NULL) {
					len = strlen("11AXHE80");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE80", len);
					scan_array[index].ap_OperatingChannelBandwidth[len] = '\0';
					ret = fgets(line, sizeof(line), f);
				} else
					continue;
				if (strstr(line, "HE160/5GHz") != NULL) {
					len = strlen("11AXHE160");
					memcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE160", len);
					scan_array[index].ap_OperatingChannelBandwidth[len] = '\0';
				}
			}
			continue;
		} else if (strstr(line, "WPA") != NULL) {
			memcpy(scan_array[index].ap_SecurityModeEnabled, "WPA", 3);
			scan_array[index].ap_SecurityModeEnabled[3] = '\0';
		} else if (strstr(line, "RSN") != NULL) {
			memcpy(scan_array[index].ap_SecurityModeEnabled, "RSN", 3);
			scan_array[index].ap_SecurityModeEnabled[3] = '\0';
		} else if (strstr(line, "Group cipher") != NULL) {
			sscanf(line, "		 * Group cipher: %63s", scan_array[index].ap_EncryptionMode);
			if (strncmp(scan_array[index].ap_EncryptionMode, "CCMP", strlen("CCMP")) == 0) {
				memcpy(scan_array[index].ap_EncryptionMode, "AES", 3);
				scan_array[index].ap_EncryptionMode[3] = '\0';
			}
		}
		ret = fgets(line, sizeof(line), f);
	}

	if (!filter_BSS) {
		*output_array_size = index + 1;
	} else {
		memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));
		*output_array_size = index;
	}
	*neighbor_ap_array = scan_array;
	pclose(f);
	free(channels_noise_arr);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getApAssociatedDeviceStats(
		INT apIndex,
		mac_address_t *clientMacAddress,
		wifi_associated_dev_stats_t *associated_dev_stats,
		u64 *handle)
{
	wifi_associated_dev_stats_t *dev_stats = associated_dev_stats;
	char interface_name[50] = {0};
	char cmd[1024] =  {0};
	char mac_str[18] = {0};
	char *key = NULL;
	char *val = NULL;
	FILE *f = NULL;
	char *line = NULL;
	size_t len = 0;
	int res;

	if(wifi_getApName(apIndex, interface_name) != RETURN_OK) {
		wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
		return RETURN_ERR;
	}

	res = snprintf(mac_str, sizeof(mac_str), "%x:%x:%x:%x:%x:%x",
		(*clientMacAddress)[0], (*clientMacAddress)[1], (*clientMacAddress)[2],
		(*clientMacAddress)[3], (*clientMacAddress)[4], (*clientMacAddress)[5]);
	if (os_snprintf_error(sizeof(mac_str), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "iw dev %s station get %s | grep 'rx\\|tx' | tr -d '\t'", interface_name, mac_str);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if((f = popen(cmd, "r")) == NULL) {
		wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
		return RETURN_ERR;
	}

	while ((getline(&line, &len, f)) != -1) {
		key = strtok(line,":");
		val = strtok(NULL,":");

	if(!strncmp(key,"rx bytes",8))
		sscanf(val, "%llu", &dev_stats->cli_rx_bytes);
	if(!strncmp(key,"tx bytes",8))
			sscanf(val, "%llu", &dev_stats->cli_tx_bytes);
	if(!strncmp(key,"rx packets",10))
			sscanf(val, "%llu", &dev_stats->cli_tx_frames);
	if(!strncmp(key,"tx packets",10))
			sscanf(val, "%llu", &dev_stats->cli_tx_frames);
		if(!strncmp(key,"tx retries",10))
			sscanf(val, "%llu", &dev_stats->cli_tx_retries);
		if(!strncmp(key,"tx failed",9))
			sscanf(val, "%llu", &dev_stats->cli_tx_errors);
		if(!strncmp(key,"rx drop misc",13))
			sscanf(val, "%llu", &dev_stats->cli_rx_errors);
		if(!strncmp(key,"rx bitrate",10)) {
			val = strtok(val, " ");
			sscanf(val, "%lf", &dev_stats->cli_rx_rate);
		}
		if(!strncmp(key,"tx bitrate",10)) {
			val = strtok(val, " ");
			sscanf(val, "%lf", &dev_stats->cli_tx_rate);
		}
	}
	free(line);
	pclose(f);
	return RETURN_OK;
}

INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output_string)
{
	char interface_name[IF_NAME_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0}, buf[32] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	if (NULL == output_string)
		return RETURN_ERR;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli  -i %s get_config | grep ^ssid | cut -d '=' -f2 | tr -d '\\n'", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	//size of SSID name restricted to value less than 32 bytes
	res = snprintf(output_string, 32, "%s", buf);
	if (os_snprintf_error(32, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getApMacAddressControlMode(INT apIndex, INT *output_filterMode)
{
	char *mac_arry_buf = NULL;
	INT policy = -1;
	INT buf_size = 1024;

	mac_arry_buf =	malloc(buf_size);
	if (!mac_arry_buf) {
		wifi_debug(DEBUG_ERROR,"malloc mac_arry_buf fails\n");
		return RETURN_ERR;
	}
	memset(mac_arry_buf, 0, buf_size);
	if (mtk_wifi_getApAclDevices(apIndex, mac_arry_buf, buf_size) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR,"mtk_wifi_getApAclDevices get fails\n");
		goto err;
	}
	/*
	mtk format to get policy:
	"policy=1
	 00:11:22:33:44:55
	 00:11:22:33:44:66
	"
	*/
	if (strlen(mac_arry_buf) < strlen("policy=1") || sscanf(mac_arry_buf, "policy=%01d", &policy) != 1) {
		wifi_debug(DEBUG_ERROR,"mac_arry_buf(%s) invalid\n", mac_arry_buf);
		goto err;
	}
	if (!(policy >=0 && policy <= 2)){
		wifi_debug(DEBUG_ERROR,"policy(%d) is invalid\n", policy);
		goto err;
	}
	*output_filterMode = policy;
	wifi_debug(DEBUG_NOTICE, "output_filterMode(%d), success\n", *output_filterMode);
	free(mac_arry_buf);
	mac_arry_buf = NULL;
	return RETURN_OK;
err:
	free(mac_arry_buf);
	mac_arry_buf = NULL;
	wifi_debug(DEBUG_NOTICE, "output_filterMode(%d), fails\n", *output_filterMode);
	return RETURN_ERR;
}


INT wifi_getApAssociatedDeviceDiagnosticResult2(INT apIndex,wifi_associated_dev2_t **associated_dev_array,UINT *output_array_size)
{
	FILE *fp = NULL;
	char str[MAX_BUF_SIZE] = {0};
	int wificlientindex = 0 ;
	int count = 0;
	int signalstrength = 0;
	int arr[MACADDRESS_SIZE] = {0};
	unsigned char mac[MACADDRESS_SIZE] = {0};
	UINT wifi_count = 0;
	char pipeCmd[MAX_CMD_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	*output_array_size = 0;
	*associated_dev_array = NULL;
	char interface_name[50] = {0};

	if(wifi_getApName(apIndex, interface_name) != RETURN_OK) {
		wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
		return RETURN_ERR;
	}

	res = snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
	if (os_snprintf_error(sizeof(pipeCmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fp = popen(pipeCmd, "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__ );
		return RETURN_ERR;
	}

	/* Read the output a line at a time - output it. */
	fgets(str, sizeof(str)-1, fp);
	wifi_count = (unsigned int) atoi ( str );
	*output_array_size = wifi_count;
	wifi_dbg_printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
	pclose(fp);

	if(wifi_count == 0)
	{
		return RETURN_OK;
	}
	else
	{
		wifi_associated_dev2_t* temp = NULL;
		temp = (wifi_associated_dev2_t*)calloc(wifi_count, sizeof(wifi_associated_dev2_t));
		*associated_dev_array = temp;
		if(temp == NULL)
		{
			printf("Error Statement. Insufficient memory \n");
			return RETURN_ERR;
		}

		res = snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
		if (os_snprintf_error(sizeof(pipeCmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		system(pipeCmd);

		fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
		if(fp == NULL)
		{
			printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
			return RETURN_ERR;
		}
		fclose(fp);

		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2");
		fp = popen(pipeCmd, "r");
		if(fp)
		{
			for(count =0 ; count < wifi_count; count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					wifi_dbg_printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_AuthenticationState = 1; //TODO
				temp[count].cli_Active = 1; //TODO
			}
			pclose(fp);
		}

		//Updating  RSSI per client
		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt");
		fp = popen(pipeCmd, "r");
		if(fp)
		{
			pclose(fp);
		}
		fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				signalstrength = atoi(str);
				temp[count].cli_RSSI = signalstrength;
			}
			pclose(fp);
		}


		//LastDataDownlinkRate
		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt");
		fp = popen(pipeCmd, "r");
		if (fp)
		{
			pclose(fp);
		}
		fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
		if (fp)
		{
			for (count = 0; count < wifi_count; count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
				temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
			}
			pclose(fp);
		}

		//LastDataUplinkRate
		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt");
		fp = popen(pipeCmd, "r");
		if (fp)
		{
			pclose(fp);
		}
		fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
		if (fp)
		{
			for (count = 0; count < wifi_count; count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
				temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
			}
			pclose(fp);
		}
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;

}

INT wifi_getSSIDTrafficStats2(INT ssidIndex,wifi_ssidTrafficStats2_t *output_struct)
{
	FILE *fp = NULL;
	char interface_name[50] = {0};
	char pipeCmd[128] = {0};
	char str[256] = {0};
	wifi_ssidTrafficStats2_t *out = output_struct;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	if (!output_struct)
		return RETURN_ERR;

	memset(out, 0, sizeof(wifi_ssidTrafficStats2_t));
	if (wifi_GetInterfaceName(ssidIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(pipeCmd, sizeof(pipeCmd), "cat /proc/net/dev | grep %s", interface_name);
	if (os_snprintf_error(sizeof(pipeCmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	fp = popen(pipeCmd, "r");
	if (fp == NULL) {
		fprintf(stderr, "%s: popen failed\n", __func__);
		return RETURN_ERR;
	}
	fgets(str, sizeof(str), fp);
	pclose(fp);

	if (strlen(str) == 0)   // interface not exist
		return RETURN_OK;

	sscanf(str, "%*[^:]: %lu %lu %lu %lu %*d %*d %*d %*d %lu %lu %lu %lu", &out->ssid_BytesReceived, &out->ssid_PacketsReceived, &out->ssid_ErrorsReceived, \
	&out->ssid_DiscardedPacketsReceived, &out->ssid_BytesSent, &out->ssid_PacketsSent, &out->ssid_ErrorsSent, &out->ssid_DiscardedPacketsSent);

	memset(str, 0, sizeof(str));

	res = snprintf(pipeCmd, sizeof(pipeCmd), "tail -n1 /proc/net/netstat");
	if (os_snprintf_error(sizeof(pipeCmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fp = popen(pipeCmd, "r");
	if (fp == NULL) {
		wifi_debug(DEBUG_ERROR, "popen failed\n");
		return RETURN_ERR;
	}
	fgets(str, sizeof(str), fp);

	sscanf(str, "%*[^:]: %*d %*d %lu %lu %lu %lu", &out->ssid_MulticastPacketsReceived, &out->ssid_MulticastPacketsSent, &out->ssid_BroadcastPacketsRecevied, \
	&out->ssid_BroadcastPacketsSent);
	pclose(fp);

	out->ssid_UnicastPacketsSent = out->ssid_PacketsSent - out->ssid_MulticastPacketsSent - out->ssid_BroadcastPacketsSent - out->ssid_DiscardedPacketsSent;
	out->ssid_UnicastPacketsReceived = out->ssid_PacketsReceived - out->ssid_MulticastPacketsReceived - out->ssid_BroadcastPacketsRecevied - out->ssid_DiscardedPacketsReceived;

	// Not supported
	output_struct->ssid_RetransCount = 0;
	output_struct->ssid_FailedRetransCount = 0;
	output_struct->ssid_RetryCount = 0;
	output_struct->ssid_MultipleRetryCount = 0;
	output_struct->ssid_ACKFailureCount = 0;
	output_struct->ssid_AggregatedPacketCount = 0;

	return RETURN_OK;
}

//Enables or disables device isolation. A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output)
{
	char output_val[16]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (!output)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "ap_isolate", output_val, sizeof(output_val));

	if( strcmp(output_val,"1") == 0 )
		*output = TRUE;
	else
		*output = FALSE;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char string[MAX_BUF_SIZE]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	struct params params;
	int res;

	string[0] = enable == TRUE ? '1' : '0';

	params.name = "ap_isolate";
	params.value = string;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	wifi_hostapdWrite(config_file,&params,1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm)
{
	char mgmtpwr_file[32] = {0};
	char cmd[64] = {0};
	char buf[32]={0};
	int res;

	if (NULL == output_dBm)
		return RETURN_ERR;
	res = snprintf(mgmtpwr_file, sizeof(mgmtpwr_file), "%s%d.txt", MGMT_POWER_CTRL, apIndex);
	if (os_snprintf_error(sizeof(mgmtpwr_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	res = snprintf(cmd, sizeof(cmd), "cat %s 2> /dev/null", mgmtpwr_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0)
		*output_dBm = strtol(buf, NULL, 10);
   	else
 		*output_dBm = 23;
	return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT wlanIndex, INT dBm)
{
	char interface_name[16] = {0};
	char mgmt_pwr_file[128]={0};
	FILE *f = NULL;
	int if_idx, ret = 0;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;
	char power[16] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_GetInterfaceName(wlanIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if_idx = if_nametoindex(interface_name);
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_TXPOWER;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/
	res = snprintf(power, sizeof(power), "%d", dBm);
	if (os_snprintf_error(sizeof(power), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_TXPWR_MGMT, strlen(power), power)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}

	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");

	res = snprintf(mgmt_pwr_file, sizeof(mgmt_pwr_file), "%s%d.txt", MGMT_POWER_CTRL, wlanIndex);
	if (os_snprintf_error(sizeof(mgmt_pwr_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	f = fopen(mgmt_pwr_file, "w");
	if (f == NULL) {
		fprintf(stderr, "%s: fopen failed\n", __func__);
		return RETURN_ERR;
	}
	fprintf(f, "%d", dBm);
	fclose(f);
   return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}
INT wifi_getRadioDcsChannelMetrics(INT radioIndex,wifi_channelMetrics_t *input_output_channelMetrics_array,INT size)
{
	return RETURN_OK;
}
INT wifi_setRadioDcsDwelltime(INT radioIndex, INT ms)
{
	return RETURN_OK;
}
INT wifi_getRadioDcsDwelltime(INT radioIndex, INT *ms)
{
	return RETURN_OK;
}
INT wifi_setRadioDcsScanning(INT radioIndex, BOOL enable)
{
	return RETURN_OK;
}
INT wifi_setBSSTransitionActivation(UINT apIndex, BOOL activate)
{
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	list.name = "bss_transition";
	list.value = activate?"1":"0";
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);

	return RETURN_OK;
}
wifi_apAuthEvent_callback apAuthEvent_cb = NULL;

void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc)
{
	return;
}

INT wifi_setApCsaDeauth(INT apIndex, INT mode)
{
	// TODO Implement me!
	return RETURN_OK;
}

INT wifi_setApScanFilter(INT apIndex, INT mode, CHAR *essid)
{
	char file_name[128] = {0};
	FILE *f = NULL;
	int max_num_radios = 0;
	int res, ret;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	wifi_getMaxRadioNumber(&max_num_radios);
	if (essid == NULL || strlen(essid) == 0 || apIndex == -1) {
		for (int index = 0; index < max_num_radios; index++) {
			res = snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, index);
			if (os_snprintf_error(sizeof(file_name), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}

			f = fopen(file_name, "w");
			if (f == NULL)
				return RETURN_ERR;
			// For mode == 0 is to disable filter, just don't write to the file.
			if (mode) {
				ret = fprintf(f, "%s", essid);
				if (ret < 0)
					wifi_debug(DEBUG_ERROR, "fprintf fail\n");
			}

			fclose(f);
		}
	} else {		// special case, need to set AP's SSID as filter for each radio.
		res = snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, apIndex);
		if (os_snprintf_error(sizeof(file_name), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		f = fopen(file_name, "w");
		if (f == NULL)
			return RETURN_ERR;

		// For mode == 0 is to disable filter, just don't write to the file.
		if (mode) {
			ret = fprintf(f, "%s", essid);
			if (ret < 0)
				wifi_debug(DEBUG_ERROR, "fprintf fail\n");
		}

		fclose(f);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_pushRadioChannel(INT radioIndex, UINT channel)
{
	// TODO Implement me!
	//Apply wifi_pushRadioChannel() instantly
	return RETURN_ERR;
}

INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enable)
{
	// TODO Implement me!
	return RETURN_OK;
}


static int tidStats_callback(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1],*tidattr;
	int rem , tid_index = 0;

	wifi_associated_dev_tid_stats_t *out = (wifi_associated_dev_tid_stats_t*)arg;
	wifi_associated_dev_tid_entry_t *stats_entry;

	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
				 [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED },
	};
	static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
				 [NL80211_TID_STATS_TX_MSDU] = { .type = NLA_U64 },
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
				  genlmsg_attrlen(gnlh, 0), NULL);


	if (!tb[NL80211_ATTR_STA_INFO]) {
		wifi_debug(DEBUG_ERROR, "station stats missing!\n");
		return NL_SKIP;
	}

	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
							 tb[NL80211_ATTR_STA_INFO],
							 stats_policy)) {
		wifi_debug(DEBUG_ERROR, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	if (sinfo[NL80211_STA_INFO_TID_STATS]) {
		nla_for_each_nested(tidattr, sinfo[NL80211_STA_INFO_TID_STATS], rem)
		{
			stats_entry = &out->tid_array[tid_index];

			stats_entry->tid = tid_index;
			stats_entry->ac = _tid_ac_index_get[tid_index];

			if(sinfo[NL80211_STA_INFO_TID_STATS])
			{
				if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,tidattr, tid_policy)) {
					printf("failed to parse nested stats attributes!");
					return NL_SKIP;
				}
			}
			if(stats_info[NL80211_TID_STATS_TX_MSDU])
				stats_entry->num_msdus = (unsigned long long)nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

			if(tid_index < (PS_MAX_TID - 1))
				tid_index++;
		}
	}
	//ToDo: sum_time_ms, ewma_time_ms
	return NL_SKIP;
}

INT wifi_getApAssociatedDeviceTidStatsResult(INT radioIndex,  mac_address_t *clientMacAddress, wifi_associated_dev_tid_stats_t *tid_stats,  ULLONG *handle)
{
	Netlink nl;
	char  if_name[IF_NAME_SIZE];
	char interface_name[IF_NAME_SIZE] = {0};
	int res;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(if_name, sizeof(if_name), "%s", interface_name);
	if (os_snprintf_error(sizeof(if_name), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	nl.id = initSock80211(&nl);

	if (nl.id < 0) {
		wifi_debug(DEBUG_ERROR, "Error initializing netlink \n");
		return -1;
	}

	struct nl_msg* msg = nlmsg_alloc();

	if (!msg) {
		wifi_debug(DEBUG_ERROR, "Failed to allocate netlink message.\n");
		nlfree(&nl);
		return -2;
	}

	genlmsg_put(msg,
			  NL_AUTO_PID,
			  NL_AUTO_SEQ,
			  nl.id,
			  0,
			  0,
			  NL80211_CMD_GET_STATION,
			  0);

	nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, clientMacAddress);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
	nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,tidStats_callback,tid_stats);
	nl_send_auto_complete(nl.socket, msg);
	nl_recvmsgs(nl.socket, nl.cb);
	nlmsg_free(msg);
	nlfree(&nl);
	return RETURN_OK;
}


INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
	char interface_name[16] = {0};
	char cmd[128]={0};
	char buf[128]={0};
	int freq = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	// full mode is used to scan all channels.
	// multiple channels is ambiguous, iw can not set multiple frequencies in one time.
	if (scan_mode != WIFI_RADIO_SCAN_MODE_FULL)
		ieee80211_channel_to_frequency(chan_list[0], &freq);

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if (freq)
		res = snprintf(cmd, sizeof(cmd), "iw dev %s scan trigger duration %d freq %d", interface_name, dwell_time, freq);
	else
		res = snprintf(cmd, sizeof(cmd), "iw dev %s scan trigger duration %d", interface_name, dwell_time);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	_syscmd(cmd, buf, sizeof(buf));
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}


INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientMeasure(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_eventUnregister(void)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_delApAclDevices(INT apIndex)
{
	char inf_name[IF_NAME_SIZE] = {0};
	struct unl unl_ins;
	int if_idx = 0, ret = 0;
	struct nl_msg *msg  = NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;

	if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}
	/*init mtk nl80211 vendor cmd*/
	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_ACL;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;
	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}
	/*add mtk vendor cmd data*/
	if (nla_put_flag(msg, MTK_NL80211_VENDOR_ATTR_ACL_CLEAR_ALL)) {
		wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
		nlmsg_free(msg);
		goto err;
	}
	/*send mtk nl80211 vendor msg*/
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}
	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");
	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;

	return RETURN_OK;
}

static int rxStatsInfo_callback(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
	char mac_addr[20],dev[20];

	nla_parse(tb,
		NL80211_ATTR_MAX,
		genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0),
		NULL);

	if (!tb[NL80211_ATTR_STA_INFO]) {
		wifi_debug(DEBUG_ERROR, "sta stats missing!\n");
		return NL_SKIP;
	}

	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
		wifi_debug(DEBUG_ERROR, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}
	mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

	if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
		if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy )) {
			wifi_debug(DEBUG_ERROR, "failed to parse nested rate attributes!");
			return NL_SKIP;
		}
	}

	if (sinfo[NL80211_STA_INFO_TID_STATS]) {
		if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
			printf("failed to parse nested stats attributes!");
			return NL_SKIP;
		}
	}
	if (tb[NL80211_ATTR_VHT_CAPABILITY]) {

		if( nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]) )
		{
			printf("Type is VHT\n");
			if(rinfo[NL80211_RATE_INFO_VHT_NSS])
				((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);

			if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 1;
			if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
			if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
			if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
				 ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
			if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]) )
							 ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
		} else {
			printf(" OFDM or CCK \n");
			((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
			((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = 0;
		}
	}

	if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
		if(rinfo[NL80211_RATE_INFO_MCS])
			((wifi_associated_dev_rate_info_rx_stats_t*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
	}
	if (sinfo[NL80211_STA_INFO_RX_BYTES64])
		((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]);
	else if (sinfo[NL80211_STA_INFO_RX_BYTES])
		((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);

	if (sinfo[NL80211_STA_INFO_TID_STATS]) {
		if (stats_info[NL80211_TID_STATS_RX_MSDU])
			((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_RX_MSDU]);
	}

	if (sinfo[NL80211_STA_INFO_SIGNAL])
		((wifi_associated_dev_rate_info_rx_stats_t*)arg)->rssi_combined = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
	//Assigning 0 for RETRIES ,PPDUS and MPDUS as we dont have rx retries attribute in libnl_3.3.0
	((wifi_associated_dev_rate_info_rx_stats_t*)arg)->retries = 0;
	((wifi_associated_dev_rate_info_rx_stats_t*)arg)->ppdus = 0;
	((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = 0;
	//rssi_array need to be filled
	return NL_SKIP;
}

INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
	Netlink nl;
	char if_name[32];
	if (wifi_GetInterfaceName(radioIndex, if_name) != RETURN_OK)
		return RETURN_ERR;

	*output_array_size = sizeof(wifi_associated_dev_rate_info_rx_stats_t);

	if (*output_array_size <= 0)
		return RETURN_OK;

	nl.id = initSock80211(&nl);

	if (nl.id < 0) {
	wifi_debug(DEBUG_ERROR, "Error initializing netlink \n");
	return 0;
	}

	struct nl_msg* msg = nlmsg_alloc();

	if (!msg) {
		wifi_debug(DEBUG_ERROR, "Failed to allocate netlink message.\n");
		nlfree(&nl);
		return 0;
	}

	genlmsg_put(msg,
		NL_AUTO_PID,
		NL_AUTO_SEQ,
		nl.id,
		0,
		0,
		NL80211_CMD_GET_STATION,
		0);

	nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, *clientMacAddress);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
	nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, rxStatsInfo_callback, stats_array);
	nl_send_auto_complete(nl.socket, msg);
	nl_recvmsgs(nl.socket, nl.cb);
	nlmsg_free(msg);
	nlfree(&nl);
	return RETURN_OK;
}

static int txStatsInfo_callback(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
	struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
	char mac_addr[20],dev[20];

	nla_parse(tb,
			  NL80211_ATTR_MAX,
			  genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0),
			  NULL);

	if(!tb[NL80211_ATTR_STA_INFO]) {
		wifi_debug(DEBUG_ERROR, "sta stats missing!\n");
		return NL_SKIP;
	}

	if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
		wifi_debug(DEBUG_ERROR, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

	if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
		if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
			wifi_debug(DEBUG_ERROR, "failed to parse nested rate attributes!");
			return NL_SKIP;
		}
	}

	if(sinfo[NL80211_STA_INFO_TID_STATS])
	{
		if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
			printf("failed to parse nested stats attributes!");
			return NL_SKIP;
		}
	}
	if (tb[NL80211_ATTR_VHT_CAPABILITY]) {
		if(nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]))
		{
			printf("Type is VHT\n");
			if(rinfo[NL80211_RATE_INFO_VHT_NSS])
				((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);

			if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 1;
			if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
			if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
			if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
				((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
			if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]))
				((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
		}
		else
		{
			printf(" OFDM or CCK \n");
			((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
			((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = 0;
		}
	}

	if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
	   if(rinfo[NL80211_RATE_INFO_MCS])
		   ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
	}

	if(sinfo[NL80211_STA_INFO_TX_BYTES64])
		((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]);
	else if (sinfo[NL80211_STA_INFO_TX_BYTES])
		((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);

	//Assigning  0 for mpdus and ppdus , as we do not have attributes in netlink
	((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;
	((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;

	if(sinfo[NL80211_STA_INFO_TID_STATS]) {
		if(stats_info[NL80211_TID_STATS_TX_MSDU])
			((wifi_associated_dev_rate_info_tx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);
	}

	if(sinfo[NL80211_STA_INFO_TX_RETRIES])
		((wifi_associated_dev_rate_info_tx_stats_t*)arg)->retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);

	if(sinfo[NL80211_STA_INFO_TX_FAILED] && sinfo[NL80211_STA_INFO_TX_PACKETS])
		((wifi_associated_dev_rate_info_tx_stats_t*)arg)->attempts = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]) + nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);

	return NL_SKIP;
}

INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
	Netlink nl;
	char if_name[IF_NAME_SIZE];
	char interface_name[IF_NAME_SIZE] = {0};
	int res;

	if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	*output_array_size = sizeof(wifi_associated_dev_rate_info_tx_stats_t);

	if (*output_array_size <= 0)
		return RETURN_OK;

	res = snprintf(if_name, sizeof(if_name), "%s", interface_name);
	if (os_snprintf_error(sizeof(if_name), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	nl.id = initSock80211(&nl);

	if(nl.id < 0) {
		wifi_debug(DEBUG_ERROR, "Error initializing netlink \n");
		return 0;
	}

	struct nl_msg* msg = nlmsg_alloc();

	if(!msg) {
		wifi_debug(DEBUG_ERROR, "Failed to allocate netlink message.\n");
		nlfree(&nl);
		return 0;
	}

	genlmsg_put(msg,
				NL_AUTO_PID,
				NL_AUTO_SEQ,
				nl.id,
				0,
				0,
				NL80211_CMD_GET_STATION,
				0);

	nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, clientMacAddress);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
	nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, txStatsInfo_callback, stats_array);
	nl_send_auto_complete(nl.socket, msg);
	nl_recvmsgs(nl.socket, nl.cb);
	nlmsg_free(msg);
	nlfree(&nl);
	return RETURN_OK;
}

INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate)
{
	// TODO Implement me!
	char buf[MAX_BUF_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "bss_transition", buf, sizeof(buf));
	*activate = (strncmp("1",buf,1) == 0);

	return RETURN_OK;
}

INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;
	int res;

	list.name = "rrm_neighbor_report";
	list.value = activate?"1":"0";
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &list, 1);

	return RETURN_OK;
}

INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate)
{
	char buf[32] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "rrm_neighbor_report", buf, sizeof(buf));
	*activate = (strncmp("1",buf,1) == 0);

	return RETURN_OK;
}
#undef HAL_NETLINK_IMPL
#ifdef HAL_NETLINK_IMPL
static int chanSurveyInfo_callback(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
	char dev[20];
	int freq =0 ;
	static int i=0;

	wifi_channelStats_t_loc *out = (wifi_channelStats_t_loc*)arg;

	static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0), NULL);

	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

	if (!tb[NL80211_ATTR_SURVEY_INFO]) {
		fprintf(stderr, "survey data missing!\n");
		return NL_SKIP;
	}

	if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,tb[NL80211_ATTR_SURVEY_INFO],survey_policy))
	{
		fprintf(stderr, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}


	if(out[0].array_size == 1 )
	{
		if(sinfo[NL80211_SURVEY_INFO_IN_USE])
		{
			if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
				freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
			out[0].ch_number = ieee80211_frequency_to_channel(freq);

			if (sinfo[NL80211_SURVEY_INFO_NOISE])
				out[0].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
				out[0].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
				out[0].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
				out[0].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
				out[0].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
			if (sinfo[NL80211_SURVEY_INFO_TIME])
				out[0].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
			return NL_STOP;
		}
	} else {
		if ( i <=  out[0].array_size ) {
			if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
				freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
			out[i].ch_number = ieee80211_frequency_to_channel(freq);

			if (sinfo[NL80211_SURVEY_INFO_NOISE])
				out[i].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
				out[i].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
				out[i].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
				out[i].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
			if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
				out[i].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
			if (sinfo[NL80211_SURVEY_INFO_TIME])
				out[i].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
		}
	}

	i++;
	return NL_SKIP;
}
#endif

static int ieee80211_channel_to_frequency(int channel, int *freqMHz)
{
	char command[MAX_CMD_SIZE], output[MAX_BUF_SIZE];
	FILE *fp;
	int res;

	if(access("/tmp/freq-channel-map.txt", F_OK)==-1)
	{
		printf("Creating Frequency-Channel Map\n");
		system("iw phy | grep 'MHz \\[' | cut -d' ' -f2,4 > /tmp/freq-channel-map.txt");
	}
	res = snprintf(command, sizeof(command), "cat /tmp/freq-channel-map.txt | grep '\\[%d\\]$' | cut -d' ' -f1", channel);
	if (os_snprintf_error(sizeof(command), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if((fp = popen(command, "r")))
	{
		fgets(output, sizeof(output), fp);
		*freqMHz = atoi(output);
		pclose(fp);
	}

	return 0;
}

static int get_survey_dump_buf(INT radioIndex, int channel, char *buf, size_t bufsz)
{
	int freqMHz = -1;
	char cmd[MAX_CMD_SIZE] = {'\0'};
	char interface_name[16] = {0};
	int res;

	ieee80211_channel_to_frequency(channel, &freqMHz);
	if (freqMHz == -1) {
		wifi_dbg_printf("%s: failed to get channel frequency for channel: %d\n", __func__, channel);
		return -1;
	}

	wifi_GetInterfaceName(radioIndex, interface_name);
	res = snprintf(cmd, sizeof(cmd), "iw dev %s survey dump | grep -A5 %d | tr -d '\\t'", interface_name, freqMHz);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (_syscmd(cmd, buf, bufsz) == RETURN_ERR) {
		wifi_dbg_printf("%s: failed to execute '%s' for radioIndex=%d\n", __FUNCTION__, cmd, radioIndex);
		return -1;
	}

	return 0;
}

static int fetch_survey_from_buf(INT radioIndex, const char *buf, wifi_channelStats_t *stats)
{
	const char *ptr = buf;
	char *key = NULL;
	char *val = NULL;
	char line[256] = { '\0' };

	while ((ptr = get_line_from_str_buf(ptr, line))) {
		if (strstr(line, "Frequency")) continue;

		key = strtok(line, ":");
		val = strtok(NULL, " ");
		wifi_dbg_printf("%s: key='%s' val='%s'\n", __func__, key, val);

		if (!strcmp(key, "noise")) {
			sscanf(val, "%d", &stats->ch_noise);
			if (stats->ch_noise == 0) {
				// Workaround for missing noise information.
				// Assume -95 for 2.4G and -103 for 5G
				if (radioIndex == 0) stats->ch_noise = -95;
				if (radioIndex == 1) stats->ch_noise = -103;
			}
		}
		else if (!strcmp(key, "channel active time")) {
			sscanf(val, "%llu", &stats->ch_utilization_total);
		}
		else if (!strcmp(key, "channel busy time")) {
			sscanf(val, "%llu", &stats->ch_utilization_busy);
		}
		else if (!strcmp(key, "channel receive time")) {
			sscanf(val, "%llu", &stats->ch_utilization_busy_rx);
		}
		else if (!strcmp(key, "channel transmit time")) {
			sscanf(val, "%llu", &stats->ch_utilization_busy_tx);
		}
	};

	return 0;
}

INT wifi_getRadioChannelStats(INT radioIndex,wifi_channelStats_t *input_output_channelStats_array,INT array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
#ifdef HAL_NETLINK_IMPL
	Netlink nl;
	wifi_channelStats_t_loc local[array_size];
	char  if_name[32];

	local[0].array_size = array_size;

	if (wifi_GetInterfaceName(radioIndex, if_name) != RETURN_OK)
		return RETURN_ERR;

	nl.id = initSock80211(&nl);

	if (nl.id < 0) {
		fprintf(stderr, "Error initializing netlink \n");
		return -1;
	}

	struct nl_msg* msg = nlmsg_alloc();

	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message.\n");
		nlfree(&nl);
		return -2;
	}

	genlmsg_put(msg,
				NL_AUTO_PID,
				NL_AUTO_SEQ,
				nl.id,
				0,
				NLM_F_DUMP,
				NL80211_CMD_GET_SURVEY,
				0);

	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
	nl_send_auto_complete(nl.socket, msg);
	nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,chanSurveyInfo_callback,local);
	nl_recvmsgs(nl.socket, nl.cb);
	nlmsg_free(msg);
	nlfree(&nl);
	//Copying the Values
	for(int i=0;i<array_size;i++)
	{
		input_output_channelStats_array[i].ch_number = local[i].ch_number;
		input_output_channelStats_array[i].ch_noise = local[i].ch_noise;
		input_output_channelStats_array[i].ch_utilization_busy_rx = local[i].ch_utilization_busy_rx;
		input_output_channelStats_array[i].ch_utilization_busy_tx = local[i].ch_utilization_busy_tx;
		input_output_channelStats_array[i].ch_utilization_busy = local[i].ch_utilization_busy;
		input_output_channelStats_array[i].ch_utilization_busy_ext = local[i].ch_utilization_busy_ext;
		input_output_channelStats_array[i].ch_utilization_total = local[i].ch_utilization_total;
		//TODO: ch_radar_noise, ch_max_80211_rssi, ch_non_80211_noise, ch_utilization_busy_self
	}
#else
	ULONG channel = 0;
	int i;
	int number_of_channels = array_size;
	char buf[512];

	if (number_of_channels == 0) {
		if (wifi_getRadioChannel(radioIndex, &channel) != RETURN_OK) {
			wifi_dbg_printf("%s: cannot get current channel for radioIndex=%d\n", __func__, radioIndex);
			return RETURN_ERR;
		}
		number_of_channels = 1;
		input_output_channelStats_array[0].ch_number = channel;
	}

	for (i = 0; i < number_of_channels; i++) {

		input_output_channelStats_array[i].ch_noise = 0;
		input_output_channelStats_array[i].ch_utilization_busy_rx = 0;
		input_output_channelStats_array[i].ch_utilization_busy_tx = 0;
		input_output_channelStats_array[i].ch_utilization_busy = 0;
		input_output_channelStats_array[i].ch_utilization_busy_ext = 0; // XXX: unavailable
		input_output_channelStats_array[i].ch_utilization_total = 0;

		memset(buf, 0, sizeof(buf));
		if (get_survey_dump_buf(radioIndex, input_output_channelStats_array[i].ch_number, buf, sizeof(buf))) {
			return RETURN_ERR;
		}
		if (fetch_survey_from_buf(radioIndex, buf, &input_output_channelStats_array[i])) {
			wifi_dbg_printf("%s: cannot fetch survey from buf for radioIndex=%d\n", __func__, radioIndex);
			return RETURN_ERR;
		}

		// XXX: fake missing 'self' counter which is not available in iw survey output
		//	  the 'self' counter (a.k.a 'bss') requires Linux Kernel update
		input_output_channelStats_array[i].ch_utilization_busy_self = input_output_channelStats_array[i].ch_utilization_busy_rx / 8;

		input_output_channelStats_array[i].ch_utilization_busy_rx *= 1000;
		input_output_channelStats_array[i].ch_utilization_busy_tx *= 1000;
		input_output_channelStats_array[i].ch_utilization_busy_self *= 1000;
		input_output_channelStats_array[i].ch_utilization_busy *= 1000;
		input_output_channelStats_array[i].ch_utilization_total *= 1000;

		wifi_dbg_printf("%s: ch_number=%d ch_noise=%d total=%llu busy=%llu busy_rx=%llu busy_tx=%llu busy_self=%llu busy_ext=%llu\n",
				   __func__,
				   input_output_channelStats_array[i].ch_number,
				   input_output_channelStats_array[i].ch_noise,
				   input_output_channelStats_array[i].ch_utilization_total,
				   input_output_channelStats_array[i].ch_utilization_busy,
				   input_output_channelStats_array[i].ch_utilization_busy_rx,
				   input_output_channelStats_array[i].ch_utilization_busy_tx,
				   input_output_channelStats_array[i].ch_utilization_busy_self,
				   input_output_channelStats_array[i].ch_utilization_busy_ext);
	}
#endif
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
#define HAL_NETLINK_IMPL

/* Hostapd events */

#ifndef container_of
#define offset_of(st, m) ((size_t)&(((st *)0)->m))
#define container_of(ptr, type, member) \
				   ((type *)((char *)ptr - offset_of(type, member)))
#endif /* container_of */

struct ctrl {
	char sockpath[128];
	char sockdir[128];
	char bss[IFNAMSIZ];
	char reply[4096];
	int ssid_index;
	void (*cb)(struct ctrl *ctrl, int level, const char *buf, size_t len);
	void (*overrun)(struct ctrl *ctrl);
	struct wpa_ctrl *wpa;
	unsigned int ovfl;
	size_t reply_len;
	int initialized;
	ev_timer retry;
	ev_timer watchdog;
	ev_stat stat;
	ev_io io;
};
static wifi_newApAssociatedDevice_callback clients_connect_cb;
static wifi_apDisassociatedDevice_callback clients_disconnect_cb;
static struct ctrl wpa_ctrl[MAX_APS];
static int initialized;

static unsigned int ctrl_get_drops(struct ctrl *ctrl)
{
	char cbuf[256] = {};
	struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cmsg;
	unsigned int ovfl = ctrl->ovfl;
	unsigned int drop;

	recvmsg(ctrl->io.fd, &msg, MSG_DONTWAIT);
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL)
			ovfl = *(unsigned int *)CMSG_DATA(cmsg);

	drop = ovfl - ctrl->ovfl;
	ctrl->ovfl = ovfl;

	return drop;
}

static void ctrl_close(struct ctrl *ctrl)
{
	if (ctrl->io.cb)
		ev_io_stop(EV_DEFAULT_ &ctrl->io);
	if (ctrl->retry.cb)
		ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
	if (!ctrl->wpa)
		return;

	wpa_ctrl_detach(ctrl->wpa);
	wpa_ctrl_close(ctrl->wpa);
	ctrl->wpa = NULL;
	printf("WPA_CTRL: closed index=%d\n", ctrl->ssid_index);
}

static void ctrl_process(struct ctrl *ctrl)
{
	const char *str;
	int drops;
	int level;

	/* Example events:
	 *
	 * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19
	 * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19 keyid=sample_keyid
	 * <3>AP-STA-DISCONNECTED 60:b4:f7:f0:0a:19
	 * <3>CTRL-EVENT-CONNECTED - Connection to 00:1d:73:73:88:ea completed [id=0 id_str=]
	 * <3>CTRL-EVENT-DISCONNECTED bssid=00:1d:73:73:88:ea reason=3 locally_generated=1
	 */
	if (!(str = index(ctrl->reply, '>')))
		return;
	if (sscanf(ctrl->reply, "<%d>", &level) != 1)
		return;

	str++;

	if (strncmp("AP-STA-CONNECTED ", str, 17) == 0) {
		if (!(str = index(ctrl->reply, ' ')))
			return;
		wifi_associated_dev_t sta;
		memset(&sta, 0, sizeof(sta));

		sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&sta.cli_MACAddress[0], &sta.cli_MACAddress[1], &sta.cli_MACAddress[2],
				&sta.cli_MACAddress[3], &sta.cli_MACAddress[4], &sta.cli_MACAddress[5]);

		sta.cli_Active=true;

		(clients_connect_cb)(ctrl->ssid_index, &sta);
		goto handled;
	}

	if (strncmp("AP-STA-DISCONNECTED ", str, 20) == 0) {
		if (!(str = index(ctrl->reply, ' ')))
			return;

		(clients_disconnect_cb)(ctrl->ssid_index, (char*)str, 0);
		goto handled;
	}

	if (strncmp("CTRL-EVENT-TERMINATING", str, 22) == 0) {
		printf("CTRL_WPA: handle TERMINATING event\n");
		goto retry;
	}

	if (strncmp("AP-DISABLED", str, 11) == 0) {
		printf("CTRL_WPA: handle AP-DISABLED\n");
		goto retry;
	}

	printf("Event not supported!!\n");

handled:

	if ((drops = ctrl_get_drops(ctrl))) {
		printf("WPA_CTRL: dropped %d messages index=%d\n", drops, ctrl->ssid_index);
		if (ctrl->overrun)
			ctrl->overrun(ctrl);
	}

	return;

retry:
	printf("WPA_CTRL: closing\n");
	ctrl_close(ctrl);
	printf("WPA_CTRL: retrying from ctrl prcoess\n");
	ev_timer_again(EV_DEFAULT_ &ctrl->retry);
}

static void ctrl_ev_cb(EV_P_ struct ev_io *io, int events)
{
	struct ctrl *ctrl = container_of(io, struct ctrl, io);
	int err;

	memset(ctrl->reply, 0, sizeof(ctrl->reply));
	ctrl->reply_len = sizeof(ctrl->reply) - 1;
	err = wpa_ctrl_recv(ctrl->wpa, ctrl->reply, &ctrl->reply_len);
	ctrl->reply[ctrl->reply_len] = 0;
	if (err < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		ctrl_close(ctrl);
		ev_timer_again(EV_A_ &ctrl->retry);
		return;
	}

	ctrl_process(ctrl);
}

static int ctrl_open(struct ctrl *ctrl)
{
	int fd;

	if (ctrl->wpa)
		return 0;

	ctrl->wpa = wpa_ctrl_open(ctrl->sockpath);
	if (!ctrl->wpa)
		goto err;

	if (wpa_ctrl_attach(ctrl->wpa) < 0)
		goto err_close;

	fd = wpa_ctrl_get_fd(ctrl->wpa);
	if (fd < 0)
		goto err_detach;

	if (setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, (int[]){1}, sizeof(int)) < 0)
		goto err_detach;

	ev_io_init(&ctrl->io, ctrl_ev_cb, fd, EV_READ);
	ev_io_start(EV_DEFAULT_ &ctrl->io);

	return 0;

err_detach:
	wpa_ctrl_detach(ctrl->wpa);
err_close:
	wpa_ctrl_close(ctrl->wpa);
err:
	ctrl->wpa = NULL;
	return -1;
}

static void ctrl_stat_cb(EV_P_ ev_stat *stat, int events)
{
	struct ctrl *ctrl = container_of(stat, struct ctrl, stat);

	printf("WPA_CTRL: index=%d file state changed\n", ctrl->ssid_index);
	ctrl_open(ctrl);
}

static void ctrl_retry_cb(EV_P_ ev_timer *timer, int events)
{
	struct ctrl *ctrl = container_of(timer, struct ctrl, retry);

	printf("WPA_CTRL: index=%d retrying\n", ctrl->ssid_index);
	if (ctrl_open(ctrl) == 0) {
		printf("WPA_CTRL: retry successful\n");
		ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
	}
}

int ctrl_enable(struct ctrl *ctrl)
{
	if (ctrl->wpa)
		return 0;

	if (!ctrl->stat.cb) {
		ev_stat_init(&ctrl->stat, ctrl_stat_cb, ctrl->sockpath, 0.);
		ev_stat_start(EV_DEFAULT_ &ctrl->stat);
	}

	if (!ctrl->retry.cb) {
		ev_timer_init(&ctrl->retry, ctrl_retry_cb, 0., 5.);
	}

	return ctrl_open(ctrl);
}

static void
ctrl_msg_cb(char *buf, size_t len)
{
	struct ctrl *ctrl = container_of(buf, struct ctrl, reply);

	printf("WPA_CTRL: unsolicited message: index=%d len=%zu msg=%s", ctrl->ssid_index, len, buf);
	ctrl_process(ctrl);
}

static int ctrl_request(struct ctrl *ctrl, const char *cmd, size_t cmd_len, char *reply, size_t *reply_len)
{
	int err;

	if (!ctrl->wpa)
		return -1;
	if (*reply_len < 2)
		return -1;

	(*reply_len)--;
	ctrl->reply_len = sizeof(ctrl->reply);
	err = wpa_ctrl_request(ctrl->wpa, cmd, cmd_len, ctrl->reply, &ctrl->reply_len, ctrl_msg_cb);
	printf("WPA_CTRL: index=%d cmd='%s' err=%d\n", ctrl->ssid_index, cmd, err);
	if (err < 0)
		return err;

	if (ctrl->reply_len > *reply_len)
		ctrl->reply_len = *reply_len;

	*reply_len = ctrl->reply_len;
	memcpy(reply, ctrl->reply, *reply_len);
	reply[*reply_len - 1] = 0;
	printf("WPA_CTRL: index=%d reply='%s'\n", ctrl->ssid_index, reply);
	return 0;
}

static void ctrl_watchdog_cb(EV_P_ ev_timer *timer, int events)
{
	const char *pong = "PONG";
	const char *ping = "PING";
	char reply[1024];
	size_t len = sizeof(reply);
	int err;
	ULONG s, snum;
	INT ret;
	BOOL status;

	printf("WPA_CTRL: watchdog cb\n");

	ret = wifi_getSSIDNumberOfEntries(&snum);
	if (ret != RETURN_OK) {
		printf("%s: failed to get SSID count", __func__);
		return;
	}

	if (snum > MAX_APS) {
		printf("more ssid than supported! %lu\n", snum);
		return;
	}

	for (s = 0; s < snum; s++) {
		if (wifi_getApEnable(s, &status) != RETURN_OK) {
			printf("%s: failed to get AP Enable for index: %lu\n", __func__, s);
			continue;
		}
		if (status == false) continue;

		memset(reply, 0, sizeof(reply));
		len = sizeof(reply);
		printf("WPA_CTRL: pinging index=%d\n", wpa_ctrl[s].ssid_index);
		err = ctrl_request(&wpa_ctrl[s], ping, strlen(ping), reply, &len);
		if (err == 0 && len > strlen(pong) && !strncmp(reply, pong, strlen(pong)))
			continue;

		printf("WPA_CTRL: ping timeout index=%d\n", wpa_ctrl[s].ssid_index);
		ctrl_close(&wpa_ctrl[s]);
		printf("WPA_CTRL: ev_timer_again %lu\n", s);
		ev_timer_again(EV_DEFAULT_ &wpa_ctrl[s].retry);
	}
}

static int init_wpa()
{
	int ret = 0;
	ULONG s, snum;

	ret = wifi_getSSIDNumberOfEntries(&snum);
	if (ret != RETURN_OK) {
		printf("%s: failed to get SSID count", __func__);
		return RETURN_ERR;
	}

	if (snum > MAX_APS) {
		printf("more ssid than supported! %lu\n", snum);
		return RETURN_ERR;
	}

	for (s = 0; s < snum; s++) {
		memset(&wpa_ctrl[s], 0, sizeof(struct ctrl));
		ret = snprintf(wpa_ctrl[s].sockpath, sizeof(wpa_ctrl[s].sockpath), "%s%lu", SOCK_PREFIX, s);
		if (os_snprintf_error(sizeof(wpa_ctrl[s].sockpath), ret)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		wpa_ctrl[s].ssid_index = s;
		ctrl_enable(&wpa_ctrl[s]);
	}

	ev_timer_init(&wpa_ctrl->watchdog, ctrl_watchdog_cb, 0., 30.);
	ev_timer_again(EV_DEFAULT_ &wpa_ctrl->watchdog);

	initialized = 1;
	printf("WPA_CTRL: initialized\n");

	return RETURN_OK;
}

void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc)
{
	clients_connect_cb = callback_proc;
	if (!initialized)
		init_wpa();
}

void wifi_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback callback_proc)
{
	clients_disconnect_cb = callback_proc;
	if (!initialized)
		init_wpa();
}

INT wifi_setBTMRequest(UINT apIndex, CHAR *peerMac, wifi_BTMRequest_t *request)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_setRMBeaconRequest(UINT apIndex, CHAR *peer, wifi_BeaconRequest_t *in_request, UCHAR *out_DialogToken)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_getRadioChannels(INT radioIndex, wifi_channelMap_t *outputMap, INT outputMapSize)
{
	int i;
	int phyId = -1;
	char cmd[256] = {0};
	char channel_numbers_buf[256] = {0};
	char dfs_state_buf[256] = {0};
	char line[256] = {0};
	const char *ptr;
	BOOL dfs_enable = false;
	int res;

	memset(outputMap, 0, outputMapSize*sizeof(wifi_channelMap_t)); // all unused entries should be zero

	wifi_getRadioDfsEnable(radioIndex, &dfs_enable);
	phyId = radio_index_to_phy(radioIndex);

	res = snprintf(cmd, sizeof (cmd), "iw phy phy%d info | grep -e '\\*.*MHz .*dBm' | grep -v '%sno IR\\|5340\\|5480' | awk '{print $4}' | tr -d '[]'", phyId, dfs_enable?"":"radar\\|");
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	if (_syscmd(cmd, channel_numbers_buf, sizeof(channel_numbers_buf)) == RETURN_ERR) {
		wifi_dbg_printf("%s: failed to execute '%s'\n", __FUNCTION__, cmd);
		return RETURN_ERR;
	}

	ptr = channel_numbers_buf;
	i = 0;
	while ((ptr = get_line_from_str_buf(ptr, line))) {
		if (i >= outputMapSize) {
				wifi_dbg_printf("%s: DFS map size too small\n", __FUNCTION__);
				return RETURN_ERR;
		}
		sscanf(line, "%d", &outputMap[i].ch_number);

		memset(cmd, 0, sizeof(cmd));
		// Below command should fetch string for DFS state (usable, available or unavailable)
		// Example line: "DFS state: usable (for 78930 sec)"
		if (sprintf(cmd,"iw list | grep -A 2 '\\[%d\\]' | tr -d '\\t' | grep 'DFS state' | awk '{print $3}' | tr -d '\\n'", outputMap[i].ch_number) < 0) {
			wifi_dbg_printf("%s: failed to build dfs state command\n", __FUNCTION__);
			return RETURN_ERR;
		}

		memset(dfs_state_buf, 0, sizeof(dfs_state_buf));
		if (_syscmd(cmd, dfs_state_buf, sizeof(dfs_state_buf)) == RETURN_ERR) {
			wifi_dbg_printf("%s: failed to execute '%s'\n", __FUNCTION__, cmd);
			return RETURN_ERR;
		}

		wifi_dbg_printf("DFS state = '%s'\n", dfs_state_buf);

		if (!strcmp(dfs_state_buf, "usable")) {
			outputMap[i].ch_state = CHAN_STATE_DFS_NOP_FINISHED;
		} else if (!strcmp(dfs_state_buf, "available")) {
			outputMap[i].ch_state = CHAN_STATE_DFS_CAC_COMPLETED;
		} else if (!strcmp(dfs_state_buf, "unavailable")) {
			outputMap[i].ch_state = CHAN_STATE_DFS_NOP_START;
		} else {
			outputMap[i].ch_state = CHAN_STATE_AVAILABLE;
		}
		i++;
	}

	return RETURN_OK;

	wifi_dbg_printf("%s: wrong radio index (%d)\n", __FUNCTION__, radioIndex);
	return RETURN_ERR;
}

INT wifi_chan_eventRegister(wifi_chan_eventCB_t eventCb)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_getRadioBandUtilization (INT radioIndex, INT *output_percentage)
{
	int ret = -1;
	char inf_name[IF_NAME_SIZE] = {0};
	int if_idx = 0;
	struct unl unl_ins;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct mtk_nl80211_cb_data cb_data;
	wdev_ap_metric ap_metric;

	/*init mtk nl80211 vendor cmd*/

	if (wifi_GetInterfaceName(radioIndex, inf_name) != RETURN_OK)
		return RETURN_ERR;
	if_idx = if_nametoindex(inf_name);
	if (!if_idx) {
		wifi_debug(DEBUG_ERROR,"can't finde ifname(%s) index,ERROR\n", inf_name);
		return RETURN_ERR;
	}

	param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_GET_STATISTIC;
	param.if_type = NL80211_ATTR_IFINDEX;
	param.if_idx = if_idx;

	ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
		return RETURN_ERR;
	}

	/*add mtk vendor cmd data*/

	if (nla_put(msg, MTK_NL80211_VENDOR_ATTR_GET_AP_METRICS, sizeof(wdev_ap_metric), (char *)&ap_metric)) {
		wifi_debug(DEBUG_ERROR, "Nla put GET_AP_METRICS attribute error\n");
		nlmsg_free(msg);
		goto err;
	}

	/*send mtk nl80211 vendor msg*/
	cb_data.out_buf = (char *)output_percentage;
	cb_data.out_len = sizeof(wdev_ap_metric);
	ret = mtk_nl80211_send(&unl_ins, msg, msg_data, mtk_get_ap_metrics, &cb_data);
	if (ret) {
		wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
		goto err;
	}

	/*deinit mtk nl80211 vendor msg*/
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_NOTICE, "set cmd success.\n");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
err:
	mtk_nl80211_deint(&unl_ins);
	wifi_debug(DEBUG_ERROR, "set cmd fails.\n");
	return RETURN_ERR;
}


INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_switchBand(char *interface_name,INT radioIndex,char *freqBand)
{
	// TODO API refrence Implementaion is present on RPI hal
	return RETURN_ERR;
}

INT wifi_getRadioPercentageTransmitPower(INT apIndex, ULONG *txpwr_pcntg)
{
	ULONG pwr_percentage = 0;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(txpwr_pcntg == NULL)
		return RETURN_ERR;

	wifi_getRadioTransmitPower(apIndex, &pwr_percentage);
	*txpwr_pcntg = pwr_percentage;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setZeroDFSState(UINT radioIndex, BOOL enable, BOOL precac)
{
	// TODO precac feature.
	struct params params[2] = {0};
	char config_file[128] = {0};
	BOOL dfs_enable = false;
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	band = wifi_index_to_band(radioIndex);
	wifi_getRadioDfsEnable(radioIndex, &dfs_enable);

	if (dfs_enable == false) {
		WIFI_ENTRY_EXIT_DEBUG("Please enable DFS firstly!: %s\n", __func__);
		return RETURN_ERR;
	}
	params[0].name = "DfsZeroWaitDefault";
	params[0].value = enable?"1":"0";
	params[1].name = "DfsDedicatedZeroWait";
	params[1].value = enable?"1":"0";
	res = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_datfileWrite(config_file, params, 2);
	wifi_reloadAp(radioIndex);
	/* TODO precac feature */

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getZeroDFSState(UINT radioIndex, BOOL *enable, BOOL *precac)
{
	char config_file[128] = {0};
	char buf1[32] = {0};
	char buf2[32] = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == enable || NULL == precac)
		return RETURN_ERR;
	band = wifi_index_to_band(radioIndex);
	res = snprintf(config_file, sizeof(config_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_datfileRead(config_file, "DfsZeroWaitDefault", buf1, sizeof(buf1));
	wifi_datfileRead(config_file, "DfsDedicatedZeroWait", buf2, sizeof(buf2));
	if ((strncmp(buf1, "1", 1) == 0) && (strncmp(buf2, "1", 1) == 0))
		*enable = true;
	else
		*enable = false;

	/* TODO precac feature */

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_isZeroDFSSupported(UINT radioIndex, BOOL *supported)
{
	*supported = TRUE;
	return RETURN_OK;
}

INT wifi_setDownlinkMuType(INT radio_index, wifi_dl_mu_type_t mu_type)
{
	CHAR dat_file[64] = {0};
	wifi_band band = band_invalid;
	char ofdmabuf[32] = {'\0'};
	char mimobuf[32] = {'\0'};
	char new_ofdmabuf[32] = {'\0'};
	char new_mimobuf[32] = {'\0'};
	struct params params[2];
	char *str_zero = "0;0;0;0;0;0;0;0;0;0;0;0;0;0;0";/*default 15bss per band.*/
	char *str_one = "1;1;1;1;1;1;1;1;1;1;1;1;1;1;1";
	UCHAR bss_cnt = 0;
	UCHAR val_cnt = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if ((mu_type < WIFI_DL_MU_TYPE_NONE)
		|| (mu_type > WIFI_DL_MU_TYPE_OFDMA_MIMO)) {
		printf("%s:mu_type input Error", __func__);
		return RETURN_ERR;
	}
	band = wifi_index_to_band(radio_index);
	if (band == band_invalid) {
		printf("%s:Band Error\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	/*get current value in dat file*/
	wifi_datfileRead(dat_file, "MuOfdmaDlEnable", ofdmabuf, sizeof(ofdmabuf));
	wifi_datfileRead(dat_file, "MuMimoDlEnable", mimobuf, sizeof(mimobuf));
	WIFI_ENTRY_EXIT_DEBUG("%s:ofdma-%s, mimo-%s\n", __func__, ofdmabuf, mimobuf);
	get_bssnum_byindex(radio_index, &bss_cnt);
	val_cnt = 2*bss_cnt - 1;
	WIFI_ENTRY_EXIT_DEBUG("bss number: %d\n", bss_cnt);
	if ((val_cnt >= sizeof(new_ofdmabuf))
		|| (val_cnt >= sizeof(new_mimobuf))) {
		printf("%s:bss cnt Error", __func__);
		return RETURN_ERR;
	}
	/*translate set value*/
	if (mu_type == WIFI_DL_MU_TYPE_NONE) {
		strncpy(new_ofdmabuf, str_zero, val_cnt);
		strncpy(new_mimobuf, str_zero, val_cnt);
	} else if (mu_type == WIFI_DL_MU_TYPE_OFDMA) {
		strncpy(new_ofdmabuf, str_one, val_cnt);
		strncpy(new_mimobuf, str_zero, val_cnt);
	} else if (mu_type == WIFI_DL_MU_TYPE_MIMO) {
		strncpy(new_ofdmabuf, str_zero, val_cnt);
		strncpy(new_mimobuf, str_one, val_cnt);
	} else if (mu_type == WIFI_DL_MU_TYPE_OFDMA_MIMO) {
		strncpy(new_ofdmabuf, str_one, val_cnt);
		strncpy(new_mimobuf, str_one, val_cnt);
	}
	WIFI_ENTRY_EXIT_DEBUG("%s:new_ofdmabuf-%s, new_mimobuf-%s\n", __func__, new_ofdmabuf, new_mimobuf);
	/*same value, not operation*/
	if ((strncmp(new_mimobuf, mimobuf, 1) ==0)
		&& (strncmp(new_ofdmabuf, ofdmabuf, 1) ==0)) {
		printf("%s:Reduntant value\n", __func__);
		return RETURN_OK;
	}
	/*modify dat file to new file*/
	params[0].name="MuOfdmaDlEnable";
	params[0].value=new_ofdmabuf;
	params[1].name="MuMimoDlEnable";
	params[1].value=new_mimobuf;
	wifi_datfileWrite(dat_file, params, 2);
	/*hostapd control restarp ap to take effect on these new value*/
	wifi_reloadAp(radio_index);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getDownlinkMuType(INT radio_index, wifi_dl_mu_type_t *mu_type)
{
	CHAR dat_file[64] = {0};
	wifi_band band = band_invalid;
	char ofdmabuf[32] = {'\0'};
	char mimobuf[32] = {'\0'};
	char *token = NULL;
	UCHAR ofdma = 0;
	UCHAR mimo = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (mu_type == NULL)
		return RETURN_ERR;
	band = wifi_index_to_band(radio_index);
	if (band == band_invalid) {
		printf("%s:Band Error\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	/*get current value in dat file*/
	wifi_datfileRead(dat_file, "MuOfdmaDlEnable", ofdmabuf, sizeof(ofdmabuf));
	wifi_datfileRead(dat_file, "MuMimoDlEnable", mimobuf, sizeof(mimobuf));

	token = strtok(ofdmabuf, ";");
	ofdma = strtol(token, NULL, 10);
	token = strtok(mimobuf, ";");
	mimo = strtol(token, NULL, 10);
	WIFI_ENTRY_EXIT_DEBUG("%s:ofdma=%d,mimo=%d\n", __func__, ofdma, mimo);
	if ((ofdma == 1) && (mimo == 1))
		*mu_type = WIFI_DL_MU_TYPE_OFDMA_MIMO;
	else if ((ofdma == 0) && (mimo == 1))
		*mu_type = WIFI_DL_MU_TYPE_MIMO;
	else if ((ofdma == 1) && (mimo == 0))
		*mu_type = WIFI_DL_MU_TYPE_OFDMA;
	else
		*mu_type = WIFI_DL_MU_TYPE_NONE;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setUplinkMuType(INT radio_index, wifi_ul_mu_type_t mu_type)
{
	// hemu onoff=<val> (bitmap- UL MU-MIMO(bit3), DL MU-MIMO(bit2), UL OFDMA(bit1), DL OFDMA(bit0))
	CHAR dat_file[64] = {0};
	wifi_band band = band_invalid;
	char ofdmabuf[32] = {'\0'};
	char mimobuf[32] = {'\0'};
	char new_ofdmabuf[32] = {'\0'};
	char new_mimobuf[32] = {'\0'};
	struct params params[2];
	char *str_zero = "0;0;0;0;0;0;0;0;0;0;0;0;0;0;0";/*default 15bss per band.*/
	char *str_one = "1;1;1;1;1;1;1;1;1;1;1;1;1;1;1";
	UCHAR bss_cnt = 0;
	UCHAR val_cnt = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	band = wifi_index_to_band(radio_index);
	if (band == band_invalid) {
		printf("%s:Band Error\n", __func__);
		return RETURN_ERR;
	}
	if ((mu_type < WIFI_UL_MU_TYPE_NONE)
		|| (mu_type > WIFI_UL_MU_TYPE_OFDMA)) {
		printf("%s:mu_type input Error\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	/*get current value in dat file*/
	wifi_datfileRead(dat_file, "MuOfdmaUlEnable", ofdmabuf, sizeof(ofdmabuf));
	wifi_datfileRead(dat_file, "MuMimoUlEnable", mimobuf, sizeof(mimobuf));
	WIFI_ENTRY_EXIT_DEBUG("%s:ofdma-%s, mimo-%s\n", __func__, ofdmabuf, mimobuf);
	get_bssnum_byindex(radio_index, &bss_cnt);
	val_cnt = 2*bss_cnt - 1;
	printf("bssNumber:%d,ValCnt:%d\n", bss_cnt, val_cnt);
	if ((val_cnt >= sizeof(new_ofdmabuf))
		|| (val_cnt >= sizeof(new_mimobuf))) {
		printf("%s:bss cnt Error\n", __func__);
		return RETURN_ERR;
	}
	/*translate set value*/
	if (mu_type == WIFI_UL_MU_TYPE_NONE) {
		strncpy(new_ofdmabuf, str_zero, val_cnt);
		strncpy(new_mimobuf, str_zero, val_cnt);
	}
	if (mu_type == WIFI_UL_MU_TYPE_OFDMA) {
		strncpy(new_ofdmabuf, str_one, val_cnt);
		strncpy(new_mimobuf, str_zero, val_cnt);
	}
	printf("%s:new_ofdmabuf-%s, new_mimobuf-%s\n", __func__, new_ofdmabuf, new_mimobuf);
	/*same value, not operation*/
	if ((strncmp(new_mimobuf, mimobuf, 1) ==0)
		&& (strncmp(new_ofdmabuf, ofdmabuf, 1) ==0)) {
		printf("%s:Reduntant value\n", __func__);
		return RETURN_OK;
	}
	/*modify dat file to new file*/
	params[0].name="MuOfdmaUlEnable";
	params[0].value=new_ofdmabuf;
	params[1].name="MuMimoUlEnable";
	params[1].value=new_mimobuf;
	wifi_datfileWrite(dat_file, params, 2);
	wifi_reloadAp(radio_index);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getUplinkMuType(INT radio_index, wifi_ul_mu_type_t *mu_type)
{
	CHAR dat_file[64] = {0};
	wifi_band band = band_invalid;
	char ofdmabuf[32] = {'\0'};
	char mimobuf[32] = {'\0'};
	char *token = NULL;
	UCHAR ofdma = 0;
	UCHAR mimo = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (mu_type == NULL)
	return RETURN_ERR;
	band = wifi_index_to_band(radio_index);
	if (band == band_invalid) {
		printf("%s:Band Error", __func__);
		return RETURN_ERR;
	}
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	/*get current value in dat file*/
	wifi_datfileRead(dat_file, "MuOfdmaUlEnable", ofdmabuf, sizeof(ofdmabuf));
	wifi_datfileRead(dat_file, "MuMimoUlEnable", mimobuf, sizeof(mimobuf));

	token = strtok(ofdmabuf, ";");
	ofdma = strtol(token, NULL, 10);
	token = strtok(mimobuf, ";");
	mimo = strtol(token, NULL, 10);
	WIFI_ENTRY_EXIT_DEBUG("%s:ofdma=%d, mimo=%d\n", __func__, ofdma, mimo);
	if ((ofdma == 1) && (mimo == 0))
		*mu_type = WIFI_UL_MU_TYPE_OFDMA;
	else
		*mu_type = WIFI_UL_MU_TYPE_NONE;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}


INT wifi_setGuardInterval(INT radio_index, wifi_guard_interval_t guard_interval)
{
	char cmd[128] = {0};
	char buf[256] = {0};
	char config_file[64] = {0};
	char GI[8] = {0};
	UINT mode_map = 0;
	FILE *f = NULL;
	wifi_band band = band_invalid;
	char dat_file[64] = {'\0'};
	struct params params[3];
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (wifi_getRadioMode(radio_index, buf, &mode_map) == RETURN_ERR) {
		wifi_dbg_printf("%s: wifi_getRadioMode return error\n", __func__);
		return RETURN_ERR;
	}
	/*sanity check*/
	if (((guard_interval == wifi_guard_interval_1600)
		|| (guard_interval == wifi_guard_interval_3200))
		&& ((mode_map & (WIFI_MODE_BE | WIFI_MODE_AX)) == 0)) {
		wifi_dbg_printf("%s: N/AC Mode not support 1600/3200ns GI\n", __func__);
		return RETURN_ERR;
	}
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radio_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	band = wifi_index_to_band(radio_index);

	// Hostapd are not supported HE mode GI 1600, 3200 ns.
	if (guard_interval == wifi_guard_interval_800) {	// remove all capab about short GI
		res = snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[SHORT-GI-(.){1,2}0\\]//g' %s", config_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
	} else if (guard_interval == wifi_guard_interval_400 || guard_interval == wifi_guard_interval_auto){
		wifi_hostapdRead(config_file, "ht_capab", buf, sizeof(buf));
		if (strstr(buf, "[SHORT-GI-") == NULL) {
			res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^ht_capab=.*/s/$/[SHORT-GI-20][SHORT-GI-40]/' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			_syscmd(cmd, buf, sizeof(buf));
		}
		if (band == band_5) {
			wifi_hostapdRead(config_file, "vht_capab", buf, sizeof(buf));
			if (strstr(buf, "[SHORT-GI-") == NULL) {
				res = snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[SHORT-GI-80][SHORT-GI-160]/' %s", config_file);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}
				_syscmd(cmd, buf, sizeof(buf));
			}
		}
	}
	/*wifi_reloadAp(radio_index);
		caller "wifi_setRadioOperatingParameters" have done this step.
	*/
	res = snprintf(dat_file, sizeof(dat_file), "%s%d.dat", LOGAN_DAT_FILE, band);
	if (os_snprintf_error(sizeof(dat_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (guard_interval == wifi_guard_interval_400) {
		params[0].name = "HT_GI";
		params[0].value = "1";
		params[1].name = "VHT_SGI";
		params[1].value = "1";
		wifi_datfileWrite(dat_file, params, 2);
		memcpy(GI, "0.4", 3);
	} else {
		params[0].name = "HT_GI";
		params[0].value = "0";
		params[1].name = "VHT_SGI";
		params[1].value = "0";
		/*should enable FIXED_HE_GI_SUPPORT in driver*/
		params[2].name = "FgiFltf";
		if (guard_interval == wifi_guard_interval_800) {
			params[2].value = "800";
			memcpy(GI, "0.8", 3);
		} else if (guard_interval == wifi_guard_interval_1600) {
			params[2].value = "1600";
			memcpy(GI, "1.6", 3);
		} else if (guard_interval == wifi_guard_interval_3200) {
			params[2].value = "3200";
			memcpy(GI, "3.2", 3);
		} else if (guard_interval == wifi_guard_interval_auto) {
			params[2].value = "0";
			memcpy(GI, "auto", 4);
		}
		wifi_datfileWrite(dat_file, params, 3);
	}
	// Record GI for get GI function
	res = snprintf(buf, sizeof(buf), "%s%d.txt", GUARD_INTERVAL_FILE, radio_index);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	f = fopen(buf, "w");
	if (f == NULL)
		return RETURN_ERR;
	fprintf(f, "%s", GI);
	fclose(f);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getGuardInterval(INT radio_index, wifi_guard_interval_t *guard_interval)
{
	char buf[32] = {0};
	char cmd[64] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if (guard_interval == NULL)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "cat %s%d.txt 2> /dev/null", GUARD_INTERVAL_FILE, radio_index);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));

	if (strncmp(buf, "0.4", 3) == 0)
		*guard_interval = wifi_guard_interval_400;
	else if (strncmp(buf, "0.8", 3) == 0)
		*guard_interval = wifi_guard_interval_800;
	else if (strncmp(buf, "1.6", 3) == 0)
		*guard_interval = wifi_guard_interval_1600;
	else if (strncmp(buf, "3.2", 3) == 0)
		*guard_interval = wifi_guard_interval_3200;
	else
		*guard_interval = wifi_guard_interval_auto;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setBSSColor(INT radio_index, UCHAR color)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params = {0};
	char config_file[128] = {0};
	char bss_color[4] ={0};
	int res;

	if (color < 1 || color > 63) {
		wifi_dbg_printf("color value is err:%d.\n", color);
		return RETURN_ERR;
	}
	params.name = "he_bss_color";
	res = snprintf(bss_color, sizeof(bss_color), "%hhu", color);
	if (os_snprintf_error(sizeof(bss_color), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.value = bss_color;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radio_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &params, 1);
	//wifi_hostapdProcessUpdate(radio_index, &params, 1);
	wifi_reloadAp(radio_index);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getBSSColor(INT radio_index, UCHAR *color)
{
	char config_file[128] = {0};
	char buf[64] = {0};
	char temp_output[128] = {'\0'};
	int res;

	wifi_dbg_printf("\nFunc=%s\n", __func__);
	if (NULL == color)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radio_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "he_bss_color", buf, sizeof(buf));

	if(strlen(buf) > 0) {
		res = snprintf(temp_output, sizeof(temp_output), "%s", buf);
	} else {
		res = snprintf(temp_output, sizeof(temp_output), "1");   // default value
	}
	if (os_snprintf_error(sizeof(temp_output), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	*color = (UCHAR)strtoul(temp_output, NULL, 10);
	wifi_dbg_printf("\noutput_string=%s\n", color);

	return RETURN_OK;
}

/* multi-psk support */
INT wifi_getMultiPskClientKey(INT apIndex, mac_address_t mac, wifi_key_multi_psk_t *key)
{
	char cmd[256];
	char interface_name[16] = {0};
	int res;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s sta %x:%x:%x:%x:%x:%x |grep '^keyid' | cut -f 2 -d = | tr -d '\n'",
		interface_name,
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5]
	);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	printf("DEBUG LOG wifi_getMultiPskClientKey(%s)\n",cmd);
	_syscmd(cmd, key->wifi_keyId, 64);


	return RETURN_OK;
}

INT wifi_pushMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber)
{
	char interface_name[16] = {0};
	FILE *fd	  = NULL;
	char fname[100];
	char cmd[128] = {0};
	char out[64] = {0};
	wifi_key_multi_psk_t * key = NULL;
	int res, ret;

	if(keysNumber < 0)
			return RETURN_ERR;

	res = snprintf(fname, sizeof(fname), "%s%d.psk", PSK_FILE, apIndex);
	if (os_snprintf_error(sizeof(fname), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fd = fopen(fname, "w");
	if (!fd) {
			return RETURN_ERR;
	}
	key= (wifi_key_multi_psk_t *) keys;
	for(int i=0; i<keysNumber; ++i, key++) {
		ret = fprintf(fd, "keyid=%s 00:00:00:00:00:00 %s\n", key->wifi_keyId, key->wifi_psk);
		if (ret < 0)
			wifi_debug(DEBUG_ERROR, "fprintf fail\n");
	}
	fclose(fd);

	//reload file
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s raw RELOAD_WPA_PSK", interface_name);

	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, out, 64);
	return RETURN_OK;
}

INT wifi_getMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber)
{
	FILE *fd	  = NULL;
	char fname[100];
	char * line = NULL;
	char * pos = NULL;
	size_t len = 0;
	ssize_t read = 0;
	INT ret = RETURN_OK;
	wifi_key_multi_psk_t *keys_it = NULL;
	int res;

	if (keysNumber < 1) {
		return RETURN_ERR;
	}

	res = snprintf(fname, sizeof(fname), "%s%d.psk", PSK_FILE, apIndex);
	if (os_snprintf_error(sizeof(fname), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	fd = fopen(fname, "r");
	if (!fd) {
		return RETURN_ERR;
	}

	if (keys == NULL) {
		ret = RETURN_ERR;
		goto close;
	}

	keys_it = keys;
	while ((read = getline(&line, &len, fd)) != -1) {
		//Strip trailing new line if present
		if (read > 0 && line[read-1] == '\n') {
			line[read-1] = '\0';
		}

		if(strcmp(line,"keyid=")) {
			sscanf(line, "keyid=%63s", keys_it->wifi_keyId);
			if (!(pos = index(line, ' '))) {
				ret = RETURN_ERR;
				goto close;
			}
			pos++;
			//Here should be 00:00:00:00:00:00
			if (!(strcmp(pos,"00:00:00:00:00:00"))) {
				 printf("Not supported MAC: %s\n", pos);
			}
			if (!(pos = index(pos, ' '))) {
				ret = RETURN_ERR;
				goto close;
			}
			pos++;

			//The rest is PSK
			res = snprintf(&keys_it->wifi_psk[0], sizeof(keys_it->wifi_psk), "%s", pos);
			if (os_snprintf_error(sizeof(keys_it->wifi_psk), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				fclose(fd);
				return RETURN_ERR;
			}

			keys_it++;

			if(--keysNumber <= 0)
		break;
		}
	}

close:
	free(line);
	fclose(fd);
	return ret;
}
/* end of multi-psk support */

INT wifi_setNeighborReports(UINT apIndex,
							 UINT numNeighborReports,
							 wifi_NeighborReport_t *neighborReports)
{
	char cmd[256] = { 0 };
	char hex_bssid[13] = { 0 };
	char bssid[18] = { 0 };
	char nr[100] = { 0 };
	char ssid[32];
	char hex_ssid[32];
	char interface_name[16] = {0};
	INT ret;
	int res;

	/*rmeove all neighbors*/
	wifi_dbg_printf("\n[%s]: removing all neighbors from %s\n", __func__, interface_name);
	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd),
		"hostapd_cli show_neighbor -i %s | awk '{print $1 \" \" $2}' | xargs -n2 -r hostapd_cli remove_neighbor -i %s",
		interface_name, interface_name);

	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	system(cmd);

	for(unsigned int i = 0; i < numNeighborReports; i++)
	{
		memset(ssid, 0, sizeof(ssid));
		ret = wifi_getSSIDName(apIndex, ssid);
		if (ret != RETURN_OK)
			return RETURN_ERR;

		memset(hex_ssid, 0, sizeof(hex_ssid));
		for(size_t j = 0,k = 0; ssid[j] != '\0' && k < sizeof(hex_ssid); j++,k+=2 )
			sprintf(hex_ssid + k,"%02x", ssid[j]);

		res = snprintf(hex_bssid, sizeof(hex_bssid),
				"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
				neighborReports[i].bssid[0], neighborReports[i].bssid[1], neighborReports[i].bssid[2], neighborReports[i].bssid[3], neighborReports[i].bssid[4], neighborReports[i].bssid[5]);
		if (os_snprintf_error(sizeof(hex_bssid), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		res = snprintf(bssid, sizeof(bssid),
				"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
				neighborReports[i].bssid[0], neighborReports[i].bssid[1], neighborReports[i].bssid[2], neighborReports[i].bssid[3], neighborReports[i].bssid[4], neighborReports[i].bssid[5]);
		if (os_snprintf_error(sizeof(bssid), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		res = snprintf(nr, sizeof(nr),
				"%s"									// bssid
				"%02hhx%02hhx%02hhx%02hhx"			  // bssid_info
				"%02hhx"								// operclass
				"%02hhx"								// channel
				"%02hhx",							   // phy_mode
				hex_bssid,
				neighborReports[i].info & 0xff, (neighborReports[i].info >> 8) & 0xff,
				(neighborReports[i].info >> 16) & 0xff, (neighborReports[i].info >> 24) & 0xff,
				neighborReports[i].opClass,
				neighborReports[i].channel,
				neighborReports[i].phyTable);
		if (os_snprintf_error(sizeof(nr), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		res = snprintf(cmd, sizeof(cmd),
				"hostapd_cli set_neighbor "
				"%s "						// bssid
				"ssid=%s "				   // ssid
				"nr=%s "					// nr
				"-i %s",
				bssid,hex_ssid,nr, interface_name);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		if (WEXITSTATUS(system(cmd)) != 0)
		{
			wifi_dbg_printf("\n[%s]: %s failed",__func__,cmd);
		}
	}

	return RETURN_OK;
}

INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
	return RETURN_OK;
}

#ifdef _WIFI_HAL_TEST_
int main(int argc,char **argv)
{
	int index;
	INT ret=0;
	char buf[1024]="";

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(argc<3)
	{
		if(argc==2)
		{
			if(!strcmp(argv[1], "init"))
				return wifi_init();
			if(!strcmp(argv[1], "reset"))
				return wifi_reset();
			if(!strcmp(argv[1], "wifi_getHalVersion"))
			{
				char buffer[64];
				if(wifi_getHalVersion(buffer)==RETURN_OK)
					printf("Version: %s\n", buffer);
				else
					printf("Error in wifi_getHalVersion\n");
				return RETURN_OK;
			}
		}
		printf("wifihal <API> <radioIndex> <arg1> <arg2> ...\n");
		exit(-1);
	}

	index = atoi(argv[2]);
	if(strstr(argv[1], "wifi_getApName")!=NULL)
	{
		wifi_getApName(index,buf);
		printf("Ap name is %s \n",buf);
		return 0;
	}
	if(strstr(argv[1], "wifi_setRadioMode")!=NULL)
	{
		UINT pureMode = atoi(argv[3]);

		wifi_setRadioMode(index, NULL, pureMode);
		printf("Ap SET Radio mode 0x%x\n", pureMode);
		return 0;
	}
	if (strstr(argv[1], "wifi_setRadioAutoBlockAckEnable") != NULL) {
		unsigned char enable = atoi(argv[3]);
		if (enable)
			wifi_setRadioAutoBlockAckEnable(index, TRUE);
		else
			wifi_setRadioAutoBlockAckEnable(index, FALSE);
		printf("%s handle wifi_setRadioAutoBlockAckEnable\n", __FUNCTION__);
	}
	if(strstr(argv[1], "wifi_setRadioTrafficStatsRadioStatisticsEnable")!=NULL)
	{
		wifi_setRadioTrafficStatsRadioStatisticsEnable(index, TRUE);
		printf("Ap SET wifi_setRadioTrafficStatsRadioStatisticsEnable\n");
		return 0;
	}
	if(strstr(argv[1], "wifi_setRadioTrafficStatsMeasure")!=NULL)
	{
		wifi_radioTrafficStatsMeasure_t input = {30, 200};

		wifi_setRadioTrafficStatsMeasure(index, &input);
		printf("Ap SET wifi_setRadioTrafficStatsMeasure\n");
		return 0;
	}
	if(strstr(argv[1], "wifi_setRadioTransmitPower")!=NULL)
	{
		ULONG TransmitPower = atoi(argv[3]);

		wifi_setRadioTransmitPower(index, TransmitPower);
		printf("Ap SET TransmitPower %lu\n", TransmitPower);
		return 0;
	}
	if(strstr(argv[1], "wifi_setApManagementFramePowerControl")!=NULL)
	{
		INT TransmitPower = atoi(argv[3]);

		wifi_setApManagementFramePowerControl(index, TransmitPower);
		printf("Ap SET Mgnt TransmitPower %d\n", TransmitPower);
		return 0;
	}
	if(strstr(argv[1], "wifi_setRadioBW")!=NULL)
	{
		CHAR *bandwith = argv[3];

		wifi_setRadioOperatingChannelBandwidth(index, bandwith);
		printf("Ap SET bw %s\n", bandwith);
		return 0;
	}
	if(strstr(argv[1], "wifi_factoryResetRadio")!=NULL)
	{
		wifi_factoryResetRadio(index);
		printf("wifi_factoryResetRadio ok!\n");
		return 0;
	}
	if(strstr(argv[1], "wifi_getRadioResetCount")!=NULL)
	{
		ULONG rst_cnt;
		wifi_getRadioResetCount(index, &rst_cnt);
		printf("wifi_factoryResetRadio rst_cnt = %lu\n", rst_cnt);
		return 0;
	}
	if (strncmp(argv[1], "wifi_addApAclDevice", strlen(argv[1])) == 0) {
		if(argc <= 3 )
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		wifi_addApAclDevice(index, argv[3]);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getApAclDevices", strlen(argv[1])) == 0) {
		wifi_getApAclDevices(index, buf, 1024);
		wifi_debug(DEBUG_NOTICE, "Ap acl Devices: %s\n", buf);
		return 0;
	}
	if (strncmp(argv[1], "wifi_delApAclDevice", strlen(argv[1])) == 0) {
		if(argc <= 3 )
		{
		   wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		wifi_delApAclDevice(index, argv[3]);
		return 0;
	}
	if (strncmp(argv[1], "wifi_delApAclDevices", strlen(argv[1])) == 0) {
		wifi_delApAclDevices(index);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getApAclDeviceNum", strlen(argv[1])) == 0) {
		UINT acl_num = 0;
		wifi_getApAclDeviceNum(index, &acl_num);
		wifi_debug(DEBUG_NOTICE, "Ap acl numbers: %d\n", acl_num);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getApDenyAclDevices", strlen(argv[1])) == 0) {
		wifi_getApDenyAclDevices(index, buf, 1024);
		wifi_debug(DEBUG_NOTICE, "Ap Deny Acl Devices: %s\n", buf);
		return 0;
	}
	if (strncmp(argv[1], "wifi_setApMacAddressControlMode", strlen(argv[1])) == 0) {
		int filter_mode = 0;
		if(argc <= 3 )
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		filter_mode = atoi(argv[3]);
		wifi_setApMacAddressControlMode(index,filter_mode);
		return 0;
	}
		if (strncmp(argv[1], "wifi_getRadioDeclineBARequestEnable", strlen(argv[1])) == 0) {
		BOOL output_bool = 0;
		wifi_getRadioDeclineBARequestEnable(index, &output_bool);
		wifi_debug(DEBUG_NOTICE, "Ap get radio ba decline enable: %d\n", output_bool);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getRadioAutoBlockAckEnable", strlen(argv[1])) == 0) {
		BOOL output_bool = 0;
		wifi_getRadioAutoBlockAckEnable(index, &output_bool);
		wifi_debug(DEBUG_NOTICE, "Ap get radio auto_ba enable: %d\n", output_bool);
		return 0;
	}

	if (strncmp(argv[1], "wifi_getApMacAddressControlMode", strlen(argv[1])) == 0) {
		int filter_mode = 0;
		wifi_getApMacAddressControlMode(index, &filter_mode);
		wifi_debug(DEBUG_NOTICE, "Ap MacAddress Control Mode: %d\n", filter_mode);
		return 0;
	}
	if (strncmp(argv[1], "wifi_setRadioIGMPSnoopingEnable", strlen(argv[1])) == 0) {
		int enable = 0;
		if(argc <= 3 )
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		enable = (BOOL)atoi(argv[3]);
		wifi_setRadioIGMPSnoopingEnable(index, enable);
		wifi_debug(DEBUG_NOTICE, "Ap set IGMP Snooping Enable: %d\n", enable);
		return 0;
	}
	if (strncmp(argv[1], "wifi_setRadioDCSEnable(", strlen(argv[1])) == 0) {
		int enable = 0;
		if(argc <= 3 )
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		enable = (BOOL)atoi(argv[3]);
		wifi_setRadioDCSEnable(index, enable);
		wifi_debug(DEBUG_NOTICE, "Ap set DCS Enable: %d\n", enable);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getRadioAutoChannelRefreshPeriod(", strlen(argv[1])) == 0) {
		ULONG period = 0;

		wifi_getRadioAutoChannelRefreshPeriod(index, &period);
		wifi_debug(DEBUG_NOTICE, "Get RefreshPeriod: %ld\n", period);
		return 0;
	}
	if (strncmp(argv[1], "wifi_setRadioDfsRefreshPeriod(", strlen(argv[1])) == 0) {
		ULONG period = 0;

		period = (ULONG)atoi(argv[3]);
		wifi_setRadioDfsRefreshPeriod(index, period);
		wifi_debug(DEBUG_NOTICE, "Set RefreshPeriod: %ld\n", period);
		return 0;
	}
	if (strncmp(argv[1], "wifi_setRadioDCSChannelPool(", strlen(argv[1])) == 0) {
		char pool[256] = {'\0'};

		strcpy(pool, argv[3]);
		wifi_setRadioDCSChannelPool(index, pool);
		wifi_debug(DEBUG_NOTICE, "Set DCSChannelPool: %s\n", pool);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getRadioDCSChannelPool(", strlen(argv[1])) == 0) {
		char pool[256] = {'\0'};

		wifi_getRadioDCSChannelPool(index, pool);
		wifi_debug(DEBUG_NOTICE, "Get DCSChannelPool: %s\n", pool);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getRadioIGMPSnoopingEnable", strlen(argv[1])) == 0) {
		BOOL out_status = 0;
		wifi_getRadioIGMPSnoopingEnable(index, &out_status);
		wifi_debug(DEBUG_NOTICE, "Ap get IGMP Snooping Enable: %d\n", out_status);
		return 0;
	}

	if (strncmp(argv[1], "wifi_setApWmmEnable", strlen(argv[1])) == 0) {
		int enable = 0;
		if(argc <= 3)
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		enable = atoi(argv[3]);
		wifi_setApWmmEnable(index,enable);
		return 0;
	}
	if (strncmp(argv[1], "wifi_pushSsidAdvertisementEnable", strlen(argv[1])) == 0) {
		int enable = 0;
		if(argc <= 3)
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		enable = atoi(argv[3]);
		wifi_pushSsidAdvertisementEnable(index,enable);
		return 0;
	}
	if (strncmp(argv[1], "wifi_down", strlen(argv[1])) == 0) {
		wifi_down();
		return 0;
	}

	if (strncmp(argv[1], "wifi_getRadioStatus", strlen(argv[1])) == 0) {
		BOOL enable = 0;

		wifi_getRadioStatus(index, &enable);
		wifi_debug(DEBUG_NOTICE, "wifi_getRadioStatus enable: %d\n", (int)enable);
		return 0;
	}

	if (strncmp(argv[1], "wifi_getApWMMCapability", strlen(argv[1])) == 0) {
		BOOL enable = 0;

		wifi_getApWMMCapability(index, &enable);
		wifi_debug(DEBUG_NOTICE, "wifi_getApWMMCapability enable: %d\n", (int)enable);
		return 0;
	}

	if (strncmp(argv[1], "wifi_getApWmmEnable", strlen(argv[1])) == 0) {
		BOOL enable = 0;

		wifi_getApWmmEnable(index, &enable);
		wifi_debug(DEBUG_NOTICE, "wifi_getApWmmEnable enable: %d\n", (int)enable);
		return 0;
	}

	if (strncmp(argv[1], "wifi_getApMacAddressControlMode", strlen(argv[1])) == 0) {
		int filter_mode = 0;
		wifi_getApMacAddressControlMode(index, &filter_mode);
		wifi_debug(DEBUG_NOTICE, "Ap MacAddress Control Mode: %d\n", filter_mode);
		return 0;
	}
	if(strstr(argv[1], "wifi_getRadioMode")!=NULL)
	{
		UINT mode = 0;

		wifi_getRadioMode(index, buf, &mode);
		printf("Ap Radio mode is %s , mode = 0x%x\n", buf, mode);
		return 0;
	}
	if(strstr(argv[1], "wifi_getRadioAutoChannelEnable")!=NULL)
	{
		BOOL b = FALSE;
		BOOL *output_bool = &b;
		wifi_getRadioAutoChannelEnable(index,output_bool);
		printf("Channel enabled = %d \n",b);
		return 0;
	}
	if(strstr(argv[1], "wifi_getApWpaEncryptionMode")!=NULL)
	{
		wifi_getApWpaEncryptionMode(index,buf);
		printf("encryption enabled = %s\n",buf);
		return 0;
	}
	if(strstr(argv[1], "wifi_getApSsidAdvertisementEnable")!=NULL)
	{
		BOOL b = FALSE;
		BOOL *output_bool = &b;
		wifi_getApSsidAdvertisementEnable(index,output_bool);
		printf("advertisment enabled =  %d\n",b);
		return 0;
	}
	if(strstr(argv[1],"wifi_getApAssociatedDeviceTidStatsResult")!=NULL)
	{
		if(argc <= 3 )
		{
			printf("Insufficient arguments \n");
			exit(-1);
		}

		char sta[20] = {'\0'};
		ULLONG handle= 0;
		strcpy(sta,argv[3]);
		mac_address_t st;
	mac_addr_aton(st,sta);

		wifi_associated_dev_tid_stats_t tid_stats;
		wifi_getApAssociatedDeviceTidStatsResult(index,&st,&tid_stats,&handle);
		for(int tid_index=0; tid_index<PS_MAX_TID; tid_index++) //print tid stats
			printf(" tid=%d \t ac=%d \t num_msdus=%lld \n" ,tid_stats.tid_array[tid_index].tid,tid_stats.tid_array[tid_index].ac,tid_stats.tid_array[tid_index].num_msdus);
	}

	if(strstr(argv[1], "getApEnable")!=NULL) {
		BOOL enable;
		ret=wifi_getApEnable(index, &enable);
		printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
	}
	else if(strstr(argv[1], "setApEnable")!=NULL) {
		BOOL enable = atoi(argv[3]);
		ret=wifi_setApEnable(index, enable);
		printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
	}
	else if(strstr(argv[1], "getApStatus")!=NULL) {
		char status[64];
		ret=wifi_getApStatus(index, status);
		printf("%s %d: %s, returns %d\n", argv[1], index, status, ret);
	}
	else if(strstr(argv[1], "wifi_getSSIDNameStatus")!=NULL)
	{
		wifi_getSSIDNameStatus(index,buf);
		printf("%s %d: active ssid : %s\n",argv[1], index,buf);
		return 0;
	} else if(strstr(argv[1], "wifi_resetApVlanCfg")!=NULL) {
		wifi_resetApVlanCfg(index);
		printf("%s %d: wifi_resetApVlanCfg : %s\n",argv[1], index,buf);
		return 0;
	}
	else if(strstr(argv[1], "getSSIDTrafficStats2")!=NULL) {
		wifi_ssidTrafficStats2_t stats={0};
		ret=wifi_getSSIDTrafficStats2(index, &stats); //Tr181
		printf("%s %d: returns %d\n", argv[1], index, ret);
		printf("	 ssid_BytesSent			 =%lu\n", stats.ssid_BytesSent);
		printf("	 ssid_BytesReceived		 =%lu\n", stats.ssid_BytesReceived);
		printf("	 ssid_PacketsSent		   =%lu\n", stats.ssid_PacketsSent);
		printf("	 ssid_PacketsReceived	   =%lu\n", stats.ssid_PacketsReceived);
		printf("	 ssid_RetransCount		  =%lu\n", stats.ssid_RetransCount);
		printf("	 ssid_FailedRetransCount	=%lu\n", stats.ssid_FailedRetransCount);
		printf("	 ssid_RetryCount			=%lu\n", stats.ssid_RetryCount);
		printf("	 ssid_MultipleRetryCount	=%lu\n", stats.ssid_MultipleRetryCount);
		printf("	 ssid_ACKFailureCount	   =%lu\n", stats.ssid_ACKFailureCount);
		printf("	 ssid_AggregatedPacketCount =%lu\n", stats.ssid_AggregatedPacketCount);
		printf("	 ssid_ErrorsSent			=%lu\n", stats.ssid_ErrorsSent);
		printf("	 ssid_ErrorsReceived		=%lu\n", stats.ssid_ErrorsReceived);
		printf("	 ssid_UnicastPacketsSent	=%lu\n", stats.ssid_UnicastPacketsSent);
		printf("	 ssid_UnicastPacketsReceived	=%lu\n", stats.ssid_UnicastPacketsReceived);
		printf("	 ssid_DiscardedPacketsSent	  =%lu\n", stats.ssid_DiscardedPacketsSent);
		printf("	 ssid_DiscardedPacketsReceived  =%lu\n", stats.ssid_DiscardedPacketsReceived);
		printf("	 ssid_MulticastPacketsSent	  =%lu\n", stats.ssid_MulticastPacketsSent);
		printf("	 ssid_MulticastPacketsReceived  =%lu\n", stats.ssid_MulticastPacketsReceived);
		printf("	 ssid_BroadcastPacketsSent	  =%lu\n", stats.ssid_BroadcastPacketsSent);
		printf("	 ssid_BroadcastPacketsRecevied  =%lu\n", stats.ssid_BroadcastPacketsRecevied);
		printf("	 ssid_UnknownPacketsReceived	=%lu\n", stats.ssid_UnknownPacketsReceived);
	}
	else if(strstr(argv[1], "getNeighboringWiFiDiagnosticResult2")!=NULL) {
		wifi_neighbor_ap2_t *neighbor_ap_array=NULL, *pt=NULL;
		UINT array_size=0;
		UINT i=0;
		ret=wifi_getNeighboringWiFiDiagnosticResult2(index, &neighbor_ap_array, &array_size);
		printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
		for(i=0, pt=neighbor_ap_array; i<array_size; i++, pt++) {
			printf("  neighbor %d:\n", i);
			printf("	 ap_SSID				=%s\n", pt->ap_SSID);
			printf("	 ap_BSSID			   =%s\n", pt->ap_BSSID);
			printf("	 ap_Mode				=%s\n", pt->ap_Mode);
			printf("	 ap_Channel			 =%d\n", pt->ap_Channel);
			printf("	 ap_SignalStrength	  =%d\n", pt->ap_SignalStrength);
			printf("	 ap_SecurityModeEnabled =%s\n", pt->ap_SecurityModeEnabled);
			printf("	 ap_EncryptionMode	  =%s\n", pt->ap_EncryptionMode);
			printf("	 ap_SupportedStandards  =%s\n", pt->ap_SupportedStandards);
			printf("	 ap_OperatingStandards  =%s\n", pt->ap_OperatingStandards);
			printf("	 ap_OperatingChannelBandwidth   =%s\n", pt->ap_OperatingChannelBandwidth);
			printf("	 ap_SecurityModeEnabled		 =%s\n", pt->ap_SecurityModeEnabled);
			printf("	 ap_BeaconPeriod				=%d\n", pt->ap_BeaconPeriod);
			printf("	 ap_Noise					   =%d\n", pt->ap_Noise);
			printf("	 ap_BasicDataTransferRates	  =%s\n", pt->ap_BasicDataTransferRates);
			printf("	 ap_SupportedDataTransferRates  =%s\n", pt->ap_SupportedDataTransferRates);
			printf("	 ap_DTIMPeriod				  =%d\n", pt->ap_DTIMPeriod);
			printf("	 ap_ChannelUtilization		  =%d\n", pt->ap_ChannelUtilization);
		}
		if(neighbor_ap_array)
			free(neighbor_ap_array); //make sure to free the list
	}
	else if(strstr(argv[1], "getApAssociatedDeviceDiagnosticResult")!=NULL) {
		wifi_associated_dev_t *associated_dev_array=NULL, *pt=NULL;
		UINT array_size=0;
		UINT i=0;
		ret=wifi_getApAssociatedDeviceDiagnosticResult(index, &associated_dev_array, &array_size);
		printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
		for(i=0, pt=associated_dev_array; i<array_size; i++, pt++) {
			printf("  associated_dev %d:\n", i);
			printf("	 cli_OperatingStandard	  =%s\n", pt->cli_OperatingStandard);
			printf("	 cli_OperatingChannelBandwidth  =%s\n", pt->cli_OperatingChannelBandwidth);
			printf("	 cli_SNR					=%d\n", pt->cli_SNR);
			printf("	 cli_InterferenceSources	=%s\n", pt->cli_InterferenceSources);
			printf("	 cli_DataFramesSentAck	  =%lu\n", pt->cli_DataFramesSentAck);
			printf("	 cli_DataFramesSentNoAck	=%lu\n", pt->cli_DataFramesSentNoAck);
			printf("	 cli_BytesSent			  =%lu\n", pt->cli_BytesSent);
			printf("	 cli_BytesReceived		  =%lu\n", pt->cli_BytesReceived);
			printf("	 cli_RSSI				   =%d\n", pt->cli_RSSI);
			printf("	 cli_MinRSSI				=%d\n", pt->cli_MinRSSI);
			printf("	 cli_MaxRSSI				=%d\n", pt->cli_MaxRSSI);
			printf("	 cli_Disassociations		=%d\n", pt->cli_Disassociations);
			printf("	 cli_AuthenticationFailures =%d\n", pt->cli_AuthenticationFailures);
		}
		if(associated_dev_array)
			free(associated_dev_array); //make sure to free the list
	}

	if(strstr(argv[1],"wifi_getRadioChannelStats")!=NULL)
	{
#define MAX_ARRAY_SIZE 64
		int i, array_size;
		char *p, *ch_str;
		wifi_channelStats_t input_output_channelStats_array[MAX_ARRAY_SIZE];

		if(argc != 5)
		{
			printf("Insufficient arguments, Usage: wifihal wifi_getRadioChannelStats <AP-Index> <Array-Size> <Comma-seperated-channel-numbers>\n");
			exit(-1);
		}
		memset(input_output_channelStats_array, 0, sizeof(input_output_channelStats_array));

		for (i=0, array_size=atoi(argv[3]), ch_str=argv[4]; i<array_size; i++, ch_str=p)
		{
			strtok_r(ch_str, ",", &p);
			input_output_channelStats_array[i].ch_number = atoi(ch_str);
		}
		wifi_getRadioChannelStats(atoi(argv[2]), input_output_channelStats_array, array_size);
		if(!array_size)
			array_size=1;//Need to print current channel statistics
		for(i=0; i<array_size; i++)
			printf("chan num = %d \t, noise =%d\t ch_utilization_busy_rx = %lld \t,\
					ch_utilization_busy_tx = %lld \t,ch_utilization_busy = %lld \t,\
					ch_utilization_busy_ext = %lld \t, ch_utilization_total = %lld \t \n",\
					input_output_channelStats_array[i].ch_number,\
					input_output_channelStats_array[i].ch_noise,\
					input_output_channelStats_array[i].ch_utilization_busy_rx,\
					input_output_channelStats_array[i].ch_utilization_busy_tx,\
					input_output_channelStats_array[i].ch_utilization_busy,\
					input_output_channelStats_array[i].ch_utilization_busy_ext,\
					input_output_channelStats_array[i].ch_utilization_total);
	}

	if(strstr(argv[1],"wifi_getAssociatedDeviceDetail")!=NULL)
	{
		if(argc <= 3 )
		{
			printf("Insufficient arguments \n");
			exit(-1);
		}
		char mac_addr[20] = {'\0'};
		wifi_device_t output_struct;
		int dev_index = atoi(argv[3]);

		wifi_getAssociatedDeviceDetail(index,dev_index,&output_struct);
		mac_addr_ntoa(mac_addr,output_struct.wifi_devMacAddress);
		printf("wifi_devMacAddress=%s \t wifi_devAssociatedDeviceAuthentiationState=%d \t, wifi_devSignalStrength=%d \t,wifi_devTxRate=%d \t, wifi_devRxRate =%d \t\n ", mac_addr,output_struct.wifi_devAssociatedDeviceAuthentiationState,output_struct.wifi_devSignalStrength,output_struct.wifi_devTxRate,output_struct.wifi_devRxRate);
	}

	if(strstr(argv[1],"wifi_setNeighborReports")!=NULL)
	{
		if (argc <= 3)
		{
			printf("Insufficient arguments\n");
			exit(-1);
		}
		char args[256];
		wifi_NeighborReport_t *neighborReports;

		neighborReports = calloc(argc - 2, sizeof(neighborReports));
		if (!neighborReports)
		{
			printf("Failed to allocate memory");
			exit(-1);
		}

		for (int i = 3; i < argc; ++i)
		{
			char *val;
			int j = 0;
			memset(args, 0, sizeof(args));
			strncpy(args, argv[i], sizeof(args));
			val = strtok(args, ";");
			while (val != NULL)
			{
				if (j == 0)
				{
					mac_addr_aton(neighborReports[i - 3].bssid, val);
				} else if (j == 1)
				{
					neighborReports[i - 3].info = strtol(val, NULL, 16);
				} else if (j == 2)
				{
					neighborReports[i - 3].opClass = strtol(val, NULL, 16);
				} else if (j == 3)
				{
					neighborReports[i - 3].channel = strtol(val, NULL, 16);
				} else if (j == 4)
				{
					neighborReports[i - 3].phyTable = strtol(val, NULL, 16);
				} else {
					printf("Insufficient arguments]n\n");
					exit(-1);
				}
				val = strtok(NULL, ";");
				j++;
			}
		}

		INT ret = wifi_setNeighborReports(index, argc - 3, neighborReports);
		if (ret != RETURN_OK)
		{
			printf("wifi_setNeighborReports ret = %d", ret);
			exit(-1);
		}
	}
	if(strstr(argv[1],"wifi_getRadioIfName")!=NULL)
	{
		if((ret=wifi_getRadioIfName(index, buf))==RETURN_OK)
			printf("%s.\n", buf);
		else
			printf("Error returned\n");
	}
	if(strstr(argv[1],"wifi_getApSecurityModesSupported")!=NULL)
	{
		if((ret=wifi_getApSecurityModesSupported(index, buf))==RETURN_OK)
			printf("%s.\n", buf);
		else
			printf("Error returned\n");
	}
	if(strstr(argv[1],"wifi_getRadioOperatingChannelBandwidth")!=NULL)
	{
		if (argc <= 2)
		{
			printf("Insufficient arguments\n");
			exit(-1);
		}
		char buf[64]= {'\0'};
		wifi_getRadioOperatingChannelBandwidth(index,buf);
		printf("Current bandwidth is %s \n",buf);
		return 0;
	}
	if(strstr(argv[1],"pushRadioChannel2")!=NULL)
	{
		if (argc <= 5)
		{
			printf("Insufficient arguments\n");
			exit(-1);
		}
		UINT channel = atoi(argv[3]);
		UINT width = atoi(argv[4]);
		UINT beacon = atoi(argv[5]);
		INT ret = wifi_pushRadioChannel2(index,channel,width,beacon);
		printf("Result = %d", ret);
	}
	if(strstr(argv[1],"wifi_getApBridgeInfo")!=NULL)
	{
		char br_name[64], ip[64], subset[64] = {0};
		wifi_getApBridgeInfo(0, br_name, ip, subset);
		printf("wifi_getApBridgeInfo br_name = %s, ip = %s, subset = %s\n", br_name, ip, subset);
	}
	if(strstr(argv[1],"wifi_enableGreylistAccessControl")!=NULL)
	{
		int enable = atoi(argv[3]);
		wifi_enableGreylistAccessControl(enable == 0 ? FALSE : TRUE);
		printf("wifi_enableGreylistAccessControl enable=%d\n", enable);
	}
	if(strstr(argv[1],"wifi_setApBridgeInfo")!=NULL)
	{
		wifi_setApBridgeInfo(0, argv[3], argv[4], argv[5]);
		printf("wifi_setApBridgeInfo br_name = %s, ip = %s, subset = %s\n", argv[3], argv[4], argv[5]);
	}

	if(strstr(argv[1], "wifi_getATMCapable")!=NULL)
    {
        BOOL b = FALSE;
        BOOL *output_bool = &b;
        wifi_getATMCapable(output_bool);
        printf("ATM capable = %d \n",b);
        return 0;
    }
	if (strncmp(argv[1], "wifi_setATMEnable", strlen(argv[1])) == 0) {
		int enable = 0;
		if(argc <= 3)
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		enable = atoi(argv[3]);
		wifi_setATMEnable(enable);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getATMEnable", strlen(argv[1])) == 0) {
		BOOL b = FALSE;
        BOOL *output_bool = &b;
		wifi_getATMEnable(output_bool);
		printf("ATM enable = %d \n", b);
		return 0;
	}
	if (strncmp(argv[1], "wifi_setApATMAirTimePercent", strlen(argv[1])) == 0) {
		unsigned int percent = 0;
		if(argc <= 3)
		{
			wifi_debug(DEBUG_ERROR, "Insufficient arguments \n");
			exit(-1);
		}
		percent = atoi(argv[3]);
		wifi_setApATMAirTimePercent(index, percent);
		return 0;
	}
	if (strncmp(argv[1], "wifi_getApATMAirTimePercent", strlen(argv[1])) == 0) {
		unsigned int percent = 0;
		unsigned int *output = &percent;

		wifi_getApATMAirTimePercent(index, output);
		printf("ATM percent = %d \n", percent);
		return 0;
	}
	if (strstr(argv[1],"setGF")!=NULL)
	{
		BOOL enable = atoi(argv[3]);
		if((ret=wifi_setRadio11nGreenfieldEnable(index, enable))==RETURN_OK)
			printf("wifi_setRadio11nGreenfieldEnable success\n");
		else
			printf("wifi_setRadio11nGreenfieldEnable Error\n");
	}
	if (strstr(argv[1],"setVID")!=NULL)
	{
		INT vid = atoi(argv[3]);
		if((ret=wifi_setApVlanID(index, vid))==RETURN_OK)
			printf("wifi_setApVlanID success.\n");
		else
			printf("wifi_setApVlanID Error\n");
	}	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return 0;
}

#endif

#ifdef WIFI_HAL_VERSION_3

INT BitMapToTransmitRates(UINT bitMap, char *BasicRate, unsigned long size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (bitMap & WIFI_BITRATE_1MBPS) {
		if ((size - strlen(BasicRate)) <= 2)
			return RETURN_ERR;
		strncat(BasicRate, "1,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_2MBPS) {
		if ((size - strlen(BasicRate)) <= 2)
			return RETURN_ERR;
		strncat(BasicRate, "2,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_5_5MBPS) {
		if ((size - strlen(BasicRate)) <= 4)
			return RETURN_ERR;
		strncat(BasicRate, "5.5,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_6MBPS) {
		if ((size - strlen(BasicRate)) <= 2)
			return RETURN_ERR;
		strncat(BasicRate, "6,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_9MBPS) {
		if ((size - strlen(BasicRate)) <= 2)
			return RETURN_ERR;
		strncat(BasicRate, "9,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_11MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "11,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_12MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "12,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_18MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "18,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_24MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "24,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_36MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "36,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_48MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "48,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (bitMap & WIFI_BITRATE_54MBPS) {
		if ((size - strlen(BasicRate)) <= 3)
			return RETURN_ERR;
		strncat(BasicRate, "54,", sizeof(BasicRate) - strlen(BasicRate) - 1);
	}
	if (strlen(BasicRate) != 0)	 // remove last comma
		BasicRate[strlen(BasicRate) - 1] = '\0';
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT TransmitRatesToBitMap (char *BasicRatesList, UINT *basicRateBitMap)
{
	UINT BitMap = 0;
	char *rate;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	rate = strtok(BasicRatesList, ",");
	while(rate != NULL)
	{
		if (strcmp(rate, "1") == 0)
			BitMap |= WIFI_BITRATE_1MBPS;
		else if (strcmp(rate, "2") == 0)
			BitMap |= WIFI_BITRATE_2MBPS;
		else if (strcmp(rate, "5.5") == 0)
			BitMap |= WIFI_BITRATE_5_5MBPS;
		else if (strcmp(rate, "6") == 0)
			BitMap |= WIFI_BITRATE_6MBPS;
		else if (strcmp(rate, "9") == 0)
			BitMap |= WIFI_BITRATE_9MBPS;
		else if (strcmp(rate, "11") == 0)
			BitMap |= WIFI_BITRATE_11MBPS;
		else if (strcmp(rate, "12") == 0)
			BitMap |= WIFI_BITRATE_12MBPS;
		else if (strcmp(rate, "18") == 0)
			BitMap |= WIFI_BITRATE_18MBPS;
		else if (strcmp(rate, "24") == 0)
			BitMap |= WIFI_BITRATE_24MBPS;
		else if (strcmp(rate, "36") == 0)
			BitMap |= WIFI_BITRATE_36MBPS;
		else if (strcmp(rate, "48") == 0)
			BitMap |= WIFI_BITRATE_48MBPS;
		else if (strcmp(rate, "54") == 0)
			BitMap |= WIFI_BITRATE_54MBPS;
		rate = strtok(NULL, ",");
	}
	*basicRateBitMap = BitMap;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// This API is used to configured all radio operation parameter in a single set. it includes channel number, channelWidth, mode and auto chammel configuration.
INT wifi_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
	char buf[128] = {0};
	int bandwidth = 20;
	int set_mode = 0;
	BOOL drv_dat_change = 0, hapd_conf_change = 0;
	wifi_radio_operationParam_t current_param;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	multiple_set = TRUE;
	if (wifi_getRadioOperatingParameters(index, &current_param) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioOperatingParameters return error.\n");
		return RETURN_ERR;
	}
	if (current_param.autoChannelEnabled != operationParam->autoChannelEnabled) {
		if (wifi_setRadioAutoChannelEnable(index, operationParam->autoChannelEnabled) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioAutoChannelEnable return error.\n");
			return RETURN_ERR;
		}
		drv_dat_change = TRUE;
	}
	if (current_param.channelWidth != operationParam->channelWidth ||
		current_param.channel != operationParam->channel ||
		current_param.autoChannelEnabled != operationParam->autoChannelEnabled) {
		if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_20MHZ)
			bandwidth = 20;
		else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
			bandwidth = 40;
		else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_80MHZ)
			bandwidth = 80;
		else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ || operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_80_80MHZ)
			bandwidth = 160;

		if (operationParam->autoChannelEnabled) {
			if (wifi_pushRadioChannel2(index, 0, bandwidth, operationParam->csa_beacon_count) != RETURN_OK) {
				wifi_debug(DEBUG_ERROR, "wifi_pushRadioChannel2 return error.\n");
				return RETURN_ERR;
			}
		} else {
			if (wifi_pushRadioChannel2(index, operationParam->channel, bandwidth, operationParam->csa_beacon_count) != RETURN_OK) {
				wifi_debug(DEBUG_ERROR, "wifi_pushRadioChannel2 return error.\n");
				return RETURN_ERR;
			}
		}
		drv_dat_change = TRUE;
	}
	if (current_param.variant != operationParam->variant) {
		// Two different definition bit map, so need to check every bit.
		if (operationParam->variant & WIFI_80211_VARIANT_A)
			set_mode |= WIFI_MODE_A;
		if (operationParam->variant & WIFI_80211_VARIANT_B)
			set_mode |= WIFI_MODE_B;
		if (operationParam->variant & WIFI_80211_VARIANT_G)
			set_mode |= WIFI_MODE_G;
		if (operationParam->variant & WIFI_80211_VARIANT_N)
			set_mode |= WIFI_MODE_N;
		if (operationParam->variant & WIFI_80211_VARIANT_AC)
			set_mode |= WIFI_MODE_AC;
		if (operationParam->variant & WIFI_80211_VARIANT_AX)
			set_mode |= WIFI_MODE_AX;
		// Second parameter is to set channel band width, it is done by wifi_pushRadioChannel2 if changed.
		memset(buf, 0, sizeof(buf));
		drv_dat_change = TRUE;
		if (wifi_setRadioMode_by_dat(index, set_mode) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioMode return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.dtimPeriod != operationParam->dtimPeriod) {
		hapd_conf_change = TRUE;
		if (wifi_setApDTIMInterval(index, operationParam->dtimPeriod) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setApDTIMInterval return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.beaconInterval != operationParam->beaconInterval) {
		hapd_conf_change = TRUE;
		if (wifi_setRadioBeaconPeriod(index, operationParam->beaconInterval) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioBeaconPeriod return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.operationalDataTransmitRates != operationParam->operationalDataTransmitRates) {
		hapd_conf_change = TRUE;
		BitMapToTransmitRates(operationParam->operationalDataTransmitRates, buf, sizeof(buf));
		if (wifi_setRadioBasicDataTransmitRates(index, buf) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioBasicDataTransmitRates return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.fragmentationThreshold != operationParam->fragmentationThreshold) {
		hapd_conf_change = TRUE;
		if (wifi_setRadioFragmentationThreshold(index, operationParam->fragmentationThreshold) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioFragmentationThreshold return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.guardInterval != operationParam->guardInterval) {
		hapd_conf_change = TRUE;
		drv_dat_change = TRUE;
		if (wifi_setGuardInterval(index, operationParam->guardInterval) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setGuardInterval return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.transmitPower != operationParam->transmitPower) {
		drv_dat_change = TRUE;
		if (wifi_setRadioTransmitPower(index, operationParam->transmitPower) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioTransmitPower return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.rtsThreshold != operationParam->rtsThreshold) {
		hapd_conf_change = TRUE;
		if (wifi_setApRtsThreshold(index, operationParam->rtsThreshold) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setApRtsThreshold return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.obssCoex != operationParam->obssCoex) {
		hapd_conf_change = TRUE;
		if (wifi_setRadioObssCoexistenceEnable(index, operationParam->obssCoex) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioObssCoexistenceEnable return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.stbcEnable != operationParam->stbcEnable) {
		hapd_conf_change = TRUE;
		drv_dat_change = TRUE;
		if (wifi_setRadioSTBCEnable(index, operationParam->stbcEnable) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadioSTBCEnable return error.\n");
			return RETURN_ERR;
		}
	}
	if (current_param.greenFieldEnable != operationParam->greenFieldEnable) {
		if (wifi_setRadio11nGreenfieldEnable(index, operationParam->greenFieldEnable) != RETURN_OK) {
			wifi_debug(DEBUG_ERROR, "wifi_setRadio11nGreenfieldEnable return error.\n");
			return RETURN_ERR;
		}
	}

	/* only down/up interface when dat file has been changed,
	 * if enable is true, then restart the radio.
	 */
	if (drv_dat_change == TRUE) {
		wifi_setRadioEnable(index, FALSE);
		if (operationParam->enable == TRUE)
			wifi_setRadioEnable(index, TRUE);
	} else if (hapd_conf_change == TRUE) {
		hostapd_raw_remove_bss(index);
		if (operationParam->enable == TRUE)
			hostapd_raw_add_bss(index);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
	char band[64] = {0};
	char buf[256] = {0};
	char config_file[64] = {0};
	char cmd[128] = {0};
	UINT mode = 0;
	BOOL enabled = FALSE;
	int dtimPeriod;
	UINT beaconInterval;
	UINT basicDataTransmitRates;
	UINT operationalDataTransmitRates;
	wifi_guard_interval_t guardInterval;
	UINT transmitPower;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	printf("Entering %s index = %d\n", __func__, (int)index);

	memset(operationParam, 0, sizeof(wifi_radio_operationParam_t));
	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if (wifi_getRadioEnable(index, &enabled) != RETURN_OK)
	{
		wifi_debug(DEBUG_ERROR, "wifi_getRadioEnable return error.\n");
		return RETURN_ERR;
	}
	operationParam->enable = enabled;

	memset(band, 0, sizeof(band));
	if (wifi_getRadioOperatingFrequencyBand(index, band) != RETURN_OK)
	{
		wifi_debug(DEBUG_ERROR, "wifi_getRadioOperatingFrequencyBand return error.\n");
		return RETURN_ERR;
	}

	if (!strcmp(band, "2.4GHz"))
		operationParam->band = WIFI_FREQUENCY_2_4_BAND;
	else if (!strcmp(band, "5GHz"))
		operationParam->band = WIFI_FREQUENCY_5_BAND;
	else if (!strcmp(band, "6GHz"))
		operationParam->band = WIFI_FREQUENCY_6_BAND;
	else
	{
		wifi_debug(DEBUG_ERROR, "cannot decode band for radio index %d ('%s')\n", index, band);
	}

	wifi_hostapdRead(config_file, "channel", buf, sizeof(buf));
	if (strcmp(buf, "0") == 0 || strcmp(buf, "acs_survey") == 0) {
		operationParam->channel = 0;
		operationParam->autoChannelEnabled = TRUE;
	} else {
		operationParam->channel = strtol(buf, NULL, 10);
		operationParam->autoChannelEnabled = FALSE;
	}

	memset(buf, 0, sizeof(buf));
	if (wifi_getRadioOperatingChannelBandwidth(index, buf) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioOperatingChannelBandwidth return error.\n");
		return RETURN_ERR;
	}
	if (!strcmp(buf, "20MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
	else if (!strcmp(buf, "40MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_40MHZ;
	else if (!strcmp(buf, "80MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
	else if (!strcmp(buf, "160MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
	else
	{
		wifi_debug(DEBUG_ERROR, "Unknown channel bandwidth: %s\n", buf);
		return false;
	}

	if (wifi_getRadioMode(index, buf, &mode) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioMode return error.\n");
		return RETURN_ERR;
	}
	// Two different definition bit map, so need to check every bit.
	if (mode & WIFI_MODE_A)
		operationParam->variant |= WIFI_80211_VARIANT_A;
	if (mode & WIFI_MODE_B)
		operationParam->variant |= WIFI_80211_VARIANT_B;
	if (mode & WIFI_MODE_G)
		operationParam->variant |= WIFI_80211_VARIANT_G;
	if (mode & WIFI_MODE_N)
		operationParam->variant |= WIFI_80211_VARIANT_N;
	if (mode & WIFI_MODE_AC)
		operationParam->variant |= WIFI_80211_VARIANT_AC;
	if (mode & WIFI_MODE_AX)
		operationParam->variant |= WIFI_80211_VARIANT_AX;
	if (wifi_getRadioDCSEnable(index, &operationParam->DCSEnabled) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioDCSEnable return error.\n");
		return RETURN_ERR;
	}
	if (wifi_getApDTIMInterval(index, &dtimPeriod) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getApDTIMInterval return error.\n");
		return RETURN_ERR;
	}
	operationParam->dtimPeriod = dtimPeriod;
	if (wifi_getRadioBeaconPeriod(index, &beaconInterval) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioBeaconPeriod return error.\n");
		return RETURN_ERR;
	}
	operationParam->beaconInterval = beaconInterval;

	memset(buf, 0, sizeof(buf));
	if (wifi_getRadioSupportedDataTransmitRates(index, buf) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioSupportedDataTransmitRates return error.\n");
		return RETURN_ERR;
	}
	TransmitRatesToBitMap(buf, &basicDataTransmitRates);
	operationParam->basicDataTransmitRates = basicDataTransmitRates;

	memset(buf, 0, sizeof(buf));
	if (wifi_getRadioBasicDataTransmitRates(index, buf) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioBasicDataTransmitRates return error.\n");
		return RETURN_ERR;
	}
	TransmitRatesToBitMap(buf, &operationalDataTransmitRates);
	operationParam->operationalDataTransmitRates = operationalDataTransmitRates;

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "fragm_threshold", buf, sizeof(buf));
	operationParam->fragmentationThreshold = strtoul(buf, NULL, 10);

	if (wifi_getGuardInterval(index, &guardInterval) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getGuardInterval return error.\n");
		return RETURN_ERR;
	}
	operationParam->guardInterval = guardInterval;

	if (wifi_getRadioPercentageTransmitPower(index, (ULONG *)&transmitPower) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadioPercentageTransmitPower return error.\n");
		return RETURN_ERR;
	}
	operationParam->transmitPower = transmitPower;

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "rts_threshold", buf, sizeof(buf));
	if (strcmp(buf, "-1") == 0) {
		operationParam->rtsThreshold = (UINT)-1;	// maxuimum unsigned integer value
		operationParam->ctsProtection = FALSE;
	} else {
		operationParam->rtsThreshold = strtoul(buf, NULL, 10);
		operationParam->ctsProtection = TRUE;
	}

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "ht_coex", buf, sizeof(buf));
	if (strcmp(buf, "0") == 0)
		operationParam->obssCoex = FALSE;
	else
		operationParam->obssCoex = TRUE;

	res = snprintf(cmd, sizeof(cmd), "cat %s | grep STBC", config_file);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) != 0)
		operationParam->stbcEnable = TRUE;
	else
		operationParam->stbcEnable = FALSE;

	if (wifi_getRadio11nGreenfieldEnable(index, &operationParam->greenFieldEnable) != RETURN_OK) {
		wifi_debug(DEBUG_ERROR, "wifi_getRadio11nGreenfieldEnable return error.\n");
		return RETURN_ERR;
	}

	// Below value is hardcoded

	operationParam->numSecondaryChannels = 0;
	for (int i = 0; i < MAXNUMSECONDARYCHANNELS; i++) {
		operationParam->channelSecondary[i] = 0;
	}
	operationParam->csa_beacon_count = 15;
	operationParam->countryCode = wifi_countrycode_US;  // hard to convert string to corresponding enum

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

static int array_index_to_vap_index(UINT radioIndex, int arrayIndex)
{
	int max_radio_num = 0;

	wifi_getMaxRadioNumber(&max_radio_num);
	if (radioIndex >= max_radio_num) {
		wifi_debug(DEBUG_ERROR, "Wrong radio index (%d)\n", radioIndex);
		return RETURN_ERR;
	}

	return (arrayIndex * max_radio_num) + radioIndex;
}

static int vap_index_to_array_index(int vapIndex, int *radioIndex, int *arrayIndex)
{
	int max_radio_num = 0;

	if ((vapIndex < 0) || (vapIndex >  MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS))
	return -1;

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	(*radioIndex) = vapIndex % max_radio_num;
	(*arrayIndex) = vapIndex / max_radio_num;

	return 0;
}


wifi_bitrate_t beaconRate_string_to_enum(char *beaconRate) {
	if (strncmp(beaconRate, "1Mbps", 5) == 0)
		return WIFI_BITRATE_1MBPS;
	else if (strncmp(beaconRate, "2Mbps", 5) == 0)
		return WIFI_BITRATE_2MBPS;
	else if (strncmp(beaconRate, "5.5Mbps", 7) == 0)
		return WIFI_BITRATE_5_5MBPS;
	else if (strncmp(beaconRate, "6Mbps", 5) == 0)
		return WIFI_BITRATE_6MBPS;
	else if (strncmp(beaconRate, "9Mbps", 5) == 0)
		return WIFI_BITRATE_9MBPS;
	else if (strncmp(beaconRate, "11Mbps", 6) == 0)
		return WIFI_BITRATE_11MBPS;
	else if (strncmp(beaconRate, "12Mbps", 6) == 0)
		return WIFI_BITRATE_12MBPS;
	else if (strncmp(beaconRate, "18Mbps", 6) == 0)
		return WIFI_BITRATE_18MBPS;
	else if (strncmp(beaconRate, "24Mbps", 6) == 0)
		return WIFI_BITRATE_24MBPS;
	else if (strncmp(beaconRate, "36Mbps", 6) == 0)
		return WIFI_BITRATE_36MBPS;
	else if (strncmp(beaconRate, "48Mbps", 6) == 0)
		return WIFI_BITRATE_48MBPS;
	else if (strncmp(beaconRate, "54Mbps", 6) == 0)
		return WIFI_BITRATE_54MBPS;
	return WIFI_BITRATE_DEFAULT;
}

struct beacon_rate_2_string {
	wifi_bitrate_t beacon;
	char beacon_str[8];
};

struct beacon_rate_2_string br2str[12] = {
	{WIFI_BITRATE_1MBPS, "1Mbps"},
	{WIFI_BITRATE_2MBPS, "2Mbps"},
	{WIFI_BITRATE_5_5MBPS, "5.5Mbps"},
	{WIFI_BITRATE_6MBPS, "6Mbps"},
	{WIFI_BITRATE_9MBPS, "9Mbps"},
	{WIFI_BITRATE_11MBPS, "11Mbps"},
	{WIFI_BITRATE_12MBPS, "12Mbps"},
	{WIFI_BITRATE_18MBPS, "18Mbps"},
	{WIFI_BITRATE_24MBPS, "24Mbps"},
	{WIFI_BITRATE_36MBPS, "36Mbps"},
	{WIFI_BITRATE_48MBPS, "48Mbps"},
	{WIFI_BITRATE_54MBPS, "54Mbps"}
};

INT beaconRate_enum_to_string(wifi_bitrate_t beacon, char *beacon_str, unsigned long str_size)
{
	int i;
	unsigned long len;

	for (i = 0; i < (sizeof(br2str)/sizeof(br2str[0])); i++) {
		if (beacon == br2str[i].beacon) {
			len = strlen(br2str[i].beacon_str);
			if (len >= str_size)
				return RETURN_ERR;
			memcpy(beacon_str, br2str[i].beacon_str, len);
			beacon_str[len] = '\0';
			break;
		}
	}
	return RETURN_OK;
}

INT wifi_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
	INT mode = 0;
	INT ret = -1;
	UINT output = 0;
	int i = 0;
	int vap_index = 0;
	BOOL enabled = FALSE;
	char buf[32] = {0};
	wifi_vap_security_t security = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	printf("Entering %s index = %d\n", __func__, (int)index);

	ret = wifi_BandProfileRead(0, index, "BssidNum", buf, sizeof(buf), "0");
	if (ret != 0) {
		wifi_debug(DEBUG_ERROR, "wifi_BandProfileRead BssidNum failed\n");
		return RETURN_ERR;
	}

	map->num_vaps = atoi(buf);
	if (map->num_vaps <= 0)  {
		wifi_debug(DEBUG_ERROR, "invalid BssidNum %s\n", buf);
		return RETURN_ERR;
	}

	for (i = 0; i < map->num_vaps; i++)
	{
		map->vap_array[i].radio_index = index;

		vap_index = array_index_to_vap_index(index, i);
		if (vap_index < 0)
			return RETURN_ERR;

		strncpy(map->vap_array[i].bridge_name, BRIDGE_NAME,sizeof(map->vap_array[i].bridge_name) - 1);
		map->vap_array[i].bridge_name[sizeof(map->vap_array[i].bridge_name) - 1] = '\0';

		map->vap_array[i].vap_index = vap_index;

		memset(buf, 0, sizeof(buf));
		ret = wifi_getApName(vap_index, buf);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApName return error\n", __func__);
			return RETURN_ERR;
		}
		res = snprintf(map->vap_array[i].vap_name, sizeof(map->vap_array[i].vap_name), "%s", buf);
		if (os_snprintf_error(sizeof(map->vap_array[i].vap_name), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		memset(buf, 0, sizeof(buf));
		ret = wifi_getSSIDName(vap_index, buf);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getSSIDName return error\n", __func__);
			return RETURN_ERR;
		}
		res = snprintf(map->vap_array[i].u.bss_info.ssid, sizeof(map->vap_array[i].u.bss_info.ssid), "%s", buf);
		if (os_snprintf_error(sizeof(map->vap_array[i].u.bss_info.ssid), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}

		map->vap_array[i].u.bss_info.enabled = true;

		ret = wifi_getApSsidAdvertisementEnable(vap_index, &enabled);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApSsidAdvertisementEnable return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.showSsid = enabled;

		ret = wifi_getApIsolationEnable(vap_index, &enabled);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApIsolationEnable return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.isolation = enabled;

		ret = wifi_getApMaxAssociatedDevices(vap_index, &output);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApMaxAssociatedDevices return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.bssMaxSta = output;

		ret = wifi_getBSSTransitionActivation(vap_index, &enabled);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getBSSTransitionActivation return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.bssTransitionActivated = enabled;

		ret = wifi_getNeighborReportActivation(vap_index, &enabled);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getNeighborReportActivation return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.nbrReportActivated = enabled;

		ret = wifi_getApSecurity(vap_index, &security);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApSecurity return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.security = security;

		ret = wifi_getApMacAddressControlMode(vap_index, &mode);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApMacAddressControlMode return error\n", __func__);
			return RETURN_ERR;
		}
		if (mode == 0)
			map->vap_array[i].u.bss_info.mac_filter_enable = FALSE;
		else
			map->vap_array[i].u.bss_info.mac_filter_enable = TRUE;
		if (mode == 1)
			map->vap_array[i].u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
		else if (mode == 2)
			map->vap_array[i].u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;

		ret = wifi_getApWmmEnable(vap_index, &enabled);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApWmmEnable return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.wmm_enabled = enabled;

		ret = wifi_getApUAPSDCapability(vap_index, &enabled);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApUAPSDCapability return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.UAPSDEnabled = enabled;

		memset(buf, 0, sizeof(buf));
		ret = wifi_getApBeaconRate(map->vap_array[i].radio_index, buf);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getApBeaconRate return error\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.beaconRate = beaconRate_string_to_enum(buf);

		memset(buf, 0, sizeof(buf));
		ret = wifi_getBaseBSSID(vap_index, buf);
		if (ret != RETURN_OK) {
			printf("%s: wifi_getBaseBSSID return error\n", __func__);
			return RETURN_ERR;
		}
		if (hwaddr_aton2(buf, map->vap_array[i].u.bss_info.bssid) < 0) {
			printf("%s: hwaddr_aton2 fail\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_getRadioIGMPSnoopingEnable(map->vap_array[i].radio_index, &enabled);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_getRadioIGMPSnoopingEnable\n", __func__);
			return RETURN_ERR;
		}
		map->vap_array[i].u.bss_info.mcast2ucast = enabled;

		// TODO: wps, noack
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

void checkVapStatus(int apIndex, BOOL *enable)
{
	char if_name[16] = {0};
	char cmd[128] = {0};
	char buf[128] = {0};
	int res;

	*enable = FALSE;
	if (wifi_GetInterfaceName(apIndex, if_name) != RETURN_OK)
		return;

	res = snprintf(cmd, sizeof(cmd), "cat %s | grep ^%s=1", VAP_STATUS_FILE, if_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return;
	}
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0)
		*enable = TRUE;
	return;
}

int hostapd_manage_bss(INT apIndex, BOOL enable)
{
	char interface_name[16] = {0};
	char config_file[MAX_SUB_CMD_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	BOOL status = FALSE;
	int  max_radio_num = 0;
	int phyId = 0;
	int res;

	wifi_getApEnable(apIndex, &status);

	wifi_getMaxRadioNumber(&max_radio_num);
	if (enable == status)
		return RETURN_OK;

	if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
		return RETURN_ERR;

	if (enable == TRUE) {
		int radioIndex = apIndex % max_radio_num;
		phyId = radio_index_to_phy(radioIndex);
		fprintf(stderr, "%s %d\n", __func__, __LINE__);
		res = snprintf(config_file, MAX_BUF_SIZE, "%s%d.conf", CONFIG_PREFIX, apIndex);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		res = snprintf(cmd, MAX_CMD_SIZE, "hostapd_cli -i global raw ADD bss_config=phy%d:%s", phyId, config_file);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
	} else {
		fprintf(stderr, "%s %d\n", __func__, __LINE__);
		res = snprintf(cmd, MAX_CMD_SIZE, "hostapd_cli -i global raw REMOVE %s", interface_name);
		if (os_snprintf_error(MAX_CMD_SIZE, res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));
	}
	res = snprintf(cmd, MAX_CMD_SIZE, "sed -i -n -e '/^%s=/!p' -e '$a%s=%d' %s",
				interface_name, interface_name, enable, VAP_STATUS_FILE);
	if (os_snprintf_error(MAX_CMD_SIZE, res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	//Wait for wifi up/down to apply
	return RETURN_OK;
}

int hostapd_raw_add_bss(int apIndex)
{
	return hostapd_manage_bss(apIndex, TRUE);
}

int hostapd_raw_remove_bss(int apIndex)
{
	return hostapd_manage_bss(apIndex, FALSE);
}

int hostapd_raw_restart_bss(int apIndex)
{
	int ret = 0;

	ret = hostapd_raw_remove_bss(apIndex);
	if(ret != RETURN_OK)
		return RETURN_ERR;

	ret = hostapd_raw_add_bss(apIndex);
	if(ret != RETURN_OK)
		return RETURN_ERR;

	return RETURN_OK;
}

INT wifi_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
	unsigned int i;
	wifi_vap_info_t *vap_info = NULL;
	int acl_mode;
	int ret = 0;
	char buf[256] = {0};
	char cmd[128] = {0};
	char config_file[64] = {0};
	char psk_file[64] = {0};
	BOOL enable = FALSE;
	int band_idx;
	int res;


	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	printf("Entering %s index = %d\n", __func__, (int)index);
	for (i = 0; i < map->num_vaps; i++)
	{
		multiple_set = TRUE;
		vap_info = &map->vap_array[i];

		// Check vap status file to enable multiple ap if the system boot.
		checkVapStatus(vap_info->vap_index, &enable);
		if (vap_info->u.bss_info.enabled == FALSE && enable == FALSE)
			continue;

		wifi_debug(DEBUG_ERROR, "\nCreate VAP for ssid_index=%d (vap_num=%d)\n", vap_info->vap_index, i);

		band_idx = radio_index_to_band(index);
		res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, vap_info->vap_index);
		if (os_snprintf_error(sizeof(config_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		if(band_idx >= 0 && band_idx < sizeof(wifi_band_str)/sizeof(wifi_band_str[0])){
			res = snprintf(cmd, sizeof(cmd), "cp /etc/hostapd-%s.conf %s", wifi_band_str[band_idx], config_file);
		} else{
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));

		struct params params[3];
		params[0].name = "interface";
		params[0].value = vap_info->vap_name;
		res = snprintf(psk_file, sizeof(psk_file), "\\/nvram\\/hostapd%d.psk", vap_info->vap_index);
		if (os_snprintf_error(sizeof(psk_file), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		params[1].name = "wpa_psk_file";
		params[1].value = psk_file;
		params[2].name = "ssid";
		params[2].value = vap_info->u.bss_info.ssid;

		snprintf(config_file,sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, vap_info->vap_index);
		wifi_hostapdWrite(config_file, params, 3);

		res = snprintf(cmd, sizeof(cmd), "touch %s", psk_file);
		if (os_snprintf_error(sizeof(cmd), res)) {
			wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
			return RETURN_ERR;
		}
		_syscmd(cmd, buf, sizeof(buf));

		ret = wifi_setSSIDName(vap_info->vap_index, vap_info->u.bss_info.ssid);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setSSIDName return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setApSsidAdvertisementEnable(vap_info->vap_index, vap_info->u.bss_info.showSsid);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApSsidAdvertisementEnable return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setApIsolationEnable(vap_info->vap_index, vap_info->u.bss_info.isolation);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApIsolationEnable return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setApMaxAssociatedDevices(vap_info->vap_index, vap_info->u.bss_info.bssMaxSta);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApMaxAssociatedDevices return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setBSSTransitionActivation(vap_info->vap_index, vap_info->u.bss_info.bssTransitionActivated);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setBSSTransitionActivation return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setNeighborReportActivation(vap_info->vap_index, vap_info->u.bss_info.nbrReportActivated);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setNeighborReportActivation return error\n", __func__);
			return RETURN_ERR;
		}

		if (vap_info->u.bss_info.mac_filter_enable == false){
			acl_mode = 0;
		}else {
			if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list){
				acl_mode = 2;
				res = snprintf(cmd, sizeof(cmd), "touch %s%d", DENY_PREFIX, vap_info->vap_index);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}
				_syscmd(cmd, buf, sizeof(buf));
			}else{
				acl_mode = 1;
			}
		}

		ret = wifi_setApWmmEnable(vap_info->vap_index, vap_info->u.bss_info.wmm_enabled);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApWmmEnable return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setApWmmUapsdEnable(vap_info->vap_index, vap_info->u.bss_info.UAPSDEnabled);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApWmmUapsdEnable return error\n", __func__);
			return RETURN_ERR;
		}

		memset(buf, 0, sizeof(buf));
		beaconRate_enum_to_string(vap_info->u.bss_info.beaconRate, buf, sizeof(buf));
		ret = wifi_setApBeaconRate(vap_info->radio_index, buf);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApBeaconRate return error\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setRadioIGMPSnoopingEnable(vap_info->radio_index, vap_info->u.bss_info.mcast2ucast);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setRadioIGMPSnoopingEnable\n", __func__);
			return RETURN_ERR;
		}

		ret = wifi_setApSecurity(vap_info->vap_index, &vap_info->u.bss_info.security);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApSecurity return error\n", __func__);
			return RETURN_ERR;
		}

		hostapd_raw_restart_bss(vap_info->vap_index);

		multiple_set = FALSE;

		// If config use hostapd_cli to set, we calling these type of functions after enable the ap.
		ret = wifi_setApMacAddressControlMode(vap_info->vap_index, acl_mode);
		if (ret != RETURN_OK) {
			fprintf(stderr, "%s: wifi_setApMacAddressControlMode return error\n", __func__);
			return RETURN_ERR;
		}

		// TODO mgmtPowerControl, interworking, wps
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

int parse_channel_list_int_arr(char *pchannels, wifi_channels_list_t* chlistptr)
{
	char *token, *next;
	const char s[2] = ",";
	int count =0;

	/* get the first token */
	token = strtok_r(pchannels, s, &next);

	/* walk through other tokens */
	while( token != NULL && count < MAX_CHANNELS) {
		chlistptr->channels_list[count++] = atoi(token);
		token = strtok_r(NULL, s, &next);
	}

	return count;
}

static int getRadioCapabilities(int radioIndex, wifi_radio_capabilities_t *rcap)
{
	INT status;
	wifi_channels_list_t *chlistp;
	CHAR output_string[64];
	CHAR pchannels[128];
	CHAR interface_name[16] = {0};
	wifi_band band;
	int res;

	if(rcap == NULL)
	{
		return RETURN_ERR;
	}

	rcap->numSupportedFreqBand = 1;
	band = wifi_index_to_band(radioIndex);

	if (band == band_2_4)
		rcap->band[0] = WIFI_FREQUENCY_2_4_BAND;
	else if (band == band_5)
		rcap->band[0] = WIFI_FREQUENCY_5_BAND;
	else if (band == band_6)
		rcap->band[0] = WIFI_FREQUENCY_6_BAND;

	chlistp = &(rcap->channel_list[0]);
	memset(pchannels, 0, sizeof(pchannels));

	/* possible number of radio channels */
	status = wifi_getRadioPossibleChannels(radioIndex, pchannels);
	{
		 printf("[wifi_hal dbg] : func[%s] line[%d] error_ret[%d] radio_index[%d] output[%s]\n", __FUNCTION__, __LINE__, status, radioIndex, pchannels);
	}
	/* Number of channels and list*/
	chlistp->num_channels = parse_channel_list_int_arr(pchannels, chlistp);

	/* autoChannelSupported */
	/* always ON with wifi_getRadioAutoChannelSupported */
	rcap->autoChannelSupported = TRUE;

	/* DCSSupported */
	/* always ON with wifi_getRadioDCSSupported */
	rcap->DCSSupported = TRUE;

	/* zeroDFSSupported - TBD */
	rcap->zeroDFSSupported = FALSE;

	/* Supported Country List*/
	memset(output_string, 0, sizeof(output_string));
	status = wifi_getRadioCountryCode(radioIndex, output_string);
	if( status != 0 ) {
		printf("[wifi_hal dbg] : func[%s] line[%d] error_ret[%d] radio_index[%d] output[%s]\n", __FUNCTION__, __LINE__, status, radioIndex, output_string);
		return RETURN_ERR;
	} else {
		printf("[wifi_hal dbg] : func[%s] line[%d], output [%s]\n", __FUNCTION__, __LINE__, output_string);
	}
	if(!strcmp(output_string,"US")){
		rcap->countrySupported[0] = wifi_countrycode_US;
		rcap->countrySupported[1] = wifi_countrycode_CA;
	} else if (!strcmp(output_string,"CA")) {
		rcap->countrySupported[0] = wifi_countrycode_CA;
		rcap->countrySupported[1] = wifi_countrycode_US;
	} else {
		printf("[wifi_hal dbg] : func[%s] line[%d] radio_index[%d] Invalid Country [%s]\n", __FUNCTION__, __LINE__, radioIndex, output_string);
	}

	rcap->numcountrySupported = 2;

	/* csi */
	rcap->csi.maxDevices = 8;
	rcap->csi.soudingFrameSupported = TRUE;

	wifi_GetInterfaceName(radioIndex, interface_name);
	res = snprintf(rcap->ifaceName, sizeof(interface_name), "%s",interface_name);
	if (os_snprintf_error(sizeof(interface_name), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	/* channelWidth - all supported bandwidths */
	int i=0;
	rcap->channelWidth[i] = 0;
	if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND) {
		rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
								WIFI_CHANNELBANDWIDTH_40MHZ);

	}
	else if (rcap->band[i] & (WIFI_FREQUENCY_5_BAND ) || rcap->band[i] & (WIFI_FREQUENCY_6_BAND)) {
		rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
								WIFI_CHANNELBANDWIDTH_40MHZ |
								WIFI_CHANNELBANDWIDTH_80MHZ | WIFI_CHANNELBANDWIDTH_160MHZ);
	}


	/* mode - all supported variants */
	// rcap->mode[i] = WIFI_80211_VARIANT_H;
	if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND ) {
		rcap->mode[i] = ( WIFI_80211_VARIANT_B | WIFI_80211_VARIANT_G | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AX );
	}
	else if (rcap->band[i] & WIFI_FREQUENCY_5_BAND ) {
		rcap->mode[i] = ( WIFI_80211_VARIANT_A | WIFI_80211_VARIANT_N | WIFI_80211_VARIANT_AC | WIFI_80211_VARIANT_AX );
	}
	else if (rcap->band[i] & WIFI_FREQUENCY_6_BAND) {
		rcap->mode[i] = ( WIFI_80211_VARIANT_AX );
	}
	rcap->maxBitRate[i] = ( rcap->band[i] & WIFI_FREQUENCY_2_4_BAND ) ? 300 :
		((rcap->band[i] & WIFI_FREQUENCY_5_BAND) ? 1734 : 0);

	/* supportedBitRate - all supported bitrates */
	rcap->supportedBitRate[i] = 0;
	if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND) {
		rcap->supportedBitRate[i] |= (WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS |
									WIFI_BITRATE_11MBPS | WIFI_BITRATE_12MBPS);
	}
	else if ((rcap->band[i] & (WIFI_FREQUENCY_5_BAND )) || (rcap->band[i] & (WIFI_FREQUENCY_6_BAND))) {
		rcap->supportedBitRate[i] |= (WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS |
									WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS | WIFI_BITRATE_24MBPS |
									WIFI_BITRATE_36MBPS | WIFI_BITRATE_48MBPS | WIFI_BITRATE_54MBPS);
	}


	rcap->transmitPowerSupported_list[i].numberOfElements = 5;
	rcap->transmitPowerSupported_list[i].transmitPowerSupported[0]=12;
	rcap->transmitPowerSupported_list[i].transmitPowerSupported[1]=25;
	rcap->transmitPowerSupported_list[i].transmitPowerSupported[2]=50;
	rcap->transmitPowerSupported_list[i].transmitPowerSupported[3]=75;
	rcap->transmitPowerSupported_list[i].transmitPowerSupported[4]=100;
	rcap->cipherSupported = 0;
	rcap->cipherSupported |= WIFI_CIPHER_CAPA_ENC_TKIP | WIFI_CIPHER_CAPA_ENC_CCMP;
	rcap->maxNumberVAPs = MAX_NUM_VAP_PER_RADIO;

	return RETURN_OK;
}

INT wifi_getHalCapability(wifi_hal_capability_t *cap)
{
	INT status = 0, radioIndex = 0;
	char output[MAX_BUF_SIZE] = {0};
	int iter = 0;
	unsigned int j = 0;
	int max_num_radios = 0;
	wifi_interface_name_idex_map_t *iface_info = NULL;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	memset(cap, 0, sizeof(wifi_hal_capability_t));

	/* version */
	cap->version.major = WIFI_HAL_MAJOR_VERSION;
	cap->version.minor = WIFI_HAL_MINOR_VERSION;

	/* number of radios platform property */
	wifi_getMaxRadioNumber(&max_num_radios);
	cap->wifi_prop.numRadios = max_num_radios;

	for(radioIndex=0; radioIndex < cap->wifi_prop.numRadios; radioIndex++)
	{
		status = getRadioCapabilities(radioIndex, &(cap->wifi_prop.radiocap[radioIndex]));
		if (status != 0) {
			printf("%s: getRadioCapabilities idx = %d\n", __FUNCTION__, radioIndex);
			return RETURN_ERR;
		}

		for (j = 0; j < cap->wifi_prop.radiocap[radioIndex].maxNumberVAPs; j++)
		{
			if (iter >= MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)
			{
				 printf("%s: to many vaps for index map (%d)\n", __func__, iter);
				 return RETURN_ERR;
			}
			iface_info = &cap->wifi_prop.interface_map[iter];
			iface_info->phy_index = radioIndex; // XXX: parse phyX index instead
			iface_info->rdk_radio_index = radioIndex;
			memset(output, 0, sizeof(output));
			if (wifi_getRadioIfName(radioIndex, output) == RETURN_OK)
			{
				strncpy(iface_info->interface_name, output, sizeof(iface_info->interface_name) - 1);
			}
			// TODO: bridge name
			// TODO: vlan id
			// TODO: primary
			iface_info->index = array_index_to_vap_index(radioIndex, j);
			memset(output, 0, sizeof(output));
			if (wifi_getApName(iface_info->index, output) == RETURN_OK)
			{
				 strncpy(iface_info->vap_name, output, sizeof(iface_info->vap_name) - 1);
			}
		iter++;
		}
	}

	cap->BandSteeringSupported = FALSE;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setOpportunisticKeyCaching(int ap_index, BOOL okc_enable)
{
	struct params h_config={0};
	char config_file[64] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	h_config.name = "okc";
	h_config.value = okc_enable?"1":"0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &h_config, 1);
	wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setSAEMFP(int ap_index, BOOL enable)
{
	struct params h_config={0};
	char config_file[64] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	h_config.name = "sae_require_mfp";
	h_config.value = enable?"1":"0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &h_config, 1);
	wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setSAEpwe(int ap_index, int sae_pwe)
{
	struct params h_config={0};
	char config_file[64] = {0};
	char buf[128] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	h_config.name = "sae_pwe";
	res = snprintf(buf, sizeof(buf), "%d", sae_pwe);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}

	h_config.value = buf;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &h_config, 1);
	wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setDisable_EAPOL_retries(int ap_index, BOOL disable_EAPOL_retries)
{
	// wpa3 use SAE instead of PSK, so we need to disable this feature when using wpa3.
	struct params h_config={0};
	char config_file[64] = {0};
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	h_config.name = "wpa_disable_eapol_key_retries";
	h_config.value = disable_EAPOL_retries?"1":"0";

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdWrite(config_file, &h_config, 1);
	wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_setApSecurity(INT ap_index, wifi_vap_security_t *security)
{
	char buf[128] = {0};
	char config_file[128] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char password[65] = {0};
	char mfp[32] = {0};
	char wpa_mode[32] = {0};
	BOOL okc_enable = FALSE;
	BOOL sae_MFP = FALSE;
	BOOL disable_EAPOL_retries = TRUE;
	int sae_pwe = 0;
	struct params params = {0};
	wifi_band band = band_invalid;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	multiple_set = TRUE;
	snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
	if (security->mode == wifi_security_mode_none) {
		strncpy(wpa_mode, "None",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa_personal) {
		strncpy(wpa_mode, "WPA-Personal",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa2_personal){
		strncpy(wpa_mode, "WPA2-Personal",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa_wpa2_personal){
		strncpy(wpa_mode, "WPA-WPA2-Personal",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa_enterprise){
		strncpy(wpa_mode, "WPA-Enterprise",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa2_enterprise){
		strncpy(wpa_mode, "WPA2-Enterprise",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa_wpa2_enterprise){
		strncpy(wpa_mode, "WPA-WAP2-Enterprise",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
	} else if (security->mode == wifi_security_mode_wpa3_personal) {
		strncpy(wpa_mode, "WPA3-Personal",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
		okc_enable = TRUE;
		sae_MFP = TRUE;
		sae_pwe = 2;
		disable_EAPOL_retries = FALSE;
	} else if (security->mode == wifi_security_mode_wpa3_transition) {
		strncpy(wpa_mode, "WPA3-Personal-Transition",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
		okc_enable = TRUE;
		sae_MFP = TRUE;
		sae_pwe = 2;
		disable_EAPOL_retries = FALSE;
	} else if (security->mode == wifi_security_mode_wpa3_enterprise) {
		strncpy(wpa_mode, "WPA3-Enterprise",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
		sae_MFP = TRUE;
		sae_pwe = 2;
		disable_EAPOL_retries = FALSE;
	} else if (security->mode == wifi_security_mode_enhanced_open) {
		strncpy(wpa_mode, "OWE",sizeof(wpa_mode) - 1);
		wpa_mode[sizeof(wpa_mode) - 1] = '\0';
		sae_MFP = TRUE;
		sae_pwe = 2;
		disable_EAPOL_retries = FALSE;
	}

	band = wifi_index_to_band(ap_index);
	if (band == band_6 && strstr(wpa_mode, "WPA3") == NULL) {
		fprintf(stderr, "%s: 6G band must set with wpa3.\n", __func__);
		return RETURN_ERR;
	}

	wifi_setApSecurityModeEnabled(ap_index, wpa_mode);
	wifi_setOpportunisticKeyCaching(ap_index, okc_enable);
	wifi_setSAEMFP(ap_index, sae_MFP);
	wifi_setSAEpwe(ap_index, sae_pwe);
	wifi_setDisable_EAPOL_retries(ap_index, disable_EAPOL_retries);

	if (security->mode != wifi_security_mode_none && security->mode != wifi_security_mode_enhanced_open) {
		if (security->u.key.type == wifi_security_key_type_psk || security->u.key.type == wifi_security_key_type_pass || security->u.key.type == wifi_security_key_type_psk_sae) {
			int key_len = strlen(security->u.key.key);
			// wpa_psk and wpa_passphrase cann;t use at the same time, the command replace one with the other.
			if (key_len == 64) {	// set wpa_psk
				strncpy(password, security->u.key.key, 64);	 // 64 characters
				password[64] = '\0';
				wifi_setApSecurityPreSharedKey(ap_index, password);
				res = snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^wpa_passphrase=/!p' %s", config_file);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}
			} else if (key_len >= 8 && key_len < 64) {  // set wpa_passphrase
				strncpy(password, security->u.key.key, 63);
				password[63] = '\0';
				wifi_setApSecurityKeyPassphrase(ap_index, password);
				res = snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^wpa_psk=/!p' %s", config_file);
				if (os_snprintf_error(sizeof(cmd), res)) {
					wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
					return RETURN_ERR;
				}
			} else
				return RETURN_ERR;
			_syscmd(cmd, buf, sizeof(buf));
		}
		if (security->u.key.type == wifi_security_key_type_sae || security->u.key.type == wifi_security_key_type_psk_sae) {
			params.name = "sae_password";
			params.value = security->u.key.key;
			wifi_hostapdWrite(config_file, &params, 1);
		} else {	// remove sae_password
			res = snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^sae_password=/!p' %s", config_file);
			if (os_snprintf_error(sizeof(cmd), res)) {
				wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
				return RETURN_ERR;
			}
			_syscmd(cmd, buf, sizeof(buf));
		}
	}

	if (security->mode != wifi_security_mode_none) {
		memset(&params, 0, sizeof(params));
		params.name = "wpa_pairwise";
		if (security->encr == wifi_encryption_tkip)
			params.value = "TKIP";
		else if (security->encr == wifi_encryption_aes)
			params.value = "CCMP";
		else if (security->encr == wifi_encryption_aes_tkip)
			params.value = "TKIP CCMP";
		wifi_hostapdWrite(config_file, &params, 1);
	}

	if (security->mfp == wifi_mfp_cfg_disabled){
		strncpy(mfp,"Disabled",sizeof(mfp)-1);
		mfp[sizeof(mfp)-1] = '\0';
	} else if (security->mfp == wifi_mfp_cfg_optional){
		strncpy(mfp,"Optional",sizeof(mfp)-1);
		mfp[sizeof(mfp)-1] = '\0';
	} else if (security->mfp == wifi_mfp_cfg_required){
		strncpy(mfp,"Required",sizeof(mfp)-1);
		mfp[sizeof(mfp)-1] = '\0';
	}
	wifi_setApSecurityMFPConfig(ap_index, mfp);

	memset(&params, 0, sizeof(params));
	params.name = "transition_disable";
	if (security->wpa3_transition_disable == TRUE)
		params.value = "0x01";
	else
		params.value = "0x00";
	wifi_hostapdWrite(config_file, &params, 1);

	memset(&params, 0, sizeof(params));
	params.name = "wpa_group_rekey";
	res = snprintf(buf, sizeof(buf), "%d", security->rekey_interval);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.value = buf;
	wifi_hostapdWrite(config_file, &params, 1);

	memset(&params, 0, sizeof(params));
	params.name = "wpa_strict_rekey";
	params.value = security->strict_rekey?"1":"0";
	wifi_hostapdWrite(config_file, &params, 1);

	memset(&params, 0, sizeof(params));
	params.name = "wpa_pairwise_update_count";
	if (security->eapol_key_retries == 0)
		security->eapol_key_retries = 4;	// 0 is invalid, set to default value.
	res = snprintf(buf, sizeof(buf), "%u", security->eapol_key_retries);
	if (os_snprintf_error(sizeof(buf), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	params.value = buf;
	wifi_hostapdWrite(config_file, &params, 1);

	memset(&params, 0, sizeof(params));
	params.name = "disable_pmksa_caching";
	params.value = security->disable_pmksa_caching?"1":"0";
	wifi_hostapdWrite(config_file, &params, 1);

	if (multiple_set == FALSE) {
		wifi_setApEnable(ap_index, FALSE);
		wifi_setApEnable(ap_index, TRUE);
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getApSecurity(INT ap_index, wifi_vap_security_t *security)
{
	char buf[256] = {0};
	char config_file[128] = {0};
	int disable = 0;
	bool set_sae = FALSE;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
	wifi_getApSecurityModeEnabled(ap_index, buf);   // Get wpa config
	security->mode = wifi_security_mode_none;
	if (strlen(buf) != 0) {
		if (!strcmp(buf, "WPA-Personal"))
			security->mode = wifi_security_mode_wpa_personal;
		else if (!strcmp(buf, "WPA2-Personal"))
			security->mode = wifi_security_mode_wpa2_personal;
		else if (!strcmp(buf, "WPA-WPA2-Personal"))
			security->mode = wifi_security_mode_wpa_wpa2_personal;
		else if (!strcmp(buf, "WPA-Enterprise"))
			security->mode = wifi_security_mode_wpa_enterprise;
		else if (!strcmp(buf, "WPA2-Enterprise"))
			security->mode = wifi_security_mode_wpa2_enterprise;
		else if (!strcmp(buf, "WPA-WPA2-Enterprise"))
			security->mode = wifi_security_mode_wpa_wpa2_enterprise;
		else if (!strcmp(buf, "WPA3-Personal"))
			security->mode = wifi_security_mode_wpa3_personal;
		else if (!strcmp(buf, "WPA3-Personal-Transition"))
			security->mode = wifi_security_mode_wpa3_transition;
		else if (!strcmp(buf, "WPA3-Enterprise"))
			security->mode = wifi_security_mode_wpa3_enterprise;
		else if (!strcmp(buf, "OWE"))
			security->mode = wifi_security_mode_enhanced_open;
	}

	wifi_hostapdRead(config_file,"wpa_pairwise",buf,sizeof(buf));
	if (security->mode == wifi_security_mode_none)
		security->encr = wifi_encryption_none;
	else {
		if (strcmp(buf, "TKIP") == 0)
			security->encr = wifi_encryption_tkip;
		else if (strcmp(buf, "CCMP") == 0)
			security->encr = wifi_encryption_aes;
		else
			security->encr = wifi_encryption_aes_tkip;
	}

	if (security->mode != wifi_security_mode_none) {
		memset(buf, 0, sizeof(buf));
		// wpa3 can use one or both configs as password, so we check sae_password first.
		wifi_hostapdRead(config_file, "sae_password", buf, sizeof(buf));
		if (strlen(buf) != 0) {
			if (security->mode == wifi_security_mode_wpa3_personal || security->mode == wifi_security_mode_wpa3_transition)
				security->u.key.type = wifi_security_key_type_sae;
			set_sae = TRUE;
			strncpy(security->u.key.key, buf, sizeof(buf));
		}
		wifi_hostapdRead(config_file, "wpa_passphrase", buf, sizeof(buf));
		if (strlen(buf) != 0){
			if (set_sae == TRUE)
				security->u.key.type = wifi_security_key_type_psk_sae;
			else if (strlen(buf) == 64)
				security->u.key.type = wifi_security_key_type_psk;
			else
				security->u.key.type = wifi_security_key_type_pass;
			strncpy(security->u.key.key, buf, sizeof(security->u.key.key));
		}
		security->u.key.key[255] = '\0';
	}

	memset(buf, 0, sizeof(buf));
	wifi_getApSecurityMFPConfig(ap_index, buf);
	if (strcmp(buf, "Disabled") == 0)
		security->mfp = wifi_mfp_cfg_disabled;
	else if (strcmp(buf, "Optional") == 0)
		security->mfp = wifi_mfp_cfg_optional;
	else if (strcmp(buf, "Required") == 0)
		security->mfp = wifi_mfp_cfg_required;

	memset(buf, 0, sizeof(buf));
	security->wpa3_transition_disable = FALSE;
	wifi_hostapdRead(config_file, "transition_disable", buf, sizeof(buf));
	disable = strtol(buf, NULL, 16);
	if (disable != 0)
		security->wpa3_transition_disable = TRUE;

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "wpa_group_rekey", buf, sizeof(buf));
	if (strlen(buf) == 0)
		security->rekey_interval = 86400;
	else
		security->rekey_interval = strtol(buf, NULL, 10);

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "wpa_strict_rekey", buf, sizeof(buf));
	if (strlen(buf) == 0)
		security->strict_rekey = 1;
	else
		security->strict_rekey = strtol(buf, NULL, 10);

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "wpa_pairwise_update_count", buf, sizeof(buf));
	if (strlen(buf) == 0)
		security->eapol_key_retries = 4;
	else
		security->eapol_key_retries = strtol(buf, NULL, 10);

	memset(buf, 0, sizeof(buf));
	wifi_hostapdRead(config_file, "disable_pmksa_caching", buf, sizeof(buf));
	if (strlen(buf) == 0)
		security->disable_pmksa_caching = FALSE;
	else
		security->disable_pmksa_caching = strtol(buf, NULL, 10)?TRUE:FALSE;

	/* TODO
	eapol_key_timeout, eap_identity_req_timeout, eap_identity_req_retries, eap_req_timeout, eap_req_retries
	*/
	security->eapol_key_timeout = 1000; // Unit is ms. The default value in protocol.
	security->eap_identity_req_timeout = 0;
	security->eap_identity_req_retries = 0;
	security->eap_req_timeout = 0;
	security->eap_req_retries = 0;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

#endif /* WIFI_HAL_VERSION_3 */

#ifdef WIFI_HAL_VERSION_3_PHASE2
INT wifi_getApAssociatedDevice(INT ap_index, mac_address_t *output_deviceMacAddressArray, UINT maxNumDevices, UINT *output_numDevices)
{
	char interface_name[16] = {0};
	char cmd[128] = {0};
	char buf[128] = {0};
	char *mac_addr = NULL;
	BOOL status = FALSE;
	size_t len = 0;

	if(ap_index > MAX_APS)
		return RETURN_ERR;

	*output_numDevices = 0;
	wifi_getApEnable(ap_index, &status);
	if (status == FALSE)
		return RETURN_OK;

	if (wifi_GetInterfaceName(ap_index, interface_name) != RETURN_OK)
		return RETURN_ERR;
	sprintf(cmd, "hostapd_cli -i %s list_sta", interface_name);
	_syscmd(cmd, buf, sizeof(buf));

	mac_addr = strtok(buf, "\n");
	for (int i = 0; i < maxNumDevices && mac_addr != NULL; i++) {
		*output_numDevices = i + 1;
		fprintf(stderr, "mac_addr: %s\n", mac_addr);
		addr_ptr = output_deviceMacAddressArray[i];
		mac_addr_aton(addr_ptr, mac_addr);
		mac_addr = strtok(NULL, "\n");
	}

	return RETURN_OK;
}
#else
INT wifi_getApAssociatedDevice(INT ap_index, CHAR *output_buf, INT output_buf_size)
{
	char interface_name[16] = {0};
	char cmd[128];
	BOOL status = false;
	int res;

	if(ap_index > MAX_APS || output_buf == NULL || output_buf_size <= 0)
		return RETURN_ERR;

	output_buf[0] = '\0';

	wifi_getApEnable(ap_index,&status);
	if (!status)
		return RETURN_OK;

	if (wifi_GetInterfaceName(ap_index, interface_name) != RETURN_OK)
		return RETURN_ERR;
	res = snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s list_sta | tr '\\n' ',' | sed 's/.$//'", interface_name);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	
	_syscmd(cmd, output_buf, output_buf_size);

	return RETURN_OK;
}
#endif

INT wifi_getProxyArp(INT apIndex, BOOL *enable)
{
	char output[16]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int res;

	if (!enable)
		return RETURN_ERR;

	res = snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
	if (os_snprintf_error(sizeof(config_file), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	wifi_hostapdRead(config_file, "proxy_arp", output, sizeof(output));

	if (strlen(output) == 0)
		*enable = FALSE;
	else if (strncmp(output, "1", 1) == 0)
		*enable = TRUE;
	else
		*enable = FALSE;

	wifi_dbg_printf("\n[%s]: proxy_arp is : %s", __func__, output);
	return RETURN_OK;
}

INT wifi_getRadioStatsEnable(INT radioIndex, BOOL *output_enable)
{
	if (NULL == output_enable || radioIndex >=MAX_NUM_RADIOS)
		return RETURN_ERR;
	*output_enable=TRUE;
	return RETURN_OK;
}

INT wifi_getTWTsessions(INT ap_index, UINT maxNumberSessions, wifi_twt_sessions_t *twtSessions, UINT *numSessionReturned)
{
	char cmd[128] = {0};
	char buf[128] = {0};
	char line[128] = {0};
	FILE *f = NULL;
	int index = 0;
	int exp = 0;
	int mantissa = 0;
	int duration = 0;
	int radio_index = 0;
	int max_radio_num = 0;
	uint twt_wake_interval = 0;
	int phyId = 0;
	int res;

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	wifi_getMaxRadioNumber(&max_radio_num);
	if(max_radio_num == 0){
		return RETURN_ERR;
	}
	radio_index = ap_index % max_radio_num;

	phyId = radio_index_to_phy(radio_index);

	res = snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy%d/mt76/twt_stats | wc -l", phyId);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	_syscmd(cmd, buf, sizeof(buf));
	*numSessionReturned = strtol(buf, NULL, 10) - 1;
	if (*numSessionReturned > maxNumberSessions)
		*numSessionReturned = maxNumberSessions;
	else if (*numSessionReturned < 1) {
		*numSessionReturned = 0;
		return RETURN_OK;
	}

	res = snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy%d/mt76/twt_stats | tail -n %d | tr '|' ' ' | tr -s ' '", phyId, *numSessionReturned);
	if (os_snprintf_error(sizeof(cmd), res)) {
		wifi_debug(DEBUG_ERROR, "Unexpected snprintf fail\n");
		return RETURN_ERR;
	}
	if ((f = popen(cmd, "r")) == NULL) {
		wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
		return RETURN_ERR;
	}

	// the format of each line is "[wcid] [id] [flags] [exp] [mantissa] [duration] [tsf]"
	while((fgets(line, sizeof(line), f)) != NULL) {
		char *tmp = NULL;
		size_t len = strlen(line);
		strncpy(buf, line,len);
		buf[len] = '\0';
		tmp = strtok(buf, " ");
		twtSessions[index].numDevicesInSession = strtol(tmp, NULL, 10);
		tmp = strtok(NULL, " ");
		twtSessions[index].twtParameters.operation.flowID = strtol(tmp, NULL, 10);
		tmp = strtok(NULL, " ");
		if (strstr(tmp, "t")) {
			twtSessions[index].twtParameters.operation.trigger_enabled = TRUE;
		}
		if (strstr(tmp, "a")) {
			twtSessions[index].twtParameters.operation.announced = TRUE;
		}
		tmp = strtok(NULL, " ");
		exp = strtol(tmp, NULL, 10);
		tmp = strtok(NULL, " ");
		mantissa = strtol(tmp, NULL, 10);
		tmp = strtok(NULL, " ");
		duration = strtol(tmp, NULL, 10);

		// only implicit supported
		twtSessions[index].twtParameters.operation.implicit = TRUE;
		// only individual agreement supported
		twtSessions[index].twtParameters.agreement = wifi_twt_agreement_type_individual;

		// wakeInterval_uSec is a unsigned integer, but the maximum TWT wake interval could be 2^15 (mantissa) * 2^32 = 2^47.
		twt_wake_interval = mantissa * (1 << exp);
		if (mantissa == 0 || twt_wake_interval/mantissa != (1 << exp)) {
			// Overflow handling
			twtSessions[index].twtParameters.params.individual.wakeInterval_uSec = -1;   // max unsigned int
		} else {
			twtSessions[index].twtParameters.params.individual.wakeInterval_uSec = twt_wake_interval;
		}
		twtSessions[index].twtParameters.params.individual.minWakeDuration_uSec = duration * 256;
		index++;
	}

	pclose(f);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_enableGreylistAccessControl(BOOL enable)
{
	char inf_name[IFNAMSIZ] = {0};
	int if_idx, ret = 0;
	struct nl_msg *msg	= NULL;
	struct nlattr * msg_data = NULL;
	struct mtk_nl80211_param param;
	struct unl unl_ins;
	unsigned short apIndex = 0;

	for (apIndex = 0; apIndex < MAX_APS; apIndex++) {
		if (wifi_GetInterfaceName(apIndex, inf_name) != RETURN_OK)
			continue;

		if_idx = if_nametoindex(inf_name);
		if (!if_idx) {
			wifi_debug(DEBUG_ERROR, "can't finde ifname(%s) index,ERROR\n", inf_name);
			continue;
		}

		/*init mtk nl80211 vendor cmd*/
		param.sub_cmd = MTK_NL80211_VENDOR_SUBCMD_SET_ACL;
		param.if_type = NL80211_ATTR_IFINDEX;
		param.if_idx = if_idx;
		ret = mtk_nl80211_init(&unl_ins, &msg, &msg_data, &param);
		if (ret) {
			wifi_debug(DEBUG_ERROR, "init mtk 80211 netlink and msg fails\n");
			return RETURN_ERR;
		}

		if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_ACL_POLICY, enable == FALSE ? 0 : 1)) {
			wifi_debug(DEBUG_ERROR, "Nla put attribute error\n");
			nlmsg_free(msg);
			mtk_nl80211_deint(&unl_ins);
			continue;
		}

		/*send mtk nl80211 vendor msg*/
		ret = mtk_nl80211_send(&unl_ins, msg, msg_data, NULL, NULL);
		if (ret) {
			wifi_debug(DEBUG_ERROR, "send mtk nl80211 vender msg fails\n");
			mtk_nl80211_deint(&unl_ins);
			continue;
		}
		/*deinit mtk nl80211 vendor msg*/
		mtk_nl80211_deint(&unl_ins);
		wifi_debug(DEBUG_NOTICE, " %s cmd success.\n", inf_name);
	}

	return RETURN_OK;
}
