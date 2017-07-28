#ifndef __RVCD_CONFIG_H__
#define __RVCD_CONFIG_H__

/* rvcd config item structure */
struct rvcd_config_item {
	char name[RVCD_CONFIG_NAME_MAX_LEN + 1];
	char ovpn_profile_path[RVCD_MAX_PATH];
	bool connected;
};

/* rvcd configuration structure */
typedef struct rvcd_config {
	bool init_flag;

	int config_items_count;
	struct rvcd_config_item *config_items;

	pthread_mutex_t config_mt;
} rvcd_config_t;

/* rvcd configuration functions */
int rvcd_config_init(struct rvcd_ctx *c);
void rvcd_config_finalize(rvcd_config_t *config);

void rvcd_config_to_buffer(rvcd_config_t *config, bool json_format, char **buffer);

#endif	/* __RVCD_CONFIG_H__ */
