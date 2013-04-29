#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "onep_core_services.h"
#include "onep_types.h"
#include "onep_dpss_packet_delivery.h"
#include "onep_dpss_pkt.h"
#include "onep_dpss_flow.h"
#include "onep_dpss_callback_framework.h"

#include "onep_dpss_actions.h"

#include "class.h"
#include "filter.h"


/*
	 A simple macro for test harnesses that logs onePK errors and returns.
 */
#define TRY(_rc, _expr, _fmt, _args...)                                 \
	if (((_rc) = (_expr)) != ONEP_OK) {                                 \
		fprintf(                                                        \
				stderr, "\n%s:%d: Error: %s(%d): " _fmt "\n",               \
				__FILE__, __LINE__, onep_strerror((_rc)), (_rc) , ##_args); \
		return ((_rc));                                                 \
	}


static network_interface_t *intf = NULL;
static ace_t*              ace;
static acl_t*              acl; 
static target_t*           targ = NULL;
static class_t *           acl_class = NULL;
static filter_t *          acl_filter = NULL;
static interface_filter_t* intf_filter = NULL;
static onep_collection_t*  intfs = NULL;
static unsigned int        count = 0;
static network_element_t*  ne1 = NULL;
static onep_status_t       rc;
static onep_if_name        name;
static onep_dpss_handle_t  *dpss_handle;
static onep_dpss_packet_loop_t *pak_loop;
static onep_dpss_traffic_reg_t *reg_handle;

static session_config_t	   *config;

static network_application_t* myapp = NULL;

struct sockaddr_in	v4addr;


void dpss_tutorial_pak_injector (
		onep_dpss_traffic_reg_t *reg,
		onep_dpss_paktype_t *pak,
		void *client_context,
		bool *return_pak)
{
	onep_status_t rc;
	onep_dpss_handle_t *dpss;
	target_t *targ;
	network_interface_t *intf;
	uint16_t l3_protocol;

	rc = onep_dpss_traffic_reg_get_dpss_handle (reg, &dpss);
	rc = onep_dpss_traffic_reg_get_target(reg, &targ);
	rc = onep_policy_get_target_interface(targ, &intf);

	if (rc==ONEP_OK) {
		onep_if_name name;
		rc = onep_interface_get_name(intf,name);
		printf("Packet arrived on interface [%s]\n",name);
		rc = onep_dpss_pkt_get_l3_protocol(pak, &l3_protocol);
		uint8_t newdscp[1] = {48};

		rc = onep_dpss_modify_packet(pak,
				ONEP_DPSS_LAYER_3,
				1,
				1,
				newdscp,
				1	
				);
		if(rc == ONEP_OK) printf("pack mod\n");

	} else {
		printf("Cant get interface, won't try to explicitly reinject\n");
		return;
	}
	return;
}


int main (int argc, char* argv[]) 
{
	session_handle_t* sh1 = NULL;
	TRY(rc, onep_application_get_instance(&myapp),
			"onep_application_get_instance");
	onep_application_set_name(myapp, "myapp");

	TRY(rc, onep_session_config_new(ONEP_SESSION_SOCKET, &config),
			"onep_session_config_new");
	onep_session_config_set_event_queue_size(
			config, 300);
	onep_session_config_set_event_drop_mode(
			config, ONEP_SESSION_EVENT_DROP_OLD);

	memset(&v4addr, 0, sizeof(struct sockaddr_in));
	v4addr.sin_family = AF_INET;
	inet_pton(AF_INET, "171.71.16.77", &(v4addr.sin_addr));
	TRY(rc, onep_application_get_network_element(
				myapp, (struct sockaddr*)&v4addr, &ne1),
			"onep_application_get_network_element");

	TRY(rc, onep_element_connect(ne1, "user1", "pass1", config, &sh1),
			"onep_element_connect");

	onep_interface_filter_new(&intf_filter);
	rc = onep_element_get_interface_list(ne1, intf_filter, &intfs);

	rc = onep_collection_get_size(intfs, &count);
	if (count <= 0 ) {
		fprintf(stderr, "\nNo interfaces available");
		return ONEP_FAIL;
	}
	onep_collection_get_by_index(intfs, 2, (void *)&intf);
	rc = onep_interface_get_name(intf, name);

	onep_acl_create_l3_acl(AF_INET, ne1, &acl);
	onep_acl_create_l3_ace(1, TRUE, &ace); // seq#, permit, ace obj
	onep_acl_set_l3_ace_protocol(ace, ONEP_PROTOCOL_ALL);
	onep_acl_set_l3_ace_src_prefix(ace, NULL, 24);
	onep_acl_set_l3_ace_dst_prefix(ace, NULL, 24);
	onep_acl_add_ace(acl, ace);
	
	onep_policy_create_class(ne1, ONEP_CLASS_OPER_OR, &acl_class);  
	onep_policy_create_acl_filter(acl, &acl_filter);
	onep_policy_add_class_filter(acl_class, acl_filter);

	onep_dpss_packet_loop_start(1, &pak_loop);
	onep_dpss_initialize(&dpss_handle, "dpss_tutorial", ne1);
	onep_dpss_packet_loop_register_dpss_handle(pak_loop, dpss_handle);

	onep_policy_create_interface_target(intf, ONEP_TARGET_LOCATION_HARDWARE_DEFINED_OUTPUT, &targ);
	onep_dpss_register_for_packets(dpss_handle, 
			targ, 
			acl_class,
			ONEP_DPSS_ACTION_PUNT,
			dpss_tutorial_pak_injector, 
			0, 
			&reg_handle);
	printf ("Registered for packets on interface %s\n", name);
	printf("Press Enter to end program.\n");
	getchar();
	return EXIT_SUCCESS;
}
