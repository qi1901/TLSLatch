#ifndef TCPRA_UNIFIED_FLOW_SELECTOR_H
#define TCPRA_UNIFIED_FLOW_SELECTOR_H

#include <stdint.h>

#include "flow_gate.h"

struct tcpra_flow_selector;

struct tcpra_flow_selector *tcpra_flow_selector_open(const char *object_path, const char *server_ip,
                                                     uint16_t server_port,
                                                     const char *pin_directory);
struct tcpra_flow_selector *tcpra_flow_selector_open_capture(const char *object_path,
                                                             const char *server_ip,
                                                             uint16_t server_port,
                                                             const char *pin_directory);
int tcpra_flow_selector_map_fd(const struct tcpra_flow_selector *selector);
int tcpra_flow_selector_capture_program_fd(const struct tcpra_flow_selector *selector);
int tcpra_flow_selector_delete(struct tcpra_flow_selector *selector, const struct flow_key *flow);
void tcpra_flow_selector_close(struct tcpra_flow_selector *selector);

#endif
