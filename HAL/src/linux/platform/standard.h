#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "veth-2l",
    "veth-2r",
    "eth3",
    "eth4",
};
