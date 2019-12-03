ip netns add net1
ip netns add net2
ip netns add net3
ip link add veth-1r type veth peer name veth-2l
ip link add veth-2r type veth peer name veth-3l
ip link set veth-1r netns net1
ip link set veth-2l netns net2
ip link set veth-2r netns net2
ip link set veth-3l netns net3
ip netns exec net1 ip addr add 192.168.3.1/24 dev veth-1r
ip netns exec net2 ip addr add 192.168.3.2/24 dev veth-2l
ip netns exec net2 ip addr add 192.168.4.1/24 dev veth-2r
ip netns exec net3 ip addr add 192.168.4.2/24 dev veth-3l
ip netns exec net1 ip link set veth-1r up
ip netns exec net2 ip link set veth-2l up
ip netns exec net2 ip link set veth-2r up
ip netns exec net3 ip link set veth-3l up
