tmux new -s bird -d
tmux neww -n bird0 -t 1 ip netns exec net0 bird -c bird0.conf -d -s "bird0"
tmux neww -n bird1 -t 2 ip netns exec net1 bird -c bird1.conf -d -s "bird1"
tmux neww -n bird2 -t 3 ip netns exec net2 bird -c bird2.conf -d -s "bird2"
tmux neww -n bird3 -t 4 ip netns exec net3 bird -c bird3.conf -d -s "bird3"
tmux neww -n bird4 -t 5 ip netns exec net4 bird -c bird4.conf -d -s "bird4"
ip netns exec net0 sysctl -w net.ipv4.ip_forward=1
ip netns exec net1 sysctl -w net.ipv4.ip_forward=1
ip netns exec net2 sysctl -w net.ipv4.ip_forward=1
ip netns exec net3 sysctl -w net.ipv4.ip_forward=1
ip netns exec net4 sysctl -w net.ipv4.ip_forward=1
tmux a