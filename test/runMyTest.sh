tmux new -s bird -d
tmux neww -n bird1 -t 1 ip netns exec net1 bird -c bird1.conf -d -s "bird1"
tmux neww -n router -t 2 ip netns exec net2 /home/yyr/Work/Router-Lab/Homework/boilerplate/boilerplate
tmux neww -n bird3 -t 3 ip netns exec net3 bird -c bird3.conf -d -s "bird3"
tmux a
