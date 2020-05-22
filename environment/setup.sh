echo "Cleaning up enviornment before creation..."
echo "--------------"
(set -x; ip netns delete ns-gateway)
(set -x; ip link delete gw0)
echo "Done..."

echo "Mounting BPF Map"
echo "--------------"
(set -x; mount -t bpf bpf /sys/fs/bpf/)
echo "Done..."

echo "Enabling IPV4 forwarding..."
echo "--------------"
(set -x; sysctl -w net.ipv4.ip_forward=1)
echo "Done..."

echo "Creating namespace..."
echo "--------------"
(set -x; ip netns add ns-gateway)
echo "Done..."

echo "Adding gateway links..."
echo "--------------"
(set -x; ip link add gw0 type veth peer name gw1)
(set -x; ip link set gw1 netns ns-gateway)
(set -x; ip link set dev gw0 address 02:00:00:00:01:00)
(set -x; ip addr add 10.0.0.1 dev gw0)
echo "Done..."

echo "Enabling gateway links"
echo "--------------"
(set -x; ip link set gw0 up)
(set -x; ip netns exec ns-gateway ip link set gw1 up)
echo "Done..."

echo "Adding ARP entries"
echo "--------------"
(set -x; arp -i gw0 -s 10.0.0.2 02:00:00:00:00:01)
(set -x; arp -i gw0 -s 10.0.0.3 02:00:00:00:00:02)
echo "Done..."

echo "Adding route entry"
echo "--------------"
(set -x; ip route add 10.0.0.0/24 via 0.0.0.0 dev gw0)
echo "Done..."