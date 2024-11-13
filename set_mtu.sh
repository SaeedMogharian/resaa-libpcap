#!/bin/bash

# Check if the user has provided at least one interface
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <interface1> [interface2 ... interfaceN]"
    exit 1
fi

# Iterate over each interface provided as an argument
for iface in "$@"; do
    # Check if the interface exists
    if ip link show "$iface" > /dev/null 2>&1; then
        echo "Setting MTU to 9000 on interface: $iface"
        sudo ip link set dev "$iface" mtu 9000
        
        # Verify the change
        current_mtu=$(ip link show "$iface" | grep -oP 'mtu \K[0-9]+')
        if [ "$current_mtu" -eq 9000 ]; then
            echo "Successfully set MTU on $iface to $current_mtu."
        else
            echo "Failed to set MTU on $iface. Current MTU is $current_mtu."
        fi
    else
        echo "Error: Interface $iface does not exist."
    fi
done
