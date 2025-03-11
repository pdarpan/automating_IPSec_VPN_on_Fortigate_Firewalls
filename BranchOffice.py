#!/usr/bin/env python3
"""
FortiGate Branch Office IPsec VPN Configuration Script

This script automates the configuration of the branch office side of an IPsec VPN 
using the FortiOS REST API. It follows the configuration guidelines from the FortiGate cookbook.
"""

import requests
import json
import argparse
import sys
import urllib3
from getpass import getpass

# Disable SSL warnings (use in test environments only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(description='Configure FortiGate Branch Office IPsec VPN')
    parser.add_argument('--ip', required=True, help='FortiGate IP address')
    parser.add_argument('--username', required=True, help='FortiGate admin username')
    parser.add_argument('--vpn-name', required=True, help='VPN name (max 13 chars, no spaces)')
    parser.add_argument('--wan-interface', default='wan1', help='External interface (default: wan1)')
    parser.add_argument('--local-interface', default='lan', help='Internal interface (default: lan)')
    parser.add_argument('--local-subnet', required=True, help='Local subnet (e.g., 192.168.2.0/24)')
    parser.add_argument('--remote-subnet', required=True, help='Remote subnet at head office (e.g., 192.168.1.0/24)')
    parser.add_argument('--remote-gateway', required=True, help='Head office FortiGate public IP or FQDN')
    
    return parser.parse_args()

def validate_args(args):
    if len(args.vpn_name) > 13 or ' ' in args.vpn_name:
        print("Error: VPN name cannot include spaces or exceed 13 characters.")
        sys.exit(1)

def api_request(ip, endpoint, method, token, data=None):
    url = f"https://{ip}/api/v2/{endpoint}"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, verify=False)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data, verify=False)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data, verify=False)
        else:
            print(f"Error: Unsupported method {method}")
            return None
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

def get_token(ip, username, password):
    try:
        response = requests.post(
            f"https://{ip}/api/v2/authentication/login",
            json={"username": username, "password": password},
            verify=False
        )
        response.raise_for_status()
        return response.json().get('session')
    except requests.exceptions.RequestException as e:
        print(f"Authentication failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

def create_address_objects(ip, token, args):
    # Create local subnet address object
    local_subnet_name = f"Local-Subnet-{args.vpn_name}"
    local_data = {
        "name": local_subnet_name,
        "type": "subnet",
        "subnet": args.local_subnet
    }
    
    result = api_request(ip, "cmdb/firewall/address", "POST", token, local_data)
    if not result:
        print(f"Failed to create local subnet address object.")
        return False
    
    # Create remote subnet address object
    remote_subnet_name = f"Remote-Subnet-{args.vpn_name}"
    remote_data = {
        "name": remote_subnet_name,
        "type": "subnet",
        "subnet": args.remote_subnet
    }
    
    result = api_request(ip, "cmdb/firewall/address", "POST", token, remote_data)
    if not result:
        print(f"Failed to create remote subnet address object.")
        return False
    
    print(f"Created address objects for local subnet ({args.local_subnet}) and remote subnet ({args.remote_subnet}).")
    return True

def configure_ipsec_vpn(ip, token, args):
    # Phase 1 configuration
    vpn_phase1_data = {
        "name": args.vpn_name,
        "type": "static",
        "interface": args.wan_interface,
        "peertype": "any",
        "proposal": "aes128-sha256 aes256-sha256 aes128-sha1 aes256-sha1",
        "dhgrp": "14 5",
        "remote-gw": args.remote_gateway,
        "psksecret": getpass("Enter pre-shared key (must match head office key): "),
        "comments": "Branch office VPN to head office, created via automation script"
    }
    
    result = api_request(ip, "cmdb/vpn.ipsec/phase1-interface", "POST", token, vpn_phase1_data)
    if not result:
        print("Failed to configure IPsec VPN phase 1.")
        return False
    
    # Phase 2 configuration
    vpn_phase2_data = {
        "name": args.vpn_name,
        "phase1name": args.vpn_name,
        "proposal": "aes128-sha1 aes256-sha1 aes128-sha256 aes256-sha256",
        "pfs": "enable",
        "dhgrp": "14 5",
        "src-addr-type": "subnet",
        "dst-addr-type": "subnet",
        "src-subnet": args.local_subnet.split('/')[0] + " " + args.local_subnet.split('/')[1],
        "dst-subnet": args.remote_subnet.split('/')[0] + " " + args.remote_subnet.split('/')[1],
        "comments": "Phase 2 configuration for branch office VPN"
    }
    
    result = api_request(ip, "cmdb/vpn.ipsec/phase2-interface", "POST", token, vpn_phase2_data)
    if not result:
        print("Failed to configure IPsec VPN phase 2.")
        return False
    
    print(f"Successfully configured IPsec VPN '{args.vpn_name}' to connect to {args.remote_gateway}.")
    return True

def create_static_route(ip, token, args):
    # Create static route to remote subnet via VPN
    route_data = {
        "dst": args.remote_subnet,
        "gateway": "0.0.0.0",
        "device": args.vpn_name,
        "comment": f"Route to head office via {args.vpn_name} VPN"
    }
    
    result = api_request(ip, "cmdb/router/static", "POST", token, route_data)
    if result:
        print(f"Created static route to {args.remote_subnet} via VPN tunnel.")
        return True
    else:
        print("Failed to create static route.")
        return False

def create_firewall_policies(ip, token, args):
    # Local to Remote policy
    outbound_policy = {
        "name": f"{args.vpn_name}-outbound",
        "srcintf": [{"name": args.local_interface}],
        "dstintf": [{"name": args.vpn_name}],
        "srcaddr": [{"name": f"Local-Subnet-{args.vpn_name}"}],
        "dstaddr": [{"name": f"Remote-Subnet-{args.vpn_name}"}],
        "action": "accept",
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "comments": "Allow branch office to access head office"
    }
    
    result = api_request(ip, "cmdb/firewall/policy", "POST", token, outbound_policy)
    if not result:
        print("Failed to create outbound firewall policy.")
        return False
    
    # Remote to Local policy
    inbound_policy = {
        "name": f"{args.vpn_name}-inbound",
        "srcintf": [{"name": args.vpn_name}],
        "dstintf": [{"name": args.local_interface}],
        "srcaddr": [{"name": f"Remote-Subnet-{args.vpn_name}"}],
        "dstaddr": [{"name": f"Local-Subnet-{args.vpn_name}"}],
        "action": "accept",
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "comments": "Allow head office to access branch office"
    }
    
    result = api_request(ip, "cmdb/firewall/policy", "POST", token, inbound_policy)
    if not result:
        print("Failed to create inbound firewall policy.")
        return False
    
    print("Created firewall policies for VPN traffic in both directions.")
    return True

def main():
    args = parse_args()
    validate_args(args)
    
    password = getpass(f"Enter password for {args.username}: ")
    token = get_token(args.ip, args.username, password)
    if not token:
        sys.exit(1)
    
    # Create address objects
    if not create_address_objects(args.ip, token, args):
        sys.exit(1)
    
    # Configure VPN
    if not configure_ipsec_vpn(args.ip, token, args):
        sys.exit(1)
    
    # Create static route
    if not create_static_route(args.ip, token, args):
        sys.exit(1)
    
    # Create firewall policies
    if not create_firewall_policies(args.ip, token, args):
        sys.exit(1)
    
    print("\nIPsec VPN configuration completed successfully!")
    print(f"VPN Name: {args.vpn_name}")
    print(f"External Interface: {args.wan_interface}")
    print(f"Local Network: {args.local_subnet}")
    print(f"Remote Network: {args.remote_subnet}")
    print(f"Remote Gateway: {args.remote_gateway}")
    print("\nThe branch office is now configured to connect to the head office.")

if __name__ == "__main__":
    main()