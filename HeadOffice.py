#!/usr/bin/env python3
"""
FortiGate Head Office IPsec VPN Configuration Script

This script automates the configuration of the head office side of an IPsec VPN 
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
    parser = argparse.ArgumentParser(description='Configure FortiGate Head Office IPsec VPN')
    parser.add_argument('--ip', required=True, help='FortiGate IP address')
    parser.add_argument('--username', required=True, help='FortiGate admin username')
    parser.add_argument('--vpn-name', required=True, help='VPN name (max 13 chars, no spaces)')
    parser.add_argument('--wan-interface', default='wan1', help='External interface (default: wan1)')
    parser.add_argument('--local-interface', default='lan', help='Internal interface (default: lan)')
    parser.add_argument('--local-subnet', required=True, help='Local subnet (e.g., 192.168.1.0/24)')
    parser.add_argument('--client-ip-range', required=True, help='IP range for VPN clients (e.g., 10.10.10.1-10.10.10.100)')
    parser.add_argument('--user-group', default='Employees', help='User group for VPN users (default: Employees)')
    
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

def create_user_group(ip, token, group_name):
    # Check if user group already exists
    result = api_request(ip, "cmdb/user/group", "GET", token)
    if result and 'results' in result:
        for group in result['results']:
            if group['name'] == group_name:
                print(f"User group '{group_name}' already exists.")
                return True
    
    # Create user group if it doesn't exist
    group_data = {
        "name": group_name,
        "member": [],
        "member-attr": []
    }
    
    result = api_request(ip, "cmdb/user/group", "POST", token, group_data)
    if result:
        print(f"Created user group '{group_name}'.")
        return True
    else:
        print(f"Failed to create user group '{group_name}'.")
        return False

def create_address_object(ip, token, name, subnet):
    # Check if address object already exists
    result = api_request(ip, "cmdb/firewall/address", "GET", token)
    if result and 'results' in result:
        for addr in result['results']:
            if addr['name'] == name:
                print(f"Address object '{name}' already exists.")
                return True
    
    # Create address object if it doesn't exist
    address_data = {
        "name": name,
        "type": "subnet",
        "subnet": subnet
    }
    
    result = api_request(ip, "cmdb/firewall/address", "POST", token, address_data)
    if result:
        print(f"Created address object '{name}' for subnet {subnet}.")
        return True
    else:
        print(f"Failed to create address object '{name}'.")
        return False

def configure_ipsec_vpn(ip, token, args):
    vpn_data = {
        "name": args.vpn_name,
        "type": "dial-up",
        "interface": args.wan_interface,
        "peertype": "dialup",
        "proposal": "aes128-sha256 aes256-sha256 aes128-sha1 aes256-sha1",
        "dhgrp": "14 5",
        "psksecret": getpass("Enter pre-shared key: "),
        "usrgrp": args.user_group,
        "ipv4-start-ip": args.client_ip_range.split('-')[0],
        "ipv4-end-ip": args.client_ip_range.split('-')[1],
        "ipv4-split-include": args.local_subnet,
        "mode-cfg": "enable",
        "comments": "Created via automation script"
    }
    
    result = api_request(ip, "cmdb/vpn.ipsec/phase1-interface", "POST", token, vpn_data)
    if not result:
        print("Failed to configure IPsec VPN phase 1.")
        return False
    
    # Configure phase 2
    phase2_data = {
        "name": args.vpn_name,
        "phase1name": args.vpn_name,
        "proposal": "aes128-sha1 aes256-sha1 aes128-sha256 aes256-sha256",
        "pfs": "enable",
        "dhgrp": "14 5",
        "comments": "Created via automation script"
    }
    
    result = api_request(ip, "cmdb/vpn.ipsec/phase2-interface", "POST", token, phase2_data)
    if not result:
        print("Failed to configure IPsec VPN phase 2.")
        return False
    
    print(f"Successfully configured IPsec VPN '{args.vpn_name}'.")
    return True

def create_firewall_policy(ip, token, args):
    # Create policy allowing VPN users to access the internal network
    policy_data = {
        "name": f"VPN-{args.vpn_name}-Policy",
        "srcintf": [{"name": args.vpn_name}],
        "dstintf": [{"name": args.local_interface}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": f"Local-Subnet-{args.vpn_name}"}],
        "action": "accept",
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "nat": "disable",
        "groups": [{"name": args.user_group}],
        "comments": "Allow VPN users to access local network"
    }
    
    result = api_request(ip, "cmdb/firewall/policy", "POST", token, policy_data)
    if result:
        print(f"Created firewall policy for VPN {args.vpn_name}.")
        return True
    else:
        print("Failed to create firewall policy.")
        return False

def main():
    args = parse_args()
    validate_args(args)
    
    password = getpass(f"Enter password for {args.username}: ")
    token = get_token(args.ip, args.username, password)
    if not token:
        sys.exit(1)
    
    # Create required objects
    if not create_user_group(args.ip, token, args.user_group):
        sys.exit(1)
    
    local_subnet_name = f"Local-Subnet-{args.vpn_name}"
    if not create_address_object(args.ip, token, local_subnet_name, args.local_subnet):
        sys.exit(1)
    
    # Configure VPN
    if not configure_ipsec_vpn(args.ip, token, args):
        sys.exit(1)
    
    # Create firewall policy
    if not create_firewall_policy(args.ip, token, args):
        sys.exit(1)
    
    print("\nIPsec VPN configuration completed successfully!")
    print(f"VPN Name: {args.vpn_name}")
    print(f"External Interface: {args.wan_interface}")
    print(f"User Group: {args.user_group}")
    print(f"Local Network: {args.local_subnet}")
    print(f"Client IP Range: {args.client_ip_range}")

if __name__ == "__main__":
    main()