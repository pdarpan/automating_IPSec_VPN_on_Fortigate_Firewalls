# FortiGate IPsec VPN Automation

Automate the deployment of IPsec VPNs across your FortiGate infrastructure with these Python scripts. This repository contains tools to programmatically configure both head office and branch office VPN connections following FortiGate best practices.

## 🔒 Features

- **Complete Automation**: Configure IPsec VPNs without manual CLI or GUI interaction
- **Standardized Deployment**: Ensure consistent configuration across all locations
- **Time-Saving**: Reduce deployment time from hours to minutes
- **Dual-Purpose**: Separate scripts for head office and branch office configurations
- **FortiOS API**: Leverages the FortiGate REST API for reliable automation
- **Error Handling**: Robust validation and error checking throughout the process

## 📋 Requirements

- Python 3.6+
- FortiGate devices running FortiOS 6.0.0 or higher
- Network connectivity to FortiGate management interfaces
- Admin credentials with API access permissions
- Required Python packages:
  - `requests`
  - `argparse`
  - `urllib3`

### Head Office Configuration

The head office script sets up a FortiGate to accept connections from both remote users (dial-up VPN) and branch offices.

```bash
python fortigate-vpn-head-office.py \
  --ip 192.168.1.1 \
  --username admin \
  --vpn-name HeadOfficeVPN \
  --wan-interface wan1 \
  --local-interface lan \
  --local-subnet 192.168.1.0/24 \
  --client-ip-range 10.10.10.1-10.10.10.100 \
  --user-group Employees
```

### Branch Office Configuration

The branch office script configures a FortiGate to establish a site-to-site VPN tunnel to the head office.

```bash
python fortigate-vpn-branch-office.py \
  --ip 192.168.2.1 \
  --username admin \
  --vpn-name BranchVPN \
  --wan-interface wan1 \
  --local-interface lan \
  --local-subnet 192.168.2.0/24 \
  --remote-subnet 192.168.1.0/24 \
  --remote-gateway headoffice.example.com
```

## 🔧 Command Line Arguments

### Head Office Script

| Argument | Description | Required | Default |
|----------|-------------|----------|---------|
| `--ip` | FortiGate IP address | Yes | - |
| `--username` | FortiGate admin username | Yes | - |
| `--vpn-name` | VPN name (max 13 chars, no spaces) | Yes | - |
| `--wan-interface` | External interface | No | wan1 |
| `--local-interface` | Internal interface | No | lan |
| `--local-subnet` | Local subnet (e.g., 192.168.1.0/24) | Yes | - |
| `--client-ip-range` | IP range for VPN clients | Yes | - |
| `--user-group` | User group for VPN users | No | Employees |

### Branch Office Script

| Argument | Description | Required | Default |
|----------|-------------|----------|---------|
| `--ip` | FortiGate IP address | Yes | - |
| `--username` | FortiGate admin username | Yes | - |
| `--vpn-name` | VPN name (max 13 chars, no spaces) | Yes | - |
| `--wan-interface` | External interface | No | wan1 |
| `--local-interface` | Internal interface | No | lan |
| `--local-subnet` | Local subnet (e.g., 192.168.2.0/24) | Yes | - |
| `--remote-subnet` | Remote subnet at head office | Yes | - |
| `--remote-gateway` | Head office FortiGate public IP or FQDN | Yes | - |

## 🏗️ What Gets Configured

### Head Office Script
- User group for remote VPN users
- Address objects for local networks
- IPsec VPN phase 1 settings (dial-up configuration)
- IPsec VPN phase 2 settings
- Security policies to allow traffic

### Branch Office Script
- Address objects for local and remote networks
- IPsec VPN phase 1 settings (site-to-site configuration)
- IPsec VPN phase 2 settings
- Static routes to direct traffic through the VPN
- Bidirectional security policies

## 🔍 Verification

After running the scripts, you can verify the configuration:

1. Log in to the FortiGate web UI
2. Navigate to **VPN > IPsec Tunnels** to see the configured tunnels
3. Check **Policy & Objects > IPv4 Policy** to view the created security policies
4. For branch offices, verify **Network > Static Routes** for the VPN routes

## 📊 Sample Network Topology

```
┌───────────────┐             Internet            ┌───────────────┐
│               │                                 │               │
│  Head Office  │◄─────IPsec VPN Tunnels────────►│ Branch Office │
│  FortiGate    │                                 │  FortiGate    │
│               │                                 │               │
└───────┬───────┘                                 └───────┬───────┘
        │                                                 │
   ┌────▼────┐                                       ┌────▼────┐
   │ 192.168.│                                       │ 192.168.│
   │ 1.0/24  │                                       │ 2.0/24  │
   └─────────┘                                       └─────────┘
        ▲                                       
        │                               
        │ Client VPNs                   
        │                               
┌───────▼───────┐                       
│               │                       
│ Remote Users  │                       
│ (FortiClient) │                       
│               │                       
└───────────────┘                       
```

## 🛠️ Troubleshooting

### Common Issues

1. **API Connection Issues**
   - Ensure the FortiGate has API access enabled
   - Verify network connectivity to the FortiGate management interface
   - Check if HTTPS admin access is allowed on the interface

2. **Permission Errors**
   - Ensure the admin account has sufficient privileges 
   - Try using the 'super_admin' profile for testing

3. **VPN Not Establishing**
   - Verify pre-shared keys match between locations
   - Check that firewall policies are correctly configured
   - Ensure NAT is properly configured for external access

## 🔄 Future Enhancements

- Support for certificate-based authentication
- Multi-site hub and spoke configuration
- Configuration backup and restore
- FortiClient profile generation
- Advanced VPN monitoring capabilities
- Support for SD-WAN integration

## 🙏 Acknowledgements

- Based on FortiGate VPN configuration best practices
- Developed with reference to the [FortiGate Cookbook](https://docs.fortinet.com/document/fortigate/5.6.0/cookbook/786021/configuring-the-ipsec-vpn)
