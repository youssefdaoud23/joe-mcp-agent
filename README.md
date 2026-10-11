# Joe MCP Agent

Lightweight managed-node runtime for Joe-MCP-Server.

Version: `0.27.4`  
Source controller commit: `0b2b62eff62696b3a2df23126540b668b453c5bf`

This repository contains only the customer-node agent/runtime exported from the private Joe-MCP-Server source tree. It does **not** contain the Joe controller, customer web application, authentication database, tenant administration, MCP server, billing, or platform-admin code.

## Normal installation

Normal users do not need to clone this repository. In Joe-MCP-Server, open **Devices -> Add Device**, copy the generated one-time command, and run it with `sudo` on the Linux server you want to connect.

The installer:

- requires Linux with systemd;
- downloads the versioned agent package from your Joe-MCP-Server controller over HTTPS;
- verifies the package SHA-256 checksum;
- installs the guarded host bridge and persistent-session host;
- enrolls the machine using the one-time account-bound token;
- starts the outbound-only managed agent;
- opens no inbound management port.

## Trust boundary

The agent connects outbound to the configured Joe-MCP-Server controller. Remote actions remain subject to both the controller account/device policy and the managed node's local action/workspace policy.

Joe-MCP-Server deliberately does not expose an unrestricted root shell, arbitrary PID termination, unrestricted filesystem access, arbitrary Docker exec, force push, or raw secret-bearing history.

## Source of truth

Do not edit exported runtime files independently. The private `joe-mcp-server` repository is the source of truth. Public releases are generated from its explicit managed-agent manifest and should be replaced by the next generated export rather than manually merged.

## Security

See `SECURITY.md`. Never commit enrollment tokens, device credentials, Git credentials, `.env` files, controller data, customer data, or runtime state to this repository.
