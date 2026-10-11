# Security Policy

## Sensitive data

This public agent repository must never contain:

- Joe-MCP-Server controller authentication state or customer data;
- enrollment tokens or managed-device credentials;
- GitHub tokens, passwords, private keys, API keys, tunnel credentials, or `.env` files;
- controller-only web, authentication, tenant, billing, routing, or deployment-runner source.

## Reporting a vulnerability

Do not publish secrets, credentials, exploit details against a live deployment, or customer data in a public issue. Report security problems privately to the Joe-MCP-Server operator/maintainer.

## Runtime model

The managed agent is designed for outbound HTTPS control, local fail-closed policy, bounded operations, redacted output, and explicit authorization of mutations. Public source visibility does not grant access to any Joe-MCP-Server deployment.
