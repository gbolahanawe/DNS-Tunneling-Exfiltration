# DNS Tunneling Lab Setup

## Step 1: DNS Server and Zone Configuration

Ensure your attacker machine at `172.16.50.54` is running a DNS server with a configured zone for `mydomain.local`.

Test DNS resolution from the victim machine:
```bash
nslookup test.mydomain.local 172.16.50.54
