"""Restricted egress proxy for the isolated fetcher (Milestone B). Standard library only.

The fetcher's Docker network is `internal`: it has no route to anything but this proxy. The
proxy accepts only HTTPS CONNECT tunnels to an exact allowlist of host names on port 443,
resolves each name itself, refuses the tunnel if ANY resolved address is not public, and then
connects to an address it validated (DNS-rebinding safe: the client never supplies an IP, and
the name is never resolved twice). See docs/security/fetcher.md.
"""
