# Adblock Filters & Tools

This repository maintains several automated workflows for filtering and updating adblock rules and IPTV lists.

## 1. Filtered M3U (IPTV)

Automated filtering and processing of IPTV M3U playlists.

- **HTTPS Channels**: [filtered_https_only.m3u](filtered_https_only.m3u)
  - Contains only IPv4/MyIPTV channels using HTTPS.
  - Excludes specific channels (e.g., CGTN).

- **HTTP Valid Channels**: [filtered_http_only_valid.m3u](filtered_http_only_valid.m3u)
  - Contains valid HTTP channels.

- **Global (Attributes Removed)**: [filtered_global_attributes_removed.m3u](filtered_global_attributes_removed.m3u)
  - Sourced from global lists with specific attributes (like `tvg-logo`, `tvg-id`) removed for cleaner lists.

**Update Frequency**: Every 6 hours.

## 2. AdGuard DNS Filter (X DNS)

High-quality AdGuard DNS filter rules with automated validation to remove invalid (NXDOMAIN) domains.

- **Combined List**: [a11b11.txt](a11b11.txt)
  - Use this for best coverage. Combined validated rules from multiple sources.

- **Source A Unique**: [a11.txt](a11.txt)
  - Unique validated rules from Source A.

- **Source B Unique**: [b11.txt](b11.txt)
  - Unique validated rules from Source B.

**Update Frequency**: Daily (20:15 UTC).

## 3. X Filter

Merged general adblock rules.

- **Rule List**: [xfilter.txt](xfilter.txt)

**Update Frequency**: Daily (00:00 UTC).

---

### Workflows

| Name | File | Description |
|------|------|-------------|
| **Update Filtered M3U** | `update_m3u.yml` | Processes M3U playlists (Merge, Filter, Attribute Removal). |
| **x abc dns1** | `adguard-dns.yml` | Updates AdGuard DNS rules with domain validation. |
| **X Filter** | `xfilter.yml` | Usage for general adblock rule merging. |
