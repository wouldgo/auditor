DROP INDEX IF EXISTS network.vulns_type_idx;
DROP INDEX IF EXISTS network.ips_vulns_ip_and_type_idx;

DROP TABLE IF EXISTS network.vulns CASCADE;
DROP TABLE IF EXISTS network.ips_vulns CASCADE;
