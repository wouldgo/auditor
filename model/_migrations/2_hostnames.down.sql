DROP INDEX IF EXISTS network.hostnames_hostname_idx;
DROP INDEX IF EXISTS network.ips_hostnames_ip_hostname_idx;

DROP TABLE IF EXISTS network.hostnames CASCADE;
DROP TABLE IF EXISTS network.ips_hostnames CASCADE;
