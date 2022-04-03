DROP INDEX IF EXISTS network.isps_isp_idx;
DROP INDEX IF EXISTS network.ips_isps_ip_and_isp_idx;

DROP TABLE IF EXISTS network.isps CASCADE;
DROP TABLE IF EXISTS network.ips_isps CASCADE;
