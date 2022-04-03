DROP INDEX IF EXISTS network.ports_port_idx;
DROP INDEX IF EXISTS network.ips_ports_ip_and_port_idx;

DROP TABLE IF EXISTS network.ports CASCADE;
DROP TABLE IF EXISTS network.ips_ports CASCADE;
