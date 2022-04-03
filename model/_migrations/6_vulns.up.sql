CREATE TABLE IF NOT EXISTS network.vulns (
  type TEXT NOT NULL,
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (type)
);

CREATE TABLE IF NOT EXISTS network.ips_vulns (
  ip INET NOT NULL REFERENCES network.ips (ip),
  type TEXT NOT NULL REFERENCES network.vulns (type),
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, type)
);

CREATE INDEX IF NOT EXISTS vulns_type_idx ON network.vulns (type);
CREATE INDEX IF NOT EXISTS ips_vulns_ip_and_type_idx ON network.ips_vulns (ip, type);
