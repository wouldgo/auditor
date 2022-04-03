CREATE TABLE IF NOT EXISTS network.hostnames (
  hostname TEXT NOT NULL,
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (hostname)
);

CREATE TABLE IF NOT EXISTS network.ips_hostnames (
  ip INET NOT NULL REFERENCES network.ips (ip),
  hostname TEXT NOT NULL REFERENCES network.hostnames (hostname),
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, hostname)
);

CREATE INDEX IF NOT EXISTS hostnames_hostname_idx ON network.hostnames (hostname);
CREATE INDEX IF NOT EXISTS ips_hostnames_ip_hostname_idx ON network.ips_hostnames (ip, hostname);
