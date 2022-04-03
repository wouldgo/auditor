CREATE TABLE IF NOT EXISTS network.ports (
  port INTEGER NOT NULL,
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (port)
);

CREATE TABLE IF NOT EXISTS network.ips_ports (
  ip INET NOT NULL REFERENCES network.ips (ip),
  port INTEGER NOT NULL REFERENCES network.ports (port),
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, port)
);

CREATE INDEX IF NOT EXISTS ports_port_idx ON network.ports (port);
CREATE INDEX IF NOT EXISTS ips_ports_ip_and_port_idx ON network.ips_ports (ip, port);
