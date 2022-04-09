CREATE TABLE IF NOT EXISTS network.isps (
  isp TEXT NOT NULL,
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (isp)
);

CREATE TABLE IF NOT EXISTS network.ips_isps (
  ip INET NOT NULL REFERENCES network.ips (ip),
  isp TEXT NOT NULL REFERENCES network.isps (isp),
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, isp)
);

CREATE INDEX IF NOT EXISTS isps_isp_idx ON network.isps (isp);
CREATE INDEX IF NOT EXISTS ips_isps_ip_and_isp_idx ON network.ips_isps (ip, isp);
