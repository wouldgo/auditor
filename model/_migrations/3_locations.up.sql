CREATE TABLE IF NOT EXISTS network.locations (
  id BIGSERIAL UNIQUE NOT NULL,
  city TEXT NOT NULL,
  country TEXT NOT NULL,
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (city, country)
);

CREATE TABLE IF NOT EXISTS network.ips_locations (
  ip INET NOT NULL REFERENCES network.ips (ip),
  location_fk BIGINT NOT NULL REFERENCES network.locations (id),
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, location_fk)
);

CREATE INDEX IF NOT EXISTS locations_id_idx ON network.locations (id);
CREATE INDEX IF NOT EXISTS locations_city_and_country_idx ON network.locations (city, country);
CREATE INDEX IF NOT EXISTS ips_locations_ip_and_location_fk_idx ON network.ips_locations (ip, location_fk);
CREATE INDEX IF NOT EXISTS ips_locations_location_fk_idx ON network.ips_locations (location_fk);
