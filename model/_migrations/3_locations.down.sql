DROP INDEX IF EXISTS network.locations_city_and_country_idx;
DROP INDEX IF EXISTS network.ips_locations_ip_idx;

DROP TABLE IF EXISTS network.locations CASCADE;
DROP TABLE IF EXISTS network.ips_locations CASCADE;
