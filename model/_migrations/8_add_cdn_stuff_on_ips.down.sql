DROP INDEX IF EXISTS network.cdns_cdn_idx;
DROP INDEX IF EXISTS network.ips_cdn_fk_idx;

ALTER TABLE network.ips
  DROP COLUMN IF EXISTS is_cdn CASCADE,
  DROP COLUMN IF EXISTS cdn_fk CASCADE;

DROP TABLE IF EXISTS network.cdns CASCADE;
