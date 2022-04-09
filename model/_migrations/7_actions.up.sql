CREATE TABLE IF NOT EXISTS network.subjects (
  id BIGSERIAL UNIQUE NOT NULL,
  src_ip   INET   NOT NULL REFERENCES network.ips       (ip),
  dst_ip   INET   NOT NULL REFERENCES network.ips       (ip),
  PRIMARY KEY (src_ip, dst_ip)
);

CREATE INDEX IF NOT EXISTS subjects_id_idx ON network.subjects (id);
CREATE INDEX IF NOT EXISTS subjects_src_ip_and_dst_ip_idx ON network.subjects (src_ip, dst_ip);

CREATE TABLE IF NOT EXISTS network.actions (
  subject_fk  BIGINT                   NOT NULL REFERENCES network.subjects  (id),
  hostname    TEXT                              REFERENCES network.hostnames (hostname),
  src_port    INTEGER                           REFERENCES network.ports     (port),
  dst_port    INTEGER                           REFERENCES network.ports     (port),
  create_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (subject_fk, create_date)
);

CREATE INDEX IF NOT EXISTS actions_subject_fk_idx ON network.actions (subject_fk);
CREATE INDEX IF NOT EXISTS actions_subject_fk_create_date_idx ON network.actions (subject_fk, create_date);
