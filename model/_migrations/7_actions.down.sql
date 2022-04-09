DROP INDEX IF EXISTS network.subjects_id_idx;
DROP INDEX IF EXISTS network.subjects_src_ip_and_dst_ip_idx;
DROP INDEX IF EXISTS network.actions_subject_fk_idx;
DROP INDEX IF EXISTS network.actions_subject_fk_create_date_idx;

DROP TABLE IF EXISTS network.actions CASCADE;
DROP TABLE IF EXISTS network.subjects CASCADE;
