delete from mutation_specs where job_id in (select job_id from to_del where to_del.ID % 20 != %SHARD%);
delete from work_items where job_id in (select job_id from to_del where to_del.ID % 20 != %SHARD%);
drop table to_del;
