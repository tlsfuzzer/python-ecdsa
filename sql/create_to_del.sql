create table to_del (job_id VARCHAR NOT NULL, id INTEGER PRIMARY KEY);
insert into to_del select *, ROWID from work_items;
