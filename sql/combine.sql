attach 'session-to_merge.sqlite' as toMerge;
BEGIN;
    insert into work_items select * from toMerge.work_items;
    insert into mutation_specs select * from toMerge.mutation_specs;
    insert into work_results select * from toMerge.work_results;
COMMIT;
detach toMerge;
