-- +goose Up
create table subscriptions
(
    id           bigint generated always as identity primary key,
    chat_id      bigint      not null,
    product      text        not null check (product != ''),
    version      text check ( version != ''),
    min_severity int check (min_severity between 1 and 4) default 1 not null,
    kev          bool        not null                     default false,
    created_at   timestamptz not null                     default now(),
    unique nulls not distinct (chat_id, product, version)
);

-- +goose Down
drop table subscriptions;
