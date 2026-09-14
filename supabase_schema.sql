create table if not exists public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    username text unique not null,
    coins integer not null default 0 check (coins >= 0),
    correct_answers integer not null default 0 check (correct_answers >= 0),
    character jsonb not null default jsonb_build_object(
        'inventory', '[]'::jsonb,
        'equipped', jsonb_build_object(
            'shirt', '#4caf50',
            'hair', '#4b2e1f',
            'accessory', ''
        )
    ),
    created_at timestamptz not null default now()
);

create table if not exists public.game_state (
    id boolean primary key default true check (id),
    announcement text not null default '',
    multiplier integer not null default 1 check (multiplier in (1, 2, 4, 10, 20, 100)),
    coin_event_active boolean not null default false,
    poll jsonb,
    updated_at timestamptz not null default now()
);

alter table public.game_state add column if not exists poll jsonb;
alter table public.profiles add column if not exists correct_answers integer not null default 0;

insert into public.game_state (id)
values (true)
on conflict (id) do nothing;

alter table public.profiles enable row level security;
alter table public.game_state enable row level security;

drop policy if exists "Profiles are readable by signed in users" on public.profiles;
create policy "Profiles are readable by signed in users"
on public.profiles for select
to authenticated
using (true);

drop policy if exists "Users can create their own profile" on public.profiles;
create policy "Users can create their own profile"
on public.profiles for insert
to authenticated
with check (auth.uid() = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
on public.profiles for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

drop policy if exists "Signed in users can read game state" on public.game_state;
create policy "Signed in users can read game state"
on public.game_state for select
to authenticated
using (true);

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and username = 'CyberTimo1234'
    ) or coalesce((select raw_user_meta_data ->> 'username' from auth.users where id = auth.uid()), '') = 'CyberTimo1234';
$$;

drop policy if exists "Admin can update game state" on public.game_state;
create policy "Admin can update game state"
on public.game_state for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

create or replace function public.add_coins(target_user uuid, amount integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_admin() or amount = 0 then
        raise exception 'Not allowed';
    end if;

    update public.profiles
    set coins = coins + amount
    where id = target_user;

    if (select coins from public.profiles where id = target_user) < 0 then
        raise exception 'Coins cannot go below 0';
    end if;
end;
$$;

grant execute on function public.add_coins(uuid, integer) to authenticated;

create or replace function public.remove_coins(target_user uuid, amount integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_admin() or amount < 1 then
        raise exception 'Not allowed';
    end if;

    update public.profiles
    set coins = coins - amount
    where id = target_user and coins >= amount;

    if not found then
        raise exception 'Not enough coins or user not found';
    end if;
end;
$$;

grant execute on function public.remove_coins(uuid, integer) to authenticated;

create or replace function public.add_correct_answers(target_user uuid, amount integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_admin() or amount = 0 then
        raise exception 'Not allowed';
    end if;

    update public.profiles
    set correct_answers = correct_answers + amount
    where id = target_user;

    if (select correct_answers from public.profiles where id = target_user) < 0 then
        raise exception 'Correct answers cannot go below 0';
    end if;
end;
$$;

grant execute on function public.add_correct_answers(uuid, integer) to authenticated;

create or replace function public.remove_correct_answers(target_user uuid, amount integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_admin() or amount < 1 then
        raise exception 'Not allowed';
    end if;

    update public.profiles
    set correct_answers = correct_answers - amount
    where id = target_user and correct_answers >= amount;

    if not found then
        raise exception 'Not enough correct answers or user not found';
    end if;
end;
$$;

grant execute on function public.remove_correct_answers(uuid, integer) to authenticated;

create or replace function public.grant_item(target_user uuid, item_id text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    target_profile jsonb;
    current_inventory jsonb;
begin
    if not public.is_admin() or item_id not in (
        'blue-shirt', 'red-shirt', 'gold-hair', 'crown', 'brown-hair',
        'space-shirt', 'space-helmet', 'challenge-jacket', 'challenge-crown'
    ) then
        raise exception 'Not allowed or invalid item';
    end if;

    select character into target_profile from public.profiles where id = target_user for update;
    if target_profile is null then
        raise exception 'User not found';
    end if;

    current_inventory := coalesce(target_profile -> 'inventory', '[]'::jsonb);
    if not current_inventory ? item_id then
        update public.profiles
        set character = jsonb_set(
            coalesce(character, '{}'::jsonb),
            '{inventory}',
            current_inventory || jsonb_build_array(item_id)
        )
        where id = target_user;
    end if;
end;
$$;

grant execute on function public.grant_item(uuid, text) to authenticated;

create or replace function public.remove_item(target_user uuid, item_id text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    target_character jsonb;
    new_inventory jsonb;
begin
    if not public.is_admin() then
        raise exception 'Not allowed';
    end if;

    select character into target_character from public.profiles where id = target_user for update;
    if target_character is null then
        raise exception 'User not found';
    end if;

    new_inventory := coalesce(target_character -> 'inventory', '[]'::jsonb) - item_id;
    update public.profiles
    set character = jsonb_set(
        coalesce(character, '{}'::jsonb),
        '{inventory}',
        new_inventory
    )
    where id = target_user;
end;
$$;

grant execute on function public.remove_item(uuid, text) to authenticated;

drop function if exists public.create_poll(text, text[]);

create or replace function public.create_poll(poll_question text, poll_options text[], duration_seconds integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_admin() or length(trim(poll_question)) = 0 or cardinality(poll_options) < 2 or duration_seconds < 10 then
        raise exception 'Not allowed or invalid poll';
    end if;

    update public.game_state
    set poll = jsonb_build_object(
        'question', trim(poll_question),
        'options', to_jsonb(poll_options),
        'votes', to_jsonb(array_fill(0, array[cardinality(poll_options)])),
        'voters', '[]'::jsonb,
        'expires_at', (now() + make_interval(secs => duration_seconds))::text
    ),
    updated_at = now()
    where id = true;
end;
$$;

create or replace function public.vote_poll(option_index integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    current_poll jsonb;
    current_votes jsonb;
    current_voters jsonb;
    voter_id text := auth.uid()::text;
    next_votes jsonb;
begin
    if auth.uid() is null then
        raise exception 'You must be signed in';
    end if;

    select poll into current_poll from public.game_state where id = true for update;
    if current_poll is null or option_index < 0 or option_index >= jsonb_array_length(current_poll -> 'options') then
        raise exception 'Invalid poll option';
    end if;

    if current_poll ? 'expires_at' and (current_poll ->> 'expires_at')::timestamptz <= now() then
        raise exception 'Poll is closed';
    end if;

    current_voters := coalesce(current_poll -> 'voters', '[]'::jsonb);
    if current_voters ? voter_id then
        raise exception 'You already voted';
    end if;

    current_votes := current_poll -> 'votes';
    next_votes := jsonb_set(
        current_votes,
        array[option_index::text],
        to_jsonb((current_votes ->> option_index)::integer + 1)
    );

    update public.game_state
    set poll = jsonb_set(
        jsonb_set(current_poll, '{votes}', next_votes),
        '{voters}',
        current_voters || jsonb_build_array(voter_id)
    ),
    updated_at = now()
    where id = true;
end;
$$;

grant execute on function public.create_poll(text, text[], integer) to authenticated;
grant execute on function public.vote_poll(integer) to authenticated;

notify pgrst, 'reload schema';

do $$
begin
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'profiles') then
        alter publication supabase_realtime add table public.profiles;
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'game_state') then
        alter publication supabase_realtime add table public.game_state;
    end if;
end;
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.profiles (id, username)
    values (new.id, coalesce(new.raw_user_meta_data ->> 'username', split_part(new.email, '@', 1)));
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();
