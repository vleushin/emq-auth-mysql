%%--------------------------------------------------------------------
%% Copyright (c) 2012-2017 Feng Lee <feng@emqtt.io>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_mysql).

-behaviour(emqttd_auth_mod).

-include_lib("emqttd/include/emqttd.hrl").

-import(emq_auth_mysql_cli, [is_superuser/2, query/3]).

-export([init/1, check/3, description/0]).

-record(state, {auth_query, super_query, hash_type}).

-define(EMPTY(Username), (Username =:= undefined orelse Username =:= <<>>)).

init({AuthQuery, SuperQuery, HashType}) ->
    {ok, #state{auth_query = AuthQuery, super_query = SuperQuery, hash_type = HashType}}.

check(#mqtt_client{username = Username}, Password, _State) when ?EMPTY(Username); ?EMPTY(Password) ->
    {error, username_or_password_undefined};

check(Client, Password, #state{
    auth_query = {AuthSql, AuthParams},
    super_query = SuperQuery,
    hash_type = HashType}) ->
    Result = case check_client_id(Client) of
                 ok ->
                     case query(AuthSql, AuthParams, Client) of
                         {ok, [<<"password">>], [[PassHash]]} ->
                             check_pass(PassHash, Password, HashType);
                         {ok, [<<"password">>, <<"salt">>], [[PassHash, Salt]]} ->
                             check_pass(PassHash, Salt, Password, HashType);
                         {ok, _Columns, []} ->
                             {error, notfound};
                         {error, Reason} ->
                             {error, Reason}
                     end;
                 _Error -> _Error
             end,
    case Result of
        ok ->
            {ok, is_superuser(SuperQuery, Client)};
        Error -> Error
    end.

check_pass(PassHash, Password, HashType) ->
    check_pass(PassHash, hash(HashType, Password)).
check_pass(PassHash, Salt, Password, {salt, HashType}) ->
    check_pass(PassHash, hash(HashType, <<Salt/binary, Password/binary>>));
check_pass(PassHash, Salt, Password, {HashType, salt}) ->
    check_pass(PassHash, hash(HashType, <<Password/binary, Salt/binary>>)).

check_pass(PassHash, PassHash) ->
    ok;
check_pass(_, _) ->
    {error, password_error}.

description() ->
    "Authentication with MySQL".

hash(Type, Password) ->
    emqttd_auth_mod:passwd_hash(Type, Password).

% We expect ClientId to be in format username_someid to prevent ClientId abuse
check_client_id(#mqtt_client{username = Username, client_id = ClientId}) ->
    case byte_size(ClientId) =< byte_size(Username) + 1 of
        true ->
            {error, "Bad client id"};
        false ->
            ExpectedScope = {0, byte_size(Username) + 1},
            case binary:match(ClientId, <<Username/binary, "_">>, [{scope, ExpectedScope}]) of
                ExpectedScope ->
                    ok;
                _Rest ->
                    {error, "Bad client id"}
            end
    end.