%%--------------------------------------------------------------------
%% Copyright (c) 2013-2017 EMQ Enterprise, Inc. (http://emqtt.io)
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

%% @doc MySQL Authentication/ACL Client
-module(emq_auth_mysql_cli).

-behaviour(ecpool_worker).

-include("emq_auth_mysql.hrl").

-include_lib("emqttd/include/emqttd.hrl").

-export([is_superuser/3, parse_query/1, connect/1, query/4]).

%%--------------------------------------------------------------------
%% Is Superuser?
%%--------------------------------------------------------------------

-spec(is_superuser(undefined | {string(), list()}, string(), mqtt_client()) -> boolean()).
is_superuser(undefined, _Password, _Client) ->
    false;
is_superuser({SuperSql, Params}, Password, Client) ->
    case query(SuperSql, Params, Password, Client) of
        {ok, [_Super], [[1]]} ->
            true;
        {ok, [_Super], [[_False]]} ->
            false;
        {ok, [_Super], []} ->
            false;
        {error, _Error} ->
            false
    end.

%%--------------------------------------------------------------------
%% Avoid SQL Injection: Parse SQL to Parameter Query.
%%--------------------------------------------------------------------

parse_query(undefined) ->
    undefined;
parse_query(Sql) ->
    case re:run(Sql, "'%[ucap]'", [global, {capture, all, list}]) of
        {match, Variables} ->
            Params = [Var || [Var] <- Variables],
            {re:replace(Sql, "'%[ucap]'", "?", [global, {return, list}]), Params};
        nomatch ->
            {Sql, []}
    end.

%%--------------------------------------------------------------------
%% MySQL Connect/Query
%%--------------------------------------------------------------------

connect(Options) ->
    mysql:start_link(Options).

query(Sql, Params, Password, Client) ->
    ecpool:with_client(?APP, fun(C) -> mysql:query(C, Sql, replvar(Params, Password, Client)) end).

replvar(Params, Password, Client) ->
    replvar(Params, Password, Client, []).

replvar([], _Password, _Client, Acc) ->
    lists:reverse(Acc);
replvar(["'%u'" | Params], Password, Client = #mqtt_client{username = Username}, Acc) ->
    replvar(Params, Password, Client, [Username | Acc]);
replvar(["'%c'" | Params], Password, Client = #mqtt_client{client_id = ClientId}, Acc) ->
    replvar(Params, Password, Client, [ClientId | Acc]);
replvar(["'%a'" | Params], Password, Client = #mqtt_client{peername = {IpAddr, _}}, Acc) ->
    replvar(Params, Password, Client, [inet_parse:ntoa(IpAddr) | Acc]);
replvar(["'%p'" | Params], Password, Client, Acc) ->
    replvar(Params, Password, Client, [Password | Acc]);
replvar([Param | Params], Password, Client, Acc) ->
    replvar(Params, Password, Client, [Param | Acc]).

