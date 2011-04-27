%%  The contents of this file are subject to the Mozilla Public License
%%  Version 1.1 (the "License"); you may not use this file except in
%%  compliance with the License. You may obtain a copy of the License
%%  at http://www.mozilla.org/MPL/
%%
%%  Software distributed under the License is distributed on an "AS IS"
%%  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%%  the License for the specific language governing rights and
%%  limitations under the License.
%%
%%  The Original Code is HSTCP.
%%
%%  The Initial Developer of the Original Code is VMware, Inc.
%%  Copyright (c) 2009-2011 VMware, Inc.  All rights reserved.
%%

-module(hstcp_drv).

-export([start/0, stop/1, listen/3, close/2, accept/2, recv/3, write/3]).

-define(LIBNAME, "libhstcp").

-define(HSTCP_LISTEN, 0). %% KEEP IN SYNC WITH HSTCP.H
-define(HSTCP_CLOSE,  1).
-define(HSTCP_ACCEPT, 2).
-define(HSTCP_RECV,   3).
-define(HSTCP_WRITE,  4).

start() ->
    erl_ddll:start(),
    {file, Path} = code:is_loaded(?MODULE),
    Dir = filename:join(filename:dirname(Path), "../priv"),
    case erl_ddll:load_driver(Dir, ?LIBNAME) of
        ok                 -> ok;
        {error, permanent} -> ok %% it's already loaded
    end,
    Port = open_port({spawn_driver, ?LIBNAME}, [binary, stream]),
    %% The reply here actually comes up from the ev loop thread, and
    %% is worth waiting for.
    {simple_reply(Port), Port}.

stop(Port) ->
    true = port_close(Port),
    ok.

listen(IpAddress, IpPort, Port) ->
    AddressStr = address_str(IpAddress),
    true = port_command(
             Port, <<?HSTCP_LISTEN, (length(AddressStr)):64/native,
                     (list_to_binary(AddressStr))/binary, IpPort:16/native>>),
    simple_reply(Port).

close(Fd, Port) ->
    true = port_command(Port, <<?HSTCP_CLOSE, Fd:64/native-signed>>),
    simple_reply(Port).

accept(Fd, Port) ->
    true = port_command(Port, <<?HSTCP_ACCEPT, Fd:64/native-signed>>),
    simple_reply(Port).

recv(all, Fd, Port) ->
    recv1(-2, Fd, Port);
recv(once, Fd, Port) ->
    recv1(-1, Fd, Port);
recv(Bytes, Fd, Port) ->
    recv1(Bytes, Fd, Port).

recv1(N, Fd, Port) ->
    true = port_command(
             Port, <<?HSTCP_RECV, Fd:64/native-signed, N:64/native-signed>>),
    ok.

write(Fd, Port, Data) ->
    true = port_command(
             Port, [<<?HSTCP_WRITE, Fd:64/native-signed>>, Data]),
    ok.

%% ---------------------------------------------------------------------------

simple_reply(Port) ->
    receive {hstcp_event, Port, Result} -> Result end.

address_str({A,B,C,D}) ->
    tl(lists:flatten([[$., integer_to_list(X)] || X <- [A,B,C,D]]));
address_str(List) when is_list(List) ->
    List.
