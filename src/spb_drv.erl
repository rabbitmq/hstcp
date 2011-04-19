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
%%  The Original Code is SPB.
%%
%%  The Initial Developer of the Original Code is VMware, Inc.
%%  Copyright (c) 2009-2011 VMware, Inc.  All rights reserved.
%%

-module(spb_drv).

-export([start/0, stop/1, listen/3, close/2, accept/2]).

-define(LIBNAME, "libspb").

-define(SPB_LISTEN, 0). %% KEEP IN SYNC WITH SPB.H
-define(SPB_CLOSE,  1).
-define(SPB_ACCEPT, 2).

start() ->
    erl_ddll:start(),
    {file, Path} = code:is_loaded(?MODULE),
    Dir = filename:join(filename:dirname(Path), "../priv"),
    ok = erl_ddll:load_driver(Dir, ?LIBNAME),
    Port = open_port({spawn_driver, ?LIBNAME}, [binary, stream]),
    %% The reply here actually comes up from the ev loop thread, and
    %% is worth waiting for.
    {simple_reply(Port), Port}.

stop(Port) ->
    port_close(Port).

listen(IpAddress, IpPort, Port) ->
    AddressStr = address_str(IpAddress),
    port_command(Port,
                 <<?SPB_LISTEN, (length(AddressStr)):64/native,
                   (list_to_binary(AddressStr))/binary, IpPort:16/native>>),
    simple_reply(Port).

close(Fd, Port) ->
    port_command(Port, <<?SPB_CLOSE, Fd:64/native-signed>>),
    simple_reply(Port).

accept(Fd, Port) ->
    port_command(Port, <<?SPB_ACCEPT, Fd:64/native-signed>>).

simple_reply(Port) ->
    receive {spb_reply, Port, Result} -> Result end.

address_str({A,B,C,D}) ->
    tl(lists:flatten([[$., integer_to_list(X)] || X <- [A,B,C,D]]));
address_str(List) when is_list(List) ->
    List.
