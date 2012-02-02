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
%%  Copyright (c) 2009-2012 VMware, Inc.  All rights reserved.
%%

-module(hstcp_drv).

-export([start/0, stop/1, listen/3, connect/3, close/1, accept/1,
         recv/2, write/2, set_options/3]).

-define(LIBNAME, "libhstcp").

-define(HSTCP_LISTEN,       0). %% KEEP IN SYNC WITH HSTCP.H
-define(HSTCP_CONNECT,      1).
-define(HSTCP_CLOSE,        2).
-define(HSTCP_ACCEPT,       3).
-define(HSTCP_RECV,         4).
-define(HSTCP_WRITE,        5).
-define(HSTCP_SET_OPTIONS,  6).

-define(IS_WATERMARK(WM), WM =:= none orelse (is_integer(WM) andalso 0 =< WM)).

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
    {simple_reply(Port, 0), {Port, 0}}.

stop({Port, 0}) ->
    true = port_close(Port),
    ok.

listen({Port, 0}, IpAddress, IpPort) ->
    socket(?HSTCP_LISTEN, Port, IpAddress, IpPort).

connect({Port, 0}, IpAddress, IpPort) ->
    socket(?HSTCP_CONNECT, Port, IpAddress, IpPort).

close({Port, Fd}) when Fd > 0 ->
    true = port_command(Port, <<?HSTCP_CLOSE, Fd:64/native-signed>>),
    simple_reply(Port, Fd).

accept({Port, Fd}) when Fd > 0 ->
    true = port_command(Port, <<?HSTCP_ACCEPT, Fd:64/native-signed>>),
    simple_reply(Port, Fd).

recv({Port, Fd}, all) when Fd > 0 ->
    recv1(Port, Fd, -2);
recv({Port, Fd}, once) when Fd > 0 ->
    recv1(Port, Fd, -1);
recv({Port, Fd}, Bytes) when Fd > 0 andalso Bytes >= 0 ->
    recv1(Port, Fd, Bytes).

write({Port, Fd}, Data) when Fd > 0 ->
    true = port_command(
             Port, [<<?HSTCP_WRITE, Fd:64/native-signed>>, Data]),
    simple_reply(Port, Fd).

set_options({Port, Fd}, LowWatermark, HighWatermark)
  when ?IS_WATERMARK(LowWatermark) andalso ?IS_WATERMARK(HighWatermark) ->
    true = port_command(
             Port, <<?HSTCP_SET_OPTIONS, Fd:64/native-signed,
                     (watermark_to_number(LowWatermark)):64/native-signed,
                     (watermark_to_number(HighWatermark)):64/native-signed>>),
    simple_reply(Port, Fd).

%% ---------------------------------------------------------------------------

simple_reply(Port, Fd) ->
    receive
        {hstcp_reply, {Port, Fd1}, Result} when Fd1 =:= Fd orelse Fd1 =:= 0 ->
            Result
    end.

address_str({A,B,C,D}) ->
    tl(lists:flatten([[$., integer_to_list(X)] || X <- [A,B,C,D]]));
address_str(List) when is_list(List) ->
    List.

socket(Action, Port, IpAddress, IpPort) ->
    AddressStr = address_str(IpAddress),
    true = port_command(
             Port, <<Action, (length(AddressStr)):64/native,
                     (list_to_binary(AddressStr))/binary, IpPort:16/native>>),
    simple_reply(Port, 0).

recv1(Port, Fd, N) ->
    true = port_command(
             Port, <<?HSTCP_RECV, Fd:64/native-signed, N:64/native-signed>>),
    simple_reply(Port, Fd).

watermark_to_number(none) -> -1;
watermark_to_number(N)    -> N.
