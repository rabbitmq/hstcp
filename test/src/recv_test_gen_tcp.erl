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

-module(recv_test_gen_tcp).

-compile(export_all).

-record(s, {sock, buf, size, expected}).

listen(Port) ->
    {ok, LSock} = gen_tcp:listen(Port, [binary,
                                        {nodelay, true},
                                        {active, once}]),
    accept(LSock),
    LSock.

accept(LSock) ->
    spawn(fun () ->
                  {ok, Sock} = gen_tcp:accept(LSock),
                  accept(LSock),
                  recv(Sock)
          end).

recv(Sock) ->
    recv(#s{sock = Sock, buf = [], size = 0, expected = 4}, os:timestamp()).

recv(State, T) ->
    erlang:send_after(1000, self(), {stats, T}),
    recvloop(State, 0).

print_stats(Count, T) ->
    Now = os:timestamp(),
    io:format("~p ~p kHz~n", [?MODULE, 1000* Count / timer:now_diff(Now, T)]),
    Now.

recvloop(State = #s{sock = Sock, size = Sz, expected = Expected}, Count)
  when Sz < Expected ->
    ok = inet:setopts(Sock, [{active, once}]),
    recv_active_once(State, Count);
recvloop(State = #s{buf = Buf}, Count) ->
    {Bin, Expected, Count1} =
        segment(case Buf of
                    [Bin1] -> Bin1;
                    _      -> list_to_binary(lists:reverse(Buf))
                end, Count),
    recvloop(State#s{buf = [Bin], size = size(Bin), expected = Expected},
             Count1).

segment(<<L:32, Data:L/binary, Rest/binary>>, Count) ->
    segment(Rest, Count + 1);
segment(<<L:32, Bin/binary>>, Count) ->
    {<<L:32, Bin/binary>>, L + 4, Count};
segment(Bin, Count) ->
    {Bin,4, Count}.

recv_active_once(State = #s{sock = Sock, buf = Buf, size = Sz}, Count) ->
    receive
        {tcp, Sock, Data} ->
            recvloop(State#s{buf = [Data | Buf], size = Sz + size(Data)},
                     Count);
        {tcp_closed, Sock} ->
            gen_tcp:close(Sock),
            closed;
        {tcp_error, Sock, Reason} ->
            gen_tcp:close(Sock),
            {error, Reason};
        {stats, T} ->
            recv(State, print_stats(Count, T));
        Other ->
            exit({unexpected_message, Other})
    end.
