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

-module(test_hstcp).

-compile({parse_transform, erlando}).
-compile([export_all]).

-define(PORT, 5678).

test() ->
    passed = do([test_m || start_stop(),
                           start_listen_close_stop(),
                           start_listen_accept_close_stop(),
                           start_listen_accept_connect_close_close_stop_1(),
                           start_listen_accept_connect_close_close_stop_2(),
                           write_client_server(),
                           write_server_client(),
                           write_server_client_variations()
                ]).

start_stop() ->
    twice(fun () ->
                  {ok, Port} = hstcp_drv:start(),
                  ok = hstcp_drv:stop(Port),
                  passed
          end).

start_listen_close_stop() ->
    twice(fun () ->
                  {ok, Port} = hstcp_drv:start(),
                  {ok, Fd} = hstcp_drv:listen("0.0.0.0", ?PORT, Port),
                  {closed, Fd} = hstcp_drv:close(Fd, Port),
                  ok = hstcp_drv:stop(Port),
                  passed
          end).

start_listen_accept_close_stop() ->
    twice(fun () ->
                  {ok, Port} = hstcp_drv:start(),
                  {ok, Fd} = hstcp_drv:listen("0.0.0.0", ?PORT, Port),
                  {ok, Fd} = hstcp_drv:accept(Fd, Port),
                  {closed, Fd} = hstcp_drv:close(Fd, Port),
                  ok = hstcp_drv:stop(Port),
                  passed
          end).

start_listen_accept_connect_close_close_stop_1() ->
    %% We get the client to disconnect first here.
    twice(fun () ->
                  with_connection(
                    fun (Sock,  _FdPort) -> gen_tcp:close(Sock), passed end,
                    fun (_Sock, _FdPort) ->                      passed end)
          end).

start_listen_accept_connect_close_close_stop_2() ->
    %% We get the server to disconnect first here.
    twice(fun () ->
                  with_connection(
                    fun (_Sock, _FdPort) ->                      passed end,
                    fun (Sock,  _FdPort) -> gen_tcp:close(Sock), passed end)
          end).

write_client_server() ->
    twice(fun () ->
                  with_connection(
                    fun (Sock, {Fd, Port}) ->
                            Bin = <<"Hello World">>,
                            ok = gen_tcp:send(Sock, Bin),
                            Bin = receive_up_to(Fd, Port, size(Bin)),
                            gen_tcp:close(Sock),
                            passed
                    end,
                    fun (_Sock, _FdPort) -> passed end)
          end).

write_server_client() ->
    twice(fun () ->
                  with_connection(
                    fun (Sock, {Fd, Port}) ->
                            Bin = <<"Hello World">>,
                            ok = hstcp_drv:write(Fd, Port, Bin),
                            {ok, Bin} = gen_tcp:recv(Sock, size(Bin)),
                            gen_tcp:close(Sock),
                            passed
                    end,
                    fun (_Sock, _FdPort) -> passed end)
          end).

write_server_client_variations() ->
    %% The point here is to test the various ways in which binaries
    %% can get passed to the driver.
    BigBin1 = <<-1:4096/native-unsigned>>,
    BigBin2 = <<1:4096/native-unsigned>>,
    SmallBin = <<10:8/native-unsigned>>,

    ToSend = [SmallBin,
              [SmallBin],
              BigBin1,
              [BigBin1],
              [SmallBin, BigBin1],
              [BigBin1, SmallBin],
              [SmallBin, BigBin1, BigBin2],
              [BigBin1, SmallBin, BigBin2],
              [BigBin1, BigBin2, SmallBin],
              [SmallBin, SmallBin],
              [BigBin1, BigBin1],
              [lists:duplicate(2000, BigBin1), BigBin2]],
    MD5 = erlang:md5(ToSend),
    twice(
      fun () ->
              with_connection(
                fun (Sock, {Fd, Port}) ->
                        [ok = hstcp_drv:write(Fd, Port, Bin)
                         || Bin <- ToSend],
                        MD5 = erlang:md5_final(
                                lists:foldl(
                                  fun (Bin, Context) ->
                                          Size = iolist_size(Bin),
                                          %% Bin1 will always be a
                                          %% plain binary, and not the
                                          %% iolist that was written.
                                          {ok, Bin1} = gen_tcp:recv(Sock, Size),
                                          erlang:md5_update(Context, Bin1)
                                  end, erlang:md5_init(), ToSend)),
                        gen_tcp:close(Sock),
                        passed
                end,
                fun (_Sock, _FdPort) -> passed end)
      end).

receive_up_to(Fd, Port, N) ->
    ok = hstcp_drv:recv(N, Fd, Port),
    receive_up_to(Fd, Port, N, []).

receive_up_to(_Fd, _Port, 0, Lst) ->
    list_to_binary(lists:reverse(Lst));
receive_up_to(Fd, Port, N, Lst) when N > 0 ->
    receive
        {hstcp_event, Port, {data, Fd, Data}} ->
            receive_up_to(Fd, Port, N - size(Data), [Data|Lst]);
        {hstcp_event, Port, Event} ->
            {error, Event}
    end.

acceptor(Parent, Fd, Port) ->
    fun () ->
            {ok, Fd} = hstcp_drv:accept(Fd, Port),
            Fd1 = receive
                      {hstcp_event, Port, {ok, Fd2}} -> Fd2
                  end,
            Parent ! {self(), connected},
            receive {Parent, close, Connected, Closed, Sock} ->
                    passed = Connected(Sock, {Fd1, Port}),
                    {closed, Fd1} = hstcp_drv:close(Fd1, Port),
                    passed = Closed(Sock, {Fd1, Port}),
                    Parent ! {self(), closed}
            end
    end.

with_connection(Connected, Closed) ->
    {ok, Port} = hstcp_drv:start(),
    {ok, Fd} = hstcp_drv:listen("0.0.0.0", ?PORT, Port),
    Me = self(),
    Pid = spawn(acceptor(Me, Fd, Port)),
    {ok, Sock} = gen_tcp:connect("localhost", ?PORT,
                                 [binary, {active, false}, {nodelay, true}]),
    receive {Pid, connected} -> Pid ! {Me, close, Connected, Closed, Sock} end,
    receive {Pid, closed}    -> ok end,
    {closed, Fd} = hstcp_drv:close(Fd, Port),
    ok = hstcp_drv:stop(Port),
    passed.

twice(Fun) ->
    passed = Fun(),
    passed = Fun().

test_write2(IpPort) ->
    {ok, Port} = hstcp_drv:start(),
    {ok, Fd} = hstcp_drv:listen("0.0.0.0", IpPort, Port),
    Bin = <<-1:524288/native-unsigned>>,
    Lst = lists:duplicate(16384, Bin),
    {ok, Fd} = hstcp_drv:accept(Fd, Port),
    receive
        {hstcp_event, Port, {ok, Fd1}} ->
            hstcp_drv:write(Fd1, Port, Lst),
            timer:sleep(10000),
            {closed, Fd1} = hstcp_drv:close(Fd1, Port),
            {closed, Fd} = hstcp_drv:close(Fd, Port),
            ok = hstcp_drv:stop(Port)
    end.

test_write3(IpPort) ->
    {ok, Port} = hstcp_drv:start(),
    {ok, Fd} = hstcp_drv:listen("0.0.0.0", IpPort, Port),
    Bin = <<-1:8192/native-unsigned>>,
    Lst = lists:duplicate(128, Bin),
    {ok, Fd} = hstcp_drv:accept(Fd, Port),
    receive
        {hstcp_event, Port, {ok, Fd1}} ->
            tw3(Port, Fd1, Lst, 65536),
            timer:sleep(10000),
            {closed, Fd1} = hstcp_drv:close(Fd1, Port),
            {closed, Fd} = hstcp_drv:close(Fd, Port),
            ok = hstcp_drv:stop(Port)
    end.
tw3(_Port, _Fd, _List, 0) ->
    ok;
tw3(Port, Fd, List, N) ->
    hstcp_drv:write(Fd, Port, List),
    tw3(Port, Fd, List, N-1).

spawn_test(IpPort) ->
    spawn(fun () -> test(IpPort) end).

test(IpPort) ->
    {ok, Port} = hstcp_drv:start(),
    {ok, Fd} = hstcp_drv:listen("0.0.0.0", IpPort, Port),
    {ok, Fd} = hstcp_drv:accept(Fd, Port),
    receive
        {hstcp_event, Port, {ok, Fd1}} ->
            ok = hstcp_drv:recv(once, Fd1, Port),
            Result = drain(Fd1, Port, now(), 0, 0),
            {closed, Fd} = hstcp_drv:close(Fd, Port),
            ok = hstcp_drv:stop(Port),
            Result
    end.
drain(Fd, Port, Start, Count, Size) ->
    receive
        {hstcp_event, Port, {data, Fd, Data}} ->
            ok = hstcp_drv:recv(once, Fd, Port),
            drain(Fd, Port, Start, Count+1, Size + size(Data));
        {hstcp_event, Port, Event} ->
            Elapsed = timer:now_diff(now(), Start),
            io:format("received ~p bytes, in ~p msgs, in ~p microseconds (~p bytes/sec)~n",
                      [Size, Count, Elapsed, (Size*1000000)/Elapsed]),
            {ClosedOrBadArg, Fd} = hstcp_drv:close(Fd, Port),
            %% ASSERTION: badarg if it's already been closed
            true = ClosedOrBadArg =:= closed orelse ClosedOrBadArg =:= badarg,
            {Event, Count, Size};
        Other ->
            Other
    end.
