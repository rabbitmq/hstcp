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
%%  Copyright (c) 2009-2013 VMware, Inc.  All rights reserved.
%%

-module(test_hstcp).

-compile([export_all]).

-define(PORT, 5678).

test() ->
    test:test([{?MODULE, [start_stop,
                          start_listen_close_stop,
                          start_listen_accept_close_stop,
                          start_listen_accept_connect_close_close_stop_1,
                          start_listen_accept_connect_close_close_stop_2,
                          write_client_server,
                          write_server_client,
                          write_server_client_variations,
                          write_server_client_one_big,
                          write_server_client_streaming]}],
              [report, {name, ?MODULE}]).

start_stop() ->
    twice(fun () ->
                  {ok, Sock} = hstcp_drv:start(),
                  ok = hstcp_drv:stop(Sock),
                  passed
          end).

start_listen_close_stop() ->
    twice(fun () ->
                  {ok, Sock} = hstcp_drv:start(),
                  {new_fd, Sock1} = hstcp_drv:listen(Sock, "0.0.0.0", ?PORT),
                  closed = hstcp_drv:close(Sock1),
                  ok = hstcp_drv:stop(Sock),
                  passed
          end).

start_listen_accept_close_stop() ->
    twice(fun () ->
                  {ok, Sock} = hstcp_drv:start(),
                  {new_fd, Sock1} = hstcp_drv:listen(Sock, "0.0.0.0", ?PORT),
                  ok = hstcp_drv:accept(Sock1),
                  closed = hstcp_drv:close(Sock1),
                  ok = hstcp_drv:stop(Sock),
                  passed
          end).

start_listen_accept_connect_close_close_stop_1() ->
    %% We get the client to disconnect first here.
    twice(fun () ->
                  with_connection(
                    fun (Sock,  _Sock1) -> gen_tcp:close(Sock), passed end,
                    fun (_Sock, _Sock1) ->                      passed end)
          end).

start_listen_accept_connect_close_close_stop_2() ->
    %% We get the server to disconnect first here.
    twice(fun () ->
                  with_connection(
                    fun (_Sock, _Sock1) ->                      passed end,
                    fun (Sock,  _Sock1) -> gen_tcp:close(Sock), passed end)
          end).

write_client_server() ->
    twice(fun () ->
                  with_connection(
                    fun (Sock, Sock1) ->
                            Bin = <<"Hello World">>,
                            ok = gen_tcp:send(Sock, Bin),
                            ok = hstcp_drv:recv(Sock1, size(Bin)),
                            BinLst = receive_up_to(true, Sock1, size(Bin),
                                                   fun (E,L) -> [E,L] end,
                                                   []),
                            Bin = list_to_binary(lists:reverse(BinLst)),
                            gen_tcp:close(Sock),
                            passed
                    end,
                    fun (_Sock, _Sock1) -> passed end)
          end).

write_server_client() ->
    twice(fun () ->
                  with_connection(
                    fun (Sock, Sock1) ->
                            Bin = <<"Hello World">>,
                            ok = hstcp_drv:write(Sock1, Bin),
                            {ok, Bin} = gen_tcp:recv(Sock, size(Bin)),
                            gen_tcp:close(Sock),
                            passed
                    end,
                    fun (_Sock, _Sock1) -> passed end)
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
              [BigBin1 ],
              [SmallBin, BigBin1 ],
              [BigBin1,  SmallBin],
              [SmallBin, BigBin1,  BigBin2 ],
              [BigBin1,  SmallBin, BigBin2 ],
              [BigBin1,  BigBin2,  SmallBin],
              [SmallBin, SmallBin],
              [BigBin1,  BigBin1 ],
              [lists:duplicate(2000, BigBin1), BigBin2]
             ],
    MD5 = erlang:md5(ToSend),
    twice(
      fun () ->
              with_connection(
                fun (Sock, Sock1) ->
                        [ok = hstcp_drv:write(Sock1, Bin)
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
                fun (_Sock, _Sock1) -> passed end)
      end).

write_server_client_one_big() ->
    Bin = <<-1:524288/native-unsigned>>,
    Lst = lists:duplicate(16384, Bin),
    Size = iolist_size(Lst), %% == 1GB
    MD5 = erlang:md5(Lst),
    twice(
      fun () ->
              with_connection(
                fun (Sock, Sock1) ->
                        ok = hstcp_drv:write(Sock1, Lst),
                        Context =
                            receive_up_to(false, Sock, Size,
                                          fun (Bin1, Ctx) ->
                                                  erlang:md5_update(Ctx, Bin1)
                                          end,
                                          erlang:md5_init()),
                        MD5 = erlang:md5_final(Context),
                        gen_tcp:close(Sock),
                        passed
                end,
                fun (_Sock, _Sock1) -> passed end)
      end).

write_server_client_streaming() ->
    %% The point here is to continue to send data through to the
    %% driver as the driver is still writing data out of the
    %% socket. This stresses the driver's command queue between the
    %% driver thread, and the libev thread.
    Count = 65536,
    Bin = <<-1:1024/native-unsigned>>,
    Lst = lists:duplicate(128, Bin),
    MD5 = erlang:md5_final(
            lists:foldl(fun (_, Ctx) -> erlang:md5_update(Ctx, Lst) end,
                        erlang:md5_init(), lists:duplicate(Count, ok))),
    twice(
      fun () ->
              with_connection(
                fun (Sock, Sock1) ->
                        spawn(fun () -> repeat_write(Sock1, Lst, Count) end),
                        BytesRecv = Count * iolist_size(Lst),
                        Context =
                            receive_up_to(false, Sock, BytesRecv,
                                          fun (Bin1, Ctx) ->
                                                  erlang:md5_update(Ctx, Bin1)
                                          end,
                                          erlang:md5_init()),
                        MD5 = erlang:md5_final(Context),
                        gen_tcp:close(Sock),
                        passed
                end,
                fun (_Sock, _Sock1) -> passed end)
      end).

repeat_write(_Sock, _List, 0) ->
    ok;
repeat_write(Sock, List, N) when N > 0 ->
    ok = hstcp_drv:write(Sock, List),
    repeat_write(Sock, List, N - 1).

receive_up_to(_IsHS, _Sock, 0, _Comb, Init) ->
    Init;
receive_up_to(true, Sock, N, Comb, Init) when N > 0 ->
    receive
        {hstcp_event, Sock, {data, Data}} ->
            receive_up_to(true, Sock, N - size(Data), Comb, Comb(Data, Init));
        {hstcp_event, Sock, Event} ->
            {error, Event}
    end;
receive_up_to(false, Sock, N, Comb, Init) ->
    Amount = case N > 65536 of
                 true  -> 65536;
                 false -> N
             end,
    {ok, Data} = gen_tcp:recv(Sock, Amount),
    receive_up_to(false, Sock, N - size(Data), Comb, Comb(Data, Init)).

acceptor(Parent, Sock) ->
    fun () ->
            ok = hstcp_drv:accept(Sock),
            Sock1 = receive
                        {hstcp_event, Sock, {new_fd, Sock2}} -> Sock2
                    end,
            Parent ! {self(), connected},
            receive {Parent, close, Connected, Closed, Sock3} ->
                    passed = Connected(Sock3, Sock1),
                    closed = hstcp_drv:close(Sock1),
                    passed = Closed(Sock3, Sock1),
                    Parent ! {self(), closed}
            end
    end.

with_connection(Connected, Closed) ->
    {ok, Sock} = hstcp_drv:start(),
    {new_fd, Sock1} = hstcp_drv:listen(Sock, "0.0.0.0", ?PORT),
    Me = self(),
    Pid = spawn(acceptor(Me, Sock1)),
    {ok, Sock2} = gen_tcp:connect("localhost", ?PORT,
                                  [binary, {active, false}, {nodelay, true}]),
    receive {Pid, connected} -> Pid ! {Me, close, Connected, Closed, Sock2} end,
    receive {Pid, closed}    -> ok end,
    closed = hstcp_drv:close(Sock1),
    ok = hstcp_drv:stop(Sock),
    passed.

twice(Fun) ->
    passed = Fun(),
    passed = Fun().

%% This is a general speed receiving test
recv(IpPort) ->
    receive_and_echo(IpPort, false).

%% This is a general speed echo test
echo(IpPort) ->
    receive_and_echo(IpPort, true).

receive_and_echo(IpPort, Echo) ->
    {ok, Sock} = hstcp_drv:start(),
    {new_fd, Sock1} = hstcp_drv:listen(Sock, "0.0.0.0", IpPort),
    ok = hstcp_drv:accept(Sock1),
    receive
        {hstcp_event, Sock1, {new_fd, Sock2}} ->
            ok = hstcp_drv:recv(Sock2, once),
            Result = drain(Echo, Sock2, now(), 0, 0),
            closed = hstcp_drv:close(Sock1),
            ok = hstcp_drv:stop(Sock),
            Result
    end.

drain(Echo, Sock, Start, Count, Size) ->
    receive
        {hstcp_event, Sock, {data, Data}} ->
            ok = hstcp_drv:recv(Sock, once),
            case Echo of
                true  -> ok = hstcp_drv:write(Sock, Data);
                false -> ok
            end,
            drain(Echo, Sock, Start, Count+1, Size + size(Data));
        {hstcp_event, Sock, Event} ->
            Elapsed = timer:now_diff(now(), Start),
            io:format("received ~p bytes, in ~p msgs, in ~p microseconds (~p bytes/sec)~n",
                      [Size, Count, Elapsed, (Size*1000000)/Elapsed]),
            ClosedOrBadArg = hstcp_drv:close(Sock),
            %% ASSERTION: badarg if it's already been closed
            true = ClosedOrBadArg =:= closed orelse ClosedOrBadArg =:= badarg,
            {Event, Count, Size};
        Other ->
            Other
    end.

send(IpAddress, IpPort, Time) ->
    {ok, Sock} = hstcp_drv:start(),
    {new_fd, Sock1} = hstcp_drv:connect(Sock, IpAddress, IpPort),
    %% set low at 1MB, high at 128MB
    Low = 1024*1024,
    High = 128*Low,
    ok = hstcp_drv:set_options(Sock1, Low, High),
    receive {hstcp_event, Sock1, {low_watermark, Low}} -> ok end,
    TRef = timer:send_after(Time, stop),
    %% 256KB (8*1024*256)
    PayloadSize = 252,
    Bin = << <<PayloadSize:(8*4), 1:(8*PayloadSize)>>
             || _ <- lists:seq(1, 1024) >>,
    List = lists:duplicate(64, Bin), %% 16MB
    Result = send1(Sock1, Low, High, List, true),
    closed = hstcp_drv:close(Sock1),
    ok = hstcp_drv:stop(Sock),
    timer:cancel(TRef),
    receive stop -> ok after 0 -> ok end,
    Result.

send1(Sock, Low, High, Payload, true) ->
    ok = hstcp_drv:write(Sock, Payload),
    receive
        {hstcp_event, Sock, {high_watermark, High}} ->
            io:format("stopping send~n"),
            send1(Sock, Low, High, Payload, false);
        {hstcp_event, Sock, {low_watermark, Low}} ->
            %% This is ok: it means that there was temporarily more
            %% than Low enqueued and it's now cleared, thus dropping
            %% below the low again.
            send1(Sock, Low, High, Payload, true);
        {hstcp_event, Sock, Other} ->
            Other;
        stop -> ok
    after 0 ->
        send1(Sock, Low, High, Payload, true)
    end;
send1(Sock, Low, High, Payload, false) ->
    receive
        {hstcp_event, Sock, {low_watermark, Low}} ->
            io:format("starting send~n"),
            send1(Sock, Low, High, Payload, true);
        {hstcp_event, Sock, high_watermark} ->
            send1(Sock, Low, High, Payload, false);
        {hstcp_event, Sock, Other} ->
            Other;
        stop -> ok
    end.
