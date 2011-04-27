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

test() ->
    passed = do([test_m || start_stop(),
                           start_listen_close_stop()]).

start_stop() ->
    twice(fun () ->
                  {ok, Port} = hstcp_drv:start(),
                  ok = hstcp_drv:stop(Port),
                  passed
          end).

start_listen_close_stop() ->
    twice(fun () ->
                  {ok, Port} = hstcp_drv:start(),
                  {ok, Fd} = hstcp_drv:listen("0.0.0.0", 5678, Port),
                  {closed, Fd} = hstcp_drv:close(Fd, Port),
                  ok = hstcp_drv:stop(Port),
                  passed
          end).

twice(Fun) ->
    passed = Fun(),
    passed = Fun().


test_write(IpPort) ->
    {ok, Port} = hstcp_drv:start(),
    {ok, Fd} = hstcp_drv:listen("0.0.0.0", IpPort, Port),
    BigBin1 = <<-1:4096/native-unsigned>>,
    BigBin2 = <<1:4096/native-unsigned>>,
    SmallBin = <<10:8/native-unsigned>>,
    {ok, Fd} = hstcp_drv:accept(Fd, Port),
    receive
        {hstcp_event, Port, {ok, Fd1}} ->
            io:format("small bin raw~n"),
            hstcp_drv:write(Fd1, Port, SmallBin),
            io:format("small bin list~n"),
            hstcp_drv:write(Fd1, Port, [SmallBin]),
            io:format("big bin raw~n"),
            hstcp_drv:write(Fd1, Port, BigBin1),
            io:format("big bin list~n"),
            hstcp_drv:write(Fd1, Port, [BigBin1]),
            io:format("small big~n"),
            hstcp_drv:write(Fd1, Port, [SmallBin, BigBin1]),
            io:format("big small~n"),
            hstcp_drv:write(Fd1, Port, [BigBin1, SmallBin]),
            io:format("small big1 big2~n"),
            hstcp_drv:write(Fd1, Port, [SmallBin, BigBin1, BigBin2]),
            io:format("big1 small big2~n"),
            hstcp_drv:write(Fd1, Port, [BigBin1, SmallBin, BigBin2]),
            io:format("big1 big2 small~n"),
            hstcp_drv:write(Fd1, Port, [BigBin1, BigBin2, SmallBin]),
            io:format("small small~n"),
            hstcp_drv:write(Fd1, Port, [SmallBin, SmallBin]),
            io:format("big big~n"),
            hstcp_drv:write(Fd1, Port, [BigBin1, BigBin1]),
            io:format("massive~n"),
            hstcp_drv:write(Fd1, Port, [lists:duplicate(2000, BigBin1), BigBin2]),
            io:format("done~n"),
            timer:sleep(5000),
            {closed, Fd1} = hstcp_drv:close(Fd1, Port),
            {closed, Fd} = hstcp_drv:close(Fd, Port),
            ok = hstcp_drv:stop(Port)
    end.

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
