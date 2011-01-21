%%%----------------------------------------------------------------------
%%% Copyright (c) 2006-2011 Gemini Mobile Technologies, Inc.  All rights reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%% File    : partition_detector_server.erl
%%% Purpose : Network partition detector module
%%%----------------------------------------------------------------------

-module(partition_detector_server).

-behaviour(gen_server).

-include("partition_detector.hrl").
-include("gmt_elog.hrl").

-define(UDP_PORT_STATUS, 63099).
-define(UDP_PORT_STATUS_XMIT, 63100).      % Actual port may be higher

%% External exports
-export([start_link/1, stop/0, is_active/0,
         set_emergency_shutdown_fun/1, exec_emergency_shutdown_fun/1,
         add_to_beacon_extra/1, del_from_beacon_extra/1,
         replace_beacon_extra/2, get_last_beacons/0,
         get_state/0
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Internal exports
-export([do_beacon/7, beacon_loop/8]).

%% Debugging exports
-export([send_fake_admin_beacon/0, send_fake_admin_beacon/1]).

-record(state, {
          arglist,                              % term()
          heart_warn,                           % Seconds for heartbeat warning
          heart_fail,                           % Seconds for heardbeat failure
          monitor_p = false,                    % Flag: do monitoring?
          beacon_a,                             % Pid for beacon proc A
          beacon_b,                             % Pid for beacon proc B
          mon_sock,                             % Socket for receiving b'casts
          timer_ref,                            % Ref for periodic timer
          t_nodes = [],                         % List of gcxKV disc_copies
          h_list = [],                          % History (list of history)
          last_bothbad = [],
          last_onlyabad = [],
          last_onlybbad = [],
          counter = 0,
          emergency_shutdown_fun,
          event_pid,
          extra_list = [],
          udp_port,                             % Config var
          udp_port_xmit                         % Config var
         }).


%% NOTE: Only exported funcs are included so far....

-type a_or_b() :: 'A' | 'B'.
-type broadcast_addr() :: atom() | string() | {byte(),byte(),byte(),byte()} | {char(),char(),char(),char(),char(),char(),char(),char()}. % inferred from gen_udp:send(), I think

-spec add_to_beacon_extra(_) -> ok.
-spec beacon_loop(port(), a_or_b(), number(), broadcast_addr(), fun(), 'infinity' | non_neg_integer(), integer(), list()) -> any().
-spec code_change(_,_,_) -> {ok, any()}.
-spec del_from_beacon_extra(_) -> ok.
-spec do_beacon(a_or_b(), 'network_a_address' | 'network_b_address','network_a_broadcast_address' | 'network_b_broadcast_address', fun(), integer(), integer(), list()) -> any().
-spec exec_emergency_shutdown_fun(_) -> ok.
-spec get_last_beacons() -> list().
-spec get_state() -> any().
-spec handle_call(_,_,_) -> {reply, any(), #state{}} | {stop, any(), any(), #state{}}.
-spec handle_cast(_,_) -> {noreply, #state{}}.
-spec handle_info(_,_) -> {noreply, #state{}} | {stop, any(), #state{}}.
-spec init(_) -> {ok, #state{}}.
-spec is_active() -> boolean().
-spec replace_beacon_extra(_,_) -> boolean().
-spec send_fake_admin_beacon() -> 'ok'.
-spec send_fake_admin_beacon(broadcast_addr()) -> 'ok'.
-spec set_emergency_shutdown_fun(fun(() -> any())) -> any().
-spec start_link(_) -> any().
-spec stop() -> ok.
-spec terminate(_,_) -> any().


%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start_link(ArgList) ->
    gen_server:start_link({local,?MODULE}, ?MODULE, ArgList, []).

stop() ->
    gen_server:call(?MODULE, {stop}).

is_active() ->
    gen_server:call(?MODULE, {is_active}).

set_emergency_shutdown_fun(Fun) when is_function(Fun, 0) ->
    gen_server:call(?MODULE, {set_emergency_shutdown_fun, Fun}, infinity).

exec_emergency_shutdown_fun(Who) ->
    gen_server:call(?MODULE, {exec_emergency_shutdown_fun, Who}, infinity).

add_to_beacon_extra(Term) ->
    gen_server:call(?MODULE, {add_to_beacon_extra, Term}).

del_from_beacon_extra(Term) ->
    gen_server:call(?MODULE, {del_from_beacon_extra, Term}).

replace_beacon_extra(OldTerm, NewTerm) ->
    gen_server:call(?MODULE, {replace_beacon_extra, OldTerm, NewTerm}).

get_last_beacons() ->
    gen_server:call(?MODULE, {get_last_beacons}, infinity).

get_state() ->
    gen_server:call(?MODULE, {get_state}, infinity).

%%%----------------------------------------------------------------------
%%% Callback functions from gen_server
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, State}          |
%%          {ok, State, Timeout} |
%%          ignore               |
%%          {stop, Reason}
%%----------------------------------------------------------------------
init(ArgList) ->
    EmergencyShutdownFun =
        case proplists:get_value(shutdown_modfunc, ArgList) of
            undefined ->
                fun async_shutdown_everything/0;
            {Mod, Func} ->
                fun() ->
                        ?ELOG_ERROR("~p:~p/0", [Mod, Func]),
                        Mod:Func() end
        end,
    ExtraList = proplists:get_value(extra_list, ArgList, []),

    erlang:process_flag(priority, high),

    case application:get_env(partition_detector, network_monitor_enable) of
        {ok, true} ->
            {ok, UdpPort} = application:get_env(partition_detector, heartbeat_status_udp_port),
            {ok, UdpPortXmit} = application:get_env(partition_detector, heartbeat_status_xmit_udp_port),

            BPidA = spawn_link(?MODULE, do_beacon,
                               ['A', 'network_a_address',
                                'network_a_broadcast_address',
                                EmergencyShutdownFun,
                                UdpPort, UdpPortXmit, []]),
            BPidB = spawn_link(?MODULE, do_beacon,
                               ['B', 'network_b_address',
                                'network_b_broadcast_address',
                                EmergencyShutdownFun,
                                UdpPort, UdpPortXmit, []]),

            {ok, HeartWarn} = application:get_env(partition_detector, heartbeat_warning_interval),
            {ok, HeartFail} = application:get_env(partition_detector, heartbeat_failure_interval),

            {ok, TRef} = timer:send_interval(1000, {check_status}),
            %% DEBUGGING USE ONLY!
            %% timer:send_after(10*1000, {inconsistent_database, running_partitioned_network, blar_foo_delme}),

            TNodes = case get_monitored_nodes() of
                         [] ->
                             case (catch partition_detector_mnesia:get_mnesia_monitored_nodes()) of
                                 {'EXIT', _} = Err ->
                                     timer:sleep(2*1000),
                                     exit(Err);
                                 List ->
                                     List
                             end;
                         Ns ->
                             Ns
                     end,
            EventPid = case gen_event:start_link({local, ?EVENT_SERVER}) of
                           {ok, EP}                       -> EP;
                           {error, {already_started, EP}} -> EP
                       end,
            S = #state{arglist = ArgList,
                       beacon_a = BPidA, beacon_b = BPidB,
                       timer_ref = TRef,
                       t_nodes = TNodes,
                       heart_warn = HeartWarn, heart_fail = HeartFail,
                       emergency_shutdown_fun = EmergencyShutdownFun,
                       event_pid = EventPid,
                       extra_list = ExtraList,
                       udp_port = UdpPort,
                       udp_port_xmit = UdpPortXmit},
            %% Intentionally only match the 2 cases that we care about.
            case open_udp_listen_port(UdpPort) of
                {ok, Sock} ->
                    ?ELOG_INFO("Partition detector: active status "
                               "on node ~p",
                               [node()]),
                    {ok, S#state{monitor_p = true,
                                 mon_sock = Sock}};
                {error, eaddrinuse} ->
                    ?ELOG_INFO("Partition detector: standby status "
                               "on node ~p",
                               [node()]),
                    {ok, S#state{monitor_p = false,
                                 mon_sock = undefined}}
            end;
        _ ->
            %% Defaults are OK for no monitoring
            ?ELOG_WARNING("Network monitor is not enabled"),
            {ok, #state{}}
    end.

%%----------------------------------------------------------------------
%% Func: handle_call/3
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_call({set_emergency_shutdown_fun, Fun}, _From, State) ->
    ?ELOG_INFO("New emergency shutdown fun: ~p", [Fun]),
    {reply, ok, State#state{emergency_shutdown_fun = Fun}};
handle_call({exec_emergency_shutdown_fun, Who}, _From, State) ->
    ?ELOG_INFO("Exec emergency shutdown fun: called by ~p", [Who]),
    _ = (State#state.emergency_shutdown_fun)(),
    {reply, ok, State};
handle_call({add_to_beacon_extra, Term}, _From, State) ->
    Es = State#state.extra_list,
    NewEs = [Term|(Es -- [Term])],
    catch State#state.beacon_a ! {new_beacon_extra, NewEs},
    catch State#state.beacon_b ! {new_beacon_extra, NewEs},
    {reply, ok, State#state{extra_list = NewEs}};
handle_call({del_from_beacon_extra, Term}, _From, State) ->
    Es = State#state.extra_list,
    NewEs = Es -- [Term],
    catch State#state.beacon_a ! {new_beacon_extra, NewEs},
    catch State#state.beacon_b ! {new_beacon_extra, NewEs},
    {reply, ok, State#state{extra_list = NewEs}};
handle_call({replace_beacon_extra, OldTerm, NewTerm}, _From, State) ->
    Es = State#state.extra_list,
    NewEs = (Es -- [OldTerm]) ++ [NewTerm],
    catch State#state.beacon_a ! {new_beacon_extra, NewEs},
    catch State#state.beacon_b ! {new_beacon_extra, NewEs},
    {reply, ok, State#state{extra_list = NewEs}};
handle_call({get_last_beacons}, _From, State) ->
    Res = [H#history.beacon || H <- State#state.h_list],
    {reply, Res, State};
handle_call({get_state}, _From, State) ->
    {reply, State, State};
handle_call({stop}, _From, State) ->
    {stop, normal, ok, State};
handle_call({is_active}, _From, State) ->
    {reply, State#state.monitor_p, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%----------------------------------------------------------------------
%% Func: handle_cast/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: handle_info/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_info({udp, Sock, FromAddr, FromPort, Data}, State)
  when Sock =:= State#state.mon_sock ->
    case catch binary_to_term(Data) of
        B when is_record(B, beacon) ->
            NewState = process_beacon(FromAddr, FromPort, B, State),
            {noreply, NewState};
        _ ->
            %% io:format("bogus beacon 2: ~P\n", [Data, 20]),
            {noreply, State}                    % Ignore it
    end;
handle_info({check_status}, State) when State#state.monitor_p =:= true ->
    NewTNodes = case get_monitored_nodes() of
                    [] ->
                        partition_detector_mnesia:get_mnesia_monitored_nodes();
                    L ->
                        L
                end,
    if NewTNodes =/= State#state.t_nodes ->
            {stop, {node_list_change, State#state.t_nodes, NewTNodes}, State};
       true ->
            NewState = do_check_status(State),
            NewState2 = if NewState#state.last_onlyabad =/= [] ->
                                do_check_failure(NewState);
                           true ->
                                NewState
                        end,
            {noreply, NewState2#state{counter = NewState2#state.counter + 1}}
    end;
handle_info({check_status}, State) when State#state.monitor_p =:= false ->
    case open_udp_listen_port(State#state.udp_port) of
        {ok, Sock} ->
            ?ELOG_INFO("Partition detector: change active status on "
                       "node ~p",
                       [node()]),
            gen_udp:close(Sock),
            ArgList =
                [{extra_list, State#state.extra_list}|State#state.arglist],
            {ok, NewState} = init(ArgList),
            {noreply, NewState};
        _ ->
            {noreply, State}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: terminate/2
%% Purpose: Shutdown the server
%% Returns: any (ignored by gen_server)
%%----------------------------------------------------------------------
terminate(_Reason, _State) ->
    As = gmt_util:get_alarms(),
    MyAs = [Name
            || {{alarm_network_heartbeat, _} = Name, warning} <- As],
    _ = [gmt_util:clear_alarm(A, alarm_log_clear_fun(NetAbbr)) ||
            {alarm_network_heartbeat, NetAbbr} = A <- MyAs],
    %% Everything else will clean up automatically when we exit.
    ok.

%%----------------------------------------------------------------------
%% Func: code_change/3
%% Purpose: Convert process state when code is changed
%% Returns: {ok, NewState}
%%----------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------

%% @spec (a_or_b(), atom(), atom(), fun(), integer(), integer(), term()) ->
%%       ok | exit()

do_beacon(NetAbbr, AddrKnob, BcastKnob, EmergencyShutdownFun,
          UdpPort, UdpPortXmit, BeaconExtras) ->
    erlang:process_flag(priority, high),
    {ok, BeaconInterval} = application:get_env(partition_detector, heartbeat_beacon_interval),

    MyAddr = get_ip_from_config(AddrKnob),
    BcastAddr = get_ip_from_config(BcastKnob),
    {ok, Sock} = open_a_udp_sock(UdpPortXmit, MyAddr),
    beacon_loop(Sock, NetAbbr, 0, BcastAddr, EmergencyShutdownFun,
                BeaconInterval, UdpPort, BeaconExtras).

%% @spec (port(), a_or_b(), integer(), ip_addr(), fun(), integer(), integer(), term()) -> forever_loop
%% @doc A simple beacon loop, also replying to any UDP packets sent to
%% the Sock socket.

beacon_loop(Sock, NetAbbr, Count, BcastAddr, EmergencyShutdownFun,
            BeaconInterval, UdpPort, BeaconExtras)
  when is_port(Sock) ->
    Data = pack_beacon(Count, NetAbbr, BeaconExtras),
    ok = gen_udp:send(Sock, BcastAddr, UdpPort, Data),
    %%
    case gen_udp:recv(Sock, 32*1024, BeaconInterval) of
        %% NOTE: I confess, at the moment, we aren't expecting to receive
        %%       any UDP packets sent directly to this socket.  So,
        %%       at the moment, we're using gen_udp:recv() as a novel
        %%       way to sleep for 1 second.
        {ok, {FromAddr, FromPort, FromData}} ->
            %% Use "catch" in case FromData is stuff from
            %% "nc -u host port < /etc/termcap".
            case catch unpack_beacon(FromData) of
                B when is_record(B, beacon) ->
                    ?ELOG_INFO("Received UDP unicast beacon: ~p", [B]),
                    process_unicast_beacon(FromAddr, FromPort, B,
                                           EmergencyShutdownFun);
                _ ->
                    %% io:format("bogus beacon: ~p\n", [FromData]),
                    ok
            end,
            timer:sleep(BeaconInterval);        % Avoid infinite A->B->A loop!
        {error, timeout} ->
            ok
    end,
    NewBeaconExtras = receive {new_beacon_extra, NewEs} -> NewEs
                      after 0                           -> BeaconExtras
                      end,
    ?MODULE:beacon_loop(Sock, NetAbbr, Count + 1, BcastAddr,
                        EmergencyShutdownFun, BeaconInterval, UdpPort,
                        NewBeaconExtras).

%% @spec (Knob::atom()) -> ip_addr() | error | exit()

get_ip_from_config(Knob) ->
    case application:get_env(partition_detector, Knob) of
        {ok,""} ->
            ?ELOG_WARNING("No configuration info available for ~p", [Knob]),
            error;
        {ok,V} ->
            case inet:getaddr(V, inet) of
                {ok, IP} ->
                    IP;
                {error, Reason} ->
                    ?ELOG_WARNING("Invalid configuration value for "
                                  "~p: ~p",
                                  [Knob, Reason]),
                    exit({bad_config_value, Knob, V, Reason})
            end
    end.

%% @spec () -> list(atom())

get_monitored_nodes() ->
    {ok, Nodes} = application:get_env(partition_detector, network_monitor_monitored_nodes),
    Nodes.

open_udp_listen_port(UdpPort) ->
    gen_udp:open(UdpPort, [binary, {broadcast, true},
                           {active, true}]).

open_a_udp_sock(PortNum, MyAddr) ->
    case gen_udp:open(PortNum, [{ip, MyAddr}, binary, {broadcast, true},
                                {active, false}]) of
        {ok, Sock} ->
            {ok, Sock};
        {error, eaddrinuse} ->
            open_a_udp_sock(PortNum + 1, MyAddr);
        {error, Reason} ->
            ?ELOG_WARNING("Error opening UDP port ~p on ~p: ~p",
                          [PortNum, MyAddr, Reason]),
            exit({udp_open_error, PortNum, Reason})
    end.

pack_beacon(Count, NetAbbr, Extra) ->
    term_to_binary(#beacon{node = node(), net = NetAbbr, count = Count,
                           time = now(), extra = Extra}).

unpack_beacon(B) ->
    binary_to_term(B).

%% @spec (_FromAddr::ip_addr(), _FromPort::udp_port(), B::beacon_r(), S::state_r()) -> state_r()

process_beacon(FromAddr, FromPort, B, S) ->
    gen_event:notify(S#state.event_pid, {beacon_event, FromAddr, FromPort, B}),
    Key = {B#beacon.node, B#beacon.net},
    H = #history{node_net = Key,
                 lastcount = B#beacon.count, lasttime = now(), beacon = B},
    NewH = [H|lists:keydelete(Key, #history.node_net, S#state.h_list)],
    S#state{h_list = NewH}.

%% @spec (S::state_r()) -> state_r()

do_check_status(S) ->
    Now = now(),
    HeartWarnUsec = S#state.heart_warn * 1000*1000,
    CheckNet =
        fun(Net) ->
                fun(H, Acc) when element(2, H#history.node_net) =/= Net ->
                        Acc;
                   (H, Acc) ->
                        case timer:now_diff(Now, H#history.lasttime) of
                            Diff when Diff > HeartWarnUsec ->
                                Node = element(1, H#history.node_net),
                                [Node|Acc];
                            _D ->
                                Acc
                        end
                end
        end,
    BadNetA = lists:foldl(CheckNet('A'), [], S#state.h_list) ++
        %% Add the nodes that have no history on net 'A'
        [N || N <- S#state.t_nodes, has_no_history_p(N, 'A', S)],
    %% io:format("BadNetA = ~p\n", [BadNetA]),
    BadNetB = lists:foldl(CheckNet('B'), [], S#state.h_list) ++
        %% Add the nodes that have no history on net 'B'
        [N || N <- S#state.t_nodes, has_no_history_p(N, 'B', S)],
    %% io:format("BadNetB = ~p\n", [BadNetB]),

    %% These will be lists of node names
    BothBad  = [N || N <- BadNetA,     lists:member(N, BadNetB)],
    OnlyABad = [N || N <- BadNetA, not lists:member(N, BadNetB)] -- BothBad,
    OnlyBBad = [N || N <- BadNetB, not lists:member(N, BadNetA)] -- BothBad,
    %% io:format("QQQ: Both ~p, OnlyA ~p, OnlyB ~p\n", [BothBad, OnlyABad, OnlyBBad]),

    _ = clear_alarms(S#state.last_bothbad, BothBad, 'A'),
    _ = clear_alarms(S#state.last_bothbad, BothBad, 'B'),
    _ = clear_alarms(S#state.last_onlyabad, OnlyABad, 'A'),
    _ = clear_alarms(S#state.last_onlybbad, OnlyBBad, 'B'),
    _ = set_alarms(S#state.last_bothbad, BothBad, 'A'),
    _ = set_alarms(S#state.last_bothbad, BothBad, 'B'),
    _ = set_alarms(S#state.last_onlyabad, OnlyABad, 'A'),
    _ = set_alarms(S#state.last_onlybbad, OnlyBBad, 'B'),

    S#state{last_bothbad = BothBad,
            last_onlyabad = OnlyABad, last_onlybbad = OnlyBBad}.

do_check_failure(S) ->
    Now = now(),
    HeartFailUsec = S#state.heart_fail * 1000*1000,
    F = fun(N) ->
                BSecs = case get_history(N, 'B',
                                         S#state.h_list) of
                            {value, HB} ->
                                DiffB = timer:now_diff(Now,
                                                       HB#history.lasttime),
                                DiffB / 1000000;
                            _ ->
                                'Never'
                        end,
                case {BSecs, get_history(N, 'A', S#state.h_list)} of
                    {'Never', _} ->
                        %% In this case, we've never seen a heartbeat on
                        %% 'B' for this node (??).
                        %% Don't do anything right now.
                        ok;
                    {BSecs, {value, HA}} ->
                        case timer:now_diff(Now, HA#history.lasttime) of
                            Diff when Diff > HeartFailUsec,
                                      BSecs =/= 'Never' ->
                                %% Definitely a partition!
                                ?ELOG_ERROR("Network 'A' is partitioned.  Heartbeats from ~p on network 'A' are lost (~p seconds) but are functioning normally on network 'B' (last heard ~p seconds ago)",
                                            [N, Diff/1000000, BSecs]),
                                {ok,Addr} = application:get_env(partition_detector, network_a_tiebreaker),
                                case do_ping_p(Addr) of
                                    true  ->
                                        ?ELOG_ERROR("Network 'A' is partitioned.  Able to successfully ping ~s. Continuing operation.",
                                                    [Addr]);
                                    false ->
                                        ?ELOG_ERROR("Network 'A' is partitioned.  Unable to ping ~s.  Starting emergency shutdown to prevent database damage.",
                                                    [Addr]),
                                        (S#state.emergency_shutdown_fun)()
                                end;
                            Diff ->
                                %% Partition is possible, wait and see...
                                ?ELOG_WARNING("Partition of network 'A' is possible.  Heartbeats from ~p on network 'A' are lost (~p seconds) but are functioning normally on network 'B' (last heard ~p seconds ago)",
                                              [N, Diff/1000000, BSecs])
                        end;
                    {BSecs, false} ->
                        %% In this case, we've never seen a heartbeat on
                        %% 'A' for this node (??).  An alarm should already
                        %% be raised.  Don't do anything right now.
                        ok
                end
        end,
    _ = lists:map(F, S#state.last_onlyabad),    % We want the side-effects!
    S.

get_history(Node, NetAbbr, HList) ->
    lists:keysearch({Node, NetAbbr}, #history.node_net, HList).

%% @doc Predicate: true if Node has no history record on network NetAbbr.
%% NOTE: If the state counter is less than 5, then we always return false.
%%       This hack permits a bit of time for stray beacons to be added to
%%       the history list.  (A.k.a. a hack to avoid a race condition that
%%       may set an alarm only to have it cleared 1-2 seconds later.)

has_no_history_p(_Node, _NetAbbr, S) when S#state.counter < 5 ->
    false;
has_no_history_p(Node, NetAbbr, S) ->
    case lists:keysearch({Node, NetAbbr}, #history.node_net, S#state.h_list) of
        {value, _} -> false;
        false      -> true
    end.

set_alarms(Last, Current, NetAbbr) ->
    Ns = [N || N <- Current, not lists:member(N, Last)],
    Fun = alarm_log_set_fun(NetAbbr),
    [gmt_util:set_alarm({alarm_network_heartbeat, {N, NetAbbr}}, warning, Fun)
     || N <- Ns].

clear_alarms(Last, Current, NetAbbr) ->
    Ns = [N || N <- Last, not lists:member(N, Current)],
    Fun = alarm_log_clear_fun(NetAbbr),
    [gmt_util:clear_alarm({alarm_network_heartbeat, {N, NetAbbr}}, Fun)
     || N <- Ns].

do_ping_p(Addr) ->
    %% NOTE: This is a Linux-specific "ping" command.
    Cmd = "ping -c 3 -i 0.3 -w 1 -q " ++ Addr ++
        " 2>&1 > /dev/null ; if [ $? -eq 0 ]; then echo -n 0; else echo -n 1; fi",
    case os:cmd(Cmd) of
        "0" -> true;
        "1"  -> false;
        Err  -> throw({do_ping_p, error, Err})
    end.

%% Dialyzer: Never called.
%% send_1_beacon(ToAddr, ToPort, Beacon, UdpPortXmit) ->
%%     {ok, Sock} = open_a_udp_sock(UdpPortXmit, {0,0,0,0}),
%%     ok = gen_udp:send(Sock, ToAddr, ToPort, Beacon),
%%     ok = gen_udp:close(Sock),
%%     ok.

process_unicast_beacon(FromAddr, FromPort, B, EmergencyShutdownFun) ->
    gen_event:notify(?EVENT_SERVER, {beacon_event, FromAddr, FromPort, B}),
    case lists:member(halt_immediately, B#beacon.extra) of
        true ->
            ?ELOG_ERROR("Shutdown beacon received: ~p", [B]),
            EmergencyShutdownFun();
        _ ->
            ok
    end.

alarm_log_set_fun(Name) ->                      % Yes, returning an arity 0 fun
    fun() ->
            ?ELOG_ERROR("Alarm SET: network_heartbeat: ~p", [Name])
    end.

alarm_log_clear_fun(Name) ->                    % Yes, returning an arity 0 fun
    fun() ->
            ?ELOG_ERROR("Alarm CLEAR: network_heartbeat: ~p", [Name])
    end.

async_shutdown_everything() ->
    %% Not clear if this would be written to the app log before the
    %% halt interferes with the writing.
    ?ELOG_ERROR("Async shutdown function in ~s called", [?MODULE]),
    spawn_opt(fun() -> process_flag(trap_exit, true),
                       erlang:halt(0)
              end, [{priority, high}]).

send_fake_admin_beacon() ->
    send_fake_admin_beacon({10,10,10,255}).

send_fake_admin_beacon(BroadcastAddr) ->
    {ok, S1} = gen_udp:open(64987,
                            [binary, {broadcast, true}, {active, false}]),
    %% Extra = [{brick_admin, {starting, {1,2,3}, foonode, self()}}],
    Extra = [{brick_admin, {running, {1,2,3}, foonode, self()}}],
    Beacon = #beacon{node = foonode, net = 'A', extra = Extra},
    ok = gen_udp:send(S1, BroadcastAddr, ?UDP_PORT_STATUS, term_to_binary(Beacon)),
    gen_udp:close(S1).
