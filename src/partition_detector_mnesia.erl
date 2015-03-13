%%%----------------------------------------------------------------------
%%% Copyright (c) 2008-2015 Hibari developers.  All rights reserved.
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
%%% File    : partition_detector_mnesia.erl
%%% Purpose : Network partition detector, Mnesia-related functions.
%%%----------------------------------------------------------------------

-module(partition_detector_mnesia).

-behaviour(gen_server).

-include("partition_detector.hrl").
-include("gmt_elog.hrl").

%% External exports
-export([start_link/1, get_state/0,
         get_mnesia_monitored_nodes/0, get_mnesia_monitored_nodes/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
         }).

-spec start_link(_) -> {ok, pid()} | {error, any()}.
-spec get_state() -> any().
-spec get_mnesia_monitored_nodes() -> any().
-spec get_mnesia_monitored_nodes(_,_) -> any().
%% 99% (100%?) boilerplate for gen_server callbacks?
-spec init(_) -> {ok, #state{}}.
-spec handle_call(_,_,_) -> {reply, any(), #state{}}.
-spec handle_cast(_,_) -> {noreply, #state{}}.
-spec handle_info(_,_) -> {noreply, #state{}}.
-spec terminate(_,_) -> any().
-spec code_change(_,_,_) -> {ok, any()}.

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start_link(ArgList) ->
    gen_server:start_link({local,?MODULE}, ?MODULE, ArgList, []).

get_state() ->
    gen_server:call(?MODULE, get_state, infinity).

get_mnesia_monitored_nodes() ->
    get_mnesia_monitored_nodes('gcxKV', disc_copies).

get_mnesia_monitored_nodes(Tab, StorageType) ->
    mnesia:table_info(Tab, StorageType).

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

init(_ArgList) ->
    %% TODO: Should we worry about a race condition where
    %% Mnesia noticed a bad event between the time that
    %% pss_sup started it and this point now?
    mnesia:subscribe(system),

    erlang:process_flag(priority, high),

    {ok, #state{}}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call(get_state, _From, State) ->
    {reply, State, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info({mnesia_system_event, {mnesia_overload, _Details}}, State) ->
    {noreply, State};
handle_info({mnesia_system_event,
             {inconsistent_database, Reason, NodeInfo}},
            State) ->
    ?ELOG_ERROR("Mnesia partitioned network error, reason = ~p, "
                "node info = ~p, aborting!",
                [Reason, NodeInfo]),
    %% Grrrrr.  We don't want to wait any longer, Mnesia is already
    %% hosed.  But it would be really very helpful to have the above
    %% app log message get scribbled to disk so we know why we shut
    %% ourselves down....
    timer:sleep(1),
    partition_detector_server:exec_emergency_shutdown_fun({?MODULE, self()}),
    {noreply, State};
handle_info({mnesia_system_event, Event}, State) ->
    case Event of
        {mnesia_up, NodeUp} ->
            ?ELOG_WARNING("Mnesia system event: node up: ~p",
                          [NodeUp]);
        {mnesia_down, NodeDown} ->
            ?ELOG_WARNING("Mnesia system event: node down: ~p",
                          [NodeDown]);
        Event ->
            ?ELOG_ERROR("Mnesia system event: ~p",
                        [Event])
    end,
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

