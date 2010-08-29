%%%----------------------------------------------------------------------
%%% Copyright: (c) 2006-2010 Gemini Mobile Technologies, Inc.  All rights reserved.
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
%%% File     : partition_detector.erl
%%% Purpose  : Network partition detector.
%%%----------------------------------------------------------------------

-module(partition_detector).

-behaviour(application).

%% application callbacks
-export([start/0, start/2, stop/1]).
-export([start_phase/3, prep_stop/1, config_change/3]).


-spec start() -> {ok, pid()} | {error, any()}.
-spec start(_,_) -> {ok, pid()} | {error, any()}.
-spec start_phase(_,_,_) -> 'ok'.
-spec prep_stop(_) -> any().
-spec config_change(_,_,_) -> 'ok'.
-spec stop(_) -> 'ok'.


%%%----------------------------------------------------------------------
%%% Callback functions from application
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: start/2
%% Returns: {ok, Pid}        |
%%          {ok, Pid, State} |
%%          {error, Reason}
%%----------------------------------------------------------------------
start() ->
    start(xxxwhocares, []).

start(_Type, StartArgs) ->
    io:format("DEBUG: ~s: application:start_type() = ~p\n",
              [?MODULE, application:start_type()]),

    case partition_detector_sup:start_link(StartArgs) of
        {ok, Pid} ->
            io:format("DEBUG: ~s:start_phase: self() = ~p, sup pid = ~p\n",
                      [?MODULE, self(), Pid]),
            {ok, Pid};
        Error ->
            io:format("QQQ: ~s:start bummer: ~p\n", [?MODULE, Error]),
            Error
    end.

%% Lesser-used callbacks....

start_phase(_Phase, _StartType, _PhaseArgs) ->
    io:format("DEBUG: ~s:start_phase(~p, ~p, ~p)\n",
              [?MODULE, _Phase, _StartType, _PhaseArgs]),
    ok.

prep_stop(State) ->
    io:format("DEBUG: ~s:prep_stop(~p)\n", [?MODULE, State]),
    State.

config_change(_Changed, _New, _Removed) ->
    io:format("DEBUG: ~s:config_change(~p, ~p, ~p)\n",
              [?MODULE, _Changed, _New, _Removed]),
    ok.


%%----------------------------------------------------------------------
%% Func: stop/1
%% Returns: any
%%----------------------------------------------------------------------
stop(_State) ->
    io:format("DEBUG: ~s:stop(~p)\n", [?MODULE, _State]),
    %% gmt_event_h:delete_report_handler(),
    ok.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------
