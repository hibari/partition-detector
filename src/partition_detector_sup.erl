%%%-------------------------------------------------------------------
%%% Copyright (c) 2006-2017 Hibari developers.  All rights reserved.
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
%%% File    : partition_detector_sup.erl
%%% Purpose : Top-level partition detector supervisor
%%%----------------------------------------------------------------------

-module(partition_detector_sup).

-behaviour(supervisor).

%% API
-export([start_link/1]).

%% Supervisor callbacks
-export([init/1]).


-spec start_link(_) -> {ok, pid()} | ignore | {error, any()}.
-spec init(_) -> {ok, any()}.


-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the supervisor
%%--------------------------------------------------------------------
start_link(ArgList) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, ArgList).

%%====================================================================
%% Supervisor callbacks
%%====================================================================
%%--------------------------------------------------------------------
%% Func: init(Args) -> {ok,  {SupFlags,  [ChildSpec]}} |
%%                     ignore                          |
%%                     {error, Reason}
%% Description: Whenever a supervisor is started using
%% supervisor:start_link/[2,3], this function is called by the new process
%% to find out about restart strategy, maximum restart frequency and child
%% specifications.
%%--------------------------------------------------------------------
init(ArgList) ->
    %% Hint:
    %% Child_spec = [Name, {M, F, A},
    %%               Restart, Shutdown_time, Type, Modules_used]

    Detector =
        {partition_detector_server, {partition_detector_server, start_link,
                                     [ArgList]},
         permanent, 2000, worker, [partition_detector_server]},
    Mnesia =
        {partition_detector_mnesia, {partition_detector_mnesia, start_link,
                                     [[]]},
         permanent, 2000, worker, [partition_detector_mnesia]},


    {ok, {{one_for_one, 15, 60},
          [ Detector ] ++
              [ Mnesia || code:which(mnesia) =/= non_existing ]
         }}.

%%====================================================================
%% Internal functions
%%====================================================================

