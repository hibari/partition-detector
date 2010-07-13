%%%-------------------------------------------------------------------
%%% $Id$
%%% Description: application log partition_detector
%%% Copyright: (c) 2007 Gemini Mobile Technologies, Inc.  All rights reserved.
%%%-------------------------------------------------------------------

-include("gmt_event_h.hrl").


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%% @doc PARTITION DETECTOR conf class
%%
-define(APPLOG_ERRORCODE_CONF(X),
        ?APPLOG_005 + ?APPLOG_CLASS_CONF + X).

%%
%% 4|No configuration info available for ~p|2140506|Specify valid
%% configuration value if central.conf config file if use of this
%% feature is desired, then restart PSS/LSS.|NETWORK_MONITOR
%%
%% @doc cause      No configuration info available
%% @doc effect     The partition detector application will be disabled.
%% @doc action     Specify valid interface address & broadcast address values in central.conf config file if use
%%                 of this feature is desired, then restart node.
%% @doc monitor    Yes
-define(APPLOG_CONF_001, ?APPLOG_ERRORCODE_CONF(1)).

%%
%% 4|Invalid configuration value for ~p: ~p|2140514|Specify valid
%% configuration value in central.conf config file.  Restart
%% PSS/LSS.|PSS_CONFIG
%%
%% @doc cause      Invalid configuration value
%% @doc effect     The partition detector application will be disabled.
%% @doc action     Specify valid interface address & broadcast address values in central.conf config file if use
%%                 of this feature is desired, then restart node.
%% @doc monitor    Yes
-define(APPLOG_CONF_002, ?APPLOG_ERRORCODE_CONF(2)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%% @doc PARTITION DETECTOR appm class
%%
-define(APPLOG_ERRORCODE_APPM(X),
        ?APPLOG_005 + ?APPLOG_CLASS_APPM + X).

%%
%% 1|Mnesia partitioned network error, node info = ~p,
%% aborting!|2110501|A Mnesia node, named by "~p", has joined the
%% cluster.  It has out-of-date cluster configuration and/or
%% out-of-date PSS/LSS data.  This node (and all other nodes in the
%% cluster) will shut down immediately to avoid further data
%% inconsistency.  Follow Mnesia repair procedure.|MNESIA
%%
%% @doc cause      A Mnesia node, named by "~p", has joined the cluster.  It has
%%                 out-of-date cluster configuration and/or out-of-date PSS/LSS data.
%% @doc effect     This node (and all other nodes in the cluster) will shut down
%%                 immediately to avoid further data inconsistency.
%% @doc action     Follow Mnesia repair procedure.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_001, ?APPLOG_ERRORCODE_APPM(1)).

%%
%% 1|Network 'A' is partitioned.  Heartbeats from ~p on network 'A'
%% are lost (~p seconds) but are functioning normally on network 'B'
%% (last heard ~p seconds ago)|2110502|A partition on Network 'A' has
%% been detected.  Heartbeats on Network 'B' are working correctly.
%% The time since the last heartbeat on Network 'A' is reported in the
%% log message; this time is greater than the
%% "heartbeat_failure_interval" configuration parameter.  Mnesia node
%% shutdown of some/all nodes is imminent.  Fix network partition
%% immediately.|NETWORK_MONITOR
%%
%% @doc cause      A partition on Network 'A' has been detected.  Heartbeats on
%%                 Network 'B' are working correctly.  The time since the last
%%                 heartbeat on Network 'A' is reported in the log message; this time
%%                 is greater than the "heartbeat_failure_interval" configuration
%%                 parameter.
%% @doc effect     Mnesia node shutdown of some/all nodes is imminent.
%% @doc action     Fix network partition immediately.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_002, ?APPLOG_ERRORCODE_APPM(2)).

%% 1|Network 'A' is partitioned.  Unable to ping ~s.  Starting
%% emergency shutdown to prevent database damage.|2110503|Fix network
%% partition immediately, then restart this node.|NETWORK_MONITOR
%%
%% @doc cause      Network 'A' is partitioned.
%% @doc effect     Mnesia node shutdown of some/all nodes is imminent.
%% @doc action     Fix network partition immediately, then restart this node.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_003, ?APPLOG_ERRORCODE_APPM(3)).

%% 1|Network 'A' is partitioned.  Able to successfully ping ~s.
%% Continuing operation.|2110504|Fix network partition
%% immediately.|NETWORK_MONITOR
%%
%% @doc cause      Network 'A' is partitioned.
%% @doc effect     Continueing operation.
%% @doc action     Fix network partition immediately.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_004, ?APPLOG_ERRORCODE_APPM(4)).

%%
%% orphan errorcode:
%%
%% 1|Mnesia partitioned network error, aborting!  Msg =
%% ~s|2110505|Follow Mnesia repair procedure.|MNESIA
%%
%%

%% 1|Shutdown beacon received: ~p|2110506|Follow Mnesia repair
%% procedure.|MNESIA
%%
%% @doc cause      Shutdown in progress.
%% @doc effect     This node (and all other nodes in the cluster) will shut down
%%                 immediately to avoid further data inconsistency.
%% @doc action     Follow Mnesia repair procedure.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_005, ?APPLOG_ERRORCODE_APPM(5)).

%% 1|Alarm SET: network_heartbeat: ~p|2110507|A PSS/LSS application
%% has been set because UDP heartbeat packets have not been detected
%% from the identified cluster member on the identified network ('A'
%% or 'B').  The alarm will remain set until a heartbeat packet from
%% that host and on that network has been received.  Fix alarm
%% cause.|NETWORK_MONITOR
%%
%% @doc cause      An application has been set because UDP heartbeat packets
%%                 have not been detected from the identified cluster member on the
%%                 identified network ('A' or 'B').
%% @doc effect     The alarm will remain set until a heartbeat packet from that host
%%                 and on that network has been received.
%% @doc action     Fix alarm cause.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_006, ?APPLOG_ERRORCODE_APPM(6)).

%% 1|Alarm CLEAR: network_heartbeat: ~p|2110508|A heartbeat packet
%% from that host and on that network has been received.  Alarm has
%% been cancelled.  No further action required.|NETWORK_MONITOR
%%
%% @doc cause      A heartbeat packet from that host and on that network has been
%%                 received.
%% @doc effect     Alarm has been cancelled.
%% @doc action     No further action required.
%%
-define(APPLOG_APPM_007, ?APPLOG_ERRORCODE_APPM(7)).

%% 1|Async shutdown function in ~s called|2110509||NETWORK_MONITOR
%%
%% @doc cause      The default asynchronous shutdown function for Mnesia has been called.
%% @doc effect     Mnesia will be shutdown on the local node.
%% @doc action     Fix the reason for the Mnesia shutdown, then restart the node.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_008, ?APPLOG_ERRORCODE_APPM(8)).

%% 1|Calling emergency shutdown function:
%% ~p:~p/0|2110510||NETWORK_MONITOR
%%
%% @doc cause      The application-specific shutdown function for Mnesia has been called.
%% @doc effect     Mnesia will be shutdown on the local node.
%% @doc action     Fix the reason for the Mnesia shutdown, then restart the node.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_009, ?APPLOG_ERRORCODE_APPM(9)).

%% 4|Network monitor is not enabled|2140507||NETWORK_MONITOR
%%
%% @doc cause      The network partition detector has been disabled by configuration.  Such configuration is not recommended in any production network environment.
%% @doc effect     This configuration is not recommended in any production network environment.
%% @doc action     Properly configure all partition detector elements in central.conf, then restart the local node.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_010, ?APPLOG_ERRORCODE_APPM(10)).

%% 4|Mnesia system event: ~P|2140508||MNESIA
%%
%% @doc cause      The Mnesia application has logged an event.
%% @doc effect     Consult actual message actually logged for detail.
%% @doc action     Consult actual message actually logged for detail.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_011, ?APPLOG_ERRORCODE_APPM(11)).

%% 4|Partition of network 'A' is possible.  Heartbeats from ~p on
%% network 'A' are lost (~p seconds) but are functioning normally on
%% network 'B' (last heard ~p seconds ago)|2140519|A possible
%% partition on Network 'A' has been detected.  Heartbeats on Network
%% 'B' are working correctly.  The time since the last heartbeat on
%% Network 'A' is reported in the log message; this time is less than
%% the "heartbeat_failure_interval" configuration parameter.  Mnesia
%% node shutdown of some/all nodes is imminent.  Fix network partition
%% immediately.|NETWORK_MONITOR
%%
%% @doc cause      A possible partition on Network 'A' has been detected.  Heartbeats
%%                 on Network 'B' are working correctly.  The time since the last
%%                 heartbeat on Network 'A' is reported in the log message; this time
%%                 is less than the "heartbeat_failure_interval" configuration
%%                 parameter.
%% @doc effect     Mnesia node shutdown of some/all nodes is imminent.
%% @doc action     Fix network partition immediately.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_012, ?APPLOG_ERRORCODE_APPM(12)).

%%
%% orphan code:
%%
%% 4|Received heartbeat on network 'A' from node ~p.  This node is
%% believed to be down.|2140520|Correct the problem on network 'A'
%% immediately.|NETWORK_MONITOR
%%

%% 4|Mnesia system event: node up: ~p|2140521|No further action
%% required.|MNESIA
%%
%% @doc cause      Node up event.
%% @doc effect     Service will resume.
%% @doc action     No further action required.
%%
-define(APPLOG_APPM_013, ?APPLOG_ERRORCODE_APPM(13)).

%% 4|Mnesia system event: node down: ~p|2140522|A Mnesia node, named
%% by "~p", has left the cluster.  The reason is not known.  It may be
%% because that node was shut down by the administrator, it crashed,
%% or because of network errors/timeouts on Network 'A'.  Check status
%% of the failed node.  Check network status.  Check application log
%% for heartbeat failures.|MNESIA
%%
%% @doc cause      A Mnesia node, named by "~p", has left the cluster.  The reason is
%%                 not known.  It may be because that node was shut down by the
%%                 administrator, it crashed, or because of network errors/timeouts on
%%                 Network 'A'.
%% @doc effect     Service may be interrupted.
%% @doc action     Check status of the failed node.  Check network status.  Check
%%                 application log for heartbeat failures.
%% @doc monitor    Yes
%%
-define(APPLOG_APPM_014, ?APPLOG_ERRORCODE_APPM(14)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%% @doc PARTITION DETECTOR netw class
%%
-define(APPLOG_ERRORCODE_NETW(X),
        ?APPLOG_005 + ?APPLOG_CLASS_NETW + X).

%% 4|Error opening UDP port ~p on ~p: ~p|2140516|While trying to open
%% a UDP socket on UDP port {first "~p"}, an OS error happened,
%% {second "~p"}.  Check config file.  Check system resources.
%% Restart PSS/LSS.|PSS_CONFIG
%%
%% @doc cause      While trying to open a UDP socket on UDP port {first "~p"}, an OS
%%                 error happened, {second "~p"}.
%% @doc effect     Node will not start.
%% @doc action     Check config file.  Check system resources. Restart Node.
%%
-define(APPLOG_NETW_001, ?APPLOG_ERRORCODE_NETW(1)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%% @doc PARTITION DETECTOR info class
%%
-define(APPLOG_ERRORCODE_INFO(X),
        ?APPLOG_005 + ?APPLOG_CLASS_INFO + X).

%% 6|Received UDP unicast beacon: ~p|2160509||NETWORK_MONITOR
%%
%% @doc cause      A UDP unicast beacon packet was received.
%% @doc effect     Application-specific.
%% @doc action     Informational Only.
%%
-define(APPLOG_INFO_001, ?APPLOG_ERRORCODE_INFO(1)).

%% 6|New emergency shutdown fun: ~p|2160510||NETWORK_MONITOR
%%
%% @doc cause      A new emergency shutdown function was configured.
%% @doc effect     Application-specific.
%% @doc action     Informational Only.
%%
-define(APPLOG_INFO_002, ?APPLOG_ERRORCODE_INFO(2)).

%%
%% orphan comment: 2160511 has been moved
%%

%% 6|Partition detector: active status on node ~p|2160512|No further
%% action required.|NETWORK_MONITOR
%%
%% @doc cause      The partition detector application is now active on the local node.
%% @doc effect     Application-specific.
%% @doc action     Informational Only.
%%
-define(APPLOG_INFO_003, ?APPLOG_ERRORCODE_INFO(3)).

%% 6|Partition detector: standby status on node ~p|2160513|No further
%% action required.|NETWORK_MONITOR
%%
%% @doc cause      The partition detector application is now in standby mode on the local node.
%% @doc effect     Application-specific.
%% @doc action     Informational Only.
%%
-define(APPLOG_INFO_004, ?APPLOG_ERRORCODE_INFO(4)).

%% 6|Partition detector: active status on node ~p|2160512|No further
%% action required.|NETWORK_MONITOR
%%
%% @doc cause      The partition detector application has switched from standby mode to active mode on the local node.
%% @doc effect     Application-specific.
%% @doc action     Informational Only.
%%
-define(APPLOG_INFO_005, ?APPLOG_ERRORCODE_INFO(5)).

%% @doc cause      The partition detector's emergency shutdown function has been called.
%% @doc effect     Application-specific.
%% @doc action     Informational Only.
%%
-define(APPLOG_INFO_006, ?APPLOG_ERRORCODE_INFO(6)).

