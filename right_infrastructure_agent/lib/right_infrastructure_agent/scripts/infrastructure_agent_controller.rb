# === Synopsis:
#   RightInfrastructureAgent Controller (rnac) - (c) 2009 RightScale
#
#   rnac is a command line tool for managing a RightInfrastructureAgents,
#   which includes mappers
#
# === Examples:
#   Start new agent named AGENT:
#     rnac --start AGENT
#     rnac -s AGENT
#
#   Stop running agent named AGENT:
#     rnac --stop AGENT
#     rnac -p AGENT
#
#   Stop agent with given serialized ID:
#     rnac --stop-agent ID
#
#   Terminate all agents on local machine:
#     rnac --killall
#     rnac -K
#
#   List running agents on local machine:
#     rnac --status
#     rnac -U
#
#   Start new agent named AGENT in foreground:
#     rnac --start AGENT --foreground
#     rnac -s AGENT -f
#
# === Usage:
#    rnac [options]
#
#    Options:
#      --start, -s AGENT    Start agent named AGENT
#      --stop, -p AGENT     Stop agent named AGENT
#      --stop-agent ID      Stop agent with serialized identity ID
#      --kill, -k PIDFILE   Kill process with given process id file
#      --killall, -K        Stop all running agents
#      --shutdown, -S       Send a terminate request to agent
#      --status, -U         List running agents on local machine
#      --identity, -i ID    Use base id ID to build agent's identity
#      --token, -t TOKEN    Use token TOKEN to build agent's identity
#      --prefix, -x PREFIX  Use prefix PREFIX to build agent's identity
#      --type TYPE          Use agent type TYPE to build agent's' identity,
#                           defaults to AGENT with any trailing '_[0-9]+' removed
#      --list, -l           List all RightScale agents
#      --user, -u USER      Set AMQP user
#      --pass, -p PASS      Set AMQP password
#      --vhost, -v VHOST    Set AMQP vhost
#      --host, -h HOST      Set AMQP server hostname for agent
#      --port, -P PORT      Set AMQP server port for agent
#      --cfg-dir, -c DIR    Set directory containing configuration for all agents
#      --pid-dir, -z DIR    Set directory containing agent process id files
#      --log-dir DIR        Set log directory
#      --log-level LVL      Log level (debug, info, warning, error or fatal)
#      --foreground, -f     Run agent/mapper in foreground
#      --interactive, -I    Spawn an irb shell after starting agent
#      --test               Use test settings
#      --debugger, -D PORT  Start a debug server on PORT and immediately break
#      --version, -v        Display version information
#      --help               Display help

require 'right_agent/scripts/agent_controller'

module RightScale

  class InfrastructureAgentController < AgentController

    include AgentFileHelper

    VERSION = [0, 2, 1]

    # Create and run controller
    #
    # === Return
    # true:: Always return true
    def self.run(debug = false)
      c = InfrastructureAgentController.new
      options = c.parse_args
      options[:user] = 'mapper' if options[:agent_type] == 'mapper' && options[:test]
      init_root_dir(options[:root_dir])
      c.control(options.merge(:debug => debug))
    end

    # Parse other arguments used by infrastructure agents
    #
    # === Parameters
    # opts(OptionParser):: Options parser with options to be parsed
    # options(Hash):: Storage for options that are parsed
    #
    # === Return
    # true:: Always return true
    def parse_other_args(opts, options)
      opts.on("-D", "--debugger PORT") do |port|
        options[:debug] = port
      end
    end

    protected

    # Start agent or mapper
    #
    # === Parameters
    # agent(Agent):: Agent class
    #
    # === Return
    # true:: Always return true
    def start_agent(agent = Agent)
      begin
        # Debugger is a special option, handle that first
        if @options[:debug]
          start_debugger(@options[:debug])
          exit
        end

        # Setup exception notification via email
        ExceptionMailer.configure_exception_callback(@options)

        # Use single thread in core agent to avoid having it pull more messages than
        # it can handle (doesn't make sense with multiple core agents running)
        @options[:single_threaded] = true

        # Actually start the agent (mapper has special logic)
        if @options[:agent_type] == 'mapper'
          start_mapper
        else
          super(InfrastructureAgent)
        end

      rescue SystemExit => e
        raise e
      rescue Exception => e
        puts "#{human_readable_name} failed with: #{e} in \n#{e.backtrace.join("\n")}"
      end
      true
    end

    # Start mapper
    #
    # === Return
    # true:: Always return true
    def start_mapper
      @options = agent_options(@options[:agent_name]).merge(@options)

      require File.expand_path(File.join(root_dir, 'lib', 'mapper'))

      @options[:exception_callback] = proc do |e, msg, mapper|
        FaultyAgentsTracker.handle_exception(msg, e, mapper)
        ExceptionMailer.deliver_notification(:mapper_receive_loop, msg, e)
      end

      puts "#{human_readable_name} being started"

      EM.error_handler do |e|
        msg = "EM block execution failed with exception: #{e}"
        Log.error(msg + "\n" + e.backtrace.join("\n"))
        Log.error("\n\n===== Exiting due to EM block exception =====\n\n")
        EM.stop
      end

      EM.run do
        begin
          @@agent = Mapper.start(@options)
        rescue SystemExit
          raise # Let parents of forked (daemonized) processes die
        rescue Exception => e
          puts "#{name} failed with: #{e} in \n#{e.backtrace.join("\n")}"
        end
      end
      true
    end

    # Start a debug server listening on the specified port
    #
    # === Parameters
    # port(Integer):: Listen port
    #
    # === Return
    # true:: Always return true
    def start_debugger(port)
      options = OpenStruct.new(
        'frame_bind'  => false,
        'host'        => nil,
        'load_mode'   => false,
        'port'        => port,
        'stop'        => true,
        'tracing'     => false
      )
      trap('INT') { Debugger.interrupt_last }

      # Set options
      Debugger.keep_frame_binding = options.frame_bind
      Debugger.tracing = options.tracing

      Debugger.debug_program(options)
      true
    end

    # Determine syslog program name based on options
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # (String):: Program name
    def syslog_program_name(options)
      options[:agent_name] || 'RightAgent'
    end

  end # InfrastructureAgentController

end # RightScale

# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.
