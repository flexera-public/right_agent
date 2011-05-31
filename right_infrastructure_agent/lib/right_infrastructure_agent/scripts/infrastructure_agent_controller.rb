# === Synopsis:
#   RightScale RightNet Infrastructure Agent Controller (rnac) - (c) 2009 RightScale
#
#   rnac is a command line tool that allows managing RightNet infrastructure agents and mappers
#
# === Examples:
#   Start new core agent:
#     rnac --start core
#     rnac -s core
#
#   Start new mapper:
#     rnac --start mapper
#     rnac -s mapper
#
#   Stop running core agent:
#     rnac --stop core
#     rnac -p core
#
#   Stop running mapper:
#     rnac --stop mapper
#     rnac -p mapper
#
#   Stop agent or mapper with given serialized ID:
#     rnac --stop-agent ID
#
#   Terminate all agents and mappers:
#     rnac --killall
#     rnac -K
#
#   List running agents and mappers on /right_net vhost:
#     rnac --status --vhost /right_net
#     rnac -U -v /right_net
#
#   Start new agent or mapper in foreground:
#     rnac --start AGENT --foreground
#     rnac -s AGENT -f
#
# === Usage:
#    rnac [options]
#
#    options:
#      --start, -s AGENT    Start agent or mapper with name AGENT
#      --stop, -p AGENT     Stop agent or mapper with name AGENT
#      --stop-agent ID      Stop agent or mapper with serialized identity ID
#      --kill, -k PIDFILE   Kill process with given pid file
#      --killall, -K        Stop all running agents
#      --shutdown, -S       Sends a terminate request to agent or mapper
#      --status, -U         List running agents on local machine
#      --identity, -i ID    Use base id ID to build agent's identity
#      --token, -t TOKEN    Use token TOKEN to build agent's identity
#      --prefix, -r PREFIX  Prefix agent's identity with PREFIX
#      --list, -l           List all RightScale agents
#      --user, -u USER      Set AMQP user
#      --pass, -p PASS      Set AMQP password
#      --vhost, -v VHOST    Set AMQP vhost
#      --host, -h HOST      Set AMQP server hostname for agent
#      --port, -P PORT      Set AMQP server port for agent
#      --log-level LVL      Log level (debug, info, warning, error or fatal)
#      --log-dir DIR        Log directory
#      --pid-dir DIR        Pid files directory (/tmp by default)
#      --alias ALIAS:       Run as alias of given agent (i.e. use different config but same name as alias)
#      --foreground, -f     Run agent/mapper in foreground
#      --interactive, -I    Spawn an irb shell after starting agent
#      --test               Use test settings
#      --debugger, -D PORT  Start a debug server on PORT and immediately break
#      --version, -v        Display version information
#      --help               Display help

require 'ostruct'
require File.join(RightScale::RightNetConfig[:right_link_path], 'scripts', 'lib', 'agent_controller')
require File.join(RightScale::RightNetConfig[:right_net_path], 'agents', 'lib', 'exception_mailer')
require File.join(RightScale::RightNetConfig[:right_net_path], 'agents', 'lib', 'infrastructure_agent')
require File.join(RightScale::RightNetConfig[:right_net_path], 'mapper', 'lib', 'mapper')
require File.join(RightScale::RightNetConfig[:right_net_path], 'mapper', 'lib', 'new_relic_instrumentation')

module RightScale

  class InfrastructureAgentController < AgentController

    include Utils

    VERSION = [0, 2, 1]
    MAPPER_DEFAULT_OPTIONS = {}

    @@mapper = nil

    # Convenience wrapper
    def self.run(debug = false)
      c = InfrastructureAgentController.new
      options = c.parse_args
      options[:user] = 'mapper' if c.mapper?(options) && options[:test]
      # In development environment allow this utility to also be used for instance agents
      RightNetConfig[:right_net_path] = RightNetConfig[:right_link_path] if c.instance?(options)
      c.control(options.merge(:debug => debug))
    end

    # Parse any other arguments used by infrastructure agents
    def parse_other_args(opts, options)
      opts.on("-D", "--debugger PORT") do |port|
        options[:debug] = port
      end
    end

    # Determine whether this is a mapper
    def mapper?(options)
      (options[:alias] || options[:agent]) == 'mapper'
    end

    # Determine whether this is an instance agent
    def instance?(options)
      (options[:alias] || options[:agent]) == 'instance'
    end

    protected

    # Start agent or mapper, return true
    def start_agent(agent = Agent)
      begin
        # Debugger is a special option, handle that first
        if @options[:debug]
          start_debugger(@options[:debug])
          exit
        end

        #Setup exception notification via email
        ExceptionMailer.configure_exception_callback(@options)

        # Use single thread in core agent to avoid having it pull more messages than
        # it can handle (doesn't make sense with multiple core agents running)
        @options[:single_threaded] = true

        # Actually start the agent (mapper has special logic)
        if mapper?(@options)
          start_mapper
        else
          super(InfrastructureAgent)
        end

      rescue SystemExit => e
        raise e
      rescue Exception => e
        puts "#{name} failed with: #{e.message} in \n#{e.backtrace.join("\n")}"
      end
      true
    end

    def start_mapper
      # Debugger is a special option, handle that first
      if @options[:debug]
        start_debugger(@options[:debug])
        exit
      end
      options = MAPPER_DEFAULT_OPTIONS.merge(agent_options(@options[:agent]))
      @options = options.merge(@options)

      Dir["#{mapper_dir}/*.rb"].each do |dep|
        require dep
      end

      @options[:exception_callback] = proc do |e, msg, mapper|
          FaultyAgentsTracker.handle_exception(msg, e, mapper)
          ExceptionMailer.deliver_notification(:mapper_receive_loop, msg, e)
      end

      puts "#{name} started."

      EM.error_handler do |e|
        msg = "EM block execution failed with exception: #{e.message}"
        RightLinkLog.error(msg + "\n" + e.backtrace.join("\n"))
        RightLinkLog.error("\n\n===== Exiting due to EM block exception =====\n\n")
        EM.stop
      end

      EM.run do
        begin
          @@mapper = Mapper.start(@options)
        rescue SystemExit
          raise # Let parents of forked (daemonized) processes die
        rescue Exception => e
          puts "#{name} failed with: #{e.message} in \n#{e.backtrace.join("\n")}"
        end
      end
    end

    # Show status of given agent or mapper, return true on success, false otherwise
    def show_agent(id)
      show(pid_file(id))
    end
    
    # Stop given agent or mapper, return true on success, false otherwise
    def stop_agent(id)
      try_kill(pid_file(id))
    end

    # Start a debug server listening on the specified port
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

      # set options
      Debugger.keep_frame_binding = options.frame_bind
      Debugger.tracing = options.tracing

      Debugger.debug_program(options)
    end

    # Human readable name for managed entity
    def name
      if mapper?(@options)
        "Mapper with ID #{@options[:identity]}"
      else
        "Agent #{@options[:agent] + ' ' if @options[:agent]}with ID #{@options[:identity]}"
      end
    end

    # Version information
    def syslog_program_name(options)
      options[:identity] || options[:agent] || 'RightNet'
    end

    # Retrieve mapper pid file
    def mapper_pid_file
      mapper = Mapper.new(@options)
      PidFile.new(mapper.identity, mapper.options)
    end
    
    # List of running mapper IDs
    def running_mappers
      list = `rabbitmqctl list_queues -p #{@options[:vhost]}`
      list.scan(/^[^-]*-(.*\*mapper\*[\S]+)/).flatten.uniq
    end

    # Path to mapper configuration files
    def mapper_dir
      File.join(root_path, 'mapper', 'lib')
    end

    # Retrieve pid file from given agent/mapper id or agent name from options
    # Use agent name for easier command line but allow using id for the case
    # where multiple agents with the same name may be running
    def pid_file(id)
      @options[:identity] = id
      agent = @options[:alias] || @options[:agent] || AgentIdentity.parse(id).agent_name rescue nil
      if agent == 'mapper'
        pid_file = mapper_pid_file
      elsif @options[:agent]
        pid_file = agent_pid_file(@options[:agent])
      else
        pid_file = agent_pid_file_from_id(@options, id)
      end
      pid_file            
    end
  
  end # InfrastructureAgentController

end # RightScale
