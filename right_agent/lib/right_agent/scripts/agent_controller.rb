# === Synopsis:
#   RightAgent Controller (rnac) - (c) 2009-2011 RightScale
#
#   rnac is a command line tool for managing a RightAgent
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
#   List agents configured on local machine:
#     rnac --list
#     rnac -l
#
#   List status of agents configured on local machine:
#     rnac --status
#     rnac -U
#
#   Start new agent named AGENT in foreground:
#     rnac --start AGENT --foreground
#     rnac -s AGENT -f
#
#   Start new agent named AGENT of type TYPE:
#     rnac --start AGENT --type TYPE
#     rnac -s AGENT -t TYPE
#
#   Note: To start multiple agents of the same type generate one
#         config.yml file with rad and then start each agent with rnac:
#         rad my_agent
#         rnac -s my_agent_1 -t my_agent
#         rnac -s my_agent_2 -t my_agent
#
# === Usage:
#    rnac [options]
#
#    options:
#      --start, -s AGENT      Start agent named AGENT
#      --stop, -p AGENT       Stop agent named AGENT
#      --stop-agent ID        Stop agent with serialized identity ID
#      --kill, -k PIDFILE     Kill process with given process id file
#      --killall, -K          Stop all running agents
#      --decommission, -d     Send decommission signal to instance agent
#      --shutdown, -S [AGENT] Send a terminate request to agent named AGENT,
#                             defaults to 'instance'
#      --status, -U           List running agents on local machine
#      --identity, -i ID      Use base id ID to build agent's identity
#      --token, -t TOKEN      Use token TOKEN to build agent's identity
#      --prefix, -x PREFIX    Use prefix PREFIX to build agent's identity
#      --type TYPE            Use agent type TYPE to build agent's' identity,
#                             defaults to AGENT with any trailing '_[0-9]+' removed
#      --list, -l             List all configured agents
#      --user, -u USER        Set AMQP user
#      --pass, -p PASS        Set AMQP password
#      --vhost, -v VHOST      Set AMQP vhost
#      --host, -h HOST        Set AMQP server hostname
#      --port, -P PORT        Set AMQP server port
#      --cfg-dir, -c DIR      Set directory containing configuration for all agents
#      --pid-dir, -z DIR      Set directory containing agent process id files
#      --log-dir DIR          Set log directory
#      --log-level LVL        Log level (debug, info, warning, error or fatal)
#      --foreground, -f       Run agent in foreground
#      --interactive, -I      Spawn an irb console after starting agent
#      --test                 Use test settings
#      --help                 Display help

require 'optparse'
require 'yaml'
require 'fileutils'
require 'rdoc/ri/ri_paths' # For backwards compatibility with ruby 1.8.5
require 'rdoc/usage'
require File.expand_path(File.join(File.dirname(__FILE__), 'rdoc_patch'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent'))
require File.expand_path(File.join(File.dirname(__FILE__), 'common_parser'))

module RightScale

  class AgentController

    include CommonParser

    FORCED_OPTIONS =
    {
      :threadpool_size => 1
    }

    DEFAULT_OPTIONS =
    {
      :single_threaded => true,
      :log_dir => Platform.filesystem.log_dir,
      :daemonize => true
    }

    @@agent = nil

    # Create and run controller
    #
    # === Return
    # true:: Always return true
    def self.run
      c = AgentController.new
      c.control(c.parse_args)
    end

    # Parse arguments and execute request
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # true:: Always return true
    def control(options)
      # Initialize directory settings
      AgentConfig.cfg_dir = options[:cfg_dir]
      AgentConfig.pid_dir = options[:pid_dir]

      # List agents if requested
      list_configured_agents if options[:list]

      # Validate arguments
      action = options.delete(:action)
      fail("No action specified on the command line.", print_usage = true) unless action
      if action == 'kill' && (options[:pid_file].nil? || !File.file?(options[:pid_file]))
        fail("Missing or invalid pid file #{options[:pid_file]}", print_usage = true)
      end
      if options[:agent_name]
        if action == 'start'
          cfg = configure_agent(action, options)
        else
          cfg = AgentConfig.load_cfg(options[:agent_name])
          fail("Deployment is missing configuration file #{AgentConfig.cfg_file(options[:agent_name]).inspect}.") unless cfg
        end
        options.delete(:identity)
        options = cfg.merge(options)
        AgentConfig.root_dir = options[:root_dir]
        AgentConfig.pid_dir = options[:pid_dir]
        Log.program_name = syslog_program_name(options)
        Log.log_to_file_only(options[:log_to_file_only])
        configure_proxy(options[:http_proxy], options[:http_no_proxy]) if options[:http_proxy]
      end
      @options = DEFAULT_OPTIONS.clone.merge(options.merge(FORCED_OPTIONS))
      FileUtils.mkdir_p(@options[:pid_dir]) unless @options[:pid_dir].nil? || File.directory?(@options[:pid_dir])

      # Execute request
      success = case action
      when /show|killall/
        action = 'stop' if action == 'killall'
        s = true
        AgentConfig.cfg_agents.each { |agent_name| s &&= run_cmd(action, agent_name) }
        s
      when 'kill'
        kill_process
      else
        run_cmd(action, @options[:agent_name])
      end

      exit(1) unless success
    end

    # Create options hash from command line arguments
    #
    # === Return
    # options(Hash):: Parsed options
    def parse_args
      options = {}

      opts = OptionParser.new do |opts|
        parse_common(opts, options)
        parse_other_args(opts, options)

        opts.on("-s", "--start AGENT") do |a|
          options[:action] = 'start'
          options[:agent_name] = a
        end

        opts.on("-p", "--stop AGENT") do |a|
          options[:action] = 'stop'
          options[:agent_name] = a
        end

        opts.on("--stop-agent ID") do |id|
          options[:action] = 'stop'
          options[:identity] = id
        end

        opts.on("-k", "--kill PIDFILE") do |file|
          options[:pid_file] = file
          options[:action] = 'kill'
        end
    
        opts.on("-K", "--killall") do
          options[:action] = 'killall'
        end

        opts.on("-d", "--decommission") do
          options[:action] = 'decommission'
          options[:agent_name] = 'instance'
        end

        opts.on("-S", "--shutdown [AGENT]") do |a|
          options[:action] = 'shutdown'
          options[:agent_name] = a || 'instance'
        end

        opts.on("-U", "--status") do
          options[:action] = 'show'
        end

        opts.on("-l", "--list") do
          options[:list] = true
        end

        opts.on("--log-level LVL") do |lvl|
          options[:log_level] = lvl
        end

        opts.on("-c", "--cfg-dir DIR") do |d|
          options[:cfg_dir] = d
        end

        opts.on("-z", "--pid-dir DIR") do |dir|
          options[:pid_dir] = dir
        end

        opts.on("--log-dir DIR") do |dir|
          options[:log_dir] = dir

          # Ensure log directory exists (for windows, etc.)
          FileUtils.mkdir_p(dir) unless File.directory?(dir)
        end

        opts.on("-f", "--foreground") do
          options[:daemonize] = false
          #Squelch Ruby VM warnings about various things 
          $VERBOSE = nil
        end

        opts.on("-I", "--interactive") do
          options[:console] = true
        end

        opts.on_tail("--help") do
          RDoc::usage_from_file(__FILE__)
          exit
        end

      end

      begin
        opts.parse(ARGV)
      rescue Exception => e
        exit 0 if e.is_a?(SystemExit)
        fail(e.message, print_usage = true)
      end
      resolve_identity(options)
      options
    end

    protected

    # Parse any other arguments used by agent
    #
    # === Parameters
    # opts(OptionParser):: Options parser with options to be parsed
    # options(Hash):: Storage for options that are parsed
    #
    # === Return
    # true:: Always return true
    def parse_other_args(opts, options)
      true
    end

    # Dispatch action
    #
    # === Parameters
    # action(String):: Action to be performed
    # agent_name(String):: Agent name
    #
    # === Return
    # true:: Always return true
    def run_cmd(action, agent_name)
      # Setup the environment from config if necessary
      begin
        case action
          when 'start'        then start_agent
          when 'stop'         then stop_agent(agent_name)
          when 'show'         then show_agent(agent_name)
          when 'decommission' then run_command('Decommissioning...', 'decommission')
          when 'shutdown'     then run_command('Shutting down...', 'terminate')
        end
      rescue SystemExit
        true
      rescue SignalException
        true
      rescue Exception => e
        msg = "Failed to #{action} #{agent_name} (#{e.class.to_s}: #{e.message})" + "\n" + e.backtrace.join("\n")
        puts msg
      end
      true
    end

    # Kill process defined in pid file
    #
    # === Parameters
    # sig(String):: Signal to be used for kill
    #
    # === Return
    # true:: Always return true
    def kill_process(sig = 'TERM')
      content = IO.read(@options[:pid_file])
      pid = content.to_i
      fail("Invalid pid file content #{content.inspect}") if pid == 0
      begin
        Process.kill(sig, pid)
      rescue Errno::ESRCH => e
        fail("Could not find process with pid #{pid}")
      rescue Errno::EPERM => e
        fail("You don't have permissions to stop process #{pid}")
      rescue Exception => e
        fail(e.message)
      end
      true
    end

    # Trigger execution of given command in instance agent and wait for it to be done
    #
    # === Parameters
    # message(String):: Console display message
    # command(String):: Command name
    #
    # === Return
    # true:: Always return true
    def run_command(message, command)
      options = AgentConfig.agent_options(@options[:agent_name])
      listen_port = options[:listen_port]
      unless listen_port
        puts "Could not retrieve listen port for agent #{@options[:identity]}"
        return false
      end
      puts message
      begin
        @client = CommandClient.new(listen_port, options[:cookie])
        @client.send_command({ :name => command }, verbose = false, timeout = 100) { |r| puts r }
      rescue Exception => e
        puts "Failed or else time limit was exceeded (#{e}).\nConfirm that the local instance is still running.\n#{e.backtrace.join("\n")}"
        return false
      end
      true
    end

    # Start agent
    #
    # === Parameters
    # agent(Agent):: Agent class
    #
    # === Return
    # true:: Always return true
    def start_agent(agent = Agent)
      puts "#{human_readable_name} being started"

      EM.error_handler do |e|
        msg = "EM block execution failed with exception: #{e}"
        Log.error(msg + "\n" + e.backtrace.join("\n"))
        Log.error("\n\n===== Exiting due to EM block exception =====\n\n")
        EM.stop
      end

      EM.run do
        begin
          @@agent = agent.start(@options)
        rescue SystemExit
          raise # Let parents of forked (daemonized) processes die
        rescue PidFile::AlreadyRunning
          puts "#{human_readable_name} already running"
          EM.stop
        rescue Exception => e
          puts "#{human_readable_name} failed with: #{e} in \n#{e.backtrace.join("\n")}"
          EM.stop
        end
      end
      true
    end
    
    # Stop agent process
    #
    # === Parameters
    # agent_name(String):: Agent name
    #
    # === Return
    # (Boolean):: true if process was stopped, otherwise false
    def stop_agent(agent_name)
      res = false
      if pid_file = AgentConfig.pid_file(agent_name)
        name = human_readable_name(agent_name, pid_file.identity)
        if pid = pid_file.read_pid[:pid]
          begin
            Process.kill('TERM', pid)
            res = true
            puts "#{name} stopped"
          rescue Errno::ESRCH
            puts "#{name} not running"
          end
        elsif File.file?(pid_file.to_s)
          puts "Invalid pid file '#{pid_file.to_s}' content: #{IO.read(pid_file.to_s)}"
        else
          puts "#{name} not running"
        end
      else
        puts "Non-existent pid file for #{agent_name}"
      end
      res
    end

    # Show status of agent
    #
    # === Parameters
    # agent_name(String):: Agent name
    #
    # === Return
    # (Boolean):: true if process is running, otherwise false
    def show_agent(agent_name)
      res = false
      if (pid_file = AgentConfig.pid_file(agent_name)) && (pid = pid_file.read_pid[:pid])
        pgid = Process.getpgid(pid) rescue -1
        name = human_readable_name(agent_name, pid_file.identity)
        if pgid != -1
          psdata = `ps up #{pid}`.split("\n").last.split
          memory = (psdata[5].to_i / 1024)
          puts "#{name} is alive, using #{memory}MB of memory"
          res = true
        else
          puts "#{name} is not running but has a stale pid file at #{pid_file}"
        end
      elsif identity = AgentConfig.agent_options(agent_name)[:identity]
        puts "#{human_readable_name(agent_name, identity)} is not running"
      end
      res
    end

    # Generate human readable name for agent
    #
    # === Return
    # (String):: Human readable name
    def human_readable_name(agent_name = nil, identity = nil)
      agent_name ||= @options[:agent_name]
      "Agent #{agent_name + ' ' if agent_name}with ID #{identity || @options[:identity]}"
    end

    # List all configured agents
    #
    # === Return
    # never
    def list_configured_agents
      agents = AgentConfig.cfg_agents
      if agents.empty?
        puts "Found no configured agents"
      else
        puts "Configured agents:"
        agents.each { |a| puts "  - #{a}" }
      end
      exit
    end

    # Determine syslog program name based on options
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # (String):: Program name
    def syslog_program_name(options)
      'RightAgent'
    end

    # Determine configuration settings for this agent and persist them if needed
    # Reuse existing agent identity when possible
    #
    # === Parameters
    # action(String):: Requested action
    # options(Hash):: Command line options
    #
    # === Return
    # cfg(Hash):: Persisted configuration options
    def configure_agent(action, options)
      agent_type = options[:agent_type]
      agent_name = options[:agent_name]
      cfg = AgentConfig.load_cfg(agent_type)
      fail("Deployment is missing configuration file #{AgentConfig.cfg_file(agent_type).inspect}.") unless cfg
      if agent_name != agent_type
        base_id = (options[:base_id] || AgentIdentity.parse(cfg[:identity]).base_id.to_s).to_i
        unless (identity = AgentConfig.agent_options(agent_name)[:identity]) &&
               AgentIdentity.parse(identity).base_id == base_id
          identity = AgentIdentity.new(options[:prefix] || 'rs', options[:agent_type], base_id, options[:token]).to_s
        end
        cfg.merge!(:identity => identity)
        cfg_file = AgentConfig.store_cfg(agent_name, cfg)
        puts "Generated configuration file for #{agent_name} agent: #{cfg_file}"
      end
      cfg
    end

    # Enable the use of an HTTP proxy for this process and its subprocesses
    #
    # === Parameters
    # proxy_setting(String):: Proxy to use
    # exceptions(String):: Comma-separated list of proxy exceptions (e.g. metadata server)
    #
    # === Return
    # true:: Always return true
    def configure_proxy(proxy_setting, exceptions)
      ENV['HTTP_PROXY'] = proxy_setting
      ENV['http_proxy'] = proxy_setting
      ENV['HTTPS_PROXY'] = proxy_setting
      ENV['https_proxy'] = proxy_setting
      ENV['NO_PROXY'] = exceptions
      ENV['no_proxy'] = exceptions
      true
    end

    # Print error on console and exit abnormally
    #
    # === Parameters
    # message(String):: Error message to be displayed
    # print_usage(Boolean):: Whether to display usage information
    #
    # === Return
    # never
    def fail(message, print_usage = false)
      puts "** #{message}"
      RDoc::usage_from_file(__FILE__) if print_usage
      exit(1)
    end

  end
end

#
# Copyright (c) 2009-2011 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
