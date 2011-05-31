# === Synopsis:
#   RightScale RightNet Statistics Manager (rstat) - (c) 2010 RightScale
#
#   rstat is a command line tool that displays operation statistics for RightNet servers
#   running on this machine or for servers that have published statistics to the "stats" exchange
#
#   Statistics are displayed for all servers unless specific servers are selected with options
#
# === Usage:
#    rstat [options]
#
#    options:
#      --broker, -b       Only display stats for the brokers on this machine
#      --core, -c         Only display stats for the core agents on this machine
#      --mapper, -m       Only display stats for the mappers on this machine
#      --instance, -i     Only display stats for the instances on this machine
#      --home-island ID   Override mapper home RightNet island setting
#      --reset, -r        As part of gathering the stats from a server also reset the stats
#      --stats, -s KEY    Receive and display stats published to the "stats" exchange with a routing
#                         key matching the specified key of form "stats.<agent name>.<token id>",
#                         e.g., stats.instance.2735167, or stats.core.*
#                         Note: Only supported on machines configured with a mapper
#      --timeout, -t SEC  Override default timeout in seconds to wait for a response from a server or
#                         set the number of seconds to listen on the "stats" exchange rather than forever
#      --json, -j         Dump the stats data in JSON format
#      --version          Display version information
#      --help             Display help

require 'optparse'
require File.join(RightScale::RightNetConfig[:right_link_path], 'common', 'lib', 'common')
require File.join(RightScale::RightNetConfig[:right_link_path], 'command_protocol', 'lib', 'command_protocol')
require File.join(RightScale::RightNetConfig[:right_link_path], 'scripts', 'lib', 'agent_utils')
require 'rdoc/usage'
require File.join(RightScale::RightNetConfig[:right_link_path], 'scripts', 'lib', 'rdoc_patch')

module RightScale

  class StatsManager

    include Utils
    include StatsHelper

    VERSION = [0, 1, 0]

    DEFAULT_TIMEOUT = 5

    SERVERS = ["broker", "mapper", "mapper_2", "core", "core_2, instance, instance_2"]

    DEFAULT_AMQP_OPTIONS = {
      :vhost       => '/right_net',
      :user        => 'test',
      :pass        => 'testing',
      :home_island => nil
    }

    # Create stats manager
    def initialize
      @command_serializer = Serializer.new
    end

    # Convenience wrapper
    def self.run
      begin
        c = StatsManager.new
        options = c.parse_args

        RightLinkLog.program_name = "stats_manager"
        RightLinkLog.log_to_file_only(true)
        RightLinkLog.init("stats_manager", RightLinkConfig[:platform].filesystem.log_dir, :print => true)

        if options[:key]
          c.receive_stats(options)
        else
          options[:timeout] ||= DEFAULT_TIMEOUT
          c.request_stats(options)
        end
      rescue Exception => e
        puts "\nFailed with: #{e}\n#{e.backtrace.join("\n")}" unless e.is_a?(SystemExit)
      end
    end

    # Parse arguments
    def parse_args
      # The options specified in the command line will be collected in 'options'
      options = {:servers => [], :reset => false}

      opts = OptionParser.new do |opts|

        opts.on('-b', '--broker') do
          options[:servers] << "broker"
        end

        opts.on('-c', '--core') do
          options[:servers] << "core"
          options[:servers] << "core_2"
        end

        opts.on('-m', '--mapper') do
          options[:servers] << "mapper"
          options[:servers] << "mapper_2"
        end

        opts.on('-i', '--instance') do
          options[:servers] << "instance"
          options[:servers] << "instance_2"
        end

        opts.on('-r', '--reset') do
          options[:reset] = true
        end

        opts.on('-s', '--stats KEY') do |key|
          options[:key] = key
        end

        opts.on('-t', '--timeout SEC') do |sec|
          options[:timeout] = sec
        end

        opts.on('--home-island ID') do |id|
          options[:home_island] = id
        end

        opts.on('-j', '--json') do
          options[:json] = true
        end

        opts.on_tail('--help') do
          RDoc::usage_from_file(__FILE__)
          exit
        end

        opts.on_tail('--version') do
          puts version
          exit
        end

      end

      begin
        opts.parse(ARGV)
      rescue Exception => e
        exit 0 if e.is_a?(SystemExit)
        fail(e.message + "\nUse 'rstat --help' for additional information")
      end

      options
    end

    # Request and display statistics from servers on this machine
    #
    # === Parameters
    # options(Hash):: Configuration options
    #
    # === Return
    # true:: Always return true
    def request_stats(options)
      count = 0
      SERVERS.each do |s|
        if options[:servers].empty? || options[:servers].include?(s)
          config_options = agent_options(s)
          if config_options.empty?
            if s == "broker"
              format = @command_serializer.format
              IO.popen("escript #{stats_script_path} #{options[:reset]} #{format.to_s} 2>&1") do |o|
                count += 1
                result = o.readline
                result.chomp!("\n")
                if result[0, 1] == "["
                  while result[-1, 1] != "]"
                    result << o.readline
                    result.chomp!("\n")
                  end
                end
                if result =~ /nodedown/ || result =~ /escript.*not found/
                  puts("No #{s} running on this machine") if options[:servers].include?(s)
                else
                  result = eval(result)
                  result = result.pack("CCC*") if format == :msgpack
                  display(s, result, options)
                end
              end
            elsif options[:servers].include?(s) && !(s =~ /_2$/)
              puts("No #{s} running on this machine")
            end
          else
            count += 1
            listen_port = config_options[:listen_port]
            fail("Could not retrieve #{s} listen port") unless listen_port
            client = CommandClient.new(listen_port, config_options[:cookie])
            command = {:name => :stats, :reset => options[:reset]}
            begin
              client.send_command(command, options[:verbose], options[:timeout]) { |r| display(s, r, options) }
            rescue Exception => e
              fail("Failed to retrieve #{s} stats: #{e}\n" + e.backtrace.join("\n"))
            end
          end
        end
      end
      puts("No servers running on this machine") if count == 0 && options[:servers].empty?
      true
    end

    # Receive and display statistics published to the "stats" exchange by RightLink agents
    #
    # === Parameters
    # options(Hash):: Configuration options
    #
    # === Return
    # true:: Always return true
    def receive_stats(options)
      require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'mapper', 'lib', 'mapper_serializer'))
      require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'db_access', 'lib', 'rnds_access'))

      mapper_options = agent_options("mapper")
      if mapper_options.empty?
        puts "No mapper configured, required for receiving stats"
      else
        EM.run do
          amqp_options = DEFAULT_AMQP_OPTIONS.dup
          mapper_options.each { |k, v| amqp_options[k] = v if DEFAULT_AMQP_OPTIONS.keys.include?(k) }
          InstanceAgentData.init(mapper_options)
          IslandData.init(mapper_options)
          amqp_options[:islands] = islands = IslandData.all
          unless islands[amqp_options[:home_island]]
            raise Exception, "Cannot find home island #{amqp_options[:home_island].inspect}"
          end
          @broker = HABrokerClient.new(Serializer.new(:secure), amqp_options)
          queue_name = AgentIdentity.new('rs', 'mapper', 654321).to_s
          queue = {:name => queue_name, :options => {:exclusive => true}}
          exchange = {:type => :topic, :name => "stats", :options => {:no_declare => true}}
          @broker.subscribe(queue, exchange, :key => options[:key], Stats => nil) do |_, r|
            if options[:json]
              puts r.data.to_json
            else
              puts "\n#{stats_str(r.data)}\n"
            end
          end

          EM.add_timer(options[:timeout]) { puts("\nReceiver timed out"); cleanup(queue_name) } if options[:timeout]
          ['INT', 'TERM'].each { |sig| old = trap(sig) { cleanup(queue_name); old.call if old.is_a?(Proc) } }

          puts "Waiting for #{options[:key]} ..." unless options[:json]
        end
      end
      true
    end

    protected

    # Path to 'stats.erl' escript
    #
    # === Return
    # path(String):: Path to script
    def stats_script_path
      return File.join(RightNetConfig[:right_net_path], 'broker', 'scripts', 'stats.erl')
    end

    # Display stats returned from server in human readable or JSON format
    #
    # === Parameters
    # server(String):: Name of server
    # result(String):: Serialized result packet containing stats or error
    # options(Hash):: Configuration options:
    #   :json(Boolean):: Whether to display in JSON format
    #
    # === Return
    # true:: Always return true
    def display(server, result, options)
      result = RightScale::OperationResult.from_results(@command_serializer.load(result))
      if options[:json]
        puts result.content.to_json
      else
        if result.respond_to?(:success?) && result.success?
          puts "\n#{stats_str(result.content)}\n"
        else
          puts "\nFailed to retrieve #{server} stats: #{result.inspect}"
        end
      end
      true
    end

    # Cleanup after using the broker
    #
    # === Parameters
    # queue_name(String):: Name of queue to clean up
    #
    # === Return
    # true:: Always return true
    def cleanup(queue_name)
      @broker.delete(queue_name, :exclusive => true)
      @broker.close { EM.stop }
      true
    end

    # Print failure message and exit abnormally
    #
    # === Parameters
    # message(String):: Failure message
    # print_usage(Boolean):: Whether to display usage information
    #
    # === Return
    # exits the program
    def fail(message, print_usage = false)
      puts "** #{message}"
      RDoc::usage_from_file(__FILE__) if print_usage
      exit(1)
    end

    # Version information
    def version
      "rstat #{VERSION.join('.')} - RightScale RightNet Statistics Manager (c) 2010 RightScale"
    end

  end
end
