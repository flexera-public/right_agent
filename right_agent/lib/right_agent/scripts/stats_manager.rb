# === Synopsis:
#   RightAgent Statistics Manager (rstat) - (c) 2010-2011 RightScale
#
#   rstat is a command line tool for displaying operation statistics for RightAgents
#
# === Examples:
#   Retrieve statistics for all locally running agents:
#     rstat
#
#   Retrieve statistics for an agent named AGENT:
#     rstat AGENT
#
#   Retrieve statistics for an agent in JSON format:
#     rstat AGENT --json
#     rstat AGENT --j
#
# === Usage:
#    rstat [AGENT] [options]
#
#    Options:
#      --reset, -r        As part of gathering the stats from an agent also reset the stats
#      --timeout, -t SEC  Override default timeout in seconds to wait for a response from an agent
#      --json, -j         Display the stats data in JSON format
#      --cfg-dir, -c DIR  Set directory containing configuration for all agents
#      --help             Display help

require 'optparse'
require 'rdoc/ri/ri_paths' # For backwards compat with ruby 1.8.5
require 'rdoc/usage'
require File.expand_path(File.join(File.dirname(__FILE__), 'rdoc_patch'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent'))
require File.expand_path(File.join(File.dirname(__FILE__), 'common_parser'))

module RightScale

  class StatsManager

    include StatsHelper

    # Default time to wait for a response from an agent
    DEFAULT_TIMEOUT = 5

    # Create and run manager
    #
    # === Return
    # true:: Always return true
    def self.run
      m = StatsManager.new
      m.manage(m.parse_args)
    end

    # Initialize manager
    def initialize
      @command_serializer = Serializer.new
    end

    # Handle stats request
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # true:: Always return true
    def manage(options)
      init_log
      AgentConfig.cfg_dir = options[:cfg_dir]
      options[:timeout] ||= DEFAULT_TIMEOUT
      request_stats(options)
    rescue Exception => e
      fail("#{e}\n#{e.backtrace.join("\n")}") unless e.is_a?(SystemExit)
    end

    # Create options hash from command line arguments
    #
    # === Return
    # options(Hash):: Parsed options
    def parse_args
      options = {:reset => false}
      options[:agent_name] = ARGV[0] unless ARGV[0] =~ /^-/

      opts = OptionParser.new do |opts|
        parse_other_args(opts, options)

        opts.on('-r', '--reset') do
          options[:reset] = true
        end

        opts.on('-t', '--timeout SEC') do |sec|
          options[:timeout] = sec
        end

        opts.on('-j', '--json') do
          options[:json] = true
        end

        opts.on("-c", "--cfg-dir DIR") do |d|
          options[:cfg_dir] = d
        end

        opts.on_tail('--help') do
          RDoc::usage_from_file(__FILE__)
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

    # Request and display statistics for agents
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # true:: Always return true
    def request_stats(options)
      # Determine candidate agents
      agent_names = if options[:agent_name]
        [options[:agent_name]]
      else
        AgentConfig.cfg_agents
      end
      fail("No agents configured") if agent_names.empty?

      # Request stats from agents
      count = 0
      agent_names.each do |agent_name|
        begin
          count += 1 if request_agent_stats(agent_name, options)
        rescue Exception => e
          $stderr.puts "Command to #{agent_name} agent failed (#{e})" unless e.is_a?(SystemExit)
        end
      end
      $stderr.puts("No agents running") if count == 0
    end

    # Request and display statistics for agent
    #
    # === Parameters
    # agent_name(String):: Agent name
    # options(Hash):: Command line options
    #
    # === Return
    # (Boolean):: true if agent running, otherwise false
    def request_agent_stats(agent_name, options)
      res = false
      config_options = AgentConfig.agent_options(agent_name)
      unless config_options.empty? || (listen_port = config_options[:listen_port]).nil?
        client = CommandClient.new(listen_port, config_options[:cookie])
        command = {:name => :stats, :reset => options[:reset]}
        begin
          client.send_command(command, options[:verbose], options[:timeout]) { |r| display(agent_name, r, options) }
          res = true
        rescue Exception => e
          msg = "Could not retrieve #{agent_name} agent stats: #{e}"
          msg += "\n" + e.backtrace.join("\n") unless e.message =~ /Timed out/
          fail(msg)
        end
      end
      res
    end

    protected

    # Initialize logging
    #
    # === Return
    # true:: Always return true
    def init_log
      Log.program_name = "stats_manager"
      Log.log_to_file_only(true)
      Log.init("stats_manager", Platform.filesystem.temp_dir, :print => true)
      true
    end

    # Parse other arguments unique to given stats manager
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

    # Display stats returned from an agent in human readable or JSON format
    #
    # === Parameters
    # agent_name(String):: Agent name
    # result(String):: Result packet in JSON format containing stats or error
    # options(Hash):: Command line options:
    #   :json(Boolean):: Whether to display in JSON format
    #
    # === Return
    # true:: Always return true
    def display(agent_name, result, options)
      result = RightScale::OperationResult.from_results(@command_serializer.load(result))
      if options[:json]
        $stdout.puts result.content.to_json
      else
        if result.respond_to?(:success?) && result.success?
          $stdout.puts "\n#{stats_str(result.content)}\n"
        else
          $stderr.puts "\nCould not retrieve #{agent_name} agent stats: #{result.inspect}"
        end
      end
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
      $stderr.puts "** #{message}"
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
