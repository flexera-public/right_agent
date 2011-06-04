# === Synopsis:
#   RightAgent Statistics Manager (rstat) - (c) 2010-2011 RightScale
#
#   rstat is a command line tool for displaying operation statistics for a RightAgent
#
# === Examples:
#   Retrieve statistics for all agents:
#     rstat
#
#   Retrieve statistics for a specific agent:
#     rstat AGENT
#
#   Retrieve statistics for a specific agent in JSON format:
#     rstat AGENT --json
#     rstat AGENT --j
#
# === Usage:
#    rstat [AGENT] [options]
#
#    Options:
#      --reset, -r        As part of gathering the stats from a server also reset the stats
#      --timeout, -t SEC  Override default timeout in seconds to wait for a response from a server
#      --json, -j         Dump the stats data in JSON format
#      --cfg-dir, -c DIR  Set directory containing configuration for all agents
#      --version          Display version information
#      --help             Display help

require 'optparse'
require 'rdoc/ri/ri_paths' # For backwards compat with ruby 1.8.5
require 'rdoc/usage'
require 'rdoc/usage'
require File.expand_path(File.join(File.dirname(__FILE__), 'rdoc_patch'))
require File.expand_path(File.join(File.dirname(__FILE__), 'common_parser'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent'))

module RightScale

  class StatsManager

    include AgentFileHelper
    include StatsHelper

    VERSION = [0, 1, 0]

    DEFAULT_TIMEOUT = 5

    SERVERS = ["instance"]

    # Convenience wrapper for creating and running manager
    def self.run
      m = StatsManager.new
      m.manage(m.parse_args)
    end

    # Handle stats request
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # true:: Always return true
    def manage(options)
      # Initialize AgentFileHelper
      init_cfg_dir(options[:cfg_dir])

      # Determine candidate agents
      agent_names = if options[:agent_name]
        [options[:agent_name]]
      else
        configured_agents
      end
      fail("No agents configured") if agent_names.empty?

      # Request stats from agents
      count = 0
      agent_names.each do |agent_name|
        begin
          count += 1 if request_stats(agent_name, options)
        rescue Exception => e
          puts "Command to agent #{agent_name} failed (#{e})"
        end
      end
      puts("No agents running") if count == 0
      true
    end

    # Create options hash from command line arguments
    #
    # === Return
    # options(Hash):: Parsed options
    def parse_args
      options = {:reset => false, :timeout => DEFAULT_TIMEOUT}
      options[:agent_name] = ARGV[0] unless ARGV[0] =~ /^-/

      opts = OptionParser.new do |opts|

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

    # Request and display statistics from agent
    #
    # === Parameters
    # agent_name(String):: Agent name
    # options(Hash):: Configuration options
    #
    # === Return
    # (Boolean):: true if agent running, otherwise false
    def request_stats(agent_name, options)
      res = false
      config_options = agent_options(agent_name)
      unless config_options.empty?
        count += 1
        listen_port = config_options[:listen_port]
        fail("Could not retrieve #{s} listen port") unless listen_port
        client = CommandClient.new(listen_port, config_options[:cookie])
        command = {:name => :stats, :reset => options[:reset]}
        begin
          client.send_command(command, options[:verbose], options[:timeout]) { |r| display(s, r, options) }
          res = true
        rescue Exception => e
          fail("Failed to retrieve #{s} stats: #{e}\n" + e.backtrace.join("\n"))
        end
      end
      res
    end

    protected

    # Display stats returned from server in human readable or JSON format
    #
    # === Parameters
    # server(String):: Name of server
    # result(String):: Result packet in JSON format containing stats or error
    # options(Hash):: Configuration options:
    #   :json(Boolean):: Whether to display in JSON format
    #
    # === Return
    # true:: Always return true
    def display(server, result, options)
      result = RightScale::OperationResult.from_results(JSON.load(result))
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
      "rstat #{VERSION.join('.')} - RightAgent Statistics Manager (c) 2010-2011 RightScale"
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
