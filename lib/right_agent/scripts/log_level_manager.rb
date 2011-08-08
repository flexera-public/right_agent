# === Synopsis:
#   RightAgent Log Level Manager (rlog) - (c) 2009-2011 RightScale Inc
#
#   rlog is a command line tool for retrieving and setting the log level
#   for a RightAgent
#
# === Examples:
#   Retrieve log level for all configured agents:
#     rlog
#
#   Retrieve log level for a specific agent:
#     rlog AGENT
#
#   Set log level to debug for all configured agents:
#     rlog [AGENT] --log-level debug
#     rlog [AGENT] -l debug
#
#   Set log level to debug for a specific agent:
#     rlog AGENT -l debug
#
# === Usage
#    rs_set_log_level [AGENT] [--log-level, -l debug|info|warn|error|fatal]
#
#    options:
#      --log-level, -l LVL  Set log level of agent
#      --cfg-dir, -c DIR    Set directory containing configuration for all agents
#      --verbose, -v        Display debug information
#      --help:              Display help
#
#    No options prints the current agent log level
#

require 'rubygems'
require 'optparse'
require File.expand_path(File.join(File.dirname(__FILE__), 'usage'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'actors', 'agent_manager'))
require File.expand_path(File.join(File.dirname(__FILE__), 'common_parser'))

module RightScale

  class LogLevelManager

    # Convenience wrapper for creating and running log level manager
    #
    # === Return
    # true:: Always return true
    def self.run
      m = LogLevelManager.new
      m.manage(m.parse_args)
    end

    # Handle log level request
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # true:: Always return true
    def manage(options)
      # Initialize configuration directory setting
      AgentConfig.cfg_dir = options[:cfg_dir]

      # Determine command
      level = options[:level]
      command = { :name => (level ? 'set_log_level' : 'get_log_level') }
      command[:level] = level.to_sym if level

      # Determine candidate agents
      agent_names = if options[:agent_name]
        [options[:agent_name]]
      else
        AgentConfig.cfg_agents
      end
      fail("No agents configured") if agent_names.empty?

      # Perform command for each agent
      count = 0
      agent_names.each do |agent_name|
        count += 1 if request_log_level(agent_name, command, options)
      end
      puts("No agents running") if count == 0
      true
    end

    # Create options hash from command line arguments
    #
    # === Return
    # options(Hash):: Hash of options as defined by the command line
    def parse_args
      options = { :verbose => false }
      options[:agent_name] = ARGV[0] unless ARGV[0] =~ /^-/

      opts = OptionParser.new do |opts|

        opts.on('-l', '--log-level LEVEL') do |l|
          fail("Invalid log level '#{l}'") unless AgentManager::LEVELS.include?(l.to_sym)
          options[:level] = l
        end

        opts.on("-c", "--cfg-dir DIR") do |d|
          options[:cfg_dir] = d
        end

        opts.on('-v', '--verbose') do
          options[:verbose] = true
        end

      end

      opts.on_tail('--help') do
         puts Usage.scan(__FILE__)
         exit
      end

      begin
        opts.parse!(ARGV)
      rescue Exception => e
        exit 0 if e.is_a?(SystemExit)
        fail(e.message + "\nUse 'rlog --help' for additional information")
      end
      options
    end

    protected

    # Send log level request to agent
    #
    # === Parameters
    # agent_name(String):: Agent name
    # command(String):: Command request
    # options(Hash):: Command line options
    #
    # === Return
    # (Boolean):: true if agent running, otherwise false
    def request_log_level(agent_name, command, options)
      res = false
      config_options = AgentConfig.agent_options(agent_name)
      unless config_options.empty?
        listen_port = config_options[:listen_port]
        fail("Could not retrieve #{agent_name} agent listen port") unless listen_port
        client = CommandClient.new(listen_port, config_options[:cookie])
        begin
          client.send_command(command, options[:verbose]) do |level|
            puts "Agent #{agent_name} log level: #{level.to_s.upcase}"
          end
          res = true
        rescue Exception => e
          puts "Command #{command.inspect} to #{agent_name} agent failed (#{e})"
        end
      end
      res
    end

    # Print error on console and exit abnormally
    #
    # === Parameter
    # message(String):: Error message, default to nil (no message printed)
    # print_usage(Boolean):: Whether script usage should be printed, default to false
    #
    # === Return
    # R.I.P. does not return
    def fail(message = nil, print_usage = false)
      puts "** #{message}" if message
      puts Usage.scan(__FILE__) if print_usage
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
