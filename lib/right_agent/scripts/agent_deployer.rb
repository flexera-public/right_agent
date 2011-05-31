# === Synopsis:
#   RightAgent Deployer (rad) - (c) 2009-2011 RightScale
#
#   rad is a command line tool for building the configuration file for a RightAgent
#
#   The configuration file is generated in:
#     <name of agent>/config.yml
#   in platform-specific RightAgent directory
#
# === Examples:
#   Build configuration for AGENT with default options:
#     rad AGENT
#
#   Build configuration for AGENT so it uses given AMQP settings:
#     rad AGENT --user USER --pass PASSWORD --vhost VHOST --port PORT --host HOST
#     rad AGENT -u USER -p PASSWORD -v VHOST -P PORT -h HOST
#
# === Usage:
#    rad AGENT [options]
#
#    Options:
#      --root-dir, -r DIR       Set agent root directory (containing actors, certs, and init subdirectories)
#      --cfg-dir, -c DIR        Set directory where generated configuration files for all agents are stored
#      --pid-dir, -z DIR        Set directory containing process id file
#      --identity, -i ID        Use base id ID to build agent's identity
#      --token, -t TOKEN        Use token TOKEN to build agent's identity
#      --prefix PREFIX          Prefix agent's identity with PREFIX
#      --secure-identity, -S    Derive actual token from given TOKEN and ID
#      --url                    Set agent AMQP connection URL (host, port, user, pass, vhost)
#      --user, -u USER          Set agent AMQP username
#      --password, -p PASS      Set agent AMQP password
#      --vhost, -v VHOST        Set agent AMQP virtual host
#      --port, -P PORT          Set AMQP broker port
#      --host, -h HOST          Set AMQP broker host
#      --type TYPE              Set agent type in agent identity and agent initialization file names,
#                               defaults to AGENT with any trailing '_[0-9]+' removed
#      --options, -o KEY=VAL    Pass-through options
#      --http-proxy PROXY       Use a proxy for all agent-originated HTTP traffic
#      --http-no-proxy          Comma-separated list of proxy exceptions (e.g. metadata server)
#      --time-to-live SEC       Set maximum age in seconds before a request times out and is rejected
#      --retry-timeout SEC      Set maximum number of seconds to retry request before give up
#      --retry-interval SEC     Set number of seconds before initial request retry, increases exponentially
#      --check-interval SEC     Set number of seconds between failed connection checks, increases exponentially
#      --ping-interval SEC      Set minimum number of seconds since last message receipt for the agent
#                               to ping the mapper to check connectivity, 0 means disable ping
#      --reconnect-interval SEC Set number of seconds between broker reconnect attempts
#      --grace-timeout SEC      Set number of seconds before graceful termination times out
#      --[no-]dup-check         Set whether to check for and reject duplicate requests, .e.g., due to retries
#      --prefetch COUNT         Set maximum requests AMQP broker is to prefetch before current is ack'd
#      --test                   Build test deployment using default test settings
#      --quiet, -Q              Do not produce output
#      --help                   Display help
#      --version                Display version information

require 'optparse'
require 'rdoc/ri/ri_paths' # For backwards compat with ruby 1.8.5
require 'rdoc/usage'
require 'yaml'
require 'ftools'
require 'fileutils'
require File.join(File.dirname(__FILE__), 'rdoc_patch')
require File.join(File.dirname(__FILE__), 'common_parser')
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent'))

module RightScale

  class AgentDeployer

    include CommonParser
    include AgentFileHelper

    VERSION = [0, 2]

    # Convenience wrapper for creating and running deployer
    #
    # === Return
    # true:: Always return true
    def self.run
      d = AgentDeployer.new
      d.deploy(d.parse_args)
    end

    # Generate configuration from specified options and the agent's base options
    # and write them to a file
    #
    # === Parameters
    # options(Hash):: Command line options
    # cfg(Hash):: Configurations options with which specified options are to be merged
    #
    # === Return
    # true:: Always return true
    def deploy(options, cfg = {})
      # Initialize AgentFileHelper
      root_dir = options[:root_dir]
      cfg_dir = options[:cfg_dir]
      pid_dir = options[:pid_dir]

      agent_type = agent_type(options[:agent_type], options[:agent_name])
      cfg.merge!(load_base_config(agent_type))
      options[:actors] = check_agent(agent_type, options[:identity], cfg.delete(:actors))
      options[:ping_interval] ||= 4 * 60 * 60
      write_config(options, cfg)
      true
    end

    # Write configuration options to file
    #
    # === Parameters
    # options(Hash):: Command line options
    # cfg(Hash):: Configurations options with which specified options are to be merged
    #
    # === Return
    # true:: Always return true
    def write_config(options, cfg = {})
      cfg[:root_dir]           = root_dir
      cfg[:pid_dir]            = pid_dir
      cfg[:identity]           = options[:identity] if options[:identity]
      cfg[:user]               = options[:user] if options[:user]
      cfg[:pass]               = options[:pass] if options[:pass]
      cfg[:vhost]              = options[:vhost] if options[:vhost]
      cfg[:port]               = options[:port] if options[:port]
      cfg[:host]               = options[:host] if options[:host]
      cfg[:actors]             = options[:actors] if options[:actors]
      cfg[:prefetch]           = options[:prefetch] || 1
      cfg[:time_to_live]       = options[:time_to_live] || 60
      cfg[:retry_timeout]      = options[:retry_timeout] || 2 * 60
      cfg[:retry_interval]     = options[:retry_interval] || 15
      cfg[:ping_interval]      = options[:ping_interval] if options[:ping_interval]
      cfg[:check_interval]     = options[:check_interval] if options[:check_interval]
      cfg[:reconnect_interval] = options[:reconnect_interval] if options[:reconnect_interval]
      cfg[:grace_timeout]      = options[:grace_timeout] if options[:grace_timeout]
      cfg[:dup_check]          = options[:dup_check].nil? ? true : options[:dup_check]
      cfg[:http_proxy]         = options[:http_proxy] if options[:http_proxy]
      cfg[:http_no_proxy]      = options[:http_no_proxy] if options[:http_no_proxy]
      options[:options].each { |k, v| cfg[k] = v } if options[:options]

      cfg_file = cfg_file(options[:agent_name])
      FileUtils.mkdir_p(Dir(cfg_file))
      File.delete(cfg_file) if File.exists?(cfg_file)
      File.open(cfg_file, 'w') { |fd| fd.puts "# Created at #{Time.now}" }
      File.open(cfg_file, 'a') { |fd| fd.write(YAML.dump(cfg)) }
      unless options[:quiet]
        puts "Generated configuration file for agent #{options[:agent_name]}:"
        puts "  - config: #{cfg_file}"
      end
      true
    end

    # Create options hash from command line arguments
    #
    # === Return
    # options(Hash):: Parsed options
    def parse_args
      options = {}
      options[:agent_name] = ARGV[0]
      options[:options] = { :secure => true }
      options[:quiet] = false
      fail('No agent specified on the command line.', print_usage = true) if options[:agent_name].nil?

      opts = OptionParser.new do |opts|
        parse_common(opts, options)
        parse_other_args(opts, options)

        opts.on('-r', '--root-dir DIR') do |d|
          options[:root_dir] = d
        end

        opts.on('-c', '--cfg-dir DIR') do |d|
          options[:cfg_dir] = d
        end

        opts.on('-z', '--pid-dir DIR') do |d|
          options[:pid_dir] = d
        end

        opts.on('-S', '--secure-identity') do
          options[:secure_identity] = true
        end

        opts.on('--http-proxy PROXY') do |proxy|
          options[:http_proxy] = proxy
        end

        opts.on('--http-no-proxy NOPROXY') do |no_proxy|
          options[:http_no_proxy] = no_proxy
        end

        opts.on('--time-to-live SEC') do |sec|
          options[:time_to_live] = sec.to_i
        end

        opts.on('--retry-timeout SEC') do |sec|
          options[:retry_timeout] = sec.to_i
        end

        opts.on('--retry-interval SEC') do |sec|
          options[:retry_interval] = sec.to_i
        end

        opts.on('--check-interval SEC') do |sec|
          options[:check_interval] = sec.to_i
        end

        opts.on('--ping-interval SEC') do |sec|
          options[:ping_interval] = sec.to_i
        end

        opts.on('--reconnect-interval SEC') do |sec|
          options[:reconnect_interval] = sec.to_i
        end

        opts.on('--grace-timeout SEC') do |sec|
          options[:grace_timeout] = sec.to_i
        end

        opts.on('--[no-]dup-check') do |b|
          options[:dup_check] = b
        end

        opts.on('--prefetch COUNT') do |count|
          options[:prefetch] = count.to_i
        end

        opts.on('-o', '--options OPT') do |e|
          fail("Invalid option definition #{e}' (use '=' to separate name and value)") unless e.include?('=')
          key, val = e.split(/=/)
          options[:options][key.gsub('-', '_').to_sym] = val
        end

        opts.on('-Q', '--quiet') do
          options[:quiet] = true
        end

        opts.on_tail('--help') do
          RDoc::usage_from_file(__FILE__)
          exit
        end
      end
      begin
        opts.parse!(ARGV)
      rescue Exception => e
        fail(e.message, print_usage = true)
      end
      resolve_identity(options)
      options
    end

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

  protected

    # Print error on console and exit abnormally
    #
    # === Parameters
    # message(String):: Error message to be displayed
    # print_usage(Boolean):: Whether to display usage information
    #
    # === Return
    # never return
    def fail(message = nil, print_usage = false)
      puts "** #{message}" if message
      RDoc::usage_from_file(__FILE__) if print_usage
      exit(1)
    end

    # Load base configuration for agent
    #
    # === Parameters
    # agent_type(String):: Type of agent
    #
    # === Return
    # cfg(Hash):: Agent configuration options
    def load_base_config(agent_type)
      cfg_file = File.normalize_path(File.join(init_dir, "#{agent_type}.yml"))
      cfg = if File.exists?(cfg_file)
        symbolize(YAML.load(IO.read(cfg_file)))
      end
      fail("Cannot read configuration for agent #{agent_type}") unless cfg
      cfg
    end

    # Check agent type consistency and existence of initialization and actors files
    #
    # === Parameters
    # agent_type(String):: Type of agent
    # identity(String):: Unique identity for agent
    # actors(Array):: Name of actors configured for this agent
    #
    # === Return
    # actors(Array):: Name of configured actors that have associated code in agent
    def check_agent(agent_type, identity, actors)
      type = AgentIdentity.parse(identity).agent_type if identity
      fail("Agent type #{agent_type.inspect} and identity #{options[:identity].inspect} are inconsistent") if agent_type != type
      init_file = File.normalize_path(File.join(init_dir, "#{agent_type}.rb"))
      fail("Cannot find agent initialization file '#{init_file}'") unless File.exists?(init_file)
      fail('Agent configuration does not define actors') unless actors && actors.respond_to?(:each)
      actors.each do |actor|
        actor_file = File.normalize_path(File.join(actors_dir, "#{actor}.rb"))
        fail("Cannot find actor file '#{actor_file}'") unless File.exists?(actor_file)
      end
      actors
    end

    # Determine agent type
    #
    # === Parameters
    # type(String):: Agent type
    # name(String):: Agent name
    #
    # === Return
    # (String):: Agent type
    def agent_type(type, name)
      unless type
        if name =~ /^(.*)_[0-9]+$/
          type = Regexp.last_match(1)
        else
          type = name || "instance"
        end
      end
      type
    end

    # Version information
    def version
      "rad #{VERSION.join('.')} - RightAgent Deployer (c) 2009-2011 RightScale"
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
