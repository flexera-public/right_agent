# === Synopsis:
#   RightAgent Deployer (rad) - (c) 2009-2011 RightScale
#
#   rad is a command line tool for building the configuration file for a RightAgent
#
#   The configuration file is generated in:
#     <agent name>/config.yml
#   in platform-specific RightAgent configuration directory
#
# === Examples:
#   Build configuration for agent named AGENT with default options:
#     rad AGENT
#
#   Build configuration for agent named AGENT so it uses given AMQP settings:
#     rad AGENT --user USER --pass PASSWORD --vhost VHOST --port PORT --host HOST
#     rad AGENT -u USER -p PASSWORD -v VHOST -P PORT -h HOST
#
# === Usage:
#    rad AGENT [options]
#
#    options:
#      --root-dir, -r DIR       Set agent root directory (containing init, actors, and certs subdirectories)
#      --cfg-dir, -c DIR        Set directory where generated configuration files for all agents are stored
#      --pid-dir, -z DIR        Set directory containing process id file
#      --identity, -i ID        Use base id ID to build agent's identity
#      --token, -t TOKEN        Use token TOKEN to build agent's identity
#      --prefix, -x PREFIX      Use prefix PREFIX to build agent's identity
#      --type TYPE              Use agent type TYPE to build agent's' identity,
#                               defaults to AGENT with any trailing '_[0-9]+' removed
#      --secure-identity, -S    Derive actual token from given TOKEN and ID
#      --url                    Set agent AMQP connection URL (host, port, user, pass, vhost)
#      --user, -u USER          Set agent AMQP username
#      --password, -p PASS      Set agent AMQP password
#      --vhost, -v VHOST        Set agent AMQP virtual host
#      --host, -h HOST          Set AMQP broker host
#      --port, -P PORT          Set AMQP broker port
#      --prefetch COUNT         Set maximum requests AMQP broker is to prefetch before current is ack'd
#      --http-proxy PROXY       Use a proxy for all agent-originated HTTP traffic
#      --http-no-proxy NOPROXY  Comma-separated list of proxy exceptions (e.g. metadata server)
#      --time-to-live SEC       Set maximum age in seconds before a request times out and is rejected
#      --retry-timeout SEC      Set maximum number of seconds to retry request before give up
#      --retry-interval SEC     Set number of seconds before initial request retry, increases exponentially
#      --check-interval SEC     Set number of seconds between failed connection checks, increases exponentially
#      --ping-interval SEC      Set minimum number of seconds since last message receipt for the agent
#                               to ping the mapper to check connectivity, 0 means disable ping
#      --reconnect-interval SEC Set number of seconds between broker reconnect attempts
#      --grace-timeout SEC      Set number of seconds before graceful termination times out
#      --[no-]dup-check         Set whether to check for and reject duplicate requests, .e.g., due to retries
#      --options, -o KEY=VAL    Set options that act as final override for any persisted configuration settings
#      --monit, -m              Generate monit configuration file
#      --test                   Build test deployment using default test settings
#      --quiet, -Q              Do not produce output
#      --help                   Display help

require 'optparse'
require 'yaml'
require 'fileutils'
require 'rdoc/ri/ri_paths' # For backwards compat with ruby 1.8.5
require 'rdoc/usage'
require File.expand_path(File.join(File.dirname(__FILE__), 'rdoc_patch'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent'))
require File.expand_path(File.join(File.dirname(__FILE__), 'common_parser'))

module RightScale

  class AgentDeployer

    include CommonParser

    # Create and run deployer
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
    #
    # === Return
    # true:: Always return true
    def deploy(options)
      # Initialize directory settings
      AgentConfig.root_dir = options[:root_dir]
      AgentConfig.cfg_dir = options[:cfg_dir]
      AgentConfig.pid_dir = options[:pid_dir]

      # Configure agent
      cfg = load_init_cfg
      check_agent(options, cfg)
      cfg = configure(options, cfg)

      # Persist configuration
      persist(options, cfg)

      # Setup agent monitoring
      monitor(options) if options[:monit]
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
          # Allow for more than one
          if options[:root_dir]
            options[:root_dir] = [options[:root_dir]] unless options[:root_dir].is_a?(Array)
            options[:root_dir] << d
          else
            options[:root_dir] = d
          end
        end

        opts.on('-c', '--cfg-dir DIR') do |d|
          options[:cfg_dir] = d
        end

        opts.on('-z', '--pid-dir DIR') do |d|
          options[:pid_dir] = d
        end

        opts.on('-w', '--monit') do
          options[:monit] = true
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

    # Load initial configuration for agent, if any
    #
    # === Return
    # cfg(Hash):: Initial agent configuration options
    def load_init_cfg
      cfg = {}
      if (cfg_file = AgentConfig.init_cfg_file) && (cfg_data = YAML.load(IO.read(cfg_file)))
        cfg = SerializationHelper.symbolize_keys(cfg_data) rescue nil
        fail("Cannot read configuration for agent #{cfg_file.inspect}") unless cfg
      end
      cfg
    end

    # Check agent type consistency and existence of initialization file and actors directory
    #
    # === Parameters
    # options(Hash):: Command line options
    # cfg(Hash):: Initial configuration settings
    #
    # === Return
    # true:: Always return true
    def check_agent(options, cfg)
      identity = options[:identity]
      agent_type = options[:agent_type]
      type = AgentIdentity.parse(identity).agent_type if identity
      fail("Agent type #{agent_type.inspect} and identity #{identity.inspect} are inconsistent") if agent_type != type
      fail("Cannot find agent init.rb file in init directory of #{AgentConfig.root_dir.inspect}") unless AgentConfig.init_file

      actors = cfg[:actors]
      fail('Agent configuration is missing actors') unless actors && actors.respond_to?(:each)
      actors_dirs = AgentConfig.actors_dirs
      actors.each do |a|
        found = false
        actors_dirs.each { |d| break if found = File.exist?(File.normalize_path(File.join(d, "#{a}.rb"))) }
        fail("Cannot find source for actor #{a.inspect} in #{actors_dirs.inspect}") unless found
      end
      true
    end

    # Determine configuration settings to be persisted
    #
    # === Parameters
    # options(Hash):: Command line options
    # cfg(Hash):: Initial configuration settings
    #
    # === Return
    # cfg(Hash):: Configuration settings
    def configure(options, cfg)
      cfg[:root_dir]           = AgentConfig.root_dir
      cfg[:pid_dir]            = AgentConfig.pid_dir
      cfg[:identity]           = options[:identity] if options[:identity]
      cfg[:user]               = options[:user] if options[:user]
      cfg[:pass]               = options[:pass] if options[:pass]
      cfg[:vhost]              = options[:vhost] if options[:vhost]
      cfg[:port]               = options[:port] if options[:port]
      cfg[:host]               = options[:host] if options[:host]
      cfg[:prefetch]           = options[:prefetch] || 1
      cfg[:time_to_live]       = options[:time_to_live] || 60
      cfg[:retry_timeout]      = options[:retry_timeout] || 2 * 60
      cfg[:retry_interval]     = options[:retry_interval] || 15
      cfg[:ping_interval]      = options[:ping_interval] ||= 4 * 60 * 60
      cfg[:check_interval]     = options[:check_interval] if options[:check_interval]
      cfg[:reconnect_interval] = options[:reconnect_interval] if options[:reconnect_interval]
      cfg[:grace_timeout]      = options[:grace_timeout] if options[:grace_timeout]
      cfg[:dup_check]          = options[:dup_check].nil? ? true : options[:dup_check]
      cfg[:http_proxy]         = options[:http_proxy] if options[:http_proxy]
      cfg[:http_no_proxy]      = options[:http_no_proxy] if options[:http_no_proxy]
      cfg
    end

    # Write configuration options to file after applying any overrides
    #
    # === Parameters
    # options(Hash):: Command line options
    # cfg(Hash):: Configurations options with which specified options are to be merged
    #
    # === Return
    # true:: Always return true
    def persist(options, cfg)
      overrides = options[:options]
      overrides.each { |k, v| cfg[k] = v } if overrides
      cfg_file = AgentConfig.store_cfg(options[:agent_name], cfg)
      unless options[:quiet]
        puts "Generated configuration file for #{options[:agent_name]} agent: #{cfg_file}" unless options[:quiet]
      end
      true
    end

    # Setup agent monitoring
    #
    # === Parameters
    # options(Hash):: Command line options
    #
    # === Return
    # true:: Always return true
    def monitor(options)
      agent_name = options[:agent_name]
      identity = options[:identity]
      pid_file = PidFile.new(identity)
      cfg = <<-EOF
check process #{agent_name}
  with pidfile \"#{pid_file}\"
  start program \"/opt/rightscale/bin/rnac --start #{agent_name}\"
  stop program \"/opt/rightscale/bin/rnac --stop #{agent_name}\"
  mode manual
      EOF
      cfg_file = File.join(AgentConfig.cfg_dir, agent_name, "#{identity}.conf")
      File.open(cfg_file, 'w') { |f| f.puts(cfg) }
      File.chmod(0600, cfg_file) # monit requires strict perms on this file
      puts "  - agent monit config: #{cfg_file}" unless options[:quiet]
      true
    end

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
