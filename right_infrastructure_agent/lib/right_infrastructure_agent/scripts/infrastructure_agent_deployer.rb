# === Synopsis:
#   RightInfrastructureAgent Deployer (rad) - (c) 2009-2011 RightScale
#
#   rad is a command line tool for building the configuration file for a RightInfrastructureAgent
#
#   The configuration file is generated in:
#     <agent name>/config.yml
#   in platform-specific RightAgent configuration directory
#
#   Note that a mapper is also a RightInfrastructureAgent but its configuration options are
#   slightly different, .e.g., broker configuration is governed by home-island option instead
#   of host and port
#
# === Examples:
#   Build configuration for agent named AGENT with default options:
#     rad AGENT
#
#   Build configuration for agent named AGENT so it uses given AMQP settings:
#     rad AGENT --user USER --pass PASSWORD --vhost VHOST --port PORT --host HOST
#     rad AGENT -u USER -p PASSWORD -v VHOST -P PORT -h HOST
#
#   Build configuration for mapper named MAPPER:
#     rad MAPPER --user USER --pass PASSWORD --vhost VHOST --home-island 1 --rnds-urls URL1,URL2
#                --tags-urls URL1,URL2 --tags-auth-key KEY
#
#   Build configuration for two core agents that are sharing a request queue named 'core'
#     rad core --shared-queue core
#     rad core_2 --shared-queue core
#
# === Usage:
#    rad AGENT [options]
#
#    common options:
#      --root-dir, -r DIR       Set agent root directory (containing init, actors, and certs subdirectories)
#      --cfg-dir, -c DIR        Set directory where generated configuration files for all agents are stored
#      --pid-dir, -z DIR        Set directory containing process id file
#      --identity, -i ID        Use base id ID to build agent's identity
#      --token, -t TOKEN        Use token TOKEN to build agent's identity
#      --prefix, -x PREFIX      Use prefix PREFIX to build agent's identity
#      --type TYPE              Use agent type TYPE to build agent's' identity,
#                               defaults to AGENT with any trailing '_[0-9]+' removed
#      --url                    Set agent AMQP connection URL (host, port, user, pass, vhost)
#      --user, -u USER          Set agent AMQP username
#      --password, -p PASS      Set agent AMQP password
#      --vhost, -v VHOST        Set agent AMQP virtual host
#      --prefetch COUNT         Set maximum requests AMQP broker is to prefetch before current is ack'd
#      --notify, -n EMAIL       Set email address EMAIL for exception notifications
#      --check-interval SEC     Set number of seconds between failed connection checks, increases exponentially
#      --reconnect-interval SEC Set number of seconds between broker reconnect attempts
#      --advertise-interval SEC Set number of seconds between agent advertising its services
#      --grace-timeout SEC      Set number of seconds before graceful termination times out
#      --instance-queue-ttl     Set time-to-live in seconds for messages published to instance queues
#      --options, -o KEY=VAL    Pass-through options
#      --monit, -m              Generate monit configuration file
#      --test                   Build test deployment using default test settings
#      --quiet, -Q              Do not produce output
#      --help                   Display help
#
#    agent-only options:
#      --host, -h HOST          Set AMQP server host for agent
#      --port, -P PORT          Set AMQP server port for agent
#      --shared-queue, -q QUEUE Use QUEUE as input for agent in addition to identity queue
#      --shard, -s ID           Set identifier for shard that agent is servicing
#      --time-to-live SEC       Set maximum age in seconds before a request expires and is ignored
#      --retry-timeout SEC      Set maximum number of seconds to retry request before give up
#      --retry-interval SEC     Set number of seconds before initial request retry, increases exponentially
#      --ping-interval SEC      Set minimum number of seconds since last message receipt for the agent
#                               to ping the mapper to check connectivity, 0 means disable ping
#
#    mapper-only options:
#      --rnds-urls URLS         Set comma-separated list of URLs for accessing RightNetDataService
#      --tags-urls URLS         Set comma-separated list of URLs for accessing TagService
#      --tags-auth-token TOKEN  Set authentication token for accessing TagService
#      --max-cache-size         Set maximum number of entries in LRU cache for storing instance agents
#      --cache-reload-age       Set age in seconds of cached instance before automatically reload
#      --home-island ID         Set identifier for RightNet island in which mapper is located

require 'right_agent/scripts/agent_deployer'
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_infrastructure_agent'))

module RightScale

  class InfrastructureAgentDeployer < AgentDeployer

    # Create and run deployer
    #
    # === Return
    # true:: Always return true
    def self.run
      d = InfrastructureAgentDeployer.new
      d.deploy(d.parse_args)
    end

    protected

    # Parse other arguments used only by infrastructure agents
    #
    # === Parameters
    # opts(OptionParser):: Options parser with options to be parsed
    # options(Hash):: Storage for options that are parsed
    #
    # === Return
    # true:: Always return true
    def parse_other_args(opts, options)
      opts.on('-q', '--shared-queue QUEUE') do |q|
        options[:shared_queue] = q
      end

      opts.on('-s', '--shard ID') do |id|
        options[:shard_id] = id.to_i
      end

      opts.on('-n', '--notify EMAIL') do |email|
        options[:notify] = email
      end

      opts.on('--rnds-urls URLS') do |urls|
        options[:rnds_urls] = urls
      end

      opts.on('--tags-urls URLS') do |urls|
        options[:tags_urls] = urls
      end

      opts.on('--tags-auth-token TOKEN') do |token|
        options[:tags_auth_token] = token
      end

      opts.on('--max-cache-size SIZE') do |size|
        options[:max_cache_size] = size.to_i
      end

      opts.on('--cache-reload-age SEC') do |sec|
        options[:cache_reload_age] = sec.to_i
      end

      opts.on('--home-island ID') do |id|
        options[:home_island] = id.to_i
      end

      opts.on('--instance-queue-ttl SEC') do |sec|
        options[:instance_queue_ttl] = sec.to_i
      end

      opts.on('--advertise-interval SEC') do |sec|
        options[:advertise_interval] = sec.to_i
      end

      opts.on('--help') do
        RDoc::usage_from_file(__FILE__)
        exit
      end
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
      cfg = super(options, cfg)
      if options[:agent_type] != 'instance'
        cfg[:reconnect_interval] ||= 5
        cfg[:grace_timeout] ||= 60
        cfg[:dup_check] = false
        cfg[:advertise_interval] = options[:advertise_interval] || 60 * 60
        cfg[:instance_queue_ttl] = options[:instance_queue_ttl] || 24 * 60 * 60
        cfg[:secure] = options[:options][:secure] = false
        cfg[:shard_id] = options[:shard_id] if options[:shard_id]
        cfg[:notify] = options[:notify] if options[:notify]
      end
      if options[:agent_type] == 'mapper'
        if options[:test]
          cfg[:rnds_urls] = '127.0.0.1:9010'
          cfg[:tags_urls] = '127.0.0.1:9030'
          cfg[:log_to_file_only] = true
        end
        cfg[:rnds_urls] = options[:rnds_urls] if options[:rnds_urls]
        cfg[:tags_urls] = options[:tags_urls] if options[:tags_urls]
        cfg[:tags_auth_token] = options[:tags_auth_token]
        cfg[:max_cache_size] = options[:max_cache_size] || 10000
        cfg[:cache_reload_age] = options[:cache_reload_age] || 30
        cfg[:home_island] = options[:home_island]
      elsif options[:agent_type] != 'instance'
        cfg[:shared_queue] = options[:shared_queue] if options[:shared_queue]
      end
      cfg
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
  start program \"/etc/init.d/#{agent_name} start\"
  stop program \"/etc/init.d/#{agent_name} stop\"
  mode manual
      EOF
      cfg_file = File.join(AgentConfig.cfg_dir, agent_name, "#{identity}.conf")
      File.open(cfg_file, 'w') { |f| f.puts(cfg) }
      File.chmod(0600, cfg_file) # monit requires strict perms on this file
      puts "  - agent monit config: #{cfg_file}" unless options[:quiet]
      true
    end

  end # InfrastructureAgentDeployer

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
