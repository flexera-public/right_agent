# === Synopsis:
#   RightScale RightNet Infrastructure Agent Deployer (rad) - (c) 2009 RightScale
#
#   rad is a command line tool used to build the configuration file for a RightNet infrastructure agent or mapper
#
#   The configuration file is generated in:
#     right_net/generated/<name of agent>/config.yml
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
#   Build configuration for core agent that is sharing request queue named 'core'
#   with other core agents
#     rad core --shared-queue core
#
# === Usage:
#    rad AGENT [options]
#
#    common options:
#      --identity, -i ID        Use base id ID to build agent's identity
#      --token, -t TOKEN        Use token TOKEN to build agent's identity
#      --prefix, -r PREFIX      Prefix agent identity with PREFIX
#      --url                    Set agent AMQP connection URL (host, port, user, pass, vhost)
#      --user, -u USER          Set agent AMQP username
#      --password, -p PASS      Set agent AMQP password
#      --vhost, -v VHOST        Set agent AMQP virtual host
#      --alias ALIAS            Use alias name for identity and base config
#      --prefetch COUNT         Set maximum requests AMQP broker is to prefetch before current is ack'd
#      --pid-dir, -z DIR        Set directory containing pid file
#      --actors-dir DIR         Set directory containing actor classes
#      --monit, -w              Generate monit configuration file
#      --reconnect-interval SEC Set number of seconds between broker reconnect attempts
#      --advertise-interval SEC Set number of seconds between agent advertising its services
#      --grace-timeout SEC      Set number of seconds before graceful termination times out
#      --instance-queue-ttl     Set time-to-live in seconds for messages published to instance queues
#      --options, -o KEY=VAL    Pass-through options
#      --test                   Build test deployment using default test settings
#      --quiet, -Q              Do not produce output
#      --help                   Display help
#      --version                Display version information
#
#    agent-only options:
#      --host, -h HOST          Set AMQP server host for agent
#      --port, -P PORT          Set AMQP server port for agent
#      --shared-queue, -q QUEUE Use QUEUE as input for agent in addition to identity queue
#      --time-to-live SEC       Set maximum age in seconds before a request expires and is ignored
#      --retry-timeout SEC      Set maximum number of seconds to retry request before give up
#      --retry-interval SEC     Set number of seconds before initial request retry, increases exponentially
#      --ping-interval SEC      Set minimum number of seconds since last message receipt for the agent
#                               to ping the mapper to check connectivity, 0 means disable ping
#      --agents-dir DIR         Set directory containing agent configuration
#
#    mapper-only options:
#      --rnds-urls URLS         Set comma-separated list of URLs for accessing RightNetDataService
#      --tags-urls URLS         Set comma-separated list of URLs for accessing TagService
#      --tags-auth-token TOKEN  Set authentication token for accessing TagService
#      --max-cache-size         Set maximum number of entries in LRU cache for storing instance agents
#      --cache-reload-age       Set age in seconds of cached instance before automatically reload
#      --home-island ID         Set identifier for RightNet island in which mapper is located

require File.join(RightScale::RightNetConfig[:right_link_path], 'scripts', 'lib', 'agent_deployer')

module RightScale

  class InfrastructureAgentDeployer < AgentDeployer

    VERSION = [0, 2, 1]

    # Helper
    def self.run
      d = InfrastructureAgentDeployer.new
      options = d.parse_args
      # In development environment allow this utility to also be used for instance agents
      RightNetConfig[:right_net_path] = RightNetConfig[:right_link_path] if d.instance?(options)
      d.generate_config(options)
    end

    # Do deployment with given options
    def generate_config(options, cfg = {})
      advertise_interval = options[:advertise_interval] || 60 * 60
      instance_queue_ttl = options[:instance_queue_ttl] || 24 * 60 * 60

      if mapper?(options)
        cfg_file = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'mapper', 'config.yml'))
        fail("Missing mapper configuration file at '#{cfg_file}'") unless File.file?(cfg_file)
        cfg = symbolize(YAML.load(File.new(cfg_file))) rescue nil
        fail('Cannot read configuration for mapper') unless cfg
        if options[:test]
          cfg[:rnds_urls] = '127.0.0.1:9010'
          cfg[:tags_urls] = '127.0.0.1:9030'
          cfg[:log_to_file_only] = true
        end
        cfg.each { |k, v| options[:options][k] = options[k] || v }
        cfg[:rnds_urls] = options[:rnds_urls] if options[:rnds_urls]
        cfg[:tags_urls] = options[:tags_urls] if options[:tags_urls]
        cfg[:tags_auth_token] = options[:tags_auth_token]
        cfg[:max_cache_size] = options[:max_cache_size] || 10000
        cfg[:cache_reload_age] = options[:cache_reload_age] || 30
        cfg[:instance_queue_ttl] = instance_queue_ttl
        cfg[:home_island] = options[:home_island]
        cfg[:advertise_interval] = advertise_interval
        options[:reconnect_interval] ||= 5
        options[:grace_timeout] ||= 60
        options[:dup_check] = false
        options[:actors_dir] ||= actors_dir
        options.delete(:host)
        options.delete(:port)
        write_config(options, cfg)
      elsif !instance?(options)
        # Allow infrastructure agents to declare their own queues
        options[:options] ||= {}
        options[:options][:secure] = false
        options[:reconnect_interval] ||= 5
        options[:grace_timeout] ||= 60
        options[:dup_check] = false
        cfg[:advertise_interval] = advertise_interval
        cfg[:shared_queue] = options[:shared_queue] if options[:shared_queue]
        cfg[:instance_queue_ttl] = instance_queue_ttl
        super(options, cfg)
      end
    end

    # Parse other arguments used only by infrastructure agents
    def parse_other_args(opts, options)
      opts.on('-q', '--shared-queue QUEUE') do |q|
        options[:shared_queue] = q
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
    end

    # Create agent monit configuration file
    def setup_agent_monit(options)
      if mapper?(options) || core?(options)
        agent = options[:agent]
        identity = options[:identity]
        pid_file = PidFile.new(identity, :pid_dir => options[:pid_dir] ||
                               RightScale::RightLinkConfig[:platform].filesystem.pid_dir)
        config = <<-EOF
check process #{agent}
  with pidfile \"#{pid_file}\"
  start program \"/etc/init.d/#{agent} start\"
  stop program \"/etc/init.d/#{agent} stop\"
  mode manual
        EOF
        setup_monit(identity, config, options)
      else
        super(options)
      end
    end

    # Determine whether this is a mapper
    def mapper?(options)
      (options[:alias] || options[:agent]) == 'mapper'
    end

    # Determine whether this is a core agent
    def core?(options)
      (options[:alias] || options[:agent]) == 'core'
    end

    # Determine whether this is an instance agent
    def instance?(options)
      (options[:alias] || options[:agent]) == 'instance'
    end

  end # InfrastructureAgentDeployer

end # RightScale
