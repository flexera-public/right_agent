# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and the licensee.

module RightScale

  # Controller for running an agent in a Rainbows Rails environment
  # Dependent upon existing base configuration file for agents of the given type
  module RainbowsAgentController

    class NoConfigurationData < Exception; end

    FORCED_OPTIONS = {
      :format          => :secure,
      :threadpool_size => 1,
      :single_threaded => true,
      :daemonize       => false
    }

    # Start agent
    # Choose agent type from candidate types based on contents of configuration directory
    # Assign agent name by using worker index to suffix agent type
    #
    # === Parameters
    # agent_types(Array):: Type name for candidate agents
    # worker_index(Integer):: Rainbows worker index starting at 0
    # logger(Object):: Logger to use
    # options(Hash):: Configuration options for agent and following specifically for use here
    #   :cfg_dir(String):: Directory containing configuration for all agents
    #   :prefix(String):: Prefix to build agent identity
    #   :base_id(String|Integer):: Base id to build agent identity, defaults to worker_index
    #
    # === Return
    # true:: Always return true
    def self.start(agent_types, worker_index, logger, options = {})
      Log.force_logger(logger) if logger

      EM.next_tick do
        begin
          AgentConfig.cfg_dir = options[:cfg_dir]
          if agent_type = pick_agent_type(agent_types)
            agent_name = form_agent_name(agent_type, worker_index)
            cfg = configure_agent(agent_type, agent_name, worker_index, options)
            cfg.merge!(options.merge(FORCED_OPTIONS))
            cfg[:agent_name] = agent_name
            ExceptionMailer.configure_exception_callback(cfg)
            Log.info("Starting #{agent_name} agent with the following options:\n" +
                     "  #{cfg.map { |k, v| "#{k}: #{v.inspect}" }.sort.join("\n  ")}")
            @@agent = InfrastructureAgent.start(cfg)
          else
            Log.info("Deployment is missing configuration file for any agents of type " +
                     "#{agent_types.inspect} in #{AgentConfig.cfg_dir}, need to run rad!")
            EM.stop
          end
        rescue PidFile::AlreadyRunning
          Log.error("#{agent_name} already running")
          EM.stop
        rescue NoConfigurationData => e
          Log.error(e.message)
          EM.stop
        rescue Exception => e
          Log.error("Failed to start #{agent_name} agent", e, :trace)
          EM.stop
        end
      end
      true
    end

    # Stop agent if it was started
    #
    # === Return
    # true:: Always return true
    def self.stop
      @@agent.terminate if @@agent
      true
    end

    # Submit packet to agent
    #
    # === Parameters
    # packet(Packet):: Packet to be processed
    #
    # === Return
    # true:: Always return true
    def self.receive(packet)
      @@agent.receive(packet) if @@agent
      true
    end

    protected

    # Pick agent type from first in list that has a configuration file
    #
    # === Parameters
    # agent_types(Array):: Type name for candidate agents
    #
    # === Return
    # type(String|nil):: Agent type, or nil if none configured
    def self.pick_agent_type(types)
      (types & AgentConfig.cfg_agents).first
    end

    # Form agent name form type and index
    #
    # === Parameters
    # type(String):: Agent type
    # index(Integer):: Worker index
    #
    # === Return
    # (String):: Agent name
    def self.form_agent_name(type, index)
      "#{type}_#{index + 1}"
    end

    # Determine configuration settings for this agent and persist them
    # Reuse existing agent identities when possible
    #
    # === Parameters
    # agent_type(String):: Agent type
    # agent_name(String):: Agent name
    # worker_index(Integer):: Rainbows worker index starting at 0
    # options(Hash):: Configuration options
    #   :prefix(String):: Prefix to build agent identity
    #   :base_id(String|Integer):: Base id to build agent identity, defaults to worker_index
    #
    # === Return
    # cfg(Hash):: Persisted configuration options
    #
    # === Raise
    # NoConfigurationData:: If no configuration data found for the agent
    def self.configure_agent(agent_type, agent_name, worker_index, options)
      cfg = AgentConfig.agent_options(agent_type)
      raise NoConfigurationData.new("No configuration data found for agents of type #{agent_type} " +
                                    "in #{AgentConfig.cfg_file(agent_type)}") if cfg.empty?
      base_id = options[:base_id].to_i
      unless (identity = AgentConfig.agent_options(agent_name)[:identity]) &&
             AgentIdentity.parse(identity).base_id == base_id
        identity = AgentIdentity.new(options[:prefix] || 'rs', agent_type, base_id).to_s
      end
      cfg.merge!(:identity => identity)
      cfg_file = AgentConfig.store_cfg(agent_name, cfg)
      Log.info("Generated configuration file for #{agent_name} agent: #{cfg_file}")
      cfg
    end

  end # RainbowsAgentController

end # RightScale
