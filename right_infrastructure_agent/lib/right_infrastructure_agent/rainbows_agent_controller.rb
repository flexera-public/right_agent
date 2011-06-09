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

    FORCED_OPTIONS = {
      :format          => :secure,
      :threadpool_size => 1,
      :single_threaded => true,
      :daemonize       => false
    }

    class << self
      include RightScale::AgentConfig
    end

    # Start agent
    # Choose agent type from candidate types based on contents of configuration directory
    #
    # === Parameters
    # agent_types(Array):: Type name for candidate agents
    # worker_index(Integer):: Rainbows worker index starting at 0
    # logger(Object):: Logger to use
    # options(Hash):: Configuration options
    #   :cfg_dir(String):: Directory containing configuration for all agents
    #   :prefix(String):: Prefix to build agent identity
    #   :base_id(String):: Base id to build agent identity, defaults to worker_index
    #
    # === Return
    # true:: Always return true
    def self.start(agent_types, worker_index, logger, options = {})
      RightScale::Log.force_logger(logger) if logger

      EM.next_tick do
        begin
          init_cfg_dir(options[:cfg_dir])
          if agent_type = pick_agent_type(agent_types)
            agent_name = form_agent_name(agent_type, worker_index)
            cfg = configure(agent_type, agent_name, worker_index, options)
            Log.info("Starting #{agent_name} agent with the following options:\n" +
                     "  #{cfg.map { |k, v| "#{k}: #{v.inspect}" }.sort.join("\n  ")}")
            @@agent = RightScale::InfrastructureAgent.start(cfg)
          else
            Log.info("Deployment is missing configuration file for any agents of type " +
                     "#{agent_types.inspect} in #{cfg_dir}, need to run rad!")
          end
        rescue Exception => e
          Log.info("Failed to start #{agent_name} agent", e, :trace)
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
    # type(String|nil):: Agent type, or nil if unknown
    def self.pick_agent_type(types)
      type = nil
      types.each { |t| (type = t; break) if File.exist?(cfg_file(t)) }
      type
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
      index == 0 ? type : "#{type}_#{index}"
    end

    # Determine configuration settings for this agent and persist them
    #
    # === Parameters
    # agent_type(String):: Agent type
    # agent_name(String):: Agent name
    # worker_index(Integer):: Rainbows worker index starting at 0
    # options(Hash):: Configuration options
    #   :prefix(String):: Prefix to build agent identity
    #   :base_id(String):: Base id to build agent identity, defaults to worker_index
    #
    # === Return
    # cfg(Hash):: Persisted configuration options
    def self.configure(agent_type, agent_name, worker_index, options)
      identity = RightScale::AgentIdentity.new(options[:prefix] || 'rs', agent_type, options[:base_id] || worker_index).to_s
      cfg = agent_options(File.exist?(cfg_file(agent_name)) ? agent_name : agent_type)
      cfg.merge!(FORCED_OPTIONS.merge(:identity => identity))
      cfg_file = cfg_file(agent_name)
      FileUtils.mkdir_p(File.dirname(cfg_file))
      File.delete(cfg_file) if File.exists?(cfg_file)
      File.open(cfg_file, 'w') { |fd| fd.puts "# Created at #{Time.now}" }
      File.open(cfg_file, 'a') { |fd| fd.write(YAML.dump(cfg)) }
      Log.info("Generated configuration file for #{agent_name} agent:\n  - config: #{cfg_file}")
      cfg
    end

  end # RainbowsAgentController

end # RightScale
