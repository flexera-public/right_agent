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

module RightScale

  # Helper methods for accessing RightAgent files, directories, and processes
  # Values returned are driven by root_dir, cfg_dir, and pid_dir, which may be set,
  # and secondarily by the contents of the associated agent configuration file
  module AgentConfig

    # Current agent protocol version
    PROTOCOL_VERSION = 15

    # Current agent protocol version
    def self.protocol_version
      PROTOCOL_VERSION
    end

    # Initialize path to root directory of agent
    def self.root_dir=(dir)
      @root_dir = dir
    end

    # Initialize path to directory containing generated agent configuration files
    def self.cfg_dir=(dir)
      @cfg_dir = dir
    end

    # Initialize path to directory containing agent process id files
    def self.pid_dir=(dir)
      @pid_dir = dir
    end

    # Path to root directory of agent that contains at least the following directories:
    #   init   - initialization code
    #   actors - actors code
    #   certs  - security certificates and private keys
    def self.root_dir
      @root_dir ||= Dir.pwd
    end

    # Path to directory containing a directory for each agent configured on the local
    # machine (e.g., core, core_2, core_3). Each agent directory contains a 'config.yml'
    # file generated to contain that agent's current configuration
    def self.cfg_dir
      @cfg_dir ||= Platform.filesystem.cfg_dir
    end

    # Path to generated agent configuration file
    def self.cfg_file(agent_name)
      File.normalize_path(File.join(cfg_dir, agent_name, "config.yml"))
    end

    # List of all agent configuration files
    def self.cfg_files
      Dir.glob(File.join(cfg_dir, "**", "*.yml"))
    end

    # Path to directory containing actor source files
    def self.actors_dir
      @actors_dir ||= File.normalize_path(File.join(root_dir, "actors"))
    end

    # Path for searching for actors:
    #  - configured optional directories
    #  - default actors_dir in root_dir
    #  - other directories produced by other_actors_dirs method
    #  - actors directory in RightAgent gem
    #
    # === Parameters
    # optional_dirs(Array):: Optional actor directories
    #
    # === Return
    # actors_dirs(Array):: List of directories to search for actors
    def self.actors_dirs(optional_dirs = nil)
      actors_dirs = []
      actors_dirs += optional_dirs if optional_dirs
      actors_dirs << actors_dir if File.directory?(actors_dir)
      actors_dirs += other_actors_dirs if self.respond_to?(:other_actors_dirs)
      actors_dirs << File.normalize_path(File.join(File.dirname(__FILE__), 'actors'))
      actors_dirs
    end

    # Path to agent directory containing initialization files:
    #   config.yml - static configuration settings for the agent
    #   init.rb    - code that registers the agent's actors and performs any other
    #                agent specific initialization such as initializing its
    #                secure serializer and its command protocol server
    def self.init_dir
      @init_dir ||= File.normalize_path(File.join(root_dir, "init"))
    end

    # Path to directory containing the certificates used to sign and encrypt all
    # outgoing messages as well as to check the signature and decrypt any incoming
    # messages. This directory should contain at least:
    #   <agent name>.key  - agent's' private key
    #   <agent name>.cert - agent's' public certificate
    #   mapper.cert       - mapper's' public certificate
    def self.certs_dir
      @certs_dir ||= File.normalize_path(File.join(root_dir, "certs"))
    end

    # Path to directory containing agent process id files
    def self.pid_dir
      @pid_dir ||= Platform.filesystem.pid_dir
    end

    # Retrieve agent process id file
    #
    # === Parameters
    # agent_name(String):: Agent name
    #
    # === Return
    # (PidFile):: Process id file
    def self.pid_file(agent_name)
      res = nil
      file = cfg_file(agent_name)
      if File.readable?(file)
        if options = SerializationHelper.symbolize_keys(YAML.load(IO.read(file)))
          agent = Agent.new(options)
          res = PidFile.new(agent.identity, agent.options)
        end
      end
      res
    end

    # Retrieve agent options from generated agent configuration file
    # and agent process id file if they exist
    # Reset root_dir to one found in agent configuration file
    #
    # === Parameters
    # agent_name(String):: Agent name
    #
    # === Return
    # options(Hash):: Agent options including
    #   :identity(String):: Serialized agent identity
    #   :log_path(String):: Path to directory for agent log file
    #   :pid(Integer):: Agent process pid if available
    #   :listen_port(Integer):: Agent command listen port if available
    #   :cookie(String):: Agent command cookie if available
    def self.agent_options(agent_name)
      options = {}
      file = cfg_file(agent_name)
      if File.readable?(file)
        options = SerializationHelper.symbolize_keys(YAML.load(IO.read(file)))
        options[:log_path] = options[:log_dir] || Platform.filesystem.log_dir
        pid_file = PidFile.new(options[:identity], options)
        options.merge!(pid_file.read_pid) if pid_file.exists?
        @root_dir = options[:root_dir]
      end
      options
    end

    # Configured agents i.e. agents that have a configuration file
    #
    # === Return
    # (Array):: Name of configured agents
    def self.configured_agents
      cfg_files.map { |c| File.basename(File.dirname(c)) }
    end

  end # AgentConfig

end # RightScale
