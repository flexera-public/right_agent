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

# Helper methods for accessing files and directories associated with an agent
# Values returned are driven by root_dir and cfg_dir, which may be set, and secondarily
# by the contents of the associated agent configuration file
module RightScale

  module AgentFileHelper

    # Initialize path to root directory of agent
    def init_root_dir(dir)
      @root_dir = dir
    end

    # Initialize path to directory containing generated agent configuration files
    def init_cfg_dir(dir)
      @cfg_dir = dir
    end

    # Initialize path to directory containing agent process id files
    def init_pid_dir(dir)
      @pid_dir = dir
    end

    # Path to root directory of agent that contains at least the following directories:
    #   init   - initialization code
    #   actors - actors code
    #   certs  - security certificates and private keys
    def root_dir
      @root_dir || Dir.pwd
    end

    # Path to directory containing a directory for each agent configured on the local
    # machine (e.g., core, core_2, core_3). Each agent directory contains a 'config.yml'
    # file generated to contain that agent's current configuration
    def cfg_dir
      @cfg_dir || Platform.filesystem.cfg_dir
    end

    # Path to generated agent configuration file
    def cfg_file(agent_name)
      File.normalize_path(File.join(cfg_dir, agent_name, "config.yml"))
    end

    # List of all agent configuration files
    def cfg_files
      Dir.glob(File.join(cfg_dir, "**", "*.{#{YAML_EXT.join(',')}}"))
    end

    # Path to directory containing actor source files
    def actors_dir
      @actors_dir ||= File.normalize_path(File.join(root_dir, "actors"))
    end

    # Path to agent directory containing initialization files:
    #   config.yml - static configuration settings for the agent
    #   init.rb    - code that registers the agent's actors and performs any other
    #                agent specific initialization such as initializing its
    #                secure serializer and its command protocol server
    def init_dir
      @init_dir ||= File.normalize_path(File.join(root_dir, "init"))
    end

    # Path to directory containing the certificates used to sign and encrypt all
    # outgoing messages as well as to check the signature and decrypt any incoming
    # messages. This directory should contain at least:
    #   <agent name>.key  - agent's' private key
    #   <agent name>.cert - agent's' public certificate
    #   mapper.cert       - mapper's' public certificate
    def certs_dir
      @certs_dir ||= File.normalize_path(File.join(root_dir, "certs"))
    end

    # Path to directory containing agent process id files
    def pid_dir
      @pid_dir || Platform.filesystem.pid_dir
    end

    # Retrieve agent process id file
    #
    # === Parameters
    # agent_name(String):: Agent name
    #
    # === Return
    # (PidFile):: Process id file
    def pid_file(agent_name)
      res = nil
      file = cfg_file(agent_name)
      if File.readable?(file)
        if options = symbolize(YAML.load(IO.read(file)))
          agent = Agent.new(options)
          res = PidFile.new(agent.identity, agent.options)
        end
      end
      res
    end

    # Retrieve agent options from generated agent configuration file
    # and agent process id file if it exists
    #
    # === Parameters
    # agent_name(String):: Agent name
    #
    # === Return
    # options(Hash):: Agent options
    #   :identity(String):: Serialized agent identity
    #   :log_path(String):: Log path
    #   :pid(Integer):: Agent process pid if available
    #   :listen_port(Integer):: Agent command listen port if available
    #   :cookie(String):: Agent command cookie if available
    #   Hash):: Other serialized configuration options
    def agent_options(agent_name)
      options = {}
      file = cfg_file(agent_name)
      if File.readable?(file)
        options = symbolize(YAML.load(IO.read(file)))
        options[:log_path] = options[:log_dir] || Platform.filesystem.log_dir
        pid_file = PidFile.new(options[:identity], options)
        options.merge!(pid_file.read_pid) if pid_file.exists?
        init_root_dir(options[:root_dir])
      end
      options
    end

    # Configured agents i.e. agents that have a configuration file
    #
    # === Return
    # (Array):: List of configured agents
    def configured_agents
      Dir.glob(File.join(cfg_dir, "*"))
    end

    # Produce a hash with keys as symbols from given hash
    #
    # === Parameters
    # hash(Hash):: Hash to be symbolized
    #
    # === Return
    # sym(Hash):: Hash with keys as symbols
    def symbolize(hash)
      sym = {}
      hash.each do |k, v|
        k = k.intern if k.respond_to?(:intern)
        sym[k] = v
      end
      sym
    end

  end # AgentUtils

end # RightScale
