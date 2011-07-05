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

  # Commands exposed by agent that has an AgentManager actor
  class AgentManagerCommands

    # List of command names associated with description
    # The commands should be implemented in methods in this class named '<name>_command'
    # where <name> is the name of the command.
    COMMANDS = {
      :list             => 'List all available commands with their description',
      :set_log_level    => 'Set log level to options[:level]',
      :get_log_level    => 'Get log level',
      :ping             => 'Ping agent',
      :stats            => 'Get statistics about agent operation',
      :terminate        => 'Terminate agent'
    }

    # Build hash of commands associating command names with block
    #
    # === Parameter
    # agent_manager(AgentManager):: Agent manager used by ping and stats commands
    #
    # === Return
    # cmds(Hash):: Hash of command blocks keyed by command names
    def self.get(agent_manager)
      cmds = {}
      target = new(agent_manager)
      COMMANDS.each { |k, v| cmds[k] = lambda { |opts, conn| opts[:conn] = conn; target.send("#{k.to_s}_command", opts) } }
      cmds
    end

    # Initialize command server
    #
    # === Parameter
    # agent_manager(AgentManager):: Agent manager used by ping and stats commands
    def initialize(agent_manager)
      @agent_manager = agent_manager
      @serializer = Serializer.new
    end

    protected

    # List command implementation
    #
    # === Parameters
    # opts(Hash):: Should contain the connection for sending data
    #
    # === Return
    # true:: Always return true
    def list_command(opts)
      usage = "Agent exposes the following commands:\n"
      COMMANDS.reject { |k, _| k == :list || k.to_s =~ /test/ }.each do |c|
        c.each { |k, v| usage += " - #{k.to_s}: #{v}\n" }
      end
      CommandIO.instance.reply(opts[:conn], usage)
    end

    # Set log level command
    #
    # === Return
    # true:: Always return true
    def set_log_level_command(opts)
      Log.level = opts[:level] if [ :debug, :info, :warn, :error, :fatal ].include?(opts[:level])
      CommandIO.instance.reply(opts[:conn], Log.level)
    end

    # Get log level command
    #
    # === Return
    # true:: Always return true
    def get_log_level_command(opts)
      CommandIO.instance.reply(opts[:conn], Log.level)
    end

    # Ping command
    #
    # === Parameters
    # opts[:conn](EM::Connection):: Connection used to send reply
    #
    # === Return
    # true
    def ping_command(opts)
      CommandIO.instance.reply(opts[:conn], @serializer.dump(@agent_manager.ping))
    end

    # Stats command
    #
    # === Parameters
    # opts[:conn](EM::Connection):: Connection used to send reply
    # opts[:reset](Boolean):: Whether to reset stats
    #
    # === Return
    # true
    def stats_command(opts)
      CommandIO.instance.reply(opts[:conn], @serializer.dump(@agent_manager.stats({:reset => opts[:reset]})))
    end

    # Terminate command
    #
    # === Parameters
    # opts[:conn](EM::Connection):: Connection used to send reply
    #
    # === Return
    # true:: Always return true
    def terminate_command(opts)
      CommandIO.instance.reply(opts[:conn], 'Terminating')
      @agent_manager.terminate
    end

  end # AgentManagerCommands

end # RightScale
