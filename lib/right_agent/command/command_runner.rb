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

  # Run commands exposed by an agent.
  # External processes can send commands through a socket with the specified port.
  # Command runner accepts connections and unserializes commands using YAML.
  # Each command is expected to be a hash containing the :name and :options keys.
  class CommandRunner
    class << self
      # (Integer) Port command runner is listening on
      attr_reader :listen_port

      # (String) Cookie used by command protocol
      attr_reader :cookie
    end

    # Start a command runner listening on a local TCP port.
    #
    # === Parameters
    # socket_port(Integer):: Base socket port on which to listen for connection,
    #                        increment and retry if port already taken
    # identity(String):: Agent identity
    # commands(Hash):: Commands exposed by agent
    # fiber_pool(NB::FiberPool):: Pool of initialized fibers to be used for executing
    #   received commands in non-blocking fashion
    #
    # === Block
    # If a block is provided, this method will yield after all setup has been completed,
    # passing its PidFile to the block. This provides a customization hook, e.g. for
    # changing the pid file's access mode or ownership.
    #
    # === Return
    # cmd_options[:cookie](String):: Command protocol cookie
    # cmd_options[:listen_port](Integer):: Command server listen port
    #
    # === Raise
    # (Exceptions::Application):: If +start+ has already been called and +stop+ hasn't since
    def self.start(socket_port, identity, commands, fiber_pool = nil)
      cmd_options = nil
      @listen_port = socket_port

      begin
        CommandIO.instance.listen(socket_port) do |c, conn|
          begin
            cmd_cookie = c[:cookie]
            if cmd_cookie == @cookie
              cmd_name = c[:name].to_sym
              if commands.include?(cmd_name)
                if fiber_pool
                  fiber_pool.spawn { commands[cmd_name].call(c, conn) }
                else
                  commands[cmd_name].call(c, conn)
                end
              else
                Log.warning("Unknown command '#{cmd_name}', known commands: #{commands.keys.join(', ')}")
              end
            else
              Log.error("Invalid cookie used by command protocol client (#{cmd_cookie})")
            end
          rescue Exception => e
            Log.error("Command failed", e, :trace)
          end
        end

        @cookie = AgentIdentity.generate
        cmd_options = { :listen_port => @listen_port, :cookie => @cookie }
        # Now update pid file with command port and cookie
        pid_file = PidFile.new(identity)
        if pid_file.exists?
          pid_file.set_command_options(cmd_options)
          yield(pid_file) if block_given?
        else
          Log.warning("Failed to update listen port in PID file - no pid file found for agent with identity #{identity}")
        end

        Log.info("[setup] Command server started listening on port #{@listen_port}")
      rescue Exceptions::IO
        # Port already taken, increment and retry
        cmd_options = start(socket_port + 1, identity, commands)
      end

      cmd_options
    end

    # Stop command runner, cleanup all opened file descriptors and delete pipe
    #
    # === Return
    # true:: If command listener was listening
    # false:: Otherwise
    def self.stop
      CommandIO.instance.stop_listening
      Log.info("[stop] Command server stopped listening")
    end

  end

end
