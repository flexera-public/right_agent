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

require 'socket'

module RightScale

  # Agent for receiving messages from the mapper and acting upon them
  # by dispatching to a registered actor to perform
  # See load_actors for details on how the agent specific environment is loaded
  class Agent

    include ConsoleHelper
    include DaemonizeHelper
    include AgentFileHelper
    include StatsHelper

    # (String) Identity of this agent
    attr_reader :identity

    # (Hash) Configuration options applied to the agent
    attr_reader :options

    # (Dispatcher) Dispatcher for messages received
    attr_reader :dispatcher

    # (ActorRegistry) Registry for this agents actors
    attr_reader :registry

    # (HABrokerClient) High availability AMQP broker client
    attr_reader :broker

    # (Array) Tag strings published by agent
    attr_reader :tags

    # (Proc) Callback procedure for exceptions
    attr_reader :exception_callback

    # Default option settings for the agent
    DEFAULT_OPTIONS = {
      :user               => 'agent',
      :pass               => 'testing',
      :vhost              => '/right_net',
      :secure             => false,
      :log_level          => :info,
      :daemonize          => false,
      :console            => false,
      :root               => Dir.pwd,
      :time_to_live       => 0,
      :retry_interval     => nil,
      :retry_timeout      => nil,
      :connect_timeout    => 60,
      :reconnect_interval => 60,
      :ping_interval      => 0,
      :check_interval     => 5 * 60,
      :grace_timeout      => 30,
      :prefetch           => 1,
    }

    # Initializes a new agent and establishes an AMQP connection.
    # This must be used inside EM.run block or if EventMachine reactor
    # is already started, for instance, by a Thin server that your Merb/Rails
    # application runs on.
    #
    # === Parameters
    # opts(Hash):: Configuration options:
    #   :identity(String):: Identity of this agent, no default
    #   :name(String):: Name of this type of agent
    #   :root_dir(String):: Application root for this agent containing subdirectories actors, agent, and certs,
    #     defaults to Dir.pwd
    #   :cfg_file(String):: Path to this agent's configuration file
    #   :pid_dir(String):: Path to the directory where the agent stores its pid file (only if daemonized).
    #     Defaults to the root or the current working directory.
    #   :log_dir(String):: Log file path. Defaults to the current working directory.
    #   :log_level(Symbol):: The verbosity of logging -- :debug, :info, :warn, :error or :fatal.
    #   :console(Boolean):: true indicates to start interactive console
    #   :daemonize(Boolean):: true indicates to daemonize
    #   :retry_interval(Numeric):: Number of seconds between request retries
    #   :retry_timeout(Numeric):: Maximum number of seconds to retry request before give up
    #   :time_to_live(Integer):: Number of seconds before a request expires and is to be ignored
    #     by the receiver, 0 means never expire, defaults to 0
    #   :connect_timeout:: Number of seconds to wait for a broker connection to be established
    #   :reconnect_interval(Integer):: Number of seconds between broker reconnect attempts
    #   :ping_interval(Integer):: Minimum number of seconds since last message receipt to ping the mapper
    #     to check connectivity, defaults to 0 meaning do not ping
    #   :check_interval:: Number of seconds between publishing stats and checking for broker connections
    #     that failed during agent launch and then attempting to reconnect via the mapper
    #   :grace_timeout(Integer):: Maximum number of seconds to wait after last request received before
    #     terminating regardless of whether there are still unfinished requests
    #   :dup_check(Boolean):: Whether to check for and reject duplicate requests, e.g., due to retries
    #   :prefetch(Integer):: Maximum number of messages the AMQP broker is to prefetch for this agent
    #     before it receives an ack. Value 1 ensures that only last unacknowledged gets redelivered
    #     if the agent crashes. Value 0 means unlimited prefetch.
    #   :exception_callback(Proc):: Callback with following parameters that is activated on exception events:
    #     exception(Exception):: Exception
    #     message(Packet):: Message being processed
    #     agent(Agent):: Reference to agent
    #   :ready_callback(Proc):: Called once agent is connected ready to service (no argument)
    #   :services(Symbol):: List of services provided by this agent. Defaults to all methods exposed by actors.
    #   :secure(Boolean):: true indicates to use Security features of RabbitMQ to restrict agents to themselves
    #   :single_threaded(Boolean):: true indicates to run all operations in one thread; false indicates
    #     to do requested work on EM defer thread and all else on main thread
    #   :threadpool_size(Integer):: Number of threads in EM thread pool
    #   :vhost(String):: AMQP broker virtual host
    #   :user(String):: AMQP broker user
    #   :pass(String):: AMQP broker password
    #   :host(String):: Comma-separated list of AMQP broker hosts; if only one, it is reapplied
    #     to successive ports; if none, defaults to 'localhost'
    #   :port(Integer):: Comma-separated list of AMQP broker ports corresponding to hosts; if only one,
    #     it is incremented and applied to successive hosts; if none, defaults to AMQP::HOST
    #
    # On start config.yml is read, so it is common to specify options in the YAML file. However, when both
    # Ruby code options and YAML file specify options, Ruby code options take precedence.
    #
    # === Return
    # agent(Agent):: New agent
    def self.start(opts = {})
      agent = new(opts)
      agent.run
      agent
    end

    # Initialize the new agent
    #
    # === Parameters
    # opts(Hash):: Configuration options per #start above
    #
    # === Return
    # true:: Always return true
    def initialize(opts)
      set_configuration(opts)
      @tags = []
      @tags << opts[:tag] if opts[:tag]
      @tags.flatten!
      @options.freeze
      @terminating = false
      @last_stat_reset_time = @service_start_time = Time.now
      reset_agent_stats
      true
    end

    # Put the agent in service
    #
    # === Return
    # true:: Always return true
    def run
      Log.init(@identity, @options[:log_path], :print => true)
      Log.level = @options[:log_level] if @options[:log_level]
      Log.debug("Start options:")
      log_opts = @options.inject([]){ |t, (k, v)| t << "-  #{k}: #{v}" }
      log_opts.each { |l| Log.debug(l) }
      
      begin
        # Capture process id in file after optional daemonize
        pid_file = PidFile.new(@identity, @options)
        pid_file.check
        daemonize(@identity, @options) if @options[:daemonize]
        pid_file.write
        at_exit { pid_file.remove }

        # Initiate AMQP broker connection, wait for connection before proceeding
        # otherwise messages published on failed connection will be lost
        @broker = HABrokerClient.new(Serializer.new(:secure), @options)
        @all_setup.each { |s| @remaining_setup[s] = @broker.all }
        @broker.connection_status(:one_off => @options[:connect_timeout]) do |status|
          if status == :connected
            # need to give EM (on Windows) a chance to respond to the AMQP handshake
            # before doing anything interesting to prevent AMQP handshake from
            # timing-out; delay post-connected activity a second.
            EM.add_timer(1) do
              begin
                @registry = ActorRegistry.new
                @dispatcher = Dispatcher.new(self)
                @sender = Sender.new(self)
                load_actors
                setup_traps
                setup_queues
                start_console if @options[:console] && !@options[:daemonize]

                # Need to keep reconnect interval at least :connect_timeout in size,
                # otherwise connection_status callback will not timeout prior to next
                # reconnect attempt, which can result in repeated attempts to setup
                # queues when finally do connect
                interval = [@options[:check_interval], @options[:connect_timeout]].max
                @check_status_count = 0
                @check_status_brokers = @broker.all
                EM.next_tick { @options[:ready_callback].call } if @options[:ready_callback]
                EM.add_periodic_timer(interval) { check_status }
              rescue Exception => e
                Log.error("Agent failed startup", e, :trace) unless e.message == "exit"
                EM.stop
              end
            end
          else
            Log.error("Agent failed to connect to any brokers")
            EM.stop
          end
        end
      rescue SystemExit => e
        raise e
      rescue Exception => e
        Log.error("Agent failed startup", e, :trace) unless e.message == "exit"
        raise e
      end
      true
    end

    # Register an actor for this agent
    #
    # === Parameters
    # actor(Actor):: Actor to be registered
    # prefix(String):: Prefix to be used in place of actor's default_prefix
    #
    # === Return
    # (Actor):: Actor registered
    def register(actor, prefix = nil)
      @registry.register(actor, prefix)
    end

    # Update set of tags published by agent and notify mapper
    # Add tags in 'new_tags' and remove tags in 'old_tags'
    #
    # === Parameters
    # new_tags(Array):: Tags to be added
    # obsolete_tags(Array):: Tags to be removed
    #
    # === Return
    # true:: Always return true
    def update_tags(new_tags, obsolete_tags)
      @tags += (new_tags || [])
      @tags -= (obsolete_tags || [])
      @tags.uniq!
      @sender.send_persistent_push("/mapper/update_tags", :new_tags => new_tags, :obsolete_tags => obsolete_tags)
      true
    end

    # Connect to an additional broker or reconnect it if connection has failed
    # Subscribe to identity queue on this broker
    # Update config file if this is a new broker
    # Assumes already has credentials on this broker and identity queue exists
    #
    # === Parameters
    # host(String):: Host name of broker
    # port(Integer):: Port number of broker
    # index(Integer):: Small unique id associated with this broker for use in forming alias
    # priority(Integer|nil):: Priority position of this broker in list for use
    #   by this agent with nil meaning add to end of list
    # force(Boolean):: Reconnect even if already connected
    #
    # === Return
    # res(String|nil):: Error message if failed, otherwise nil
    def connect(host, port, index, priority = nil, force = false)
      @connect_requests.update("connect b#{index}")
      even_if = " even if already connected" if force
      Log.info("Connecting to broker at host #{host.inspect} port #{port.inspect} " +
               "index #{index.inspect} priority #{priority.inspect}#{even_if}")
      Log.info("Current broker configuration: #{@broker.status.inspect}")
      res = nil
      begin
        @broker.connect(host, port, index, priority, nil, force) do |id|
          @broker.connection_status(:one_off => @options[:connect_timeout], :brokers => [id]) do |status|
            begin
              if status == :connected
                setup_queues([id])
                remaining = 0
                @remaining_setup.each_value { |ids| remaining += ids.size }
                Log.info("[setup] Finished subscribing to queues after reconnecting to broker #{id}") if remaining == 0
                unless update_configuration(:host => @broker.hosts, :port => @broker.ports)
                  Log.warning("Successfully connected to broker #{id} but failed to update config file")
                end
              else
                Log.error("Failed to connect to broker #{id}, status #{status.inspect}")
              end
            rescue Exception => e
              Log.error("Failed to connect to broker #{id}, status #{status.inspect}", e)
              @exceptions.track("connect", e)
            end
          end
        end
      rescue Exception => e
        res = Log.format("Failed to connect to broker #{HABrokerClient.identity(host, port)}", e)
        @exceptions.track("connect", e)
      end
      Log.error(res) if res
      res
    end

    # Disconnect from a broker and optionally remove it from the configuration
    # Refuse to do so if it is the last connected broker
    #
    # === Parameters
    # host(String):: Host name of broker
    # port(Integer):: Port number of broker
    # remove(Boolean):: Whether to remove broker from configuration rather than just closing it,
    #   defaults to false
    #
    # === Return
    # res(String|nil):: Error message if failed, otherwise nil
    def disconnect(host, port, remove = false)
      and_remove = " and removing" if remove
      Log.info("Disconnecting#{and_remove} broker at host #{host.inspect} port #{port.inspect}")
      Log.info("Current broker configuration: #{@broker.status.inspect}")
      id = HABrokerClient.identity(host, port)
      @connect_requests.update("disconnect #{@broker.alias_(id)}")
      connected = @broker.connected
      res = nil
      if connected.include?(id) && connected.size == 1
        res = "Not disconnecting  from #{id} because it is the last connected broker for this agent"
      elsif @broker.get(id)
        begin
          if remove
            @broker.remove(host, port) do |id|
              unless update_configuration(:host => @broker.hosts, :port => @broker.ports)
                res = "Successfully disconnected from broker #{id} but failed to update config file"
              end
            end
          else
            @broker.close_one(id)
          end
        rescue Exception => e
          res = Log.format("Failed to disconnect from broker #{id}", e)
          @exceptions.track("disconnect", e)
        end
      else
        res = "Cannot disconnect from broker #{id} because not configured for this agent"
      end
      Log.error(res) if res
      res
    end

    # There were problems while setting up service for this agent on the given brokers,
    # so mark these brokers as failed if not currently connected and later, during the
    # periodic status check, attempt to reconnect
    #
    # === Parameters
    # ids(Array):: Identity of brokers
    #
    # === Return
    # res(String|nil):: Error message if failed, otherwise nil
    def connect_failed(ids)
      aliases = @broker.aliases(ids).join(", ")
      @connect_requests.update("enroll failed #{aliases}")
      res = nil
      begin
        Log.info("Received indication that service initialization for this agent for brokers #{ids.inspect} has failed")
        connected = @broker.connected
        ignored = connected & ids
        Log.info("Not marking brokers #{ignored.inspect} as unusable because currently connected") if ignored
        Log.info("Current broker configuration: #{@broker.status.inspect}")
        @broker.declare_unusable(ids - ignored)
      rescue Exception => e
        res = Log.format("Failed handling broker connection failure indication for #{ids.inspect}", e)
        Log.error(res)
        @exceptions.track("connect failed", e)
      end
      res
    end

    # Gracefully terminate execution by allowing unfinished tasks to complete
    # Immediately terminate if called a second time
    #
    # === Block
    # Optional block to be executed after termination is complete
    #
    # === Return
    # true:: Always return true
    def terminate(&blk)
      begin
        if @terminating
          Log.info("[stop] Terminating immediately")
          @termination_timer.cancel if @termination_timer
          if blk then blk.call else EM.stop end
        else
          @terminating = true
          timeout = @options[:grace_timeout]
          Log.info("[stop] Agent #{@identity} terminating")
          stop_gracefully(timeout) do
            if @sender
              dispatch_age = @dispatcher.dispatch_age
              request_count, request_age = @sender.terminate
              wait_time = [timeout - (request_age || timeout), timeout - (dispatch_age || timeout), 0].max
              if wait_time > 0
                reason = ""
                reason = "completion of #{request_count} requests initiated as recently as #{request_age} seconds ago" if request_age
                reason += " and " if request_age && dispatch_age
                reason += "requests received as recently as #{dispatch_age} seconds ago" if dispatch_age
                Log.info("[stop] Termination waiting #{wait_time} seconds for #{reason}")
              end
              @termination_timer = EM::Timer.new(wait_time) do
                begin
                  Log.info("[stop] Continuing with termination") if wait_time > 0
                  request_count, request_age = @sender.terminate
                  if request_age
                    request_dump = @sender.dump_requests.join("\n  ")
                    Log.info("[stop] The following #{request_count} requests initiated as recently as #{request_age} " +
                             "seconds ago are being dropped:\n  #{request_dump}")
                  end
                  @broker.close(&blk)
                  EM.stop unless blk
                rescue Exception => e
                  Log.error("Failed while finishing termination", e, :trace)
                  EM.stop
                end
              end
            end
          end
        end
      rescue Exception => e
        Log.error("Failed to terminate gracefully", e, :trace)
        EM.stop
      end
      true
    end

    # Retrieve statistics about agent operation
    #
    # === Parameters:
    # options(Hash):: Request options:
    #   :reset(Boolean):: Whether to reset the statistics after getting the current ones
    #
    # === Return
    # result(OperationResult):: Always returns success
    def stats(options = {})
      now = Time.now
      reset = options[:reset]
      result = OperationResult.success("identity"        => @identity,
                                       "hostname"        => Socket.gethostname,
                                       "version"         => AgentConfig.protocol_version,
                                       "brokers"         => @broker.stats(reset),
                                       "agent stats"     => agent_stats(reset),
                                       "receive stats"   => @dispatcher.stats(reset),
                                       "send stats"      => @sender.stats(reset),
                                       "last reset time" => @last_stat_reset_time.to_i,
                                       "stat time"       => now.to_i,
                                       "service uptime"  => (now - @service_start_time).to_i,
                                       "machine uptime"  => Platform.shell.uptime)
      @last_stat_reset_time = now if reset
      result
    end

    protected

    # Get request statistics
    #
    # === Parameters
    # reset(Boolean):: Whether to reset the statistics after getting the current ones
    #
    # === Return
    # stats(Hash):: Current statistics:
    #   "connect requests"(Hash|nil):: Stats about requests to update connections with keys "total", "percent",
    #     and "last" with percentage breakdown by "connects: <alias>", "disconnects: <alias>", "enroll setup failed:
    #     <aliases>", or nil if none
    #   "exceptions"(Hash|nil):: Exceptions raised per category, or nil if none
    #     "total"(Integer):: Total exceptions for this category
    #     "recent"(Array):: Most recent as a hash of "count", "type", "message", "when", and "where"
    #   "non-deliveries"(Hash):: Message non-delivery activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown by request type, or nil if none
    def agent_stats(reset = false)
      stats = {
        "connect requests" => @connect_requests.all,
        "exceptions"       => @exceptions.stats,
        "non-deliveries"   => @non_deliveries.all
      }
      reset_agent_stats if reset
      stats
    end

    # Reset cache statistics
    #
    # === Return
    # true:: Always return true
    def reset_agent_stats
      @connect_requests = ActivityStats.new(measure_rate = false)
      @non_deliveries = ActivityStats.new
      @exceptions = ExceptionStats.new(self, @options[:exception_callback])
      true
    end

    # Set the agent's configuration using the supplied options
    #
    # === Parameters
    # opts(Hash):: Configuration options
    #
    # === Return
    # (String):: Serialized agent identity
    def set_configuration(opts)
      @options = DEFAULT_OPTIONS.clone
      @options.update(opts)
      @options[:log_path] = false
      if @options[:daemonize] || @options[:log_dir]
        @options[:log_path] = (@options[:log_dir] || Dir.pwd)

        # Create the path if is does not exist.  Added for windows, but is a good practice.
        FileUtils.mkdir_p(@options[:log_dir])
      end

      # Initialize AgentFileHelper
      root_dir = @options[:root_dir]

      @identity = @options[:identity]
      parsed_identity = AgentIdentity.parse(@identity)
      @agent_type = parsed_identity.agent_type
      @stats_routing_key = "stats.#{@agent_type}.#{parsed_identity.base_id}"

      @remaining_setup = {}
      @all_setup = [:setup_identity_queue]
      @identity
    end

    # Update agent's persisted configuration
    # Note that @options are frozen and therefore not updated
    #
    # === Parameters
    # opts(Hash):: Options being updated
    #
    # === Return
    # (Boolean):: true if successful, otherwise false
    def update_configuration(opts)
      res = false
      cfg_file = @options[:cfg_file] || cfg_file(@agent_type)
      if File.exists?(cfg_file) && cfg = YAML.load(IO.read(cfg_file))
        opts.each { |k, v| cfg[k] = v if cfg.has_key?(k) }
        File.open(cfg_file, 'w') { |fd| fd.write(YAML.dump(cfg)) }
        res = true
      end
      res
    rescue Exception => e
      Log.error("Failed updating configuration file #{cfg_file}", e, :trace)
      false
    end

    # Load the agent's ruby code for the actors
    # Also load the standard agent_manager actor
    #
    # === Return
    # true:: Always return true
    def load_actors
      return false unless @options[:root_dir]
      Log.error("Actors dir #{actors_dir} does not exist or is not reachable") unless File.directory?(actors_dir)

      # Load agent's configured actors
      actors = @options[:actors]
      Log.info("[setup] Agent #{@identity} with actors #{actors.inspect}")
      Dir["#{actors_dir}/*.rb"].each do |actor|
        next if actors && !actors.include?(File.basename(actor, ".rb"))
        Log.info("[setup] loading #{actor}")
        require actor
      end

      # Always load standard agent_manager actor
      require File.normalize_path(File.join(File.dirname(__FILE__), '..', 'actors', 'agent_manager'))
      @agent_manager = AgentManager.new
      Log.info("[setup] loading agent_manager.rb")

      # Perform agent-specific initialization including actor creation and registration
      init_path = File.join(init_dir, "#{@agent_type}.rb")
      if File.exists?(init_path)
        instance_eval(File.read(init_path), init_path)
        register @agent_manager
      else
        Log.error("Agent initialization file #{init_path.inspect} does not exist") unless File.exists?(init_path)
      end
      true
    end

    # Setup the queues on the specified brokers for this agent
    # Also configure message non-delivery handling
    #
    # === Parameters
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # true:: Always return true
    def setup_queues(ids = nil)
      @broker.non_delivery do |reason, type, token, from, to|
        begin
          @non_deliveries.update(type)
          reason = case reason
          when "NO_ROUTE" then OperationResult::NO_ROUTE_TO_TARGET
          when "NO_CONSUMERS" then OperationResult::TARGET_NOT_CONNECTED
          else reason.to_s
          end
          result = Result.new(token, from, OperationResult.non_delivery(reason), to)
          @sender.handle_response(result)
        rescue Exception => e
          Log.error("Failed handling non-delivery for <#{token}>", e, :trace)
          @exceptions.track("message return", e)
        end
      end
      # Do the setup regardless of whether remaining setup is empty since may be reconnecting
      @all_setup.each { |setup| @remaining_setup[setup] -= self.__send__(setup, ids) }
      true
    end

    # Setup identity queue for this agent
    #
    # === Parameters
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # ids(Array):: Identity of brokers to which subscribe submitted (although may still fail)
    def setup_identity_queue(ids = nil)
      queue = {:name => @identity, :options => {:durable => true, :no_declare => @options[:secure]}}
      filter = [:from, :tags, :tries, :persistent]
      options = {:ack => true, Request => filter, Push => filter, Result => [:from], :brokers => ids}
      ids = @broker.subscribe(queue, nil, options) do |_, packet|
        begin
          case packet
          when Push, Request then @dispatcher.dispatch(packet) unless @terminating
          when Result        then @sender.handle_response(packet)
          end
          @sender.message_received
        rescue HABrokerClient::NoConnectedBrokers => e
          Log.error("Identity queue processing error", e)
        rescue Exception => e
          Log.error("Identity queue processing error", e, :trace)
          @exceptions.track("identity queue", e, packet)
        end
      end
      ids
    end

    # Setup signal traps
    #
    # === Return
    # true:: Always return true
    def setup_traps
      ['INT', 'TERM'].each do |sig|
        old = trap(sig) do
          terminate do
            EM.stop
            old.call if old.is_a? Proc
          end
        end
      end
      true
    end

    # Finish any remaining agent setup
    #
    # === Return
    # true:: Always return true
    def finish_setup
      @broker.failed.each do |id|
        p = {:agent_identity => @identity}
        p[:host], p[:port], p[:id], p[:priority], _ = @broker.identity_parts(id)
        @sender.send_push("/registrar/connect", p)
      end
      true
    end

    # Check status of agent by gathering current operation statistics and publishing them and
    # by completing any queue setup that can be completed now based on broker status
    #
    # === Return
    # true:: Always return true
    def check_status
      begin
        finish_setup
      rescue Exception => e
        Log.error("Failed finishing setup", e)
        @exceptions.track("check status", e)
      end

      begin
        if @stats_routing_key
          exchange = {:type => :topic, :name => "stats", :options => {:no_declare => true}}
          @broker.publish(exchange, Stats.new(stats.content, @identity), :no_log => true,
                          :routing_key => @stats_routing_key, :brokers => @check_status_brokers.rotate!)
        end
      rescue Exception => e
        Log.error("Failed publishing stats", e)
        @exceptions.track("check status", e)
      end

      @check_status_count += 1
      true
    end

    # Store unique tags
    #
    # === Parameters
    # tags(Array):: Tags to be added
    #
    # === Return
    # @tags(Array):: Current tags
    def tag(*tags)
      tags.each {|t| @tags << t}
      @tags.uniq!
    end

    # Gracefully stop processing
    #
    # === Parameters
    # timeout(Integer):: Maximum number of seconds to wait after last request received before
    #   terminating regardless of whether there are still unfinished requests
    #
    # === Block
    # Required block to be executed after stopping message receipt wherever possible
    #
    # === Return
    # true:: Always return true
    def stop_gracefully(timeout)
      @broker.unusable.each { |id| @broker.close_one(id, propagate = false) }
      yield
    end

  end # Agent

end # RightScale
