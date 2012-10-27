#
# Copyright (c) 2009-2012 RightScale Inc
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

    # (String) Identity of this agent
    attr_reader :identity

    # (Hash) Configuration options applied to the agent
    attr_reader :options

    # (Dispatcher) Dispatcher for messages received
    attr_reader :dispatcher

    # (ActorRegistry) Registry for this agents actors
    attr_reader :registry

    # (RightAMQP::HABrokerClient) High availability AMQP broker client
    attr_reader :broker

    # (Array) Tag strings published by agent
    attr_accessor :tags

    # (Proc) Callback procedure for exceptions
    attr_reader :exception_callback

    # Default option settings for the agent
    DEFAULT_OPTIONS = {
      :user               => 'agent',
      :pass               => 'testing',
      :vhost              => '/right_net',
      :secure             => true,
      :log_level          => :info,
      :daemonize          => false,
      :console            => false,
      :root_dir           => Dir.pwd,
      :time_to_live       => 0,
      :retry_interval     => nil,
      :retry_timeout      => nil,
      :connect_timeout    => 60,
      :reconnect_interval => 60,
      :offline_queueing   => false,
      :ping_interval      => 0,
      :check_interval     => 5 * 60,
      :grace_timeout      => 30,
      :prefetch           => 1,
      :heartbeat          => 60
    }

    # Default block to be activated when finish terminating
    DEFAULT_TERMINATE_BLOCK = lambda { EM.stop if EM.reactor_running? }

    # Initializes a new agent and establishes an AMQP connection.
    # This must be used inside EM.run block or if EventMachine reactor
    # is already started, for instance, by a Thin server that your Merb/Rails
    # application runs on.
    #
    # === Parameters
    # opts(Hash):: Configuration options:
    #   :identity(String):: Identity of this agent, no default
    #   :agent_name(String):: Local name for this agent
    #   :root_dir(String):: Application root for this agent containing subdirectories actors, certs, and init,
    #     defaults to current working directory
    #   :pid_dir(String):: Path to the directory where the agent stores its process id file (only if daemonized),
    #     defaults to the current working directory
    #   :log_dir(String):: Log directory path, defaults to the platform specific log directory
    #   :log_level(Symbol):: The verbosity of logging -- :debug, :info, :warn, :error or :fatal
    #   :actors(Array):: List of actors to load
    #   :console(Boolean):: true indicates to start interactive console
    #   :daemonize(Boolean):: true indicates to daemonize
    #   :retry_interval(Numeric):: Number of seconds between request retries
    #   :retry_timeout(Numeric):: Maximum number of seconds to retry request before give up
    #   :time_to_live(Integer):: Number of seconds before a request expires and is to be ignored
    #     by the receiver, 0 means never expire, defaults to 0
    #   :connect_timeout(Integer):: Number of seconds to wait for a broker connection to be established
    #   :reconnect_interval(Integer):: Number of seconds between broker reconnect attempts
    #   :offline_queueing(Boolean):: Whether to queue request if currently not connected to any brokers,
    #     also requires agent invocation of Sender initialize_offline_queue and start_offline_queue methods,
    #     as well as enable_offline_mode and disable_offline_mode as broker connections status changes
    #   :ping_interval(Integer):: Minimum number of seconds since last message receipt to ping the mapper
    #     to check connectivity, defaults to 0 meaning do not ping
    #   :check_interval(Integer):: Number of seconds between publishing stats and checking for broker connections
    #     that failed during agent launch and then attempting to reconnect via the mapper
    #   :heartbeat(Integer):: Number of seconds between AMQP connection heartbeats used to keep
    #     connection alive (e.g., when AMQP broker is behind a firewall), nil or 0 means disable
    #   :grace_timeout(Integer):: Maximum number of seconds to wait after last request received before
    #     terminating regardless of whether there are still unfinished requests
    #   :dup_check(Boolean):: Whether to check for and reject duplicate requests, e.g., due to retries
    #     or redelivery by broker after server failure
    #   :prefetch(Integer):: Maximum number of messages the AMQP broker is to prefetch for this agent
    #     before it receives an ack. Value 1 ensures that only last unacknowledged gets redelivered
    #     if the agent crashes. Value 0 means unlimited prefetch.
    #   :exception_callback(Proc):: Callback with following parameters that is activated on exception events:
    #     exception(Exception):: Exception
    #     message(Packet):: Message being processed
    #     agent(Agent):: Reference to agent
    #   :ready_callback(Proc):: Called once agent is connected to broker and ready for service (no argument)
    #   :restart_callback(Proc):: Called on each restart vote with votes being initiated by offline queue
    #     exceeding MAX_QUEUED_REQUESTS or by repeated failures to access mapper when online (no argument)
    #   :abnormal_terminate_callback(Proc):: Called at end of termination when terminate abnormally (no argument)
    #   :services(Symbol):: List of services provided by this agent. Defaults to all methods exposed by actors.
    #   :secure(Boolean):: true indicates to use security features of RabbitMQ to restrict agents to themselves
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
      @last_stat_reset_time = Time.now
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
      RightSupport::Log::Mixin.default_logger = Log
      @history.update("start")
      now = Time.now
      Log.info("[start] Agent #{@identity} starting; time: #{now.utc}; utc_offset: #{now.utc_offset}")
      Log.debug("Start options:")
      log_opts = @options.inject([]) do |t, (k, v)|
        t << "-  #{k}: #{k.to_s =~ /pass/ ? '****' : (v.respond_to?(:each) ? v.inspect : v)}"
      end
      log_opts.each { |l| Log.debug(l) }
      terminate_callback = @options[:abnormal_terminate_callback]

      begin
        # Capture process id in file after optional daemonize
        pid_file = PidFile.new(@identity)
        pid_file.check
        daemonize(@identity, @options) if @options[:daemonize]
        pid_file.write
        at_exit { pid_file.remove }

        # Initiate AMQP broker connection, wait for connection before proceeding
        # otherwise messages published on failed connection will be lost
        @broker = RightAMQP::HABrokerClient.new(Serializer.new(:secure), @options)
        @queues.each { |s| @remaining_queue_setup[s] = @broker.all }
        @broker.connection_status(:one_off => @options[:connect_timeout]) do |status|
          if status == :connected
            # Need to give EM (on Windows) a chance to respond to the AMQP handshake
            # before doing anything interesting to prevent AMQP handshake from
            # timing-out; delay post-connected activity a second.
            EM.add_timer(1) { start_service(&terminate_callback) }
          elsif status == :failed
            terminate("failed to connect to any brokers during startup", &terminate_callback)
          elsif status == :timeout
            terminate("failed to connect to any brokers after #{@options[:connect_timeout]} seconds during startup",
                      &terminate_callback)
          else
            terminate("broker connect attempt failed unexpectedly with status #{status} during startup",
                      &terminate_callback)
          end
        end
      rescue SystemExit
        raise
      rescue PidFile::AlreadyRunning
        EM.stop if EM.reactor_running?
        raise
      rescue Exception => e
        terminate("failed startup", e, &terminate_callback)
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
      @connect_request_stats.update("connect b#{index}")
      even_if = " even if already connected" if force
      Log.info("Connecting to broker at host #{host.inspect} port #{port.inspect} " +
               "index #{index.inspect} priority #{priority.inspect}#{even_if}")
      Log.info("Current broker configuration: #{@broker.status.inspect}")
      res = nil
      begin
        @broker.connect(host, port, index, priority, force) do |id|
          @broker.connection_status(:one_off => @options[:connect_timeout], :brokers => [id]) do |status|
            begin
              if status == :connected
                setup_queues([id])
                remaining = 0
                @remaining_queue_setup.each_value { |ids| remaining += ids.size }
                Log.info("[setup] Finished subscribing to queues after reconnecting to broker #{id}") if remaining == 0
                unless update_configuration(:host => @broker.hosts, :port => @broker.ports)
                  Log.warning("Successfully connected to broker #{id} but failed to update config file")
                end
              else
                Log.error("Failed to connect to broker #{id}, status #{status.inspect}")
              end
            rescue Exception => e
              Log.error("Failed to connect to broker #{id}, status #{status.inspect}", e)
              @exception_stats.track("connect", e)
            end
          end
        end
      rescue Exception => e
        res = Log.format("Failed to connect to broker at host #{host.inspect} and port #{port.inspect}", e)
        @exception_stats.track("connect", e)
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
      id = RightAMQP::HABrokerClient.identity(host, port)
      @connect_request_stats.update("disconnect #{@broker.alias_(id)}")
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
          @exception_stats.track("disconnect", e)
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
      @connect_request_stats.update("enroll failed #{aliases}")
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
        @exception_stats.track("connect failed", e)
      end
      res
    end

    # Gracefully terminate execution by allowing unfinished tasks to complete
    # Immediately terminate if called a second time
    # Report reason for termination if it is abnormal
    #
    # === Parameters
    # reason(String):: Reason for abnormal termination, if any
    # exception(Exception|String):: Exception or other parenthetical error information, if any
    #
    # === Block
    # Optional block to be executed after termination is complete
    #
    # === Return
    # true:: Always return true
    def terminate(reason = nil, exception = nil, &block)
      block ||= DEFAULT_TERMINATE_BLOCK
      begin
        @history.update("stop")
        Log.error("[stop] Terminating because #{reason}", exception, :trace) if reason
        if @terminating || @broker.nil?
          @terminating = true
          @termination_timer.cancel if @termination_timer
          @termination_timer = nil
          Log.info("[stop] Terminating immediately")
          block.call
          @history.update("graceful exit") if @broker.nil?
        else
          @terminating = true
          @check_status_timer.cancel if @check_status_timer
          @check_status_timer = nil
          Log.info("[stop] Agent #{@identity} terminating")
          stop_gracefully(@options[:grace_timeout], &block)
        end
      rescue SystemExit
        raise
      rescue Exception => e
        Log.error("Failed to terminate gracefully", e, :trace)
        begin block.call; rescue Exception; end
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
      stats = {
        "name"            => @agent_name,
        "identity"        => @identity,
        "hostname"        => Socket.gethostname,
        "memory"          => Platform.process.resident_set_size,
        "version"         => AgentConfig.protocol_version,
        "brokers"         => @broker.stats(reset),
        "agent stats"     => agent_stats(reset),
        "receive stats"   => @dispatcher.stats(reset),
        "send stats"      => @sender.stats(reset),
        "last reset time" => @last_stat_reset_time.to_i,
        "stat time"       => now.to_i,
        "service uptime"  => @history.analyze_service,
        "machine uptime"  => Platform.shell.uptime
      }
      stats["revision"] = @revision if @revision
      result = OperationResult.success(stats)
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
    #   "request failures"(Hash|nil):: Request dispatch failure activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per failure type, or nil if none
    #   "response failures"(Hash|nil):: Response delivery failure activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per failure type, or nil if none
    def agent_stats(reset = false)
      stats = {
        "connect requests"  => @connect_request_stats.all,
        "exceptions"        => @exception_stats.stats,
        "non-deliveries"    => @non_delivery_stats.all,
        "request failures"  => @request_failure_stats.all,
        "response failures" => @response_failure_stats.all
      }
      reset_agent_stats if reset
      stats
    end

    # Reset cache statistics
    #
    # === Return
    # true:: Always return true
    def reset_agent_stats
      @connect_request_stats = RightSupport::Stats::Activity.new(measure_rate = false)
      @non_delivery_stats = RightSupport::Stats::Activity.new
      @request_failure_stats = RightSupport::Stats::Activity.new
      @response_failure_stats = RightSupport::Stats::Activity.new
      @exception_stats = RightSupport::Stats::Exceptions.new(self, @options[:exception_callback])
      true
    end

    # Set the agent's configuration using the supplied options
    #
    # === Parameters
    # opts(Hash):: Configuration options
    #
    # === Return
    # true:: Always return true
    def set_configuration(opts)
      @options = DEFAULT_OPTIONS.clone
      @options.update(opts)

      AgentConfig.root_dir = @options[:root_dir]
      AgentConfig.pid_dir = @options[:pid_dir]

      @options[:log_path] = false
      if @options[:daemonize] || @options[:log_dir]
        @options[:log_path] = (@options[:log_dir] || Platform.filesystem.log_dir)
        FileUtils.mkdir_p(@options[:log_path]) unless File.directory?(@options[:log_path])
      end

      @identity = @options[:identity]
      parsed_identity = AgentIdentity.parse(@identity)
      @agent_type = parsed_identity.agent_type
      @agent_name = @options[:agent_name]
      @stats_routing_key = "stats.#{@agent_type}.#{parsed_identity.base_id}"
      @revision = revision
      @queues = [@identity]
      @remaining_queue_setup = {}
      @history = History.new(@identity)
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
      if cfg = AgentConfig.load_cfg(@agent_name)
        opts.each { |k, v| cfg[k] = v }
        AgentConfig.store_cfg(@agent_name, cfg)
        true
      else
        Log.error("Could not access configuration file #{AgentConfig.cfg_file(@agent_name).inspect} for update")
        false
      end
    rescue Exception => e
      Log.error("Failed updating configuration file #{AgentConfig.cfg_file(@agent_name).inspect}", e, :trace)
      false
    end

    # Start service now that connected to at least one broker
    #
    # === Block
    # Optional block to be executed if terminate abnormally
    #
    # === Return
    # true:: Always return true
    def start_service(&terminate_callback)
      begin
        @registry = ActorRegistry.new
        @dispatcher = create_dispatcher
        @sender = create_sender
        load_actors
        setup_traps
        setup_non_delivery
        setup_queues
        @history.update("run")
        start_console if @options[:console] && !@options[:daemonize]
        EM.next_tick { @options[:ready_callback].call } if @options[:ready_callback]

        # Need to keep reconnect interval at least :connect_timeout in size,
        # otherwise connection_status callback will not timeout prior to next
        # reconnect attempt, which can result in repeated attempts to setup
        # queues when finally do connect
        setup_status_checks([@options[:check_interval], @options[:connect_timeout]].max)
      rescue SystemExit
        raise
      rescue Exception => e
        terminate("failed startup after connecting to a broker", e, &terminate_callback)
      end
      true
    end

    # Create dispatcher for handling incoming requests
    #
    # === Return
    # (Dispatcher):: New dispatcher
    def create_dispatcher
      cache = DispatchedCache.new(@identity) if @options[:dup_check]
      Dispatcher.new(self, cache)
    end

    # Create manager for outgoing requests
    #
    # === Return
    # (Sender):: New sender
    def create_sender
      Sender.new(self)
    end

    # Load the ruby code for the actors
    #
    # === Return
    # true:: Always return true
    def load_actors
      # Load agent's configured actors
      actors = (@options[:actors] || []).clone
      Log.info("[setup] Agent #{@identity} with actors #{actors.inspect}")
      actors_dirs = AgentConfig.actors_dirs
      actors_dirs.each do |dir|
        Dir["#{dir}/*.rb"].each do |file|
          actor = File.basename(file, ".rb")
          next if actors && !actors.include?(actor)
          Log.info("[setup] loading actor #{file}")
          require file
          actors.delete(actor)
        end
      end
      Log.error("Actors #{actors.inspect} not found in #{actors_dirs.inspect}") unless actors.empty?

      # Perform agent-specific initialization including actor creation and registration
      if init_file = AgentConfig.init_file
        Log.info("[setup] initializing agent from #{init_file}")
        instance_eval(File.read(init_file), init_file)
      else
        Log.error("No agent init.rb file found in init directory of #{AgentConfig.root_dir.inspect}")
      end
      true
    end

    # Setup signal traps
    #
    # === Return
    # true:: Always return true
    def setup_traps
      ['INT', 'TERM'].each do |sig|
        old = trap(sig) do
          EM.next_tick do
            begin
              terminate do
                DEFAULT_TERMINATE_BLOCK.call
                old.call if old.is_a? Proc
              end
            rescue Exception => e
              Log.error("Failed in termination", e, :trace)
            end
          end
        end
      end
      true
    end

    # Setup non-delivery handler
    #
    # === Return
    # true:: Always return true
    def setup_non_delivery
      @broker.non_delivery do |reason, type, token, from, to|
        begin
          @non_delivery_stats.update(type)
          reason = case reason
          when "NO_ROUTE" then OperationResult::NO_ROUTE_TO_TARGET
          when "NO_CONSUMERS" then OperationResult::TARGET_NOT_CONNECTED
          else reason.to_s
          end
          result = Result.new(token, from, OperationResult.non_delivery(reason), to)
          @sender.handle_response(result)
        rescue Exception => e
          Log.error("Failed handling non-delivery for <#{token}>", e, :trace)
          @exception_stats.track("message return", e)
        end
      end
    end

    # Setup the queues on the specified brokers for this agent
    # Do the setup regardless of whether remaining setup is empty since may be reconnecting
    #
    # === Parameters
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # true:: Always return true
    def setup_queues(ids = nil)
      @queues.each { |q| @remaining_queue_setup[q] -= setup_queue(q, ids) }
      true
    end

    # Setup queue for this agent
    #
    # === Parameters
    # name(String):: Queue name
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # (Array):: Identity of brokers to which subscribe submitted (although may still fail)
    def setup_queue(name, ids = nil)
      queue = {:name => name, :options => {:durable => true, :no_declare => @options[:secure]}}
      filter = [:from, :tags, :tries, :persistent]
      options = {:ack => true, Push => filter, Request => filter, Result => [:from], :brokers => ids}
      @broker.subscribe(queue, nil, options) { |_, packet, header| handle_packet(name, packet, header) }
    end

    # Handle packet from queue
    #
    # === Parameters
    # queue(String):: Name of queue from which message was received
    # packet(Packet):: Packet received
    # header(AMQP::Frame::Header):: Packet header containing ack control
    #
    # === Return
    # true:: Always return true
    def handle_packet(queue, packet, header)
      begin
        # Continue to dispatch/ack requests even when terminating otherwise will block results
        # Ideally would reject requests when terminating but broker client does not yet support that
        case packet
        when Push, Request then dispatch_request(packet, queue)
        when Result        then deliver_response(packet)
        end
        @sender.message_received
      rescue Exception => e
        Log.error("#{queue} queue processing error", e, :trace)
        @exception_stats.track("#{queue} queue", e, packet)
      ensure
        # Relying on fact that all dispatches/deliveries are synchronous and therefore
        # need to have completed or failed by now, thus allowing packet acknowledgement
        header.ack
      end
      true
    end

    # Dispatch request and then send response if any
    #
    # === Parameters
    # request(Push|Request):: Packet containing request
    # queue(String):: Name of queue from which message was received
    #
    # === Return
    # true:: Always return true
    def dispatch_request(request, queue)
      begin
        if result = @dispatcher.dispatch(request)
          exchange = {:type => :queue, :name => "response", :options => {:durable => true, :no_declare => @options[:secure]}}
          @broker.publish(exchange, result, :persistent => true, :mandatory => true, :log_filter => [:tries, :persistent, :duration])
        end
      rescue Dispatcher::DuplicateRequest
      rescue RightAMQP::HABrokerClient::NoConnectedBrokers => e
        Log.error("Failed to publish result of dispatched request #{request.trace} from queue #{queue}", e)
        @request_failure_stats.update("NoConnectedBrokers")
      rescue Exception => e
        Log.error("Failed to dispatch request #{request.trace} from queue #{queue}", e, :trace)
        @request_failure_stats.update(e.class.name)
        @exception_stats.track("request", e)
      end
      true
    end

    # Deliver response to request sender
    #
    # === Parameters
    # result(Result):: Packet containing response
    #
    # === Return
    # true:: Always return true
    def deliver_response(result)
      begin
        @sender.handle_response(result)
      rescue Exception => e
        Log.error("Failed to deliver response #{result.trace}", e, :trace)
        @response_failure_stats.update(e.class.name)
        @exception_stats.track("response", e)
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
        p[:host], p[:port], p[:id], p[:priority] = @broker.identity_parts(id)
        @sender.send_push("/registrar/connect", p)
      end
      true
    end

    # Setup periodic status check
    #
    # === Parameters
    # interval(Integer):: Number of seconds between status checks
    #
    # === Return
    # true:: Always return true
    def setup_status_checks(interval)
      @check_status_count = 0
      @check_status_brokers = @broker.all
      @check_status_timer = EM::PeriodicTimer.new(interval) { check_status }
      true
    end

    # Check status of agent by gathering current operation statistics and publishing them
    # and finishing any queue setup
    # Although agent termination cancels the check_status_timer, this method could induce
    # termination, therefore the termination status needs to be checked before each step
    #
    # === Return
    # true:: Always return true
    def check_status
      begin
        finish_setup unless @terminating
      rescue Exception => e
        Log.error("Failed finishing setup", e)
        @exception_stats.track("check status", e)
      end

      begin
        if @stats_routing_key && !@terminating
          exchange = {:type => :topic, :name => "stats", :options => {:no_declare => true}}
          @broker.publish(exchange, Stats.new(stats.content, @identity), :no_log => true,
                          :routing_key => @stats_routing_key, :brokers => @check_status_brokers.rotate!)
        end
      rescue Exception => e
        Log.error("Failed publishing stats", e)
        @exception_stats.track("check status", e)
      end

      begin
        check_other(@check_status_count) unless @terminating
      rescue Exception => e
        Log.error("Failed to perform other check status check", e)
        @exception_stats.track("check status", e)
      end

      @check_status_count += 1
      true
    end

    # Allow derived classes to perform any other useful periodic checks
    #
    # === Parameters
    # check_status_count(Integer):: Counter that is incremented for each status check
    #
    # === Return
    # true:: Always return true
    def check_other(check_status_count)
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
    # Optional block to be executed after stopping message processing wherever possible
    #
    # === Return
    # true:: Always return true
    def stop_gracefully(timeout, &block)
      @broker.unusable.each { |id| @broker.close_one(id, propagate = false) }
      finish_terminating(timeout, &block)
    end

    # Finish termination after all requests have been processed
    #
    # === Parameters
    # timeout(Integer):: Maximum number of seconds to wait after last request received before
    #   terminating regardless of whether there are still unfinished requests
    #
    # === Block
    # Optional block to be executed after stopping message processing wherever possible
    #
    # === Return
    # true:: Always return true
    def finish_terminating(timeout, &block)
      if @sender
        request_count, request_age = @sender.terminate

        finish = lambda do
          request_count, request_age = @sender.terminate
          Log.info("[stop] The following #{request_count} requests initiated as recently as #{request_age} " +
                   "seconds ago are being dropped:\n  " + @sender.dump_requests.join("\n  ")) if request_age
          @broker.close { block.call }
        end

        if (wait_time = [timeout - (request_age || timeout), 0].max) > 0
          Log.info("[stop] Termination waiting #{wait_time} seconds for completion of #{request_count} " +
                   "requests initiated as recently as #{request_age} seconds ago")
          @termination_timer = EM::Timer.new(wait_time) do
            begin
              Log.info("[stop] Continuing with termination")
              finish.call
            rescue Exception => e
              Log.error("Failed while finishing termination", e, :trace)
              begin block.call; rescue Exception; end
            end
          end
        else
          finish.call
        end
      else
        block.call
      end
      @history.update("graceful exit")
      true
    end

    # Determine current revision of software
    #
    # === Return
    # (String):: Revision of software in displayable format
    def revision
    end

  end # Agent

end # RightScale
