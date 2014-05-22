#
# Copyright (c) 2009-2013 RightScale Inc
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

  # Agent for receiving requests via RightNet and acting upon them
  # by dispatching to a registered actor to perform
  # See load_actors for details on how the agent specific environment is loaded
  # Operates in either HTTP or AMQP mode for RightNet communication
  class Agent

    include ConsoleHelper
    include DaemonizeHelper

    # (String) Identity of this agent
    attr_reader :identity

    # (Hash) Configuration options applied to the agent
    attr_reader :options

    # (Hash) Dispatcher for each queue for messages received via AMQP
    attr_reader :dispatchers

    # (ActorRegistry) Registry for this agents actors
    attr_reader :registry

    # (RightHttpClient|RightAMQP::HABrokerClient) Client for accessing RightNet/RightApi
    attr_reader :client

    # (Symbol) RightNet communication mode: :http or :amqp
    attr_reader :mode

    # (String) Name of AMQP queue to which requests are to be published
    attr_reader :request_queue

    # (Array) Tag strings published by agent
    attr_accessor :tags

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
      :mode               => :amqp,
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
      :heartbeat          => 0
    }

    # Maximum abnormal termination delay for slowing crash cycling
    MAX_ABNORMAL_TERMINATE_DELAY = 60 * 60

    # Block to be activated when finish terminating
    TERMINATE_BLOCK = lambda { EM.stop if EM.reactor_running? }

    # Exceptions with restricted error backtrace level
    # Value :no_trace means no backtrace and no tracking in stats or reporting to Errbit
    TRACE_LEVEL = {
      RightSupport::Net::NoResult => :no_trace,
      RightScale::Exceptions::ConnectivityFailure => :no_trace,
      RightScale::BalancedHttpClient::NotResponding => :no_trace,
      RightAMQP::HABrokerClient::NoConnectedBrokers => :no_trace
    }

    # Initializes a new agent and establishes an HTTP or AMQP RightNet connection
    # This must be used inside an EM.run block unless the EventMachine reactor
    # was already started by the server that this application runs on
    #
    # === Parameters
    # opts(Hash):: Configuration options:
    #   :identity(String):: Identity of this agent; no default
    #   :agent_name(String):: Local name for this agent
    #   :root_dir(String):: Application root for this agent containing subdirectories actors, certs, and init;
    #     defaults to current working directory
    #   :pid_dir(String):: Path to the directory where the agent stores its process id file (only if daemonized);
    #     defaults to the current working directory
    #   :log_dir(String):: Log directory path; defaults to the platform specific log directory
    #   :log_level(Symbol):: The verbosity of logging -- :debug, :info, :warn, :error or :fatal
    #   :actors(Array):: List of actors to load
    #   :console(Boolean):: true indicates to start interactive console
    #   :daemonize(Boolean):: true indicates to daemonize
    #   :retry_interval(Numeric):: Number of seconds between request retries
    #   :retry_timeout(Numeric):: Maximum number of seconds to retry request before give up
    #   :time_to_live(Integer):: Number of seconds before a request expires and is to be ignored
    #     by the receiver, 0 means never expire; defaults to 0
    #   :connect_timeout(Integer):: Number of seconds to wait for an AMQP broker connection to be established
    #   :reconnect_interval(Integer):: Number of seconds between AMQP broker reconnect attempts
    #   :offline_queueing(Boolean):: Whether to queue request if currently not connected to RightNet,
    #     also requires agent invocation of Sender initialize_offline_queue and start_offline_queue methods,
    #     as well as enable_offline_mode and disable_offline_mode as connection status changes
    #   :ping_interval(Integer):: Minimum number of seconds since last message receipt to ping the RightNet
    #     router to check connectivity; defaults to 0 meaning do not ping
    #   :check_interval(Integer):: Number of seconds between publishing stats and checking for AMQP broker
    #     connections that failed during agent launch and then attempting to reconnect
    #   :heartbeat(Integer):: Number of seconds between AMQP connection heartbeats used to keep
    #     connection alive (e.g., when AMQP broker is behind a firewall), nil or 0 means disable
    #   :grace_timeout(Integer):: Maximum number of seconds to wait after last request received before
    #     terminating regardless of whether there are still unfinished requests
    #   :dup_check(Boolean):: Whether to check for and reject duplicate requests, e.g., due to retries
    #     or redelivery by AMQP broker after server failure
    #   :prefetch(Integer):: Maximum number of messages the AMQP broker is to prefetch for this agent
    #     before it receives an ack. Value 1 ensures that only last unacknowledged gets redelivered
    #     if the agent crashes. Value 0 means unlimited prefetch.
    #   :airbrake_endpoint(String):: URL for Airbrake for reporting unexpected exceptions to Errbit
    #   :airbrake_api_key(String):: Key for using the Airbrake API access to Errbit
    #   :ready_callback(Proc):: Called once agent is connected to AMQP broker and ready for service (no argument)
    #   :restart_callback(Proc):: Called on each restart vote with votes being initiated by offline queue
    #     exceeding MAX_QUEUED_REQUESTS or by repeated failures to access RightNet when online (no argument)
    #   :services(Symbol):: List of services provided by this agent; defaults to all methods exposed by actors
    #   :secure(Boolean):: true indicates to use security features of RabbitMQ to restrict agents to themselves
    #   :fiber_pool_size(Integer):: Size of fiber pool
    #   :fiber_pool(FiberPool):: Fiber pool configured for use with EventMachine when making HTTP requests
    #   :mode(Symbol):: RightNet communication mode: :http or :amqp; defaults to :amqp
    #   :api_url(String):: Domain name for HTTP access to RightApi server
    #   :account_id(Integer):: Identifier for account owning this agent
    #   :shard_id(Integer):: Identifier for database shard in which this agent is operating
    #   :vhost(String):: AMQP broker virtual host
    #   :user(String):: AMQP broker user
    #   :pass(String):: AMQP broker password
    #   :host(String):: Comma-separated list of AMQP broker hosts; if only one, it is reapplied
    #     to successive ports; if none; defaults to 'localhost'
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
    # opts(Hash):: Configuration options per start method above
    #
    # === Return
    # true:: Always return true
    def initialize(opts)
      set_configuration(opts)
      @tags = []
      @tags << opts[:tag] if opts[:tag]
      @tags.flatten!
      @status_callbacks = []
      @options.freeze
      @last_stat_reset_time = Time.now
      reset_agent_stats
      true
    end

    # Put the agent in service
    # This requires making a RightNet connection via HTTP or AMQP
    # and other initialization like loading actors
    #
    # === Return
    # true:: Always return true
    def run
      Log.init(@identity, @options[:log_path], :print => true)
      Log.level = @options[:log_level] if @options[:log_level]
      RightSupport::Log::Mixin.default_logger = Log
      ErrorTracker.init(self, @options[:agent_name], :shard_id => @options[:shard_id], :trace_level => TRACE_LEVEL,
                        :airbrake_endpoint => @options[:airbrake_endpoint], :airbrake_api_key => @options[:airbrake_api_key])
      @history.update("start")

      now = Time.now
      Log.info("[start] Agent #{@identity} starting; time: #{now.utc}; utc_offset: #{now.utc_offset}")
      @options.each { |k, v| Log.info("-  #{k}: #{k.to_s =~ /pass/ ? '****' : (v.respond_to?(:each) ? v.inspect : v)}") }

      begin
        # Capture process id in file after optional daemonize
        pid_file = PidFile.new(@identity)
        pid_file.check
        daemonize(@identity, @options) if @options[:daemonize]
        pid_file.write
        at_exit { pid_file.remove }

        if @mode == :http
          # HTTP is being used for RightNet communication instead of AMQP
          # The code loaded with the actors specific to this application
          # is responsible to call setup_http at the appropriate time
          start_service
        else
          # Initiate AMQP broker connection, wait for connection before proceeding
          # otherwise messages published on failed connection will be lost
          @client = RightAMQP::HABrokerClient.new(Serializer.new(:secure), @options.merge(:exception_stats => ErrorTracker.exception_stats))
          @queues.each { |s| @remaining_queue_setup[s] = @client.all }
          @client.connection_status(:one_off => @options[:connect_timeout]) do |status|
            if status == :connected
              # Need to give EM (on Windows) a chance to respond to the AMQP handshake
              # before doing anything interesting to prevent AMQP handshake from
              # timing-out; delay post-connected activity a second
              EM_S.add_timer(1) { start_service }
            elsif status == :failed
              terminate("failed to connect to any brokers during startup")
            elsif status == :timeout
              terminate("failed to connect to any brokers after #{@options[:connect_timeout]} seconds during startup")
            else
              terminate("broker connect attempt failed unexpectedly with status #{status} during startup")
            end
          end
        end
      rescue PidFile::AlreadyRunning
        EM.stop if EM.reactor_running?
        raise
      rescue StandardError => e
        terminate("failed startup", e)
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

    # Resource href associated with this agent, if any
    #
    # @return [String, NilClass] href or nil if unknown
    def self_href
      @client.self_href if @client && @mode == :http
    end

    # Record callback to be notified of agent status changes
    # Multiple callbacks are supported
    #
    # === Block
    # optional block activated when there is a status change with parameters
    #   type (Symbol):: Type of client reporting status change: :auth, :api, :router, :broker
    #   state (Symbol):: State of client
    #
    # === Return
    # (Hash):: Status of various clients
    def status(&callback)
      @status_callbacks << callback if callback
      @status
    end

    # Connect to an additional AMQP broker or reconnect it if connection has failed
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
    # (String|nil):: Error message if failed, otherwise nil
    def connect(host, port, index, priority = nil, force = false)
      @connect_request_stats.update("connect b#{index}")
      even_if = " even if already connected" if force
      Log.info("Connecting to broker at host #{host.inspect} port #{port.inspect} " +
               "index #{index.inspect} priority #{priority.inspect}#{even_if}")
      Log.info("Current broker configuration: #{@client.status.inspect}")
      result = nil
      begin
        @client.connect(host, port, index, priority, force) do |id|
          @client.connection_status(:one_off => @options[:connect_timeout], :brokers => [id]) do |status|
            begin
              if status == :connected
                setup_queues([id])
                remaining = 0
                @remaining_queue_setup.each_value { |ids| remaining += ids.size }
                Log.info("[setup] Finished subscribing to queues after reconnecting to broker #{id}") if remaining == 0
                unless update_configuration(:host => @client.hosts, :port => @client.ports)
                  Log.warning("Successfully connected to broker #{id} but failed to update config file")
                end
              else
                ErrorTracker.log(self, "Failed to connect to broker #{id}, status #{status.inspect}")
              end
            rescue Exception => e
              ErrorTracker.log(self, "Failed to connect to broker #{id}, status #{status.inspect}", e)
            end
          end
        end
      rescue StandardError => e
        ErrorTracker.log(self, msg = "Failed to connect to broker at host #{host.inspect} and port #{port.inspect}", e)
        result = Log.format(msg, e)
      end
      result
    end

    # Disconnect from an AMQP broker and optionally remove it from the configuration
    # Refuse to do so if it is the last connected broker
    #
    # === Parameters
    # host(String):: Host name of broker
    # port(Integer):: Port number of broker
    # remove(Boolean):: Whether to remove broker from configuration rather than just closing it,
    #   defaults to false
    #
    # === Return
    # (String|nil):: Error message if failed, otherwise nil
    def disconnect(host, port, remove = false)
      and_remove = " and removing" if remove
      Log.info("Disconnecting#{and_remove} broker at host #{host.inspect} port #{port.inspect}")
      Log.info("Current broker configuration: #{@client.status.inspect}")
      id = RightAMQP::HABrokerClient.identity(host, port)
      @connect_request_stats.update("disconnect #{@client.alias_(id)}")
      connected = @client.connected
      result = e = nil
      if connected.include?(id) && connected.size == 1
        result = "Not disconnecting from #{id} because it is the last connected broker for this agent"
      elsif @client.get(id)
        begin
          if remove
            @client.remove(host, port) do |id|
              unless update_configuration(:host => @client.hosts, :port => @client.ports)
                result = "Successfully disconnected from broker #{id} but failed to update config file"
              end
            end
          else
            @client.close_one(id)
          end
        rescue StandardError => e
          result = Log.format("Failed to disconnect from broker #{id}", e)
        end
      else
        result = "Cannot disconnect from broker #{id} because not configured for this agent"
      end
      ErrorTracker.log(self, result, e) if result
      result
    end

    # There were problems while setting up service for this agent on the given AMQP brokers,
    # so mark these brokers as failed if not currently connected and later, during the
    # periodic status check, attempt to reconnect
    #
    # === Parameters
    # ids(Array):: Identity of brokers
    #
    # === Return
    # (String|nil):: Error message if failed, otherwise nil
    def connect_failed(ids)
      aliases = @client.aliases(ids).join(", ")
      @connect_request_stats.update("enroll failed #{aliases}")
      result = nil
      begin
        Log.info("Received indication that service initialization for this agent for brokers #{ids.inspect} has failed")
        connected = @client.connected
        ignored = connected & ids
        Log.info("Not marking brokers #{ignored.inspect} as unusable because currently connected") if ignored
        Log.info("Current broker configuration: #{@client.status.inspect}")
        @client.declare_unusable(ids - ignored)
      rescue StandardError => e
        ErrorTracker.log(self, msg = "Failed handling broker connection failure indication for #{ids.inspect}", e)
        result = Log.format(msg, e)
      end
      result
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
      if (cfg = AgentConfig.load_cfg(@agent_name))
        opts.each { |k, v| cfg[k] = v }
        AgentConfig.store_cfg(@agent_name, cfg)
        true
      else
        ErrorTracker.log(self, "Could not access configuration file #{AgentConfig.cfg_file(@agent_name).inspect} for update")
        false
      end
    rescue StandardError => e
      ErrorTracker.log(self, "Failed updating configuration file #{AgentConfig.cfg_file(@agent_name).inspect}", e)
      false
    end

    # Gracefully terminate execution by allowing unfinished tasks to complete
    # Immediately terminate if called a second time
    # Report reason for termination if it is abnormal
    #
    # === Parameters
    # reason(String):: Reason for abnormal termination, if any
    # exception(Exception|String):: Exception or other parenthetical error information, if any
    #
    # === Return
    # true:: Always return true
    def terminate(reason = nil, exception = nil)
      begin
        @history.update("stop") if @history
        ErrorTracker.log(self, "[stop] Terminating because #{reason}", exception) if reason
        if exception.is_a?(Exception)
          h = @history.analyze_service
          if h[:last_crashed]
            delay = [(Time.now.to_i - h[:last_crash_time]) * 2, MAX_ABNORMAL_TERMINATE_DELAY].min
            Log.info("[stop] Delaying termination for #{RightSupport::Stats.elapsed(delay)} to slow crash cycling")
            sleep(delay)
          end
        end
        if @terminating || @client.nil?
          @terminating = true
          @termination_timer.cancel if @termination_timer
          @termination_timer = nil
          Log.info("[stop] Terminating immediately")
          @terminate_callback.call
          @history.update("graceful exit") if @history && @client.nil?
        else
          @terminating = true
          @check_status_timer.cancel if @check_status_timer
          @check_status_timer = nil
          Log.info("[stop] Agent #{@identity} terminating")
          stop_gracefully(@options[:grace_timeout])
        end
      rescue StandardError => e
        ErrorTracker.log(self, "Failed to terminate gracefully", e)
        begin @terminate_callback.call; rescue Exception; end
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
        "agent stats"     => agent_stats(reset),
        "receive stats"   => dispatcher_stats(reset),
        "send stats"      => @sender.stats(reset),
        "last reset time" => @last_stat_reset_time.to_i,
        "stat time"       => now.to_i,
        "service uptime"  => @history.analyze_service,
        "machine uptime"  => Platform.shell.uptime
      }
      stats["revision"] = @revision if @revision
      if @mode == :http
        stats.merge!(@client.stats(reset))
      else
        stats["brokers"] = @client.stats(reset)
      end
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
    #   "connect requests"(Hash|nil):: Stats about requests to update AMQP broker connections with keys "total", "percent",
    #     and "last" with percentage breakdown by "connects: <alias>", "disconnects: <alias>", "enroll setup failed:
    #     <aliases>", or nil if none
    #   "exceptions"(Hash|nil):: Exceptions raised per category, or nil if none
    #     "total"(Integer):: Total exceptions for this category
    #     "recent"(Array):: Most recent as a hash of "count", "type", "message", "when", and "where"
    #   "non-deliveries"(Hash):: AMQP message non-delivery activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown by request type, or nil if none
    #   "request failures"(Hash|nil):: Request dispatch failure activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per failure type, or nil if none
    #   "response failures"(Hash|nil):: Response delivery failure activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per failure type, or nil if none
    def agent_stats(reset = false)
      stats = {
        "request failures"  => @request_failure_stats.all,
        "response failures" => @response_failure_stats.all
      }.merge(ErrorTracker.stats(reset))
      if @mode != :http
        stats["connect requests"] = @connect_request_stats.all
        stats["non-deliveries"] = @non_delivery_stats.all
      end
      reset_agent_stats if reset
      stats
    end

    # Reset agent statistics
    #
    # === Return
    # true:: Always return true
    def reset_agent_stats
      @connect_request_stats = RightSupport::Stats::Activity.new(measure_rate = false)
      @non_delivery_stats = RightSupport::Stats::Activity.new
      @request_failure_stats = RightSupport::Stats::Activity.new
      @response_failure_stats = RightSupport::Stats::Activity.new
      true
    end

    # Get dispatcher statistics
    #
    # === Return
    # (Hash):: Current statistics
    def dispatcher_stats(reset)
      @dispatchers[@identity].stats(reset)
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

      @options[:async_response] = true unless @options.has_key?(:async_response)
      @options[:non_blocking] = true if @options[:fiber_pool_size].to_i > 0

      @identity = @options[:identity]
      parsed_identity = AgentIdentity.parse(@identity)
      @agent_type = parsed_identity.agent_type
      @agent_name = @options[:agent_name]
      @request_queue = "request"
      @request_queue << "-#{@options[:shard_id].to_i}" if @options[:shard_id].to_i != 0
      @mode = @options[:mode].to_sym
      @stats_routing_key = "stats.#{@agent_type}.#{parsed_identity.base_id}"
      @terminate_callback = TERMINATE_BLOCK
      @revision = revision
      @queues = [@identity]
      @remaining_queue_setup = {}
      @history = History.new(@identity)
    end

    # Start service
    #
    # === Return
    # true:: Always return true
    def start_service
      begin
        @registry = ActorRegistry.new
        @dispatchers = create_dispatchers
        # Creating sender now but for HTTP mode it is not really usable until setup_http
        # is called by the code loaded for this application in load_actors
        @sender = create_sender
        load_actors
        setup_traps
        setup_status
        if @mode != :http
          setup_non_delivery
          setup_queues
        end
        @history.update("run")
        start_console if @options[:console] && !@options[:daemonize]
        EM.next_tick { @options[:ready_callback].call } if @options[:ready_callback]
        @client.listen(nil) { |e| handle_event(e) } if @mode == :http

        # Need to keep reconnect interval at least :connect_timeout in size,
        # otherwise connection_status callback will not timeout prior to next
        # reconnect attempt, which can result in repeated attempts to setup
        # queues when finally do connect
        setup_status_checks([@options[:check_interval], @options[:connect_timeout]].max)
      rescue StandardError => e
        terminate("failed service startup", e)
      end
      true
    end

    # Handle events received by this agent
    #
    # === Parameters
    # event(Hash):: Event received
    #
    # === Return
    # nil:: Always return nil indicating no response since handled separately via notify
    def handle_event(event)
      if event.is_a?(Hash)
        if ["Push", "Request"].include?(event[:type])
          # Use next_tick to ensure that on main reactor thread
          # so that any data access is thread safe
          EM_S.next_tick do
            begin
              if (result = @dispatcher.dispatch(event_to_packet(event))) && event[:type] == "Request"
                @client.notify(result_to_event(result), [result.to])
              end
            rescue Dispatcher::DuplicateRequest
            rescue Exception => e
              ErrorTracker.log(self, "Failed sending response for <#{event[:uuid]}>", e)
            end
          end
        elsif event[:type] == "Result"
          if (data = event[:data]) && (result = data[:result]) && result.respond_to?(:non_delivery?) && result.non_delivery?
            Log.info("Non-delivery of event <#{data[:request_uuid]}>: #{result.content}")
          else
            ErrorTracker.log(self, "Unexpected Result event from #{event[:from]}: #{event.inspect}")
          end
        else
          ErrorTracker.log(self, "Unrecognized event type #{event[:type]} from #{event[:from]}")
        end
      else
        ErrorTracker.log(self, "Unrecognized event: #{event.class}")
      end
      nil
    end

    # Convert event hash to packet
    #
    # === Parameters
    # event(Hash):: Event to be converted
    #
    # === Return
    # (Push|Request):: Packet
    def event_to_packet(event)
      packet = nil
      case event[:type]
      when "Push"
        packet = RightScale::Push.new(event[:path], event[:data], {:from => event[:from], :token => event[:uuid]})
        packet.expires_at = event[:expires_at].to_i if event.has_key?(:expires_at)
      when "Request"
        options = {:from => event[:from], :token => event[:uuid], :reply_to => event[:reply_to], :tries => event[:tries]}
        packet = RightScale::Request.new(event[:path], event[:data], options)
        packet.expires_at = event[:expires_at].to_i if event.has_key?(:expires_at)
      end
      packet
    end

    # Convert result packet to event
    #
    # === Parameters
    # result(Result):: Event to be converted
    #
    # === Return
    # (Hash):: Event
    def result_to_event(result)
      { :type => "Result",
        :from => result.from,
        :data => {
          :result => result.results,
          :duration => result.duration,
          :request_uuid => result.token,
          :request_from => result.request_from } }
    end

    # Create dispatcher per queue for use in handling incoming requests
    #
    # === Return
    # [Hash]:: Dispatchers with queue name as key
    def create_dispatchers
      cache = DispatchedCache.new(@identity) if @options[:dup_check]
      @dispatcher = Dispatcher.new(self, cache)
      @queues.inject({}) { |dispatchers, queue| dispatchers[queue] = @dispatcher; dispatchers }
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
          Log.info("[setup] Loading actor #{file}")
          require file
          actors.delete(actor)
        end
      end
      ErrorTracker.log(self, "Actors #{actors.inspect} not found in #{actors_dirs.inspect}") unless actors.empty?

      # Perform agent-specific initialization including actor creation and registration
      if (init_file = AgentConfig.init_file)
        Log.info("[setup] Initializing agent from #{init_file}")
        instance_eval(File.read(init_file), init_file)
      else
        ErrorTracker.log(self, "No agent init.rb file found in init directory of #{AgentConfig.root_dir.inspect}")
      end
      true
    end

    # Create client for HTTP-based RightNet communication
    # The code loaded with the actors specific to this application
    # is responsible for calling this function
    #
    # === Parameters
    # auth_client(AuthClient):: Authorization client to be used by this agent
    #
    # === Return
    # true:: Always return true
    def setup_http(auth_client)
      @auth_client = auth_client
      if @mode == :http
        RightHttpClient.init(@auth_client, @options.merge(:retry_enabled => true))
        @client = RightHttpClient.instance
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
                TERMINATE_BLOCK.call
                old.call if old.is_a? Proc
              end
            rescue Exception => e
              ErrorTracker.log(self, "Failed in termination", e)
            end
          end
        end
      end
      true
    end

    # Setup client status collection
    #
    # === Return
    # true:: Always return true
    def setup_status
      @status = {}
      if @client
        if @mode == :http
          @status = @client.status { |type, state| update_status(type, state) }.dup
        else
          @client.connection_status { |state| update_status(:broker, state) }
          @status[:broker] = :connected
          @status[:auth] = @auth_client.status { |type, state| update_status(type, state) } if @auth_client
        end
      end
      true
    end

    # Setup non-delivery handler
    #
    # === Return
    # true:: Always return true
    def setup_non_delivery
      @client.non_delivery do |reason, type, token, from, to|
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
          ErrorTracker.log(self, "Failed handling non-delivery for <#{token}>", e)
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
      @client.subscribe(queue, nil, options) { |_, packet, header| handle_packet(name, packet, header) }
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
        ErrorTracker.log(self, "#{queue} queue processing error", e)
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
        if (dispatcher = @dispatchers[queue])
          if (result = dispatcher.dispatch(request))
            exchange = {:type => :queue, :name => request.reply_to, :options => {:durable => true, :no_declare => @options[:secure]}}
            @client.publish(exchange, result, :persistent => true, :mandatory => true, :log_filter => [:request_from, :tries, :persistent, :duration])
          end
        else
          ErrorTracker.log(self, "Failed to dispatch request #{request.trace} from queue #{queue} because no dispatcher configured")
          @request_failure_stats.update("NoConfiguredDispatcher")
        end
      rescue Dispatcher::DuplicateRequest
      rescue RightAMQP::HABrokerClient::NoConnectedBrokers => e
        ErrorTracker.log(self, "Failed to publish result of dispatched request #{request.trace} from queue #{queue}", e)
        @request_failure_stats.update("NoConnectedBrokers")
      rescue StandardError => e
        ErrorTracker.log(self, "Failed to dispatch request #{request.trace} from queue #{queue}", e)
        @request_failure_stats.update(e.class.name)
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
      rescue StandardError => e
        ErrorTracker.log(self, "Failed to deliver response #{result.trace}", e)
        @response_failure_stats.update(e.class.name)
      end
      true
    end

    # Finish any remaining agent setup
    #
    # === Return
    # true:: Always return true
    def finish_setup
      @client.failed.each do |id|
        p = {:agent_identity => @identity}
        p[:host], p[:port], p[:id], p[:priority] = @client.identity_parts(id)
        @sender.send_push("/registrar/connect", p)
      end
      true
    end

    # Forward status updates via callbacks
    #
    # === Parameters
    # type (Symbol):: Type of client: :auth, :api, :router, or :broker
    # state (Symbol):: State of client
    #
    # === Return
    # true:: Always return true
    def update_status(type, state)
      old_state, @status[type] = @status[type], state
      Log.info("Client #{type.inspect} changed state from #{old_state.inspect} to #{state.inspect}")
      @status_callbacks.each do |callback|
        begin
          callback.call(type, state)
        rescue RuntimeError => e
          ErrorTracker.log(self, "Failed status callback", e, nil, :caller)
        end
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
      @check_status_brokers = @client.all if @mode != :http
      @check_status_timer = EM_S::PeriodicTimer.new(interval) { check_status }
      true
    end

    # Check status of agent by finishing any queue setup, checking the status of the queues,
    # and gathering/publishing current operation statistics
    # Checking the status of a queue will cause the broker connection to fail if the
    # queue does not exist, but a reconnect should then get initiated on the next check loop
    # Although agent termination cancels the check_status_timer, this method could induce
    # termination, therefore the termination status needs to be checked before each step
    #
    # === Return
    # true:: Always return true
    def check_status
      begin
        if @auth_client && @auth_client.mode != @mode
          Log.info("Detected request to switch mode from #{@mode} to #{@auth_client.mode}")
          update_status(:auth, :failed)
        end
      rescue Exception => e
        ErrorTracker.log(self, "Failed switching mode", e)
      end

      begin
        finish_setup unless @terminating || @mode == :http
      rescue Exception => e
        ErrorTracker.log(self, "Failed finishing setup", e)
      end

      begin
        @client.queue_status(@queues, timeout = @options[:check_interval] / 10) unless @terminating || @mode == :http
      rescue Exception => e
        ErrorTracker.log(self, "Failed checking queue status", e)
      end

      begin
        publish_stats unless @terminating || @stats_routing_key.nil?
      rescue Exception => e
        ErrorTracker.log(self, "Failed publishing stats", e)
      end

      begin
        check_other(@check_status_count) unless @terminating
      rescue Exception => e
        ErrorTracker.log(self, "Failed to perform other check status check", e)
      end

      @check_status_count += 1
      true
    end

    # Publish current stats
    #
    # === Return
    # true:: Always return true
    def publish_stats
      s = stats({}).content
      if @mode == :http
        @client.notify({:type => "Stats", :from => @identity, :data => s}, nil)
      else
        exchange = {:type => :topic, :name => "stats", :options => {:no_declare => true}}
        @client.publish(exchange, Stats.new(s, @identity), :no_log => true,
                        :routing_key => @stats_routing_key, :brokers => @check_status_brokers.rotate!)
      end
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
    # Close clients except for authorization
    #
    # === Parameters
    # timeout(Integer):: Maximum number of seconds to wait after last request received before
    #   terminating regardless of whether there are still unfinished requests
    #
    # === Return
    # true:: Always return true
    def stop_gracefully(timeout)
      if @mode == :http
        @client.close
      else
        @client.unusable.each { |id| @client.close_one(id, propagate = false) }
      end
      finish_terminating(timeout)
    end

    # Finish termination after all requests have been processed
    #
    # === Parameters
    # timeout(Integer):: Maximum number of seconds to wait after last request received before
    #   terminating regardless of whether there are still unfinished requests
    #
    # === Return
    # true:: Always return true
    def finish_terminating(timeout)
      if @sender
        request_count, request_age = @sender.terminate

        finish = lambda do
          request_count, request_age = @sender.terminate
          Log.info("[stop] The following #{request_count} requests initiated as recently as #{request_age} " +
                   "seconds ago are being dropped:\n  " + @sender.dump_requests.join("\n  ")) if request_age
          if @mode == :http
            @terminate_callback.call
          else
            @client.close { @terminate_callback.call }
          end
        end

        if (wait_time = [timeout - (request_age || timeout), 0].max) > 0
          Log.info("[stop] Termination waiting #{wait_time} seconds for completion of #{request_count} " +
                   "requests initiated as recently as #{request_age} seconds ago")
          @termination_timer = EM::Timer.new(wait_time) do
            begin
              Log.info("[stop] Continuing with termination")
              finish.call
            rescue Exception => e
              ErrorTracker.log(self, "Failed while finishing termination", e)
              begin @terminate_callback.call; rescue Exception; end
            end
          end
        else
          finish.call
        end
      else
        @terminate_callback.call
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
