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

  # This class allows sending requests to agents without having to run a local mapper
  # It is used by Actor.request which is used by actors that need to send requests to remote agents
  # If requested, it will queue requests when there are no broker connections
  # All requests go through the mapper for security purposes
  class Sender

    include StatsHelper

    # Request that is waiting for a response
    class PendingRequest

      # (Symbol) Kind of send request
      attr_reader :kind

      # (Time) Time when request message was received
      attr_reader :receive_time

      # (Proc) Block to be activated when response is received
      attr_reader :response_handler

      # (String) Token for parent request in a retry situation
      attr_accessor :retry_parent

      def initialize(kind, receive_time, response_handler)
        @kind = kind
        @receive_time = receive_time
        @response_handler = response_handler
        @retry_parent = nil
      end

    end # PendingRequest

    # Cache for requests that are waiting for a response
    # Automatically deletes push requests when get too old
    # Retains non-push requests until explicitly deleted
    class PendingRequests < Hash

      # Kinds of send requests
      REQUEST_KINDS = [:send_retryable_request, :send_persistent_request]

      # Kinds of send pushes
      PUSH_KINDS = [:send_push, :send_persistent_push]

      # Maximum number of seconds to retain send pushes in cache
      MAX_PUSH_AGE = 2 * 60

      # Minimum number of seconds between push cleanups
      MIN_CLEANUP_INTERVAL = 15

      # Create cache
      def initialize
        @last_cleanup = Time.now
        super
      end

      # Store pending request
      #
      # === Parameters
      # token(String):: Generated message identifier
      # request(PendingRequest):: Pending request
      #
      # === Return
      # (PendingRequest):: Stored request
      def []=(token, request)
        now = Time.now
        if (now - @last_cleanup) > MIN_CLEANUP_INTERVAL
          self.reject! { |t, r| PUSH_KINDS.include?(r.kind) && (now - r.receive_time) > MAX_PUSH_AGE }
          @last_cleanup = now
        end
        super
      end

      # Select cache entries of the given kinds
      #
      # === Parameters
      # kinds(Array):: Kind of requests to be included
      #
      # === Return
      # (Hash):: Requests of specified kind
      def kind(kinds)
        self.reject { |t, r| !kinds.include?(r.kind) }
      end

      # Get age of youngest pending request
      #
      # === Return
      # age(Integer):: Age of youngest request
      def youngest_age
        now = Time.now
        age = nil
        self.each_value do |r|
          seconds = (now - r.receive_time).to_i
          age = seconds if age.nil? || seconds < age
        end
        age
      end

      # Get age of oldest pending request
      #
      # === Return
      # age(Integer):: Age of oldest request
      def oldest_age
        now = Time.now
        age = nil
        self.each_value do |r|
          seconds = (now - r.receive_time).to_i
          age = seconds if age.nil? || seconds > age
        end
        age
      end

    end # PendingRequests

    # Queue for storing requests while disconnected from broker and then sending
    # them when successfully reconnect
    class OfflineHandler

      # Maximum seconds to wait before starting flushing offline queue when disabling offline mode
      MAX_QUEUE_FLUSH_DELAY = 2 * 60

      # Maximum number of offline queued requests before triggering restart vote
      MAX_QUEUED_REQUESTS = 1000

      # Number of seconds that should be spent in offline mode before triggering a restart vote
      RESTART_VOTE_DELAY = 15 * 60

      # (Symbol) Current queue state with possible values:
      #   Value          Description                Action               Next state
      #   :created       Queue created              init                 :initializing
      #   :initializing  Agent still initializing   start                :running
      #   :running       Queue has been started     disable when offline :flushing
      #   :flushing      Sending queued requests    enable               :running
      #   :terminating   Agent terminating
      attr_reader :state

      # (Symbol) Current offline handling mode with possible values:
      #   Value          Description
      #   :initializing  Agent still initializing
      #   :online        Agent connected to broker
      #   :offline       Agent disconnected from broker
      attr_reader :mode

      # (Array) Offline queue
      attr_accessor :queue

      # Create offline queue
      #
      # === Parameters
      # restart_callback(Proc):: Callback that is activated on each restart vote with votes being initiated
      #   by offline queue exceeding MAX_QUEUED_REQUESTS
      # offline_stats(ActivityStats):: Offline queue tracking statistics
      def initialize(restart_callback, offline_stats)
        @restart_vote = restart_callback
        @restart_vote_timer = nil
        @restart_vote_count = 0
        @offline_stats = offline_stats
        @state = :created
        @mode = :initializing
        @queue = []
      end

      # Initialize the offline queue
      # All requests sent prior to running this initialization are queued
      # and then are sent once this initialization has run
      # All requests following this call and prior to calling start
      # are prepended to the request queue
      #
      # === Return
      # true:: Always return true
      def init
        @state = :initializing if @state == :created
        true
      end

      # Switch to online mode and send all buffered messages
      #
      # === Return
      # true:: Always return true
      def start
        if @state == :initializing
          @state = :running
          flush unless @mode == :offline
          @mode = :online if @mode == :initializing
        end
        true
      end

      # Is agent currently offline?
      #
      # === Return
      # (Boolean):: true if agent offline, otherwise false
      def offline?
        @mode == :offline || @state == :created
      end

      # In request queueing mode?
      #
      # === Return
      # (Boolean):: true if should queue request, otherwise false
      def queueing?
        offline? && @state != :flushing
      end

      # Switch to offline mode
      # In this mode requests are queued in memory rather than sent to the mapper
      # Idempotent
      #
      # === Return
      # true:: Always return true
      def enable
        if offline?
          if @state == :flushing
            # If we were in offline mode then switched back to online but are still in the
            # process of flushing the in-memory queue and are now switching to offline mode
            # again then stop the flushing
            @state = :running
          end
        else
          Log.info("[offline] Disconnect from broker detected, entering offline mode")
          Log.info("[offline] Messages will be queued in memory until connection to broker is re-established")
          @offline_stats.update
          @queue ||= []  # ensure queue is valid without losing any messages when going offline
          @mode = :offline
          start_timer
        end
        true
      end

      # Switch back to sending requests to mapper after in-memory queue gets flushed
      # Idempotent
      #
      # === Return
      # true:: Always return true
      def disable
        if offline? && @state != :created
          Log.info("[offline] Connection to broker re-established")
          @offline_stats.finish
          cancel_timer
          @state = :flushing
          # Wait a bit to avoid flooding the mapper
          EM.add_timer(rand(MAX_QUEUE_FLUSH_DELAY)) { flush }
        end
        true
      end

      # Queue given request in memory
      #
      # === Parameters
      # request(Hash):: Request to be stored
      #
      # === Return
      # true:: Always return true
      def queue_request(kind, type, payload, target, callback)
        request = {:kind => kind, :type => type, :payload => payload, :target => target, :callback => callback}
        Log.info("[offline] Queuing request: #{request.inspect}")
        vote_to_restart if (@restart_vote_count += 1) >= MAX_QUEUED_REQUESTS
        if @state == :initializing
          # We are in the initialization callback, requests should be put at the head of the queue
          @queue.unshift(request)
        else
          @queue << request
        end
        true
      end

      # Prepare for agent termination
      #
      # === Return
      # true:: Always return true
      def terminate
        @state = :terminating
        cancel_timer
        true
      end

      protected

      # Send any requests that were queued while in offline mode
      # Do this asynchronously to allow for agents to respond to requests
      # Once all in-memory requests have been flushed, switch off offline mode
      #
      # === Return
      # true:: Always return true
      def flush
        if @state == :flushing
          Log.info("[offline] Starting to flush request queue of size #{@queue.size}") unless @mode == :initializing
          unless @queue.empty?
            r = @queue.shift
            if r[:callback]
              Sender.instance.__send__(r[:kind], r[:type], r[:payload], r[:target]) { |result| r[:callback].call(result) }
            else
              Sender.instance.__send__(r[:kind], r[:type], r[:payload], r[:target])
            end
          end
          if @queue.empty?
            Log.info("[offline] Request queue flushed, resuming normal operations") unless @mode == :initializing
            @mode = :online
            @state = :running
          else
            EM.next_tick { flush }
          end
        end
        true
      end

      # Vote for restart and reset trigger
      #
      # === Parameters
      # timer_trigger(Boolean):: true if vote was triggered by timer, false if it
      #   was triggered by number of messages in in-memory queue
      #
      # === Return
      # true:: Always return true
      def vote_to_restart(timer_trigger = false)
        if @restart_vote
          @restart_vote.call
          if timer_trigger
            start_timer
          else
            @restart_vote_count = 0
          end
        end
        true
      end

      # Start restart vote timer
      #
      # === Return
      # true:: Always return true
      def start_timer
        if @restart_vote && @state != :terminating
          @restart_vote_timer ||= EM::Timer.new(RESTART_VOTE_DELAY) { vote_to_restart(timer_trigger = true) }
        end
        true
      end

      # Cancel restart vote timer
      #
      # === Return
      # true:: Always return true
      def cancel_timer
        if @restart_vote_timer
          @restart_vote_timer.cancel
          @restart_vote_timer = nil
          @restart_vote_count = 0
        end
        true
      end

    end # OfflineHandler

    # Broker connectivity checker
    # Checks connectivity when requested
    class ConnectivityChecker

      # Minimum number of seconds between restarts of the inactivity timer
      MIN_RESTART_INACTIVITY_TIMER_INTERVAL = 60

      # Number of seconds to wait for ping response from a mapper when checking connectivity
      PING_TIMEOUT = 30

      # (EM::Timer) Timer while waiting for mapper ping response
      attr_accessor :ping_timer

      def initialize(sender, check_interval, ping_stats, exception_stats)
        @sender = sender
        @check_interval = check_interval
        @ping_timer = nil
        @ping_stats = ping_stats
        @exception_stats = exception_stats
        @last_received = Time.now
        @message_received_callbacks = []
        restart_inactivity_timer if @check_interval > 0
      end

      # Update the time this agent last received a request or response message
      # and restart the inactivity timer thus deferring the next connectivity check
      # Also forward this message receipt notification to any callbacks that have registered
      #
      # === Block
      # Optional block without parameters that is activated when a message is received
      #
      # === Return
      # true:: Always return true
      def message_received(&callback)
        if block_given?
          @message_received_callbacks << callback
        else
          @message_received_callbacks.each { |c| c.call }
          if @check_interval > 0
            now = Time.now
            if (now - @last_received) > MIN_RESTART_INACTIVITY_TIMER_INTERVAL
              @last_received = now
              restart_inactivity_timer
            end
          end
        end
        true
      end

      # Check whether broker connection is usable by pinging a mapper via that broker
      # Attempt to reconnect if ping does not respond in PING_TIMEOUT seconds
      # Ignore request if already checking a connection
      # Only to be called from primary thread
      #
      # === Parameters
      # id(String):: Identity of specific broker to use to send ping, defaults to any
      #   currently connected broker
      #
      # === Return
      # true:: Always return true
      def check(id = nil)
        unless @terminating || @ping_timer || (id && !@sender.broker.connected?(id))
          @ping_timer = EM::Timer.new(PING_TIMEOUT) do
            begin
              @ping_stats.update("timeout")
              @ping_timer = nil
              Log.warning("Mapper ping via broker #{id} timed out after #{PING_TIMEOUT} seconds, attempting to reconnect")
              host, port, index, priority, _ = @sender.broker.identity_parts(id)
              @sender.agent.connect(host, port, index, priority, force = true)
            rescue Exception => e
              Log.error("Failed to reconnect to broker #{id}", e, :trace)
              @exception_stats.track("ping timeout", e)
            end
          end

          handler = lambda do |_|
            begin
              if @ping_timer
                @ping_stats.update("success")
                @ping_timer.cancel
                @ping_timer = nil
              end
            rescue Exception => e
              Log.error("Failed to cancel mapper ping", e, :trace)
              @exception_stats.track("cancel ping", e)
            end
          end
          request = Request.new("/mapper/ping", nil, {:from => @sender.identity, :token => AgentIdentity.generate})
          @sender.pending_requests[request.token] = PendingRequest.new(:send_persistent_request, Time.now, handler)
          ids = [id] if id
          id = @sender.publish(request, ids).first
        end
        true
      end

      # Prepare for agent termination
      #
      # === Return
      # true:: Always return true
      def terminate
        @terminating = true
        @check_interval = 0
        if @ping_timer
          @ping_timer.cancel
          @ping_timer = nil
        end
        if @inactivity_timer
          @inactivity_timer.cancel
          @inactivity_timer = nil
        end
        true
      end

      protected

      # Start timer that waits for inactive messaging period to end before checking connectivity
      #
      # === Return
      # true:: Always return true
      def restart_inactivity_timer
        @inactivity_timer.cancel if @inactivity_timer
        @inactivity_timer = EM::Timer.new(@check_interval) do
          begin
            check
          rescue Exception => e
            Log.error("Failed connectivity check", e, :trace)
            @exception_stats.track("check connectivity", e)
          end
        end
        true
      end

    end # ConnectivityChecker

    # Factor used on each retry iteration to achieve exponential backoff
    RETRY_BACKOFF_FACTOR = 4

    # (PendingRequests) Requests waiting for a response
    attr_accessor :pending_requests

    # (OfflineHandler) Handler for requests when disconnected from broker
    attr_reader :offline_handler

    # (ConnectivityChecker) Broker connection checker
    attr_reader :connectivity_checker

    # (HABrokerClient) High availability AMQP broker client
    attr_accessor :broker

    # (String) Identity of the associated agent
    attr_reader :identity

    # (Agent) Associated agent
    attr_reader :agent

    # Accessor for use by actor
    #
    # === Return
    # (Sender):: This sender instance if defined, otherwise nil
    def self.instance
      @@instance if defined?(@@instance)
    end

    # Initialize sender
    #
    # === Parameters
    # agent(Agent):: Agent using this sender; uses its identity, broker, and following options:
    #   :exception_callback(Proc):: Callback with following parameters that is activated on exception events:
    #     exception(Exception):: Exception
    #     message(Packet):: Message being processed
    #     agent(Agent):: Reference to agent
    #   :offline_queueing(Boolean):: Whether to queue request if currently not connected to any brokers,
    #     also requires agent invocation of initialize_offline_queue and start_offline_queue methods below
    #   :ping_interval(Integer):: Minimum number of seconds since last message receipt to ping the mapper
    #     to check connectivity, defaults to 0 meaning do not ping
    #   :restart_callback(Proc):: Callback that is activated on each restart vote with votes being initiated
    #     by offline queue exceeding MAX_QUEUED_REQUESTS or by repeated failures to access mapper when online
    #   :retry_timeout(Numeric):: Maximum number of seconds to retry request before give up
    #   :retry_interval(Numeric):: Number of seconds before initial request retry, increases exponentially
    #   :time_to_live(Integer):: Number of seconds before a request expires and is to be ignored
    #     by the receiver, 0 means never expire
    #   :secure(Boolean):: true indicates to use Security features of rabbitmq to restrict agents to themselves
    #   :single_threaded(Boolean):: true indicates to run all operations in one thread; false indicates
    #     to do requested work on EM defer thread and all else, such as pings on main thread
    def initialize(agent)
      @agent = agent
      @identity = @agent.identity
      @options = @agent.options || {}
      @broker = @agent.broker
      @secure = @options[:secure]
      @single_threaded = @options[:single_threaded]
      @retry_timeout = nil_if_zero(@options[:retry_timeout])
      @retry_interval = nil_if_zero(@options[:retry_interval])

      # Only to be accessed from primary thread
      @pending_requests = PendingRequests.new

      reset_stats
      @offline_handler = OfflineHandler.new(@options[:restart_callback], @offline_stats)
      @connectivity_checker = ConnectivityChecker.new(self, @options[:ping_interval] || 0, @ping_stats, @exception_stats)
      @@instance = self
    end

    # Initialize the offline queue
    # All requests sent prior to running this initialization are queued if offline
    # queueing is enabled and then are sent once this initialization has run
    # All requests following this call and prior to calling start_offline_queue
    # are prepended to the request queue
    #
    # === Return
    # true:: Always return true
    def initialize_offline_queue
      @offline_handler.init if @options[:offline_queueing]
    end

    # Switch offline queueing to online mode and flush all buffered messages
    #
    # === Return
    # true:: Always return true
    def start_offline_queue
      @offline_handler.start if @options[:offline_queueing]
    end

    # Switch to offline mode
    # In this mode requests are queued in memory rather than sent to the mapper
    # Idempotent
    #
    # === Return
    # true:: Always return true
    def enable_offline_mode
      @offline_handler.enable if @options[:offline_queueing]
    end

    # Switch back to sending requests to mapper after in memory queue gets flushed
    # Idempotent
    #
    # === Return
    # true:: Always return true
    def disable_offline_mode
      @offline_handler.disable if @options[:offline_queueing]
    end

    # Update the time this agent last received a request or response message
    # Also forward this message receipt notification to any callbacks that have registered
    #
    # === Block
    # Optional block without parameters that is activated when a message is received
    #
    # === Return
    # true:: Always return true
    def message_received(&callback)
      @connectivity_checker.message_received(&callback)
    end

    # Send a request to a single target or multiple targets with no response expected other
    # than routing failures
    # Do not persist the request en route
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request
    # Set time-to-live to be forever
    #
    # === Parameters
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(String|Hash):: Identity of specific target, hash for selecting potentially multiple
    #   targets, or nil if routing solely using type
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :deployment(Integer):: Restrict to agents with this deployment id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector(Symbol):: Which of the matched targets to be selected, either :any or :all,
    #     defaults to :any
    #
    # === Block
    # Optional block used to process routing responses asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     with an initial SUCCESS response containing the targets to which the mapper published the
    #     request and any additional responses indicating any failures to actually route the request
    #     to those targets, use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    def send_push(type, payload = nil, target = nil, &callback)
      build_push(:send_push, type, payload, target, &callback)
    end

    # Send a request to a single target or multiple targets with no response expected other
    # than routing failures
    # Persist the request en route to reduce the chance of it being lost at the expense of some
    # additional network overhead
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request
    # Set time-to-live to be forever
    #
    # === Parameters
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(String|Hash):: Identity of specific target, hash for selecting potentially multiple
    #   targets, or nil if routing solely using type
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :deployment(Integer):: Restrict to agents with this deployment id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector(Symbol):: Which of the matched targets to be selected, either :any or :all,
    #     defaults to :any
    #
    # === Block
    # Optional block used to process routing responses asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     with an initial SUCCESS response containing the targets to which the mapper published the
    #     request and any additional responses indicating any failures to actually route the request
    #     to those targets, use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    def send_persistent_push(type, payload = nil, target = nil, &callback)
      build_push(:send_persistent_push, type, payload, target, &callback)
    end

    # Send a request to a single target with a response expected
    # Automatically retry the request if a response is not received in a reasonable amount of time
    # or if there is a non-delivery response indicating the target is not currently available
    # Timeout the request if a response is not received in time, typically configured to 2 minutes
    # Because of retries there is the possibility of duplicated requests, and these are detected and
    # discarded automatically unless the receiving agent is using a shared queue, in which case this
    # method should not be used for actions that are non-idempotent
    # Allow the request to expire per the agent's configured time-to-live, typically 1 minute
    # Note that receiving a response does not guarantee that the request activity has actually
    # completed since the request processing may involve other asynchronous requests
    #
    # === Parameters
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(String|Hash):: Identity of specific target, hash for selecting targets of which one is picked
    #   randomly, or nil if routing solely using type
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :deployment(Integer):: Restrict to agents with this deployment id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #
    # === Block
    # Required block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    def send_retryable_request(type, payload = nil, target = nil, &callback)
      build_request(:send_retryable_request, type, payload, target, &callback)
    end

    # Send a request to a single target with a response expected
    # Persist the request en route to reduce the chance of it being lost at the expense of some
    # additional network overhead
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request if there is the possibility of the request being duplicated
    # Set time-to-live to be forever
    # Note that receiving a response does not guarantee that the request activity has actually
    # completed since the request processing may involve other asynchronous requests
    #
    # === Parameters
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(String|Hash):: Identity of specific target, hash for selecting targets of which one is picked
    #   randomly, or nil if routing solely using type
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :deployment(Integer):: Restrict to agents with this deployment id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #
    # === Block
    # Required block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    def send_persistent_request(type, payload = nil, target = nil, &callback)
      build_request(:send_persistent_request, type, payload, target, &callback)
    end

    # Handle response to a request
    # Only to be called from primary thread
    #
    # === Parameters
    # response(Result):: Packet received as result of request
    #
    # === Return
    # true:: Always return true
    def handle_response(response)
      token = response.token
      if response.is_a?(Result)
        if result = OperationResult.from_results(response)
          if result.non_delivery?
            @non_delivery_stats.update(result.content.nil? ? "nil" : result.content.inspect)
          elsif result.error?
            @result_error_stats.update(result.content.nil? ? "nil" : result.content.inspect)
          end
          @result_stats.update(result.status)
        else
          @result_stats.update(response.results.nil? ? "nil" : response.results)
        end

        if handler = @pending_requests[token]
          if result && result.non_delivery? && handler.kind == :send_retryable_request &&
             [OperationResult::TARGET_NOT_CONNECTED, OperationResult::TTL_EXPIRATION].include?(result.content)
            # Log and ignore so that timeout retry mechanism continues
            # Leave purging of associated request until final response, i.e., success response or retry timeout
            Log.info("Non-delivery of <#{token}> because #{result.content}")
          else
            deliver(response, handler)
          end
        elsif result && result.non_delivery?
          Log.info("Non-delivery of <#{token}> because #{result.content}")
        else
          Log.debug("No pending request for response #{response.to_s([])}")
        end
      end
      true
    end

    # Publish request
    # Use mandatory flag to request return of message if it cannot be delivered
    #
    # === Parameters
    # request(Push|Request):: Packet to be sent
    # ids(Array|nil):: Identity of specific brokers to choose from, or nil if any okay
    #
    # === Return
    # ids(Array):: Identity of brokers published to
    def publish(request, ids = nil)
      begin
        exchange = {:type => :fanout, :name => "request", :options => {:durable => true, :no_declare => @secure}}
        ids = @broker.publish(exchange, request, :persistent => request.persistent, :mandatory => true,
                              :log_filter => [:tags, :target, :tries, :persistent], :brokers => ids)
      rescue HABrokerClient::NoConnectedBrokers => e
        Log.error("Failed to publish request #{request.to_s([:tags, :target, :tries])}", e)
        ids = []
      rescue Exception => e
        Log.error("Failed to publish request #{request.to_s([:tags, :target, :tries])}", e, :trace)
        @exception_stats.track("publish", e, request)
        ids = []
      end
      ids
    end

    # Take any actions necessary to quiesce mapper interaction in preparation
    # for agent termination but allow message receipt to continue
    #
    # === Return
    # (Array):: Number of pending non-push requests and age of youngest request
    def terminate
      @offline_handler.terminate
      @connectivity_checker.terminate
      pending = @pending_requests.kind(PendingRequests::REQUEST_KINDS)
      [pending.size, pending.youngest_age]
    end

    # Create displayable dump of unfinished non-push request information
    # Truncate list if there are more than 50 requests
    #
    # === Return
    # info(Array(String)):: Receive time and token for each request in descending time order
    def dump_requests
      info = []
      @pending_requests.kind(PendingRequests::REQUEST_KINDS).each do |token, request|
        info << "#{request.receive_time.localtime} <#{token}>"
      end
      info.sort.reverse
      info = info[0..49] + ["..."] if info.size > 50
      info
    end

    # Get sender statistics
    #
    # === Parameters
    # reset(Boolean):: Whether to reset the statistics after getting the current ones
    #
    # === Return
    # stats(Hash):: Current statistics:
    #   "exceptions"(Hash|nil):: Exceptions raised per category, or nil if none
    #     "total"(Integer):: Total exceptions for this category
    #     "recent"(Array):: Most recent as a hash of "count", "type", "message", "when", and "where"
    #   "non-deliveries"(Hash|nil):: Non-delivery activity stats with keys "total", "percent", "last",
    #     and 'rate' with percentage breakdown per reason, or nil if none
    #   "offlines"(Hash|nil):: Offline activity stats with keys "total", "last", and "duration",
    #     or nil if none
    #   "pings"(Hash|nil):: Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown for "success" vs. "timeout", or nil if none
    #   "request kinds"(Hash|nil):: Request kind activity stats with keys "total", "percent", and "last"
    #     with percentage breakdown per kind, or nil if none
    #   "requests"(Hash|nil):: Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    #   "requests pending"(Hash|nil):: Number of requests waiting for response and age of oldest,
    #     or nil if none
    #   "response time"(Float):: Average number of seconds to respond to a request recently
    #   "result errors"(Hash|nil):: Error result activity stats with keys "total", "percent", "last",
    #     and 'rate' with percentage breakdown per error, or nil if none
    #   "results"(Hash|nil):: Results activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per operation result type, or nil if none
    #   "retries"(Hash|nil):: Retry activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    def stats(reset = false)
      offlines = @offline_stats.all
      offlines.merge!("duration" => @offline_stats.avg_duration) if offlines
      if @pending_requests.size > 0
        pending = {}
        pending["pushes"] = @pending_requests.kind(PendingRequests::PUSH_KINDS).size
        requests = @pending_requests.kind(PendingRequests::REQUEST_KINDS)
        if (pending["requests"] = requests.size) > 0
          pending["oldest age"] = requests.oldest_age
        end
      end
      stats = {
        "exceptions"       => @exception_stats.stats,
        "non-deliveries"   => @non_delivery_stats.all,
        "offlines"         => offlines,
        "pings"            => @ping_stats.all,
        "request kinds"    => @request_kinds.all,
        "requests"         => @request_stats.all,
        "requests pending" => pending,
        "response time"    => @request_stats.avg_duration,
        "result errors"    => @result_error_stats.all,
        "results"          => @result_stats.all,
        "retries"          => @retry_stats.all
      }
      reset_stats if reset
      stats
    end

    protected

    # Reset dispatch statistics
    #
    # === Return
    # true:: Always return true
    def reset_stats
      @ping_stats = ActivityStats.new
      @retry_stats = ActivityStats.new
      @request_stats = ActivityStats.new
      @result_stats = ActivityStats.new
      @result_error_stats = ActivityStats.new
      @non_delivery_stats = ActivityStats.new
      @offline_stats = ActivityStats.new(measure_rate = false)
      @request_kinds = ActivityStats.new(measure_rate = false)
      @exception_stats = ExceptionStats.new(@agent, @options[:exception_callback])
      true
    end

    # Build and send Push packet
    #
    # === Parameters
    # kind(Symbol):: Kind of push: :send_push or :send_persistent_push
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(String|Hash):: Identity of specific target, or hash for selecting potentially multiple
    #   targets, or nil if routing solely using type
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :deployment(Integer):: Restrict to agents with this deployment id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector(Symbol):: Which of the matched targets to be selected, either :any or :all,
    #     defaults to :any
    #
    # === Block
    # Optional block used to process routing responses asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     with an initial SUCCESS response containing the targets to which the mapper published the
    #     request and any additional responses indicating any failures to actually route the request
    #     to those targets, use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target is invalid
    def build_push(kind, type, payload = nil, target = nil, &callback)
      validate_target(target, allow_selector = true)
      if should_queue?
        @offline_handler.queue_request(kind, type, payload, target, callback)
      else
        method = type.split('/').last
        received_at = @request_stats.update(method)
        push = Push.new(type, payload)
        push.from = @identity
        push.token = AgentIdentity.generate
        if target.is_a?(Hash)
          push.tags = target[:tags] || []
          push.scope = target[:scope]
          push.selector = target[:selector] || :any
        else
          push.target = target
        end
        push.persistent = kind == :send_persistent_push
        @request_kinds.update((push.selector == :all ? kind.to_s.sub(/push/, "fanout") : kind.to_s)[5..-1])
        if callback
          push.confirm = true
          @pending_requests[push.token] = PendingRequest.new(kind, received_at, callback)
        end
        publish(push)
      end
      true
    end

    # Build and send Request packet
    #
    # === Parameters
    # kind(Symbol):: Kind of request: :send_retryable_request or :send_persistent_request
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(String|Hash):: Identity of specific target, or hash for selecting targets of which one is picked
    #   randomly, or nil if routing solely using type
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :deployment(Integer):: Restrict to agents with this deployment id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #
    # === Block
    # Required block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target is invalid
    def build_request(kind, type, payload, target, &callback)
      validate_target(target, allow_selector = false)
      if should_queue?
        @offline_handler.queue_request(kind, type, payload, target, callback)
      else
        method = type.split('/').last
        token = AgentIdentity.generate
        non_duplicate = kind == :send_persistent_request
        received_at = @request_stats.update(method, token)
        @request_kinds.update(kind.to_s[5..-1])

        # Using next_tick to ensure on primary thread since using @pending_requests
        EM.next_tick do
          begin
            request = Request.new(type, payload)
            request.from = @identity
            request.token = token
            if target.is_a?(Hash)
              request.tags = target[:tags] || []
              request.scope = target[:scope]
              request.selector = :any
            else
              request.target = target
            end
            request.expires_at = Time.now.to_i + @options[:time_to_live] if !non_duplicate && @options[:time_to_live] && @options[:time_to_live] != 0
            request.persistent = non_duplicate
            @pending_requests[token] = PendingRequest.new(kind, received_at, callback)
            if non_duplicate
              publish(request)
            else
              publish_with_timeout_retry(request, token)
            end
          rescue Exception => e
            Log.error("Failed to send #{type} #{kind.to_s}", e, :trace)
            @exception_stats.track(kind.to_s, e, request)
          end
        end
      end
      true
    end

    # Validate target argument of send
    #
    # === Parameters
    # target(String|Hash):: Identity of specific target, or hash for selecting targets of which one is picked
    # allow_selector(Boolean):: Whether to allow :selector
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target is invalid
    def validate_target(target, allow_selector)
      if target.is_a?(Hash)
        selector = allow_selector ? ":selector, " : ""
        t = SerializationHelper.symbolize_keys(target)
        if s = target[:scope]
          if s.is_a?(Hash)
            s = SerializationHelper.symbolize_keys(s)
            if ([:account, :deployment, :shard] & s.keys).empty? && !s.empty?
              raise ArgumentError, "Invalid target scope (#{t[:scope].inspect}), choices are :account, :deployment, and :shard allowed"
            end
            t[:scope] = s
          else
            raise ArgumentError, "Invalid target scope (#{t[:scope].inspect}), must be a hash of :account, :deployment, and/or :shard"
          end
        elsif (s = t[:selector]) && allow_selector
          s = s.to_sym
          unless [:any, :all].include?(s)
            raise ArgumentError, "Invalid target selector (#{t[:selector].inspect}), choices are :any and :all"
          end
          t[:selector] = s
        elsif !t.has_key?(:tags) && !t.empty?
          raise ArgumentError, "Invalid target hash (#{target.inspect}), choices are #{selector}:tags and/or :scope"
        end
        target = t
      elsif !target.nil? && !target.is_a?(String)
        raise ArgumentError, "Invalid target (#{target.inspect}), choices are specific target name or a hash of #{selector}:tags and/or :scope"
      end
      true
    end

    # Publish request with one or more retries if do not receive a response in time
    # Send timeout result if reach configured retry timeout limit
    # Use exponential backoff with RETRY_BACKOFF_FACTOR for retry spacing
    # Adjust retry interval by average response time to avoid adding to system load
    # when system gets slow
    #
    # === Parameters
    # request(Request):: Request to be sent
    # parent(String):: Token for original request
    # count(Integer):: Number of retries so far
    # multiplier(Integer):: Multiplier for retry interval for exponential backoff
    # elapsed(Integer):: Elapsed time in seconds since this request was first attempted
    #
    # === Return
    # true:: Always return true
    def publish_with_timeout_retry(request, parent, count = 0, multiplier = 1, elapsed = 0)
      ids = publish(request)

      if @retry_interval && @retry_timeout && parent && !ids.empty?
        interval = [(@retry_interval * multiplier) + (@request_stats.avg_duration || 0), @retry_timeout - elapsed].min
        EM.add_timer(interval) do
          begin
            if handler = @pending_requests[parent]
              count += 1
              elapsed += interval
              if elapsed < @retry_timeout
                request.tries << request.token
                request.token = AgentIdentity.generate
                @pending_requests[parent].retry_parent = parent if count == 1
                @pending_requests[request.token] = @pending_requests[parent]
                publish_with_timeout_retry(request, parent, count, multiplier * RETRY_BACKOFF_FACTOR, elapsed)
                @retry_stats.update(request.type.split('/').last)
              else
                Log.warning("RE-SEND TIMEOUT after #{elapsed.to_i} seconds for #{request.to_s([:tags, :target, :tries])}")
                result = OperationResult.non_delivery(OperationResult::RETRY_TIMEOUT)
                @non_delivery_stats.update(result.content)
                handle_response(Result.new(request.token, request.reply_to, result, @identity))
              end
              @connectivity_checker.check(ids.first) if count == 1
            end
          rescue Exception => e
            Log.error("Failed retry for #{request.token}", e, :trace)
            @exception_stats.track("retry", e, request)
          end
        end
      end
      true
    end

    # Deliver the response and remove associated request(s) from pending
    # Use defer thread instead of primary if not single threaded, consistent with dispatcher,
    # so that all shared data is accessed from the same thread
    # Do callback if there is an exception, consistent with agent identity queue handling
    # Only to be called from primary thread
    #
    # === Parameters
    # response(Result):: Packet received as result of request
    # handler(Hash):: Associated request handler
    #
    # === Return
    # true:: Always return true
    def deliver(response, handler)
      @request_stats.finish(handler.receive_time, response.token)

      @pending_requests.delete(response.token) if PendingRequests::REQUEST_KINDS.include?(handler.kind)
      if parent = handler.retry_parent
        @pending_requests.reject! { |k, v| k == parent || v.retry_parent == parent }
      end

      if handler.response_handler
        EM.__send__(@single_threaded ? :next_tick : :defer) do
          begin
            handler.response_handler.call(response)
          rescue Exception => e
            Log.error("Failed processing response #{response.to_s([])}", e, :trace)
            @exception_stats.track("response", e, response)
          end
        end
      end
      true
    end

    # Should agent be queueing current request?
    #
    # === Return
    # (Boolean):: true if should queue request, otherwise false
    def should_queue?
      @options[:offline_queueing] && @offline_handler.queueing?
    end

  end # Sender

end # RightScale
