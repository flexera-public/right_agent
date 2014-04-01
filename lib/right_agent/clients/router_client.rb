#--
# Copyright (c) 2013 RightScale Inc
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
#++

require 'faye/websocket'

# Monkey patch WebSocket close method so that can specify status code and reason
# Valid status codes are defined in RFC6455 section 7.4.1
module Faye
  class WebSocket
    module API
      def close(code = nil, reason = nil)
        @ready_state = CLOSING if @ready_state == OPEN
        @driver.close(reason, code)
      end
    end
  end
end

module RightScale

  # HTTP interface to RightNet router
  class RouterClient < BaseRetryClient

    # RightNet router API version for use in X-API-Version header
    API_VERSION = "2.0"

    # Initial interval between attempts to make a WebSocket connection
    CONNECT_INTERVAL = 30

    # Maximum interval between attempts to make a WebSocket connection
    MAX_CONNECT_INTERVAL = 60 * 60 * 24

    # Initial interval between attempts to reconnect or long-poll when router is not responding
    RECONNECT_INTERVAL = 2

    # Maximum interval between attempts to reconnect or long-poll when router is not responding
    MAX_RECONNECT_INTERVAL = 60

    # Interval between checks for lost WebSocket connection
    CHECK_INTERVAL = 5

    # Backoff factor for connect and reconnect intervals
    BACKOFF_FACTOR = 2

    # WebSocket close status codes
    NORMAL_CLOSE = 1000
    SHUTDOWN_CLOSE = 1001
    PROTOCOL_ERROR_CLOSE = 1002
    UNEXPECTED_ERROR_CLOSE = 1011

    # Default time to wait for an event or to ping WebSocket
    DEFAULT_LISTEN_TIMEOUT = 60

    # Maximum repeated listen failures at which point give up listening
    MAX_LISTEN_FAILURES = 10

    # Create RightNet router client
    #
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :listen_timeout maximum wait for event; defaults to DEFAULT_LISTEN_TIMEOUT
    # @option options [Boolean] :long_polling_only never attempt to create a WebSocket, always long-polling instead
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Numeric] :reconnect_interval for reconnect attempts after lose connectivity
    # @option options [Boolean] :non_blocking i/o is to be used for HTTP requests by applying
    #   EM::HttpRequest and fibers instead of RestClient; requests remain synchronous
    # @option options [Proc] :exception_callback for unexpected exceptions
    #
    # @raise [ArgumentError] auth client does not support this client type
    def initialize(auth_client, options)
      init(:router, auth_client, options.merge(:server_name => "RightNet", :api_version => API_VERSION))
      @options[:listen_timeout] ||= DEFAULT_LISTEN_TIMEOUT
    end

    # Route a request to a single target or multiple targets with no response expected
    # Persist the request en route to reduce the chance of it being lost at the expense of some
    # additional network overhead
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request if there is the possibility of it being duplicated
    # Set time-to-live to be forever
    #
    # @param [String] type of request as path specifying actor and action
    # @param [Hash, NilClass] payload for request
    # @param [Hash, NilClass] target for request, which may be a specific agent (using :agent_id),
    #   potentially multiple targets (using :tags, :scope, :selector), or nil to route solely
    #   using type:
    #   [String] :agent_id serialized identity of specific target
    #   [Array] :tags that must all be associated with a target for it to be selected
    #   [Hash] :scope for restricting routing which may contain:
    #     [Integer] :account id that agents must be associated with to be included
    #     [Integer] :shard id that agents must be in to be included, or if value is
    #       Packet::GLOBAL, ones with no shard id
    #   [Symbol] :selector for picking from qualified targets: :any or :all;
    #     defaults to :any
    # @param [String, NilClass] token uniquely identifying this request;
    #   defaults to randomly generated ID
    #
    # @return [NilClass] always nil since there is no expected response to the request
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def push(type, payload, target, token = nil)
      params = {
        :type => type,
        :payload => payload,
        :target => target }
      make_request(:post, "/push", params, type.split("/")[2], token)
    end

    # Route a request to a single target with a response expected
    # Automatically retry the request if a response is not received in a reasonable amount of time
    # or if there is a non-delivery response indicating the target is not currently available
    # Timeout the request if a response is not received in time, typically configured to 30 sec
    # Because of retries there is the possibility of duplicated requests, and these are detected and
    # discarded automatically for non-idempotent actions
    # Allow the request to expire per the agent's configured time-to-live, typically 1 minute
    #
    # @param [String] type of request as path specifying actor and action
    # @param [Hash, NilClass] payload for request
    # @param [Hash, NilClass] target for request, which may be a specific agent (using :agent_id),
    #   one chosen randomly from potentially multiple targets (using :tags, :scope), or nil to
    #   route solely using type:
    #   [String] :agent_id serialized identity of specific target
    #   [Array] :tags that must all be associated with a target for it to be selected
    #   [Hash] :scope for restricting routing which may contain:
    #     [Integer] :account id that agents must be associated with to be included
    # @param [String, NilClass] token uniquely identifying this request;
    #   defaults to randomly generated ID
    #
    # @return [Result, NilClass] response from request
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def request(type, payload, target, token = nil)
      params = {
        :type => type,
        :payload => payload,
        :target => target }
      make_request(:post, "/request", params, type.split("/")[2], token)
    end

    # Route event
    # Use WebSocket if possible
    # Do not block this request even if in the process of closing since used for request responses
    #
    # @param [Hash] event to send
    # @param [Array, NilClass] routing_keys as strings to assist router in delivering
    #   event to interested parties
    #
    # @return [TrueClass] always true
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def notify(event, routing_keys)
      event[:uuid] ||= RightSupport::Data::UUID.generate
      event[:version] ||= AgentConfig.protocol_version
      params = {:event => event}
      params[:routing_keys] = routing_keys if routing_keys
      if @websocket
        path = event[:path] ? " #{event[:path]}" : ""
        to = routing_keys ? " to #{routing_keys.inspect}" : ""
        Log.info("Sending EVENT <#{event[:uuid]}> #{event[:type]}#{path}#{to}")
        @websocket.send(JSON.dump(params))
      else
        make_request(:post, "/notify", params, "notify", event[:uuid], :filter_params => ["event"])
      end
      true
    end

    # Receive events via an HTTP WebSocket if available, otherwise via an HTTP long-polling
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received
    #
    # @return [TrueClass] always true, although only returns when closing
    #
    # @raise [ArgumentError] block missing
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def listen(routing_keys, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      @event_uuids = nil
      @listen_interval = 0
      @listen_state = :choose
      @listen_failures = 0
      @connect_interval = CONNECT_INTERVAL
      @reconnect_interval = RECONNECT_INTERVAL

      listen_loop(routing_keys, &handler)
      true
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @param [Symbol] scope of close action: :receive for just receive side
    #   of client, :all for both receive and send side; defaults to :all
    #
    # @return [TrueClass] always true
    def close(scope = :all)
      super
      update_listen_state(:cancel)
      @websocket.close(SHUTDOWN_CLOSE, "Agent terminating") if @websocket
    end

    # Current statistics for this client
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics
    #   [Hash, NilClass] "events" Activity stats or nil if none
    #   [Hash, NilClass] "reconnects" Activity stats or nil if none
    #   [Hash, NilClass] "request failures" Activity stats or nil if none
    #   [Hash, NilClass] "request sent" Activity stats or nil if none
    #   [Float, NilClass] "response time" average number of seconds to respond to a request or nil if none
    #   [Hash, NilClass] "exceptions" Exceptions stats or nil if none
    def stats(reset = false)
      events = @stats["events"].all
      stats = super(reset)
      stats["events"] = events
      stats
    end

    protected

    # Reset API interface statistics
    #
    # @return [TrueClass] always true
    def reset_stats
      super
      @stats["events"] = RightSupport::Stats::Activity.new
      true
    end

    # Perform listen action, then wait prescribed time for next action
    # A periodic timer is not effective here because it does not wa
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received
    #
    # @return [Boolean] false if failed or terminating, otherwise true
    def listen_loop(routing_keys, &handler)
      @listen_timer = nil

      begin
        # Perform listen action based on current state
        case @listen_state
        when :choose
          # Choose listen method or continue as is if already listening
          # or want to delay choosing
          choose_listen_method
        when :check
          # Check whether really got connected, given the possibility of an
          # asynchronous WebSocket handshake failure that resulted in a close
          # Continue to use WebSockets if still connected or if connect failed
          # due to unresponsive server
          if @websocket.nil?
            if router_not_responding?
              update_listen_state(:connect, backoff_reconnect_interval)
            else
              backoff_connect_interval
              update_listen_state(:long_poll)
            end
          elsif (@listen_checks += 1) > CHECK_INTERVAL
            @reconnect_interval = RECONNECT_INTERVAL
            update_listen_state(:choose, @connect_interval = CONNECT_INTERVAL)
          end
        when :connect
          # Use of WebSockets is enabled and it is again time to try to connect
          @stats["reconnects"].update("websocket") if @attempted_connect_at
          try_connect(routing_keys, &handler)
        when :long_poll
          # Resorting to long-polling
          # Need to long-poll on separate thread if cannot use non-blocking HTTP i/o
          # Will still periodically retry WebSockets if not restricted to just long-polling
          if @options[:non_blocking]
            @event_uuids = process_long_poll(try_long_poll(routing_keys, @event_uuids, &handler))
          else
            update_listen_state(:wait, 1)
            try_deferred_long_poll(routing_keys, @event_uuids, &handler)
          end
        when :wait
          # Deferred long-polling is expected to break out of this state eventually
        when :cancel
          return false
        end
        @listen_failures = 0
      rescue Exception => e
        Log.error("Failed to listen", e, :trace)
        @stats["exceptions"].track("listen", e)
        @listen_failures += 1
        if @listen_failures > MAX_LISTEN_FAILURES
          Log.error("Exceeded maximum repeated listen failures (#{MAX_LISTEN_FAILURES}), stopping listening")
          @listen_state = :cancel
          self.state = :failed
          return false
        end
        @listen_state = :choose
        @listen_interval = CHECK_INTERVAL
      end

      # Loop using next_tick or timer
      if @listen_interval == 0
        EM_S.next_tick { listen_loop(routing_keys, &handler) }
      else
        @listen_timer = EM_S::Timer.new(@listen_interval) { listen_loop(routing_keys, &handler) }
      end
      true
    end

    # Update listen state
    #
    # @param [Symbol] state next
    # @param [Integer] interval before next listen action
    #
    # @return [TrueClass] always true
    #
    # @raise [ArgumentError] invalid state
    def update_listen_state(state, interval = 0)
      if state == :cancel
        @listen_timer.cancel if @listen_timer
        @listen_timer = nil
        @listen_state = state
      elsif [:choose, :check, :connect, :long_poll, :wait].include?(state)
        @listen_checks = 0 if state == :check && @listen_state != :check
        @listen_state = state
        @listen_interval = interval
      else
        raise ArgumentError, "Invalid listen state: #{state.inspect}"
      end
      true
    end

    # Determine whether should retry creation of WebSocket connection now
    # Should only retry if (1) WebSocket is enabled, (2) there is none currently,
    # (3) previous closure was for acceptable reasons (normal, router shutdown,
    # router inaccessible), or (4) enough time has elapsed to make another attempt
    #
    # @return [TrueClass] always true
    def choose_listen_method
      if @options[:long_polling_only]
        update_listen_state(:long_poll)
        @connect_interval = MAX_CONNECT_INTERVAL
      elsif @websocket
        update_listen_state(:choose, @connect_interval)
      else
        if @attempted_connect_at.nil?
          interval = 0
        elsif (interval = @connect_interval - (Time.now - @attempted_connect_at)) < 0 ||
              [NORMAL_CLOSE, SHUTDOWN_CLOSE].include?(@close_code) ||
              router_not_responding?
          interval = 0
        end
        update_listen_state(:connect, interval)
      end
      true
    end

    # Try to create WebSocket connection
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received
    #
    # @return [TrueClass] always true
    def try_connect(routing_keys, &handler)
      connect(routing_keys, &handler)
      update_listen_state(:check, 1)
    rescue Exception => e
      Log.error("Failed creating WebSocket", e)
      @stats["exceptions"].track("websocket", e)
      backoff_connect_interval
      update_listen_state(:long_poll)
    end

    # Connect to RightNet router using WebSocket for receiving events
    #
    # @param [Array, NilClass] routing_keys as strings to assist router in delivering
    #   event to interested parties
    #
    # @yield [event] required block called when event received
    # @yieldparam [Object] event received
    # @yieldreturn [Hash, NilClass] event this is response to event received,
    #   or nil meaning no response
    #
    # @return [Faye::WebSocket] WebSocket created
    #
    # @raise [ArgumentError] block missing
    def connect(routing_keys, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      @attempted_connect_at = Time.now
      @close_code = @close_reason = nil

      options = {
        # Limit to .auth_header here (rather than .headers) to keep WebSockets happy
        :headers => {"X-API-Version" => API_VERSION}.merge(@auth_client.auth_header),
        :ping => @options[:listen_timeout] }
      url = URI.parse(@auth_client.router_url)
      url.scheme = url.scheme == "https" ? "wss" : "ws"
      url.path = url.path + "/connect"
      url.query = routing_keys.map { |k| "routing_keys[]=#{CGI.escape(k)}" }.join("&") if routing_keys && routing_keys.any?
      Log.info("Creating WebSocket connection to #{url.to_s}")
      @websocket = Faye::WebSocket::Client.new(url.to_s, protocols = nil, options)

      @websocket.onerror = lambda do |event|
        Log.error("WebSocket error (#{event.data})") if event.data
      end

      @websocket.onclose = lambda do |event|
        begin
          @close_code = event.code.to_i
          @close_reason = event.reason
          msg = "WebSocket closed (#{event.code}"
          msg << ((event.reason.nil? || event.reason.empty?) ? ")" : ": #{event.reason})")
          Log.info(msg)
        rescue Exception => e
          Log.error("Failed closing WebSocket", e, :trace)
          @stats["exceptions"].track("event", e)
        end
        @websocket = nil
      end

      @websocket.onmessage = lambda do |event|
        begin
          # Receive event
          event = SerializationHelper.symbolize_keys(JSON.load(event.data))
          Log.info("Received EVENT <#{event[:uuid]}> #{event[:type]} #{event[:path]} from #{event[:from]}")
          @stats["events"].update("#{event[:type]} #{event[:path]}")

          # Acknowledge event
          @websocket.send(JSON.dump({:ack => event[:uuid]}))

          # Handle event
          handler.call(event)
          @communicated_callbacks.each { |callback| callback.call } if @communicated_callbacks
        rescue Exception => e
          Log.error("Failed handling WebSocket event", e, :trace)
          @stats["exceptions"].track("event", e)
        end
      end

      @websocket
    end

    # Try to make long-polling request to receive events
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    # @param [Array, NilClass] event_uuids from previous poll
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received
    #
    # @return [Array, NilClass, Exception] UUIDs of events received, or nil if none, or Exception if failed
    def try_long_poll(routing_keys, event_uuids, &handler)
      begin
        long_poll(routing_keys, event_uuids, &handler)
      rescue Exception => e
        e
      end
    end

    # Try to make long-polling request to receive events using EM defer thread
    # Repeat long-polling until there is an error or the stop time has been reached
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    # @param [Array, NilClass] event_uuids from previous poll
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received
    #
    # @return [Array, NilClass] UUIDs of events received, or nil if none
    def try_deferred_long_poll(routing_keys, event_uuids, &handler)
      # Proc for running long-poll in EM defer thread since this is a blocking call
      @defer_operation_proc = Proc.new { try_long_poll(routing_keys, event_uuids, &handler) }

      # Proc that runs in main EM reactor thread to handle result from above operation proc
      @defer_callback_proc = Proc.new { |result| @event_uuids = process_long_poll(result) }

      # Use EM defer thread since the long-poll will block
      EM.defer(@defer_operation_proc, @defer_callback_proc)
      true
    end

    # Make long-polling request to receive one or more events
    # Do not return until an event is received or the polling times out or fails
    # Limit logging unless in debug mode
    #
    # @param [Array, NilClass] routing_keys as strings to assist router in delivering
    #   event to interested parties
    # @param [Array, NilClass] ack UUIDs for events received on previous poll
    #
    # @yield [event] required block called for each event received
    # @yieldparam [Object] event received
    #
    # @return [Array, NilClass] UUIDs of events received, or nil if none
    #
    # @raise [ArgumentError] block missing
    def long_poll(routing_keys, ack, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      params = {
        :wait_time => @options[:listen_timeout] - 5,
        :timestamp => Time.now.to_f }
      params[:routing_keys] = routing_keys if routing_keys
      params[:ack] = ack if ack && ack.any?

      options = {
        :log_level => :debug,
        :request_timeout => @connect_interval,
        :poll_timeout => @options[:listen_timeout] }

      event_uuids = []
      events = make_request(:poll, "/listen", params, "listen", nil, options)
      if events
        events.each do |event|
          event = SerializationHelper.symbolize_keys(event)
          Log.info("Received EVENT <#{event[:uuid]}> #{event[:type]} #{event[:path]} from #{event[:from]}")
          @stats["events"].update("#{event[:type]} #{event[:path]}")
          event_uuids << event[:uuid]
          handler.call(event)
        end
      end
      event_uuids if event_uuids.any?
    end

    # Process result from long-polling attempt
    #
    # @param [Array, NilClass] result from long-polling attempt
    #
    # @return [Array, NilClass] result for long-polling attempt
    def process_long_poll(result)
      case result
      when Exceptions::Unauthorized, Exceptions::ConnectivityFailure, Exceptions::RetryableError, Exceptions::InternalServerError
        Log.error("Failed long-polling", result, :no_trace)
        update_listen_state(:choose, backoff_reconnect_interval)
        result = nil
      when Exception
        Log.error("Failed long-polling", result, :trace)
        @stats["exceptions"].track("long-polling", result)
        update_listen_state(:choose, backoff_reconnect_interval)
        result = nil
      else
        @reconnect_interval = RECONNECT_INTERVAL
        @communicated_callbacks.each { |callback| callback.call } if @communicated_callbacks
        update_listen_state(:choose)
      end
      result
    end

    # Exponentially increase WebSocket connect attempt interval after failing to connect
    #
    # @return [Integer] new interval
    def backoff_connect_interval
      @connect_interval = [@connect_interval * BACKOFF_FACTOR, MAX_CONNECT_INTERVAL].min
    end

    # Exponentially increase reconnect attempt interval when router not responding
    #
    # @return [Integer] new interval
    def backoff_reconnect_interval
      @reconnect_interval = [@reconnect_interval * BACKOFF_FACTOR, MAX_RECONNECT_INTERVAL].min
    end

    # Determine whether WebSocket attempts are failing because router not responding
    #
    # @return [Boolean] true if router not responding, otherwise false
    def router_not_responding?
      @close_code == PROTOCOL_ERROR_CLOSE && @close_reason =~ /502|503/
    end

  end # RouterClient

end # RightScale
