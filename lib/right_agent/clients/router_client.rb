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

module RightScale

  # HTTP interface to RightNet router
  class RouterClient < BaseRetryClient

    # RightNet router API version for use in X-API-Version header
    API_VERSION = "2.0"

    # Initial interval between attempts to create a WebSocket
    WEBSOCKET_CONNECT_INTERVAL = 30

    # Backoff factor for WebSocket connect interval
    WEBSOCKET_BACKOFF_FACTOR = 2

    # Maximum interval between attempts to create a WebSocket
    MAX_WEBSOCKET_CONNECT_INTERVAL = 60 * 60 * 24

    # Sleep interval after long-polling error before re-polling to give RightNet chance to recover
    LONG_POLL_ERROR_DELAY = 5

    # Default time to wait for an event or to ping WebSocket
    DEFAULT_LISTEN_TIMEOUT = 60

    # Create RightNet router client
    #
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :listen_timeout maximum wait for event; defaults to DEFAULT_POLL_TIMEOUT
    # @option options [Boolean] :long_polling_only never attempt to create a WebSocket, always long-polling instead
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Numeric] :reconnect_interval for reconnect attempts after lose connectivity
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
        @websocket.send(JSON.dump(params))
      else
        make_request(:post, "/notify", params, "notify", event[:uuid], :filter_params => ["event"])
      end
      true
    end

    # Receive events via an HTTP WebSocket if available, otherwise via an HTTP long-polling
    # This is a blocking call and therefore should be used from a thread different than
    # otherwise used with this object, e.g., EM.defer thread
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received
    #
    # @return [TrueClass] always true, although normally never returns
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

      @connect_interval = WEBSOCKET_CONNECT_INTERVAL # instance variable needed for testing
      last_connect_time = Time.now - @connect_interval

      # Proc for exponentially increasing WebSocket connect attempt interval when failing
      adjust_interval = lambda do
        last_connect_time = Time.now
        @connect_interval = [@connect_interval * WEBSOCKET_BACKOFF_FACTOR, MAX_WEBSOCKET_CONNECT_INTERVAL].min
      end

      until state == :closing do
        # Attempt to create a WebSocket if enabled and enough time has elapsed since last attempt
        # or if WebSocket connection has been lost
        unless @options[:long_polling_only]
          if @websocket.nil? && (Time.now - last_connect_time) > @connect_interval
            begin
              @stats["reconnects"].update("websocket") unless @websocket
              @websocket = create_websocket(routing_keys, &handler)
              [1, 1, 1, 1, 1, @options[:listen_timeout] - 5].each do |t|
                # Allow for possibility of asynchronous handshake failure resulting in close
                if @websocket.nil?
                  adjust_interval.call
                  break
                end
                sleep(t)
              end
            rescue Exception => e
              Log.error("Failed creating WebSocket", e)
              @stats["exceptions"].track("websocket", e)
              adjust_interval.call
            end
          elsif @websocket
            @connect_interval = WEBSOCKET_CONNECT_INTERVAL
            sleep(@options[:listen_timeout])
          end
        end

        # Resort to long-polling if a WebSocket cannot be created
        if @websocket.nil?
          begin
            long_poll(routing_keys, &handler)
          rescue Exceptions::Unauthorized, Exceptions::ConnectivityFailure, Exceptions::RetryableError => e
            Log.error("Failed long-polling", e, :no_trace)
            sleep(LONG_POLL_ERROR_DELAY)
          rescue Exception => e
            Log.error("Failed long-polling", e, :trace)
            @stats["exceptions"].track("long-polling", e)
            sleep(LONG_POLL_ERROR_DELAY)
          end
        end
      end
      true
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @return [TrueClass] always true
    def close
      super
      @websocket.close if @websocket
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

    # Connect to RightNet router using WebSocket for receiving events
    #
    # @param [Array, NilClass] routing_keys as strings to assist router in delivering
    #   event to interested parties
    #
    # @yield [event] required block called when event received
    # @yieldparam [Object] event received
    #
    # @return [Faye::WebSocket] WebSocket created
    #
    # @raise [ArgumentError] block missing
    def create_websocket(routing_keys, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      # TODO figure out how to send routing_keys as parameter to connect
      options = {
        :headers => {"X-API-Version" => API_VERSION}.merge(@auth_client.auth_header),
        :ping => @options[:listen_timeout] }
      uri = @auth_client.router_url + "/connect"
      Log.info("Creating WebSocket connection to #{uri}")
      @websocket = Faye::WebSocket::Client.new(uri, protocols = nil, options)

      @websocket.onerror = lambda do |event|
        Log.error("WebSocket error (#{event.data})") if event.data
      end

      @websocket.onclose = lambda do |event|
        begin
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
          event = SerializationHelper.symbolize_keys(JSON.load(event.data))
          Log.info("Received #{event[:type]} event <#{event[:uuid]}> from #{event[:from]}")
          @stats["events"].update(event[:type])
          if (result = handler.call(event))
            Log.info("Sending #{event[:type]} event <#{event[:uuid]}> to #{event[:from]}")
            @websocket.send(JSON.dump({:event => result, :routing_keys => [event[:from]]}))
          end
        rescue Exception => e
          Log.error("Failed handling WebSocket event", e, :trace)
          @stats["exceptions"].track("event", e)
        end
      end

      @websocket
    end

    # Make long-polling request to receive one or more events
    # Limit logging unless in debug mode
    #
    # @param [Array, NilClass] routing_keys as strings to assist router in delivering
    #   event to interested parties
    #
    # @yield [event] required block called for each event received
    # @yieldparam [Object] event received
    #
    # @return [TrueClass] always true
    #
    # @raise [ArgumentError] block missing
    def long_poll(routing_keys, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      params = {
        :wait_time => @options[:listen_timeout] - 5,
        :timestamp => Time.now.to_f }
      params[:routing_keys] = routing_keys if routing_keys

      if (events = make_request(:get, "/listen", params, "listen", nil, :log_level => :debug,
                                :request_timeout => @options[:listen_timeout]))
        events.each do |event|
          event = SerializationHelper.symbolize_keys(event)
          Log.info("Received #{event[:type]} event <#{event[:uuid]}> from #{event[:from]}")
          @stats["events"].update(event[:type])
          handler.call(event)
        end
      end
      true
    end

  end # RouterClient

end # RightScale
