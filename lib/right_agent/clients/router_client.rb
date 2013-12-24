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

module RightScale

  # HTTP interface to RightNet router
  class RouterClient < BaseClient

    # RightNet router API version for use in X-API-Version header
    API_VERSION = "2.0"

    # Path for RightNet router health check
    HEALTH_CHECK_PATH = "/router/health-check"

    # Initial interval between attempts to create a WebSocket
    WEBSOCKET_CONNECT_INTERVAL = 30

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
    # @option options [Proc] :exception_callback for unexpected exceptions
    #
    # @raise [ArgumentError] auth client does not support this client type
    def initialize(auth_client, options)
      init(:router, auth_client, options.merge(:api_version => API_VERSION, :health_check_path => HEALTH_CHECK_PATH))
      @options[:listen_timeout] ||= DEFAULT_LISTEN_TIMEOUT
    end

    # Make request via HTTP
    # Rely on underlying HTTP client to log request and response
    # Retry request if response indicates to or if there are "not responding" failures
    #
    # There are several possible levels of retry involved here starting with the outermost:
    # - This method will retry if there is a routing failure it considers retryable or if
    #   it receives a retry request, but not exceeding an elapsed time of :request_timeout
    # - RequestBalancer in REST client will retry using other endpoints if it gets an error
    #   that it considers retryable, and even if a front-end balancer is in use there will
    #   likely be two at least two such endpoints for redundancy
    # - The RightNet router when processing a request, if it is the server targeted,
    #   will retry if it receives no response, but not exceeding its configured :retry_timeout;
    #   if its timeouts for retry are consistent with the ones here, #2 above will not be
    #   applied if this level is (there is no retrying of requests in RightApi)
    #
    # There are also several timeouts involved:
    # - Underlying RestClient connection open timeout (:open_timeout)
    # - Underlying RestClient request timeout (:request_timeout)
    # - Retry timeout for this method and its handlers (:retry_timeout)
    # - RightNet router response timeout (ideally > :retry_timeout and < :request_timeout)
    # - RightNet router retry timeout (ideally = :retry_timeout)
    #
    # @param [Symbol] kind of request: :push or :request
    # @param [String] type of request as path specifying actor and action
    # @param [Hash, NilClass] payload for request
    # @param [String, Hash, NilClass] target for request
    # @param [String, NilClass] request_token uniquely identifying this request;
    #   defaults to randomly generated ID
    #
    # @return [Object, NilClass] result of request with nil meaning no result
    #
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    # @raise [RightScale::Exceptions::ConnectivityFailure] could not make connection to send request
    # @raise [RightScale::Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [RightScale::Exceptions::StructuredError] mismatch in state from which transitioning
    # @raise [RightScale::Exceptions::Application] request could not be processed by target
    # @raise [RightScale::Exceptions::Terminating] closing client and terminating service
    def make_request(kind, type, payload, target, request_token)
      raise RightScale::Exceptions::Terminating if state == :closing
      action = type.split("/")[2]
      request_token ||= RightSupport::Data::UUID.generate
      original_request_token = request_token
      started_at = @stats["requests sent"].update(action, request_token)
      attempts = 0

      begin
        attempts += 1
        params = {
          :type => type,
          :payload => payload,
          :target => target,
          :request_token => request_token }
        options = {
          :open_timeout => @options[:open_timeout],
          :request_timeout => @options[:request_timeout],
          :request_uuid => request_token,
          :auth_header => @auth_client.auth_header }
        raise RightScale::Exceptions::ConnectivityFailure unless state == :connected
        result = @client.post("/router/requests/#{kind.to_s}", params, options)
      rescue StandardError => e
        request_token = handle_exception(e, action, type, original_request_token, started_at, attempts)
        retry
      end

      @stats["requests sent"].finish(started_at, original_request_token)
      result
    end

    # Route event
    # Use WebSocket if possible
    # Do not block this request even if in the process of closing
    #
    # @param [Hash, Packet] event to send
    # @param [String] key for routing
    #
    # @return [TrueClass] always true
    #
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    def notify(event, key)
      params = {
        :agent_id => @auth_client.identity,
        :event => event,
        :routing_key => key }
      options = {
        :open_timeout => @options[:open_timeout],
        :request_timeout => @options[:request_timeout],
        :auth_header => @auth_client.auth_header }
      if @websocket
        @websocket.send(JSON.dump(params))
      else
        @http_client.post("/router/events/notify", params, options)
      end
      true
    end

    # Receive events via an HTTP WebSocket if available, otherwise via an HTTP long-polling
    # This is a blocking call and therefore should be used from a thread different than
    # otherwise used with this object, e.g., EM.defer thread
    #
    # @yield [event] to required block each time event received
    # @yieldparam [Object] event received
    #
    # @return [TrueClass] always true, although normally never returns
    #
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    def listen(&handler)
      connect_interval = WEBSOCKET_CONNECT_INTERVAL
      last_connect_time = Time.now - connect_interval

      until state == :closing do
        # Attempt to create a WebSocket if enabled and enough time has elapsed since last attempt
        # or if WebSocket connection has been lost
        now = Time.now
        if !@options[:long_polling_only] && (@websocket.nil? && (now - last_connect_time) > connect_interval)
          begin
            @stats["reconnects"].update("websocket") unless @websocket
            create_websocket(&handler)
            sleep(@options[:listen_timeout])
          rescue Exception => e
            Log.error("Failed creating WebSocket", e)
            @stats["exceptions"].track("websocket", e)
            last_connect_time = now
            connect_interval = [connect_interval * 2, MAX_WEBSOCKET_CONNECT_INTERVAL].min
          end
        end

        # Resort to long-polling if a WebSocket cannot be created
        if @websocket.nil?
          begin
            options = {
              :open_timeout => @options[:open_timeout],
              :request_timeout => @options[:listen_timeout],
              :auth_header => @auth_client.auth_header }
            params = {
              :agent_id => @auth_client.identity,
              :wait_time => @options[:listen_timeout] - 5,
              :timestamp => now.to_f }
            if (event = @http_client.get("/router/events/listen", params, options))
              Log.info("Received event: #{(event.respond_to?(:type) ? event.type : event.inspect)}")
              @stats["events"].update(event.respond_to?(:type) ? event.type : "unknown")
              handler.call(event)
            end
          rescue Exception => e
            trace = e.is_a?(RightScale::Exceptions::ConnectivityFailure) ? :no_trace : :trace
            Log.error("Failed long-polling", e, trace)
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
    # @yield [event] called when event received
    # @yieldparam [Object] event received
    #
    # @return [Faye::WebSocket] WebSocket created
    def create_websocket(&handler)
      options = {
        :headers => {"X-API-Version" => API_VERSION}.merge(@auth_client.auth_header),
        :ping => @options[:listen_timeout] }
      uri = @auth_client.router_url + "/router/events/connect/#{@auth_client.identity}"
      @websocket = Faye::WebSocket::Client.new(uri, protocols = nil, options)

      @websocket.onclose = lambda do |event|
        msg = "Closing WebSocket (#{event.code}"
        msg << ((event.reason.nil? || event.reason.empty?) ? ")" : ": #{event.reason})")
        Log.info(msg)
        @websocket = nil
      end

      @websocket.onerror = lambda do |event|
        Log.error("Error on WebSocket: #{event.data}")
      end

      @websocket.onmessage = lambda do |event|
        begin
          event = JSON.load(event.data) rescue event
          Log.info("Received event: #{(event.respond_to?(:type) ? event.type : event.inspect)}")
          @stats["events"].update(event.respond_to?(:type) ? event.type : "unknown")
          if (response = handler.call(event))
            @websocket.send(JSON.dump(response))
          end
        rescue Exception => e
          Log.error("Failed handling event", e, :trace)
          @stats[:exceptions].track("event", e)
        end
      end

      @websocket
    end

  end # RouterClient

end # RightScale
