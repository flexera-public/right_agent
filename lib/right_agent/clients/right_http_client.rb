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

  # HTTP interface to RightNet router and to RightNet services in RightApi
  # It is intended for use by instance agents and infrastructure servers
  # The interface supports sending requests and sending/receiving events
  # Events are received over a WebSocket if possible, otherwise via long-polling
  # Requests to RightNet and RightApi are automatically retried to overcome connectivity failures
  # A status callback is provided so that the user of this client can take action
  # (e.g., queue requests) when connectivity is lost
  # Health checks are sent periodically to try to recover from connectivity failures
  class RightHttpClient

    include RightSupport::Ruby::EasySingleton

    # Initialize RightNet client
    # Must be called before any other functions are usable
    #
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [Numeric] :open_timeout maximum wait for connection
    # @option options [Numeric] :request_timeout maximum wait for response
    # @option options [Numeric] :listen_timeout maximum wait for event when long-polling
    # @option options [Numeric] :retry_timeout maximum before stop retrying
    # @option options [Array] :retry_intervals between successive retries
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Boolean] :long_polling_only never attempt to create a WebSocket, always long-polling instead
    # @option options [Array] :filter_params symbols or strings for names of request parameters
    #   whose values are to be hidden when logging
    # @option options [Proc] :exception_callback for unexpected exceptions with following parameters:
    #   [Exception] exception raised
    #   [Packet, NilClass] packet being processed
    #   [Agent, NilClass] agent in which exception occurred
    #
    # @return [TrueClass] always true
    #
    # @raise [ArgumentError] no auth client
    def init(auth_client, options = {})
      raise ArgumentError, "No authorization client provided" unless auth_client.is_a?(AuthClient)
      @status = {}
      callback = lambda { |type, state| update_status(type, state) }
      @auth = auth_client
      @status[:auth] = @auth.status(&callback)
      @router = RouterClient.new(@auth, options)
      @status[:router] = @router.status(&callback)
      if @auth.api_url
        @api = ApiClient.new(@auth, options)
        @status[:api] = @api.status(&callback)
      end
      true
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
    # @param [String, Hash, NilClass] target for request, which may be identity of specific
    #   target, hash for selecting potentially multiple targets, or nil if routing solely
    #   using type; hash may contain:
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
    # @raise [RuntimeError] init was not called
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def push(type, payload = nil, target = nil, token = nil)
      raise RuntimeError, "#{self.class.name}#init was not called" unless @auth
      client = (@api && @api.support?(type)) ? @api : @router
      client.push(type, payload, target, token)
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
    # @param [String, Hash, NilClass] target for request, which may be identity of specific
    #   target, hash for selecting targets of which one is picked randomly, or nil if routing solely
    #   using type; hash may contain:
    #   [Array] :tags that must all be associated with a target for it to be selected
    #   [Hash] :scope for restricting routing which may contain:
    #     [Integer] :account id that agents must be associated with to be included
    # @param [String, NilClass] token uniquely identifying this request;
    #   defaults to randomly generated ID
    #
    # @return [Result, NilClass] response from request
    #
    # @raise [RuntimeError] init was not called
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def request(type, payload = nil, target = nil, token = nil)
      raise RuntimeError, "#{self.class.name}#init was not called" unless @auth
      client = (@api && @api.support?(type)) ? @api : @router
      client.request(type, payload, target, token)
    end

    # Route event
    # Use WebSocket if possible
    # Do not block this request even if in the process of closing
    #
    # @param [Hash] event to send
    # @param [Array, NilClass] routing_keys as strings to assist router in delivering
    #   event to interested parties
    #
    # @return [TrueClass] always true
    #
    # @raise [RuntimeError] init was not called
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def notify(event, routing_keys)
      raise RuntimeError, "#{self.class.name}#init was not called" unless @auth
      @router.notify(event, routing_keys)
    end

    # Receive events via an HTTP WebSocket if available, otherwise via an HTTP long-polling
    # This is a blocking call and therefore should be used from a thread different than
    # otherwise used with this object, e.g., EM.defer thread
    #
    # @param [Array, NilClass] routing_keys for event sources of interest with nil meaning all
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Object] event received
    #
    # @return [TrueClass] always true, although normally never returns
    #
    # @raise [RuntimeError] init was not called
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def listen(routing_keys, &handler)
      raise RuntimeError, "#{self.class.name}#init was not called" unless @auth
      @router.listen(routing_keys, &handler)
    end

    # Resource href associated with the user of this client
    #
    # @return [String, NilClass] href or nil if unknown
    def href
      @api.href if @api
    end

    # Record callback to be notified of status changes
    # Multiple callbacks are supported
    #
    # @yield [type, status] called when status changes (optional)
    # @yieldparam [Symbol] type of client reporting status change: :auth, :api, or :router
    # @yieldparam [Symbol] state of client
    #
    # @return [Hash] status of various clients
    #
    # @raise [RuntimeError] init was not called
    def status(&callback)
      raise RuntimeError, "#{self.class.name}#init was not called" unless @auth
      @status_callbacks = (@status_callbacks || []) << callback if callback
      @status
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    # Only router and api clients are closed, not auth client
    #
    # @param [Symbol] scope of close action: :receive for just closing receive side
    #   of client, :all for closing both receive and send side; defaults to :all
    #
    # @return [TrueClass] always true
    def close(scope = :all)
      @router.close(scope) if @router
      @api.close(scope) if @api
      true
    end

    # Current statistics for this client
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics with keys "auth client stats", "router client stats",
    #   and optionally "api client stats"
    #
    # @raise [RuntimeError] init was not called
    def stats(reset = false)
      raise RuntimeError, "#{self.class.name}#init was not called" unless @auth
      stats = {}
      stats["auth stats"] = @auth.stats(reset)
      stats["router stats"] = @router.stats(reset)
      stats["api stats"] = @api.stats(reset) if @api
      stats
    end

    protected

    # Forward status updates via callbacks
    #
    # @param [Symbol] type of client: :auth, :api, or :router
    # @param [Symbol] state of client
    #
    # @return [Hash] status of various clients
    def update_status(type, state)
      @status[type] = state
      @status_callbacks.each do |callback|
        begin
          callback.call(type, state)
        rescue RuntimeError => e
          Log.error("Failed status callback", e)
        end
      end
      @status
    end

  end # RightHttpClient

end # RightScale
