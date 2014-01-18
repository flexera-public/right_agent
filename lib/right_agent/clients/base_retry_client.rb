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

require File.join(File.dirname(__FILE__), '..', 'core_payload_types')

module RightScale

  # Abstract base client for creating RightNet and RightApi clients with retry capability
  # Requests are automatically retried to overcome connectivity failures
  # A status callback is provided so that the user of the client can take action
  # (e.g., queue requests) when connectivity is lost
  # Health checks are sent periodically to try to recover from connectivity failures
  class BaseRetryClient

    # Interval between reconnect attempts
    DEFAULT_RECONNECT_INTERVAL = 15

    # Default time to wait for HTTP connection to open
    DEFAULT_OPEN_TIMEOUT = 2

    # Default time to wait for response from request, which is chosen to be 5 seconds greater
    # than the response timeout inside the RightNet router
    DEFAULT_REQUEST_TIMEOUT = 35

    # Default interval between successive retries and default maximum elapsed time until stop retrying
    # These are chosen to be consistent with the retry sequencing for RightNet retryable requests
    # (per :retry_interval and :retry_timeout agent deployer configuration parameters for RightNet router),
    # so that if the retrying happens within the router, it will not retry here
    DEFAULT_RETRY_INTERVALS = [4, 12, 36]
    DEFAULT_RETRY_TIMEOUT = 25

    # State of this client: :pending, :connected, :disconnected, :failed, :closing
    attr_reader :state

    PERMITTED_STATE_TRANSITIONS = {
      :pending      => [:pending, :connected, :disconnected, :failed, :closing],
      :connected    => [:connected, :disconnected, :failed, :closing],
      :disconnected => [:connected, :disconnected, :failed, :closing],
      :failed       => [:failed, :closing],
      :closing      => [:closing] }

    # Set configuration of this client and initialize HTTP access
    #
    # @param [Symbol] type of server for use in obtaining URL from auth_client, e.g., :router
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [String] :server_name for use in reporting errors, e.g., RightNet
    # @option options [String] :api_version of server for use in X-API-Version header
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Numeric] :reconnect_interval for reconnect attempts after lose connectivity
    # @option options [Array] :filter_params symbols or strings for names of request parameters
    #   whose values are to be hidden when logging; can be augmented on individual requests
    # @option options [Proc] :exception_callback for unexpected exceptions
    #
    # @return [Boolean] whether currently connected
    #
    # @raise [ArgumentError] auth client does not support this client type
    # @raise [ArgumentError] :api_version missing
    def init(type, auth_client, options)
      raise ArgumentError, "Auth client does not support server type #{type.inspect}" unless auth_client.respond_to?(type.to_s + "_url")
      raise ArgumentError, ":api_version option missing" unless options[:api_version]
      @type = type
      @auth_client = auth_client
      @http_client = nil
      @status_callbacks = []
      @options = options.dup
      @options[:server_name] ||= type.to_s
      @options[:open_timeout] ||= DEFAULT_OPEN_TIMEOUT
      @options[:request_timeout] ||= DEFAULT_REQUEST_TIMEOUT
      @options[:retry_timeout] ||= DEFAULT_RETRY_TIMEOUT
      @options[:retry_intervals] ||= DEFAULT_RETRY_INTERVALS
      @options[:reconnect_interval] ||= DEFAULT_RECONNECT_INTERVAL
      reset_stats
      @state = :pending
      create_http_client
      enable_use if check_health == :connected
      state == :connected
    end

    # Record callback to be notified of status changes
    # Multiple callbacks are supported
    #
    # @yield [type, status] called when status changes (optional)
    # @yieldparam [Symbol] type of client reporting status change
    # @yieldparam [Symbol] state of client
    #
    # @return [Symbol] current state
    def status(&callback)
      @status_callbacks << callback if callback
      state
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @return [TrueClass] always true
    def close
      self.state = :closing
      @reconnect_timer.cancel if @reconnect_timer
      @reconnect_timer = nil
      true
    end

    # Current statistics for this client
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics
    #   [Hash, NilClass] "reconnects" Activity stats or nil if none
    #   [Hash, NilClass] "request failures" Activity stats or nil if none
    #   [Hash, NilClass] "request sent" Activity stats or nil if none
    #   [Float, NilClass] "response time" average number of seconds to respond to a request or nil if none
    #   [Hash, NilClass] "state" Activity stats or nil if none
    #   [Hash, NilClass] "exceptions" Exceptions stats or nil if none
    def stats(reset = false)
      stats = {}
      @stats.each { |k, v| stats[k] = v.all }
      stats["response time"] = @stats["requests sent"].avg_duration
      reset_stats if reset
      stats
    end

    protected

    # Reset statistics for this client
    #
    # @return [TrueClass] always true
    def reset_stats
      @stats = {
        "reconnects"       => RightSupport::Stats::Activity.new,
        "request failures" => RightSupport::Stats::Activity.new,
        "requests sent"    => RightSupport::Stats::Activity.new,
        "state"            => RightSupport::Stats::Activity.new,
        "exceptions"       => RightSupport::Stats::Exceptions.new(agent = nil, @options[:exception_callback]) }
      true
    end

    # Update state of this client
    # If state has changed, make external callbacks to notify of change
    # Do not update state once set to :closing
    #
    # @param [Hash] value for new state
    #
    # @return [Symbol] updated state
    #
    # @raise [ArgumentError] invalid state transition
    def state=(value)
      if @state != :closing
        unless PERMITTED_STATE_TRANSITIONS[@state].include?(value)
          raise ArgumentError, "Invalid state transition: #{@state.inspect} -> #{value.inspect}"
        end

        case value
        when :pending, :closing
          @stats["state"].update(value.to_s)
          @state = value
        when :connected, :disconnected, :failed
          if value != @state
            @stats["state"].update(value.to_s)
            @state = value
            @status_callbacks.each do |callback|
              begin
                callback.call(@type, @state)
              rescue StandardError => e
                Log.error("Failed status callback", e)
                @stats["exceptions"].track("status", e)
              end
            end
            reconnect if @state == :disconnected
          end
        end
      end
      @state
    end

    # Create HTTP client
    #
    # @return [TrueClass] always true
    #
    # @return [RightSupport::Net::BalancedHttpClient] client
    def create_http_client
      url = @auth_client.send(@type.to_s + "_url")
      Log.info("Connecting to #{@options[:server_name]} via #{url.inspect}")
      options = {
        :server_name => @options[:server_name],
        :open_timeout => @options[:open_timeout],
        :request_timeout => @options[:request_timeout] }
      options[:api_version] = @options[:api_version] if @options[:api_version]
      options[:filter_params] = @options[:filter_params] if @options[:filter_params]
      @http_client = RightScale::BalancedHttpClient.new(url, options)
    end

    # Perform any other steps needed to make this client fully usable
    # once HTTP client has been created and server known to be accessible
    #
    # @return [TrueClass] always true
    def enable_use
      true
    end

    # Check health of RightApi
    # No check is done if HTTP client does not exist
    #
    # @return [Symbol] RightApi client state
    def check_health
      begin
        @http_client.check_health
        self.state = :connected
      rescue BalancedHttpClient::NotResponding
        self.state = :disconnected
      rescue Exception => e
        Log.error("Failed #{@options[:server_name]} health check", e)
        @stats["exceptions"].track("check health", e)
        self.state = :disconnected
      end
    end

    # Reconnect with server by periodically checking health
    # Randomize when initially start checking to reduce server spiking
    #
    # @return [TrueClass] always true
    def reconnect
      unless @reconnecting
        @reconnecting = true
        @stats["reconnects"].update("initiate")
        @reconnect_timer = EM::PeriodicTimer.new(rand(@options[:reconnect_interval])) do
          begin
            create_http_client
            if check_health == :connected
              enable_use
              @stats["reconnects"].update("success")
              @reconnect_timer.cancel if @reconnect_timer # only need 'if' for test purposes
              @reconnect_timer = @reconnecting = nil
            end
          rescue Exception => e
            Log.error("Failed #{@options[:server_name]} reconnect", e)
            @stats["reconnects"].update("failure")
            @stats["exceptions"].track("reconnect", e)
            self.state = :disconnected
          end
          @reconnect_timer.interval = @options[:reconnect_interval] if @reconnect_timer
        end
      end
      true
    end

    # Make request via HTTP
    # Rely on underlying HTTP client to log request and response
    # Retry request if response indicates to or if there are connectivity failures
    #
    # There are also several timeouts involved:
    #   - Underlying BalancedHttpClient connection open timeout (:open_timeout)
    #   - Underlying BalancedHttpClient request timeout (:request_timeout)
    #   - Retry timeout for this method and its handlers (:retry_timeout)
    # and if the target server is a RightNet router:
    #   - Router response timeout (ideally > :retry_timeout and < :request_timeout)
    #   - Router retry timeout (ideally = :retry_timeout)
    #
    # There are several possible levels of retry involved, starting with the outermost:
    #   - This method will retry if the targeted server is not responding or if it receives
    #     a retry response, but the total elapsed time is not allowed to exceed :request_timeout
    #   - RequestBalancer in BalancedHttpClient will retry using other endpoints if it gets an error
    #     that it considers retryable, and even if a front-end balancer is in use there will
    #     likely be at least two such endpoints for redundancy
    # and if the target server is a RightNet router:
    #   - The router when sending a request via AMQP will retry if it receives no response,
    #     but not exceeding its configured :retry_timeout; if the router's timeouts for retry
    #     are consistent with the ones prescribed above, there will be no retry by the
    #     RequestBalancer after router retries
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [Hash] params for HTTP request
    # @param [String] type of request for use in logging; defaults to path
    # @param [String, NilClass] request_uuid uniquely identifying this request;
    #   defaults to randomly generated UUID
    # @param [Hash] options augmenting or overriding default options for HTTP request
    #
    # @return [Object, NilClass] result of request with nil meaning no result
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def make_request(verb, path, params = {}, type = nil, request_uuid = nil, options = {})
      raise Exceptions::Terminating if state == :closing
      request_uuid ||= RightSupport::Data::UUID.generate
      started_at = Time.now
      attempts = 0
      result = nil
      @stats["requests sent"].measure(type || path, request_uuid) do
        begin
          attempts += 1
          http_options = {
            :open_timeout => @options[:open_timeout],
            :request_timeout => @options[:request_timeout],
            :request_uuid => request_uuid,
            :headers => @auth_client.headers }
          raise Exceptions::ConnectivityFailure, "#{@type} client not connected" unless state == :connected
          result = @http_client.send(verb, path, params, http_options.merge(options))
        rescue StandardError => e
          request_uuid = handle_exception(e, type || path, request_uuid, started_at, attempts)
          request_uuid ? retry : raise
        end
      end
      result
    end

    # Examine exception to determine whether to setup retry, raise new exception, or re-raise
    #
    # @param [StandardError] exception raised
    # @param [String] action from request type
    # @param [String] type of request for use in logging
    # @param [String] request_uuid originally created for this request
    # @param [Time] started_at time for request
    # @param [Integer] attempts to make request
    #
    # @return [String, NilClass] request token to be used on retry or nil if to raise instead
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def handle_exception(exception, type, request_uuid, started_at, attempts)
      result = request_uuid
      if exception.respond_to?(:http_code)
        case exception.http_code
        when 301, 302 # MovedPermanently, Found
          handle_redirect(exception, type, request_uuid)
        when 401 # Unauthorized
          raise Exceptions::Unauthorized.new(exception.http_body, exception)
        when 403 # Forbidden
          @auth_client.expired
          raise Exceptions::RetryableError.new("Authorization expired", exception)
        when 449 # RetryWith
          result = handle_retry_with(exception, type, request_uuid, started_at, attempts)
        when 500 # InternalServerError
          raise Exceptions::InternalServerError.new(exception.http_body, @options[:server_name])
        else
          @stats["request failures"].update("#{type} - #{exception.http_code}")
          result = nil
        end
      elsif exception.is_a?(BalancedHttpClient::NotResponding)
        handle_not_responding(exception, type, request_uuid, started_at, attempts)
      else
        @stats["request failures"].update("#{type} - #{exception.class.name}")
        result = nil
      end
      result
    end

    # Treat redirect response as indication that no longer accessing the correct shard
    # Handle it by informing auth client so that it can re-authorize
    # Do not retry, but tell client to with the expectation that re-auth will correct the situation
    #
    # @param [RestClient::MovedPermanently, RestClient::Found] redirect exception raised
    # @param [String] type of request for use in logging
    # @param [String] request_uuid originally created for this request
    #
    # @return [TrueClass] never returns
    #
    # @raise [Exceptions::RetryableError] request redirected but if retried may succeed
    # @raise [Exceptions::InternalServerError] no redirect location provided
    def handle_redirect(redirect, type, request_uuid)
      Log.info("Received redirect #{redirect} response for #{type} request <#{request_uuid}>")
      if redirect.respond_to?(:response) && (location = redirect.response.headers[:location]) && !location.empty?
        Log.info("Requesting auth client to handle redirect to #{location.inspect}")
        @stats["reconnects"].update("redirect")
        @auth_client.redirect(location)
        raise Exceptions::RetryableError.new(redirect.http_body, redirect)
      else
        raise Exceptions::InternalServerError.new("No redirect location provided", @options[:server_name])
      end
      true
    end

    # Handle retry response by retrying it once
    # This indicates the request was received but a retryable error prevented
    # it from being processed; the retry responsibility may be passed on
    # If retrying, this function does not return until it is time to retry
    #
    # @param [RestClient::RetryWith] retry_result exception raised
    # @param [String] type of request for use in logging
    # @param [String] request_uuid originally created for this request
    # @param [Time] started_at time for request
    # @param [Integer] attempts to make request
    #
    # @return [String] request token to be used on retry
    #
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    def handle_retry_with(retry_result, type, request_uuid, started_at, attempts)
      if @options[:retry_enabled]
        interval = @options[:retry_intervals][attempts - 1]
        if attempts == 1 && interval && (Time.now - started_at) < @options[:retry_timeout]
          Log.error("Retrying #{type} request <#{request_uuid}> in #{interval} seconds " +
                    "in response to retryable error (#{retry_result.http_body})")
          sleep(interval)
        else
          @stats["request failures"].update("#{type} - retry")
          raise Exceptions::RetryableError.new(retry_result.http_body, retry_result)
        end
      else
        @stats["request failures"].update("#{type} - retry")
        raise Exceptions::RetryableError.new(retry_result.http_body, retry_result)
      end
      # Change request_uuid so that retried request not rejected as duplicate
      "#{request_uuid}:retry"
    end

    # Handle not responding response by determining whether okay to retry
    # If request is being retried, this function does not return until it is time to retry
    #
    # @param [RightScale::BalancedHttpClient::NotResponding] not_responding exception
    #   indicating targeted server is too busy or out of service
    # @param [String] type of request for use in logging
    # @param [String] request_uuid originally created for this request
    # @param [Time] started_at time for request
    # @param [Integer] attempts to make request
    #
    # @return [TrueClass] always true
    #
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    def handle_not_responding(not_responding, type, request_uuid, started_at, attempts)
      if @options[:retry_enabled]
        interval = @options[:retry_intervals][attempts - 1]
        if interval && (Time.now - started_at) < @options[:retry_timeout]
          Log.error("Retrying #{type} request <#{request_uuid}> in #{interval} seconds " +
                    "in response to routing failure (#{BalancedHttpClient.exception_text(not_responding)})")
          sleep(interval)
        else
          @stats["request failures"].update("#{type} - no result")
          self.state = :disconnected
          raise Exceptions::ConnectivityFailure.new(not_responding.message + " after #{attempts} attempts")
        end
      else
        @stats["request failures"].update("#{type} - no result")
        self.state = :disconnected
        raise Exceptions::ConnectivityFailure.new(not_responding.message)
      end
      true
    end

  end # BaseRetryClient

end # RightScale
