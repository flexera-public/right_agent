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
  class BaseClient

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

    # State of this client
    attr_reader :state

    # Set configuration of this client and initialize HTTP access
    #
    # @param [Symbol] type of agent: :api or :router
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Array] :filter_params symbols or strings for names of request parameters
    #   whose values are to be hidden when logging; can be augmented on individual requests
    # @option options [String] :health_check_path for making service health check
    # @option options [Proc] :exception_callback for unexpected exceptions
    #
    # @return [TrueClass] always true
    #
    # @raise [ArgumentError] auth client does not support this client type
    def init(type, auth_client, options)
      raise ArgumentError.new("Auth client does not support type #{type}") unless auth_client.respond_to?(type + "_url")
      @type = type
      @auth_client = auth_client
      @http_client = nil
      @status_callbacks = []
      @options = options.dup
      @options[:open_timeout] ||= DEFAULT_OPEN_TIMEOUT
      @options[:request_timeout] ||= DEFAULT_REQUEST_TIMEOUT
      @options[:retry_timeout] ||= DEFAULT_RETRY_TIMEOUT
      @options[:retry_intervals] ||= DEFAULT_RETRY_INTERVALS
      @options[:reconnect_interval] ||= DERFAULT_RECONNECT_INTERVAL
      reset_stats
      state = :initializing
      reconnect(0)
      true
    end

    def push(*args)
      make_request(:push, *args)
    end

    def request(*args)
      make_request(:request, *args)
    end

    # Make request via HTTP
    # Rely on underlying HTTP client to log request and response
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
      raise NotImplementedError.new("#{self.class.name} is an abstract class.")
    end

    # Record callback to be notified of status changes
    # Multiple callbacks are supported
    #
    # @yield [type, status] called when status changes
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
      unless state == :closing
        state = :closing
        @reconnect_timer.cancel if @reconnect_timer
        @reconnect_timer = nil
      end
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

    # Reset API interface statistics
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
    # @raise [ArgumentError] unknown state
    def state=(value)
      case value
      when :initializing, :closing
        @stats["state"].update(value.to_s)
        @state = value
      when :connected, :disconnected, :failed
        if value != @state || @state == :closing
          @status_callbacks.each do |callback|
            begin
              callback.call(@type, @state)
            rescue RuntimeError => e
              Log.error("Failed status callback", e)
              @stats["exceptions"].update("status", e)
            end
          end
          @stats["state"].update(value.to_s)
          @state = value
          reconnect if @state == :disconnected
        end
      else
        raise ArgumentError.new("Unknown state: #{value.inspect}")
      end
      @state
    end

    # Create HTTP client
    #
    # @return [TrueClass] always true
    #
    # @return [RightSupport::Net::BalancedHttpClient] client
    def create_http_client
      url = @auth_client.send(@type + "_url")
      Log.info("Connecting to #{@type} via #{url.inspect}")
      options = {
        :api_version => @options[:api_version],
        :open_timeout => @options[:open_timeout],
        :request_timeout => @options[:request_timeout],
        :filter_params => @options[:filter_params],
        :health_check_path => @options[:health_check_path] }
      @http_client = RightScale::BalancedHttpClient.new(url, options)
    end

    # Perform any other steps needed to make this client fully usable
    # once HTTP client has been created and service known to be accessible
    #
    # @return [TrueClass] always true
    def init_client_usage
      true
    end

    # Check health of RightApi
    # No check is done if HTTP client does not exist
    #
    # @return [Symbol] RightApi client state
    def check_health
      begin
        @http_client.get(@options[:health_check_path])
        state = :connected
      rescue BalancedHttpClient::NotResponding => e
        state = :disconnected
      rescue Exception => e
        Log.error("Failed #{@type} health check", e)
        @stats["exceptions"].track("check health", e)
        state = :disconnected
      end
      state == :connected
    end

    # Reconnect with service by periodically checking health
    #
    # @param [Integer, NilClass] wait time before attempt to reconnect; defaults
    #   to random interval to reduce service spiking
    #
    # @return [TrueClass] always true
    def reconnect(wait = nil)
      unless @reconnecting
        @reconnecting = true
        EM.add_timer(wait || rand(@options[:reconnect_interval])) do
          @stats["reconnects"].update("initiate")
          @reconnect_timer = EM::PeriodicTimer.new(wait || @options[:reconnect_interval]) do
            begin
              create_http_client
              if check_health
                @stats["reconnects"].update("success")
                @reconnect_timer.cancel
                @reconnect_timer = @reconnecting = nil
              end
              init_client_usage
            rescue Exception => e
              Log.error("Failed #{@type} reconnect", e)
              @stats["reconnects"].update("failure")
              @stats["exceptions"].track("check health", e)
            end
          end
        end
      end
      true
    end

    # Examine exception to determine whether to setup retry, raise new exception, or re-raise
    #
    # @param [StandardError] exception raised
    # @param [String] action from request type
    # @param [String] type of request as path specifying actor and action
    # @param [String] request_token originally created for this request
    # @param [Time] started_at time for request
    # @param [Integer] attempts to make request
    #
    # @return [String] request token to be used on retry
    #
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    # @raise [RightScale::Exceptions::ConnectivityFailure] could not make connection to send request
    # @raise [RightScale::Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [RightScale::Exceptions::StructuredError] mismatch in state from which transitioning
    # @raise [RightScale::Exceptions::Application] request could not be processed by target
    def handle_exception(exception, action, type, request_token, started_at, attempts)
      case exception
      when RestClient::Unauthorized
        raise RightScale::Exceptions::Unauthorized.new(exception.message, exception)
      when BalancedHttpClient::Redirect
        # This probably indicates that shard has changed, so inform auth client
        # Do not try to redirect this request; let auth client sort it out first
        handle_redirect(exception, type, request_token, attempts)
        raise
      when BalancedHttpClient::NotResponding
        # This indicates the service is not responding and a retry is recommended
        handle_no_result(exception, action, type, request_token, started_at, attempts)
      when RestClient::RetryWith
        # This indicates the request was receive but a retryable error prevented
        # it from being processed; the retry responsibility may be passed back
        # to the requester or accepted here
        handle_retry_result(exception, action, type, request_token, started_at, attempts)
        request_token << ":retry" # so that retried request not rejected as duplicate
      when RestClient::Conflict
        # This indicates a request conflict with a structured error result
        data = JSON.load(exception.data)
        message = (data.is_a?(Hash) && data["message"]) || exception.inspect
        raise RightScale::Exceptions::StructuredError.new(message, data, exception)
      when RestClient::UnprocessableEntity
        raise RightScale::Exceptions::Application.new(exception.message, exception)
      else
        @stats["request failures"].update("#{action} - #{exception.respond_to?(:http_body) ? exception.http_code : exception.class.name}")
        raise
      end
      request_token
    end

    # Handle no result from request by determining whether it is a retryable
    # If request is being retried, this function does not return until it is time to retry
    #
    # @param [RightSupport::Net::NoResult] no_result exception raised by request balancer when it
    #   could not deliver request including details about why
    # @param [String] action from request type
    # @param [String] type of request as path specifying actor and action
    # @param [String] request_token originally created for this request
    # @param [Time] started_at time for request
    # @param [Integer] attempts to make request
    #
    # @return [TrueClass] always true
    #
    # @raise [RightScale::Exceptions::ConnectivityFailure] could not make connection to send request
    def handle_no_result(no_result, action, type, request_token, started_at, attempts)
      if @retry_enabled
        interval = @options[:retry_intervals][attempts - 1]
        if interval && (Time.now - started_at) < @options[:retry_timeout]
          Log.error("Retrying #{type} request <#{request_token}> in #{interval} seconds " +
                    "in response to routing failure (#{BalancedHttpClient.exception_text(no_result)})")
          sleep(interval)
        else
          @stats["request failures"].update("#{action} - no result")
          state = :disconnected
          raise RightScale::Exceptions::ConnectivityFailure.new("Cannot process #{type} request <#{request_token}> " +
              "because routing failed after #{attempts} attempts (#{BalancedHttpClient.exception_text(no_result)})")
        end
      else
        @stats["request failures"].update("#{action} - no result")
        state = :disconnected
        raise RightScale::Exceptions::ConnectivityFailure.new("Cannot process #{type} request <#{request_token}> " +
            "because routing failed (#{BalancedHttpClient.exception_text(no_result)})")
      end
      true
    end

    # Handle retry result from request by retrying it once
    # If retrying, this function does not return until it is time to retry
    #
    # @param [RestClient::RetryWith] retry_result exception raised
    # @param [String] action from request type
    # @param [String] type of request as path specifying actor and action
    # @param [String] request_token originally created for this request
    # @param [Time] started_at time for request
    # @param [Integer] attempts to make request
    #
    # @return [TrueClass] always true
    #
    # @raise [RightScale::Exceptions::RetryableError] request failed but if retried may succeed
    def handle_retry_result(retry_result, action, type, request_token, started_at, attempts)
      if @options[:retry_enabled]
        interval = @options[:retry_intervals][attempts - 1]
        if attempts == 1 && interval && (Time.now - started_at) < @options[:retry_timeout]
          Log.error("Retrying #{type} request <#{request_token}> in #{interval} seconds " +
                    "in response to RightNet retryable error (#{retry_result.http_body})")
          sleep(interval)
        else
          @stats["request failures"].update("#{action} - retry")
          raise RightScale::Exceptions::RetryableError.new(retry_result.http_body, retry_result)
        end
      else
        @stats["request failures"].update("#{action} - retry")
        raise RightScale::Exceptions::RetryableError.new(retry_result.http_body, retry_result)
      end
      true
    end

    # Treat redirect response as indication that no longer accessing the correct shard
    # Handle it by informing auth client so that it can re-initialize
    #
    # @param [RestClient::MovedPermanently, RestClient::Found] redirect exception raised
    # @param [String] type of request as path specifying actor and action
    # @param [String] request_token originally created for this request
    #
    # @return [TrueClass] always true
    def handle_redirect(redirect, type, request_token, attempts)
      Log.info("Received redirect #{redirect} response for #{type} request <#{request_token}> to #{redirect.location.inspect}")
      if attempts == 1 && redirect.location && !redirect.location.empty?
        Log.info("Requesting auth client to handle redirect request")
        @stats["reconnects"].update("redirect")
        @auth_client.redirect(redirect.location)
      end
      true
    end

  end # BaseClient

end # RightScale
