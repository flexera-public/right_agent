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

  # OAuth2 authorization client for instance agent
  # It continuously renews the authorization to avoid expiring
  class InstanceAuthClient < AuthClient

    # TODO
    # - handle redirect
    # - shouldn't auth be returning new auth_url too for redirect situations
    #
    # Test cases:
    # - unauthorized failure
    # - cannot renew before expires
    # - cannot connect
    # - unexpected renew or connect failures
    # - notify about changes in status
    # - redirection

    # RightNet router API version for use in X-API-Version header
    API_VERSION = "2.0"

    # Path for RightNet router health check
    HEALTH_CHECK_PATH = "/router/health-check"

    # Default time to wait for HTTP connection to open
    DEFAULT_OPEN_TIMEOUT = 2

    # Default time to wait for response from request, which is chosen to be 5 seconds greater
    # than the response timeout inside the RightNet router
    DEFAULT_REQUEST_TIMEOUT = 5

    # Expiration time divisor for when to renew
    # Multiplier for renewal backoff when unauthorized
    RENEW_FACTOR = 2

    # Minimum expiration time before give up
    MIN_RENEW_TIME = 5

    # Initial interval between renew attempts when unauthorized
    UNAUTHORIZED_RENEW_INTERVAL = 60

    # Maximum interval between renew attempts when unauthorized
    MAX_UNAUTHORIZED_RENEW_INTERVAL = 60 * 60

    # Interval between health checks when disconnected
    HEALTH_CHECK_INTERVAL = 15

    # Maximum redirects allowed for an authorization request
    MAX_REDIRECTS = 5

    # Identity of instance agent using this client
    attr_reader :identity

    # ID of account owning this instance
    attr_reader :account_id

    # Type of agent
    attr_reader :agent_type

    # State of authorization
    attr_reader :state

    # Create authorization client for instance agent
    #
    # @option options [String] :auth_url to access RightNet authorization service; this URI must have
    #   user set to the instance API token ID and the password set to the authorization token
    # @option options [Boolean] :no_renew create session without setting up for continuous renewal
    # @option options [Proc] :exception_callback for unexpected exceptions with following parameters:
    #   [Exception] exception raised
    #   [Packet, NilClass] packet being processed
    #   [Agent, NilClass] agent in which exception occurred
    #
    # @raise [ArgumentError] missing :auth_url
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    # @raise [RightScale::AuthClient::AuthorizationError] could not create OAuth2 session
    def initialize(options)
      raise ArgumentError.new(":auth_url missing") if options[:auth_url].nil? || options[:auth_url].empty?
      uri = URI.parse(options[:auth_url])
      @token_id = uri.user
      raise ArgumentError.new(":auth_url missing user (token ID)") if @token_id.nil? || @token_id.empty?
      @auth_token = uri.password
      raise ArgumentError.new(":auth_url missing password (auth token)") if @auth_token.nil? || @auth_token.empty?
      token = SecureIdentity.derive(@token_id, @auth_token)
      @agent_type = "instance"
      @identity = AgentIdentity.new("rs", @agent_type, @token_id, token).to_s
      @expires_in = 0
      @api_url = @router_url = @protocol = nil
      @exception_callback = options[:exception_callback]
      reset_stats
      state = :initializing
      create_http_client
      if options[:no_renew]
        create_session
      else
        renew_session
      end
    end

    # Header to be added to HTTP request for authorization
    #
    # @return [Hash] value to be inserted into request header
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def auth_header
      raise RightScale::Exceptions::Unauthorized("Not authorized with RightNet") if state != :authorized
      {"Authorization" => "Bearer #{@session}"}
    end

    # URL for accessing RightApi
    #
    # @return [String] base URL
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def api_url
      raise RightScale::Exceptions::Unauthorized("Not authorized with RightNet") if state != :authorized
      @api_url
    end

    # URL for accessing RightNet router
    #
    # @return base URL
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def router_url
      raise RightScale::Exceptions::Unauthorized("Not authorized with RightNet") if state != :authorized
      @router_url
    end

    # Protocol to be used
    #
    # @return [String] "http" or "amqp"
    #
    # @raise [RightScale::Exceptions::Unauthorized] not authorized
    def protocol
      raise RightScale::Exceptions::Unauthorized("Not authorized with RightNet") if state != :authorized
      @protocol
    end

    # An HTTP request received a redirect response
    # Infer from this that need to re-authorize
    #
    # @param [String] location to which response indicated to redirect
    #
    # @return [TrueClass] always true
    def redirect(location)
      Log.info("Renewing auth session because of request redirect to #{location.inspect}")
      renew_session
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @return [TrueClass] always true
    def close
      if state != :closing
        state = :closing
        @renew_timer.cancel if @renew_timer
        @renew_timer = nil
        @reconnect_timer.cancel if @reconnect_timer
        @reconnect_timer = nil
      end
    end

    # Record callback to be notified of status changes
    # Multiple callbacks are supported
    #
    # @yield [type, status] called when status changes
    # @yieldparam [Symbol] type of client reporting status change: :auth
    # @yieldparam [Symbol] state of authorization
    #
    # @return [Symbol] current state
    def status(&callback)
      @status_callbacks = (@status_callbacks || []) << callback if callback
      state
    end

    # Current statistics for this client
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics
    #   [Hash, NilClass] "auth state" Activity stats or nil if none
    #   [Hash, NilClass] "reconnects" Activity stats or nil if none
    #   [Hash, NilClass] "exceptions" Exceptions stats or nil if none
    def stats(reset = false)
      stats = {}
      @stats.each { |k, v| stats[k] = v.all }
      reset_stats if reset
      stats
    end

    protected

    # Reset statistics for this client
    #
    # @return [TrueClass] always true
    def reset_stats
      @stats = {
        "state"      => RightSupport::Stats::Activity.new,
        "reconnects" => RightSupport::Stats::Activity.new,
        "exceptions" => RightSupport::Stats::Exceptions.new(agent = nil, @options[:exception_callback])}
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
      when :authorized, :unauthorized, :expired, :failed
        if value != @state
          @status_callbacks.each do |callback|
            begin
              callback.call(:auth, @state)
            rescue RuntimeError => e
              Log.error("Failed status callback", e)
             @stats["exceptions"].track("status", e)
            end
          end
          @stats["state"].update(value.to_s)
          @state = value
        end
      else
        raise ArgumentError.new("Unknown state: #{value.inspect}")
      end
      @state
    end

    # Create health-checked HTTP client for performing authorization
    #
    # @return [RightSupport::Net::BalancedHttpClient] client
    def create_http_client
      options = {
        :api_version => API_VERSION,
        :open_timeout => DEFAULT_OPEN_TIMEOUT,
        :request_timeout => DEFAULT_REQUEST_TIMEOUT,
        :health_check_path => HEALTH_CHECK_PATH }
      @http_client = RightSupport::Net::BalancedHttpClient.new(@auth_url, options)
    end

    # Create OAuth2 session and as an extension receive URLs needed for other services
    #
    # @return [TrueClass] always true
    #
    # @raise [RightScale::Exceptions::Unauthorized] authorization failed
    # @raise [RightScale::AuthClient::AuthorizationError] could not create OAuth2 session
    def create_session
      redirects = 0

      begin
        Log.info("Creating OAuth2 session via #{URI.parse(@auth_url).hostname}")
        response = @http_client.post("/router/sessions/oauth2", {:r_s_version => AgentConfig.protocol_version})
        @session = response["access_token"]
        @expires_in = response["expires_in"]
        @account_id = response["account_id"]
        update_urls(response)
        state = :authorized
      rescue RestClient::Unauthorized => e
        state = :unauthorized
        @session = @api_url = @router_url = nil
        @expires_in = 0
        raise RightScale::Exceptions::Unauthorized.new(e.http_body, e)
      rescue RightScale::BalancedHttpClient::Redirect => e
        handle_redirect(e, redirects)
        retry
      rescue AuthorizationError
        state = :failed
        raise
      rescue StandardError => e
        @stats["exceptions"].track("create")
        state = :failed
        raise AuthorizationError.new("#{e.class}: #{e.message}")
      end
      true
    end

    # Create OAuth2 session and continuously renew it before it expires
    #
    # @param [Integer] wait time before attempt to renew
    #
    # @return [TrueClass] always true
    def renew_session(wait = 0)
      if @renew_timer && wait == 0
        @renew_timer.cancel
        @renew_timer = nil
      end
      unless @renew_timer
        @renew_timer = EM::Timer.new(wait) do
          @renew_timer = nil
          previous_state = state
          begin
            create_session
            renew_session(@expires_in / RENEW_FACTOR)
          rescue BalancedHttpClient::NotResponding => e
            if wait > MIN_RENEW_TIME
              renew_session(wait / RENEW_FACTOR)
            else
              state = :expired
              reconnect
            end
          rescue RightScale::Exceptions::Unauthorized => e
            renew_session(previous_state == :unauthorized ? UNAUTHORIZED_RENEW_INTERVAL : (wait * RENEW_FACTOR))
          rescue AuthorizationError
            Log.error("Failed OAuth2 session renewal", e)
           @stats["exceptions"].track("renew", e)
            state = :failed
          rescue Exception => e
            Log.error("Failed OAuth2 session renewal", e, :trace)
           @stats["exceptions"].track("renew", e)
            state = :failed
          end
        end
      end
    end

    # Update URLs and recreate client if auth URL has changed
    #
    # @param [Hash] response containing URLs
    #
    # @return [TrueClass] always true
    def update_urls(response)
      @api_url = response["api_url"]
      @router_url = response["router_url"]
      Log.info("Setting API URL to #{@api_url.inspect} and router URL to #{@router_url.inspect}")
      auth_url = URI.parse(response["auth_url"]).merge(@auth_url).to_s
      if auth_url != @auth_url
        Log.info("Resetting auth URL to #{response["auth_url"].inspect}")
        @auth_url = auth_url
        create_http_client
      end
      true
    end

    # Handle redirect by resetting auth_url to requested location
    #
    # @param [RightScale::BalancedHttpClient::Redirect] redirect exception containing new location
    # @param [Integer] redirects so far
    #
    # @return [TrueClass] always true
    #
    # @raise [AuthorizationError] exceeded maximum redirects or no redirect location provided
    def handle_redirect(redirect, redirects)
      if redirect.location.nil? || redirect.location.empty?
        raise AuthorizationError.new("Redirect exception does contain a redirect location")
      elsif redirects > MAX_REDIRECTS
        Log.error("Failed authorization because exceeded maximum redirects (#{MAX_REDIRECTS})")
        raise AuthorizationError.new("Exceeded maximum redirects (#{MAX_REDIRECTS})")
      end
      Log.info("Redirecting auth URL to #{redirect.location.inspect}")
      @stats["state"].update("redirect")
      @auth_url = URI.parse(redirect.location).merge(@auth_url).to_s
      create_http_client
      true
    end

    # Reconnect with authorization service by periodically checking health
    # Delay random interval before starting to check to reduce service spiking
    # When again healthy, renew session
    #
    # @return [TrueClass] always true
    def reconnect
      unless @reconnecting
        @reconnecting = true
        EM.add_timer(rand(HEALTH_CHECK_INTERVAL)) do
          @stats["reconnects"].update("initiate")
          @reconnect_timer = EM::PeriodicTimer.new(HEALTH_CHECK_INTERVAL) do
            begin
              @http_client.get(HEALTH_CHECK_PATH)
              @stats["reconnects"].update("success")
              @reconnect_timer.cancel
              @reconnect_timer = @reconnecting = nil
              renew_session
            rescue BalancedHttpClient::NotResponding => e
              @stats["reconnects"].update("no_response")
            rescue Exception => e
              Log.error("Failed OAuth2 check", e)
              @stats["reconnects"].update("failure")
             @stats["exceptions"].track("check health", e)
            end
          end
        end
      end
      true
    end

  end # InstanceAuthClient

end # RightScale