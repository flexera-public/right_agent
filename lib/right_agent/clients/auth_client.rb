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

  # Abstract base class for authorization client
  class AuthClient

    # State of authorization: :pending, :authorized, :unauthorized, :expired, :failed, :closed
    attr_reader :state

    PERMITTED_STATE_TRANSITIONS = {
      :pending      => [:pending, :authorized, :unauthorized, :failed, :closed],
      :authorized   => [:authorized, :unauthorized, :expired, :failed, :closed],
      :unauthorized => [:authorized, :unauthorized, :failed, :closed],
      :expired      => [:authorized, :unauthorized, :expired, :failed, :closed],
      :failed       => [:failed, :closed],
      :closed      => [:closed] }

    # Initialize client
    # Derived classes need to call reset_stats
    def initialize(options = {})
      raise NotImplementedError, "#{self.class.name} is an abstract class"
    end

    # Identity of agent using this client
    #
    # @return [String] identity
    def identity
      @identity
    end

    # Headers to be added to HTTP request
    # Include authorization header by default
    #
    # @return [Hash] headers to be added to request header
    #
    # @raise [Exceptions::Unauthorized] not authorized
    # @raise [Exceptions::RetryableError] authorization expired, but retry may succeed
    def headers
      check_authorized
      auth_header
    end

    # Authorization header to be added to HTTP request
    #
    # @return [Hash] authorization header
    #
    # @raise [Exceptions::Unauthorized] not authorized
    # @raise [Exceptions::RetryableError] authorization expired, but retry may succeed
    def auth_header
      check_authorized
      {"Authorization" => "Bearer #{@access_token}"}
    end

    # Account if any to which agent using this client belongs
    #
    # @return [Integer] account ID
    #
    # @raise [Exceptions::Unauthorized] not authorized
    def account_id
      check_authorized
      @account_id
    end

    # URL for accessing RightApi including base path
    #
    # @return [String] URL including base path
    #
    # @raise [Exceptions::Unauthorized] not authorized
    # @raise [Exceptions::RetryableError] authorization expired, but retry may succeed
    def api_url
      check_authorized
      @api_url
    end

    # URL for accessing RightNet router including base path
    #
    # @return [String] URL including base path
    #
    # @raise [Exceptions::Unauthorized] not authorized
    # @raise [Exceptions::RetryableError] authorization expired, but retry may succeed
    def router_url
      check_authorized
      @router_url
    end

    # RightNet communication mode
    #
    # @return [Symbol] :http or :amqp
    def mode
      @mode
    end

    # An HTTP request had an authorization expiration error
    # Renew authorization
    #
    # @return [TrueClass] always true
    def expired
      Log.info("Renewing authorization for #{identity} because request failed due to expiration")
      self.state = :expired
      renew_authorization
      true
    end

    # An HTTP request received a redirect response
    #
    # @param [String] location to which response indicated to redirect
    #
    # @return [TrueClass] always true
    def redirect(location)
      true
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @return [TrueClass] always true
    def close
      self.state = :closed
      true
    end

    # Record callback to be notified of authorization status changes
    # Multiple callbacks are supported
    #
    # @yield [type, status] called when status changes (optional)
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
    #   [Hash, NilClass] "state" Activity stats or nil if none
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
        "state" => RightSupport::Stats::Activity.new,
        "exceptions" => RightSupport::Stats::Exceptions.new(agent = nil, @exception_callback)}
      true
    end

    # Check whether authorized
    #
    # @return [TrueClass] always true if don't raise exception
    #
    # @raise [Exceptions::Unauthorized] not authorized
    # @raise [Exceptions::RetryableError] authorization expired, but retry may succeed
    def check_authorized
      if state == :expired
        raise Exceptions::RetryableError, "Authorization expired"
      elsif state != :authorized
        raise Exceptions::Unauthorized, "Not authorized with RightScale" if state != :authorized
      end
      true
    end

    # Renew authorization
    #
    # @param [Integer] wait time before attempt to renew
    #
    # @return [TrueClass] always true
    def renew_authorization(wait = 0)
      true
    end

    # Update authorization state
    # If state has changed, make external callbacks to notify of change
    # Do not update state once set to :closed
    #
    # @param [Hash] value for new state
    #
    # @return [Symbol] updated state
    #
    # @raise [ArgumentError] invalid state transition
    def state=(value)
      return if @state == :closed
      unless PERMITTED_STATE_TRANSITIONS[@state].include?(value)
        raise ArgumentError, "Invalid state transition: #{@state.inspect} -> #{value.inspect}"
      end

      case value
      when :pending, :closed
        @stats["state"].update(value.to_s)
        @state = value
      when :authorized, :unauthorized, :expired, :failed
        if value != @state
          @stats["state"].update(value.to_s)
          @state = value
          (@status_callbacks || []).each do |callback|
            begin
              callback.call(:auth, @state)
            rescue StandardError => e
              Log.error("Failed status callback", e)
             @stats["exceptions"].track("status", e)
            end
          end
        end
      else
        raise ArgumentError, "Unknown state: #{value.inspect}"
      end
      @state
    end

  end # AuthClient

end # RightScale