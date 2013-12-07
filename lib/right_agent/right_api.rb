#--
# Copyright (c) 2013 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.
#++

require File.join(File.dirname(__FILE__), 'core_payload_types')

module RightScale

  # HTTP interface to RightApi for use by RightNet agents
  class RightApi

    include OperationResultHelper

    # Request parameter name map
    PARAM_NAME_MAP = {
      :agent_identity => :agent_id,
      :klass          => :class_name }

    # HTTP status codes that are to be retried
    RETRY_STATUS_CODES = [502, 503, 504]

    # Maximum length of an audit summary as enforced by RightApi and database
    MAX_AUDIT_SUMMARY_LENGTH = 255

    # Sleep interval after encountering long-polling error
    LONG_POLL_ERROR_SLEEP = 5

    # Create API interface
    #
    # @param [Agent] agent using API
    #
    # @option options [Hash] :actor_api_map from actor-based request types to API verb and URI
    # @option options [Array] :filter_params Symbols for payload parameters to be filtered when logging
    def initialize(agent, options)
      @agent = agent
      @options = options
      @actor_api_map = options[:actor_api_map]
      HttpRouter.init("instance", [ENV["RS_RN_URL"]], nil)
      @client = Client.new([ENV["RS_API_URL"]], options)
      @account_id, api_token = ENV["RS_API_TOKEN"].split(":")
      @client.post("/api/session/instance", {:account_href => "/api/accounts/#{@account_id}", :instance_token => api_token})
      response = @client.get("/api/session/instance", {})
      @instance_href = response["links"].select { |link| link["rel"] == "self" }.first["href"]
      reset_stats
    end

    def online?

    end

    # Dispatch request via HTTP
    # Rely on underlying HTTP client to log request and response
    # Concatenate audit ID and request token for identifying request in HTTP header
    # For "not responding" failures when this request is a Push or is marked persistent,
    # retry dispatch repeatedly until TTL, if any, expires or until terminating in which
    # case do not ack request so that it gets requeued
    #
    # @param [Push, Request] request packet
    #
    # @return [Result, NilClass] result of request with nil meaning no result to return
    def make_request(request)
      actor, action = request.type.split('/')[1..-1]
      received_at = @request_send_stats.update(action, request.token)

      begin
        params = parameterize(request)
        verb, uri = @actor_api_map[request.type]
        raise ArgumentError, "Unknown request type #{request.type}" if verb.nil?
        options = {:request_token => [params[:audit_id], request.token]}
        if actor == "auditor"
          # Need to translate audit payload to API parameters
          result = make_audit_request(action, verb, uri, params, options)
        elsif actor == "mapper" && action =~ /tags/
          # Need to translate tags payload to API parameters
          result = make_tags_request(action, verb, uri, params, options)
        elsif actor == "instance_scheduler"
          # Needs to go through router for mapping to multiple targets
          HttpRouter.push(request.type, request.payload, request.target)
          result = nil
        else
          result = @client.send(verb, uri, params, options)
        end
        result = success_result(result)
      rescue RightSupport::Net::NoResult => e
        # This indicates the request balancer could not obtain a result
        result = handle_no_result(e, request, action)
      rescue RestClient::RetryWith => e
        # This indicates a retryable error for which the retry responsibility
        # is to be passed back to the original requester
        result = retry_result(e.http_body)
      rescue RestClient::Forbidden => e
        if e.http_body =~ /duplicate/
          # This indicates a duplicate request for which the response needs to be killed
          from_retry = e.http_body =~ /retry/ ? "retry " : ""
          Log.info("Rejecting #{from_retry.upcase}request #{request.trace} because already serviced")
          @request_reject_stats.update("#{from_retry}duplicate (#{action})")
          result = nil
        else
          result = handle_exception(request.trace, action, e)
        end
      rescue RestClient::Conflict => e
        # This indicates a state_recorder structured error result
        result = error_result(JSON.load(e.http_body))
      rescue ArgumentError => e
        result = error_result(e.message)
      rescue Exception => e
        result = handle_exception(request.trace, action, e)
      end

      @request_send_stats.finish(received_at, request.token)

      if result && request.is_a?(Request)
        result = Result.new(request.token, request.reply_to, result, @agent.identity, request.from,
                            request.tries, request.persistent)
        result.received_at = received_at.to_f
      else
        result = nil
      end
      result
    end

    # Receive requests via HTTP long-polling
    # Send any responses to the requests via HTTP
    # May be requested from thread different than otherwise used with this class
    #
    # @yield [request] required block invoked each time request received
    # @yieldparam [Packet] request received
    #
    # @return [TrueClass] always true
    def receive_requests(&handler)
      loop do
        # TODO Only use long poll if cannot create websocket
        begin
          if (request = HttpRouter.wait_for_event(@agent.identity))
            @request_receive_stats.update(request.type)
            handler.call(request)
          end
        rescue Exception => e
          trace = e.is_a?(RightScale::Exceptions::ConnectivityFailure) ? :no_trace : :trace
          Log.error("Failed long-poll", e, trace)
          sleep(LONG_POLL_ERROR_SLEEP)
        end
      end
      true
    end

    # Send response to previously received request
    #
    # @param [Result] result to be sent
    #
    # @return [TrueClass] always true
    def respond(result)
      HttpRouter.response(result.token, result.results, result.from, result.request_from, result.duration)
      true
    end

    # Report current agent statistics to RightNet
    def publish_stats(stats)
      HttpRouter.stats(@agent.identity, stats)
      true
    end

    # Get API interface statistics
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics
    #   "exceptions" [Hash, NilClass] Exceptions raised per category, or nil if none
    #     "total" [Integer] Total for category
    #     "recent" [Array] Most recent as a hash of "count", "type", "message", "when", and "where"
    #   "rejects" [Hash, NilClass] Request reject activity stats with keys "total", "percent", "last",
    #     and "rate" with percentage breakdown per reason ("duplicate (<method>)", "retry duplicate
    #     (<method>)", or "stale (<method>)"), or nil if none
    #   "request failures" [Hash, NilClass] Request failure activity stats with keys "total",
    #    "percent", "last", and "rate" with percentage breakdown per failure type, or nil if none
    #   "requests" [Hash, NilClass] Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    #   "response time" [Float] Average number of seconds to respond to a request recently
    def stats(reset = false)
      stats = {
        "exceptions"        => @exception_stats.stats,
        "request failures"  => @request_failure_stats.all,
        "requests received" => @request_receive_stats.all,
        "request rejects"   => @request_reject_stats.all,
        "requests sent"     => @request_send_stats.all,
        "response time"     => @request_send_stats.avg_duration
      }
      reset_stats if reset
      stats
    end

    protected

    # Reset API interface statistics
    #
    # @return [TrueClass] always true
    def reset_stats
      @request_failure_stats = RightSupport::Stats::Activity.new
      @request_receive_stats = RightSupport::Stats::Activity.new
      @request_reject_stats = RightSupport::Stats::Activity.new
      @request_send_stats = RightSupport::Stats::Activity.new
      @exception_stats = RightSupport::Stats::Exceptions.new(@agent, @agent.exception_callback)
      true
    end

    # Convert payload of request packet to parameters for HTTP request
    # The request token and tries values are parameterized as :request_token
    # and :request_tries as needed for duplicate request detection by the
    # controller receiving the request
    # The :agent_id parameter continues to be passed to the API even
    # though the API no longer references it (still useful for tracking)
    #
    # @param [Push, Request] request packet
    #
    # @return [Hash] HTTP parameters
    def parameterize(request)
      params = {
        :request_token => request.token,
        :account_id    => @account_id }
      params[:request_tries] = request.tries unless request.tries.empty?
      if (payload = request.payload) && payload.is_a?(Hash)
        payload.each { |k, v| params[PARAM_NAME_MAP[k.to_sym] || k.to_sym] = v }
      end
      params
    end

    # Retrieve base parameters
    #
    # @param [Hash] params from HTTP request
    #
    # @return [Hash] Base parameters
    def base_params(params)
      result = {}
      result[:agent_id] = params[:agent_id] if params[:agent_id]
      result[:request_tries] = params[:request_tries] if params[:request_tries]
      result
    end

    # Translate tags request to one or more RightApi requests
    #
    # @param [String] action requested: query_tags or update_tags
    # @param [Symbol] verb for REST request
    # @param [String] uri to route request to at host URL; in the case of an
    #   update_tags request the uri is missing the "add" or "delete" suffix
    # @param [Hash] params from HTTP request
    # @param [Hash] options for HTTP request
    #
    # @return [Object] result of request
    def make_tags_request(action, verb, uri, params, options)
      result = nil
      case action
      when "query_tags"
        result = @client.send(verb, uri, {:resource_hrefs => [@instance_href]}, options)
      when "update_tags"
        {:new_tags => "add", :obsolete_tags => "delete"}.each do |param, operation|
          tags = Array(params[param]).flatten.compact
          result = @client.send(verb, uri + operation, {:resource_hrefs => [@instance_href], :tags => tags}, options) if tags.any?
        end
      end
      result
    end

    # Translate audit request to one or more RightApi requests
    # Truncate audit summary to MAX_AUDIT_SUMMARY_LENGTH if sending to RightApi
    #
    # @param [String] action requested: create_entry or update_entry
    # @param [Symbol] verb for REST request
    # @param [String] uri to route request at host URL
    # @param [Hash] params from HTTP request
    # @param [Hash] options for HTTP request
    #
    # @return [Object] result of request
    #
    # @raise [ArgumentError] Unknown request action
    def make_audit_request(action, verb, uri, params, options)
      uri = uri.sub(/:id/, params[:audit_id].to_s || "")
      params.delete(:audit_id)
      case action
      when "create_entry"
        create_params = base_params(params)
        create_params[:audit_entry] = {
            :auditee_href => @instance_href,
            :summary      => truncate(params[:summary], MAX_AUDIT_SUMMARY_LENGTH) }
        create_params[:audit_entry][:detail] = params[:detail] if params[:detail]
        create_params[:user_email] = params[:user_email] if params[:user_email]
        create_params[:notify] = params[:category] if params[:category]
        result = @client.send(verb, uri, create_params, options)
        # Convert returned audit entry href to audit ID
        result.sub!(/^.*\/api\/audit_entries\//, "")
      when "update_entry"
        update_params = base_params(params)
        update_params[:offset] = params[:offset] if params[:offset]
        if (summary = params[:summary]) && !summary.empty?
          update_params[:summary] = truncate(summary, MAX_AUDIT_SUMMARY_LENGTH)
          update_params[:notify] = params[:category] if params[:category]
        end
        if (detail = params[:detail]) && !detail.empty?
          update_params[:detail] = detail
        end
        result = @client.send(verb, uri, update_params, options)
      else
        raise ArgumentError.new("Unknown audit request action: #{action}")
      end
      result
    end

    # Truncate string if it exceeds maximum length
    # Do length check with bytesize rather than size since this code
    # is running with ruby 1.9.2 while the API uses 1.8.7, otherwise
    # multi-byte characters could cause this code to be too lenient
    #
    # @param [String, NilClass] value to be truncated
    # @param [Integer] max_length allowed; must be greater than 3
    #
    # @return [String, NilClass] truncated string or original value if it is not a string
    #
    # @raise [ArgumentError] max_length too small
    def truncate(value, max_length)
      raise ArgumentError.new("max_length must be greater than 3") if max_length <= 3
      if value.is_a?(String) && value.bytesize > max_length
        max_truncated = max_length - 3
        truncated = value[0, max_truncated]
        while truncated.bytesize > max_truncated do
          truncated.chop!
        end
        truncated + "..."
      else
        value
      end
    end

    # Handle no result from server by determining whether it is a retryable
    #
    # @param [RightSupport::Net::NoResult] no_result exception raised by request balancer when it
    #   could not deliver request including details about why
    # @param [Push, Request] request packet sent
    # @param [String] action requested
    #
    # @return [OperationResult] final result
    def handle_no_result(no_result, request, action)
      exception = no_result.details.values.flatten.last
      if (exception.respond_to?(:http_code) && RETRY_STATUS_CODES.include?(exception.http_code)) || no_result.details.empty?
        @request_failure_stats.update("#{action} - API not responding")
        result = retry_result("RightScale API not responding")
      else
        result = handle_exception(request.trace, action, exception || no_result)
      end
      result
    end

    # Handle fatal exception from HTTP request
    #
    # @param [String] trace identifying request
    # @param [String] action requested
    # @param [Exception] exception that was raised
    #
    # @return [OperationResult] error result to respond with
    def handle_exception(trace, action, exception)
      message = "Fatal error when making request #{trace}"
      if exception.respond_to?(:http_body)
        Log.error("#{message} (#{exception.inspect})")
        @request_failure_stats.update("#{action} - #{exception.http_code}")
        result = exception.inspect
      else
        Log.error(message, exception, :trace)
        @request_failure_stats.update("#{action} - #{exception.class.name}")
        @exception_stats.track("request", exception)
        result = exception.message
      end
      error_result(result)
    end

    # HTTP client for request balanced access to the RightNet router
    class Client

      # RightApi version
      API_VERSION = "1.5"

      # Health check URI for API
      HEALTH_CHECK_URI = "/api/right_net/health-check"

      # Text used for filtered parameter value
      FILTERED_PARAM_VALUE = "<hidden>"

      # Default time for HTTP connection to open
      DEFAULT_OPEN_TIMEOUT = 2

      # Default time to wait for response from request
      DEFAULT_REQUEST_TIMEOUT = 30

      # Default time to wait for health check response
      HEALTH_CHECK_TIMEOUT = 5

      # Create balancer for making API requests
      #
      # @param [Array] urls of server being accessed as array or comma-separated string
      #
      # @option options [Array] :filter_params Symbols for payload parameters to be filtered when logging
      def initialize(urls, options = {})
        @filter_params = options[:filter_params] || []

        # Create health check proc for use by request balancer
        @health_check = Proc.new do |host|
          check_options = {
            :open_timeout => DEFAULT_OPEN_TIMEOUT,
            :timeout => HEALTH_CHECK_TIMEOUT,
            :headers => {"X-API-Version" => API_VERSION} }
          RightSupport::Net::HTTPClient.new.get(host + HEALTH_CHECK_URI, check_options)
        end

        # Initialize request balancer
        balancer_options = {
          :policy => RightSupport::Net::LB::HealthCheck,
          :health_check => @health_check }
        @balancer = RightSupport::Net::RequestBalancer.new(urls, balancer_options)
      end

      # Copied from activesupport/lib/active_support/inflector/methods.rb
      def constantize(camel_cased_word)
        names = camel_cased_word.split('::')
        names.shift if names.empty? || names.first.empty?

        names.inject(Object) do |constant, name|
          if constant == Object
            constant.const_get(name)
          else
            candidate = constant.const_get(name)
            next candidate if constant.const_defined?(name, false)
            next candidate unless Object.const_defined?(name)

            # Go down the ancestors to check it it's owned
            # directly before we reach Object or the end of ancestors.
            constant = constant.ancestors.inject do |const, ancestor|
              break const    if ancestor == Object
              break ancestor if ancestor.const_defined?(name, false)
              const
            end

            # owner is in Object, so raise
            constant.const_get(name, false)
          end
        end
      end

      def get(*args)
        make_request(:get, *args)
      end

      def post(*args)
        make_request(:post, *args)
      end

      def put(*args)
        make_request(:put, *args)
      end

      def delete(*args)
        make_request(:delete, *args)
      end

      protected

      # Submit request to API via request balancer
      # Log request/response omitting unfiltered params/results except when failure or in debug
      #
      # @param [Symbol] verb for REST request
      # @param [String] uri to route request at host URL
      # @param [Hash] params for HTTP request
      #
      # @option options [Fixnum] :timeout maximum time to wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
      # @option options [Fixnum] :open_timeout maximum time to wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
      # @option options [String] :request_token uniquely identifying request; defaults to random generated UUID
      #
      # @return [Object] Result returned by receiver of request
      def make_request(verb, uri, params, options = {})
        result = nil
        host_picked = nil
        started_at = Time.now
        request_token = options[:request_token] || RightSupport::Data::UUID.generate
        if request_token.is_a?(Array)
          request_trace = request_token.map { |t| "<#{t}>" }.join(" ")
          request_token = request_token.compact.join(":")
        else
          request_trace = "<#{request_token}>"
        end

        Log.info("Requesting #{verb.to_s.upcase} #{request_trace} " + log_text(uri, params))

        begin
          request_options = {
            :open_timeout => options[:open_timeout] || DEFAULT_OPEN_TIMEOUT,
            :timeout => options[:timeout] || DEFAULT_REQUEST_TIMEOUT,
            :headers => {
              "X-Request-Lineage-Uuid" => request_token,
              "X-API-Version" => API_VERSION,
              :accept => "application/json"},
            :query => {
              :request_token => request_token } }
          request_options[:headers][:cookies] = @cookies if @cookies
          if [:get, :delete].include?(verb)
            request_options[:query].merge!(params)
          else
            request_options[:payload] = JSON.dump(params)
            request_options[:headers][:content_type] = "application/json"
          end

          response = @balancer.request do |host|
            host_picked = host
            RightSupport::Net::HTTPClient.new.send(verb, host + uri, request_options)
          end
        rescue Exception => e
          report_failure(host_picked, uri, params, request_trace, started_at, e)
          raise
        end

        if response.nil? || response.code == 204 || (response.body.respond_to?(:empty?) && response.body.empty?) ||
           (result = JSON.load(response.body)).nil? || (result.respond_to?(:empty?) && result.empty?)
          result = nil
        end

        status = response ? response.code : "nil"
        duration = "%.0fms" % ((Time.now - started_at) * 1000)
        length =  if response
          @cookies = response.cookies unless response.cookies.empty?
          response.headers[:content_length] ? response.headers[:content_length] : response.body.size
        else
          "-"
        end
        display = "Completed #{request_trace} in #{duration} | #{status} [#{host_picked}#{uri}] | #{length} bytes"
        display << " #{result.inspect}" if Log.level == Logger::DEBUG
        Log.info(display)

        result
      end

      # Report request failure to logs
      # Also report it as audit entry if an instance is targeted
      #
      # @param [String] host server URL where request was attempted if known
      # @param [String] uri to route request at host URL
      # @param [String] request_trace uniquely identifying request
      # @param [Time] started_at time when request started
      # @param [Exception, String] exception or message that should be logged
      #
      # @return [TrueClass] Always return true
      def report_failure(host, uri, params, request_trace, started_at, exception)
        status = exception.respond_to?(:http_code) ? exception.http_code : "nil"
        duration = "%.0fms" % ((Time.now - started_at) * 1000)
        Log.error("Failed <#{request_trace}> in #{duration} | #{status} " +
                     log_text(uri, params, host, exception))
        true
      end

      # Generate log text describing request and failure if any
      #
      # @param [String] uri to route request at host URL
      # @param [Hash] params for HTTP request
      # @param [String] host server URL where request was attempted if known
      # @param [Exception, String, NilClass] exception or failure message that should be logged
      #
      # @return [String] Log text
      def log_text(uri, params, host = nil, exception = nil)
        filtered_params = (exception || Log.level == Logger::DEBUG) ? filter(params).inspect : "..."
        text = "#{uri}(#{filtered_params})"
        text = "[#{host}#{text}]" if host
        text << " | #{exception_text(exception)}" if exception
        text
      end

      # Extract text of exception for logging
      #
      # @param [Exception, String, NilClass] exception or failure message
      #
      # @return [String] exception text
      def exception_text(exception)
        case exception
        when String
          exception
        when RestClient::Exception
          if exception.http_body.nil? || exception.http_body.empty? || exception.http_body =~ /^<html>/
            exception.message
          else
            exception.inspect
          end
        when Exception
          backtrace = exception.backtrace ? " in\n" + exception.backtrace.join("\n") : ""
          "#{exception.class}: #{exception.message}" + backtrace
        else
          ""
        end
      end

      # Apply parameter filter
      #
      # @param [Hash, Object] params to be filtered
      #
      # @return [Hash, Object] filtered parameters
      def filter(params)
        if @filter_params.empty? || !params.is_a?(Hash)
          params
        else
          filtered_params = {}
          params.each { |k, p| filtered_params[k] = @filter_params.include?(k) ? FILTERED_PARAM_VALUE : p }
          filtered_params
        end
      end

    end # Client

  end # RightApi

end # RightScale
