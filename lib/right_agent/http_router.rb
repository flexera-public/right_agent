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

# TODO This is a temporary hack to deal with lack of global_session gem in instance
begin require 'global_session'; rescue LoadError; end

module RightScale

  # Provides support for routing requests over HTTP to AMQP and back.  The functionality
  # is similar to RightScale::Sender except that requests here are synchronous.
  # Also provides ancillary functions like creating the X.509 certificate for an instance.
  # It is intended for use in rails environment such as right_site or library and depends
  # on RAILS_DEFAULT_LOGGER being defined. It applies OAuth global session for authorization
  # in the infrastructure servers it accesses.
  module HttpRouter

    # Initialize underlying HTTP client
    # This is required for use of other functions
    #
    # @param source [String] Generic name of server using this service for use in global session
    # @param urls [Array, String] HTTP URLs of server being accessed as array or comma-separated string
    # @param config_dir [String] Directory path for global session configuration information
    #
    # @option options [Array] :filter_params Symbols for payload parameters to be filtered when logging
    #
    # @return [TrueClass] Always return true
    def self.init(source, urls, config_dir, options = {})
      @client = Client.new(source, urls, config_dir, options)
      true
    end

    # Route a request to a single target or multiple targets with no response expected
    # Do not persist the request en route
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request
    # Set time-to-live to be forever
    #
    # @param type [String] RightNet dispatch route for the request
    # @param payload [Object] Request data
    # @param target [String, Hash, NilClass] Identity of specific target, hash for selecting
    #   potentially multiple targets, or nil if routing solely using type. Hash may contain:
    #   :tags [Array] Tags that must all be associated with a target for it to be selected
    #   :scope [Hash] Scoping to be used to restrict routing
    #     :account [Integer] Restrict to agents with this account id
    #     :shard [Integer] Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector [Symbol] Which of the matched targets to be selected, either :any or :all,
    #     defaults to :any
    #
    # @return [TrueClass] Always return true
    #
    # @raise [RightScale::Exceptions::ConnectivityFailure] Cannot connect to Router or
    #   Router cannot deliver message
    # @raise [RightScale::Exceptions::Application] Message could not be processed by target
    def self.push(type, payload = nil, target = nil)
      client.post_request("/router/push", type, payload, target)
      true
    end

    # Route a request to a single target or multiple targets with no response expected
    # Persist the request en route to reduce the chance of it being lost at the expense of some
    # additional network overhead
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request
    # Set time-to-live to be forever
    #
    # @param type [String] RightNet dispatch route for the request
    # @param payload [Object] Request data
    # @param target [String, Hash, NilClass] Identity of specific target, hash for selecting
    #   potentially multiple targets, or nil if routing solely using type. Hash may contain:
    #   :tags [Array] Tags that must all be associated with a target for it to be selected
    #   :scope [Hash] Scoping to be used to restrict routing
    #     :account [Integer] Restrict to agents with this account id
    #     :shard [Integer] Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector [Symbol] Which of the matched targets to be selected, either :any or :all,
    #     defaults to :any
    #
    # @return [TrueClass] Always return true
    #
    # @raise [RightScale::Exceptions::ConnectivityFailure] Cannot connect to Router or
    #   Router cannot deliver message
    # @raise [RightScale::Exceptions::Application] Message could not be processed by target
    def self.persistent_push(type, payload = nil, target = nil)
      client.post_request("/router/persistent_push", type, payload, target)
      true
    end

    # Route a request to a single target and wait for a response from it
    # Automatically retry the request if a response is not received in a reasonable amount of time
    # or if there is a non-delivery response indicating the target is not currently available
    # Timeout the request if a response is not received in time, typically configured to 1 minute
    # Because of retries there is the possibility of duplicated requests, and these are detected and
    # discarded automatically for non-idempotent actions
    # Allow the request to expire per the agent's configured time-to-live, typically 1 minute
    #
    # @param type [String] RightNet dispatch route for the request
    # @param payload [Object] Request data
    # @param target [String, Hash, NilClass] Identity of specific target, hash for selecting targets
    #   of which one is picked randomly, or nil if routing solely using type. Hash may contain:
    #   :tags [Array] Tags that must all be associated with a target for it to be selected
    #   :scope [Hash] Behavior to be used to resolve tag based routing with the following keys:
    #     :account [String] Restrict to agents with this account id
    #
    # @return [Object] Response from request
    #
    # @raise [RightScale::Exceptions::ConnectivityFailure] Cannot connect to Router or
    #   Router cannot deliver message
    # @raise [RightScale::Exceptions::Application] Message could not be processed by target
    def self.retryable_request(type, payload = nil, target = nil)
      client.post_request("/router/retryable_request", type, payload, target)
    end

    def self.response(token, result, from, request_from, duration)
      client.post_response("/router/response", token, result, from, request_from, duration)
    end

    def self.stats(from, stats)
      client.post_stats("/router/stats", from, stats)
    end

    def self.wait_for_event(agent_id)
      client.get_event("/router/event", agent_id)
    end

    # Generate an RSA key pair and return it along with a corresponding self-signed certificate
    #
    # @param uuid [String] Universally unique identifier to be included in certificate's Common Name field
    #
    # @return [Array] RightScale::Certificate and RightScale::RsaKeyPair
    def self.create_certificate(uuid)
      key     = RightScale::RsaKeyPair.new
      subject = RightScale::DistinguishedName.new({
        'C'  => 'US',
        'ST' => 'California',
        'L'  => 'Santa Barbara',
        'O'  => 'RightScale, Inc.',
        'OU' => 'Operations',
        'CN' => uuid })
      issuer = subject # This is a self-signed certificate

      [RightScale::Certificate.new(key, issuer, subject).data, key.data]
    end

    protected

    def self.client
      raise Exception.new("RightScale::HttpRouter.init was not called to initialize client") unless @client
      @client
    end

    # HTTP client for request balanced access to the RightNet router
    class Client

      # RightNet router API version
      API_VERSION = "1.0"

      # Text used for filtered parameter value
      FILTERED_PARAM_VALUE = "<hidden>"

      # Interval between successive retries and the maximum elapsed time until stop retrying
      # These are chosen to be consistent with the retry sequencing for RightNet retryable_requests
      # (per :retry_interval and :retry_timeout agent deployer configuration parameters for router),
      # so that if the retrying happens within the router, it will not retry here
      RETRY_INTERVALS = [4, 12, 36]
      RETRY_TIMEOUT = 25

      # Request timeout, which is chosen to be 5 seconds greater than the response timeout
      # inside the router
      REQUEST_TIMEOUT = 35
      OPEN_TIMEOUT = 2
      HEALTH_CHECK_TIMEOUT = 5

      # Event timeout
      EVENT_TIMEOUT = 60

      # HTTP status codes that are to be retried, which is limited to when RightNet router
      # is not accessible for some reason (502, 503) or router response indicates that
      # the request could not be routed for some retryable reason (504)
      RETRY_STATUS_CODES = [502, 503, 504]

      # Default logger
      attr_reader :logger

      # Create balancer for making AMQP requests over HTTP
      #
      # @param source [String] Generic name of server using this service for use in global session
      # @param urls [Array, String] HTTP URLs of server being accessed as array or comma-separated string
      # @param config_dir [String] Directory path for global session configuration information
      #
      # @option options [Array] :filter_params Symbols for payload parameters to be filtered when logging
      def initialize(source, urls, config_dir, options = {})
        @filter_params = options[:filter_params] || []
        @source = source
        @urls = urls.is_a?(Array) ? urls : urls.split(/,\s*/)
        @config_dir = config_dir
        @logger = defined?(RAILS_DEFAULT_LOGGER) ? RAILS_DEFAULT_LOGGER : RightScale::Log

        # Create health check proc for use by request balancer
        @health_check = Proc.new do |host|
          options = {
            :timeout => HEALTH_CHECK_TIMEOUT,
            :open_timeout => OPEN_TIMEOUT,
            :headers => {"X-API-Version" => API_VERSION} }
          RightSupport::Net::HTTPClient.new.get(host + "/router/health-check", options)
        end

        # Initialize request balancer
        options = {:policy => RightSupport::Net::LB::HealthCheck, :health_check => @health_check}
        @balancer = RightSupport::Net::RequestBalancer.new(@urls, options)

        # Initialize global session directory
        if config_dir
          config = GlobalSession::Configuration.new(File.join(@config_dir, "global_session.yml"), ENV["RAILS_ENV"])
          if (directory = config["directory"])
            @global_session_dir = directory.constantize.new(config, File.join(@config_dir, "authorities"))
          else
            @global_session_dir = GlobalSession::Directory.new(config, File.join(@config_dir, "authorities"))
          end
          @global_session_timeout = (config["timeout"] * 8) / 10
        end
      end

      # Post request via balancer
      # Retry request on routing failures and when told to retry
      # Log request/response omitting unfiltered payload/results except when failure or in debug
      #
      # There are several possible levels of retry involved here starting with the outermost:
      #   1. RequestBalancer will retry using other endpoints if it gets an error that it considers
      #      retryable, and even if a front-end balancer is in use there will likely be two at least
      #      two endpoints for redundancy
      #   2. This method will retry if there is a routing failure it considers retryable or if
      #      it receives a retry request, but not exceeding an elapsed time of RETRY_TIMEOUT.
      #   3. The RightNet router when processing a retryable_request will retry if it receives no
      #      response, but not exceeding its configured :retry_timeout. If its timeouts for retry
      #      are consistent with the ones here, #2 above will not be applied if this level is.
      #
      # There are also several timeouts involved:
      #   1. RestClient connection open timeout (OPEN_TIMEOUT)
      #   2. RestClient request timeout (REQUEST_TIMEOUT)
      #   3. Retry timeout for this method (RETRY_TIMEOUT)
      #   4. Router response timeout (ideally > RETRY_TIMEOUT and < REQUEST_TIMEOUT)
      #   5. Router retry timeout (ideally = RETRY_TIMEOUT)
      #
      # @param uri [String] Dispatch route to AMQP sender to be appended to host to form full URL
      # @param type [String] RightNet dispatch route for the request
      # @param payload [Object] Request data
      # @param target [String, Hash, NilClass] Identity of specific target, hash for selecting
      #   potentially multiple targets, or nil if routing solely using type
      #
      # @return [Object] Result returned by receiver of request
      #
      # @raise [RightScale::Exceptions::ConnectivityFailure] Cannot connect to Router or
      #   Router cannot deliver message
      # @raise [RightScale::Exceptions::Application] Message could not be processed by target
      def post_request(uri, type, payload, target)
        result = nil
        host_picked = nil
        started_at = Time.now
        original_request_uuid = request_uuid = RightSupport::Data::UUID.generate
        retries = 0

        logger.info("Requesting POST <#{request_uuid}> " + log_text(uri, type, payload, target))

        begin
          options = {
            :timeout => REQUEST_TIMEOUT,
            :open_timeout => OPEN_TIMEOUT,
            :query => {
              :type => type,
              :request_token => request_uuid },
            :payload => JSON.dump({:payload => payload}),
            :headers => {
              "X-Request-Lineage-Uuid" => request_uuid,
              "X-API-Version" => API_VERSION,
              "Authorization" => "Bearer #{infrastructure_cookie}",
            :content_type => "application/json" } }
          options[:query][:target] = target if target

          response = @balancer.request do |host|
            host_picked = host
            RightSupport::Net::HTTPClient.new.post(host + uri, options)
          end
        rescue RestClient::RetryWith => e
          if retries < 1 && (interval = RETRY_INTERVALS[retries]) && (Time.now - started_at) < RETRY_TIMEOUT
            logger.error("Retrying #{type} request <#{original_request_uuid}> in #{interval} seconds " +
                         "in response to RightNet retryable error (#{e.http_body})")
            sleep(interval)
            request_uuid << " retry" # So that retried request not rejected as duplicate
            retries += 1
            retry
          else
            report_failure(host_picked, uri, type, payload, target, original_request_uuid, started_at, e, false)
            raise RightScale::Exceptions::RetryableError.new(e.http_body, e)
          end
        rescue RightSupport::Net::NoResult => e
          if e.details.empty? || e.details[host_picked].nil? || ((exception = e.details[host_picked].last) &&
             exception.respond_to?(:http_code) && RETRY_STATUS_CODES.include?(exception.http_code))
            # Note that after a retry the RequestBalancer may return no details in the exception
            # (e.g., because there were no endpoints to try that had passed the health check) in
            # which case the exception variable value used below may be from a previous attempt
            # and that is used here because it is likely more valuable than just saying no result
            # especially as the final disposition if all retries fail
            e = exception || e
            if (interval = RETRY_INTERVALS[retries]) && (Time.now - started_at) < RETRY_TIMEOUT
              logger.error("Retrying #{type} request <#{original_request_uuid}> in #{interval} seconds " +
                           "in response to RightNet routing failure (#{exception_text(e)})")
              sleep(interval)
              retries += 1
              retry
            else
              report_failure(host_picked, uri, type, payload, target, original_request_uuid, started_at, e, true)
              raise RightScale::Exceptions::ConnectivityFailure.new("Cannot process #{type} request because RightNet routing failed " +
                                                                    "after #{retries + 1} attempts (#{exception_text(e)})")
            end
          else
            e = exception || e
            report_failure(host_picked, uri, type, payload, target, original_request_uuid, started_at, e, true)
            raise e
          end
        rescue RestClient::UnprocessableEntity => e
          report_failure(host_picked, uri, type, payload, target, original_request_uuid, started_at, e, false)
          raise RightScale::Exceptions::Application.new(e.message)
        rescue Exception => e
          report_failure(host_picked, uri, type, payload, target, original_request_uuid, started_at, e, true)
          raise
        end

        if response.nil? || response.code == 204 || (response.body.respond_to?(:empty?) && response.body.empty?) ||
           (result = JSON.load(response.body)).nil? || (result.respond_to?(:empty?) && result.empty?)
          result = nil
        end

        status = response ? response.code : "nil"
        duration = "%.0fms" % ((Time.now - started_at) * 1000)
        length =  if response
          response.headers[:content_length] ? response.headers[:content_length] : response.body.size
        else
          "-"
        end
        display = "Completed <#{original_request_uuid}> in #{duration} | #{status} [#{host_picked}#{uri}] | #{length} bytes"
        display << " #{result.inspect}" if logger.level == Logger::DEBUG
        logger.info(display)

        result
      end

      # Request an event
      #
      # @param agent_id [String] Serialized identity of agent requesting event
      # @param uri [String] Dispatch route to AMQP event receiver to be appended to host to form full URL
      #
      # @return [Object, NilClass] Event received, or nil if none
      #
      # @raise [RightScale::Exceptions::ConnectivityFailure] Cannot connect to Router
      def get_event(uri, agent_id)
        result = nil
        host_picked = nil
        started_at = Time.now

        logger.info("Requesting GET event for #{agent_id}")

        begin
          options = {
            :timeout => EVENT_TIMEOUT,
            :open_timeout => OPEN_TIMEOUT,
            :query => {
              :agent_id => agent_id,
              :wait_time => EVENT_TIMEOUT - 5,
              :timestamp => started_at.to_f },
            :headers => {
              "X-API-Version" => API_VERSION,
              :content_type => "application/json" } }

          response = @balancer.request do |host|
            host_picked = host
            RightSupport::Net::HTTPClient.new.get(host + uri, options)
          end
        rescue Exception => e
          no_result = e.is_a?(RightSupport::Net::NoResult)
          e = e.details[host_picked].last unless !e.respond_to?(:details) || e.details.empty? || e.details[host_picked].nil?
          status = e.respond_to?(:http_code) ? e.http_code : "nil"
          duration = "%.0fms" % ((Time.now - started_at) * 1000)
          logger.error("Failed GET event in #{duration} | #{status} | #{e.class}: #{e.message}")
          raise RightScale::Exceptions::ConnectivityFailure.new("RightNet router not responding") if no_result
          raise
        end

        if response.nil? || response.code == 204 || (response.body.respond_to?(:empty?) && response.body.empty?) ||
           (result = JSON.load(response.body)).nil? || (result.respond_to?(:empty?) && result.empty?)
          result = nil
        end

        status = response ? response.code : "nil"
        duration = "%.0fms" % ((Time.now - started_at) * 1000)
        length =  if response
          response.headers[:content_length] ? response.headers[:content_length] : response.body.size
        else
          "-"
        end
        display = "Completed GET event in #{duration} | #{status} [#{host_picked}#{uri}] | #{length} bytes"
        logger.info(display)

        result
      end

      protected

      # Report request failure to logs
      # Also report it as audit entry if an instance is targeted
      #
      # @param host [String] HTTP URL for server where request was attempted
      # @param uri [String] HTTP dispatch route to AMQP sender to be appended to host to form full URL
      # @param type [String] RightNet dispatch route for the request
      # @param payload [Object] Request data
      # @param target [String, Hash, NilClass] Identity of specific target, hash for selecting
      #   potentially multiple targets, or nil if routing solely using type
      # @param request_uuid [String] UUID uniquely identifying request
      # @param started_at [Time] Time when request processing started
      # @param exception [Exception, String] Exception or message that should be logged
      # @param notify [Boolean] Whether to send a user notification if an instance is the target
      #
      # @return [TrueClass] Always return true
      def report_failure(host, uri, type, payload, target, request_uuid, started_at, exception, notify)
        status = exception.respond_to?(:http_code) ? exception.http_code : "nil"
        duration = "%.0fms" % ((Time.now - started_at) * 1000)
        logger.error("Failed <#{request_uuid}> in #{duration} | #{status} " +
                     log_text(uri, type, payload, target, host, exception))

        parsed_identity = (AgentIdentity.parse(target) rescue nil)
        if notify && parsed_identity && parsed_identity.agent_type == "instance"
          # Note: Instance API tokens are not accessible from the Account class
          # In this case it's safe to do a lookup not scoped to an account as the token id
          # comes from an internal query
          api_token = InstanceApiToken.find_by_id(parsed_identity.base_id)
          if api_token && (instance = api_token.instance)
            summary = "Request failed"
            detail = "Failed to send request to instance #{instance.resource_uid}."
            options = {}
            if payload.is_a?(Hash) && (audit_id = payload[:audit_id])
              entry = instance.account.audit_entries.find_by_id(audit_id)
              options[:audit_entry] = entry if entry
            end
            EventSystem.event!(instance, instance.account, UserNotification::CATEGORY_ERROR, summary, detail, options)
          end
        end
      end

      # Generate log text describing request and failure if any
      #
      # @param uri [String] Dispatch route to AMQP sender to be appended to host to form full URL
      # @param type [String] RightNet dispatch route for the request
      # @param payload [Object] Request data
      # @param target [String, Hash, NilClass] Identity of specific target, hash for selecting targets
      #   of which one is picked randomly, or nil if routing solely using type
      # @param host [String] HTTP URL for server where request was attempted if known
      # @param exception [Exception, String, NilClass] Exception or failure message that should be logged
      #
      # @return [String] Log text
      def log_text(uri, type, payload, target, host = nil, exception = nil)
        payload = (exception || logger.level == Logger::DEBUG) ? filter(payload).inspect : "..."
        text = "#{uri}(#{type}, #{payload}) to #{target.inspect}"
        text = "[#{host}#{text}]" if host
        text << " | #{exception_text(exception)}" if exception
        text
      end

      # Extract text of exception for logging
      #
      # @param exception [Exception, String, NilClass] Exception or failure message
      #
      # @return [String] Exception text
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
      # @param params [Hash, Object] Parameters to be filtered
      #
      # @return [Hash, Object] Filtered parameters
      def filter(params)
        if @filter_params.empty? || !params.is_a?(Hash)
          params
        else
          filtered_params = {}
          params.each { |k, p| filtered_params[k] = @filter_params.include?(k) ? FILTERED_PARAM_VALUE : p }
          filtered_params
        end
      end

      # Retrieve or create global session cookie for infrastructure agent
      # Cache session and only recreate when times out
      #
      # @return [String] Infrastructure cookie
      def infrastructure_cookie
        now = Time.now
        if @infrastructure_session && (now - @infrastructure_session[:created_at]) < @global_session_timeout
          @infrastructure_session[:cookie]
        else
          global_session = GlobalSession::Session.new(@global_session_dir)
          global_session["infrastructure"] = @source
          cookie = global_session.to_s
          @infrastructure_session = { :cookie => cookie, :created_at => now }
          cookie
        end
      end

    end # Client

  end # HttpRouter

end # RightScale

