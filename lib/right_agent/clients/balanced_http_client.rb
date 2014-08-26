#--
# Copyright (c) 2013-2014 RightScale Inc
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

  # HTTP REST client for request-balanced access to RightScale servers
  # Requests can be made using the EventMachine asynchronous HTTP interface
  # in an efficient i/o non-blocking fashion using fibers or they can be made
  # using the RestClient interface; either way they are synchronous to the client
  # For the non-blocking i/o approach this class must be used from a spawned fiber
  # rather than the root fiber
  # This class is intended for use by instance agents and by infrastructure servers
  # and therefore supports both session cookie and global session-based authentication
  class BalancedHttpClient

    # When server not responding and retry is recommended
    class NotResponding < Exceptions::NestedException; end

    # HTTP status codes for which a retry is warranted, which is limited to when server
    # is not accessible for some reason (408, 502, 503) or server response indicates that
    # the request could not be routed for some retryable reason (504)
    RETRY_STATUS_CODES = [408, 502, 503, 504]

    # Default time for HTTP connection to open
    DEFAULT_OPEN_TIMEOUT = 2

    # Time to wait for health check response
    HEALTH_CHECK_TIMEOUT = 5

    # Default time to wait for response from request
    DEFAULT_REQUEST_TIMEOUT = 30

    # Maximum time between uses of an HTTP connection
    CONNECTION_REUSE_TIMEOUT = 5

    # Default health check path
    DEFAULT_HEALTH_CHECK_PATH = "/health-check"

    # Text used for filtered parameter value
    FILTERED_PARAM_VALUE = "<hidden>"

    # Parameters whose contents are also to have filtering applied
    CONTENT_FILTERED_PARAMS = ["payload"]

    # Environment variables to examine for proxy settings, in order
    PROXY_ENVIRONMENT_VARIABLES = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY']

    # Create client for making HTTP REST requests
    #
    # @param [Array, String] urls of server being accessed as array or comma-separated string
    #
    # @option options [String] :api_version for X-API-Version header
    # @option options [String] :server_name of server for use in exceptions; defaults to host name
    # @option options [String] :health_check_path in URI for health check resource;
    #   defaults to DEFAULT_HEALTH_CHECK_PATH
    # @option options [Array] :filter_params symbols or strings for names of request parameters
    #   whose values are to be hidden when logging; also applied to contents of any parameters
    #   in CONTENT_FILTERED_PARAMS; can be augmented on individual requests
    # @option options [Boolean] :non_blocking i/o is to be used for HTTP requests by applying
    #   EM::HttpRequest and fibers instead of RestClient; requests remain synchronous
    def initialize(urls, options = {})
      @urls = split(urls)
      @api_version = options[:api_version]
      @server_name = options[:server_name]
      @filter_params = (options[:filter_params] || []).map { |p| p.to_s }

      # Create appropriate underlying HTTP client
      @http_client = options[:non_blocking] ? NonBlockingClient.new(options) : BlockingClient.new(options)

      # Initialize health check and its use in request balancer
      balancer_options = {:policy => RightSupport::Net::LB::HealthCheck, :health_check => @http_client.health_check_proc }
      @balancer = RightSupport::Net::RequestBalancer.new(@urls, balancer_options)
    end

    # Check health of server
    #
    # @param [String] host name of server
    #
    # @return [Object] health check result from server
    #
    # @raise [NotResponding] server is not responding
    def check_health(host = nil)
      begin
        @http_client.health_check_proc.call(host || @urls.first)
      rescue StandardError => e
        if e.respond_to?(:http_code) && RETRY_STATUS_CODES.include?(e.http_code)
          raise NotResponding.new("#{@server_name || host} not responding", e)
        else
          raise
        end
      end
    end

    def get(*args)
      request(:get, *args)
    end

    def post(*args)
      request(:post, *args)
    end

    def put(*args)
      request(:put, *args)
    end

    def poll(*args)
      request(:poll, *args)
    end

    def delete(*args)
      request(:delete, *args)
    end

    # Make HTTP request
    # If polling, continue to poll until receive data, timeout, or hit error
    # Encode request parameters and response using JSON
    # Apply configured authorization scheme
    # Log request/response with filtered parameters included for failure or debug mode
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [Hash] params for HTTP request
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [String] :request_uuid uniquely identifying request; defaults to random generated UUID
    # @option options [Array] :filter_params symbols or strings for names of request parameters whose
    #   values are to be hidden when logging in addition to the ones provided during object initialization;
    #   also applied to contents of any parameters named :payload
    # @option options [Hash] :headers to be added to request
    # @option options [Numeric] :poll_timeout maximum wait for individual poll; defaults to :request_timeout
    # @option options [Symbol] :log_level to use when logging information about the request other than errors;
    #   defaults to :info
    #
    # @return [Object] result returned by receiver of request
    #
    # @raise [NotResponding] server not responding, recommend retry
    # @raise [HttpException] HTTP failure with associated status code
    def request(verb, path, params = {}, options = {})
      started_at = Time.now
      filter = @filter_params + (options[:filter_params] || []).map { |p| p.to_s }
      log_level = options[:log_level] || :info
      request_uuid = options[:request_uuid] || RightSupport::Data::UUID.generate
      connect_options, request_options = @http_client.options(verb, path, params, request_headers(request_uuid, options), options)

      Log.send(log_level, "Requesting #{verb.to_s.upcase} <#{request_uuid}> " + log_text(path, params, filter))

      used = {}
      result, code, body, headers = if verb != :poll
        rest_request(verb, path, connect_options, request_options, used)
      else
        poll_request(path, connect_options, request_options, options[:request_timeout], started_at, used)
      end

      log_success(result, code, body, headers, used[:host], path, request_uuid, started_at, log_level)
      result
    rescue RightSupport::Net::NoResult => e
      handle_no_result(e, used[:host]) do |e2|
        log_failure(used[:host], path, params, filter, request_uuid, started_at, e2)
      end
    rescue RestClient::Exception => e
      e2 = HttpExceptions.convert(e)
      log_failure(used[:host], path, params, filter, request_uuid, started_at, e2)
      raise e2
    rescue StandardError => e
      log_failure(used[:host], path, params, filter, request_uuid, started_at, e)
      raise
    end

    # Close all persistent connections
    #
    # @param [String] reason for closing
    #
    # @return [TrueClass] always true
    def close(reason)
      @http_client.close(reason) if @http_client
      true
    end

    protected

    # Construct headers for request
    #
    # @param [String] request_uuid uniquely identifying request
    # @param [Hash] options per #request
    #
    # @return [Hash] headers for request
    def request_headers(request_uuid, options)
      headers = {"X-Request-Lineage-Uuid" => request_uuid, :accept => "application/json"}
      headers["X-API-Version"] = @api_version if @api_version
      headers.merge!(options[:headers]) if options[:headers]
      headers["X-DEBUG"] = true if Log.level == :debug
      headers
    end

    # Make REST request
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [Hash] connect_options for HTTP connection
    # @param [Hash] request_options for HTTP request
    # @param [Hash] used container for returning :host used for request;
    #   needed so that can return it even when the request fails with an exception
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [NotResponding] server not responding, recommend retry
    # @raise [HttpException] HTTP failure with associated status code
    def rest_request(verb, path, connect_options, request_options, used)
      result, code, body, headers = @balancer.request do |host|
        uri = URI.parse(host)
        uri.user = uri.password = nil
        used[:host] = uri.to_s
        @http_client.request(verb, path, host, connect_options, request_options)
      end
      [result, code, body, headers]
    end

    # Make long-polling request
    #
    # @param [String] path in URI for desired resource
    # @param [Hash] connect_options for HTTP connection
    # @param [Hash] request_options for HTTP request
    # @param [Integer] request_timeout for a non-nil result
    # @param [Time] started_at time for request
    # @param [Hash] used container for returning :host used for request;
    #   needed so that can return it even when the request fails with an exception
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [NotResponding] server not responding, recommend retry
    # @raise [HttpException] HTTP failure with associated status code
    def poll_request(path, connect_options, request_options, request_timeout, started_at, used)
      result = code = body = headers = nil
      if (connection = @http_client.connections[path]).nil? || Time.now >= connection[:expires_at]
        # Use normal :get request using request balancer for first poll
        result, code, body, headers = rest_request(:get, path, connect_options, request_options.dup, used)
        return [result, code, body, headers] if (Time.now - started_at) >= request_timeout
      end
      if result.nil? && (connection = @http_client.connections[path]) && Time.now < connection[:expires_at]
        begin
          # Continue to poll using same connection until get result, timeout, or hit error
          used[:host] = connection[:host]
          result, code, body, headers = @http_client.poll(connection, request_options, started_at + request_timeout)
        rescue HttpException, RestClient::Exception => e
          raise NotResponding.new(e.http_body, e) if RETRY_STATUS_CODES.include?(e.http_code)
          raise NotResponding.new("Request timeout", e) if e.is_a?(RestClient::RequestTimeout)
          raise
        end
      end
      [result, code, body, headers]
    end

    # Handle no result from balancer
    # Distinguish the not responding case since it likely warrants a retry by the client
    # Also try to distinguish between the targeted server not responding and that server
    # gatewaying to another server that is not responding, so that the receiver of
    # the resulting exception is clearer as to the source of the problem
    #
    # @param [RightSupport::Net::NoResult] no_result exception raised by request balancer when it
    #   could not deliver request
    # @param [String] host server URL where request was attempted
    #
    # @yield [exception] required block called for reporting exception of interest
    # @yieldparam [Exception] exception extracted
    #
    # @return [TrueClass] always true
    #
    # @raise [NotResponding] server not responding, recommend retry
    def handle_no_result(no_result, host)
      server_name = @server_name || host
      e = no_result.details.values.flatten.last
      if no_result.details.empty?
        yield(no_result)
        raise NotResponding.new("#{server_name} not responding", no_result)
      elsif e.respond_to?(:http_code) && RETRY_STATUS_CODES.include?(e.http_code)
        yield(e)
        if e.http_code == 504 && (e.http_body && !e.http_body.empty?)
          raise NotResponding.new(e.http_body, e)
        else
          raise NotResponding.new("#{server_name} not responding", e)
        end
      elsif e.is_a?(RestClient::RequestTimeout)
        # Special case RequestTimeout because http_code is typically nil given no actual response
        yield(e)
        raise NotResponding.new("Request timeout", e)
      else
        yield(e)
        raise e
      end
      true
    end

    # Log successful request completion
    #
    # @param [Object] result to be returned to client
    # @param [Integer, NilClass] code for response status
    # @param [Object] body of response
    # @param [Hash] headers for response
    # @param [String] host server URL where request was completed
    # @param [String] path in URI for desired resource
    # @param [String] request_uuid uniquely identifying request
    # @param [Time] started_at time for request
    # @param [Symbol] log_level to use when logging information about the request
    #   other than errors
    #
    # @return [TrueClass] always true
    def log_success(result, code, body, headers, host, path, request_uuid, started_at, log_level)
      length = (headers && headers[:content_length]) || (body && body.size) || "-"
      duration = "%.0fms" % ((Time.now - started_at) * 1000)
      completed = "Completed <#{request_uuid}> in #{duration} | #{code || "nil"} [#{host}#{path}] | #{length} bytes"
      completed << " | #{result.inspect}" if Log.level == :debug
      Log.send(log_level, completed)
      true
    end

    # Log request failure
    # Also report it as audit entry if an instance is targeted
    #
    # @param [String] host server URL where request was attempted if known
    # @param [String] path in URI for desired resource
    # @param [Hash] params for request
    # @param [Array] filter list of parameters whose value is to be hidden
    # @param [String] request_uuid uniquely identifying request
    # @param [Time] started_at time for request
    # @param [Exception, String] exception or message that should be logged
    #
    # @return [TrueClass] Always return true
    def log_failure(host, path, params, filter, request_uuid, started_at, exception)
      code = exception.respond_to?(:http_code) ? exception.http_code : "nil"
      duration = "%.0fms" % ((Time.now - started_at) * 1000)
      ErrorTracker.log(self, "Failed <#{request_uuid}> in #{duration} | #{code} " + log_text(path, params, filter, host, exception))
      true
    end

    # Generate log text describing request and failure if any
    #
    # @param [String] path in URI for desired resource
    # @param [Hash] params for HTTP request
    # @param [Array, NilClass] filter augmentation to base filter list
    # @param [String] host server URL where request was attempted if known
    # @param [Exception, String, NilClass] exception or failure message that should be logged
    #
    # @return [String] Log text
    def log_text(path, params, filter, host = nil, exception = nil)
      text = "#{path} #{filter(params, filter).inspect}"
      text = "[#{host}#{text}]" if host
      text << " | #{self.class.exception_text(exception)}" if exception
      text
    end

    # Apply parameter hiding filter
    #
    # @param [Hash, Object] params to be filtered with strings or symbols as keys
    # @param [Array] filter names of params as strings (not symbols) whose value is to be hidden;
    #   also filter the contents of any CONTENT_FILTERED_PARAMS
    #
    # @return [Hash] filtered parameters
    def filter(params, filter)
      if filter.empty? || !params.is_a?(Hash)
        params
      else
        filtered_params = {}
        params.each do |k, p|
          s = k.to_s
          if filter.include?(s)
            filtered_params[k] = FILTERED_PARAM_VALUE
          else
            filtered_params[k] = CONTENT_FILTERED_PARAMS.include?(s) ? filter(p, filter) : p
          end
        end
        filtered_params
      end
    end

    # Split string into an array unless nil or already an array
    #
    # @param [String, Array, NilClass] object to be split
    # @param [String, Regex] pattern on which to split; defaults to comma
    #
    # @return [Array] split object
    def split(object, pattern = /,\s*/)
      object ? (object.is_a?(Array) ? object : object.split(pattern)) : []
    end

    public

    # Format query parameters for inclusion in URI
    # It can only handle parameters that can be converted to a string or arrays of same,
    # not hashes or arrays/hashes that recursively contain arrays and/or hashes
    #
    # @param params [Hash] Parameters that are converted to <key>=<escaped_value> format
    #   and any value that is an array has each of its values formatted as <key>[]=<escaped_value>
    #
    # @return [String] Formatted parameter string with parameters separated by '&'
    def self.format(params)
      p = []
      params.each do |k, v|
        if v.is_a?(Array)
          v.each { |v2| p << "#{k.to_s}[]=#{CGI.escape(v2.to_s)}" }
        else
          p << "#{k.to_s}=#{CGI.escape(v.to_s)}"
        end
      end
      p.join("&")
    end

    # Process HTTP response to produce result for client
    # Extract result from location header for 201 response
    # JSON-decode body of other 2xx responses except for 204
    # Raise exception if request failed
    #
    # @param [Integer] code for response status
    # @param [Object] body of response
    # @param [Hash] headers for response
    # @param [Boolean] decode JSON-encoded body on success
    #
    # @return [Object] JSON-decoded response body
    #
    # @raise [HttpException] HTTP failure with associated status code
    def self.response(code, body, headers, decode)
      if (200..207).include?(code)
        if code == 201
          result = headers[:location]
        elsif code == 204 || body.nil? || (body.respond_to?(:empty?) && body.empty?)
          result = nil
        elsif decode
          result = JSON.load(body)
          result = nil if result.respond_to?(:empty?) && result.empty?
        else
          result = body
        end
      else
        raise HttpExceptions.create(code, body, headers)
      end
      result
    end

    # Extract text of exception for logging
    # For RestClient exceptions extract useful info from http_body attribute
    #
    # @param [Exception, String, NilClass] exception or failure message
    #
    # @return [String] exception text
    def self.exception_text(exception)
      case exception
      when String
        exception
      when HttpException, RestClient::Exception
        if exception.http_body.nil? || exception.http_body.empty? || exception.http_body =~ /^<html>| html /
          exception.message
        else
          exception.inspect
        end
      when RightSupport::Net::NoResult, NotResponding
        "#{exception.class}: #{exception.message}"
      when Exception
        backtrace = exception.backtrace ? " in\n" + exception.backtrace.join("\n") : ""
        "#{exception.class}: #{exception.message}" + backtrace
      else
        ""
      end
    end

  end # BalancedHttpClient

end # RightScale
