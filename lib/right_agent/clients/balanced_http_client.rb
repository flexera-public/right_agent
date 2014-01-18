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

require 'restclient'

module RightScale

  # HTTP REST client for request balanced access to RightScale servers
  # It is intended for use by instance agents and by infrastructure servers
  # and therefore supports both session cookie and global session-based authentication
  class BalancedHttpClient

    # When server not responding and retry is recommended
    class NotResponding < Exceptions::NestedException; end

    # HTTP status codes for which a retry is warranted, which is limited to when server
    # is not accessible for some reason (502, 503) or server response indicates that
    # the request could not be routed for some retryable reason (504)
    RETRY_STATUS_CODES = [502, 503, 504]

    # Default time for HTTP connection to open
    DEFAULT_OPEN_TIMEOUT = 2

    # Default time to wait for health check response
    HEALTH_CHECK_TIMEOUT = 5

    # Default time to wait for response from request
    DEFAULT_REQUEST_TIMEOUT = 30

    # Default health check path
    DEFAULT_HEALTH_CHECK_PATH = "/health-check"

    # Text used for filtered parameter value
    FILTERED_PARAM_VALUE = "<hidden>"

    # Create client for making HTTP REST requests
    #
    # @param [Array, String] urls of server being accessed as array or comma-separated string
    #
    # @option options [String] :api_version for X-API-Version header
    # @option options [String] :server_name of server for use in exceptions; defaults to host name
    # @option options [String] :health_check_path in URI for health check resource;
    #   defaults to DEFAULT_HEALTH_CHECK_PATH
    # @option options [Array] :filter_params symbols or strings for names of request parameters
    #   whose values are to be hidden when logging; can be augmented on individual requests
    def initialize(urls, options = {})
      @urls = split(urls)
      @api_version = options[:api_version]
      @server_name = options[:server_name]
      @filter_params = (options[:filter_params] || []).map { |p| p.to_s }

      # Create health check proc for use by request balancer
      # Strip user and password from host name since health-check does not require authorization
      @health_check_proc = Proc.new do |host|
        uri = URI.parse(host)
        uri.user = uri.password = nil
        uri.path = uri.path + (options[:health_check_path] || DEFAULT_HEALTH_CHECK_PATH)
        check_options = {
          :open_timeout => DEFAULT_OPEN_TIMEOUT,
          :timeout => HEALTH_CHECK_TIMEOUT }
        check_options[:headers] = {"X-API-Version" => @api_version} if @api_version
        RightSupport::Net::HTTPClient.new.get(uri.to_s, check_options)
      end

      # Initialize request balancer
      balancer_options = {
        :policy => RightSupport::Net::LB::HealthCheck,
        :health_check => @health_check_proc }
      @balancer = RightSupport::Net::RequestBalancer.new(@urls, balancer_options)
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

    def delete(*args)
      request(:delete, *args)
    end

    def check_health(host = nil)
      @health_check_proc.call(host || @urls.first)
    end

    protected

    # Make request via request balancer
    # Encode request parameters and response using JSON
    # Apply configured authorization scheme
    # Log request/response and for failure or in debug include filtered params
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [Hash] params for HTTP request
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [String] :request_uuid uniquely identifying request; defaults to random generated UUID
    # @option options [Array] :filter_params symbols or strings for names of request
    #   parameters whose values are to be hidden when logging in addition to the ones
    #   provided during object initialization
    # @option options [Hash] :headers to be added to request
    #
    # @return [Object] result returned by receiver of request
    #
    # @raise [NotResponding] server not responding, recommend retry
    def request(verb, path, params = {}, options = {})
      result = nil
      host_picked = nil
      started_at = Time.now
      filter = @filter_params + (options[:filter_params] || []).map { |p| p.to_s }
      request_uuid = options[:request_uuid] || RightSupport::Data::UUID.generate

      Log.info("Requesting #{verb.to_s.upcase} <#{request_uuid}> " + log_text(path, params, filter))

      begin
        request_options = {
          :open_timeout => options[:open_timeout] || DEFAULT_OPEN_TIMEOUT,
          :timeout => options[:request_timeout] || DEFAULT_REQUEST_TIMEOUT,
          :headers => {
            "X-Request-Lineage-Uuid" => request_uuid,
            :accept => "application/json" } }
        request_options[:headers]["X-API-Version"] = @api_version if @api_version
        request_options[:headers].merge!(options[:headers]) if options[:headers]

        if [:get, :delete].include?(verb)
          request_options[:query] = params if params.is_a?(Hash) && params.any?
        else
          request_options[:payload] = JSON.dump(params)
          request_options[:headers][:content_type] = "application/json"
        end

        response = @balancer.request do |host|
          uri = URI.parse(host)
          uri.user = uri.password = nil
          host_picked = uri.to_s
          RightSupport::Net::HTTPClient.new.send(verb, host + path, request_options)
        end
      rescue RightSupport::Net::NoResult => e
        handle_no_result(e, host_picked) do |e2|
          report_failure(host_picked, path, params, filter, request_uuid, started_at, e2)
        end
      rescue Exception => e
        report_failure(host_picked, path, params, filter, request_uuid, started_at, e)
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
      display = "Completed <#{request_uuid}> in #{duration} | #{status} [#{host_picked}#{path}] | #{length} bytes"
      display << " #{result.inspect}" if Log.level == Logger::DEBUG
      Log.info(display)

      result
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
      elsif (e.respond_to?(:http_code) && RETRY_STATUS_CODES.include?(e.http_code))
        yield(e)
        if e.http_code == 504 && (e.http_body && !e.http_body.empty?)
          raise NotResponding.new(e.http_body, e)
        else
          raise NotResponding.new("#{server_name} not responding", e)
        end
      else
        yield(e)
        raise e
      end
      true
    end

    # Report request failure to logs
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
    def report_failure(host, path, params, filter, request_uuid, started_at, exception)
      status = exception.respond_to?(:http_code) ? exception.http_code : "nil"
      duration = "%.0fms" % ((Time.now - started_at) * 1000)
      Log.error("Failed <#{request_uuid}> in #{duration} | #{status} " + log_text(path, params, filter, host, exception))
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
      filtered_params = (exception || Log.level == Logger::DEBUG) ? filter(params, filter).inspect : nil
      text = filtered_params ? "#{path} (#{filtered_params})" : path
      text = "[#{host}#{text}]" if host
      text << " | #{self.class.exception_text(exception)}" if exception
      text
    end

    # Apply parameter hiding filter
    #
    # @param [Hash, Object] params to be filtered
    # @param [Array] filter names of params as strings (not symbols) whose value is to be hidden
    #
    # @return [Hash] filtered parameters
    def filter(params, filter)
      if filter.empty? || !params.is_a?(Hash)
        params
      else
        filtered_params = {}
        params.each { |k, p| filtered_params[k] = filter.include?(k.to_s) ? FILTERED_PARAM_VALUE : p }
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
      when RestClient::Exception
        if exception.http_body.nil? || exception.http_body.empty? || exception.http_body =~ /^<html>/
          exception.message
        else
          exception.inspect
        end
      when RightSupport::Net::NoResult
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
