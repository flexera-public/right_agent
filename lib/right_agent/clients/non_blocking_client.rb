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

  # Interface to HTTP using EM::HttpRequest
  # This interface uses non-blocking i/o so that HTTP requests are synchronous
  # to the caller but the underlying thread yields to other activity when blocked on i/o
  class NonBlockingClient

    # Fully configured health check procedure for use with this client
    attr_reader :health_check_proc

    # Hash of active connections with request path as key and hash value containing
    # :host, :connection, and :expires_at
    attr_reader :connections

    # Initialize client
    #
    # @option options [String] :api_version for X-API-Version header
    # @option options [String] :health_check_path in URI for health check resource;
    #   defaults to BalancedHttpClient::DEFAULT_HEALTH_CHECK_PATH
    def initialize(options)
      # Defer requiring this gem until now so that right_agent can be used with ruby 1.8.7
      require 'em-http-request'

      @connections = {}

      # Initialize use of proxy if defined
      if (v = BalancedHttpClient::PROXY_ENVIRONMENT_VARIABLES.detect { |v| ENV.has_key?(v) })
        proxy_uri = ENV[v].match(/^[[:alpha:]]+:\/\//) ? URI.parse(ENV[v]) : URI.parse("http://" + ENV[v])
        @proxy = {:host => proxy_uri.host, :port => proxy_uri.port}
        @proxy[:authorization] = [proxy_uri.user, proxy_uri.password] if proxy_uri.user
      end

      # Create health check proc for use by request balancer
      # Strip user and password from host name since health-check does not require authorization
      @health_check_proc = Proc.new do |host|
        uri = URI.parse(host)
        uri.user = uri.password = nil
        uri.path = uri.path + (options[:health_check_path] || BalancedHttpClient::DEFAULT_HEALTH_CHECK_PATH)
        connect_options = {
          :connect_timeout => BalancedHttpClient::DEFAULT_OPEN_TIMEOUT,
          :inactivity_timeout => BalancedHttpClient::HEALTH_CHECK_TIMEOUT }
        connect_options[:proxy] = @proxy if @proxy
        request_options = {:path => uri.path}
        request_options[:head] = {"X-API-Version" => options[:api_version]} if options[:api_version]
        uri.path = ""
        request(:get, "", uri.to_s, connect_options, request_options)
      end
    end

    # Construct options for HTTP request
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [Hash] params for HTTP request
    # @param [String] request_headers to be applied to request
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :poll_timeout maximum wait for individual poll; defaults to :request_timeout
    #
    # @return [Array] connect and request option hashes
    def options(verb, path, params, request_headers, options)
      poll_timeout = verb == :poll && options[:poll_timeout]
      connect_options = {
        :connect_timeout => options[:open_timeout] || BalancedHttpClient::DEFAULT_OPEN_TIMEOUT,
        :inactivity_timeout => poll_timeout || options[:request_timeout] || BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT }
      connect_options[:proxy] = @proxy if @proxy

      request_body, request_path = if [:get, :delete].include?(verb)
        # Doing own formatting because :query option on EM::HttpRequest does not reliably
        # URL encode, e.g., messes up on arrays in hashes
        [nil, (params.is_a?(Hash) && params.any?) ? path + "?#{BalancedHttpClient.format(params)}" : path]
      else
        request_headers[:content_type] = "application/json"
        [(params.is_a?(Hash) && params.any?) ? JSON.dump(params) : nil, path]
      end
      request_options = {:path => request_path, :body => request_body, :head => request_headers}
      request_options[:keepalive] = true if verb == :poll
      [connect_options, request_options]
    end

    # Make HTTP request
    # Note that the underlying thread is not blocked by the HTTP i/o, but this call itself is blocking
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [String] host name of server
    # @param [Hash] connect_options for HTTP connection
    # @param [Hash] request_options for HTTP request
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [HttpException] HTTP failure with associated status code
    def request(verb, path, host, connect_options, request_options)
      # Finish forming path by stripping path, if any, from host
      uri = URI.parse(host)
      request_options[:path] = uri.path + request_options[:path]
      uri.path = ""

      # Make request an then yield fiber until it completes
      fiber = Fiber.current
      connection = EM::HttpRequest.new(uri.to_s, connect_options)
      http = connection.send(verb, request_options)
      http.errback { fiber.resume(http.error.to_s == "Errno::ETIMEDOUT" ? 504 : 500,
                                  (http.error && http.error.to_s) || "HTTP connection failure for #{verb.to_s.upcase}") }
      http.callback { fiber.resume(http.response_header.status, http.response, http.response_header) }
      Log.info("#{sprintf(".%06u", Time.now.usec)} [#{Thread.current.object_id}][#{Fiber.current.object_id}] LEE REQUEST YIELD")
      response_code, response_body, response_headers = Fiber.yield
      response_headers = beautify_headers(response_headers) if response_headers
      result = BalancedHttpClient.response(response_code, response_body, response_headers, request_options[:head][:accept])
      if request_options[:keepalive]
        expires_at = Time.now + BalancedHttpClient::CONNECTION_REUSE_TIMEOUT
        @connections[path] = {:host => host, :connection => connection, :expires_at => expires_at}
      end
      [result, response_code, response_body, response_headers]
    end

    # Make long-polling request
    # Note that the underlying thread is not blocked by the HTTP i/o, but this call itself is blocking
    #
    # @param [Hash] connection to server from previous request with keys :host, :connection,
    #   and :expires_at, with the :expires_at being adjusted on return
    # @param [Hash] request_options for HTTP request
    # @param [Time] stop_at time for polling
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [HttpException] HTTP failure with associated status code
    def poll(connection, request_options, stop_at)
      uri = URI.parse(connection[:host])
      request_options[:path] = uri.path + request_options[:path]
      poll_again(Fiber.current, connection[:connection], request_options, stop_at)
      code, body, headers = Fiber.yield
      headers = beautify_headers(headers) if headers
      result = BalancedHttpClient.response(code, body, headers, request_options[:head][:accept])
      connection[:expires_at] = Time.now + BalancedHttpClient::CONNECTION_REUSE_TIMEOUT
      [result, code, body, headers]
    end

    protected

    # Repeatedly make long-polling request until receive data or timeout
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [EM:HttpRequest] connection to server from previous request
    # @param [Hash] request_options for HTTP request
    # @param [Time] stop_at time for polling
    #
    # @return [TrueClass] always true
    #
    # @raise [HttpException] HTTP failure with associated status code
    def poll_again(fiber, connection, request_options, stop_at)
      http = connection.send(:get, request_options)
      http.errback { fiber.resume(http.error.to_s == "Errno::ETIMEDOUT" ? 504 : 500,
                                  (http.error && http.error.to_s) || "HTTP connection failure for POLL") }
      http.callback do
        code, body, headers = http.response_header.status, http.response, http.response_header
        if code == 200 && (body.nil? || body == "null") && Time.now < stop_at
          poll_again(fiber, connection, request_options, stop_at)
        else
          fiber.resume(code, body, headers)
        end
      end
      true
    end

    # Beautify response header keys so that in same form as RestClient
    #
    # @param [Hash] headers from response
    #
    # @return [Hash] response headers with keys as lower case symbols
    def beautify_headers(headers)
      headers.inject({}) { |out, (key, value)| out[key.gsub(/-/, '_').downcase.to_sym] = value; out }
    end

  end # NonBlockingClient

end # RightScale
