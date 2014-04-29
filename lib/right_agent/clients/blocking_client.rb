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

require 'restclient'

module RightScale

  # Interface to HTTP using RightSupport::Net::HTTPClient and RestClient
  # This interfaces blocks the given thread until an HTTP response is received
  class BlockingClient

    # Fully configured health check procedure for use with this client
    attr_reader :health_check_proc

    # Hash of active connections with request path as key and hash value containing
    # :host and :expires_at
    attr_reader :connections

    # Initialize client
    #
    # @option options [String] :api_version for X-API-Version header
    # @option options [String] :health_check_path in URI for health check resource;
    #   defaults to DEFAULT_HEALTH_CHECK_PATH
    def initialize(options)
      @connections = {}

      # Initialize use of proxy if defined
      if (v = BalancedHttpClient::PROXY_ENVIRONMENT_VARIABLES.detect { |v| ENV.has_key?(v) })
        proxy_uri = ENV[v].match(/^[[:alpha:]]+:\/\//) ? URI.parse(ENV[v]) : URI.parse("http://" + ENV[v])
        RestClient.proxy = proxy_uri.to_s if proxy_uri
      end

      # Create health check proc for use by request balancer
      # Strip user and password from host name since health-check does not require authorization
      @health_check_proc = Proc.new do |host|
        uri = URI.parse(host)
        uri.user = uri.password = nil
        uri.path = uri.path + (options[:health_check_path] || BalancedHttpClient::DEFAULT_HEALTH_CHECK_PATH)
        request_options = {
          :open_timeout => BalancedHttpClient::DEFAULT_OPEN_TIMEOUT,
          :timeout => BalancedHttpClient::HEALTH_CHECK_TIMEOUT }
        request_options[:headers] = {"X-API-Version" => options[:api_version]} if options[:api_version]
        request(:get, "", uri.to_s, {}, request_options)
      end
    end

    # Construct options for HTTP request
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource (ignored)
    # @param [Hash] params for HTTP request
    # @param [String] request_headers to be applied to request
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :poll_timeout maximum wait for individual poll; defaults to :request_timeout
    #
    # @return [Array] connect and request option hashes
    def options(verb, path, params, request_headers, options)
      request_options = {
        :open_timeout => options[:open_timeout] || BalancedHttpClient::DEFAULT_OPEN_TIMEOUT,
        :timeout => options[:poll_timeout] || options[:request_timeout] || BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT,
        :headers => request_headers }

      if [:get, :delete].include?(verb)
        # Doing own formatting because :query option for HTTPClient uses addressable gem
        # for conversion and that gem encodes arrays in a Rails-compatible fashion without []
        # markers and that is inconsistent with what sinatra expects
        request_options[:query] = "?#{BalancedHttpClient.format(params)}" if params.is_a?(Hash) && params.any?
      else
        request_options[:payload] = JSON.dump(params)
        request_options[:headers][:content_type] = "application/json"
      end
      [{}, request_options]
    end

    # Make HTTP request
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource
    # @param [String] host name of server
    # @param [Hash] connect_options for HTTP connection (ignored)
    # @param [Hash] request_options for HTTP request
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [HttpException] HTTP failure with associated status code
    def request(verb, path, host, connect_options, request_options)
      url = host + path + request_options.delete(:query).to_s
      result = request_once(verb, url, request_options)
      @connections[path] = {:host => host, :path => path, :expires_at => Time.now + BalancedHttpClient::CONNECTION_REUSE_TIMEOUT }
      result
    end

    # Make long-polling requests until receive data, hit error, or timeout
    #
    # @param [Hash] connection to server from previous request with keys :host, :path,
    #   and :expires_at, with the :expires_at being adjusted on return
    # @param [Hash] request_options for HTTP request
    # @param [Time] stop_at time for polling
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [HttpException] HTTP failure with associated status code
    def poll(connection, request_options, stop_at)
      url = connection[:host] + connection[:path] + request_options.delete(:query).to_s
      begin
        result, code, body, headers = request_once(:get, url, request_options)
      end until result || Time.now >= stop_at
      connection[:expires_at] = Time.now + BalancedHttpClient::CONNECTION_REUSE_TIMEOUT
      [result, code, body, headers]
    end

    # Close all persistent connections
    #
    # @param [String] reason for closing
    #
    # @return [TrueClass] always true
    def close(reason)
      @connections = {}
      true
    end

    protected

    # Make HTTP request once
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] url for request
    # @param [Hash] request_options for HTTP request
    #
    # @return [Array] result to be returned followed by response code, body, and headers
    #
    # @raise [HttpException] HTTP failure with associated status code
    def request_once(verb, url, request_options)
      if (r = RightSupport::Net::HTTPClient.new.send(verb, url, request_options))
        [BalancedHttpClient.response(r.code, r.body, r.headers, request_options[:headers][:accept]), r.code, r.body, r.headers]
      else
        [nil, nil, nil, nil]
      end
    end

  end # BlockingClient

end # RightScale