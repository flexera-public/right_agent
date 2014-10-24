#--
# Copyright (c) 2014 RightScale Inc
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

  # Authorization client for use with RabbitMQ broker
  class BrokerAuthClient < AuthClient

    DEFAULT_API_PORT = 15672

    attr_reader :broker_url

    # Create HTTP authorization client for RabbitMQ broker
    #
    # @param [String] user name
    # @param [String] password
    # @param [String] broker_host name for accessing broker
    def initialize(user, password, broker_host)
      @access_token = RightSupport::Net::StringEncoder.new(:base64).encode("#{user}:#{password}")
      scheme = RAILS_ENV =~ /development/ ? "http" : "https"
      @broker_url = URI::Generic.build(:scheme => scheme, :host => broker_host, :port => DEFAULT_API_PORT, :path => "/api").to_s
      @state = :authorized
    end

    # Authorization header to be added to HTTP request
    #
    # @return [Hash] authorization header
    def auth_header
      {"Authorization" => "Basic #{@access_token}"}
    end
  end

  # HTTP interface to RabbitMQ brokers
  class BrokerHttpClient

    include RightSupport::Ruby::EasySingleton

    DEFAULT_HEALTH_CHECK_VHOST = "/"

    # Create HTTP client for each broker
    #
    # @param [String] user name
    # @param [String] password
    # @param [Array, String] broker_hosts to which all HTTP requests
    #   are to be submitted, as an array or a comma-separated list
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Numeric] :reconnect_interval for reconnect attempts after lose connectivity
    # @option options [Boolean] :non_blocking i/o is to be used for HTTP requests by applying
    #   EM::HttpRequest and fibers instead of RestClient; requests remain synchronous
    # @option options [Array] :filter_params symbols or strings for names of request parameters whose
    #   values are to be hidden when logging; also applied to contents of any parameters named :payload
    # @option options [String] :health_check_vhost used for aliveness-test; defaults to DEFAULT_HEALTH_CHECK_VHOST
    #
    # @return [TrueClass] always true
    def init(user, password, broker_hosts, options = {})
      @clients = {}
      broker_hosts = broker_hosts.split(/,\s*/) if broker_hosts.is_a?(String)
      vhost = RightSupport::Net::StringEncoder.new(:url).encode(options[:health_check_vhost] || DEFAULT_HEALTH_CHECK_VHOST)
      broker_hosts.each do |host|
        auth_client = BrokerAuthClient.new(user, password, host)
        client_options = options.merge(:server_name => "RabbitMQ",
                                       :health_check_path => "/aliveness-test/#{vhost}",
                                       :health_check_headers => auth_client.auth_header,
                                       :api_version => "1.0")
        @clients[host] = BaseRetryClient.new(:broker, auth_client, client_options)
      end
      true
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

    # Make HTTP request to each client
    #
    # @param [Symbol] verb for HTTP REST request
    # @param [String] path in URI for desired resource; it gets appended to /api
    # @param [Hash] params for HTTP request
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [String] :request_uuid uniquely identifying request; defaults to random generated UUID
    # @option options [Array] :filter_params symbols or strings for names of request parameters whose
    #   values are to be hidden when logging in addition to the ones provided during object initialization;
    #   also applied to contents of any parameters named :payload
    # @option options [Hash] :headers to be added to request
    # @option options [Symbol] :log_level to use when logging information about the request other than errors;
    #   defaults to :info
    # @option options [Array] :broker_hosts to which request is to be limited to
    #
    # @return [Hash] result returned by each client
    #
    # @raise [NotResponding] server not responding, recommend retry
    # @raise [HttpException] HTTP failure with associated status code
    def request(verb, path, params = {}, options = {})
      result = {}
      (options[:broker_hosts] || @clients.keys).each do |host|
        begin
          if @clients[host].state == :connected
            result[host] = @clients[host].make_request(verb, path, params, nil, options)
          else

          end
        rescue StandardError => e
          result[host] = e
        end
      end
      result
    end

  end # BrokerHttpClient

end # RightScale
