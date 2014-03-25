require 'restclient'

module RightScale

  # This code is largely borrowed from RestClient

  # Container for response so that access response headers in same fashion as RestClient
  class Response
    attr_reader :headers

    def initialize(headers)
      @headers = headers
    end
  end

  # Base HTTP exception class
  class HttpException < RuntimeError
    attr_writer :message
    attr_reader :http_code, :http_body
    attr_accessor :response

    def initialize(code, body, response = nil)
      @http_code = code
      @http_body = body
      @response = response
    end

    def inspect
      "#{message}: #{http_body}"
    end

    def to_s
      inspect
    end

    def message
      @message || self.class.name
    end

  end

  # Exceptions created for each status code defined in RestClient::STATUSES
  # e.g., RightScale::HttpExceptions::ResourceNotFound for status code 404
  module HttpExceptions

    # Exception when request failed with an error code that is not managed here
    class RequestFailed < HttpException

      def to_s
        message
      end

      def message
        "HTTP status code #{http_code}"
      end
    end

    # Map HTTP status codes to the corresponding exception class
    HTTP_EXCEPTIONS_MAP = {}

    # Create exception for given code
    def self.create(code, body = "", response = nil)
      if HttpExceptions::HTTP_EXCEPTIONS_MAP[code]
        HttpExceptions::HTTP_EXCEPTIONS_MAP[code].new(code, body, response)
      else
        RequestFailed.new(code, body, response)
      end
    end

    # Convert RestClient exception
    def self.convert(e)
      e2 = create(e.http_code, e.http_body, RightScale::Response.new((e.response && e.response.headers) || {}))
      e2.message = e.message
      e2
    end

    RestClient::STATUSES.each do |code, message|
      klass = Class.new(HttpException) do
        send(:define_method, :message) {"#{http_code ? "#{http_code} " : ''}#{message}"}
      end
      klass_constant = const_set(message.delete(' \-\''), klass)
      HTTP_EXCEPTIONS_MAP[code] = klass_constant
    end

  end # HttpExceptions

end # RightScale
