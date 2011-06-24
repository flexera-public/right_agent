# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.

require 'rubygems'
require 'rest_client'
require 'cgi'

module RightScale

  # Wrapper class for performing REST queries as needed by RightNet
  # for accessing the Cassandra-based RightNetDataService and TagService
  class RightNetRestClient

    class UnprocessableEntity < Exception; end
    class QueryFailure < Exception; end

    include StatsHelper

    # Create REST client
    #
    # === Parameters
    # services(Hash):: Services to be accessed with key same as used for 'service' parameter
    #   in queries, e.g., :rnds or :tags, and with value being a hash of :urls (String) and
    #   :usage_stats (ActivityStats)
    # exception_stats(ExceptionStats):: Statistics updated with any exceptions that are caught
    def initialize(services, exception_stats = nil)
      @services = services
      @urls = {}
      @usage_stats = {}
      @services.each { |k, v| @urls[k] = v[:urls]; @usage_stats[k] = v[:usage_stats] }
      @exception_stats = exception_stats
      @query_token = 0
    end

    # Wrappers for REST queries

    def get(service, uri, params = nil, options = {})
      query(:get, service, uri, params, options)
    end

    def put(service, uri, params = nil, options = {})
      query(:put, service, uri, params, options)
    end

    def post(service, uri, params = nil, options = {})
      query(:post, service, uri, params, options)
    end

    def delete(service, uri, params = nil, options = {})
      query(:delete, service, uri, params, options)
    end

    protected

    # Perform REST query
    # Catch and log all exceptions but reraise UnprocessableEntity
    #
    # === Parameters
    # type(Symbol):: Type of query (:get, :put, :post, or :delete)
    # service(Symbol):: Service being accessed, e.g., :rnds or :tags
    # uri(String):: URI path to be added to hostname to form universal resource identifier
    #   for accessing desired service
    # params(Hash):: Parameters to query
    # options(Hash):: Query options
    #   :filter_params(Array):: Name of parameters to filter
    #   :raise_exceptions(Boolean):: Whether to raise exception with failure reason for
    #      unexpected exceptions in addition to logging them
    #
    # === Return
    # (Object|nil):: JSON unserialized response, or nil if there was an error
    #
    # === Raise
    # UnprocessableEntity:: If receive RestClient::UnprocessableEntity exception
    # QueryFailure:: If unexpected query failure and :raise_exceptions option is set
    def query(type, service, uri, params, options)
      filtered_params = {}
      filter_params = options[:filter_params] || []
      params.each { |k, v| filtered_params[k] = filter_params.include?(k) ? "****"  : v  } if params
      response = nil
      host = ""
      begin
        # Currently RightSupport::Net::REST #get and #delete ignore parameters so add to URI
        uri2 = uri.dup
        params2 = params
        if params && [:get, :delete].include?(type)
          uri2 << "?#{format(params)}"
          params2 = nil
        end
        usage_stats = @usage_stats[service]
        started_at = usage_stats ? usage_stats.update(type, @query_token += 1) : Time.now

        callback = lambda do |fatal, e, host|
          if fatal
            Log.error("Failed #{query_log(type, service, host, uri, filtered_params)}", e, :no_trace)
          else
            Log.error("Retried #{query_log(type, service, host, uri, filtered_params)}", e, :no_trace)
          end
        end

        RightSupport::Net::RequestBalancer.request(@urls[service], :on_exception => callback) do |host|
          response = RightSupport::Net::REST.__send__(type, host + uri2, params2)
          duration = usage_stats ? usage_stats.finish(started_at, @query_token) : Time.now - started_at
          duration = StatsHelper::Utilities.enough_precision(duration)
          Log.info("#{query_log(type, service, host, uri, filtered_params)} (#{(response || "").size} bytes, #{duration} sec)")
          response
        end
        if response.nil? || response.empty? || (response = JSON.load(response)).nil? || response.empty?
          response = nil
        end
      rescue RestClient::ResourceNotFound
      rescue RestClient::UnprocessableEntity => e
        raise UnprocessableEntity.new("Request cannot be processed: #{reason(e)}")
      rescue Exception => e
        @exception_stats.track(service.to_s, e) if @exception_stats
        if reason = reason(e)
          reason = " (#{reason})"
        end
        msg = "Failed #{service.to_s.upcase} [#{type}] query#{reason} with #{host + uri} #{filtered_params.inspect}"
        Log.error(msg, e)
        raise (reason ? QueryFailure.new(reason(e)) : e) if options[:raise_exceptions]
      end
      response
    end

    # Generate log header for given query
    #
    # === Parameters
    # type(Symbol):: Type of query (:get, :put, :post, or :delete)
    # service(Symbol):: Service being accessed, e.g., :rnds or :tags
    # host(String):: Server hostname
    # uri(String):: URI path to be added to hostname to form universal resource identifier
    #   for accessing desired service
    # params(Hash):: Parameters to query
    #
    # === Return
    # log(String):: Resulting log header text
    def query_log(type, service, host, uri, params)
      log = "#{service.to_s.upcase} [#{type}] #{(host || '') + uri} #{(params || {}).inspect}"
    end

    # Format query parameters for inclusion in URI
    #
    # === Parameters
    # params(Hash):: Parameters that are converted to <key>=<escaped_value> format
    #   and any value that is an array has each of its values formatted as <key>[]=<escaped_value>
    #
    # === Return
    # (String):: Formatted parameter string with parameters separated by '&'
    def format(params)
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

    # Extract failure reason from exception if it exists
    # Optionally JSON parse the reason
    #
    # === Parameters
    # exception(Exception):: Exception
    #
    # === Return
    # (String):: Failure reason in the format ": <reason>", or "" if none found
    def reason(exception)
      reason = ""
      if exception.respond_to?(:response) && exception.response
        begin
          if (r = JSON.parse(exception.response)) && !r.empty? && (e = r["error"])
            reason = e
          else
            reason = exception.response
          end
        rescue Exception
          reason = exception.response
        end
      end
      reason
    end

  end # RightNetRestClient

end # RightScale
