# Copyright (c) 2014 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and
# the licensee.

module RightScale

  # Tracker for unexpected errors
  # Logs them with appropriate trace information
  # Accumulates statistics about exceptions
  # Reports exceptions to external Errbit service via Airbrake
  class ErrorTracker

    include RightSupport::Ruby::EasySingleton

    # Text used for filtered parameter value
    FILTERED_PARAM_VALUE = "<hidden>"

    # Container for exception statistics
    attr_reader :exception_stats

    # Initialize error tracker
    #
    # @param [Object] agent object using this tracker
    # @param [String] agent_name uniquely identifying agent process on given server
    #
    # @option options [Integer, NilClass] :shard_id identifying shard of database in use
    # @option options [Hash] :trace_level for restricting backtracing and Errbit reporting
    #   with exception class as key and :no_trace, :caller, or :trace as value; exceptions
    #   with :no_trace are not backtraced when logging nor are they recorded in stats
    #   or reported to Errbit
    # @option options [Array<Symbol, String>] :filter_params names whose values are to be
    #   filtered when notifying
    # @option options [String] :airbrake_endpoint URL for Airbrake for reporting exceptions
    #   to Errbit
    # @option options [String] :airbrake_api_key for using the Airbrake API to access Errbit
    #
    # @return [TrueClass] always true
    def init(agent, agent_name, options = {})
      @agent = agent
      @trace_level = options[:trace_level] || {}
      notify_init(agent_name, options)
      reset_stats
      true
    end

    # Log error and optionally track in stats
    # Errbit notification is left to the callback configured in the stats tracker
    # Logging works even if init was never called
    #
    # @param [String, Object] component reporting error; non-string is snake-cased
    # @param [String] description of failure for use in logging
    # @param [Exception, String] exception to be logged and tracked in stats;
    #   string errors are logged but not tracked in stats
    # @param [Packet, Hash, NilClass] packet associated with exception
    # @param [Symbol, NilClass] trace level override unless excluded by configured
    #   trace levels
    #
    # @return [Boolean] true if successfully logged, otherwise false
    def log(component, description, exception = nil, packet = nil, trace = nil)
      if exception.nil?
        Log.error(description)
      elsif exception.is_a?(String)
        Log.error(description, exception)
      else
        trace = (@trace_level && @trace_level[exception.class]) || trace || :trace
        Log.error(description, exception, trace)
        track(component, exception, packet) if trace != :no_trace
      end
      true
    rescue StandardError => e
      Log.error("Failed to log error", e, :trace) rescue nil
      false
    end

    # Track error in stats
    #
    # @param [String] component reporting error
    # @param [Exception] exception to be tracked
    # @param [Packet, Hash, NilClass] packet associated with exception
    #
    # @return [TrueClass] always true
    def track(component, exception, packet = nil)
      if @exception_stats
        component = component.class.name.split("::").last.snake_case unless component.is_a?(String)
        @exception_stats.track(component, exception, packet)
      end
      true
    end

    # Notify Errbit of error if notification enabled
    #
    # @param [Exception, String] exception raised
    # @param [Packet, Hash] packet associated with exception
    # @param [Object] agent object reporting error
    # @param [String,Object] component or service area where error occurred
    #
    # @return [TrueClass] always true
    def notify(exception, packet = nil, agent = nil, component = nil)
      if @notify_enabled
        if packet && packet.is_a?(Packet)
          action = packet.type.split("/").last if packet.respond_to?(:type)
          params = packet.respond_to?(:payload) && packet.payload
          uuid = packet.respond_to?(:token) && packet.token
        elsif packet.is_a?(Hash)
          action_path = packet[:path] || packet["path"]
          action = action_path.split("/").last if action_path
          params = packet[:data] || packet["data"]
          uuid = packet[:uuid] || packet["uuid"]
        else
          params = uuid = nil
        end

        component = component.class.name unless component.is_a?(String)

        n = Airbrake.build_notice(
          exception,
          { component: component, action: action },
          :right_agent )

        n[:params] = params.is_a?(Hash) ? filter(params) : {:param => params} if params
        n[:session] = { :uuid => uuid } if uuid

        if agent
          n[:environment] = (@cgi_data || {}).merge(:agent_class => agent.class.name)
        elsif @cgi_data
          n[:environment] = @cgi_data || {}
        end

        Airbrake.notify(n, {}, :right_agent)
      end
      true
    rescue Exception => e
      raise if e.class.name =~ /^RSpec/ # keep us from going insane while running tests
      Log.error("Failed to notify Errbit", e, :trace)
    end

    # Create proc for making callback to notifier
    #
    # @return [Proc] notifier callback
    def notify_callback
      Proc.new do |exception, packet, agent, component|
        notify(exception, packet, agent, component)
      end
    end

    # Get exception statistics
    #
    # @param reset [Boolean] Whether to reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics
    def stats(reset = false)
      stats = {"exceptions" => @exception_stats && @exception_stats.all}
      reset_stats if reset
      stats
    end

    protected

    # Reset statistics
    # Do not recreate exception stats since may be referenced externally
    #
    # @return [TrueClass] always true
    def reset_stats
      @exception_stats ||= RightSupport::Stats::Exceptions.new(@agent, notify_callback)
      @exception_stats.reset
    end

    # Configure Airbrake for exception notification
    #
    # @param [String] agent_name uniquely identifying agent process on given server
    #
    # @option options [Integer, NilClass] :shard_id identifying shard of database in use
    # @option options [Array<Symbol, String>] :filter_params names whose values are to be
    #   filtered when notifying
    # @option options [String] :airbrake_endpoint URL for Airbrake for reporting exceptions
    #   to Errbit
    # @option options [String] :airbrake_api_key for using the Airbrake API to access Errbit
    #
    # @return [TrueClass] always true
    #
    # @raise [RuntimeError] airbrake gem missing
    def notify_init(agent_name, options)
      if options[:airbrake_endpoint] && options[:airbrake_api_key]
        unless require_succeeds?("airbrake-ruby")
          raise RuntimeError, "airbrake-ruby gem missing - required if airbrake options used in ErrorTracker"
        end

        @cgi_data = {
          :process    => $0,
          :pid        => Process.pid,
          :agent_name => agent_name
        }
        @cgi_data[:shard_id] = options[:shard_id] if options[:shard_id]
        @filter_params = (options[:filter_params] || []).map { |p| p.to_s }
        @notify_enabled = true

        return true if Airbrake.send(:configured?, :right_agent)

        Airbrake.configure(:right_agent) do |config|
          config.host = options[:airbrake_endpoint]
          config.project_id = options[:airbrake_api_key]
          config.project_key = options[:airbrake_api_key]
          config.root_directory = AgentConfig.root_dir
          config.environment = ENV['RAILS_ENV']
          config.app_version = CURRENT_SOURCE_SHA if defined?(CURRENT_SOURCE_SHA)
        end
      else
        @notify_enabled = false
      end

      true
    end

    # Apply parameter filter
    #
    # @param [Hash] params to be filtered
    #
    # @return [Hash] filtered parameters
    def filter(params)
      if @filter_params
        filtered_params = {}
        params.each { |k, p| filtered_params[k] = @filter_params.include?(k.to_s) ? FILTERED_PARAM_VALUE : p }
        filtered_params
      end
    end

  end # ErrorTracker

end # RightScale
