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
  # Reports exceptions to external Errbit service via HydraulicBrake
  class ErrorTracker

    include RightSupport::Ruby::EasySingleton

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
    # @option options [String] :airbrake_endpoint URL for Airbrake for reporting exceptions
    #   to Errbit
    # @option options [String] :airbrake_api_key for using the Airbrake API to access Errbit
    #
    # @return [TrueClass] always true
    def init(agent, agent_name, options = {})
      @agent = agent
      @trace_level = options[:trace_level] || {}
      notify_init(agent_name, options[:shard_id], options[:airbrake_endpoint], options[:airbrake_api_key])
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
    # @param [String] component or service area where error occurred
    #
    # @return [TrueClass] always true
    def notify(exception, packet = nil, agent = nil, component = nil)
      if @notify_enabled
        data = {
          :error_message => exception.respond_to?(:message) ? exception.message : exception.to_s,
          :backtrace => exception.respond_to?(:backtrace) ? exception.backtrace : caller,
          :environment_name => ENV["RAILS_ENV"],
        }
        if agent
          data[:cgi_data] = (@cgi_data || {}).merge(:agent_class => agent.class.name)
        elsif @cgi_data
          data[:cgi_data] = @cgi_data
        end
        data[:error_class] = exception.class.name if exception.is_a?(Exception)
        data[:component] = component if component
        if packet && packet.is_a?(Packet)
          data[:action] = packet.type.split("/").last if packet.respond_to?(:type)
          data[:parameters] = packet.payload if packet.respond_to?(:payload)
          uuid = packet.token if packet.respond_to?(:token)
        elsif packet.is_a?(Hash)
          action = packet[:path] || packet["path"]
          data[:action] = action.split("/").last if action
          data[:parameters] = packet[:data] || packet["data"]
          uuid = packet[:uuid] || packet["uuid"]
        end
        data[:session_data] = {:uuid => uuid} if uuid
        HydraulicBrake.notify(data)
      end
      true
    rescue Exception => e
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

    # Configure HydraulicBreak for exception notification
    #
    # @param [String] agent_name uniquely identifying agent process on given server
    # @param [Integer, NilClass] shard_id identifying shard of database in use
    # @param [String] endpoint URL for Airbrake for reporting exceptions to Errbit
    # @param [String] api_key for using the Airbrake API to access Errbit
    #
    # @return [TrueClass] always true
    #
    # @raise [RuntimeError] hydraulic_brake gem missing
    def notify_init(agent_name, shard_id, endpoint, api_key)
      if endpoint && api_key
        unless require_succeeds?("hydraulic_brake")
          raise RuntimeError, "hydraulic_brake gem missing - required if airbrake options used in ErrorTracker"
        end

        @cgi_data = {
          :shard_id   => shard_id,
          :process    => $0,
          :pid        => Process.pid,
          :agent_name => agent_name
        }
        @cgi_data[:shard_id] = shard_id if shard_id
        @cgi_data[:sha] = CURRENT_SOURCE_SHA if defined?(CURRENT_SOURCE_SHA)

        uri = URI.parse(endpoint)
        HydraulicBrake.configure do |config|
          config.secure = (uri.scheme == "https")
          config.host = uri.host
          config.port = uri.port
          config.api_key = api_key
          config.project_root = AgentConfig.root_dir
        end
        @notify_enabled = true
      else
        @cgi_data = {}
        @notify_enabled = false
      end
      true
    end

  end # ErrorTracker

end # RightScale
