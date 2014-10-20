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

module RightScale

  # HTTP interface to RightNet router
  class RouterClient < BaseRetryClient

    include EventMixin

    # When encounter irreparable event sequence failure
    class EventSequenceBroken < RuntimeError; end

    # RightNet router API version for use in X-API-Version header
    API_VERSION = "2.0"

    # Initial interval between attempts to make a WebSocket connection
    # and interval between ongoing checks to see if still connected
    CONNECT_INTERVAL = 15

    # Maximum interval between attempts to make a WebSocket connection
    MAX_CONNECT_INTERVAL = 60 * 60 * 24

    # Initial interval between attempts to reconnect or long-poll when router is not responding
    RECONNECT_INTERVAL = 2

    # Maximum interval between attempts to reconnect or long-poll when router is not responding
    MAX_RECONNECT_INTERVAL = 30

    # Maximum attempts to replay event source from same event
    MAX_REPLAY_ATTEMPTS = 2

    # Interval between checks for lost WebSocket connection
    CHECK_INTERVAL = 5

    # Backoff factor for connect and reconnect intervals
    BACKOFF_FACTOR = 2

    # WebSocket close status codes
    NORMAL_CLOSE = 1000
    SHUTDOWN_CLOSE = 1001
    PROTOCOL_ERROR_CLOSE = 1002
    UNEXPECTED_ERROR_CLOSE = 1011

    # Default time to wait for an event or to ping WebSocket
    DEFAULT_LISTEN_TIMEOUT = 60

    # Maximum repeated listen failures at which point give up listening
    MAX_LISTEN_FAILURES = 10

    # Create RightNet router client
    #
    # @param [AuthClient] auth_client providing authorization session for HTTP requests
    #
    # @option options [Numeric] :open_timeout maximum wait for connection; defaults to DEFAULT_OPEN_TIMEOUT
    # @option options [Numeric] :request_timeout maximum wait for response; defaults to DEFAULT_REQUEST_TIMEOUT
    # @option options [Numeric] :listen_timeout maximum wait for event; defaults to DEFAULT_LISTEN_TIMEOUT
    # @option options [Boolean] :long_polling_only never attempt to create a WebSocket, always long-polling instead
    # @option options [Numeric] :retry_timeout maximum before stop retrying; defaults to DEFAULT_RETRY_TIMEOUT
    # @option options [Array] :retry_intervals between successive retries; defaults to DEFAULT_RETRY_INTERVALS
    # @option options [Boolean] :retry_enabled for requests that fail to connect or that return a retry result
    # @option options [Numeric] :reconnect_interval for reconnect attempts after lose connectivity
    # @option options [Boolean] :non_blocking i/o is to be used for HTTP requests by applying
    #   EM::HttpRequest and fibers instead of RestClient; requests remain synchronous
    # @option options [Array] :filter_params symbols or strings for names of request parameters whose
    #   values are to be hidden when logging; also applied to contents of any parameters named :payload
    # @option options [Boolean] :event_demo output enabled
    #
    # @raise [ArgumentError] auth client does not support this client type
    def initialize(auth_client, options)
      init(:router, auth_client, options.merge(:server_name => "RightNet", :api_version => API_VERSION))
      @options[:listen_timeout] ||= DEFAULT_LISTEN_TIMEOUT
      @last_event = {}
      @replays = {}
      if @options[:event_demo]
        trap 'USR1' do
          @demo_skip_events = !@demo_skip_events
        end
        trap 'USR2' do
          if @websocket
            File.open("/tmp/event_client", "a") { |f| f.puts f.puts "close websocket" }
            @websocket.close
            sleep 5
          end
        end
      end
    end

    # Route a request to a single target or multiple targets with no response expected
    # Persist the request en route to reduce the chance of it being lost at the expense of some
    # additional network overhead
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request if there is the possibility of it being duplicated
    # Set time-to-live to be forever
    #
    # @param [String] type of request as path specifying actor and action
    # @param [Hash, NilClass] payload for request
    # @param [Hash, NilClass] target for request, which may be a specific agent (using :agent_id),
    #   potentially multiple targets (using :tags, :scope, :selector), or nil to route solely
    #   using type:
    #   [String] :agent_id serialized identity of specific target
    #   [Array] :tags that must all be associated with a target for it to be selected
    #   [Hash] :scope for restricting routing which may contain:
    #     [Integer] :account id that agents must be associated with to be included
    #     [Integer] :shard id that agents must be in to be included, or if value is
    #       Packet::GLOBAL, ones with no shard id
    #   [Symbol] :selector for picking from qualified targets: :any or :all;
    #     defaults to :any
    #
    # @option options [String] :request_uuid uniquely identifying this request; defaults to
    #   randomly generated
    # @option options [Numeric] :time_to_live seconds before request expires and is to be ignored;
    #   non-positive value or nil means never expire
    #
    # @return [NilClass] always nil since there is no expected response to the request
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def push(type, payload, target, options = {})
      params = {
        :type => type,
        :payload => payload,
        :target => target }
      make_request(:post, "/push", params, type.split("/")[2], options)
    end

    # Route a request to a single target with a response expected
    # Automatically retry the request if a response is not received in a reasonable amount of time
    # or if there is a non-delivery response indicating the target is not currently available
    # Timeout the request if a response is not received in time, typically configured to 30 sec
    # Because of retries there is the possibility of duplicated requests, and these are detected and
    # discarded automatically for non-idempotent actions
    # Allow the request to expire per the agent's configured time-to-live, typically 1 minute
    #
    # @param [String] type of request as path specifying actor and action
    # @param [Hash, NilClass] payload for request
    # @param [Hash, NilClass] target for request, which may be a specific agent (using :agent_id),
    #   one chosen randomly from potentially multiple targets (using :tags, :scope), or nil to
    #   route solely using type:
    #   [String] :agent_id serialized identity of specific target
    #   [Array] :tags that must all be associated with a target for it to be selected
    #   [Hash] :scope for restricting routing which may contain:
    #     [Integer] :account id that agents must be associated with to be included
    #
    # @option options [String] :request_uuid uniquely identifying this request; defaults to
    #   randomly generated
    # @option options [Numeric] :time_to_live seconds before request expires and is to be ignored;
    #   non-positive value or nil means never expire
    #
    # @return [Result, NilClass] response from request
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def request(type, payload, target, options = {})
      params = {
        :type => type,
        :payload => payload,
        :target => target }
      make_request(:post, "/request", params, type.split("/")[2], options)
    end

    # Route event
    # Use WebSocket if possible
    # Do not block this request even if in the process of closing since used for request responses
    #
    # @param [Hash] event to send with :source and :type controlling routing
    #
    # @return [TrueClass] always true
    #
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def notify(event)
      event[:uuid] ||= RightSupport::Data::UUID.generate
      event[:version] ||= AgentConfig.protocol_version
      params = {:event => event}
      if @websocket
        path = event[:path] ? " #{event[:path]}" : "" # TODO deprecate
        from = event[:source] ? " from #{event[:source]}" : ""
        Log.info("Sending EVENT #{event_text(event)}")
        @websocket.send(params)
      else
        make_request(:post, "/notify", params, "notify", :request_uuid => event[:uuid], :filter_params => ["event"])
      end
      true
    end

    # Receive events via an HTTP WebSocket if available, otherwise via an HTTP long-polling
    #
    # @param [Hash, NilClass] sources of events with source uid, name, or routing ID
    #   as key and array of event types of interest as value, nil meaning all from that
    #   source; defaults to events from pre-defined sources for the given type of agent
    # @param [Hash, NilClass] replay events with source uid, name, or routing ID of source
    #   as key and ID of last event received after which to replay as value
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received or exception
    #
    # @return [TrueClass] always true, although only returns when closing
    #
    # @raise [ArgumentError] block missing
    # @raise [Exceptions::Unauthorized] authorization failed
    # @raise [Exceptions::ConnectivityFailure] cannot connect to server, lost connection
    #   to it, or it is out of service or too busy to respond
    # @raise [Exceptions::RetryableError] request failed but if retried may succeed
    # @raise [Exceptions::Terminating] closing client and terminating service
    # @raise [Exceptions::InternalServerError] internal error in server being accessed
    def listen(sources, replay = nil, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      File.open("/tmp/event_sink", "a") { |f| f.puts "replay #{replay.values.first.to_i + 1}" } if @options[:event_demo] && replay

      @ack_uuids = nil
      @replay_sources = nil
      @listen_interval = 0
      @listen_state = :choose
      @listen_failures = 0
      @connect_interval = CONNECT_INTERVAL
      @reconnect_interval = RECONNECT_INTERVAL

      listen_loop(sources, replay, &handler)
      true
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow any active requests to complete
    #
    # @param [Symbol] scope of close action: :receive for just receive side
    #   of client, :all for both receive and send side; defaults to :all
    #
    # @return [TrueClass] always true
    def close(scope = :all)
      super
      update_listen_state(:cancel)
      @websocket.close(SHUTDOWN_CLOSE, "Agent terminating") if @websocket
    end

    # Current statistics for this client
    #
    # @param [Boolean] reset the statistics after getting the current ones
    #
    # @return [Hash] current statistics
    #   [Hash, NilClass] "events" Activity stats or nil if none
    #   [Hash, NilClass] "reconnects" Activity stats or nil if none
    #   [Hash, NilClass] "request failures" Activity stats or nil if none
    #   [Hash, NilClass] "request sent" Activity stats or nil if none
    def stats(reset = false)
      events = @stats["events"].all
      stats = super(reset)
      stats["events"] = events
      stats
    end

    protected

    # Reset API interface statistics
    #
    # @return [TrueClass] always true
    def reset_stats
      super
      @stats["events"] = RightSupport::Stats::Activity.new
      true
    end

    # Perform listen action, then wait prescribed time for next action
    #
    # @param [Hash, NilClass] sources of events
    # @param [Hash, NilClass] replay events for sources
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received or exception
    #
    # @return [Boolean] false if failed or terminating, otherwise true
    def listen_loop(sources, replay, &handler)
      @listen_timer = nil

      begin
        # Perform listen action based on current state
        case @listen_state
        when :choose
          # Choose listen method or continue as is if already listening
          # or want to delay choosing
          choose_listen_method
        when :check
          # Check whether really got connected, given the possibility of an
          # asynchronous WebSocket handshake failure that resulted in a close
          # Continue to use WebSockets if still connected or if connect failed
          # due to unresponsive server
          if @websocket.nil?
            if router_not_responding?
              update_listen_state(:connect, backoff_reconnect_interval)
            else
              backoff_connect_interval
              update_listen_state(:long_poll)
            end
          elsif (@listen_checks += 1) > CHECK_INTERVAL
            @reconnect_interval = RECONNECT_INTERVAL
            update_listen_state(:choose, @connect_interval = CONNECT_INTERVAL)
          end
        when :connect
          # Use of WebSockets is enabled and it is again time to try to connect
          @stats["reconnects"].update("websocket") if @attempted_connect_at
          try_connect(sources, replay, &handler)
        when :long_poll
          # Resorting to long-polling
          # Need to long-poll on separate thread if cannot use non-blocking HTTP i/o
          # Will still periodically retry WebSockets if not restricted to just long-polling
          @replay_sources = replay if replay && replay.any?
          if @options[:non_blocking]
            @ack_uuids, @replay_sources = process_long_poll(try_long_poll(sources, @ack_uuids, @replay_sources, &handler))
          else
            update_listen_state(:wait, 1)
            try_deferred_long_poll(sources, @ack_uuids, @replay_sources, &handler)
          end
        when :wait
          # Deferred long-polling is expected to break out of this state eventually
        when :cancel
          return false
        end
        @listen_failures = 0
      rescue Exception => e
        ErrorTracker.log(self, "Failed to listen", e)
        @listen_failures += 1
        if @listen_failures > MAX_LISTEN_FAILURES
          ErrorTracker.log(self, "Exceeded maximum repeated listen failures (#{MAX_LISTEN_FAILURES}), stopping listening")
          @listen_state = :cancel
          self.state = :failed
          return false
        end
        @listen_state = :choose
        @listen_interval = CHECK_INTERVAL
      end

      listen_loop_wait(Time.now, @listen_interval, sources, replay, &handler)
    end

    # Wait specified interval before next listen loop
    # Continue waiting if interval changes while waiting
    #
    # @param [Time] started_at time when first started waiting
    # @param [Numeric] interval to wait
    # @param [Hash, NilClass] sources of events
    # @param [Hash, NilClass] replay events for sources
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received or exception
    #
    # @return [TrueClass] always true
    def listen_loop_wait(started_at, interval, sources, replay, &handler)
      if @listen_interval == 0
        EM_S.next_tick { listen_loop(sources, replay, &handler) }
      else
        @listen_timer = EM_S::Timer.new(interval) do
          remaining = @listen_interval - (Time.now - started_at)
          if remaining > 0
            listen_loop_wait(started_at, remaining, sources, replay, &handler)
          else
            listen_loop(sources, replay, &handler)
          end
        end
      end
      true
    end

    # Update listen state
    #
    # @param [Symbol] state next
    # @param [Integer] interval before next listen action
    #
    # @return [TrueClass] always true
    #
    # @raise [ArgumentError] invalid state
    def update_listen_state(state, interval = 0)
      if state == :cancel
        @listen_timer.cancel if @listen_timer
        @listen_timer = nil
        @listen_state = state
      elsif [:choose, :check, :connect, :long_poll, :wait].include?(state)
        @listen_checks = 0 if state == :check && @listen_state != :check
        @listen_state = state
        @listen_interval = interval
      else
        raise ArgumentError, "Invalid listen state: #{state.inspect}"
      end
      true
    end

    # Determine whether should retry creation of WebSocket connection now
    # Should only retry if (1) WebSocket is enabled, (2) there is none currently,
    # (3) previous closure was for acceptable reasons (normal, router shutdown,
    # router inaccessible), or (4) enough time has elapsed to make another attempt
    #
    # @return [TrueClass] always true
    def choose_listen_method
      if @options[:long_polling_only]
        update_listen_state(:long_poll)
        @connect_interval = MAX_CONNECT_INTERVAL
      elsif @websocket
        update_listen_state(:choose, @connect_interval)
      else
        if @attempted_connect_at.nil?
          interval = 0
        elsif (interval = @connect_interval - (Time.now - @attempted_connect_at)) < 0 ||
              [NORMAL_CLOSE, SHUTDOWN_CLOSE].include?(@close_code) ||
              router_not_responding?
          interval = 0
        end
        update_listen_state(:connect, interval)
      end
      true
    end

    # Try to create WebSocket connection
    #
    # @param [Hash, NilClass] sources of events
    # @param [Hash, NilClass] replay events for sources
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received or exception
    #
    # @return [TrueClass] always true
    def try_connect(sources, replay, &handler)
      connect(sources, replay, &handler)
      update_listen_state(:check, 1)
    rescue Exception => e
      ErrorTracker.log(self, "Failed creating WebSocket", e, nil, :caller)
      backoff_connect_interval
      update_listen_state(:long_poll)
    end

    # Connect to RightNet router using WebSocket for receiving events
    #
    # @param [Hash, NilClass] sources of events
    # @param [Hash, NilClass] replay events for sources
    #
    # @yield [event] required block called when event received
    # @yieldparam [Object] event received or exception
    # @yieldreturn [Hash, NilClass] event this is response to event received,
    #   or nil meaning no response
    #
    # @return [EventWebSocket] WebSocket created
    #
    # @raise [ArgumentError] block missing
    def connect(sources, replay, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      # Ensure that current replay sources not arbitrarily reapplied if ever go back to long-polling
      @replay_sources && @replay_sources.clear

      @attempted_connect_at = Time.now
      @close_code = @close_reason = nil

      options = {
        # Limit to .auth_header here (rather than .headers) to keep WebSockets happy
        :headers => {"X-API-Version" => API_VERSION}.merge(@auth_client.auth_header),
        :ping => @options[:listen_timeout],
        :peer => "router"}

      url = URI.parse(@auth_client.router_url)
      url.scheme = url.scheme == "https" ? "wss" : "ws"
      url.path = url.path + "/connect"
      if sources && sources.any?
        url.query = sources.map do |key, types|
          if types
            types.map { |t| "sources[#{key}][]=#{CGI.escape(t)}" }.join("&")
          else
            "sources[#{key}]="
          end
        end.join("&")
      end

      Log.info("Creating WebSocket connection to #{url.to_s}")
      @websocket = EventWebSocket.new(url.to_s, protocols = nil, options)

      # Define proc for receiving WebSocket error messages
      @websocket.onerror = lambda do |message|
        ErrorTracker.log(self, "WebSocket error (#{message.data})") if message.data
      end

      # Define proc for receiving WebSocket close messages
      @websocket.onclose = lambda do |message|
        begin
          @close_code = message.code.to_i
          @close_reason = message.reason
          msg = "WebSocket closed (#{message.code}"
          msg << ((message.reason.nil? || message.reason.empty?) ? ")" : ": #{message.reason})")
          Log.info(msg)
        rescue Exception => e
          ErrorTracker.log(self, "Failed closing WebSocket", e)
        end
        @websocket = nil
      end

      # Define proc for receiving WebSocket messages
      @websocket.onmessage = lambda do |message|
        begin
          @websocket.receive(message.data)
        rescue Exception => e
          ErrorTracker.log(self, "Failed handling WebSocket message", e)
        end
      end

      # Define proc for receiving WebSocket event message
      @websocket.oneventmessage = lambda do |data|
        begin
          event = data[:event]
          File.open("/tmp/event_client", "a") { |f| f.puts "#{@demo_skip_events ? "drop " : ""}#{event[:id]}#{event[:replayed] ? " replayed" : ""}" } if @options[:event_demo]

          unless @demo_skip_events
            # Verify event is in sequence and if not, initiate replay
            accepted = verify_in_sequence(event) do |source, last_id|
              File.open("/tmp/event_client", "a") { |f| f.puts "replay #{last_id + 1}" } if @options[:event_demo]
              ErrorTracker.log(self, "Event #{event_trace(event)} from #{source} is out of sequence, " +
                                     "requesting replay after event #{event_trace(last_id)}")
              @websocket.send({:replay => {source => last_id}}) do |status, content|
                begin
                  ErrorTracker.log(self, "Failed replay for event #{event_trace(last_id)} from #{source} (#{status}: #{content})")
                  unless status == 449
                    error = "Attempt to replay after event #{event_trace(last_id)} from #{source} to close gap in event " +
                            "sequence failed (#{status}: #{content}), recommend application level resync"
                    handler.call(EventSequenceBroken.new(error))
                  end
                rescue Exception => e
                  ErrorTracker.log(self, "Failed handling error from replay", e)
                end
              end
            end

            # Handle event
            if accepted
              Log.info("Received EVENT #{event_text(event)}")
              @stats["events"].update("#{event[:type]} #{event[:path]}")
              @websocket.send({:ack => event[:uuid]})

              File.open("/tmp/event_sink", "a") { |f| f.puts event[:id] } if @options[:event_demo]
              handler.call(event)
              @communicated_callbacks.each { |callback| callback.call } if @communicated_callbacks
            end
          end
        rescue EventSequenceBroken => e
          handler.call(e)
        rescue Exception => e
          ErrorTracker.log(self, "Failed handling event message from WebSocket", e)
        end
      end

      # Define proc for receiving WebSocket event acknowledgement message
      @websocket.onackmessage = lambda do |data|
        Log.debug("Received ACK #{event_trace(data[:ack])}")
      end

      # Initiate replay if requested, then clear replay list
      # so that does not get reused in listen_loop
      if replay && replay.any?
        @websocket.send({:replay => replay})
        replay.clear
      end

      @websocket
    end

    # Verify that event is in sequence
    # If previously received, ignore it; if gap in sequence, initiate replay
    # If replay fails, notify application so that it can take other actions to resync
    # Do not replay if exceed maximum attempts from same event to avoid getting into cycle
    #
    # @param [Hash] event received with symbolized keys
    #
    # @yield [source, last_id] required block called to perform replay action
    # @yieldparam [String] source of event
    # @yieldparam [Numeric] last_id of last event received
    #
    # @return [Boolean] whether event should be accepted
    #
    # @raise [ArgumentError] block missing
    # @raise [EventSequenceBroken] replay has failed repeatedly and no further attempts allowed
    def verify_in_sequence(event)
      raise ArgumentError, "Block missing" unless block_given?

      result = true
      if (event_id = event[:id])
        source = event[:source]
        last_id = @last_event[source]
        if last_id.nil? || event_id == (last_id + 1)
          @last_event[source] = event_id
        elsif event_id <= last_id
          Log.info("Ignoring event #{event_trace(event)} because not newer than last #{event_trace(last_id)}")
          result = false
        else
          # Need to replay events for this source, but limit attempts from this same event
          if (replay = @replays[source])
            if replay[:last_id] == last_id && replay[:count] >= MAX_REPLAY_ATTEMPTS
              ErrorTracker.log(self, "Rejecting replay after event #{event_trace(last_id)} from #{source} " +
                                     "because already attempted #{MAX_REPLAY_ATTEMPTS} times")
              raise EventSequenceBroken, "Repeated replay attempts after event #{event_trace(last_id)} from #{source} " +
                                         "to close gap in event sequence have failed, recommend application level resync"
            elsif replay[:last_id] == last_id
              replay[:count] += 1
            else
              replay = {:last_id => last_id, :count => 1}
            end
          else
            replay = {:last_id => last_id, :count => 1}
          end
          yield(source, last_id)
          @replays[source] = replay
          result = false
        end
      end
      result
    end

    # Try to make long-polling request to receive events
    #
    # @param [Hash, NilClass] sources of events
    # @param [Array, NilClass] ack_uuids for events received on previous poll
    # @param [Hash, NilClass] replay_sources containing ID of last event received after which to replay
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received or exception
    #
    # @return [Array, Exception] UUIDs of events to be acknowledged and UUIDs for event replays,
    #   or Exception if failed
    def try_long_poll(sources, ack_uuids, replay_sources, &handler)
      begin
        long_poll(sources, ack_uuids, replay_sources, &handler)
      rescue Exception => e
        e
      end
    end

    # Try to make long-polling request to receive events using EM defer thread
    # Repeat long-polling until there is an error or the stop time has been reached
    #
    # @param [Hash, NilClass] sources of events
    # @param [Array, NilClass] ack_uuids for events received on previous poll
    # @param [Hash, NilClass] replay_sources containing ID of last event received after which to replay
    #
    # @yield [event] required block called each time event received
    # @yieldparam [Hash] event received or exception
    #
    # @return [TrueClass] always true
    def try_deferred_long_poll(sources, ack_uuids, replay_sources, &handler)
      # Proc for running long-poll in EM defer thread since this is a blocking call
      @defer_operation_proc = Proc.new { try_long_poll(sources, ack_uuids, replay_sources, &handler) }

      # Proc that runs in main EM reactor thread to handle result from above operation proc
      @defer_callback_proc = Proc.new { |result| @ack_uuids, @replay_sources = process_long_poll(result) }

      # Use EM defer thread since the long-poll will block
      EM.defer(@defer_operation_proc, @defer_callback_proc)
      true
    end

    # Make long-polling request to receive one or more events
    # Do not return until an event is received or the polling times out or fails
    #
    # @param [Hash, NilClass] sources of events
    # @param [Array, NilClass] ack_uuids for events received on previous poll
    # @param [Hash, NilClass] replay_sources containing ID of last event received after which to replay
    #
    # @yield [event] required block called for each event received
    # @yieldparam [Object] event received or exception
    #
    # @return [Array] UUIDs of events to be acknowledged and hash of sources to replay
    #
    # @raise [ArgumentError] block missing
    def long_poll(sources, ack_uuids, replay_sources, &handler)
      raise ArgumentError, "Block missing" unless block_given?

      params = {
        :wait_time => @options[:listen_timeout] - 5,
        :timestamp => Time.now.to_f }
      params[:sources] = sources if sources && sources.any?
      params[:ack] = ack_uuids if ack_uuids && ack_uuids.any?

      # Initiate replay if requested, then clear replay list
      # so that does not get reused in listen_loop
      if replay_sources && replay_sources.any?
        params[:replay] = replay_sources.dup
        replay_sources.clear
      end

      options = {
        :request_timeout => @connect_interval,
        :poll_timeout => @options[:listen_timeout] }

      events = make_request(:poll, "/listen", params, "listen", options)
      ack_uuids = []
      replay_sources = {}
      if events
        events.each do |event|
          begin
            event = SerializationHelper.symbolize_keys(event)
            File.open("/tmp/event_client", "a") { |f| f.puts "#{@demo_skip_events ? "drop " : ""}#{event[:id]}" } if @options[:event_demo]

            unless @demo_skip_events
              accepted = verify_in_sequence(event) do |source, last_id|
                File.open("/tmp/event_client", "a") { |f| f.puts "replay #{last_id + 1}" } if @options[:event_demo]
                replay_sources[source] = last_id
              end
              if accepted
                Log.info("Received EVENT #{event_text(event)}")
                @stats["events"].update("#{event[:type]} #{event[:path]}")
                ack_uuids << event[:uuid]
                File.open("/tmp/event_sink", "a") { |f| f.puts "#{event[:replayed] ? " replayed" : ""}" } if @options[:event_demo]
                handler.call(event)
              end
            end
          rescue EventSequenceBroken => e
            handler.call(e)
          end
        end
      end
      [ack_uuids, replay_sources]
    end

    # Process result from long-polling attempt
    # Not necessary to log failure since should already have been done by underlying HTTP client
    #
    # @param [Array, Exception] result from long-polling attempt
    #
    # @return [Array, NilClass] result for long-polling attempt
    def process_long_poll(result)
      case result
      when Exceptions::Unauthorized, Exceptions::ConnectivityFailure, Exceptions::RetryableError, Exceptions::InternalServerError
        update_listen_state(:choose, backoff_reconnect_interval)
        result = nil
      when Exception
        ErrorTracker.track(self, result)
        update_listen_state(:choose, backoff_reconnect_interval)
        result = nil
      else
        @reconnect_interval = RECONNECT_INTERVAL
        @communicated_callbacks.each { |callback| callback.call } if @communicated_callbacks
        update_listen_state(:choose)
      end
      result
    end

    # Exponentially increase WebSocket connect attempt interval after failing to connect
    #
    # @return [Integer] new interval
    def backoff_connect_interval
      @connect_interval = [@connect_interval * BACKOFF_FACTOR, MAX_CONNECT_INTERVAL].min
    end

    # Exponentially increase reconnect attempt interval when router not responding
    #
    # @return [Integer] new interval
    def backoff_reconnect_interval
      @reconnect_interval = [@reconnect_interval * BACKOFF_FACTOR, MAX_RECONNECT_INTERVAL].min
    end

    # Determine whether WebSocket attempts are failing because router not responding
    #
    # @return [Boolean] true if router not responding, otherwise false
    def router_not_responding?
      @close_code == PROTOCOL_ERROR_CLOSE && @close_reason =~ /408|502|503/
    end

  end # RouterClient

end # RightScale
