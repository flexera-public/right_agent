#
# Copyright (c) 2009-2014 RightScale Inc
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

module RightScale

  # TODO require target to be hash or nil only once cleanup string values in RightLink usage
  # TODO require payload to be hash or nil only once cleanup RightApi and RightLink usage

  # This class allows sending requests to agents via RightNet
  # It is used by Actor.request which is used by actors that need to send requests to remote agents
  # If requested, it will queue requests when there are is no RightNet connection
  class Sender

    include OperationResultHelper

    class SendFailure < RuntimeError; end
    class TemporarilyOffline < RuntimeError; end

    # Factor used on each retry iteration to achieve exponential backoff
    RETRY_BACKOFF_FACTOR = 3

    # (PendingRequests) Requests waiting for a response
    attr_reader :pending_requests

    # (OfflineHandler) Handler for requests when client disconnected
    attr_reader :offline_handler

    # (ConnectivityChecker) AMQP broker connection checker
    attr_reader :connectivity_checker

    # (String) Identity of the associated agent
    attr_reader :identity

    # (Agent) Associated agent
    attr_reader :agent

    # (Symbol) RightNet communication mode: :http or :amqp
    attr_reader :mode

    # For direct access to current sender
    #
    # === Return
    # (Sender):: This sender instance if defined, otherwise nil
    def self.instance
      @@instance if defined?(@@instance)
    end

    # Initialize sender
    #
    # === Parameters
    # agent(Agent):: Agent using this sender; uses its identity, client, and following options:
    #   :exception_callback(Proc):: Callback with following parameters that is activated on exception events:
    #     exception(Exception):: Exception
    #     message(Packet):: Message being processed
    #     agent(Agent):: Reference to agent
    #   :offline_queueing(Boolean):: Whether to queue request if client currently disconnected,
    #     also requires agent invocation of initialize_offline_queue and start_offline_queue methods below,
    #     as well as enable_offline_mode and disable_offline_mode as client connection status changes
    #   :ping_interval(Numeric):: Minimum number of seconds since last message receipt to ping RightNet
    #     to check connectivity, defaults to 0 meaning do not ping
    #   :restart_callback(Proc):: Callback that is activated on each restart vote with votes being initiated
    #     by offline queue exceeding MAX_QUEUED_REQUESTS or by repeated failures to access RightNet when online
    #   :retry_timeout(Numeric):: Maximum number of seconds to retry request before give up
    #   :retry_interval(Numeric):: Number of seconds before initial request retry, increases exponentially
    #   :time_to_live(Numeric):: Number of seconds before a request expires and is to be ignored;
    #     non-positive value means never expire
    #   :async_response(Boolean):: Whether to handle responses asynchronously or to handle them immediately
    #     upon arrival (for use by applications that were written expecting asynchronous AMQP responses)
    #   :secure(Boolean):: true indicates to use Security features of rabbitmq to restrict agents to themselves
    def initialize(agent)
      @agent = agent
      @identity = @agent.identity
      @options = @agent.options || {}
      @mode = @agent.mode
      @request_queue = @agent.request_queue
      @secure = @options[:secure]
      @retry_timeout = RightSupport::Stats.nil_if_zero(@options[:retry_timeout])
      @retry_interval = RightSupport::Stats.nil_if_zero(@options[:retry_interval])
      @pending_requests = PendingRequests.new
      @terminating = nil
      reset_stats
      @offline_handler = OfflineHandler.new(@options[:restart_callback], @offline_stats)
      @connectivity_checker = if @mode == :amqp
        # Only need connectivity checker for AMQP broker since RightHttpClient does its own checking
        # via periodic session renewal
        ConnectivityChecker.new(self, @options[:ping_interval] || 0, @ping_stats, @exception_stats)
      end
      @@instance = self
    end

    # Initialize the offline queue
    # All requests sent prior to running this initialization are queued if offline
    # queueing is enabled and then are sent once this initialization has run
    # All requests following this call and prior to calling start_offline_queue
    # are prepended to the request queue
    #
    # === Return
    # true:: Always return true
    def initialize_offline_queue
      @offline_handler.init if @options[:offline_queueing]
    end

    # Switch offline queueing to online mode and flush all buffered messages
    #
    # === Return
    # true:: Always return true
    def start_offline_queue
      @offline_handler.start if @options[:offline_queueing]
    end

    # Switch to offline mode
    # In this mode requests are queued in memory rather than sent
    # Idempotent
    #
    # === Return
    # true:: Always return true
    def enable_offline_mode
      @offline_handler.enable if @options[:offline_queueing]
    end

    # Switch back to sending requests after in memory queue gets flushed
    # Idempotent
    #
    # === Return
    # true:: Always return true
    def disable_offline_mode
      @offline_handler.disable if @options[:offline_queueing]
    end

    # Determine whether currently connected to RightNet via client
    #
    # === Return
    # (Boolean):: true if offline or if client disconnected, otherwise false
    def connected?
      @mode == :http ? @agent.client.connected? : @agent.client.connected.size == 0
    end

    # Update the time this agent last received a request or response message
    # Also forward this message receipt notification to any callbacks that have registered
    #
    # === Block
    # Optional block without parameters that is activated when a message is received
    #
    # === Return
    # true:: Always return true
    def message_received(&callback)
      @connectivity_checker.message_received(&callback) if @connectivity_checker
    end

    # Send a request to a single target or multiple targets with no response expected other
    # than routing failures
    # Persist the request en route to reduce the chance of it being lost at the expense of some
    # additional network overhead
    # Enqueue the request if the target is not currently available
    # Never automatically retry the request if there is the possibility of it being duplicated
    # Set time-to-live to be forever
    #
    # === Parameters
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(Hash|NilClass) Target for request, which may be a specific agent (using :agent_id),
    #   potentially multiple targets (using :tags, :scope, :selector), or nil to route solely
    #   using type:
    #   :agent_id(String):: serialized identity of specific target
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector(Symbol):: Which of the matched targets to be selected, either :any or :all,
    #     defaults to :any
    # token(String|NilClass):: Token uniquely identifying request; defaults to random generated
    # time_to_live(Numeric|NilClass):: Number of seconds before a request expires and is to be ignored;
    #   non-positive value or nil means never expire; defaults to 0
    #
    # === Block
    # Optional block used to process routing responses asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     with an initial SUCCESS response containing the targets to which the request was sent
    #     and any additional responses indicating any failures to actually route the request
    #     to those targets, use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target invalid
    # SendFailure:: If sending of request failed unexpectedly
    # TemporarilyOffline:: If cannot send request because RightNet client currently disconnected
    #   and offline queueing is disabled
    def send_push(type, payload = nil, target = nil, token = nil, time_to_live = nil, &callback)
      build_and_send_packet(:send_push, type, payload, target, token, time_to_live || 0, &callback)
    end

    # Send a request to a single target with a response expected
    # Automatically retry the request if a response is not received in a reasonable amount of time
    # or if there is a non-delivery response indicating the target is not currently available
    # Timeout the request if a response is not received in time, typically configured to 2 minutes
    # Because of retries there is the possibility of duplicated requests, and these are detected and
    # discarded automatically for non-idempotent actions
    # Allow the request to expire per the agent's configured time-to-live, typically 1 minute
    # Note that receiving a response does not guarantee that the request activity has actually
    # completed since the request processing may involve other asynchronous requests
    #
    # === Parameters
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(Hash|NilClass) Target for request, which may be a specific agent (using :agent_id),
    #   one chosen randomly from potentially multiple targets (using :tags, :scope), or nil to
    #   route solely using type:
    #   :agent_id(String):: serialized identity of specific target
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    # token(String|NilClass):: Token uniquely identifying request; defaults to random generated
    # time_to_live(Numeric|NilClass):: Number of seconds before a request expires and is to be ignored;
    #   non-positive value or nil means never expire; defaults to configured :time_to_live
    #
    # === Block
    # Required block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR,
    #     use RightScale::OperationResult.from_results to decode
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target invalid or block missing
    def send_request(type, payload = nil, target = nil, token = nil, time_to_live = nil, &callback)
      raise ArgumentError, "Missing block for response callback" unless callback
      build_and_send_packet(:send_request, type, payload, target, token, time_to_live || @options[:time_to_live], &callback)
    end

    # Build and send packet
    #
    # === Parameters
    # kind(Symbol):: Kind of request: :send_push or :send_request
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(Hash|NilClass):: Target for request
    #   :agent_id(String):: Identity of specific target
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector(Symbol):: Which of the matched targets to be selected: :any or :all
    # token(String|NilClass):: Token uniquely identifying request; defaults to random generated
    # time_to_live(Numeric):: Number of seconds before a request expires and is to be ignored;
    #   non-positive value or nil means never expire
    #
    # === Block
    # Optional block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target invalid
    def build_and_send_packet(kind, type, payload, target, token, time_to_live, &callback)
      if (packet = build_packet(kind, type, payload, target, token, time_to_live, &callback))
        action = type.split('/').last
        received_at = @request_stats.update(action, packet.token)
        @request_kind_stats.update((packet.selector == :all ? "fanout" : kind.to_s)[5..-1])
        send("#{@mode}_send", kind, target, packet, received_at, &callback)
      end
      true
    end

    # Build packet or queue it if offline
    #
    # === Parameters
    # kind(Symbol):: Kind of request: :send_push or :send_request
    # type(String):: Dispatch route for the request; typically identifies actor and action
    # payload(Object):: Data to be sent with marshalling en route
    # target(Hash|NilClass):: Target for request
    #   :agent_id(String):: Identity of specific target
    #   :tags(Array):: Tags that must all be associated with a target for it to be selected
    #   :scope(Hash):: Scoping to be used to restrict routing
    #     :account(Integer):: Restrict to agents with this account id
    #     :shard(Integer):: Restrict to agents with this shard id, or if value is Packet::GLOBAL,
    #       ones with no shard id
    #   :selector(Symbol):: Which of the matched targets to be selected: :any or :all
    # token(String|NilClass):: Token uniquely identifying request; defaults to random generated
    # time_to_live(Numeric|NilClass):: Number of seconds before a request expires and is to be ignored;
    #   non-positive value or nil means never expire
    #
    # === Block
    # Optional block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR
    #
    # === Return
    # (Push|Request|NilClass):: Packet created, or nil if queued instead
    #
    # === Raise
    # ArgumentError:: If target is invalid
    def build_packet(kind, type, payload, target, token, time_to_live, &callback)
      validate_target(target, kind == :send_push)
      if kind == :send_push
        packet = Push.new(type, payload)
        packet.selector = target[:selector] || :any if target.is_a?(Hash)
        packet.persistent = true
        packet.confirm = true if callback
      else
        packet = Request.new(type, payload)
        packet.selector = :any
      end
      packet.from = @identity
      packet.token = token || RightSupport::Data::UUID.generate
      packet.expires_at = Time.now.to_i + time_to_live if time_to_live && time_to_live > 0
      if target.is_a?(Hash)
        if (agent_id = target[:agent_id])
          packet.target = agent_id
        else
          packet.tags = target[:tags] || []
          packet.scope = target[:scope]
        end
      else
        packet.target = target
      end

      if queueing?
        @offline_handler.queue_request(kind, type, payload, target, packet.token, packet.expires_at, &callback)
        nil
      else
        packet
      end
    end

    # Handle response to a request
    #
    # === Parameters
    # response(Result):: Packet received as result of request
    #
    # === Return
    # true:: Always return true
    def handle_response(response)
      if response.is_a?(Result)
        token = response.token
        if (result = OperationResult.from_results(response))
          if result.non_delivery?
            @non_delivery_stats.update(result.content.nil? ? "nil" : result.content.inspect)
          elsif result.error?
            @result_error_stats.update(result.content.nil? ? "nil" : result.content.inspect)
          end
          @result_stats.update(result.status)
        else
          @result_stats.update(response.results.nil? ? "nil" : response.results)
        end

        if (pending_request = @pending_requests[token])
          if result && result.non_delivery? && pending_request.kind == :send_request
            if result.content == OperationResult::TARGET_NOT_CONNECTED
              # Log and temporarily ignore so that timeout retry mechanism continues, but save reason for use below if timeout
              # Leave purging of associated request until final response, i.e., success response or retry timeout
              if (parent_token = pending_request.retry_parent_token)
                @pending_requests[parent_token].non_delivery = result.content
              else
                pending_request.non_delivery = result.content
              end
              Log.info("Non-delivery of <#{token}> because #{result.content}")
            elsif result.content == OperationResult::RETRY_TIMEOUT && pending_request.non_delivery
              # Request timed out but due to another non-delivery reason, so use that reason since more germane
              response.results = OperationResult.non_delivery(pending_request.non_delivery)
              deliver_response(response, pending_request)
            else
              deliver_response(response, pending_request)
            end
          else
            deliver_response(response, pending_request)
          end
        elsif result && result.non_delivery?
          Log.info("Non-delivery of <#{token}> because #{result.content}")
        else
          Log.debug("No pending request for response #{response.to_s([])}")
        end
      end
      true
    end

    # Take any actions necessary to quiesce client interaction in preparation
    # for agent termination but allow message receipt to continue
    #
    # === Return
    # (Array):: Number of pending non-push requests and age of youngest request
    def terminate
      if @offline_handler
        @offline_handler.terminate
        @connectivity_checker.terminate if @connectivity_checker
        pending = @pending_requests.kind(:send_request)
        [pending.size, pending.youngest_age]
      else
        [0, nil]
      end
    end

    # Create displayable dump of unfinished non-push request information
    # Truncate list if there are more than 50 requests
    #
    # === Return
    # info(Array(String)):: Receive time and token for each request in descending time order
    def dump_requests
      info = []
      if @pending_requests
        @pending_requests.kind(:send_request).each do |token, request|
          info << "#{request.receive_time.localtime} <#{token}>"
        end
        info.sort!.reverse!
        info = info[0..49] + ["..."] if info.size > 50
      end
      info
    end

    # Get sender statistics
    #
    # === Parameters
    # reset(Boolean):: Whether to reset the statistics after getting the current ones
    #
    # === Return
    # stats(Hash):: Current statistics:
    #   "exceptions"(Hash|nil):: Exceptions raised per category, or nil if none
    #     "total"(Integer):: Total exceptions for this category
    #     "recent"(Array):: Most recent as a hash of "count", "type", "message", "when", and "where"
    #   "non-deliveries"(Hash|nil):: Non-delivery activity stats with keys "total", "percent", "last",
    #     and 'rate' with percentage breakdown per reason, or nil if none
    #   "offlines"(Hash|nil):: Offline activity stats with keys "total", "last", and "duration",
    #     or nil if none
    #   "pings"(Hash|nil):: Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown for "success" vs. "timeout", or nil if none
    #   "request kinds"(Hash|nil):: Request kind activity stats with keys "total", "percent", and "last"
    #     with percentage breakdown per kind, or nil if none
    #   "requests"(Hash|nil):: Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    #   "requests pending"(Hash|nil):: Number of requests waiting for response and age of oldest,
    #     or nil if none
    #   "response time"(Float):: Average number of seconds to respond to a request recently
    #   "result errors"(Hash|nil):: Error result activity stats with keys "total", "percent", "last",
    #     and 'rate' with percentage breakdown per error, or nil if none
    #   "results"(Hash|nil):: Results activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per operation result type, or nil if none
    #   "retries"(Hash|nil):: Retry activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    #   "send failure"(Hash|nil):: Send failure activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per failure type, or nil if none
    def stats(reset = false)
      stats = {}
      if @agent
        offlines = @offline_stats.all
        offlines.merge!("duration" => @offline_stats.avg_duration) if offlines
        if @pending_requests.size > 0
          pending = {}
          pending["pushes"] = @pending_requests.kind(:send_push).size
          requests = @pending_requests.kind(:send_request)
          if (pending["requests"] = requests.size) > 0
            pending["oldest age"] = requests.oldest_age
          end
        end
        stats = {
          "exceptions"       => @exception_stats.stats,
          "non-deliveries"   => @non_delivery_stats.all,
          "offlines"         => offlines,
          "pings"            => @ping_stats.all,
          "request kinds"    => @request_kind_stats.all,
          "requests"         => @request_stats.all,
          "requests pending" => pending,
          "response time"    => @request_stats.avg_duration,
          "result errors"    => @result_error_stats.all,
          "results"          => @result_stats.all,
          "retries"          => @retry_stats.all,
          "send failures"    => @send_failure_stats.all
        }
        reset_stats if reset
      end
      stats
    end

    protected

    # Reset dispatch statistics
    #
    # === Return
    # true:: Always return true
    def reset_stats
      @ping_stats = RightSupport::Stats::Activity.new
      @retry_stats = RightSupport::Stats::Activity.new
      @request_stats = RightSupport::Stats::Activity.new
      @result_stats = RightSupport::Stats::Activity.new
      @result_error_stats = RightSupport::Stats::Activity.new
      @non_delivery_stats = RightSupport::Stats::Activity.new
      @offline_stats = RightSupport::Stats::Activity.new(measure_rate = false)
      @request_kind_stats = RightSupport::Stats::Activity.new(measure_rate = false)
      @send_failure_stats = RightSupport::Stats::Activity.new
      @exception_stats = RightSupport::Stats::Exceptions.new(@agent, @options[:exception_callback])
      true
    end

    # Validate target argument of send per the semantics of each kind of send:
    #   - The target is either a specific target name, a non-empty hash, or nil
    #   - A specific target name must be a string (or use :agent_id key)
    #   - A non-empty hash target
    #     - may have keys in symbol or string format
    #     - may contain an :agent_id to select a specific target, but then cannot
    #       have any other keys
    #     - may be allowed to contain a :selector key with value :any or :all,
    #       depending on the kind of send
    #     - may contain a :scope key with a hash value with keys :account and/or :shard
    #     - may contain a :tags key with an array value
    #
    # === Parameters
    # target(String|Hash):: Identity of specific target, or hash for selecting targets;
    #   returned with all hash keys converted to symbols
    # allow_selector(Boolean):: Whether to allow :selector
    #
    # === Return
    # true:: Always return true
    #
    # === Raise
    # ArgumentError:: If target is invalid
    def validate_target(target, allow_selector)
      choices = ":agent_id OR " + (allow_selector ? ":selector, " : "") + ":tags and/or :scope"
      if target.is_a?(Hash)
        t = SerializationHelper.symbolize_keys(target)

        if (agent_id = t[:agent_id])
          raise ArgumentError, "Invalid target: #{target.inspect}" if t.size > 1
        end

        if (selector = t[:selector])
          if allow_selector
            selector = selector.to_sym
            unless [:any, :all].include?(selector)
              raise ArgumentError, "Invalid target selector (#{t[:selector].inspect}), choices are :any and :all"
            end
            t[:selector] = selector
          else
            raise ArgumentError, "Invalid target hash (#{target.inspect}), choices are #{choices}"
          end
        end

        if (scope = t[:scope])
          if scope.is_a?(Hash)
            scope = SerializationHelper.symbolize_keys(scope)
            unless (scope[:account] || scope[:shard]) && (scope.keys - [:account, :shard]).empty?
              raise ArgumentError, "Invalid target scope (#{t[:scope].inspect}), choices are :account and :shard"
            end
            t[:scope] = scope
          else
            raise ArgumentError, "Invalid target scope (#{t[:scope].inspect}), must be a hash of :account and/or :shard"
          end
        end

        if (tags = t[:tags]) && !tags.is_a?(Array)
          raise ArgumentError, "Invalid target tags (#{t[:tags].inspect}), must be an array"
        end

        unless (agent_id || selector || scope || tags) && (t.keys - [:agent_id, :selector, :scope, :tags]).empty?
          raise ArgumentError, "Invalid target hash (#{target.inspect}), choices are #{choices}"
        end
        target = t
      elsif !target.nil? && !target.is_a?(String)
        raise ArgumentError, "Invalid target (#{target.inspect}), choices are specific target name or a hash of #{choices}"
      end
      true
    end

    # Send request via HTTP
    # Use next_tick for asynchronous response and to ensure
    # that the request is sent using the main EM reactor thread
    #
    # === Parameters
    # kind(Symbol):: Kind of request: :send_push or :send_request
    # target(Hash|NilClass):: Target for request
    # packet(Push|Request):: Request packet to send
    # received_at(Time):: Time when request received
    #
    # === Block
    # Optional block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR
    #
    # === Return
    # true:: Always return true
    def http_send(kind, target, packet, received_at, &callback)
      if @options[:async_response]
        EM_S.next_tick do
          begin
            http_send_once(kind, target, packet, received_at, &callback)
          rescue Exception => e
            Log.error("Failed sending or handling response for #{packet.trace} #{packet.type}", e, :trace)
            @exception_stats.track("request", e)
          end
        end
      else
        http_send_once(kind, target, packet, received_at, &callback)
      end
      true
    end

    # Send request via HTTP and then immediately handle response
    #
    # === Parameters
    # kind(Symbol):: Kind of request: :send_push or :send_request
    # target(Hash|NilClass):: Target for request
    # packet(Push|Request):: Request packet to send
    # received_at(Time):: Time when request received
    #
    # === Block
    # Optional block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR
    #
    # === Return
    # true:: Always return true
    def http_send_once(kind, target, packet, received_at, &callback)
      begin
        method = packet.class.name.split("::").last.downcase
        time_to_live = packet.expires_at != 0 ? (packet.expires_at - Time.now.to_i) : nil
        result = success_result(@agent.client.send(method, packet.type, packet.payload, target, packet.token, time_to_live))
      rescue Exceptions::Unauthorized => e
        result = error_result(e.message)
      rescue Exceptions::ConnectivityFailure => e
        if queueing?
          @offline_handler.queue_request(kind, packet.type, packet.payload, target, packet.token, packet.expires_at, &callback)
          result = nil
        else
          result = retry_result(e.message)
        end
      rescue Exceptions::RetryableError => e
        result = retry_result(e.message)
      rescue Exceptions::InternalServerError => e
        result = error_result("#{e.server} internal error")
      rescue Exceptions::Terminating => e
        result = nil
      rescue StandardError => e
        # These errors are either unexpected errors or RestClient errors with an http_body
        # giving details about the error that are conveyed in the error_result
        if e.respond_to?(:http_body)
          # No need to log here since any HTTP request errors have already been logged
          result = error_result(e.inspect)
        else
          agent_type = AgentIdentity.parse(@identity).agent_type
          Log.error("Failed to send #{packet.trace} #{packet.type}", e, :trace)
          @exception_stats.track("request", e)
          result = error_result("#{agent_type.capitalize} agent internal error")
        end
      end

      if result && packet.is_a?(Request)
        result = Result.new(packet.token, @identity, result, from = packet.target)
        result.received_at = received_at.to_f
        @pending_requests[packet.token] = PendingRequest.new(kind, received_at, callback) if callback
        handle_response(result)
      end
      true
    end

    # Send request via AMQP
    # If lack connectivity and queueing enabled, queue request
    #
    # === Parameters
    # kind(Symbol):: Kind of request: :send_push or :send_request
    # target(Hash|NilClass):: Target for request
    # packet(Push|Request):: Request packet to send
    # received_at(Time):: Time when request received
    #
    # === Block
    # Optional block used to process response asynchronously with the following parameter:
    #   result(Result):: Response with an OperationResult of SUCCESS, RETRY, NON_DELIVERY, or ERROR
    #
    # === Return
    # true:: Always return true
    def amqp_send(kind, target, packet, received_at, &callback)
      begin
        @pending_requests[packet.token] = PendingRequest.new(kind, received_at, callback) if callback
        if packet.class == Request
          amqp_send_retry(packet, packet.token)
        else
          amqp_send_once(packet)
        end
      rescue TemporarilyOffline => e
        if queueing?
          # Queue request until come back online
          @offline_handler.queue_request(kind, packet.type, packet.payload, target, packet.token, packet.expires_at, &callback)
          @pending_requests.delete(packet.token) if callback
        else
          # Send retry response so that requester, e.g., RetryableRequest, can retry
          result = OperationResult.retry("lost RightNet connectivity")
          handle_response(Result.new(packet.token, @identity, result, @identity))
        end
      rescue SendFailure => e
        # Send non-delivery response so that requester, e.g., RetryableRequest, can retry
        result = OperationResult.non_delivery("send failed unexpectedly")
        handle_response(Result.new(packet.token, @identity, result, @identity))
      end
      true
    end

    # Send request via AMQP without retrying
    # Use mandatory flag to request return of message if it cannot be delivered
    #
    # === Parameters
    # packet(Push|Request):: Request packet to send
    # ids(Array|nil):: Identity of specific brokers to choose from, or nil if any okay
    #
    # === Return
    # (Array):: Identity of brokers to which request was published
    #
    # === Raise
    # SendFailure:: If sending of request failed unexpectedly
    # TemporarilyOffline:: If cannot send request because RightNet client currently disconnected
    #   and offline queueing is disabled
    def amqp_send_once(packet, ids = nil)
      name =
      exchange = {:type => :fanout, :name => @request_queue, :options => {:durable => true, :no_declare => @secure}}
      @agent.client.publish(exchange, packet, :persistent => packet.persistent, :mandatory => true,
                            :log_filter => [:tags, :target, :tries, :persistent], :brokers => ids)
    rescue RightAMQP::HABrokerClient::NoConnectedBrokers => e
      msg = "Failed to publish request #{packet.trace} #{packet.type}"
      Log.error(msg, e)
      @send_failure_stats.update("NoConnectedBrokers")
      raise TemporarilyOffline.new(msg + " (#{e.class}: #{e.message})")
    rescue Exception => e
      msg = "Failed to publish request #{packet.trace} #{packet.type}"
      Log.error(msg, e, :trace)
      @send_failure_stats.update(e.class.name)
      @exception_stats.track("publish", e, packet)
      raise SendFailure.new(msg + " (#{e.class}: #{e.message})")
    end

    # Send request via AMQP with one or more retries if do not receive a response in time
    # Send timeout result if reach configured retry timeout limit
    # Use exponential backoff with RETRY_BACKOFF_FACTOR for retry spacing
    # Adjust retry interval by average response time to avoid adding to system load
    # when system gets slow
    # Rotate through brokers on retries
    # Check connectivity after first retry timeout
    #
    # === Parameters
    # packet(Request):: Request packet to send
    # parent_token(String):: Token for original request
    # count(Integer):: Number of retries so far
    # multiplier(Integer):: Multiplier for retry interval for exponential backoff
    # elapsed(Integer):: Elapsed time in seconds since this request was first attempted
    # broker_ids(Array):: Identity of brokers to be used in priority order
    #
    # === Return
    # true:: Always return true
    def amqp_send_retry(packet, parent_token, count = 0, multiplier = 1, elapsed = 0, broker_ids = nil)
      check_broker_ids = amqp_send_once(packet, broker_ids)

      if @retry_interval && @retry_timeout && parent_token
        interval = [(@retry_interval * multiplier) + (@request_stats.avg_duration || 0), @retry_timeout - elapsed].min
        EM.add_timer(interval) do
          begin
            if @pending_requests[parent_token]
              count += 1
              elapsed += interval
              if elapsed < @retry_timeout && (packet.expires_at == 0 || Time.now.to_i < packet.expires_at)
                packet.tries << packet.token
                packet.token = RightSupport::Data::UUID.generate
                @pending_requests[parent_token].retry_parent_token = parent_token if count == 1
                @pending_requests[packet.token] = @pending_requests[parent_token]
                broker_ids ||= @agent.client.all
                amqp_send_retry(packet, parent_token, count, multiplier * RETRY_BACKOFF_FACTOR, elapsed,
                                broker_ids.push(broker_ids.shift))
                @retry_stats.update(packet.type.split('/').last)
              else
                Log.warning("RE-SEND TIMEOUT after #{elapsed.to_i} seconds for #{packet.trace} #{packet.type}")
                result = OperationResult.non_delivery(OperationResult::RETRY_TIMEOUT)
                @non_delivery_stats.update(result.content)
                handle_response(Result.new(packet.token, @identity, result, @identity))
              end
              @connectivity_checker.check(check_broker_ids.first) if check_broker_ids.any? && count == 1
            end
          rescue TemporarilyOffline => e
            Log.error("Failed retry for #{packet.trace} #{packet.type} because temporarily offline")
          rescue SendFailure => e
            Log.error("Failed retry for #{packet.trace} #{packet.type} because of send failure")
          rescue Exception => e
            # Not sending a response here because something more basic is broken in the retry
            # mechanism and don't want an error response to preempt a delayed actual response
            Log.error("Failed retry for #{packet.trace} #{packet.type} without responding", e, :trace)
            @exception_stats.track("retry", e, packet)
          end
        end
      end
      true
    end

    # Deliver the response and remove associated non-push requests from pending
    # including all associated retry requests
    #
    # === Parameters
    # response(Result):: Packet received as result of request
    # pending_request(Hash):: Associated pending request
    #
    # === Return
    # true:: Always return true
    def deliver_response(response, pending_request)
      @request_stats.finish(pending_request.receive_time, response.token)

      @pending_requests.delete(response.token) if pending_request.kind == :send_request
      if (parent_token = pending_request.retry_parent_token)
        @pending_requests.reject! { |k, v| k == parent_token || v.retry_parent_token == parent_token }
      end

      pending_request.response_handler.call(response) if pending_request.response_handler
      true
    end

    # Determine whether currently queueing requests because offline
    #
    # === Return
    # (Boolean):: true if queueing, otherwise false
    def queueing?
      @options[:offline_queueing] && @offline_handler.queueing?
    end

  end # Sender

end # RightScale
