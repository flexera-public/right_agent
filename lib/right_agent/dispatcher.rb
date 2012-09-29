#
# Copyright (c) 2009-2012 RightScale Inc
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

  # Dispatching of payload to specified actor
  class Dispatcher

    # Response queue name
    RESPONSE_QUEUE = "response"

    # (ActorRegistry) Registry for actors
    attr_reader :registry

    # (String) Identity of associated agent
    attr_reader :identity

    # (RightAMQP::HABrokerClient) High availability AMQP broker client
    attr_reader :broker

    # For direct access to current dispatcher
    #
    # === Return
    # (Dispatcher):: This dispatcher instance if defined, otherwise nil
    def self.instance
      @@instance if defined?(@@instance)
    end

    # Initialize dispatcher
    #
    # === Parameters
    # agent(Agent):: Agent using this dispatcher; uses its identity, broker, registry, and following options:
    #   :secure(Boolean):: true indicates to use Security features of RabbitMQ to restrict agents to themselves
    # dispatched_cache(DispatchedCache|nil):: Cache for dispatched requests that is used for detecting
    #   duplicate requests, or nil if duplicate checking is disabled
    def initialize(agent, dispatched_cache = nil)
      @agent = agent
      @broker = @agent.broker
      @registry = @agent.registry
      @identity = @agent.identity
      @secure = @agent.options[:secure]
      @dispatched_cache = dispatched_cache
      reset_stats
      @@instance = self
    end

    # Dispatch request to appropriate actor for servicing
    # Handle returning of result to requester including logging any exceptions
    # Reject requests whose TTL has expired or that are duplicates of work already dispatched
    # Acknowledge request after actor has responded
    #
    # === Parameters
    # request(Request|Push):: Packet containing request
    # header(AMQP::Frame::Header|nil):: Request header containing ack control
    # shared_queue(String|nil):: Name of shared queue if being dispatched from a shared queue
    #
    # === Return
    # (Result|nil):: Result from dispatched request, nil if not dispatched because dup or stale
    def dispatch(request, header = nil, shared_queue = nil)
      begin
        # Determine which actor this request is for
        prefix, method = request.type.split('/')[1..-1]
        method ||= :index
        method = method.to_sym
        actor = @registry.actor_for(prefix)
        token = request.token
        received_at = @request_stats.update(method, (token if request.kind_of?(Request)))
        if actor.nil?
          Log.error("No actor for dispatching request <#{token}> of type #{request.type}")
          return nil
        end
        method_idempotent = actor.class.idempotent?(method)

        # Reject this request if its TTL has expired
        if (expires_at = request.expires_at) && expires_at > 0 && received_at.to_i >= expires_at
          @reject_stats.update("expired (#{method})")
          Log.info("REJECT EXPIRED <#{token}> from #{request.from} TTL #{RightSupport::Stats.elapsed(received_at.to_i - expires_at)} ago")
          if request.is_a?(Request)
            # For agents that do not know about non-delivery, use error result
            non_delivery = if request.recv_version < 13
              OperationResult.error("Could not deliver request (#{OperationResult::TTL_EXPIRATION})")
            else
              OperationResult.non_delivery(OperationResult::TTL_EXPIRATION)
            end
            result = Result.new(token, request.reply_to, non_delivery, @identity, request.from, request.tries, request.persistent)
            exchange = {:type => :queue, :name => RESPONSE_QUEUE, :options => {:durable => true, :no_declare => @secure}}
            @broker.publish(exchange, result, :persistent => true, :mandatory => true)
          end
          return nil
        end

        # Reject this request if it is a duplicate
        if !method_idempotent && @dispatched_cache
          if by = @dispatched_cache.serviced_by(token)
            @reject_stats.update("duplicate (#{method})")
            Log.info("REJECT DUP <#{token}> serviced by #{by == @identity ? 'self' : by}")
            return nil
          end
          request.tries.each do |t|
            if by = @dispatched_cache.serviced_by(t)
              @reject_stats.update("retry duplicate (#{method})")
              Log.info("REJECT RETRY DUP <#{token}> of <#{t}> serviced by #{by == @identity ? 'self' : by}")
              return nil
            end
          end
        end

        # Proc for performing request in actor
        operation = lambda do
          begin
            @last_request_dispatch_time = received_at.to_i
            @dispatched_cache.store(token, shared_queue) if !method_idempotent && @dispatched_cache
            if actor.method(method).arity.abs == 1
              actor.__send__(method, request.payload)
            else
              actor.__send__(method, request.payload, request)
            end
          rescue Exception => e
            @dispatch_failure_stats.update("#{request.type}->#{e.class.name}")
            OperationResult.error(handle_exception(actor, method, request, e))
          end
        end

        # Proc for sending response
        callback = lambda do |r|
          begin
            if request.kind_of?(Request)
              duration = @request_stats.finish(received_at, token)
              r = Result.new(token, request.reply_to, r, @identity, request.from, request.tries, request.persistent, duration)
              exchange = {:type => :queue, :name => RESPONSE_QUEUE, :options => {:durable => true, :no_declare => @secure}}
              @broker.publish(exchange, r, :persistent => true, :mandatory => true, :log_filter => [:tries, :persistent, :duration])
            end
          rescue RightAMQP::HABrokerClient::NoConnectedBrokers => e
            Log.error("Failed to publish result of dispatched request #{request.trace}", e)
          rescue Exception => e
            Log.error("Failed to publish result of dispatched request #{request.trace}", e, :trace)
            @exception_stats.track("publish response", e)
          end
          r # For unit tests
        end

        # Process request and send response, if any
        callback.call(operation.call)
      ensure
        header.ack if header
      end
    end

    # Get dispatcher statistics
    #
    # === Parameters
    # reset(Boolean):: Whether to reset the statistics after getting the current ones
    #
    # === Return
    # stats(Hash):: Current statistics:
    #   "dispatched cache"(Hash|nil):: Number of dispatched requests cached and age of youngest and oldest,
    #     or nil if empty
    #   "exceptions"(Hash|nil):: Exceptions raised per category, or nil if none
    #     "total"(Integer):: Total for category
    #     "recent"(Array):: Most recent as a hash of "count", "type", "message", "when", and "where"
    #   "rejects"(Hash|nil):: Request reject activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per reason ("duplicate (<method>)", "retry duplicate (<method>)", or
    #     "stale (<method>)"), or nil if none
    #   "requests"(Hash|nil):: Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    #   "response time"(Float):: Average number of seconds to respond to a request recently
    def stats(reset = false)
      stats = {
        "dispatched cache" => (@dispatched_cache.stats if @dispatched_cache),
        "exceptions"       => @exception_stats.stats,
        "rejects"          => @reject_stats.all,
        "requests"         => @request_stats.all,
        "response time"    => @request_stats.avg_duration
      }
      reset_stats if reset
      stats
    end

    private

    # Reset dispatch statistics
    #
    # === Return
    # true:: Always return true
    def reset_stats
      @reject_stats = RightSupport::Stats::Activity.new
      @request_stats = RightSupport::Stats::Activity.new
      @exception_stats = RightSupport::Stats::Exceptions.new(@agent)
      true
    end

    # Handle exception by logging it, calling the actors exception callback method,
    # and gathering exception statistics
    #
    # === Parameters
    # actor(Actor):: Actor that failed to process request
    # method(Symbol):: Name of actor method being dispatched to
    # request(Packet):: Packet that dispatcher is acting upon
    # exception(Exception):: Exception that was raised
    #
    # === Return
    # (String):: Error description for this exception
    def handle_exception(actor, method, request, exception)
      error = "Could not handle #{request.type} request"
      Log.error(error, exception, :trace)
      begin
        if actor && actor.class.exception_callback
          case actor.class.exception_callback
          when Symbol, String
            actor.send(actor.class.exception_callback, method, request, exception)
          when Proc
            actor.instance_exec(method, request, exception, &actor.class.exception_callback)
          end
        end
        @exception_stats.track(request.type, exception)
      rescue Exception => e
        Log.error("Failed handling error for #{request.type}", e, :trace)
        @exception_stats.track(request.type, e) rescue nil
      end
      Log.format(error, exception)
    end

  end # Dispatcher
  
end # RightScale
