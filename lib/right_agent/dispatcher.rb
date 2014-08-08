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

    include ProtocolVersionMixin

    class InvalidRequestType < RuntimeError; end
    class DuplicateRequest < RuntimeError; end

    # (ActorRegistry) Registry for actors
    attr_reader :registry

    # (String) Identity of associated agent
    attr_reader :identity

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
    # agent(Agent):: Agent using this dispatcher; uses its identity and registry
    # dispatched_cache(DispatchedCache|nil):: Cache for dispatched requests that is used for detecting
    #   duplicate requests, or nil if duplicate checking is disabled
    def initialize(agent, dispatched_cache = nil)
      @agent = agent
      @registry = @agent.registry
      @identity = @agent.identity
      @dispatched_cache = dispatched_cache
      reset_stats
      @@instance = self
    end

    # Determine whether able to route requests to specified actor
    #
    # === Parameters
    # actor(String):: Actor name
    #
    # === Return
    # (Boolean):: true if can route to actor, otherwise false
    def routable?(actor)
      !!@registry.actor_for(actor)
    end

    # Route request to appropriate actor for servicing
    # Reject requests whose TTL has expired or that are duplicates of work already dispatched
    #
    # === Parameters
    # request(Request|Push):: Packet containing request
    # header(AMQP::Frame::Header|nil):: Request header containing ack control
    #
    # === Return
    # (Result|nil):: Result of request, or nil if there is no result because request is a Push
    #
    # === Raise
    # InvalidRequestType:: If the request cannot be routed to an actor
    # DuplicateRequest:: If request rejected because it has already been processed
    def dispatch(request)
      token = request.token
      actor, method, idempotent = route(request)
      received_at = @request_stats.update(method, (token if request.is_a?(Request)))
      if (dup = duplicate?(request, method, idempotent))
        raise DuplicateRequest, dup
      end
      unless (result = expired?(request, method))
        result = perform(request, actor, method, idempotent)
      end
      if request.is_a?(Request)
        duration = @request_stats.finish(received_at, token)
        Result.new(token, request.reply_to, result, @identity, request.from, request.tries, request.persistent, duration)
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
    #   "dispatch failures"(Hash|nil):: Dispatch failure activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per failure type, or nil if none
    #   "rejects"(Hash|nil):: Request reject activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per reason ("duplicate (<method>)", "retry duplicate (<method>)", or
    #     "stale (<method>)"), or nil if none
    #   "requests"(Hash|nil):: Request activity stats with keys "total", "percent", "last", and "rate"
    #     with percentage breakdown per request type, or nil if none
    def stats(reset = false)
      stats = {
        "dispatched cache"  => (@dispatched_cache.stats if @dispatched_cache),
        "dispatch failures" => @dispatch_failure_stats.all,
        "rejects"           => @reject_stats.all,
        "requests"          => @request_stats.all
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
      @dispatch_failure_stats = RightSupport::Stats::Activity.new
      true
    end

    # Determine if request TTL has expired
    #
    # === Parameters
    # request(Push|Request):: Request to be checked
    # method(String):: Actor method requested to be performed
    #
    # === Return
    # (OperationResult|nil):: Error result if expired, otherwise nil
    def expired?(request, method)
      if (expires_at = request.expires_at) && expires_at > 0 && (now = Time.now.to_i) >= expires_at
        @reject_stats.update("expired (#{method})")
        Log.info("REJECT EXPIRED <#{request.token}> from #{request.from} TTL #{RightSupport::Stats.elapsed(now - expires_at)} ago")
        # For agents that do not know about non-delivery, use error result
        if can_handle_non_delivery_result?(request.recv_version)
          OperationResult.non_delivery(OperationResult::TTL_EXPIRATION)
        else
          OperationResult.error("Could not deliver request (#{OperationResult::TTL_EXPIRATION})")
        end
      end
    end

    # Determine whether this request is a duplicate
    #
    # === Parameters
    # request(Request|Push):: Packet containing request
    # method(String):: Actor method requested to be performed
    # idempotent(Boolean):: Whether this method is idempotent
    #
    # === Return
    # (String|nil):: Messaging describing who already serviced request if it is a duplicate, otherwise nil
    def duplicate?(request, method, idempotent)
      if !idempotent && @dispatched_cache
        if (serviced_by = @dispatched_cache.serviced_by(request.token))
          from_retry = ""
        else
          from_retry = "retry "
          request.tries.each { |t| break if (serviced_by = @dispatched_cache.serviced_by(t)) }
        end
        if serviced_by
          @reject_stats.update("#{from_retry}duplicate (#{method})")
          msg = "<#{request.token}> already serviced by #{serviced_by == @identity ? 'self' : serviced_by}"
          Log.info("REJECT #{from_retry.upcase}DUP #{msg}")
          msg
        end
      end
    end

    # Use request type to route request to actor and an associated method
    #
    # === Parameters
    # request(Push|Request):: Packet containing request
    #
    # === Return
    # (Array):: Actor name, method name, and whether method is idempotent
    #
    # === Raise
    # InvalidRequestType:: If the request cannot be routed to an actor
    def route(request)
      prefix, method = request.type.split('/')[1..-1]
      method ||= :index
      method = method.to_sym
      actor = @registry.actor_for(prefix)
      if actor.nil? || !actor.respond_to?(method)
        raise InvalidRequestType, "Unknown actor or method for dispatching request <#{request.token}> of type #{request.type}"
      end
      [actor, method, actor.class.idempotent?(method)]
    end

    # Perform requested action
    #
    # === Parameters
    # request(Push|Request):: Packet containing request
    # token(String):: Unique identity token for request
    # method(String):: Actor method requested to be performed
    # idempotent(Boolean):: Whether this method is idempotent
    #
    # === Return
    # (OperationResult):: Result from performing a request
    def perform(request, actor, method, idempotent)
      @dispatched_cache.store(request.token) if @dispatched_cache && !idempotent
      if actor.method(method).arity.abs == 1
        actor.send(method, request.payload)
      else
        actor.send(method, request.payload, request)
      end
    rescue StandardError => e
      ErrorTracker.log(self, "Failed dispatching #{request.trace}", e, request)
      @dispatch_failure_stats.update("#{request.type}->#{e.class.name}")
      OperationResult.error("Could not handle #{request.type} request", e)
    end

  end # Dispatcher
  
end # RightScale
