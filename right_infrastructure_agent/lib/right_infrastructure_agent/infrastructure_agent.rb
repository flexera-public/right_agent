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

module RightScale

  # RightNet infrastructure agent for receiving messages from the mapper
  # and acting upon them by dispatching to a registered actor to perform
  class InfrastructureAgent < Agent

    # Number of seconds between service advertisement
    DEFAULT_ADVERTISE_INTERVAL = 60 * 60

    # (String) Name of AMQP input queue shared by this agent with others of same type
    attr_reader :shared_queue

    protected

    # Set the agent's configuration using the supplied options
    #
    # === Parameters
    # opts(Hash):: Configuration options
    #
    # === Return
    # (String):: Serialized agent identity
    def set_configuration(opts)
      @identity = super(opts)
      @shared_queue = @options[:shared_queue]
      @shard_id = @options[:shard_id]
      @all_setup = [:setup_identity_queue] + (@shared_queue ? [:setup_shared_queue] : [])
      @advertise_modulus = (@options[:advertise_interval] || DEFAULT_ADVERTISE_INTERVAL) / @options[:check_interval]
      @advertise_offset = rand(@advertise_modulus)
      @identity
    end

    # Setup the queues on the specified brokers for this agent
    # Also configure message prefetch and message non-delivery handling
    #
    # === Parameters
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # true:: Always return true
    def setup_queues(ids = nil)
      super(ids)
      advertise_services
      true
    end

    # Setup identity queue for this agent and bind it to the advertise exchange
    # so that it still can be asked to register with a mapper if needed
    #
    # === Parameters
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # ids(Array):: Identity of brokers to which subscribe submitted (although may still fail)
    def setup_identity_queue(ids = nil)
      queue = {:name => @identity, :options => {:durable => true, :no_declare => @options[:secure]}}
      filter = [:from, :tags, :tries, :persistent]
      options = {:ack => true, Advertise => nil, Request => filter, Push => filter, Result => [:from], :brokers => ids,
                 :exchange2 => {:type => :fanout, :name => "advertise", :options => {:durable => true}}}
      exchange = {:type => :direct, :name => @identity, :options => {:durable => true, :auto_delete => true}}
      ids = @broker.subscribe(queue, exchange, options) do |_, packet|
        begin
          case packet
          when Advertise     then advertise_services unless @terminating
          when Push, Request then @dispatcher.dispatch(packet) unless @terminating
          when Result        then @sender.handle_response(packet)
          end
          @sender.message_received
        rescue HABrokerClient::NoConnectedBrokers => e
          Log.error("Identity queue processing error", e)
        rescue Exception => e
          Log.error("Identity queue processing error", e, :trace)
          @exceptions.track("identity queue", e, packet)
        end
      end
      ids
    end

    # Setup shared queue for this agent
    # This queue is only allowed to receive requests
    #
    # === Parameters
    # ids(Array):: Identity of brokers for which to subscribe, defaults to all usable
    #
    # === Return
    # ids(Array):: Identity of brokers to which subscribe submitted (although may still fail)
    def setup_shared_queue(ids = nil)
      queue = {:name => @shared_queue, :options => {:durable => true}}
      exchange = {:type => :direct, :name => @shared_queue, :options => {:durable => true}}
      filter = [:from, :tags, :tries, :persistent]
      options = {:ack => true, Request => filter, Push => filter, :category => "request", :brokers => ids}
      ids = @broker.subscribe(queue, exchange, options) do |_, request|
        begin
          @dispatcher.dispatch(request, shared = true)
          @sender.message_received
        rescue HABrokerClient::NoConnectedBrokers => e
          Log.error("Shared queue processing error", e)
        rescue Exception => e
          Log.error("Shared queue processing error", e, :trace)
          @exceptions.track("shared queue", e, request)
        end
      end
      ids
    end

    # Finish any remaining agent setup and re-advertise services if it is time
    #
    # === Return
    # true:: Always return true
    def finish_setup
      begin
        before = after = 0
        @remaining_setup.each do |setup, ids|
          unless ids.empty?
            before += ids.size
            after += (@remaining_setup[setup] -= self.__send__(setup, ids)).size
          end
        end
        Log.info("[setup] Finished subscribing to queues") if before > 0 && after == 0
      rescue Exception => e
        Log.error("Failed finishing subscribing to queues", e)
        @exceptions.track("check status", e)
      end

      @broker.failed.each do |id|
        host, port, index, priority, island_id = @broker.identity_parts(id)
        connect(host, port, index, priority, island_id)
      end

      begin
        advertise_services if ((@check_status_count + @advertise_offset) % @advertise_modulus) == 0
      rescue Exception => e
        Log.error("Failed advertising services", e)
        @exceptions.track("check status", e)
      end
      true
    end

    # Advertise the services provided by this agent
    #
    # === Return
    # true:: Always return true
    def advertise_services
      exchange = {:type => :direct, :name => 'shared-registration', :options => {:no_declare => @options[:secure], :durable => true}}
      packet = Register.new(@identity, @registry.services, self.tags, @broker.all, @shared_queue, @shard_id)
      publish(exchange, packet) unless @terminating
      true
    end

    # Gracefully stop processing
    #
    # === Parameters
    # timeout(Integer):: Maximum number of seconds to wait after last request received before
    #   terminating regardless of whether there are still unfinished requests
    #
    # === Block
    # Required block to be executed after stopping message receipt wherever possible
    #
    # === Return
    # true:: Always return true
    def stop_gracefully(timeout)
      unless @unregistered
        @unregistered = true
        exchange = {:type => :direct, :name => 'shared-registration', :options => {:no_declare => @options[:secure], :durable => true}}
        publish(exchange, UnRegister.new(@identity))
      end
      @broker.unusable.each { |id| @broker.close_one(id, propagate = false) }
      if @shared_queue
        @broker.unsubscribe([@shared_queue], timeout / 2) { yield }
      else
        yield
      end
      true
    end

    # Publish packet to infrastructure exchange
    #
    # === Parameters
    # exchange(Hash):: Exchange to which to publish packet
    # packet(Packet):: Packet to be published
    #
    # === Return
    # true:: Always return true
    def publish(exchange, packet, options = {})
      begin
        @broker.publish(exchange, packet, :mandatory => true)
      rescue Exception => e
        Log.error("Failed to publish #{packet.class} to #{exchange[:name]} exchange", e) unless @terminating
        @exceptions.track("publish", e, packet)
      end
      true
    end

  end # InfrastructureAgent

end # RightScale
