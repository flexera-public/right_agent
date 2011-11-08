#
# Copyright (c) 2009-2011 RightScale Inc
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

begin
  # Clean up AMQP connection when an error is raised after a broker request failure,
  # otherwise AMQP becomes unusable
  AMQP.module_eval do
    def self.start *args, &blk
      begin
        EM.run{
          @conn ||= connect *args
          @conn.callback { AMQP.channel = AMQP::Channel.new(@conn) }

          # callback passed to .start must come last
          @conn.callback(&blk) if blk
          @conn
        }
      rescue Exception => e
        @conn = nil
        raise e
      end
    end
  end

  AMQP::Client.module_eval do
    # Add callback for connection failure
    def initialize opts = {}
      @settings = opts
      extend AMQP.client

      @_channel_mutex = Mutex.new

      @on_disconnect ||= proc{ @connection_status.call(:failed) if @connection_status }

      timeout @settings[:timeout] if @settings[:timeout]
      errback{ @on_disconnect.call } unless @reconnecting
      @connection_status = @settings[:connection_status]

      # TCP connection "openness"
      @tcp_connection_established = false
      # AMQP connection "openness"
      @connected                  = false
    end

    # Add backoff controls to the reconnect algorithm
    def reconnect(force = false)
      if @reconnecting and not force
        # Wait after first reconnect attempt and in between each subsequent attempt
        EM.add_timer(@settings[:reconnect_interval] || 5) { reconnect(true) }
        return
      end

      unless @reconnecting
        @deferred_status = nil
        initialize(@settings)

        mqs = @channels
        @channels = {}
        mqs.each{ |_,mq| mq.reset } if mqs

        @reconnecting = true

        again = @settings[:reconnect_delay]
        again = again.call if again.is_a?(Proc)
        if again.is_a?(Numeric)
          # Wait before making initial reconnect attempt
          EM.add_timer(again) { reconnect(true) }
          return
        elsif ![nil, true].include?(again)
          raise ::AMQP::Error, "Could not interpret :reconnect_delay => #{again.inspect}; expected nil, true, or Numeric"
        end
      end

      RightScale::Log.warning("Attempting to reconnect to broker " +
        "#{RightScale::AgentIdentity.new('rs', 'broker', @settings[:port].to_i, @settings[:host].gsub('-', '~')).to_s}")
      log 'reconnecting'
      EM.reconnect(@settings[:host], @settings[:port], self)
    rescue Exception => e
      RightScale::Log.error("Exception caught during AMQP reconnect", e, :trace)
      reconnect if @reconnecting
    end

    # Catch exceptions that would otherwise cause EM to stop or be in a bad state if a top
    # level EM error handler was setup. Instead close the connection and leave EM alone.
    # Don't log an error if the environment variable IGNORE_AMQP_FAILURES is set
    alias :orig_receive_data :receive_data
    def receive_data(*args)
      begin
        orig_receive_data(*args)
      rescue Exception => e
        unless ENV['IGNORE_AMQP_FAILURES']
          RightScale::Log.error("Exception caught while processing AMQP frame, closing connection", e, :trace)
        end
        close_connection
      end
    end

    # Make it log to RightScale when logging enabled
    def log(*args)
      return unless @settings[:logging] or AMQP.logging
      require 'pp'
      RightScale::Log.info("AMQP #{args.pretty_inspect.chomp}")
    end
  end

  AMQP::Channel.class_eval do
    # Detect message return and make callback
    def check_content_completion
      if @body.length >= @header.size
        if @method.is_a? AMQP::Protocol::Basic::Return
          @on_return_message.call @method, @body if @on_return_message
        else
          @header.properties.update(@method.arguments)
          @consumer.receive @header, @body if @consumer
        end
        @body = @header = @consumer = @method = nil
      end
    end

    # Provide callback to be activated when a message is returned
    def return_message(&blk)
      @on_return_message = blk
    end

    # Apply :no_declare option
    def validate_parameters_match!(entity, parameters)
      unless entity.opts == parameters || parameters[:passive] || parameters[:no_declare] || entity.opts[:no_declare]
        raise AMQP::IncompatibleOptionsError.new(entity.name, entity.opts, parameters)
      end
    end

    # Make it log to RightScale when logging enabled
    def log(*args)
      return unless AMQP.logging
      require 'pp'
      RightScale::Log.info("AMQP #{args.pretty_inspect.chomp}")
    end
  end

  # Add :no_declare => true option for new Queue objects to allow an instance that has
  # no configuration privileges to enroll without blowing up the AMQP gem when it tries
  # to subscribe to its queue before it has been created (already supported in gem for
  # Exchange)
  AMQP::Queue.class_eval do
    def initialize(mq, name, opts = {}, &block)
      raise ArgumentError, "queue name must not be nil. Use '' (empty string) for server-named queues." if name.nil?

      @mq = mq
      @opts = self.class.add_default_options(name, opts, block)
      @bindings ||= {}
      @status = @opts[:nowait] ? :unknown : :unfinished

      if name.empty?
        @mq.queues_awaiting_declare_ok.push(self)
      else
        @name = name
      end

      unless opts[:no_declare]
        @mq.callback{
          @mq.send AMQP::Protocol::Queue::Declare.new(@opts)
        }
      end

      self.callback = block

      block.call(self) if @opts[:nowait] && block
    end
  end

rescue LoadError => e
  # Make sure we're dealing with a legitimate missing-file LoadError
  raise e unless e.message =~ /^no such file to load/
  # Missing 'amqp' indicates that the AMQP gem is not installed; we can ignore this
end

