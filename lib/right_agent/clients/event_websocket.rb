#
# Copyright (c) 2014 RightScale Inc
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

require 'faye/websocket'

# Monkey patch faye-websocket (0.7.0) WebSocket close method so that can specify status code and reason
# Valid status codes are defined in RFC6455 section 7.4.1
module Faye
  class WebSocket
    module API
      def close(code = nil, reason = nil)
        @ready_state = CLOSING if @ready_state == OPEN
        @driver.close(reason, code)
      end
    end
  end
end

module RightScale

  # Wrapper for WebSocket to impose message IDs and JSON encoding
  # as required for RightNet-based event communication
  class EventWebSocket

    include ProtocolVersionMixin

    # Rack response for WebSocket for async handling (equivalent to throw :async)
    RACK_RESPONSE = [-1, {}, []]

    # WebSocket close status codes
    NORMAL_CLOSE = 1000
    SHUTDOWN_CLOSE = 1001
    PROTOCOL_ERROR_CLOSE = 1002
    UNEXPECTED_ERROR_CLOSE = 1011

    # Maximum time-to-live seconds for errback for sent message
    ERRBACK_TTL = 120

    # [Boolean] Whether enabled for generic event usage as opposed to legacy
    #   instance agent specific events
    attr_reader :generic

    # Create client or server WebSocket
    #
    # @param [String, Hash] url_or_env URL for accessing server if on client side;
    #   otherwise environment from rack middleware
    # @param [Array<String>, NilClass] protocols supported
    #
    # @option options [String] :peer identification to be used when logging errors
    # @option options [Integer] :protocol_version for RightAgent communication;
    #   defaults to one used locally
    # @option options [Boolean] :is_server or client creating WebSocket
    # @option options [Integer] :ping frames to be sent every this many seconds
    # @option options [Integer] :max_length of incoming message frames in bytes;
    #   defaults is 1 byte short of 64MB
    # @option options [Hash] :headers to be sent during the handshake process
    def initialize(url_or_env, protocols = nil, options = {})
      @in_id = 0
      @out_id = 0
      @errbacks = {}
      @active_out_ids = []
      options = options.dup
      peer = options.delete(:peer)
      @from = peer ? " from #{peer}" : ""
      version = options.delete(:protocol_version) || AgentConfig.protocol_version
      @generic = version && can_handle_generic_events?(version)
      websocket_class = options.delete(:is_server) ? Faye::WebSocket : Faye::WebSocket::Client
      @websocket = websocket_class.new(url_or_env, protocols, options)
    end

    # Send message after JSON encoding it
    #
    # @param [Hash] message to be sent on WebSocket
    #
    # @yield [status, content] optionally asynchronously if error returned within ERRBACK_TTL seconds
    # @yieldparam [Integer] status code per HTTP
    # @yieldparam [String] content describing error
    #
    # @return [Boolean] true if sent, otherwise false
    def send(message, &errback)
      if @generic
        msg_id = (@out_id += 1)
        message[:msg_id] = msg_id
        if errback
          @errbacks[msg_id] = errback
          @active_out_ids << [msg_id, Time.now.to_i]
        end
      else
        # Be compatible with older version when event was the message
        message = message[:event] || message
      end
      Log.debug("Sending WebSocket message: #{message.inspect}")
      @websocket.send(JSON.dump(message))
    end

    # Send error message
    #
    # @param [Integer] status code per HTTP
    # @param [String] content describing error
    # @param [Hash, NilClass] data from message containing :msg_id
    #
    # @return [TrueClass] always true
    def send_error(status, content, data = nil)
      send({:error => {:status => status, :content => content, :msg_id => (data[:msg_id] rescue nil)}}) if @generic
      true
    end

    # Preprocess message received to impose message formatting rules
    #
    # @param [String] message received on WebSocket, JSON-encoded
    #
    # @return [Hash] JSON-decoded message
    def receive(message)
      begin
        data = JSON.load(message)
      rescue StandardError
        ErrorTracker.log(self, "Cannot JSON decode WebSocket message")
        return nil
      end

      if data.is_a?(Hash)
        data = SerializationHelper.symbolize_keys(data)
        Log.debug("Received WebSocket message: #{message.inspect}")
        if (msg_id = data[:msg_id])
          if msg_id <= @in_id
            Log.info("Dropping WebSocket message with ID #{msg_id} because repeated, current is #{@in_id}")
            data = nil
          elsif msg_id != (@in_id + 1)
            ErrorTracker.log(self, "WebSocket message with ID #{msg_id} is out of sequence, " +
                                   "expected #{@in_id + 1}, closing connection")
            close(UNEXPECTED_ERROR_CLOSE, "Message sequence gap")
            data = nil
          else
            @in_id = msg_id
            data.each_key do |key|
              case key
              when :msg_id
              when :event  then data[key] = SerializationHelper.symbolize_keys(data[key]);
                                @on_event_message && @on_event_message.call(data)
              when :ack    then @on_ack_message && @on_ack_message.call(data)
              when :replay then @on_replay_message && @on_replay_message.call(data)
              when :error  then data[key] = SerializationHelper.symbolize_keys(data[key]);
                                receive_error(data)
              when :routing_keys
              else
                ErrorTracker.log(self, "Unrecognized WebSocket message key #{key.inspect}#{@from}")
              end
            end
            expire_errbacks
          end
        elsif @generic
          ErrorTracker.log(self, "Ignoring WebSocket message#{@from} because missing :msg_id")
          send_error(400, "Invalid WebSocket message, missing :msg_id")
          data = nil
        else
          # To be downward compatible
          if data[:uuid]
            data = {:event => data}
            @on_event_message && @on_event_message.call(data)
          elsif data[:ack]
            @on_ack_message && @on_ack_message.call(data)
          else
            ErrorTracker.log(self, "Unrecognized WebSocket message#{@from}: #{data.inspect}")
            data = nil
          end
        end
      else
        ErrorTracker.log(self, "Unrecognized message on WebSocket#{@from}: #{data.inspect}")
        send_error(400, "Invalid message format (must be JSON-encoded hash): #{data.inspect}")
        data = nil
      end
      data
    end

    # Handle error by logging it and making any associated callback locally
    # as well as to application if defined
    # Only allow one callback for a given message
    #
    # @param [Hash] data from message containing :error which is a hash
    #   containing :status, :content, and optionally :msg_id
    #
    # @return [TrueClass] true
    def receive_error(data)
      error = data[:error]
      for_msg_id = error[:msg_id] ? " for message ID #{error[:msg_id]}" : ""
      ErrorTracker.log(self, "Error received on WebSocket#{for_msg_id} (#{error[:status]}: #{error[:content]})")
      if (msg_id = error[:msg_id]) && (errback = @errbacks.delete(msg_id))
        errback.call(error[:status], error[:content])
      end
      @on_error_message && @on_error_message.call(data)
      true
    end

    # Store block to be executed when event is received
    #
    # @param [Proc] proc with one parameter, which is a hash containing :event
    #   as hash and :routing_keys as an array
    #
    # @return [Proc] proc stored
    def oneventmessage=(proc)
      @on_event_message = proc
    end

    # Store proc to be executed when event is acknowledged
    #
    # @param [Proc] proc with one parameter, which is a hash containing :ack
    #   as a UUID string
    #
    # @return [Proc] proc stored
    def onackmessage=(proc)
      @on_ack_message = proc
    end

    # Store proc to be executed when events are to be replayed
    #
    # @param [Proc] proc with one parameter, which is a hash containing :replay
    #   as an array of UUIDs
    #
    # @return [Proc] proc stored
    def onreplaymessage=(proc)
      @on_replay_message = proc
    end

    # Store proc to be executed when error message is received
    # The callback does not happen until internal actions associated with error
    # are taken including logging error and making any stored errback call
    # for associated message that caused error
    #
    # @param [Proc] proc with one parameter, which is a hash containing :error
    #   as a hash
    #
    # @return [Proc] proc stored
    def onerrormessage=(proc)
      @on_error_message = proc
    end

    # Other standard Faye::WebSocket functions
    def onmessage=(proc)
      @websocket.onmessage = proc
    end

    def onerror=(proc)
      @websocket.onerror = proc
    end

    def onclose=(proc)
      @websocket.onclose = proc
    end

    def close(*args)
      @websocket.close(*args)
    end

    def rack_response
      @websocket.rack_response
    end

    protected

    # Delete errback procs that have expired
    #
    # @return [TrueClass] always true
    def expire_errbacks
      if @generic
        now = Time.now.to_i
        @active_out_ids.delete_if do |msg_id, timestamp|
          if (now - timestamp) > ERRBACK_TTL
            @errbacks.delete(msg_id)
            true
          else
            break
          end
        end
      end
      true
    end

  end # EventWebSocket

end # RightScale