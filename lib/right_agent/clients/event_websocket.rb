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

module RightScale

  # Wrapper for WebSocket to impose message IDs and JSON encoding
  # as required for RightNet-based event communication
  class EventWebSocket

    include ProtocolVersionMixin

    # [Boolean] Whether enabled for generic event usage as opposed to legacy
    #   instance agent specific events
    attr_reader :generic

    # Create client or server WebSocket
    #
    # @param [String, Hash] url_or_env URL for accessing server if on client side;
    #   otherwise environment from rack middleware
    # @param [Array<String>] protocols supported
    #
    # @option options [String] :peer identification to be used when logging errors
    # @option options [Integer] :protocol_version for RightAgent communication;
    #   defaults to one used locally
    # @option options [Boolean] :is_server or client creating WebSocket
    # @option options [Integer] :ping frames to be sent every this many seconds
    # @option options [Integer] :max_length of incoming message frames in bytes;
    #   defaults is 1 byte short of 64MB
    # @option options [Hash] :headers to be sent during the handshake process
    def initialize(url_or_env, protocols, options = {})
      @in_id = 0
      @out_id = 0
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
    # @return [Boolean] true if sent, otherwise false
    def send(message)
      if @generic
        message[:msg_id] = (@out_id += 1)
      else
        # Be compatible with older version when event was the message
        message = message[:event] || message
      end
      Log.debug("Sending WebSocket message: #{message.inspect}")
      @websocket.send(JSON.dump(message))
    end

    # Preprocess message received to impose message formatting rules
    #
    # @param [String] message received on WebSocket, JSON-encoded
    #
    # @return [Hash] JSON-decoded message
    def receive(message)
      data = JSON.load(message)
      if data.is_a?(Hash)
        data = SerializationHelper.symbolize_keys(data)
        Log.debug("Received WebSocket message: #{message.inspect}")
        if (msg_id = data[:msg_id])
          Log.info("Message #{msg_id} out of sequence, previous was #{@in_id}") if msg_id != (@in_id + 1)
          @in_id = msg_id
          data.each_key do |key|
            case key
            when :msg_id
            when :event  then @on_event && @on_event.call(data)
            when :ack    then @on_ack && @on_ack.call(data)
            when :replay then @on_replay && @on_replay.call(data)
            when :error  then ErrorTracker.log(self, "Error received on WebSocket: #{data[:error].inspect}")
            when :routing_keys
            else
              ErrorTracker.log(self, "Unrecognized WebSocket message key #{key.inspect} from #{agent_id}")
            end
          end
        elsif @generic
          ErrorTracker.log(self, "Ignoring message#{@from} because missing :msg_id")
          error(400, "Invalid message, missing :msg_id")
          data = nil
        end
      else
        ErrorTracker.log(self, "Unrecognized message on WebSocket#{@from}: #{data.inspect}")
        error(400, "Invalid message format (must be JSON-encoded hash): #{data.inspect}")
        data = nil
      end
      data
    end

    # Send error message
    #
    # @param [Integer] status code per HTTP
    # @param [String] content describing error
    # @param [Hash, NilClass] data from message containing :msg_id
    #
    # @return [TrueClass] always true
    def error(status, content, data = nil)
      send({:error => {:status => status, :content => content, :msg_id => (data[:msg_id] rescue nil)}}) if @generic
      true
    end

    # Store block to be executed when event is received
    #
    # @yield [data] required when event is received
    # @yieldparam [Hash] data received with :event and :routing_keys keys
    #
    # @return [TrueClass] always true
    def onevent=(proc)
      @on_event = proc
      true
    end

    # Store proc to be executed when event is acknowledged
    #
    # @yield [data] required when event is acknowledged
    # @yieldparam [Hash] data received with :ack key
    #
    # @return [TrueClass] always true
    def onack=(proc)
      @on_ack = proc
      true
    end

    # Store proc to be executed when events are to be replayed
    #
    # @yield [data] required when events are to be replayed
    # @yieldparam [Hash] data received with :replay key
    #
    # @return [TrueClass] always true
    def onreplay=(proc)
      @on_replay = proc
      true
    end

    # Other standard Faye::WebSocket functions
    def onerror=(proc)
      @websocket.onerror = proc
    end

    def onclose=(proc)
      @websocket.onclose = proc
    end

    def onmessage=(proc)
      @websocket.onmessage = proc
    end

    def close(*args)
      @websocket.close(*args)
    end

    def rack_response
      @websocket.rack_response
    end

  end # EventWebSocket

end # RightScale