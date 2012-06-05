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

require 'rubygems'
require 'time'
require 'date'
require 'json'

require File.normalize_path(File.join(File.dirname(__FILE__), 'message_pack'))

# Monkey patch common classes to support MessagePack serialization
# As with JSON, unserializing them is manual using existing methods such as parse
class Date
  def to_msgpack(*a); to_s.to_msgpack(*a) end
end

class Time
  def to_msgpack(*a); to_s.to_msgpack(*a) end
end

class DateTime
  def to_msgpack(*a); to_s.to_msgpack(*a) end
end

module RightScale
  
  # Cascade serializer supporting MessagePack and JSON serialization formats
  # as well as secure serialization
  class Serializer

    class SerializationError < StandardError
      attr_accessor :action, :packet
      def initialize(action, packet, serializers, msg = nil)
        @action, @packet = action, packet
        msg = " (#{msg})" if msg && !msg.empty?
        super("Could not #{action} packet using #{serializers.inspect}#{msg}")
      end
    end

    # (Symbol) Preferred serialization format
    attr_reader :format

    # Initialize the serializer
    # Do not cascade serializers if :secure is specified
    #
    # === Parameters
    # preferred_format(Symbol|String):: Preferred serialization format: :msgpack, :json, or :secure
    #
    # === Raises
    # ArgumentError:: If preferred format is not supported
    def initialize(preferred_format = nil)
      @format = (preferred_format ||= DEFAULT_FORMAT).to_sym
      raise ArgumentError, "Serializer format #{@format.inspect} not one of #{FORMATS.inspect}" unless FORMATS.include?(@format)
      @secure = (@format == :secure)
      @async_enabled = @secure && SecureSerializer.async_enabled?
    end

    # Whether asynchronous operation enabled
    #
    # === Return
    # (Boolean):: true if async enabled, otherwise false
    def async_enabled?
      @async_enabled
    end

    # Serialize object using preferred serializer
    # Do not cascade
    #
    # === Parameters
    # packet(Object):: Object to be serialized
    # format(Symbol):: Override preferred format
    #
    # === Block
    # Optional block that is asynchronously yielded the serialized message or an exception
    #
    # === Raise
    # ArgumentError:: If block given but asynchronous operation not supported
    #
    # === Return
    # (String):: Serialized object, or nil if block given
    def dump(packet, format = nil, &block)
      if block
        raise ArgumentError, "Asynchronous operation not enabled" unless @async_enabled
        apply_serializer(SecureSerializer, :dump, packet, []) { |message| yield(message) }
        nil
      else
        cascade_serializers(:dump, packet, [@secure ? SecureSerializer : SERIALIZERS[format || @format]])
      end
    end

    # Unserialize object using cascaded serializers with order chosen by peaking at first byte
    #
    # === Parameters
    # packet(String):: Data representing serialized object
    #
    # === Block
    # Optional block that is asynchronously yielded the unserialized message or an exception
    #
    # === Raise
    # ArgumentError:: If block given but asynchronous operation not supported
    #
    # === Return
    # (Object):: Unserialized object, or nil if block given
    def load(packet, &block)
      if block
        raise ArgumentError, "Asynchronous operation not enabled" unless @async_enabled
        # Inferring SecureSerializer since only it supports asynchronous operation
        apply_serializer(SecureSerializer, :load, packet, []) { |message| yield(message) }
        nil
      else
        cascade_serializers(:load, packet, @secure ? [SecureSerializer] : order_serializers(packet))
      end
    end

    private

    # Supported serialization formats
    SERIALIZERS = {:msgpack => MessagePack, :json => JSON}.freeze
    MSGPACK_FIRST_SERIALIZERS = [MessagePack, JSON].freeze
    JSON_FIRST_SERIALIZERS = MSGPACK_FIRST_SERIALIZERS.clone.reverse.freeze
    FORMATS = (SERIALIZERS.keys + [:secure]).freeze
    DEFAULT_FORMAT = :msgpack

    # Apply serializers in order until one succeeds
    #
    # === Parameters
    # action(Symbol):: Serialization action: :dump or :load
    # packet(Object|String):: Object or serialized data on which action is to be performed
    # serializers(Array):: Serializers to apply in order
    #
    # === Raise
    # SerializationError:: If none of the serializers can perform the requested action
    #
    # === Return
    # object(String|Object):: Result of serialization action, or nil if block_given
    def cascade_serializers(action, packet, serializers)
      errors = []
      serializers.map do |serializer|
        object = apply_serializer(serializer, action, packet, errors)
        return object if object
      end
      raise SerializationError.new(action, packet, serializers, errors.join("\n"))
    end

    # Apply serializer
    #
    # === Parameters
    # serializer(Serializer):: Serializer to apply
    # action(Symbol):: Serialization action: :dump or :load
    # packet(Object|String):: Object or serialized data on which action is to be performed
    # errors(Array):: Accumulator for serialization errors
    #
    # === Block
    # Optional block that is asynchronously yielded the serialization result or an exception
    #
    # === Return
    # object(String|Object):: Result of serialization action, or nil if block_given
    def apply_serializer(serializer, action, packet, errors)
      object = nil
      begin
        if block_given?
          serializer.__send__(action, packet) { |object| yield(object) }
        else
          object = serializer.__send__(action, packet)
        end
      rescue SecureSerializer::MissingCertificate, SecureSerializer::InvalidSignature => e
        errors << Log.format("Failed to #{action} with #{serializer.name}", e)
        yield(SerializationError.new(action, packet, serializer, errors.join("\n"))) if block_given?
      rescue Exception => e
        errors << Log.format("Failed to #{action} with #{serializer.name}", e, :trace)
        yield(SerializationError.new(action, packet, serializer, errors.join("\n"))) if block_given?
      end
      object
    end

    # Determine likely serialization format and order serializers accordingly
    #
    # === Parameters
    # packet(String):: Data representing serialized object
    #
    # === Return
    # (Array):: Ordered serializers
    def order_serializers(packet)
      packet.getbyte(0) > 127 ? MSGPACK_FIRST_SERIALIZERS : JSON_FIRST_SERIALIZERS
    end

  end # Serializer
  
end # RightScale
