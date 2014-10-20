#
# Copyright (c) 2009-2013 RightScale Inc
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

module JSONSerializer
  def self.load(source)
    JSON.legacy_load(source)
  end

  def self.dump(*args)
    JSON.dump(*args)
  end
end

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
    end

    # Serialize object using preferred serializer
    # Do not cascade
    #
    # === Parameters
    # packet(Object):: Object to be serialized
    # format(Symbol):: Override preferred format
    #
    # === Return
    # (String):: Serialized object
    def dump(packet, format = nil)
      cascade_serializers(:dump, packet, [@secure ? SecureSerializer : SERIALIZERS[format || @format]])
    end

    # Unserialize object using cascaded serializers with order chosen by peaking at first byte
    #
    # === Parameters
    # packet(String):: Data representing serialized object
    # id(String|nil):: Optional identifier of source of data for use
    #   in determining who is the receiver
    #
    # === Return
    # (Object):: Unserialized object
    def load(packet, id = nil)
      cascade_serializers(:load, packet, @secure ? [SecureSerializer] : order_serializers(packet), id)
    end

    private

    # Supported serialization formats
    SERIALIZERS = {:msgpack => MessagePack, :json => JSONSerializer}.freeze
    MSGPACK_FIRST_SERIALIZERS = [MessagePack, JSONSerializer].freeze
    JSON_FIRST_SERIALIZERS = MSGPACK_FIRST_SERIALIZERS.clone.reverse.freeze
    FORMATS = (SERIALIZERS.keys + [:secure]).freeze
    DEFAULT_FORMAT = :msgpack

    # Apply serializers in order until one succeeds
    #
    # === Parameters
    # action(Symbol):: Serialization action: :dump or :load
    # packet(Object|String):: Object or serialized data on which action is to be performed
    # serializers(Array):: Serializers to apply in order
    # id(String):: Optional identifier of source of data for use in determining who is the receiver
    #
    # === Return
    # (String|Object):: Result of serialization action
    #
    # === Raises
    # SerializationError:: If none of the serializers can perform the requested action
    # RightScale::Exceptions::ConnectivityFailure:: If cannot access external services
    def cascade_serializers(action, packet, serializers, id = nil)
      errors = []
      serializers.map do |serializer|
        obj = nil
        begin
          obj = serializer == SecureSerializer ? serializer.send(action, packet, id) : serializer.send(action, packet)
        rescue RightSupport::Net::NoResult, SocketError => e
          raise Exceptions::ConnectivityFailure.new("Failed to #{action} with #{serializer.name} due to external " +
                                                    "service access failures (#{e.class.name}: #{e.message})", e)
        rescue SecureSerializer::MissingCertificate, SecureSerializer::MissingPrivateKey, SecureSerializer::InvalidSignature => e
          errors << Log.format("Failed to #{action} with #{serializer.name}", e)
        rescue StandardError => e
          errors << Log.format("Failed to #{action} with #{serializer.name}", e, :trace)
        end
        return obj if obj
      end
      raise SerializationError.new(action, packet, serializers, errors.join("\n"))
    end

    # Determine likely serialization format and order serializers accordingly
    #
    # === Parameters
    # packet(String):: Data representing serialized object
    #
    # === Return
    # (Array):: Ordered serializers
    def order_serializers(packet)
      # note the following code for getting the ascii value of the first byte is
      # efficient for a large packet because it returns an enumerator for the
      # internal byte array. it is actually more efficient than extracting the
      # first character as a string and converting it to bytes.
      # also, the following line works for both ruby 1.8 and ruby 1.9 since the
      # definition of the bracket operator has changed.
      packet.bytes.first > 127 ? MSGPACK_FIRST_SERIALIZERS : JSON_FIRST_SERIALIZERS
    end

  end # Serializer
  
end # RightScale
