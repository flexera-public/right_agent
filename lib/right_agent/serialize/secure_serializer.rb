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
  
  # Serializer implementation which secures messages by using
  # X.509 certificate signing
  class SecureSerializer

    class InitializationError < Exception; end
    class InvalidAsyncUsage < Exception; end
    class MissingCertificate < Exception; end
    class InvalidSignature < Exception; end

    # create the one and only SecureSerializer
    def self.init(serializer, identity, cert, key, store, encrypt = true)
      @serializer = SecureSerializer.new(serializer, identity, cert, key, store, encrypt)
      true
    end

    # Was serializer initialized?
    def self.initialized?
      !@serializer.nil?
    end

    # See SecureSerializer#async_enabled?
    def self.async_enabled?
      @serializer && @serializer.async_enabled?
    end

    # See SecureSerializer#dump
    def self.dump(obj, encrypt = nil)
      raise InitializationError.new("Not initialized") unless initialized?
      if block_given?
        @serializer.dump(obj, encrypt) { |result| yield(result) }
        nil
      else
        @serializer.dump(obj, encrypt)
      end
    end

    # See SecureSerializer#load
    def self.load(msg)
      raise InitializationError.new("Not initialized") unless initialized?
      if block_given?
        @serializer.load(msg) { |result| yield(result) }
        nil
      else
        @serializer.load(msg)
      end
    end

    # Initialize serializer, must be called prior to using it
    #
    # === Parameters
    # serializer(Serializer):: Object serializer
    # identity(String):: Serialized identity associated with serialized messages
    # cert(String):: X.509 certificate used to sign and decrypt serialized messages
    # key(RsaKeyPair):: X.509 private key corresponding to specified cert
    # store(Object):: Certificate store exposing certificates used for
    #   encryption (get_recipients) and signature validation (get_signer)
    # encrypt(Boolean):: true if data should be signed and encrypted, otherwise
    #   just signed, true by default
    def initialize(serializer, identity, cert, key, store, encrypt = true)
      @identity = identity
      @cert = cert
      @key = key
      @store = store
      @encrypt = encrypt
      @serializer = serializer
    end

    # Whether asynchronous operation enabled
    #
    # === Return
    # (Boolean):: true if async enabled, otherwise false
    def async_enabled?
      @store.respond_to?(:async_enabled?) && @store.async_enabled?
    end

    # Serialize, sign, and encrypt message
    # Sign and encrypt using X.509 certificate
    #
    # === Parameters
    # obj(Object):: Object to be serialized and encrypted
    # encrypt(Boolean|nil):: true if object should be signed and encrypted,
    #   false if just signed, nil means use class setting
    #
    # === Block
    # Optional block that is asynchronously yielded the serialized message or an exception
    #
    # === Raise
    # InitializationError:: If certificate identity, certificate store, certificate, or private key missing
    # InvalidAsyncUsage:: If block given but asynchronous operation not enabled
    #
    # === Return
    # (String):: MessagePack serialized and optionally encrypted object unless block given
    def dump(obj, encrypt = nil, &block)
      raise InitializationError.new("Missing certificate identity") unless @identity
      raise InitializationError.new("Missing certificate") unless @cert
      raise InitializationError.new("Missing certificate key") unless @key
      raise InitializationError.new("Missing certificate store") unless @store || !@encrypt
      if block
        async = async_enabled?
        raise InvalidAsyncUsage.new("Asynchronous operation not enabled") unless async
      end
      encrypt ||= @encrypt
      serialize_format = if obj.respond_to?(:send_version) && obj.send_version >= 12
        @serializer.format
      else
        :json
      end
      encrypt_format = (serialize_format == :json ? :pem : :der)
      msg = @serializer.dump(obj, serialize_format)
      if async
        if encrypt
          begin
            @store.get_recipients(obj) do |result|
              unless result.is_a?(Exception)
                result = begin
                  serialize(obj, msg, result, encrypt_format, serialize_format)
                rescue Exception => e
                  e
                end
              end
              yield(result)
            end
          rescue Exception => e
            yield(e)
          end
        else
          result = begin
            serialize(obj, msg, nil, encrypt_format, serialize_format)
          rescue Exception => e
            e
          end
          yield(result)
        end
        nil
      else
        certs = @store.get_recipients(obj) if encrypt
        serialize(obj, msg, certs, encrypt_format, serialize_format)
      end
    rescue Exception => e
      async ? yield(e) : raise
    end

    # Encrypt and serialize message
    #
    # === Parameters
    # obj(Object):: Original object to be serialized and encrypted
    # msg(Object):: Message object to be serialized
    # certs(Array|Certificate):: X.509 public certificate(s) of recipient
    # encrypt_format(Symbol):: Encrypt format: :pem or :der
    # serialize_format(Symbol):: Serialization format: :json or :msgpack
    #
    # === Return
    # (String):: Serialized message
    def serialize(obj, msg, certs, encrypt_format, serialize_format)
      if certs
        msg = EncryptedDocument.new(msg, certs).encrypted_data(encrypt_format)
      else
        target = obj.target_for_encryption if obj.respond_to?(:target_for_encryption)
        Log.warning("No certificate available for object #{obj.class} being sent to #{target.inspect}\n") if target
      end
      sig = Signature.new(msg, @cert, @key).data(encrypt_format)
      @serializer.dump({'id' => @identity, 'data' => msg, 'signature' => sig, 'encrypted' => !certs.nil?}, serialize_format)
    end
    
    # Decrypt, authorize signature, and unserialize message
    # Use x.509 certificate store for decrypting and validating signature
    #
    # === Parameters
    # msg(String):: Serialized and optionally encrypted object using MessagePack or JSON
    #
    # === Block
    # Optional block that is asynchronously yielded the unserialized message or an exception
    #
    # === Raise
    # InitializationError:: If certificate store, certificate, private key missing, or
    # InvalidAsyncUsage:: If block given but asynchronous operation not enabled
    #
    # === Return
    # (Object):: Unserialized object unless block given
    def load(msg, &block)
      raise InitializationError.new("Missing certificate store") unless @store
      raise InitializationError.new("Missing certificate") unless @cert || !@encrypt
      raise InitializationError.new("Missing certificate key") unless @key || !@encrypt
      if block
        async = async_enabled?
        raise InvalidAsyncUsage.new("Asynchronous operation not enabled") unless async
      end

      msg = @serializer.load(msg)
      sig = Signature.from_data(msg['signature'])
      if async
        begin
          @store.get_signer(msg['id']) do |result|
            unless result.is_a?(Exception)
              result = begin
                unserialize(msg, result, sig)
              rescue Exception => e
                e
              end
            end
            yield(result)
          end
        rescue Exception => e
          yield(e)
        end
        nil
      else
        certs = @store.get_signer(msg['id'])
        unserialize(msg, certs, sig)
      end
    rescue Exception => e
      async ? yield(e) : raise
    end

    # Decrypt and unserialize message
    #
    # === Parameters
    # msg(String):: Serialized and optionally encrypted object using MessagePack or JSON
    # certs(Array|Certificate):: X.509 public certificate(s) of message signer
    # sig(Signature):: Signature extracted from message
    #
    # === Raise
    # MissingCertificate:: If could not find certificate for message signer
    # InvalidSignature:: If message signature check failed for message
    #
    # === Return
    # (Object):: Unserialized message
    def unserialize(msg, certs, sig)
      raise MissingCertificate.new("Could not find a certificate for signer #{msg['id']}") unless certs

      certs = [ certs ] unless certs.respond_to?(:any?)
      raise InvalidSignature.new("Failed signature check for signer #{msg['id']}") unless certs.any? { |c| sig.match?(c) }

      data = msg['data']
      if data && @encrypt && msg['encrypted']
        data = EncryptedDocument.from_data(data).decrypted_data(@key, @cert)
      end
      @serializer.load(data) if data
    end

  end # SecureSerializer

end # RightScale
