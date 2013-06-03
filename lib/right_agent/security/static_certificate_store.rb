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

module RightScale

  # Simple certificate store that serves a static set of certificates and one key
  class StaticCertificateStore
    
    # Initialize store
    #
    # === Parameters
    # receiver_cert(Certificate):: Certificate for decrypting serialized data being received
    # receiver_key(RsaKeyPair):: Key corresponding to specified cert
    # signer_certs(Array|Certificate):: Signer certificate(s) used when loading data to
    #   check the digital signature. The signature associated with the serialized data
    #   needs to match with one of the signer certificates for loading to succeed.
    # target_certs(Array|Certificate):: Target certificate(s) used when serializing
    #   data for encryption. Loading the data can only be done through serializers that
    #   have been initialized with a certificate that's in the target certificates
    #   if encryption is enabled.
    def initialize(receiver_cert, receiver_key, signer_certs, target_certs)
      @receiver_cert = receiver_cert
      @receiver_key = receiver_key
      signer_certs = [ signer_certs ] unless signer_certs.respond_to?(:each)
      @signer_certs = signer_certs 
      target_certs = [ target_certs ] unless target_certs.respond_to?(:each)
      @target_certs = target_certs
    end
    
    # Retrieve signer certificates for use in verifying a signature
    #
    # === Parameters
    # id(String):: Serialized identity of signer, ignored
    #
    # === Return
    # (Array|Certificate):: Signer certificates
    def get_signer(id)
      @signer_certs
    end

    # Retrieve certificates of target for encryption
    #
    # === Parameters
    # packet(RightScale::Packet):: Packet containing target identity, ignored
    #
    # === Return
    # (Array|Certificate):: Target certificates
    def get_target(packet)
      @target_certs
    end

    # Retrieve receiver's certificate and key for decryption
    #
    # === Parameters
    # id(String|nil):: Optional identifier of source of data for use
    #   in determining who is the receiver, ignored
    #
    # === Return
    # (Array):: Certificate and key
    def get_receiver(id)
      [@receiver_cert, @receiver_key]
    end
    
  end # StaticCertificateStore

end # RightScale
