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

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

module RightScale

  # Add the ability to compare results for test purposes
  class Result
    def ==(other)
      @token == other.token && @to == other.to && @from == other.from && @results == other.results
    end
  end

end

describe RightScale::SecureSerializer do
  
  include RightScale::SpecHelper

  before(:all) do
    @dump_cert, @dump_key = issue_cert
    @load_cert, @load_key = issue_cert
    @dump_store = RightScale::StaticCertificateStore.new(@dump_cert, @dump_key, @load_cert, @load_cert)
    @load_store = RightScale::StaticCertificateStore.new(@load_cert, @load_key, @dump_cert, @dump_cert)
    @dump_id = RightScale::AgentIdentity.new("rs", "dump_agent", 1).to_s
    @load_id = RightScale::AgentIdentity.new("rs", "load_agent", 1).to_s
  end

  it "must be initialized before use" do
    data = RightScale::Result.new("token", "to", ["results"], "from")
    lambda { RightScale::SecureSerializer.dump(data) }.should raise_error(Exception, "Secure serializer not initialized")
  end

  it "must specify agent identity" do
    lambda { RightScale::SecureSerializer.init(RightScale::Serializer.new, nil, @load_store, false) }.
        should raise_error(Exception, "Missing local agent identity")
  end

  it "must specify a credentials store" do
    lambda { RightScale::SecureSerializer.init(RightScale::Serializer.new, @load_id, nil, false) }.
        should raise_error(Exception, "Missing credentials store")
  end

  it "certificate store must contain certificate and key for agent" do
    flexmock(@load_store).should_receive(:get_receiver).and_return([nil, nil]).once
    lambda { RightScale::SecureSerializer.init(RightScale::Serializer.new, @load_id, @load_store, false) }.
        should raise_error(Exception, "Missing local agent public certificate")
  end

  it "data must be serialized with MessagePack or JSON" do
    data = RightScale::Result.new("token", "to", ["results"], "from")
    RightScale::SecureSerializer.init(RightScale::Serializer.new, @load_id, @load_store, false)
    lambda { RightScale::SecureSerializer.load(Marshal.dump(data)) }.should raise_error(RightScale::Serializer::SerializationError)
    lambda { RightScale::SecureSerializer.load(YAML.dump(data)) }.should raise_error(RightScale::Serializer::SerializationError)
  end

  # Test with protocol version 11 and 12 since that is the boundary where msgpack was first supported
  [[:msgpack, 12, JSON], [:json, 11, MessagePack]].each do |type, version, other_class|

    context "using #{type.inspect}" do

      before(:each) do
        flexmock(other_class).should_receive(:dump).never
        flexmock(other_class).should_receive(:load).never
        @data = RightScale::Result.new("token", "to", ["results"], "from", nil, nil, nil, nil, [version, version])
        @serializer = RightScale::Serializer.new(type)
      end

      it "unserializes signed data" do
        RightScale::SecureSerializer.init(@serializer, @dump_id, @dump_store, false)
        data = RightScale::SecureSerializer.dump(@data)
        RightScale::SecureSerializer.init(@serializer, @load_id, @load_store, false)
        RightScale::SecureSerializer.load(data).should == @data
      end

      it "unserializes encrypted data" do
        RightScale::SecureSerializer.init(@serializer, @dump_id, @dump_store, true)
        data = RightScale::SecureSerializer.dump(@data)
        @serializer.load(data)["encrypted"].should be_true
        RightScale::SecureSerializer.init(@serializer, @load_id, @load_store, false)
        RightScale::SecureSerializer.load(data).should == @data
      end

      it "encrypt option on initialization overrides dump option" do
        RightScale::SecureSerializer.init(@serializer, @dump_id, @dump_store, true)
        data = RightScale::SecureSerializer.dump(@data, false)
        @serializer.load(data)["encrypted"].should be_true
      end

      it "uses id when supplied to choose credentials" do
        RightScale::SecureSerializer.init(@serializer, @dump_id, @dump_store, true)
        data = RightScale::SecureSerializer.dump(@data)
        RightScale::SecureSerializer.init(@serializer, @load_id, @load_store, false)
        flexmock(@load_store).should_receive(:get_receiver).with("id").and_return([@load_cert, @load_key]).once
        RightScale::SecureSerializer.load(data, "id").should == @data
      end

      it "must be able to retrieve certificate and key to decrypt message" do
        RightScale::SecureSerializer.init(@serializer, @dump_id, @dump_store, true)
        data = RightScale::SecureSerializer.dump(@data)
        RightScale::SecureSerializer.init(@serializer, @dump_id, @load_store, false)
        flexmock(@load_store).should_receive(:get_receiver).with("id").and_return([nil, @load_key], [@load_cert, nil]).twice
        lambda { RightScale::SecureSerializer.load(data, "id") }.
            should raise_error(RightScale::SecureSerializer::MissingCertificate, /Could not find a certificate/)
        lambda { RightScale::SecureSerializer.load(data, "id") }.
            should raise_error(RightScale::SecureSerializer::MissingPrivateKey, /Could not find a private key/)
      end
    end
  end

end
