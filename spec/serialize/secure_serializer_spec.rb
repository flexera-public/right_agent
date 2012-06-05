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

  class TestException < Exception; end

  before(:all) do
    @identity = "id"
    @certificate, @key = issue_cert
  end

  before(:each) do
    @log = flexmock(RightScale::Log)
    @store = RightScale::StaticCertificateStore.new(@certificate, @certificate)
    @serializer = RightScale::Serializer.new
  end

  it 'should raise when not initialized' do
    data = RightScale::Result.new("token", "to", "from", ["results"])
    lambda { RightScale::SecureSerializer.dump(data) }.should raise_error(RightScale::SecureSerializer::InitializationError)
    lambda { RightScale::SecureSerializer.load(data) }.should raise_error(RightScale::SecureSerializer::InitializationError)
  end

  it 'should raise when data not serialized with MessagePack or JSON' do
    data = RightScale::Result.new("token", "to", "from", ["results"])
    RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
    lambda { RightScale::SecureSerializer.load(Marshal.dump(data)) }.should raise_error(RightScale::Serializer::SerializationError)
    lambda { RightScale::SecureSerializer.load(YAML.dump(data)) }.should raise_error(RightScale::Serializer::SerializationError)
  end

  it 'should detect if asynchronous operation enabled' do
    store = flexmock("certificate store", :async_enabled? => true)
    RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, store, false)
    RightScale::SecureSerializer.async_enabled?.should be_true
  end

  describe "using MessagePack" do

    before(:each) do
      flexmock(JSON).should_receive(:dump).never
      flexmock(JSON).should_receive(:load).never
      @data = RightScale::Result.new("token", "to", "from", ["results"], nil, nil, nil, nil, [12, 12])
    end

    it 'should unserialize signed data' do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

    it 'should unserialize encrypted data' do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

  end

  describe "using JSON" do

    before(:each) do
      flexmock(MessagePack).should_receive(:dump).never
      flexmock(MessagePack).should_receive(:load).never
      @data = RightScale::Result.new("token", "to", "from", ["results"], nil, nil, nil, nil, [11, 11])
    end

    it 'should unserialize signed data' do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

    it 'should unserialize encrypted data' do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

  end

  describe "dump" do

    before(:each) do
      @data = RightScale::Result.new("token", "to", "from", ["results"])
    end

    it "should raise if block given but asynchronous operation not enabled" do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
      lambda { RightScale::SecureSerializer.dump("data") { |_| } }.should raise_error(RightScale::SecureSerializer::InvalidAsyncUsage)
    end

    it "should serialize and return result" do
      @log.should_receive(:warning).with(/No certificate available/).once
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

    it "should encrypt/serialize and return result" do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

    context "when block given" do

      before(:each) do
        @certs = [@certificate]
        @store = flexmock("certificate store", :async_enabled? => true)
        @store.should_receive(:get_recipients).and_yield(@certs).by_default
        @store.should_receive(:get_signer).and_yield(@certs).by_default
        @called = 0
      end

      it "should yield exception if fail early" do
        flexmock(@serializer).should_receive(:dump).and_raise(TestException).once
        RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
        RightScale::SecureSerializer.dump(@data) { |dumped| dumped.should be_a(TestException); @called += 1 }.should be_nil
        @called.should == 1
      end

      context "and must encrypt" do

        before(:each) do
          RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
        end

        it "should encrypt/serialize and yield result" do
          RightScale::SecureSerializer.dump(@data) do |dumped|
            RightScale::SecureSerializer.load(dumped) { |loaded| loaded.should == @data }
            @called += 1
          end.should be_nil
          @called.should == 1
        end

        it "should yield exception if fails to get recipients" do
          @store.should_receive(:get_recipients).and_yield(TestException.new).once
          RightScale::SecureSerializer.dump(@data) { |dumped| dumped.should be_a(TestException); @called += 1 }.should be_nil
          @called.should == 1
        end

        it "should yield exception if serialize fails" do
          flexmock(RightScale::Signature).should_receive(:new).and_raise(TestException).once
          RightScale::SecureSerializer.dump(@data) do |dumped|
            dumped.should be_a(TestException)
            @called += 1
          end.should be_nil
          @called.should == 1
        end

      end

      context "and not encrypting" do

        before(:each) do
          RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
        end

        it "should serialize and yield result" do
          @log.should_receive(:warning).with(/No certificate available/).once
          RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
          RightScale::SecureSerializer.dump(@data) do |dumped|
            RightScale::SecureSerializer.load(dumped) { |loaded| loaded.should == @data }
            @called += 1
          end.should be_nil
          @called.should == 1
        end

        it "should yield exception if serialize fails" do
          flexmock(RightScale::Signature).should_receive(:new).and_raise(TestException).once
          RightScale::SecureSerializer.dump(@data) { |dumped| dumped.should be_a(TestException); @called += 1 }.should be_nil
          @called.should == 1
        end

      end

    end

  end

  describe "load" do

    before(:each) do
      @data = RightScale::Result.new("token", "to", "from", ["results"])
    end

    it 'should raise if block given but asynchronous operation not enabled' do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
      lambda { RightScale::SecureSerializer.load("data") { |_| } }.should raise_error(RightScale::SecureSerializer::InvalidAsyncUsage)
    end

    it "should unserialize and return result" do
      @log.should_receive(:warning).with(/No certificate available/).once
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, false)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

    it "should decrypt/unserialize and return result" do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
      data = RightScale::SecureSerializer.dump(@data)
      RightScale::SecureSerializer.load(data).should == @data
    end

    it "should raise if certs missing" do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
      data = RightScale::SecureSerializer.dump(@data)
      flexmock(@store).should_receive(:get_signer).and_return(nil).once
      lambda { RightScale::SecureSerializer.load(data) }.should raise_error(RightScale::SecureSerializer::MissingCertificate)
    end

    it "should raise if signature invalid" do
      RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
      data = RightScale::SecureSerializer.dump(@data)
      flexmock(@store).should_receive(:get_signer).and_return([]).once
      lambda { RightScale::SecureSerializer.load(data) }.should raise_error(RightScale::SecureSerializer::InvalidSignature)
    end

    context "when block given" do

      before(:each) do
        @certs = [@certificate]
        @store = flexmock("certificate store", :async_enabled? => true)
        @store.should_receive(:get_recipients).and_yield(@certs).by_default
        @store.should_receive(:get_signer).and_yield(@certs).by_default
        RightScale::SecureSerializer.init(@serializer, @identity, @certificate, @key, @store, true)
        RightScale::SecureSerializer.dump(@data) { |result| @dumped = result }
        @called = 0
      end

      it "should yield exception if fail early" do
        flexmock(@serializer).should_receive(:load).and_raise(TestException).once
        RightScale::SecureSerializer.load(@dumped) { |loaded| loaded.should be_a(TestException); @called += 1 }.should be_nil
        @called.should == 1
      end

      it "should decrypt/unserialize and yield result" do
        RightScale::SecureSerializer.load(@dumped) { |loaded| loaded.should == @data; @called += 1 }.should be_nil
        @called.should == 1
      end

      it "should yield exception if fails to get signer" do
        @store.should_receive(:get_signer).and_yield(TestException.new).once
        RightScale::SecureSerializer.load(@dumped) { |loaded| loaded.should be_a(TestException); @called += 1 }.should be_nil
        @called.should == 1
      end

      it "should yield exception if unserialize fails" do
        flexmock(RightScale::EncryptedDocument).should_receive(:from_data).and_raise(TestException).once
        RightScale::SecureSerializer.load(@dumped) { |loaded| loaded.should be_a(TestException); @called += 1 }.should be_nil
        @called.should == 1
      end

    end

  end

end
