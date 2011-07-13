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

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

describe "Packet: Register" do
  it "should dump/load as MessagePack objects" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], ['b1', 'b2'])
    packet2 = MessagePack.load(packet.to_msgpack)
    packet.identity.should == packet2.identity
    packet.services.should == packet2.services
    packet.brokers.should == packet2.brokers
    packet.shared_queue.should == packet2.shared_queue
    packet.shard_id.should == packet2.shard_id
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should dump/load as JSON objects" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], ['b1', 'b2'])
    packet2 = JSON.load(packet.to_json)
    packet.identity.should == packet2.identity
    packet.services.should == packet2.services
    packet.brokers.should == packet2.brokers
    packet.shared_queue.should == packet2.shared_queue
    packet.shard_id.should == packet2.shard_id
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should set specified shared_queue" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], nil, 'shared')
    packet.shared_queue.should == 'shared'
  end

  it "should default shared_queue to nil" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], nil)
    packet.shared_queue.should be_nil
   end

  it "should set specified shard_id" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], nil, 'shared', 9)
    packet.shard_id.should == 9
  end

  it "should default shard_id to nil" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], nil)
    packet.shard_id.should be_nil
   end

  it "should use current version by default when constructing" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], nil, 'shared', 9)
    packet.recv_version.should == RightScale::Packet::VERSION
    packet.send_version.should == RightScale::Packet::VERSION
  end

  it "should use default version if none supplied when unmarshalling" do
    packet = RightScale::Register.new('0xdeadbeef', ['/foo/bar', '/nik/qux'], ['foo'], nil, 'shared', 9)
    packet.instance_variable_set(:@version, nil)
    MessagePack.load(packet.to_msgpack).send_version.should == RightScale::Packet::DEFAULT_VERSION
    JSON.load(packet.to_json).send_version.should == RightScale::Packet::DEFAULT_VERSION
  end

  it "should be one-way" do
    RightScale::Register.new('0xdeadbeef', [], [], []).one_way.should be_true
  end
end


describe "Packet: UnRegister" do
  it "should dump/load as MessagePack objects" do
    packet = RightScale::UnRegister.new('0xdeadbeef')
    packet2 = MessagePack.load(packet.to_msgpack)
    packet.identity.should == packet2.identity
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should dump/load as JSON objects" do
    packet = RightScale::UnRegister.new('0xdeadbeef')
    packet2 = JSON.load(packet.to_json)
    packet.identity.should == packet2.identity
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should use current version by default when constructing" do
    packet = RightScale::UnRegister.new('0xdeadbeef')
    packet.recv_version.should == RightScale::Packet::VERSION
    packet.send_version.should == RightScale::Packet::VERSION
  end

  it "should use default version if none supplied when unmarshalling" do
    packet = RightScale::UnRegister.new('0xdeadbeef')
    packet.instance_variable_set(:@version, nil)
    MessagePack.load(packet.to_msgpack).send_version.should == RightScale::Packet::DEFAULT_VERSION
    JSON.load(packet.to_json).send_version.should == RightScale::Packet::DEFAULT_VERSION
  end
end


describe "Packet: Advertise" do
  it "should dump/load as MessagePack objects" do
    packet = RightScale::Advertise.new
    packet2 = MessagePack.load(packet.to_msgpack)
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should dump/load as JSON objects" do
    packet = RightScale::Advertise.new
    packet2 = JSON.load(packet.to_json)
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should use current version by default when constructing" do
    packet = RightScale::Advertise.new
    packet.recv_version.should == RightScale::Packet::VERSION
    packet.send_version.should == RightScale::Packet::VERSION
  end

  it "should use default version if none supplied when unmarshalling" do
    packet = RightScale::Advertise.new
    packet.instance_variable_set(:@version, nil)
    MessagePack.load(packet.to_msgpack).send_version.should == RightScale::Packet::DEFAULT_VERSION
    JSON.load(packet.to_json).send_version.should == RightScale::Packet::DEFAULT_VERSION
  end
end


describe "Packet: Stale" do
  it "should convert unmarshalled JSON data to Result packet" do
    data = {"data" => {"identity" => "0xdeadbeef", "token" => "token", "from" => "from",
                       "created_at" => 12345678, "received_at" => 87654321, "timeout" => 900},
            "size" => 100}
    packet = RightScale::Stale.json_create(data)
    packet.should be_kind_of(RightScale::Result)
    packet.token.should == "token"
    packet.from.should == "0xdeadbeef"
    packet.to.should == "from"
    packet.request_from.should == "from"
    packet.results.should be_kind_of(RightScale::OperationResult)
    packet.results.non_delivery?.should be_true
    packet.results.content.should == RightScale::OperationResult::TTL_EXPIRATION
    packet.recv_version.should == 0
    packet.send_version.should == 0
  end
end


describe "Packet: TagUpdate" do
  it "should dump/load as MessagePack objects" do
    packet = RightScale::TagUpdate.new('from', [ 'one', 'two'] , [ 'zero'])
    packet2 = MessagePack.load(packet.to_msgpack)
    packet.identity.should == packet2.identity
    packet.new_tags.should == packet2.new_tags
    packet.obsolete_tags.should == packet2.obsolete_tags
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should dump/load as JSON objects" do
    packet = RightScale::TagUpdate.new('from', ['one', 'two'] , ['zero'])
    packet2 = JSON.load(packet.to_json)
    packet.identity.should == packet2.identity
    packet.new_tags.should == packet2.new_tags
    packet.obsolete_tags.should == packet2.obsolete_tags
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should use current version by default when constructing" do
    packet = RightScale::TagUpdate.new('from', [ 'one', 'two'] , [ 'zero'])
    packet.recv_version.should == RightScale::Packet::VERSION
    packet.send_version.should == RightScale::Packet::VERSION
  end

  it "should use default version if none supplied when unmarshalling" do
    packet = RightScale::TagUpdate.new('from', [ 'one', 'two'] , [ 'zero'])
    packet.instance_variable_set(:@version, nil)
    MessagePack.load(packet.to_msgpack).send_version.should == RightScale::Packet::DEFAULT_VERSION
    JSON.load(packet.to_json).send_version.should == RightScale::Packet::DEFAULT_VERSION
  end

  it "should be one-way" do
    RightScale::TagUpdate.new('from', [] , []).one_way.should be_true
  end
end


describe "Packet: TagQuery" do
  it "should dump/load as MessagePack objects" do
    packet = RightScale::TagQuery.new('from', :token => '0xdeadbeef', :tags => [ 'one', 'two'] , :agent_ids => [ 'some_agent', 'some_other_agent'])
    packet2 = MessagePack.load(packet.to_msgpack)
    packet.from.should == packet2.from
    packet.token.should == packet2.token
    packet.tags.should == packet2.tags
    packet.agent_ids.should == packet2.agent_ids
    packet.persistent.should == packet2.persistent
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should dump/load as JSON objects" do
    packet = RightScale::TagQuery.new('from', :token => '0xdeadbeef', :tags => ['one', 'two'] , :agent_ids => ['some_agent', 'some_other_agent'])
    packet2 = JSON.load(packet.to_json)
    packet.from.should == packet2.from
    packet.token.should == packet2.token
    packet.tags.should == packet2.tags
    packet.agent_ids.should == packet2.agent_ids
    packet.persistent.should == packet2.persistent
    packet.recv_version.should == packet2.recv_version
    packet.send_version.should == packet2.send_version
  end

  it "should use current version by default when constructing" do
    packet = RightScale::TagQuery.new('from', :token => '0xdeadbeef', :tags => [ 'one', 'two'] , :agent_ids => [ 'some_agent', 'some_other_agent'])
    packet.recv_version.should == RightScale::Packet::VERSION
    packet.send_version.should == RightScale::Packet::VERSION
  end

  it "should use default version if none supplied when unmarshalling" do
    packet = RightScale::TagQuery.new('from', :token => '0xdeadbeef', :tags => [ 'one', 'two'] , :agent_ids => [ 'some_agent', 'some_other_agent'])
    packet.instance_variable_set(:@version, nil)
    MessagePack.load(packet.to_msgpack).send_version.should == RightScale::Packet::DEFAULT_VERSION
    JSON.load(packet.to_json).send_version.should == RightScale::Packet::DEFAULT_VERSION
  end

  it "should not be one-way" do
    RightScale::TagQuery.new('from', :token => '0xdeadbeef', :tags => [] , :agent_ids => []).one_way.should be_false
  end
end
