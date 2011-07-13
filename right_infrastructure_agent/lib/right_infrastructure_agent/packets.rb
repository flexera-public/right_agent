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

module RightScale

  # Packet for availability notification from an agent to the mappers
  class Register < Packet

    attr_accessor :identity, :services, :tags, :brokers, :shared_queue, :shard_id, :version

    # Create packet
    #
    # === Parameters
    # identity(String):: Identity of agent registering
    # services(Array):: List of services provided by the agent
    # tags(Array(Symbol)):: List of tags associated with this service
    # brokers(Array|nil):: Identity of agent's brokers with nil meaning not supported
    # shared_queue(String):: Name of a queue shared between this agent and another
    # shard_id(Integer|nil):: Shard to which agent is restricted or nil if shard independent
    # version(Array):: Protocol version of the original creator of the packet followed by the
    #   protocol version of the packet contents to be used when sending
    # size(Integer):: Size of request in bytes used only for marshalling
    def initialize(identity, services, tags, brokers, shared_queue = nil, shard_id = nil, version = [VERSION, VERSION], size = nil)
      @identity     = identity
      @services     = services
      @tags         = tags
      @brokers      = brokers
      @shared_queue = shared_queue
      @shard_id     = shard_id
      @version      = version
      @size         = size
    end

    # Create packet from unmarshalled data
    #
    # === Parameters
    # o(Hash):: Unmarshalled data
    #
    # === Return
    # (Register):: New packet
    def self.create(o)
      i = o['data']
      if version = i['version']
        version = [version, version] unless version.is_a?(Array)
      else
        version = [DEFAULT_VERSION, DEFAULT_VERSION]
      end
      new(self.compatible(i['identity']), i['services'], i['tags'], i['brokers'], i['shared_queue'], i['shard_id'], version, o['size'])
    end

    # Generate log representation
    #
    # === Parameters
    # filter(Array(Symbol)):: Attributes to be included in output
    # version(Symbol|nil):: Version to display: :recv_version, :send_version, or nil meaning none
    #
    # === Return
    # log_msg(String):: Log representation
    def to_s(filter = nil, version = nil)
      log_msg = "#{super(filter, version)} #{id_to_s(@identity)}"
      log_msg += ", shared_queue #{@shared_queue}" if @shared_queue
      log_msg += ", shard_id #{@shard_id}" if @shard_id
      log_msg += ", services #{@services.inspect}" if @services && !@services.empty?
      log_msg += ", brokers #{@brokers.inspect}" if @brokers && !@brokers.empty?
      log_msg += ", tags #{@tags.inspect}" if @tags && !@tags.empty?
      log_msg
    end

  end # Register


  # Packet for unregistering an agent from the mappers
  class UnRegister < Packet

    attr_accessor :identity

    # Create packet
    #
    # === Parameters
    # identity(String):: Identity of agent unregistering
    # version(Array):: Protocol version of the original creator of the packet followed by the
    #   protocol version of the packet contents to be used when sending
    # size(Integer):: Size of request in bytes used only for marshalling
    def initialize(identity, version = [VERSION, VERSION], size = nil)
      @identity = identity
      @version  = version
      @size     = size
    end

    # Create packet from unmarshalled data
    #
    # === Parameters
    # o(Hash):: Unmarshalled data
    #
    # === Return
    # (UnRegister):: New packet
    def self.create(o)
      i = o['data']
      new(self.compatible(i['identity']), i['version'] || [DEFAULT_VERSION, DEFAULT_VERSION], o['size'])
    end

    # Generate log representation
    #
    # === Parameters
    # filter(Array(Symbol)):: Attributes to be included in output
    # version(Symbol|nil):: Version to display: :recv_version, :send_version, or nil meaning none
    #
    # === Return
    # (String):: Log representation
    def to_s(filter = nil, version = nil)
      "#{super(filter, version)} #{id_to_s(@identity)}"
    end

  end # UnRegister


  # Packet for requesting an agent to advertise its services to the mappers
  # when it initially comes online
  class Advertise < Packet

    # Create packet
    #
    # === Parameters
    # version(Array):: Protocol version of the original creator of the packet followed by the
    #   protocol version of the packet contents to be used when sending
    # size(Integer):: Size of request in bytes used only for marshalling
    def initialize(version = [VERSION, VERSION], size = nil)
      @version = version
      @size = size
    end

    # Create packet from unmarshalled data
    #
    # === Parameters
    # o(Hash):: Unmarshalled data
    #
    # === Return
    # (Advertise):: New packet
    def self.create(o)
      i = o['data']
      new(i['version'] || [DEFAULT_VERSION, DEFAULT_VERSION], o['size'])
    end

  end # Advertise


  # Deprecated for agents that are version 13 and above
  #
  # Packet for reporting a stale request packet
  class Stale < Packet

    # Create non-delivery Result packet from unmarshalled data for Stale packet
    #
    # === Parameters
    # o(Hash):: Unmarshalled data for Stale packet
    #
    # === Return
    # (Result):: New packet
    def self.create(o)
      i = o['data']
      from = self.compatible(i['from'])
      Result.new(i['token'], from, OperationResult.non_delivery(OperationResult::TTL_EXPIRATION), i['identity'],
                 from, tries = nil, persistent = true, duration = nil, version = i['version'] || [DEFAULT_VERSION, DEFAULT_VERSION])
    end

  end # Stale


  # Deprecated for agents that are version 8 and above
  # instead use /mapper/update_tags
  #
  # Packet for an agent to update the mappers with its tags
  class TagUpdate < Packet

    attr_accessor :identity, :new_tags, :obsolete_tags

    # Create packet
    #
    # === Parameters
    # identity(String):: Sender identity
    # new_tags(Array):: List of new tags
    # obsolete_tags(Array):: List of tags to be deleted
    # version(Array):: Protocol version of the original creator of the packet followed by the
    #   protocol version of the packet contents to be used when sending
    # size(Integer):: Size of request in bytes used only for marshalling
    def initialize(identity, new_tags, obsolete_tags, version = [VERSION, VERSION], size = nil)
      @identity      = identity
      @new_tags      = new_tags
      @obsolete_tags = obsolete_tags
      @version       = version
      @size          = size
    end

    # Create packet from unmarshalled data
    #
    # === Parameters
    # o(Hash):: Unmarshalled data
    #
    # === Return
    # (TagUpdate):: New packet
    def self.create(o)
      i = o['data']
      new(self.compatible(i['identity']), i['new_tags'], i['obsolete_tags'],
          i['version'] || [DEFAULT_VERSION, DEFAULT_VERSION], o['size'])
    end

    # Generate log representation
    #
    # === Parameters
    # filter(Array(Symbol)):: Attributes to be included in output
    # version(Symbol|nil):: Version to display: :recv_version, :send_version, or nil meaning none
    #
    # === Return
    # log_msg(String):: Log representation
    def to_s(filter = nil, version = nil)
      log_msg = "#{super(filter, version)} #{id_to_s(@identity)}"
      log_msg += ", new tags #{@new_tags.inspect}" if @new_tags && !@new_tags.empty?
      log_msg += ", obsolete tags #{@obsolete_tags.inspect}" if @obsolete_tags && !@obsolete_tags.empty?
      log_msg
    end

  end # TagUpdate


  # Deprecated for agents that are version 8 and above
  # instead use Request of type /mapper/query_tags with :tags and :agent_ids in payload
  #
  # Packet for requesting retrieval of agents with specified tags
  class TagQuery < Packet

    attr_accessor :from, :token, :agent_ids, :tags, :persistent

    # Create packet
    #
    # === Parameters
    # from(String):: Sender identity
    # opts(Hash):: Options, at least one must be set:
    #   :tags(Array):: Tags defining a query that returned agents tags must match
    #   :agent_ids(Array):: ids of agents that should be returned
    # version(Array):: Protocol version of the original creator of the packet followed by the
    #   protocol version of the packet contents to be used when sending
    # size(Integer):: Size of request in bytes used only for marshalling
    def initialize(from, opts, version = [VERSION, VERSION], size = nil)
      @from       = from
      @token      = opts[:token]
      @agent_ids  = opts[:agent_ids]
      @tags       = opts[:tags]
      @persistent = opts[:persistent]
      @version    = version
      @size       = size
    end

    # Create packet from unmarshalled data
    #
    # === Parameters
    # o(Hash):: Unmarshalled data
    #
    # === Return
    # (TagQuery):: New packet
    def self.create(o)
      i = o['data']
      agent_ids = i['agent_ids'].map { |id| self.compatible(id) } if i['agent_ids']
      new(i['from'], { :token => i['token'], :agent_ids => agent_ids,
                       :tags => i['tags'],   :persistent => i['persistent'] },
          i['version'] || [DEFAULT_VERSION, DEFAULT_VERSION], o['size'])
    end

    # Generate log representation
    #
    # === Parameters
    # filter(Array(Symbol)):: Attributes to be included in output
    # version(Symbol|nil):: Version to display: :recv_version, :send_version, or nil meaning none
    #
    # === Return
    # log_msg(String):: Log representation
    def to_s(filter = nil, version = nil)
      log_msg = "#{super(filter, version)} #{trace}"
      log_msg += " from #{id_to_s(@from)}" if filter.nil? || filter.include?(:from)
      log_msg += " agent_ids #{@agent_ids.inspect}"
      log_msg += " tags #{@tags.inspect}"
      log_msg
    end

    # Whether the packet is one that does not have an associated response
    #
    # === Return
    # false:: Always return false
    def one_way
      false
    end

  end # TagQuery

end # RightScale

