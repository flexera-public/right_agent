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

  # Retrieve and cache instance models from their API token ids
  # TODO: Implement LRU
  class InstanceTokensCache

    attr_accessor :tokens # Hash of cached instances indexed by API token ids

    def initialize
      @tokens = {}
      @importer = ModelsImporter.instance
    end

    # Lookup instance from given API token id
    # Search in cache or retrieve from DB and keep in cache if not found
    #
    # === Parameters
    # token_id(Integer):: Instance API token id
    #
    # === Return
    # instance(Instance):: Retrieved instance
    #
    # === Raise
    # RightScale::Exceptions::Application:: Instance with given API token or API token itself not found
    def [](token_id)
      res = @tokens[token_id]
      return @importer.run_query { res.reload } if res

      # Not in cache, look it up
      instance_api_token = @importer.instance_token(token_id)
      raise RightScale::Exceptions::Application, "Instance token with id '#{token_id}' not found" unless instance_api_token
      instance = instance_api_token.instance
      raise RightScale::Exceptions::Application, "Instance with token id '#{token_id}' not found" unless instance
      @tokens[token_id] = instance
    end

  end
end
