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

  AgentConfig.module_eval do

    # RabbitMQ permission settings for instance agent
    INSTANCE_RABBIT_ACL = '".*instance.*|request|registration|heartbeat|.*mapper.*" ".*" ".*instance.*"'

    # RabbitMQ permission settings for instance agent
    def self.instance_rabbit_acl
      INSTANCE_RABBIT_ACL
    end

    # RabbitMQ permission settings for instance agent
    def instance_rabbit_acl
      INSTANCE_RABBIT_ACL
    end

    protected

    # Other actors directories to be used in search for actors
    #
    # === Return
    # (Array):: List of actors directories
    def other_actors_dirs
      [File.expand_path(File.join(File.dirname(__FILE__), 'actors'))]
    end

  end

end
