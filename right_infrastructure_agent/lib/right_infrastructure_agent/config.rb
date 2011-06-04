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

  # Container for RightInfrastructureAgent configuration data
  class InfrastructureAgentConfig

    # RabbitMQ permission settings for instance agent
    def self.instance_rabbit_acl
      '".*instance.*|request|registration|heartbeat|.*mapper.*" ".*" ".*instance.*"'
    end

  end # InfrastructureAgentConfig

end # RightScale