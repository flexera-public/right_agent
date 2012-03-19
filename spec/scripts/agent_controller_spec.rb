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

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'scripts', 'agent_controller'))

module RightScale
  describe AgentController do
    context 'start_agent' do
      it 'Creates a log entry when the agent starts up' do
        agent_name = 'Test'
        
        class AgentController
          def test_start_agent(agent_name)
            start_agent(agent_name)
          end
        end
        
        flexmock(EM).should_receive(:run).and_return(true)
        flexmock(subject).should_receive(:human_readable_name).and_return("Agent #{agent_name}")
        flexmock(Log).should_receive(:info).once
        
        subject.test_start_agent(agent_name)
      end
    end
  end
end