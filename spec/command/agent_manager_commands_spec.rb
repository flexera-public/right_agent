#
# Copyright (c) 2009 RightScale Inc
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
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'command'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'command', 'agent_manager_commands'))

describe RightScale::AgentManagerCommands do

  before(:all) do
    @commands = RightScale::AgentManagerCommands::COMMANDS
    @agent_identity = RightScale::AgentIdentity.new('rs', 'test', 1).to_s
  end

  it 'should list commands' do
    flexmock(RightScale::CommandIO.instance).should_receive(:reply).and_return do |conn, r|
      conn.should == 42
      # r is YAML, 2 lines for each command, one less command printed (the list command)
      # plus one header line
      r.count("\n").should == (@commands.reject {|k,_| k.to_s =~ /test/}.size - 1) * 2 + 1
    end
    RightScale::AgentManagerCommands.new("agent_manager").send(:list_command, {:conn => 42}).should be_true
  end

  it 'should get commands' do
    cmds = RightScale::AgentManagerCommands.get("agent_manager")
    cmds.size.should == @commands.size
    cmds.keys.map { |k| k.to_s }.sort.should == @commands.keys.map { |k| k.to_s }.sort
    cmds.values.all? { |v| v.is_a? Proc }.should be_true
  end

end
