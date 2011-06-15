#
# Copyright (c) 2011 RightScale Inc
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

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

describe RightScale::AgentConfig do

  before(:all) do
    @agent_config = RightScale::AgentConfig
    @pwd_dir = Dir.pwd
    @tmp_dir = RightScale::Platform.filesystem.temp_dir
    @test_dir = File.join(@tmp_dir, 'agent_config_test')
    FileUtils.mkdir_p(@root_dir1 = File.join(@test_dir, 'root1'))
    FileUtils.mkdir_p(@root_dir2 = File.join(@test_dir, 'root2'))
    FileUtils.mkdir_p(@root_dir3 = File.join(@test_dir, 'root3'))
    FileUtils.mkdir_p(@init_dir1 = File.join(@root_dir1, 'init'))
    FileUtils.mkdir_p(@init_dir2 = File.join(@root_dir2, 'init'))
    FileUtils.mkdir_p(@init_dir3 = File.join(@root_dir3, 'init'))
    FileUtils.touch([@config1 = File.join(@init_dir1, 'config.yml'), @config2 = File.join(@init_dir2, 'config.yml')])
    FileUtils.touch([@init2 = File.join(@init_dir2, 'init.rb'), @init3 = File.join(@init_dir3, 'init.rb')])
    FileUtils.mkdir_p(@actors1 = File.join(@root_dir1, 'actors'))
    FileUtils.mkdir_p(@actors3 = File.join(@root_dir3, 'actors'))
    @actors = File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_agent', 'actors'))
    FileUtils.mkdir_p(@certs1 = File.join(@root_dir1, 'certs'))
    FileUtils.mkdir_p(@certs2 = File.join(@root_dir2, 'certs'))
    FileUtils.touch([@mapper_cert1 = File.join(@certs1, 'mapper.cert')])
    FileUtils.touch([@mapper_cert2 = File.join(@certs2, 'mapper.cert')])
    FileUtils.touch([@agent_cert2 = File.join(@certs2, 'agent.cert')])
    FileUtils.touch([@mapper_key2 = File.join(@certs2, 'mapper.key')])
    FileUtils.mkdir_p(@lib1 = File.join(@root_dir1, 'lib'))
    FileUtils.mkdir_p(@scripts3 = File.join(@root_dir3, 'scripts'))
    FileUtils.mkdir_p(@cfg_dir = File.join(@test_dir, 'cfg'))
    FileUtils.mkdir_p(@cfg_agent1_dir = File.join(@cfg_dir, 'agent1'))
    FileUtils.touch([@cfg_agent1 = File.join(@cfg_agent1_dir, 'config.yml')])
    FileUtils.mkdir_p(@cfg_agent2_dir = File.join(@cfg_dir, 'agent2'))
    FileUtils.touch([@cfg_agent2 = File.join(@cfg_agent2_dir, 'config.yml')])
    FileUtils.mkdir_p(@pid_dir = File.join(@test_dir, 'pid'))
  end

  after(:all) do
    FileUtils.remove_dir(@test_dir)
  end

  it 'should return protocol version' do
    @agent_config.protocol_version.should == RightScale::AgentConfig::PROTOCOL_VERSION
  end

  it 'should default root directory to current working directory' do
    @agent_config.root_dir.should == @pwd_dir
  end

  it 'should set root directory to single directory' do
    @agent_config.root_dir = @root_dir1
    @agent_config.root_dir.should == @root_dir1
  end

  it 'should set root directory to list of directories' do
    @agent_config.root_dir = [@root_dir1, @root_dir2]
    @agent_config.root_dirs.should == [@root_dir1, @root_dir2]
  end

  it 'should be able to change root directory' do
    @agent_config.root_dir = [@root_dir1, @root_dir2]
    @agent_config.root_dir.should == [@root_dir1, @root_dir2]
    @agent_config.root_dir = [@root_dir3, @root_dir2]
    @agent_config.root_dir.should == [@root_dir3, @root_dir2]
    @agent_config.root_dir = nil
    @agent_config.root_dir.should == @pwd_dir
  end

  it 'should default configuration directory to platform specific directory' do
    @agent_config.cfg_dir.should == RightScale::Platform.filesystem.cfg_dir
  end

  it 'should set configuration directory' do
    @agent_config.cfg_dir = @cfg_dir
    @agent_config.cfg_dir.should == @cfg_dir
  end

  it 'should default process id directory to platform specific directory' do
    @agent_config.pid_dir.should == RightScale::Platform.filesystem.pid_dir
  end

  it 'should set process id directory' do
    @agent_config.pid_dir = @pid_dir
    @agent_config.pid_dir.should == @pid_dir
  end

  it 'should return first init/init.rb file path found' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.init_file.should == @init2
  end

  it 'should return first init/config.yml file path found' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.init_cfg_file.should == @config1
  end

  it 'should return actors directory paths containing all in root directory paths with one from gem last' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.actors_dirs.should == [@actors1, @actors3, @actors]
  end

  it 'should return actors directory paths containing other actors directories' do

  end

  it 'should return first certs file path found' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.certs_file('mapper.cert').should == @mapper_cert1
    @agent_config.certs_file('mapper.key').should == @mapper_key2
    @agent_config.certs_file('agent.key').should be_nil
  end

  it 'should return all certs file paths found without any duplicates and by root directory order' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.certs_files('*.cert').should == [@mapper_cert1, @agent_cert2]
    @agent_config.certs_files('*.key').should == [@mapper_key2]
    @agent_config.certs_files('*.abc').should == []
  end

  it 'should return the first lib directory path' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.lib_dir.should == @lib1
  end

  it 'should return the first scripts directory path' do
    @agent_config.root_dir = [@root_dir1, @root_dir2, @root_dir3]
    @agent_config.scripts_dir.should == @scripts3
  end

  it 'should return the configuration file path for an agent' do
    @agent_config.cfg_dir = @cfg_dir
    @agent_config.cfg_file('agent1').should == @cfg_agent1
  end

  it 'should check if agent configuration file exists if requested to' do
    @agent_config.cfg_dir = @cfg_dir
    @agent_config.cfg_file('agent1', exists = true).should == @cfg_agent1
    @agent_config.cfg_file('no_agent', exists = true).should be_nil
  end

  it 'should return configuration file paths for all agents' do
    @agent_config.cfg_dir = @cfg_dir
    @agent_config.cfg_files.should == [@cfg_agent1, @cfg_agent2]
  end

  it 'should return a list of all configured agents' do
    @agent_config.cfg_dir = @cfg_dir
    @agent_config.cfg_agents.should == ['agent1', 'agent2']
  end

  it 'should return the process id file object for an agent' do

  end

  it 'should return the agent options retrieved from the configuration file' do

  end

  it 'should return the agent options retrieved from the process id file if it exists' do

  end

end
