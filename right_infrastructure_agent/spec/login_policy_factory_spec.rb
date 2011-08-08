# Copyright (c) 2009-2011 RightScale, Inc, All Rights Reserved Worldwide.
#
# THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO RIGHTSCALE
# AND CONSTITUTES A VALUABLE TRADE SECRET.  Any unauthorized use,
# reproduction, modification, or disclosure of this program is
# strictly prohibited.  Any use of this program by an authorized
# licensee is strictly subject to the terms and conditions,
# including confidentiality obligations, set forth in the applicable
# License Agreement between RightScale.com, Inc. and the licensee.

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'right_agent', 'lib', 'right_agent', 'core_payload_types'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'right_infrastructure_agent', 'login_policy_factory'))

require 'active_support'

# LoginPolicyFactory is shared between library and right_api, which is why it lives here.
# By creating a mock world of RightScale models, we allow this spec to run independently
# of the Rails web apps.
class Account; end unless defined?(Account)
class User; end unless defined?(User)
class Ec2Instance ; end unless defined?(Ec2Instance)
class Role
  def self.[](role)
    role.hash
  end
end unless defined?(Role)
module Biz
  module ResourceUuidMixin
    def self.obfuscate_id(object)
      object.to_s
    end
  end
end

module MockHelper
  def mock_account_and_users(num_users)
    account = flexmock(:model, Account)
    account.should_receive(:setting).with('managed_login_mandatory').and_return(false).by_default
    
    users = []
    (0...num_users).each do
      user = flexmock(:model, User,
                      :id=>rand(2**16),
                      :account=>account,
                      :email=>"user#{rand(2**16)}@rightscale.com")
      users << user
    end

    flexmock(User).should_receive(:all).and_return(users)
    return [account] + users
  end

  def mock_instance(account)
    instance = flexmock(:model, Ec2Instance, :account=>account)
    instance.should_receive(:managed_login_allowed?).and_return(false).by_default
    return instance
  end

  def mock_login_permission(account, user, expires_at=nil, updated_at=nil)
    updated_at ||= 1.months.ago

    user.should_receive(:perm_updated_at).and_return(updated_at.to_s)
    user.should_receive(:perm_deleted_at).and_return(expires_at.to_s)
  end

  def mock_credential(user, public_key=nil, updated_at=nil)
    updated_at ||= 1.months.ago

    user.should_receive(:cred_updated_at).and_return(updated_at.to_s)
    user.should_receive(:cred_public_value).and_return(public_key)
  end
end

describe RightScale::LoginPolicyFactory do
  include MockHelper
  
  context :policy_for_instance do
    context 'handling oddly-formatted keys' do
      before(:each) do
        @account, @user  = mock_account_and_users(1)
        @instance        = mock_instance(@account)
        @instance.should_receive(:managed_login_allowed?).with(@user, @account).and_return(true)
      end
      
      it 'should add a comment for keys that are missing it' do
        @user_credential = mock_credential(@user, 'ssh-rsa abcd1234')
        @permission = mock_login_permission(@account, @user, nil)
        @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
        @policy.users.size.should == 1
        components = RightScale::LoginPolicy.parse_public_key(@policy.users[0].public_keys.first)
        components[3].should_not be_nil #email should be substituted in
      end
    end

    context 'calculating policy for a given user' do
      before(:each) do
        @account, @user  = mock_account_and_users(1)
        @instance        = mock_instance(@account)
        @user_credential = mock_credential(@user, 'ssh-rsa abcd1234 joe@joebob.com')
        @instance.should_receive(:managed_login_allowed?).with(@user, @account).and_return(true)
      end

      context "for all users" do
        before(:each) do
          @permission = mock_login_permission(@account, @user, nil)
          @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
          @policy.users.size.should == 1
        end

        it "should specify the user's UUID" do
          @policy.users[0].uuid.should == Biz::ResourceUuidMixin.obfuscate_id(@user.id)
        end

        it "should specify a preferred username" do
          @policy.users[0].username.should_not be_nil
        end

        it "should include a single public key for pre-5.5 instances" do
          @policy.users[0].public_key.should == 'ssh-rsa abcd1234 joe@joebob.com'
        end

        it "should include a collection of public keys for modern instances" do
          @policy.users[0].public_keys.should == ['ssh-rsa abcd1234 joe@joebob.com']
        end

        it "should specify a common name" do
          @policy.users[0].username.should_not be_nil
        end
      end

      context "for users with temporary access" do
        before(:each) do
          @t = Time.at(1.days.from_now.to_i)
          @permission = mock_login_permission(@account, @user, @t)
          @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
          @policy.users.size.should == 1
        end

        it "should specify the expiry time" do
          @policy.users[0].expires_at.to_i.should == @t.to_i 
        end
      end

    end

    context 'calculating users' do
      before(:each) do
        @account, @u_ok = mock_account_and_users(1)
        mock_login_permission(@account, @u_ok)
        mock_credential(@u_ok, 'moo')

        @instance   = mock_instance(@account)
        @instance.should_receive(:managed_login_allowed?).with(@u_ok, @account).and_return(true)

        @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
        @policy.users.size.should == 1
        @policy.users.detect { |u| u.common_name == @u_ok.email }.should_not be_nil
      end

      it 'should include users that satisfy all criteria' do
        @policy.users.detect { |u| u.common_name == @u_ok.email }.should_not be_nil                
      end
    end

    context 'calculating created_at' do
      before(:each) do
        @account, @user1, @user2 = mock_account_and_users(2)

        @instance = mock_instance(@account)
        @instance.should_receive(:managed_login_allowed?).with(@user1, @account).and_return(true)
        @instance.should_receive(:managed_login_allowed?).with(@user2, @account).and_return(true)
      end

      it 'should match a UserCredential.updated_at that is most recent within scope' do
        @t = 1.days.ago
        mock_login_permission(@account, @user1)
        mock_login_permission(@account, @user2)
        mock_credential(@user1, 'moo', 2.days.ago)
        mock_credential(@user2, 'moo', @t)

        @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
        @policy.created_at.to_s.should == @t.to_s
      end

      it 'should match a Permission.updated_at that is most recent within scope' do
        @t = 1.days.ago  
        mock_login_permission(@account, @user1, nil, 2.days.ago)
        mock_login_permission(@account, @user2, nil, @t)
        mock_credential(@user1, 'moo')
        mock_credential(@user2, 'moo')

        @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
        @policy.created_at.to_s.should == @t.to_s
      end
    end

    context 'calculating exclusive' do
      before(:each) do
        @account, @user  = mock_account_and_users(1)
        mock_credential(@user, 'moo')
        mock_login_permission(@account, @user, nil, 2.days.ago)
        @instance = mock_instance(@account)
      end

      it 'should be exclusive if Managed SSH is mandatory for the account' do
        @account.should_receive(:setting).with('managed_login_mandatory').and_return(true)

        @policy   = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
        @policy.exclusive.should == true
      end
      
      it 'should not be exclusive if Managed SSH is optional for the account' do
        @policy   = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
        @policy.exclusive.should == false
      end
    end

    it 'should use the audit_id passed in by the caller' do
      @account, @user  = mock_account_and_users(1)
      @instance = mock_instance(@account)
      mock_credential(@user, 'moo')
      mock_login_permission(@account, @user, nil, 2.days.ago)

      @policy = RightScale::LoginPolicyFactory.policy_for_instance(@instance, 1234)
      @policy.audit_id.should == 1234
    end
  end
end
