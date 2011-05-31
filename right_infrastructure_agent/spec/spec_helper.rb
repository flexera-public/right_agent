require 'rubygems'
require 'spec'
require 'flexmock'
require File.join(File.dirname(__FILE__), '..', '..', '..', 'spec', 'spec_helper')
require File.join(File.dirname(__FILE__), '..', '..', 'config', 'right_net_config')
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'db_access', 'lib', 'db_access'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', 'instance', 'right_link', 'common', 'lib', 'common'))

config = Spec::Runner.configuration
config.mock_with :flexmock

RightScale::ModelsImporter.instance.load_right_site


User.blueprint do
  first_name { "test_#{ rand(2**32) }" }
  last_name { "testes_#{ rand(2**32) }" }
  email { "test_#{ rand(2**32) }@rightscale.com" }
  password { "password" }
  password_confirmation { "password" }
  global_object_version { Time.now.to_i }
end

Account.blueprint do
  name "SPEC_ACCOUNT"
  owner User.make
  plan { Plan.find(2) }
  global_object_version { Time.now.to_i }
end

AuditEntry.blueprint do
  account
end

Cloud.blueprint do
  resource_uid            { "RESOURCE_#{rand(2**32)}" }
  name                    { "Bob's Eucalyptus #{rand(2**32)}" }
  owner Account.make
  cloud_type              "eucalyptus"
  services                {{:ec2 => {:endpoint_url => "http://foo.com"}}}
  display_name            { name }
  schema_version          "v1"
  visibility              "private"
  installation_identifier { "SECRET_KEY_#{rand(2**32)}"}
  gateway_url             "gateway"
  capabilities          {Hash.new}
  global_object_version { Time.now.to_i }
end

CloudAccount.blueprint do
  cloud
  account
  account_token {"ACCOUNT_TOKEN_#{rand(2**32)}" }
  cloud_owner   {"CLOUD_OWNER_#{rand(2**32)}"}
end

Deployment.blueprint do
  account
  nickname "TEST_NICKNAME"
end

Ec2Setting.blueprint do
  account
end

Component.blueprint do
  account
  nickname {"nickname-#{rand(2**32)}"}
  deployment {Deployment.make(:account => account)}
  server_template {ServerTemplate.make(:account => account)}
  cloud
  ec2_setting {Ec2Setting.make(:account => account, :cloud => cloud)}
end

InstanceApiToken.blueprint do
  account
  token              "TEST_TOKEN"
  instance {Ec2Instance.make(:account => account)}
end

Ec2Instance.blueprint do
  account
  aws_owner "AWS_OWNER"
  aws_reservation_id "AWS_RESERVATION_ID"
  aws_id { "i-#{rand(2**32)}"}
  server_template {ServerTemplate.make(:account => account)}
  token "TOKEN"
  r_s_version 1
  cloud
  ec2_setting {Ec2Setting.make(:account => account, :cloud => cloud)}
  incarnator {Component.make(:account => account, :cloud => cloud)}
  attached_at { incarnator ? Time.now : nil}
end

Instance.blueprint do
  account
  cloud
  cloud_account  {CloudAccount.make(:cloud => cloud, :account => account) }
  resource_uid   {"RESOURCE_#{rand(2**32)}" }
  rs_id          {resource_uid + ";RAND"  }
  version        1
end

MultiCloudImage.blueprint do
  account
  name "RightNet Test Image #{rand}"
  version 1
  is_head_version true
end

ServerTemplate.blueprint do
  account
  updated_by              {"user_#{rand(2**32)}@rightscale.com"}
  nickname                {"NICKNAME_#{rand(2**32)}"}
  description             {"DESCRIPTION_#{rand(2**32)}"}
  version                 { 1 }
  is_head_version         { true }
end


Setting.blueprint do
  owner           { Account.make }
  owner_type      { "Account" }
  setting_info    { SettingInfo.make }
  value           { "VALUE" }
  global_object_version { Time.now.to_i }
end

SettingInfo.blueprint do
  name          { "NAME_#{rand(2**32)}" }
  display_name  { "DISPLAY_NAME_#{rand(2**32)}" }
  value_type    { "Boolean" }
  help_text     { "HELP_TEXT_#{rand(2**32)}" }
  global_object_version { Time.now.to_i }
end
