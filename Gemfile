source :gemcutter
source 'http://gems.github.com'

gemspec

gem 'right_support', :git => 'git@github.com:rightscale/right_support.git',
                     :branch => 'azure_11744_right_amqp'

gem 'right_amqp',    :git => 'git@github.com:rightscale/right_amqp.git',
                     :branch => 'master'

# Clients of this gem tend to use 1.6 so we want tests to use that version
gem 'json', '~> 1.6'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem 'eventmachine', '0.12.10'

group :development do
  gem "rspec",       "~> 2.5"
  gem "flexmock",    "~> 0.9"
  gem "rake",        ">= 0.8.7"
  gem "ruby-debug",  ">= 0.10"
  gem "rspec",       "~> 2.5"
  gem "memprof",     "~> 0.3"
end
