source :gemcutter
source 'http://gems.github.com'

gemspec

gem 'right_amqp',    :git => 'git@github.com:rightscale/right_amqp.git',
                     :branch => 'master'

# Clients of this gem tend to use 1.6 so we want tests to use that version
gem 'json', '~> 1.6'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem 'eventmachine', '0.12.10'

group :development, :test do
  gem "rspec",       "~> 2.8"
  gem "flexmock",    "~> 0.9"
  gem "rake",        ">= 0.9.2.2"
  gem "ruby-debug19", :platforms => "mri_19"
  # gem "memprof",     "~> 0.3" # memprof does not support 1.9 yet
end
