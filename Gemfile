source 'http://gems.test.rightscale.com'
source 'https://rubygems.org'

gemspec

gem 'right_amqp',
    :git => 'git@github.com:rightscale/right_amqp.git',
    :tag => 'v0.8.3'

gem 'right_support', '~> 2.8'

gem "simple_uuid", "~> 0.2"

gem "mime-types", "< 2.0"

# RightScale internally publishes a JSON 1.4.6 gem for mswin32 platform;
# Going forward to ruby 1.9 we can relax the constraint on the json gem.
gem 'json', '~> 1.4'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem 'eventmachine',      '~> 1.0.0.10'

gem 'hydraulic_brake',   '~> 0.1.0'

group :windows do
  platform :mswin do
    gem 'win32-dir',     '~> 0.4.5'
    gem 'win32-process', '~> 0.7.3'
  end
end

group :development, :test do
  gem "rspec",           "~> 2.8"
  gem "flexmock",        "~> 0.9"
  gem "rake",            ">= 0.9.2.2"
  gem "ruby-debug",
      :platforms => :mri_18
  gem "ruby-debug19",
      :platforms => :mri_19
  gem "fiber_pool",      "1.0.0"
  gem "em-http-request", "1.0.3"
end
