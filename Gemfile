source 'http://s3.amazonaws.com/rightscale_rightlink_gems_dev'
source 'https://rubygems.org'

gemspec

gem 'right_amqp',
    :git => 'git@github.com:rightscale/right_amqp.git',
    :branch => 'master'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem 'eventmachine', '~> 1.0.0.4'

group :windows do
  # bundler cannot distinguish the old mswin binaries from mingw...
  platform :mswin do
    # ... so we need this if-statement to distinguish it ourselves.
    if RUBY_PLATFORM =~ /mswin/
      gem 'win32-api',     '1.4.5'
      gem 'win32-process', '0.6.5'
      gem 'win32-dir',     '0.3.7'
      gem 'msgpack',       '0.4.4'
    else
      gem 'ffi',           '~> 1.9.0'
      gem 'win32-dir',     '~> 0.4.6'
      gem 'win32-process', '~> 0.7.3'
    end
  end
end

group :development, :test do
  gem "rspec",       "~> 2.8"
  gem "flexmock",    "~> 0.9"
  gem "rake",        ">= 0.9.2.2"
  gem "ruby-debug",
      :platforms => :mri_18
  gem "ruby-debug19",
      :platforms => :mri_19
end
