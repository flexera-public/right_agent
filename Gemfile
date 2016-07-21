source 'http://gems.test.rightscale.com'
source 'https://rubygems.org'

gemspec

gem 'rake',              '>= 0.9.2.2'
gem 'simple_uuid',       '~> 0.2'
gem 'mime-types',        '< 2.0'

# RightScale internally publishes a JSON 1.4.6 gem for mswin32 platform;
# Going forward to ruby 1.9 we can relax the constraint on the json gem.
gem 'json', '~> 1.4'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem 'eventmachine', '~> 1.0.0.10'
gem 'airbrake-ruby', '~> 1.2'

# we test with Ruby 2.0 which is not compatible with Rack 2.x
gem 'rack', '~> 1.6'

group :windows do
  platform :mswin do
    gem 'win32-dir',     '~> 0.4.5'
    gem 'win32-process', '~> 0.7.3'
  end
end

###
### Test-only gems
###
group :test do
  gem 'fiber_pool',      '1.0.0'
  gem 'em-http-request', '1.0.3'
  gem 'flexmock',        '~> 1.0'
  gem 'rspec',           '~> 2.13.0'
  gem 'right_develop',   '~> 3.1'
  gem 'simplecov'
end

###
### Development-only gems (not available in CI).
### No version or Ruby VM constraints; assume these are always compatible with
### whatever Ruby version we're using, until we discover otherwise.
###
group :development do
  gem 'ruby-debug', :platforms => [:ruby_18]
  gem 'pry', :platforms => [:ruby_19, :ruby_20, :ruby_21]
  gem 'pry-byebug', :platforms => [:ruby_20, :ruby_21]
end
