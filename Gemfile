source :gemcutter
source 'http://gems.github.com'
source 'http://s3.amazonaws.com/rightscale_rightlink_gems_dev'

gemspec

gem 'right_amqp',
    :git => 'git@github.com:rightscale/right_amqp.git',
    :branch => 'release4.7'

# RightScale internally publishes a JSON 1.4.6 gem for mswin32 platform;
# use that version so we can run right_agent specs under both Windows and Linux.
gem 'json', '1.4.6'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem 'eventmachine', '1.0.0.2'

# Windows gems; we must call out for a very specific
# set of versions since we rely on the prebuilt mswin
# gems that we internally publish.
platform :mswin, :mingw do
  gem "win32-api", "1.4.5"
  gem "win32-dir", ">= 0.3.5"
  gem "win32-process", "0.6.5"
end

group :development, :test do
  gem "rspec",       "~> 2.8"
  gem "flexmock",    "~> 0.9"
  gem "rake",        ">= 0.9.2.2"
  gem "ruby-debug",
      :platforms => :mri_18
  gem "ruby-debug19",
      :platforms => :mri_19
  gem "memprof",     "~> 0.3",
      :platforms => :mri_18
end
