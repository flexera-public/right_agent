source :rubygems

gemspec

gem 'right_amqp',
    :git => 'git@github.com:rightscale/right_amqp.git',
    :branch => 'azure_12_6_ruby_19_mingw'

# RightScale internally publishes a JSON 1.4.6 gem for mswin32 platform;
# use that version so we can run right_agent specs under both Windows and Linux.
gem 'json'

# Lock eventmachine to a published and well-tested version to avoid picking up
# proprietary builds that happen to be installed locally
gem "eventmachine", "1.0.0.beta.4", :git => 'https://github.com/eventmachine/eventmachine.git', :ref => '9bb885c035ac75e80d74da30829c9d2449dcf78d'

# Windows gems; we must call out for a very specific
# set of versions since we rely on the prebuilt mswin
# gems that we internally publish.
platform :mswin, :mingw do
  gem "win32-api"
  gem "win32-dir"
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
