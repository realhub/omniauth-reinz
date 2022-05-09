require "omniauth/strategies/reinz"

# Potential scopes: 
# ------
# openid
#
# Separate scopes with a space (%20)

module OmniAuth
  module Strategies
    class REINZ < OmniAuth::Strategies::OAuth2
      STAGING_URL = 'https://reinztestorg.b2clogin.com/reinztestorg.onmicrosoft.com/b2c_1a_signup_signin/'.freeze
      PRODUCTION_URL = 'https://login.reinz.co.nz/reinzorg.onmicrosoft.com/b2c_1a_signup_signin/'.freeze
      
      option :name, 'reinz'

      option :client_options,
             authorize_url: 'oauth2/v2.0/authorize',
             token_url: 'oauth2/v2.0/token'

      # Overrride client to merge in site based on sandbox option
      def client
        ::OAuth2::Client.new(
          options.client_id,
          options.client_secret,
          deep_symbolize(options.client_options).merge(site: site)
        )
      end

      def request_phase
        request_params = {
          redirect_uri: callback_url,
        }.merge(authorize_params)

        redirect client.implicit.authorize_url(request_params)
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

        def site
          options.staging ? STAGING_URL : PRODUCTION_URL
        end

    end
  end
end

OmniAuth.config.add_camelization 'reinz', 'REINZ'