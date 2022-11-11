require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class NexlOauth2 < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, "nexl_oauth2"

      option :client_options, { site: 'https://360.nexl.io' }
      option :authorize_params, { scope: 'openid profile use_graphql' }

      # You may specify that your strategy should use PKCE by setting
      # the pkce option to true: https://tools.ietf.org/html/rfc7636
      option :pkce, true

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info['id'] }

      info do
        {
          :name => [raw_info.dig('me', 'firstName'),raw_info.dig('me', 'lastName')].join(" ").strip,
          :first_name => raw_info.dig('me', 'firstName'),
          :last_name => raw_info.dig('me', 'lastName'),
          :email => raw_info.dig('data', 'me', 'email'),
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/token/me').parsed
      end
    end
  end
end
