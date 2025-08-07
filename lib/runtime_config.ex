defmodule Bonfire.OpenID.RuntimeConfig do
  use Bonfire.Common.Localise

  @behaviour Bonfire.Common.ConfigModule
  def config_module, do: true

  @doc """
  NOTE: you can override this default config in your app's runtime.exs, by placing similarly-named config keys below the `Bonfire.Common.Config.LoadExtensionsConfig.load_configs` line
  """
  def config do
    import Config

    # config :bonfire_open_id,
    #   modularity: :disabled

    # offer an OAuth & OpenID provider
    config :boruta, Boruta.Oauth,
      issuer: System.get_env("OAUTH_ISSUER", "https://bonfirenetworks.org"),
      redirect_uri_validation_fun: {Bonfire.OpenID.Provider.OAuth, :redirect_uri_validate}

    # TODO: use `Bonfire.Common.EnvConfig` to handle configuring many providers via ENV https://github.com/bonfire-networks/bonfire-app/issues/1082 

    # connect as a client to an OpenID Connect provider https://yourinstance.tld/oauth/client/openid_1
    if main_discovery_document_uri = System.get_env("OPENID_1_DISCOVERY") do
      config :bonfire_open_id, :openid_connect_providers,
        openid_1: [
          display_name: System.get_env("OPENID_1_DISPLAY_NAME", l("Single sign-on")),
          discovery_document_uri: main_discovery_document_uri,
          client_id: System.get_env("OPENID_1_CLIENT_ID"),
          client_secret: System.get_env("OPENID_1_CLIENT_SECRET"),
          response_type: System.get_env("OPENID_1_RESPONSE_TYPE", "code"),
          scope: System.get_env("OPENID_1_SCOPE", "identity data:public"),
          enable_signup: System.get_env("OPENID_1_ENABLE_SIGNUP") != "false"
        ]
    end

    # connect as a client to the orcid.org OpenID Connect provider with callback url https://yourinstance.tld/oauth/client/orcid
    if orcid_client_id = System.get_env("ORCID_CLIENT_ID") do
      config :bonfire_open_id, :openid_connect_providers,
        orcid: [
          display_name: "ORCID",
          # only_supports_login: true,
          discovery_document_uri: "https://orcid.org/.well-known/openid-configuration",
          client_id: orcid_client_id,
          client_secret: System.get_env("ORCID_CLIENT_SECRET"),
          response_type: "code",
          scope: "openid",
          enable_signup: true
        ]
    end

    # connect as a client to an OAuth2 provider with callback url https://yourinstance.tld/oauth/client/oauth_1
    if oauth_app_client_id = System.get_env("OAUTH_1_CLIENT_ID") do
      config :bonfire_open_id, :oauth2_providers,
        oauth_1: [
          display_name: System.get_env("OAUTH_1_DISPLAY_NAME", l("Single sign-on")),
          client_id: oauth_app_client_id,
          client_secret: System.get_env("OAUTH_1_CLIENT_SECRET"),
          authorize_uri: System.get_env("OAUTH_1_AUTHORIZE_URI"),
          access_token_uri: System.get_env("OAUTH_1_ACCESS_TOKEN_URI"),
          userinfo_uri: System.get_env("OAUTH_1_USERINFO_URI"),
          grant_type: System.get_env("OAUTH_1_GRANT_TYPE"),
          scope: System.get_env("OAUTH_1_SCOPE"),
          profile_url_pattern: System.get_env("OAUTH_1_PROFILE_URL_PATTERN"),
          enable_signup: System.get_env("OAUTH_1_ENABLE_SIGNUP") != "false"
        ]
    end

    # connect as a client to Github's OAuth2 provider with callback url https://yourinstance.tld/oauth/client/github
    if github_app_client_id = System.get_env("GITHUB_APP_CLIENT_ID") do
      config :bonfire_open_id, :oauth2_providers,
        github: [
          display_name: "GitHub",
          client_id: github_app_client_id,
          client_secret: System.get_env("GITHUB_CLIENT_SECRET"),
          authorize_uri: "https://github.com/login/oauth/authorize",
          access_token_uri: "https://github.com/login/oauth/access_token",
          userinfo_uri: "https://api.github.com/user",
          enable_signup: true
        ]
    end

    # connect as a client to Zenodo's OAuth2 provider with callback url https://yourinstance.tld/oauth/client/zenodo
    if zenodo_client_id = System.get_env("ZENODO_CLIENT_ID") do
      config :bonfire_open_id, :oauth2_providers,
        zenodo: [
          display_name: System.get_env("ZENODO_DISPLAY_NAME", "Zenodo"),
          client_id: zenodo_client_id,
          client_secret: System.get_env("ZENODO_CLIENT_SECRET"),
          authorize_uri: "https://zenodo.org/oauth/authorize",
          access_token_uri: "https://zenodo.org/oauth/token",
          userinfo_uri: "https://zenodo.org/api/me",
          grant_type: System.get_env("ZENODO_GRANT_TYPE", "authorization_code"),
          scope: System.get_env("ZENODO_SCOPE", "deposit:write deposit:actions"),
          enable_signup: true
        ]
    end
  end
end
