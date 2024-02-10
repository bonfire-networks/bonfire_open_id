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

    config :boruta, Boruta.Oauth,
      issuer: System.get_env("OAUTH_ISSUER", "https://bonfirenetworks.org")

    main_discovery_document_uri = System.get_env("OPENID_1_DISCOVERY")

    if main_discovery_document_uri do
      config :bonfire_open_id, :openid_connect_providers,
        main: [
          display_name: System.get_env("OPENID_1_DISPLAY_NAME", "Single sign-on"),
          discovery_document_uri: main_discovery_document_uri,
          client_id: System.get_env("OPENID_1_CLIENT_ID"),
          client_secret: System.get_env("OPENID_1_CLIENT_SECRET"),
          redirect_uri: "#{Bonfire.Common.URIs.base_url()}/openid_client/main",
          response_type: System.get_env("OPENID_1_RESPONSE_TYPE", "code"),
          scope: System.get_env("OPENID_1_SCOPE", "identity data:public")
        ]
    end

    orcid_client_id = System.get_env("ORCID_CLIENT_ID")

    if orcid_client_id do
      config :bonfire_open_id, :openid_connect_providers,
        orcid: [
          display_name: "ORCID",
          discovery_document_uri: "https://orcid.org/.well-known/openid-configuration",
          client_id: orcid_client_id,
          client_secret: System.get_env("ORCID_CLIENT_SECRET"),
          redirect_uri: "#{Bonfire.Common.URIs.base_url()}/openid_client/orcid",
          response_type: "code",
          scope: "openid"
        ]
    end

    # TODO?
    # github_app_client_id = System.get_env("GITHUB_APP_CLIENT_ID", "Iv1.8d612e6e5a2149c9")
    # if github_app_client_id do
    #   config :bonfire_open_id, :oauth2_providers,
    #     github: [
    #     display_name: "GitHub",
    #     client_id: github_app_client_id,
    #     client_secret: System.get_env("GITHUB_CLIENT_SECRET"),
    #     authorize_uri: "https://github.com/login/oauth/authorize",
    #     access_token_uri: "https://github.com/login/oauth/access_token",
    #     redirect_uri: "#{Bonfire.Common.URIs.base_url}/openid_client/github",
    #   ]
    # end
  end
end
