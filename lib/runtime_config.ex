defmodule Bonfire.OpenID.RuntimeConfig do
  use Bonfire.Common.Localise

  @behaviour Bonfire.Common.ConfigModule
  def config_module, do: true

  @doc """
  NOTE: you can override this default config in your app's runtime.exs, by placing similarly-named config keys below the `Bonfire.Common.Config.LoadExtensionsConfig.load_configs` line
  """
  def config do
    import Config

    config :bonfire_open_id,
      disabled: false

    config :boruta, Boruta.Oauth,
      issuer: System.get_env("OAUTH_ISSUER", "https://bonfirenetworks.org") 

  case System.get_env("OPENID_1_CLIENT_SECRET") do
                    nil ->
                    secret ->

                       config :bonfire_open_id, :openid_connect_providers,
    main: [
      display_name: System.get_env("OPENID_1_DISPLAY_NAME"),
      discovery_document_uri: System.get_env("OPENID_1_DISCOVERY", "https://bonfire.cafe/.well-known/openid-configuration"),
      client_id: System.get_env("OPENID_1_CLIENT_ID"),
      client_secret: secret,
      redirect_uri: System.get_env("OPENID_1_REDIRECT"),
      response_type: System.get_env("OPENID_1_RESPONSE_TYPE", "code"),
      scope: System.get_env("OPENID_1_SCOPE", "identity data:public")
    ]

     end

    
  end
end
