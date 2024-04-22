defmodule Bonfire.OpenID.Client do
  alias Bonfire.Common.Utils

  def open_id_connect_providers,
    do: Application.get_env(:bonfire_open_id, :openid_connect_providers, [])

  def oauth2_providers, do: Application.get_env(:bonfire_open_id, :oauth2_providers, [])

  def providers_authorization_urls do
    for {provider, config} <- open_id_connect_providers() do
      {
        config[:display_name] || provider,
        Utils.ok_unwrap(
          OpenIDConnect.authorization_uri(Map.new(config), %{
            "state" => Bonfire.Common.Text.random_string(),
            "nonce" => Bonfire.Common.Text.random_string()
          })
        )
      }
    end ++
      for {provider, config} <- oauth2_providers() do
        {
          config[:display_name] || provider,
          config[:redirect_uri]
        }
      end
  end
end
